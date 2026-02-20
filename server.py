"""RunPod SSH MCP Server — execute commands on a remote RunPod GPU server."""

import json
import os
import sys
import logging
from pathlib import Path

import paramiko
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging (stderr only — stdout is reserved for JSON-RPC)
# ---------------------------------------------------------------------------
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration: config file (~/.config/runpod-ssh.json) → env vars → defaults
# ---------------------------------------------------------------------------
CONFIG_PATH = Path.home() / ".config" / "runpod-ssh.json"


def _load_config() -> dict:
    """Load connection config from JSON file, falling back to env vars."""
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
            log.info("Loaded config from %s", CONFIG_PATH)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Failed to read %s: %s — falling back to env vars", CONFIG_PATH, e)

    return {
        "host": cfg.get("host") or os.environ.get("RUNPOD_HOST", "ssh.runpod.io"),
        "port": int(cfg.get("port") or os.environ.get("RUNPOD_PORT", "22")),
        "user": cfg.get("user") or os.environ.get("RUNPOD_USER", ""),
        "ssh_key_path": cfg.get("ssh_key_path") or os.environ.get("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_ed25519")),
    }

# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def _get_ssh_client() -> paramiko.SSHClient:
    """Create a fresh SSH connection to RunPod."""
    cfg = _load_config()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.Ed25519Key.from_private_key_file(cfg["ssh_key_path"])
    client.connect(hostname=cfg["host"], port=cfg["port"], username=cfg["user"], pkey=key)
    return client


def _exec(command: str, timeout: int = 30) -> dict:
    """Run a command over SSH and return stdout, stderr, exit_code.

    Uses invoke_shell because RunPod's SSH proxy requires a PTY and
    rejects plain exec_command.
    """
    import re
    import time

    client = _get_ssh_client()
    try:
        channel = client.invoke_shell()
        channel.settimeout(timeout)

        # Wait for initial shell prompt / banner
        time.sleep(1)
        if channel.recv_ready():
            channel.recv(65536)  # discard

        # Send command with explicit markers so we can extract just its output
        start_marker = "__CMD_START__"
        end_marker = "__CMD_END__"
        exit_marker = "__EXIT_CODE__"
        channel.sendall(
            f"echo {start_marker}\n{command}\n"
            f"echo {end_marker}\necho {exit_marker}$?\nexit\n".encode()
        )

        # Read all output until channel closes
        output = b""
        while True:
            try:
                chunk = channel.recv(65536)
                if not chunk:
                    break
                output += chunk
            except Exception:
                break

        channel.close()

        # Strip ANSI escape codes
        ansi_re = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07?")
        text = ansi_re.sub("", output.decode(errors="replace"))

        lines = text.splitlines()

        # Extract exit code
        exit_code = 0
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(exit_marker):
                try:
                    exit_code = int(stripped[len(exit_marker):].strip())
                except ValueError:
                    pass

        # Extract only lines between start and end markers
        capturing = False
        captured = []
        for line in lines:
            stripped = line.strip()
            if start_marker in stripped:
                capturing = True
                continue
            if end_marker in stripped:
                capturing = False
                continue
            if capturing:
                # Skip the echoed command line (shell prompt + command)
                if stripped.endswith(f"# {command}") or stripped == command:
                    continue
                captured.append(line)

        stdout_text = "\n".join(captured).strip()
        return {"stdout": stdout_text, "stderr": "", "exit_code": exit_code}
    finally:
        client.close()

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("runpod-gpu")


@mcp.tool()
def run_command(command: str, timeout: int = 30, workdir: str | None = None) -> str:
    """Execute a shell command on the remote RunPod server.

    Args:
        command: The shell command to run.
        timeout: Max seconds to wait (default 30).
        workdir: Optional working directory to cd into first.
    """
    if workdir:
        command = f"cd {workdir} && {command}"
    result = _exec(command, timeout=timeout)
    parts = []
    if result["stdout"]:
        parts.append(result["stdout"])
    if result["stderr"]:
        parts.append(f"[stderr]\n{result['stderr']}")
    if result["exit_code"] != 0:
        parts.append(f"[exit_code: {result['exit_code']}]")
    return "\n".join(parts) or "(no output)"


@mcp.tool()
def start_background_job(command: str, session_name: str) -> str:
    """Start a long-running command in a tmux session on RunPod.

    Args:
        command: The command to run in the background.
        session_name: Name for the tmux session (used to check on it later).
    """
    # Kill existing session with same name if it exists, then start new one
    tmux_cmd = (
        f"tmux kill-session -t {session_name} 2>/dev/null; "
        f"tmux new-session -d -s {session_name} '{command}'"
    )
    result = _exec(tmux_cmd, timeout=10)
    if result["exit_code"] != 0:
        return f"Failed to start job: {result['stderr']}"
    return f"Background job '{session_name}' started. Use check_job('{session_name}') to monitor."


@mcp.tool()
def check_job(session_name: str) -> str:
    """Capture recent output from a running tmux session on RunPod.

    Args:
        session_name: Name of the tmux session to check.
    """
    result = _exec(f"tmux capture-pane -t {session_name} -p", timeout=10)
    if result["exit_code"] != 0:
        # Check if session still exists
        check = _exec(f"tmux has-session -t {session_name} 2>&1; echo $?", timeout=5)
        if "1" in check["stdout"]:
            return f"Session '{session_name}' not found. The job may have finished."
        return f"Error capturing output: {result['stderr']}"
    return result["stdout"] or "(no output captured)"


if __name__ == "__main__":
    mcp.run()
