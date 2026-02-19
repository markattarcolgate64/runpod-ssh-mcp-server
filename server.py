"""RunPod SSH MCP Server — execute commands on a remote RunPod GPU server."""

import os
import sys
import logging

import paramiko
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging (stderr only — stdout is reserved for JSON-RPC)
# ---------------------------------------------------------------------------
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
RUNPOD_HOST = os.environ.get("RUNPOD_HOST", "ssh.runpod.io")
RUNPOD_PORT = int(os.environ.get("RUNPOD_PORT", "22"))
RUNPOD_USER = os.environ.get("RUNPOD_USER", "")
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_ed25519"))

# ---------------------------------------------------------------------------
# SSH helper
# ---------------------------------------------------------------------------

def _get_ssh_client() -> paramiko.SSHClient:
    """Create a fresh SSH connection to RunPod."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)
    client.connect(hostname=RUNPOD_HOST, port=RUNPOD_PORT, username=RUNPOD_USER, pkey=key)
    return client


def _exec(command: str, timeout: int = 30) -> dict:
    """Run a command over SSH and return stdout, stderr, exit_code."""
    client = _get_ssh_client()
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        return {
            "stdout": stdout.read().decode(errors="replace"),
            "stderr": stderr.read().decode(errors="replace"),
            "exit_code": exit_code,
        }
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
def gpu_status() -> str:
    """Get GPU status from nvidia-smi on the remote RunPod server."""
    result = _exec("nvidia-smi", timeout=10)
    if result["exit_code"] != 0:
        return f"nvidia-smi failed: {result['stderr']}"
    return result["stdout"]


@mcp.tool()
def list_files(path: str = "/workspace") -> str:
    """List directory contents on the remote RunPod server.

    Args:
        path: Directory path to list (default: /workspace).
    """
    result = _exec(f"ls -la {path}", timeout=10)
    if result["exit_code"] != 0:
        return f"Error: {result['stderr']}"
    return result["stdout"]


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the remote RunPod server.

    Args:
        path: Absolute path to the file to read.
    """
    result = _exec(f"cat {path}", timeout=10)
    if result["exit_code"] != 0:
        return f"Error: {result['stderr']}"
    return result["stdout"]


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
