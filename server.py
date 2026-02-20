"""RunPod SSH MCP Server — execute commands on a remote RunPod GPU server."""

import json
import os
import re
import sys
import time
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

    host = cfg.get("host") or os.environ.get("RUNPOD_HOST", "ssh.runpod.io")
    mode = cfg.get("mode") or ("proxy" if host == "ssh.runpod.io" else "direct")

    return {
        "host": host,
        "port": int(cfg.get("port") or os.environ.get("RUNPOD_PORT", "22")),
        "user": cfg.get("user") or os.environ.get("RUNPOD_USER", ""),
        "ssh_key_path": cfg.get("ssh_key_path") or os.environ.get("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_ed25519")),
        "mode": mode,
    }


def _parse_ssh_string(ssh_string: str) -> dict:
    """Parse an SSH connection string from RunPod's UI.

    Supported formats:
      - Proxy:  ssh <podid>@ssh.runpod.io -i <key_path>
      - Direct: ssh root@<ip> -p <port> -i <key_path>
    """
    parts = ssh_string.strip().split()

    if not parts or parts[0] != "ssh":
        raise ValueError(f"Expected string starting with 'ssh', got: {ssh_string}")

    # Find user@host (first arg that contains @)
    user_host = None
    for p in parts[1:]:
        if "@" in p and not p.startswith("-"):
            user_host = p
            break

    if user_host is None:
        raise ValueError(f"Could not find user@host in: {ssh_string}")

    user, host = user_host.split("@", 1)

    # Extract -p port
    port = 22
    for i, p in enumerate(parts):
        if p == "-p" and i + 1 < len(parts):
            port = int(parts[i + 1])
            break

    # Extract -i key_path
    ssh_key_path = os.path.expanduser("~/.ssh/id_ed25519")
    for i, p in enumerate(parts):
        if p == "-i" and i + 1 < len(parts):
            ssh_key_path = os.path.expanduser(parts[i + 1])
            break

    mode = "proxy" if host == "ssh.runpod.io" else "direct"

    return {
        "host": host,
        "port": port,
        "user": user,
        "ssh_key_path": ssh_key_path,
        "mode": mode,
    }


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _get_ssh_client() -> paramiko.SSHClient:
    """Create a fresh SSH connection to RunPod."""
    cfg = _load_config()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key_path = cfg["ssh_key_path"]
    # Try Ed25519 first, fall back to RSA
    try:
        key = paramiko.Ed25519Key.from_private_key_file(key_path)
    except paramiko.ssh_exception.SSHException:
        key = paramiko.RSAKey.from_private_key_file(key_path)
    client.connect(hostname=cfg["host"], port=cfg["port"], username=cfg["user"], pkey=key)
    return client


def _exec_proxy(client: paramiko.SSHClient, command: str, timeout: int) -> dict:
    """Run a command via invoke_shell (for RunPod's SSH proxy which requires PTY)."""
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
            if stripped.endswith(f"# {command}") or stripped == command:
                continue
            captured.append(line)

    stdout_text = "\n".join(captured).strip()
    return {"stdout": stdout_text, "stderr": "", "exit_code": exit_code}


def _exec_direct(client: paramiko.SSHClient, command: str, timeout: int) -> dict:
    """Run a command via exec_command (for direct TCP connections)."""
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return {
        "stdout": stdout.read().decode(errors="replace").strip(),
        "stderr": stderr.read().decode(errors="replace").strip(),
        "exit_code": exit_code,
    }


def _exec(command: str, timeout: int = 30) -> dict:
    """Run a command over SSH, dispatching to the right method based on connection mode."""
    cfg = _load_config()
    client = _get_ssh_client()
    try:
        if cfg["mode"] == "proxy":
            return _exec_proxy(client, command, timeout)
        else:
            return _exec_direct(client, command, timeout)
    finally:
        client.close()


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("runpod-ssh-gpu")


@mcp.tool()
def connect(ssh_string: str) -> str:
    """Connect to a RunPod pod by pasting the SSH command from RunPod's web UI.

    Parses the SSH string, saves the connection config, and tests the connection.

    Args:
        ssh_string: The SSH command copied from RunPod (e.g. "ssh root@ip -p port -i key"
                    or "ssh podid@ssh.runpod.io -i key").
    """
    try:
        cfg = _parse_ssh_string(ssh_string)
    except ValueError as e:
        return f"Failed to parse SSH string: {e}"

    # Save config
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")
    log.info("Saved config to %s", CONFIG_PATH)

    # Test connection
    try:
        client = _get_ssh_client()
        client.close()
    except Exception as e:
        return f"Config saved but connection test failed: {e}"

    if cfg["mode"] == "proxy":
        return (
            f"Connected to {cfg['user']}@{cfg['host']}:{cfg['port']} in PROXY mode.\n"
            f"Available: run_command, start_background_job, check_job.\n"
            f"NOT available: upload_file, download_file (SFTP is not supported over RunPod's SSH proxy). "
            f"To enable file transfer, reconnect using a direct TCP SSH string (ssh root@<ip> -p <port> -i <key>)."
        )
    else:
        return (
            f"Connected to {cfg['user']}@{cfg['host']}:{cfg['port']} in DIRECT mode.\n"
            f"All tools available: run_command, upload_file, download_file, start_background_job, check_job."
        )


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
def upload_file(local_path: str, remote_path: str) -> str:
    """Upload a file from the local machine to the remote RunPod server via SFTP.

    Requires direct TCP connection (not proxy mode).

    Args:
        local_path: Path to the file on the local machine.
        remote_path: Destination path on the RunPod server.
    """
    cfg = _load_config()
    if cfg["mode"] == "proxy":
        return "Error: File transfer requires a direct TCP connection. Reconnect using a direct SSH string (ssh root@<ip> -p <port> -i <key>)."

    local = Path(local_path).expanduser()
    if not local.is_file():
        return f"Error: Local file not found: {local}"

    client = _get_ssh_client()
    try:
        sftp = paramiko.SFTPClient.from_transport(client.get_transport())
        sftp.put(str(local), remote_path)
        sftp.close()
        size = local.stat().st_size
        return f"Uploaded {local} → {remote_path} ({size} bytes)"
    except Exception as e:
        return f"Upload failed: {e}"
    finally:
        client.close()


@mcp.tool()
def download_file(remote_path: str, local_path: str) -> str:
    """Download a file from the remote RunPod server to the local machine via SFTP.

    Requires direct TCP connection (not proxy mode).

    Args:
        remote_path: Path to the file on the RunPod server.
        local_path: Destination path on the local machine.
    """
    cfg = _load_config()
    if cfg["mode"] == "proxy":
        return "Error: File transfer requires a direct TCP connection. Reconnect using a direct SSH string (ssh root@<ip> -p <port> -i <key>)."

    local = Path(local_path).expanduser()
    local.parent.mkdir(parents=True, exist_ok=True)

    client = _get_ssh_client()
    try:
        sftp = paramiko.SFTPClient.from_transport(client.get_transport())
        sftp.get(remote_path, str(local))
        size = local.stat().st_size
        sftp.close()
        return f"Downloaded {remote_path} → {local} ({size} bytes)"
    except Exception as e:
        return f"Download failed: {e}"
    finally:
        client.close()


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
