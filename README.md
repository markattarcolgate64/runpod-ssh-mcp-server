# RunPod SSH MCP Server - Mark Attar

I made this because I was tired of having to copy paste RunPod output to my coding agent instances

MCP server that lets Claude Code/other coding agent execute commands on a remote RunPod GPU server via SSH and also transfer files from the server.

## Setup

```bash
# Install dependencies
cd ~/Developer/runpod-ssh-mcp-server
uv sync
```

## Quick Start

1. Register the MCP server with Claude Code (one-time):

```bash
claude mcp add --transport stdio --scope user runpod-ssh-gpu -- uv run ~/Developer/runpod-ssh-mcp-server/server.py
```

2. Copy the SSH command from RunPod's web UI and paste it into Claude:

For direct TCP mode copy the string that looks like this (only this mode supports SFTP & SCP):

> "Connect to my pod: `ssh root@192.168.1.10 -p 22345 -i ~/.ssh/id_ed25519`"
For SSH proxy mode copy the string in that looks like this:

> "Connect to my pod: `ssh oaplvaencc9qc0-64411be6@ssh.runpod.io -i ~/.ssh/id_ed25519`"

Or if your agent has a good browser MCP it might be able to pull the string directly from RunPod.

That's it — the agent will parse the string and save the connection config automatically.

## Connection Modes

The server supports two connection modes, detected automatically from the SSH string:

| Mode | SSH String | Capabilities |
|------|-----------|--------------|
| **Direct** | `ssh root@<ip> -p <port> -i <key>` | Full SSH: exec, SFTP upload/download |
| **Proxy** | `ssh <podid>@ssh.runpod.io -i <key>` | PTY-based exec only (no file transfer) |

**Direct mode** uses `exec_command()` for clean stdout/stderr/exit_code. **Proxy mode** uses `invoke_shell()` with marker-based output parsing (required by RunPod's SSH proxy).

To switch pods, just call `connect` again with the new SSH string.

Paramiko is used for the SSH connection and SFTP upload/download while FastMCP is used to package the MCP. 

## Tools

| Tool | Description | Mode |
|------|-------------|------|
| `connect` | Parse SSH string from RunPod UI and save connection config | Both |
| `run_command` | Execute a shell command on RunPod | Both |
| `upload_file` | Upload a local file to RunPod via SFTP | Direct only |
| `download_file` | Download a file from RunPod via SFTP | Direct only |
| `start_background_job` | Run a command in a tmux session | Both |
| `check_job` | Get recent output from a tmux session | Both |

## Configuration

The `connect` tool saves config to `~/.config/runpod-ssh.json`. You can also create this file manually or use environment variables (`RUNPOD_HOST`, `RUNPOD_PORT`, `RUNPOD_USER`, `SSH_KEY_PATH`) as fallbacks.

## Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector uv run server.py
```
