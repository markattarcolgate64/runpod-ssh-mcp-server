# RunPod SSH MCP Server

MCP server that lets Claude Code execute commands on a remote RunPod GPU server via SSH.

## Setup

```bash
# Install dependencies
cd ~/Developer/runpod-ssh-mcp-server
uv sync
```

## Tools

| Tool | Description |
|------|-------------|
| `run_command` | Execute a shell command on RunPod |
| `gpu_status` | Quick `nvidia-smi` summary |
| `list_files` | List directory contents |
| `read_file` | Read a remote file |
| `start_background_job` | Run a command in a tmux session |
| `check_job` | Get recent output from a tmux session |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNPOD_HOST` | `ssh.runpod.io` | SSH hostname |
| `RUNPOD_PORT` | `22` | SSH port |
| `RUNPOD_USER` | — | RunPod SSH username |
| `SSH_KEY_PATH` | `~/.ssh/id_ed25519` | Path to SSH private key |

## Register with Claude Code

```bash
claude mcp add --transport stdio --scope user \
  --env RUNPOD_HOST=ssh.runpod.io \
  --env RUNPOD_USER=<your-runpod-user> \
  --env RUNPOD_PORT=22 \
  --env SSH_KEY_PATH=~/.ssh/id_ed25519 \
  runpod-gpu -- uv run ~/Developer/runpod-ssh-mcp-server/server.py
```

## Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector uv run server.py
```
