# RunPod SSH MCP Server - Mark Attar 

I made this because I was tired of having to copy paste RunPod output to my coding agent instances

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
| `start_background_job` | Run a command in a tmux session |
| `check_job` | Get recent output from a tmux session |

## Configuration

Create `~/.config/runpod-ssh.json` with your pod's connection details:

```json
{
  "host": "ssh.runpod.io",
  "port": 22,
  "user": "<your-runpod-user>",
  "ssh_key_path": "~/.ssh/id_ed25519"
}
```

To switch pods, just edit this file — no need to re-register the MCP server.

Falls back to environment variables (`RUNPOD_HOST`, `RUNPOD_PORT`, `RUNPOD_USER`, `SSH_KEY_PATH`) if the config file doesn't exist.

## Register with Claude Code

One-time setup:

```bash
claude mcp add --transport stdio --scope user \
  runpod-gpu -- uv run ~/Developer/runpod-ssh-mcp-server/server.py
```

## Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector uv run server.py
```
