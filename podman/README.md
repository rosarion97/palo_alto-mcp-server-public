# Palo Alto Firewall MCP Server (Podman)

A Model Context Protocol (MCP) server that lets Claude **query and modify** a **Palo Alto Networks PAN-OS firewall** using the PAN-OS XML API. It can retrieve system info, policies, objects, and logs, **and** create / edit / delete address objects, services, tags, and security rules — then validate and commit those changes.

This variant is built and run with **Podman**. The recommended setup stores secrets in Podman's secret store and injects them into the container at runtime as environment variables, so Claude Desktop's configuration file references secrets by name only and never contains the API key, hostname, or any other credential. A plaintext `.env` option is also available for quick local testing or older Podman releases (see Step 4).

Every write stages to the firewall's **candidate configuration**; nothing goes live until you call `commit_config`. A `validate_commit` dry-run catches errors first.

> New here? Start with the [repo overview](../README.md). Looking for the Docker
> version? It's in [`../docker/`](../docker/README.md) and uses the Docker MCP Toolkit.

> Not affiliated with or endorsed by Palo Alto Networks. Use at your own risk. **This tool can change live firewall configuration — read [Write Safety](#write-safety) before enabling it against production.**

---

## What It Does

### Read tools

| Tool | Description |
|------|-------------|
| `get_system_info` | Firewall system info (hostname, model, serial, version, uptime) |
| `get_version_info` | PAN-OS version, serial, model |
| `get_ha_status` | High-availability status |
| `run_show_command` | Run any read-only `<show>` operational command |
| `get_running_config` | Active (running) config for any XPath under `/config` |
| `get_candidate_config` | Candidate (uncommitted) config for any XPath under `/config` |
| `get_security_rules` | Security policy rules |
| `get_nat_rules` | NAT policy rules |
| `get_address_objects` | Address objects |
| `get_address_groups` | Address groups (static and dynamic) |
| `get_service_objects` | Service objects (protocol/port definitions) |
| `get_security_profiles` | Security profiles (AV, anti-spyware, vulnerability, URL filtering, etc.) |
| `get_logs` | Retrieve logs (traffic, threat, system, config, URL, WildFire, etc.) |
| `get_job_status` | Check async job status |
| `get_uncommitted_changes` | Show staged changes not yet committed |

### Write tools (stage to candidate config)

| Tool | Description |
|------|-------------|
| `create_address_object` / `delete_address_object` | Manage address objects (ip-netmask, ip-range, ip-wildcard, fqdn) |
| `create_address_group` / `delete_address_group` | Manage static or dynamic address groups |
| `create_service_object` / `delete_service_object` | Manage TCP/UDP service objects |
| `create_tag` | Manage tag objects |
| `create_security_rule` / `delete_security_rule` | Manage security policy rules |
| `move_security_rule` | Reorder a security rule (top/bottom/before/after) |
| `set_config` / `edit_config` / `delete_config` | **Advanced**: raw XPath set/edit/delete for anything not covered above |

### Commit lifecycle

| Tool | Description |
|------|-------------|
| `validate_commit` | Dry-run validate the candidate config; reports errors/warnings |
| `commit_config` | Push staged candidate changes live (the only tool that affects production) |
| `discard_changes` | Revert the candidate config back to running (discards all staged edits) |

API-key generation is intentionally **not** exposed as a tool. Generate the key once, out of band, with `curl` (see Step 0).

---

## Prerequisites

- **Podman 4.4 or newer** (`podman --version`). Podman 4.4 introduced the `--secret type=env` flag this guide depends on.
- On **macOS or Windows**, a running Podman machine (`podman machine init && podman machine start`). On Linux, Podman runs natively.
- **Palo Alto Networks firewall** (PAN-OS 10.1 or newer)
- A firewall admin account with an API role scoped to exactly the objects/policies you want Claude to read and write (see [Recommended Firewall Role](#recommended-firewall-role))
- A pre-generated **PAN-OS API key**

---

## Recommended Firewall Role

Because this server can commit configuration changes, the API key's admin role is your most important control. Create a **custom Admin Role** under *Device > Admin Roles* and grant the **minimum** required:

1. **XML API**: enable Configuration (read + the write actions you actually need), Operational Requests, Commit, Logs. Leave anything you don't use disabled.
2. **WebUI / Config**: scope read/write to only the objects and policy rulebases Claude should touch. Deny visibility into **Mgt Config** (admin users / password hashes), **Certificate Management** (private keys), and any **authentication/server profiles** that hold shared secrets — a write-capable role can read these too.
3. Set a finite **API key lifetime** under *Device > Setup > Management > Authentication Settings* and rotate it.
4. Consider a role that can stage and validate but **cannot commit**, and keep `PANOS_ENABLE_WRITE=no` until you explicitly want changes to go live.

If you only want monitoring, set `PANOS_ENABLE_WRITE=no` and the write/commit tools refuse — the server behaves read-only regardless of the role.

---

## Step-by-Step Setup

### Step 0 — Generate Your API Key (out of band)

Run this from a trusted machine on a trusted network. Do **not** disable TLS verification when the admin password is on the wire.

```bash
curl -X POST 'https://<firewall-host>/api/?type=keygen' \
  --data-urlencode 'user=<admin-username>' \
  --data-urlencode 'password=<admin-password>'
```

If your firewall uses a self-signed certificate, pin it once instead of using `-k`:

```bash
echo | openssl s_client -connect <firewall-host>:443 -servername <firewall-host> 2>/dev/null \
  | openssl x509 > /tmp/fw.pem

curl --cacert /tmp/fw.pem -X POST 'https://<firewall-host>/api/?type=keygen' \
  --data-urlencode 'user=<admin-username>' \
  --data-urlencode 'password=<admin-password>'
```

You'll get back `<response status="success"><result><key>...</key></result></response>`. Copy the `<key>` value for Step 4. Do not paste this key into chat with Claude.

### Step 1 — Get the Project Files

Make sure the `podman/` directory contains:

- `server.py`
- `Containerfile`
- `.containerignore`
- `requirements.txt`
- `.env.example` (template — copy to `.env` only if you use the plaintext Option B in Step 4)

`cd` into the `podman/` directory before running the build.

### Step 2 — (macOS / Windows only) Start a Podman Machine

```bash
podman machine init
podman machine start
```

The Podman machine is a small VM that runs your containers. The image build, secret store, and `podman run` commands all operate inside it. Linux users skip this step.

### Step 3 — Build the Container Image

```bash
podman build -t paloalto-mcp-server:latest .
```

Verify:

```bash
podman images | grep paloalto-mcp-server
```

### Step 4 — Provide Secrets

**Option A (the Podman secret store) is strongly recommended** — secrets live in Podman's encrypted-on-disk store and only secret *names* appear in Claude Desktop's config. Option B (a plaintext `.env`) writes your key to disk in clear text; use it only for quick local testing, or on Podman older than 4.4 (which lacks `--secret type=env`).

Regardless of which option you pick: use `PANOS_VERIFY_SSL=yes` whenever you can. Only set it to `no` if the firewall uses a self-signed certificate and you accept the risk.

#### Option A — Podman secret store (recommended)

```bash
printf '%s' 'firewall.example.com' | podman secret create PANOS_HOST -
printf '%s' 'LUFRPT1xxxxxxxxxxxxxxxxxxxxxxxxxx==' | podman secret create PANOS_API_KEY -
printf '%s' 'yes' | podman secret create PANOS_VERIFY_SSL -
printf '%s' 'vsys1' | podman secret create PANOS_VSYS -
printf '%s' 'no' | podman secret create PANOS_ENABLE_WRITE -    # read-only (the default); 'yes' to allow writes
```

A few things to know:

- `printf '%s'` (without `\n`) avoids a trailing newline in the secret value. A stray newline in `PANOS_HOST` produces "Could not connect" errors that are tedious to debug.
- The values land in Podman's encrypted-on-disk secret store, which lives inside the Podman machine on macOS/Windows and under `~/.local/share/containers/storage/secrets/` on Linux.

Verify the secrets exist (values are not displayed):

```bash
podman secret ls
```

To rotate a secret later, remove it and recreate it:

```bash
podman secret rm PANOS_API_KEY
printf '%s' '<new-key>' | podman secret create PANOS_API_KEY -
```

Use the **Option A** config in Step 5.

#### Option B — Plaintext `.env` file (quick testing / Podman < 4.4)

> ⚠️ A `.env` file stores your API key in clear text on disk. Restrict its permissions (`chmod 600 .env`), never commit it (it's covered by `.containerignore` and `.gitignore`), and prefer Option A for anything beyond local testing.

Create `.env` from the template and fill in real values:

```bash
cp .env.example .env
chmod 600 .env
# Edit .env and set PANOS_HOST, PANOS_API_KEY, PANOS_VERIFY_SSL, PANOS_VSYS, PANOS_ENABLE_WRITE
```

Use the **Option B** config in Step 5.

### Step 5 — Configure Claude Desktop

Edit your Claude Desktop configuration file:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add the MCP server entry that matches the option you chose in Step 4.

**Option A — secret store:**

```json
{
  "mcpServers": {
    "paloalto-firewall": {
      "command": "podman",
      "args": [
        "run",
        "-i",
        "--rm",
        "--secret", "PANOS_HOST,type=env",
        "--secret", "PANOS_API_KEY,type=env",
        "--secret", "PANOS_VERIFY_SSL,type=env",
        "--secret", "PANOS_VSYS,type=env",
        "--secret", "PANOS_ENABLE_WRITE,type=env",
        "paloalto-mcp-server:latest"
      ]
    }
  }
}
```

What's important here:

- There is **no `env` block**. The Claude Desktop config only references secret **names** — the values stay in Podman.
- `--secret NAME,type=env` exposes the secret as an environment variable named `NAME` inside the container. Podman reads the value from its secret store at run time and never writes it to disk in plaintext.

**Option B — plaintext `.env` file:**

```json
{
  "mcpServers": {
    "paloalto-firewall": {
      "command": "podman",
      "args": [
        "run",
        "-i",
        "--rm",
        "--env-file", "/absolute/path/to/.env",
        "paloalto-mcp-server:latest"
      ]
    }
  }
}
```

Use the **absolute** path to your `.env` file. The values are read from that plaintext file at container start — keep it `chmod 600` and out of version control.

If `podman` isn't on Claude Desktop's `PATH` (common on macOS, where GUI apps don't inherit your shell's PATH), use the absolute path to the binary instead of `"podman"` — usually `/opt/homebrew/bin/podman` (Apple Silicon Homebrew) or `/usr/local/bin/podman` (Intel Homebrew). Run `which podman` in your shell to confirm.

### Step 6 — Restart Claude Desktop

Quit Claude Desktop fully and reopen it. The Palo Alto Firewall server should appear in the MCP tools list.

### Step 7 — Verify

From your shell, run the same command Claude Desktop will run, but interactively:

```bash
podman run --rm -i \
  --secret PANOS_HOST,type=env \
  --secret PANOS_API_KEY,type=env \
  --secret PANOS_VERIFY_SSL,type=env \
  --secret PANOS_VSYS,type=env \
  --secret PANOS_ENABLE_WRITE,type=env \
  paloalto-mcp-server:latest
```

It should start and wait on stdin for JSON-RPC. Press `Ctrl+C` to exit. If it fails, the error is shown on stderr — that's faster to diagnose than reading Claude Desktop logs.

In Claude Desktop, the tools menu should now include the firewall tools, and a prompt like *"List all address objects"* should hit `get_address_objects`.

---

## Using with Claude Code

Claude Code uses the same `command` / `args` schema as Claude Desktop, just in a different file. Three scopes:

| Scope | File | Sharing |
|---|---|---|
| **local** (default) | `~/.claude.json`, under this project's entry | just you, just this project |
| **project** | `.mcp.json` at the project root | shared via git with collaborators |
| **user** (global) | `~/.claude.json`, top level | just you, every project |

**Easiest path — let the CLI write it for you.** Pick the scope and option that matches Step 4:

Option A (Podman secret store, recommended):

```bash
claude mcp add -s user paloalto-firewall -- \
  podman run -i --rm \
  --secret PANOS_HOST,type=env \
  --secret PANOS_API_KEY,type=env \
  --secret PANOS_VERIFY_SSL,type=env \
  --secret PANOS_VSYS,type=env \
  --secret PANOS_ENABLE_WRITE,type=env \
  paloalto-mcp-server:latest
```

Option B (plaintext `.env` file):

```bash
claude mcp add -s user paloalto-firewall -- \
  podman run -i --rm \
  --env-file /absolute/path/to/.env \
  paloalto-mcp-server:latest
```

Use `-s user` for global, `-s project` to commit the entry to `.mcp.json` for collaborators, or omit `-s` for the default local scope. Verify with `claude mcp list`. If `podman` isn't on `PATH` when Claude Code launches, substitute the absolute path to the binary (same `which podman` advice as Step 5).

---

## Using with Codex

OpenAI Codex reads MCP server config from a TOML file instead of JSON. Two scopes:

| Scope | File | Trust requirement |
|---|---|---|
| **global** | `~/.codex/config.toml` | none |
| **project** | `.codex/config.toml` at the project root | Codex only loads project files for **trusted** projects — confirm trust in Codex before relying on this scope |

The translation from Claude Desktop's JSON is mechanical: `mcpServers.foo` → `[mcp_servers.foo]`; same `command`, same `args`.

Option A (Podman secret store):

```toml
[mcp_servers.paloalto-firewall]
command = "podman"
args = [
  "run",
  "-i",
  "--rm",
  "--secret", "PANOS_HOST,type=env",
  "--secret", "PANOS_API_KEY,type=env",
  "--secret", "PANOS_VERIFY_SSL,type=env",
  "--secret", "PANOS_VSYS,type=env",
  "--secret", "PANOS_ENABLE_WRITE,type=env",
  "paloalto-mcp-server:latest",
]
```

Option B (`.env` file):

```toml
[mcp_servers.paloalto-firewall]
command = "podman"
args = [
  "run",
  "-i",
  "--rm",
  "--env-file",
  "/absolute/path/to/.env",
  "paloalto-mcp-server:latest",
]
```

Restart Codex or open a new project thread so the MCP server loads. If `podman` isn't on Codex's `PATH`, substitute the absolute path in the `command` field.

---

## Usage Examples

**Read:**

- "Show me the system info for the firewall"
- "List all address objects"
- "What security rules are configured?"
- "Pull the last 50 threat logs from the past 24 hours"
- "Are there any uncommitted changes?"

**Write (staged, then committed):**

- "Create an address object `web-srv-01` of type ip-netmask `10.1.1.10/32`"
- "Make an address group `web-servers` containing web-srv-01 and web-srv-02"
- "Add a security rule `allow-web` from `trust` to `untrust`, source any, destination web-servers, application web-browsing, action allow"
- "Validate the candidate config" → `validate_commit`
- "Commit the changes with description 'add web servers'" → `commit_config`
- "Actually discard those staged changes" → `discard_changes`

A typical write flow: stage one or more objects/rules → `get_uncommitted_changes` to review → `validate_commit` → `commit_config`.

---

## Write Safety

This server can change live firewall configuration. Safeguards built in:

1. **Staging by default.** Every write tool targets the **candidate** config. Changes are not live until `commit_config` runs. `discard_changes` rolls the candidate back to running.
2. **Dry-run validation.** `validate_commit` runs a full commit validation and surfaces errors/warnings before you commit.
3. **Read-only by default.** Writes are opt-in: unless `PANOS_ENABLE_WRITE` is explicitly set to `yes`, every write/commit tool refuses and the server behaves read-only. Flip it to `yes` only when you intend to make changes.
4. **Input validation.** Object names are restricted to `[A-Za-z0-9_.\- ]`; ports, tag colors, and address types are validated against patterns/enums; free-text fields are XML-escaped before being embedded — blocking attribute-quote breakouts and XML injection.
5. **Well-formed-only raw edits.** `set_config` / `edit_config` require the XPath to start with `/config` and the element to parse as valid XML before anything is sent.
6. **RBAC is the backstop.** Scope the API key's admin role to exactly what Claude should touch.

> **Read-only is not the same as harmless, and write is not the same as reversible.** A broad role can leak password hashes, certificate private keys, and shared secrets, and a committed change takes effect immediately. Scope the role, keep `validate_commit` in your workflow, and prefer a non-committing role plus `PANOS_ENABLE_WRITE=no` until you're confident.

---

## Security Design

- **XML API only.** All requests go to `https://<host>/api/`. The REST API (`/restapi/`) is never used.
- **Commit is explicit.** No write tool auto-commits. The only call that reaches production config is `commit_config`.
- **Secrets stay out of chat.** API-key generation is not a tool; the key lives in the Podman secret store (Option A) or a `chmod 600` `.env` (Option B), never in Claude Desktop's config.
- **Non-root, rootless container.** Runs as UID 1000; Podman itself runs rootless by default.
- **Clean stdio.** All logging goes to stderr; auth-failure errors don't echo raw response bodies.

---

## Troubleshooting

### "Write operations are disabled"
The `PANOS_ENABLE_WRITE` secret is not `yes` — writes are disabled by default. Recreate it as `yes` and restart: `podman secret rm PANOS_ENABLE_WRITE && printf '%s' 'yes' | podman secret create PANOS_ENABLE_WRITE -`.

### "Commit returned no job ... no changes to commit"
There were no staged differences. Stage a change first, or check `get_uncommitted_changes`.

### "Could not connect to firewall"
- Verify `PANOS_HOST` is reachable from inside the Podman machine: `podman run --rm --secret PANOS_HOST,type=env paloalto-mcp-server:latest sh -c 'echo $PANOS_HOST && getent hosts $PANOS_HOST'`
- Check the management interface is accessible on HTTPS (port 443).
- Trailing newline in the secret value? Recreate it with `printf '%s'` (no `\n`).

### "HTTP 401" or "HTTP 403"
- The API key may be expired/invalid. Rotate it: `podman secret rm PANOS_API_KEY && printf '%s' '<new-key>' | podman secret create PANOS_API_KEY -`.
- The admin account may lack XML API access. Check *Device > Admin Roles > XML API*.

### "PAN-OS API error" on a write
Usually an RBAC denial (error 15/16) or a schema/validation problem. Run `validate_commit` to see detailed lines, and confirm the API role allows the action.

### "SSL certificate verify failed"
- For production, install a CA-signed cert on the firewall or mount its CA into the container so verification can stay on.
- For lab use only, recreate the secret as `no`: `podman secret rm PANOS_VERIFY_SSL && printf '%s' 'no' | podman secret create PANOS_VERIFY_SSL -`.

### "Job did not complete within timeout"
Large commits/log queries take time (default 180s for commit/validate). Narrow the query or retry.

### Server doesn't appear in Claude Desktop
- Verify the image built: `podman images | grep paloalto-mcp-server`.
- Verify the secrets exist: `podman secret ls`.
- Confirm Claude Desktop can find `podman`. On macOS, replace `"podman"` with the absolute path (e.g., `/opt/homebrew/bin/podman`).
- On macOS/Windows, confirm the Podman machine is running: `podman machine list`. If nothing shows as running, `podman machine start`.
- Restart Claude Desktop fully after any change.

### "unknown flag: --secret" or "type=env not supported"
Your Podman is older than 4.4. Upgrade Podman, or use the plaintext `.env` path (Option B) — `--env-file` works on all Podman versions. Keep the `.env` file `chmod 600` and outside Claude Desktop's config directory.

---

## Architecture

```
Claude Desktop
   │
   │  spawns: podman run -i --rm --secret PANOS_HOST,type=env ...
   ▼
Podman (rootless)
   │
   │  reads PANOS_HOST / PANOS_API_KEY / PANOS_VERIFY_SSL /
   │  PANOS_VSYS / PANOS_ENABLE_WRITE from its secret store
   │  and injects them as environment variables
   ▼
paloalto-firewall container
   │
   │  JSON-RPC over stdio with Claude Desktop
   │  HTTPS POST to https://<host>/api/   (writes stage to candidate config)
   ▼
PAN-OS XML API
```

Claude Desktop's config file contains only the `podman run` invocation and secret **names**. The actual credential values live in Podman's secret store and are injected at container start. Writes stage to the candidate config; `commit_config` is the only path to production.

---

## License

Provided as-is for integrating Palo Alto Networks firewalls with Claude Desktop via MCP. Use at your own risk. Not affiliated with or endorsed by Palo Alto Networks.
