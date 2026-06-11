# Palo Alto Firewall MCP Server

A Model Context Protocol (MCP) server that lets Claude **query and modify** a **Palo Alto Networks PAN-OS firewall** using the PAN-OS XML API. It can retrieve system info, policies, objects, and logs, **and** create / edit / delete address objects, services, tags, and security rules — then validate and commit those changes.

Unlike the read-only [panorama-readonly-mcp-server](https://github.com/rosarion97/panorama-readonly-mcp-server) this server is intentionally **read/write**. Every write stages to the firewall's **candidate configuration**; nothing goes live until you call the `commit_config` tool. A `validate_commit` dry-run is available to catch errors first.

This server is designed to run inside a Docker container managed by the **Docker MCP Toolkit**. The recommended setup keeps secrets in Docker's secret store, out of Claude Desktop's configuration file; a plaintext `.env` option is also available for quick local testing.

> New here? Start with the [repo overview](../README.md). Prefer **Podman**? A
> rootless Podman variant (with its own `Containerfile` and setup guide) lives in
> [`../podman/`](../podman/README.md).

> Not affiliated with or endorsed by Palo Alto Networks. Use at your own risk. **This tool can change live firewall configuration — read the [Write Safety](#write-safety) section before enabling it against production.**

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

API-key generation is intentionally **not** exposed as a tool. Generating an API key requires admin credentials, and routing those through an LLM would put them in conversation context. Instead, generate the key once, out of band, using `curl` (see Step 0).

---

## Prerequisites

- **Docker Desktop** with the [MCP Toolkit](https://docs.docker.com/desktop/features/mcp/) extension installed and enabled
- **Palo Alto Networks firewall** (PAN-OS 10.1 or newer)
- A firewall admin account with an API role scoped to exactly the objects/policies you want Claude to read and write (see [Recommended Firewall Role](#recommended-firewall-role))
- A pre-generated **PAN-OS API key**

---

## Recommended Firewall Role

Because this server can commit configuration changes, the API key's admin role is your most important control. Create a **custom Admin Role** under *Device > Admin Roles* and grant the **minimum** required:

1. **XML API**: enable Configuration (read + the write actions you actually need), Operational Requests, Commit, Logs. Leave anything you don't use disabled.
2. **WebUI / Config**: scope read/write to only the objects and policy rulebases Claude should touch. Deny visibility into **Mgt Config** (admin users / password hashes), **Certificate Management** (private keys), and any **authentication/server profiles** that hold shared secrets — a write-capable role can read these too.
3. Set a finite **API key lifetime** under *Device > Setup > Management > Authentication Settings* and rotate it.
4. Consider giving Claude a role that can stage and validate but **cannot commit**, and keep `PANOS_ENABLE_WRITE=no` until you explicitly want changes to go live.

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

You'll get back `<response status="success"><result><key>...</key></result></response>`. Copy the `<key>` value for Step 3. Do not paste this key into chat with Claude.

### Step 1 — Get the Project Files

Clone or download this repository; the `docker/` directory should contain:

- `server.py`
- `Dockerfile`
- `.dockerignore`
- `requirements.txt`
- `custom-catalog.yaml`
- `.env.example` (template — copy to `.env` only if you use plaintext Option B in Step 3)

### Step 2 — Build the Docker Image

```bash
docker build -t paloalto-mcp-server .
```

### Step 3 — Provide Secrets

**Option A (the Docker secret store) is strongly recommended.** Option B (a plaintext `.env`) writes your key to disk in clear text; use it only for quick local testing. Use `PANOS_VERIFY_SSL="yes"` whenever you can.

#### Option A — Docker secret store (recommended)

```bash
docker mcp secret set PANOS_HOST="firewall.example.com"
docker mcp secret set PANOS_API_KEY="LUFRPT1xxxxxxxxxxxxxxxxxxxxxxxxxx=="
docker mcp secret set PANOS_VERIFY_SSL="yes"
docker mcp secret set PANOS_VSYS="vsys1"
docker mcp secret set PANOS_ENABLE_WRITE="yes"   # set to "no" to run read-only
docker mcp secret list
```

#### Option B — Plaintext `.env` file (quick testing only)

This path bypasses the Docker MCP gateway and runs the container directly, so you can **skip Steps 4–6**.

> ⚠️ A `.env` file stores your API key in clear text on disk. `chmod 600 .env`, never commit it (it's git-ignored), and prefer Option A for anything beyond local testing.

```bash
cp .env.example .env
chmod 600 .env
# Edit .env and set PANOS_HOST, PANOS_API_KEY, PANOS_VERIFY_SSL, PANOS_VSYS, PANOS_ENABLE_WRITE
```

Then add this to Claude Desktop's config (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`) **instead of** Steps 4–6:

```json
{
  "mcpServers": {
    "paloalto-firewall": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", "/absolute/path/to/.env",
        "paloalto-mcp-server:latest"
      ]
    }
  }
}
```

Use the **absolute** path. Restart Claude Desktop, then jump to Step 7.

### Step 4 — Install the Custom Catalog

> Steps 4–6 apply to **Option A**. If you used Option B, skip to Step 7.

```bash
mkdir -p ~/.docker/mcp/catalogs
cp custom-catalog.yaml ~/.docker/mcp/catalogs/custom.yaml
```

### Step 5 — Enable the Server in the Registry

`~/.docker/mcp/registry.yaml` lists active servers under a single top-level `registry:` key. Add the `paloalto-firewall` entry — **do not overwrite the file** if it already exists.

```yaml
registry:
  paloalto-firewall:
    catalog: custom
    enabled: true
  # ... any other servers you already had stay here
```

### Step 6 — Point Claude Desktop at the Docker MCP Gateway

Add the gateway block to Claude Desktop's config (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`). The gateway runs as a container, mounts the Docker socket so it can spawn the `paloalto-mcp-server` container on demand, and mounts your `~/.docker/mcp` directory so it can read the catalog, registry, and secret store you set up in Steps 3–5.

Replace `<your-username>` with your macOS username (run `whoami` to check):

```json
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "/Users/<your-username>/.docker/mcp:/mcp",
        "-v", "/Users/<your-username>/Library/Caches/docker-secrets-engine/engine.sock:/root/.cache/docker-secrets-engine/engine.sock",
        "docker/mcp-gateway:latest",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--registry=/mcp/registry.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

Three bind-mounts, all required:

1. **`/var/run/docker.sock`** — lets the gateway spawn the `paloalto-mcp-server` container.
2. **`~/.docker/mcp`** — the gateway reads your catalog and registry from here.
3. **`docker-secrets-engine/engine.sock`** — the resolver socket Docker Desktop exposes for the secret store. Without it the gateway sees empty values and `docker run -e ""` rejects the env flags, so the server fails to start and only the gateway's own admin tools show up. On Linux/Docker Desktop the host path is `~/.docker/desktop/secrets-engine/engine.sock` instead; check with `find ~ -name engine.sock 2>/dev/null`.

Quit and reopen Claude Desktop. `claude_desktop_config.json` never contains `PANOS_API_KEY` — the gateway resolves it from Docker's secret store at request time.

Optional additions:

- `--catalog=/mcp/catalogs/docker-mcp.yaml` — the built-in Docker MCP catalog. Add this line if you also want the servers in Docker's default catalog available. The file is created once you've used `docker mcp catalog` at least once; omit the line otherwise.
- `--config=/mcp/config.yaml` and `--tools-config=/mcp/tools.yaml` — only add these if the files actually exist; the gateway errors on a missing path passed explicitly.

> **Shortcut alternative.** `docker mcp client connect claude-desktop` (or **MCP Toolkit > Clients** in Docker Desktop) will write a similar block for you automatically. The explicit JSON above gives you control over which catalogs load and survives Docker Desktop updates that may rewrite the auto-managed entry.

### Step 7 — Verify

```bash
docker mcp server list
docker mcp tools list
```

You should see `paloalto-firewall` enabled and its tools listed.

---

## Using with Claude Code

Claude Code uses the same `mcp-toolkit-gateway` block from Step 6 — same `command`, same `args` — but reads it from a different file. There are three scopes:

| Scope | File | Sharing |
|---|---|---|
| **local** (default) | `~/.claude.json`, under this project's entry | just you, just this project |
| **project** | `.mcp.json` at the project root | shared via git with collaborators |
| **user** (global) | `~/.claude.json`, top level | just you, every project |

**Easiest path — let the CLI write it for you.** Replace `<your-username>` and pick the scope you want:

```bash
claude mcp add -s user mcp-toolkit-gateway -- \
  docker run -i --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /Users/<your-username>/.docker/mcp:/mcp \
  -v /Users/<your-username>/Library/Caches/docker-secrets-engine/engine.sock:/root/.cache/docker-secrets-engine/engine.sock \
  docker/mcp-gateway:latest \
  --catalog=/mcp/catalogs/custom.yaml \
  --registry=/mcp/registry.yaml \
  --transport=stdio
```

Use `-s user` for global, `-s project` to commit the entry to `.mcp.json` for collaborators, or omit `-s` for the default local scope. Everything after `--` is the same docker invocation Claude Desktop uses — the schema is byte-for-byte identical.

Verify with `claude mcp list`. The Step 3 secrets and Step 4 / Step 5 catalog and registry setup all carry over; nothing else changes.

---

## Using with Codex

OpenAI Codex reads MCP server config from a TOML file instead of JSON. Two scopes:

| Scope | File | Trust requirement |
|---|---|---|
| **global** | `~/.codex/config.toml` | none |
| **project** | `.codex/config.toml` at the project root | Codex only loads project files for **trusted** projects — confirm trust in Codex before relying on this scope |

Same gateway invocation as Step 6, mechanically translated from JSON to TOML (`mcpServers.foo` → `[mcp_servers.foo]`; same `command`, same `args`). Replace `<your-username>` with your macOS username (run `whoami` to check):

```toml
[mcp_servers.mcp-toolkit-gateway]
command = "docker"
args = [
  "run",
  "-i",
  "--rm",
  "-v",
  "/var/run/docker.sock:/var/run/docker.sock",
  "-v",
  "/Users/<your-username>/.docker/mcp:/mcp",
  "-v",
  "/Users/<your-username>/Library/Caches/docker-secrets-engine/engine.sock:/root/.cache/docker-secrets-engine/engine.sock",
  "docker/mcp-gateway:latest",
  "--catalog=/mcp/catalogs/custom.yaml",
  "--registry=/mcp/registry.yaml",
  "--transport=stdio",
]
```

Restart Codex or open a new project thread so the MCP server loads. The Step 3 secrets and Step 4 / Step 5 catalog and registry setup all carry over; nothing else changes.

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

1. **Staging by default.** Every write tool targets the **candidate** config (`action=set/edit/delete/move`). Changes are not live until `commit_config` runs. `discard_changes` rolls back the candidate to the running config.
2. **Dry-run validation.** `validate_commit` runs a full commit validation and surfaces errors/warnings before you commit.
3. **Write kill-switch.** Set `PANOS_ENABLE_WRITE=no` and every write/commit tool refuses; the server behaves read-only. Flip it to `yes` only when you intend to make changes.
4. **Input validation.** Object names are restricted to `[A-Za-z0-9_.\- ]`; ports, tag colors, and address types are validated against patterns/enums; free-text fields (descriptions, comments, DAG filters) are XML-escaped before being embedded — blocking attribute-quote breakouts and XML injection.
5. **Well-formed-only raw edits.** `set_config` / `edit_config` require the XPath to start with `/config` and the element to parse as valid XML before anything is sent.
6. **RBAC is the backstop.** Scope the API key's admin role to exactly what Claude should touch (see [Recommended Firewall Role](#recommended-firewall-role)). The firewall rejects anything the role forbids.

> **Read-only is not the same as harmless, and write is not the same as reversible.** A broad role can leak password hashes, certificate private keys, and shared secrets, and a committed change takes effect immediately. Scope the role, keep `validate_commit` in your workflow, and prefer a non-committing role plus `PANOS_ENABLE_WRITE=no` until you're confident.

---

## Security Design

- **XML API only.** All requests go to `https://<host>/api/`. The REST API (`/restapi/`) is never used.
- **Commit is explicit.** No write tool auto-commits. The only call that reaches production config is `commit_config`.
- **Secrets stay out of chat.** API-key generation is not a tool; the key lives in the Docker secret store (Option A) or a `chmod 600` `.env` (Option B), never in Claude Desktop's config.
- **Non-root container.** Runs as UID 1000.
- **Clean stdio.** All logging goes to stderr; auth-failure errors don't echo raw response bodies.

---

## Troubleshooting

### "Write operations are disabled"
`PANOS_ENABLE_WRITE` is unset to `no`/`false`/`0`. Set it to `yes` (and restart) to enable write/commit tools.

### "Commit returned no job ... no changes to commit"
There were no staged differences. Stage a change first, or check `get_uncommitted_changes`.

### "PAN-OS API error: ..." on a write
Usually an RBAC denial (error 15/16) or a schema/validation problem. Run `validate_commit` to see detailed lines, and confirm the API role allows the action.

### "HTTP 401 / 403"
API key expired/invalid, or the admin role lacks XML API access. Regenerate (Step 0) and update the secret.

### "Could not connect to firewall"
Verify `PANOS_HOST` is reachable on HTTPS/443 from inside the container; confirm DNS resolves.

### "Job did not complete within timeout"
Large commits/log queries take time (default 180s for commit/validate). Narrow the query or retry.

### "element is not well-formed XML"
`set_config` / `edit_config` require a single valid XML fragment for the `element` argument.

---

## How to Add New Tools

Follow the existing patterns in `server.py`:

- **Read tools** use `action=show`/`action=get`, `type=op` with `<show>`, `type=log`, or `type=version`.
- **Write tools** call `_require_write()` first, build XPath from `_vsys_base()`, run user values through `_validate_name()` / enum checks, XML-escape free text with `_xml_escape`, and use `_config_action("set"|"edit"|"delete", ...)`. They must **not** commit — leave that to `commit_config`.
- Single-line docstrings. Default optional string params to `""`, never `None`. Always return strings.

Rebuild (`docker build -t paloalto-mcp-server .`) and restart Claude Desktop after changes.

---

## Architecture

```
Claude Desktop  ←→  Docker MCP Gateway  ←→  paloalto-firewall container  ←→  HTTPS  ←→  PAN-OS XML API
                                              │
                                              └─ reads PANOS_HOST / PANOS_API_KEY / PANOS_VERIFY_SSL /
                                                 PANOS_VSYS / PANOS_ENABLE_WRITE from secrets at startup
```

Writes stage to the candidate config; `commit_config` is the only path to production.

---

## License

Provided as-is for integrating Palo Alto Networks firewalls with Claude Desktop via MCP. Use at your own risk. Not affiliated with or endorsed by Palo Alto Networks.
