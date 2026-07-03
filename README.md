# Palo Alto Firewall MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
lets Claude **query and modify** a **Palo Alto Networks PAN-OS firewall** over
stdio, using the PAN-OS XML API. It can read system info, policies, objects, and
logs, **and** create / edit / delete address objects, services, tags, and
security rules — then validate and commit those changes.

Unlike the read-only [panorama-readonly-mcp-server](https://github.com/rosarion97/panorama-readonly-mcp-server-public),
this server is **read/write** — but it **ships read-only**: writes stay disabled
until you explicitly set `PANOS_ENABLE_WRITE=yes`. Enabled writes
stage to the firewall's **candidate configuration** — nothing goes live until
you call the `commit_config` tool. A `validate_commit` dry-run catches errors
first.

> Not affiliated with or endorsed by Palo Alto Networks. Use at your own risk.
> **This tool can change live firewall configuration — read the Write Safety
> section of a backend README before enabling it against production.**

---

## Pick a backend

The server ships in two interchangeable container flavors running the
**byte-identical** `server.py`; choose whichever matches your toolchain:

| | When to use | Setup guide |
|---|---|---|
| 🐳 **Docker** | You use Docker Desktop + the MCP Toolkit | [`docker/README.md`](docker/README.md) |
| 🦭 **Podman** | You want rootless containers / no Docker Desktop | [`podman/README.md`](podman/README.md) |

Each guide is self-contained (build → secrets → register with Claude
Desktop / Claude Code / Codex → verify). The only differences are how the image
is built and how secrets are stored; the tools, guarantees, and behavior are the
same.

---

## What it does

- **Read tools** — system/version/HA info, running & candidate config, security
  and NAT rules, address/service objects and groups, security profiles, logs,
  job status, and uncommitted changes.
- **Write tools** (stage to candidate config) — create/delete address objects,
  address groups, service objects, tags, and security rules; reorder rules; and
  raw XPath `set`/`edit`/`delete` for anything not covered.
- **Commit lifecycle** — `validate_commit` (dry-run), `commit_config` (the only
  tool that affects production), `discard_changes` (revert candidate to running).
- **One info resource** (`config://firewall-info`) — connection details and
  write-mode status, built from env values; never echoes the API key.

Full tool tables live in the backend READMEs.

---

## Write safety (in one paragraph)

Writes are gated: `PANOS_ENABLE_WRITE` controls the whole write/commit surface,
and every mutating tool checks `_require_write()` before doing anything. The
gate **defaults to `no`** — the server behaves read-only regardless of the API
role until you explicitly set it to `yes`. Mutations
stage to the **candidate configuration** via a shared `_config_action()` helper
and **only `commit_config` pushes them live**; `validate_commit` dry-runs and
`discard_changes` reverts. Object names are validated before they reach an
XPath, and the API key lives in a secret store or a `chmod 600` `.env` — never in
chat or error strings. See [`docker/README.md` › Write Safety](docker/README.md#write-safety)
for the details and the recommended least-privilege firewall role.

---

## Repository layout

```
.
├── README.md      # you are here — overview + backend chooser
├── docker/        # Docker variant (multi-stage python:3.12-slim) + custom-catalog.yaml
└── podman/        # Podman variant, rootless
```

`docker/server.py` and `podman/server.py` are kept byte-identical
(`diff -q docker/server.py podman/server.py`).

---

## Configuration

All configuration is via environment variables (container secrets or an
`--env-file`). Required: `PANOS_HOST`, `PANOS_API_KEY`. Optional:
`PANOS_VERIFY_SSL`, `PANOS_VSYS`, and `PANOS_ENABLE_WRITE` (defaults to `no` —
read-only — set `yes` to enable writes). See `docker/.env.example` for the full
list and defaults.

The API key is generated **out of band** with `curl` (backend README, Step 0) —
never through this server.

---

## License

Provided as-is for integrating a Palo Alto firewall with MCP clients. Use at your
own risk. Not affiliated with or endorsed by Palo Alto Networks.
