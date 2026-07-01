#!/usr/bin/env python3
"""Palo Alto Firewall MCP Server — read AND write access to a PAN-OS firewall via the XML API."""

import os
import re
import sys
import signal
import logging
import asyncio
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging — all output goes to stderr so stdout stays clean for JSON-RPC
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("paloalto-firewall")


def _handle_sigterm(*_args):
    logger.info("Received SIGTERM — shutting down")
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)

mcp = FastMCP("paloalto-firewall")

# ---------------------------------------------------------------------------
# Safety — read-only operational command guard (used by run_show_command)
# ---------------------------------------------------------------------------

def _validate_readonly_op(cmd_xml: str) -> bool:
    """Return True only if the operational command is a safe read-only <show> command.

    The command must be well-formed XML whose root element is <show>. Mutating
    operational commands use a different root (<request>, <set>, <delete>,
    <commit>, <load>, <revert>, ...) and are rejected. Parsing the XML and
    matching the root tag is exact — unlike substring matching, it neither
    false-rejects a show command that merely mentions a blocked word in its
    body nor risks missing a mutating verb that isn't on a denylist.
    """
    try:
        root = ET.fromstring(cmd_xml.strip())
    except ET.ParseError:
        return False
    return root.tag.lower() == "show"


# ---------------------------------------------------------------------------
# Safety — input validation
# ---------------------------------------------------------------------------
# Names embedded inside XPath attribute values / element bodies are validated
# against this pattern to prevent breakouts. PAN-OS object names allow letters,
# digits, underscore, dot, hyphen, and spaces. Anything else is rejected.
_XPATH_NAME_RE = re.compile(r"^[A-Za-z0-9_.\- ]+$")
_PORT_RE = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$")
_COLOR_RE = re.compile(r"^color([1-9]|[1-3][0-9]|4[0-2])$")

ALLOWED_PROFILE_TYPES = {
    "virus", "spyware", "vulnerability", "url-filtering",
    "file-blocking", "wildfire-analysis", "data-filtering",
    "dns-security",
}
ALLOWED_ADDRESS_TYPES = {"ip-netmask", "ip-range", "ip-wildcard", "fqdn"}
ALLOWED_RULE_ACTIONS = {
    "allow", "deny", "drop", "reset-client", "reset-server", "reset-both",
}
ALLOWED_MOVE_WHERE = {"top", "bottom", "before", "after"}


def _validate_name(value: str, label: str) -> str:
    """Strip and validate a value embedded inside an XPath attribute / element name. Raise ValueError on rejection."""
    name = value.strip()
    if not name:
        raise ValueError(f"{label} is required")
    if len(name) > 128:
        raise ValueError(f"{label} is too long (max 128 chars)")
    if not _XPATH_NAME_RE.match(name):
        raise ValueError(
            f"{label} contains invalid characters "
            f"(allowed: letters, digits, underscore, dot, hyphen, space)"
        )
    return name


def _validate_xpath(xpath: str) -> str:
    """Lightweight check for raw XPath input — must start with /config and stay short of pathological lengths."""
    xp = xpath.strip()
    if not xp:
        raise ValueError("xpath is required")
    if not xp.startswith("/config"):
        raise ValueError("xpath must start with /config")
    if len(xp) > 1024:
        raise ValueError("xpath is too long (max 1024 chars)")
    return xp


def _validate_element(element: str) -> str:
    """Ensure a config element fragment is well-formed XML and reasonably sized."""
    el = element.strip()
    if not el:
        raise ValueError("element is required")
    if len(el) > 65536:
        raise ValueError("element is too long (max 65536 chars)")
    try:
        ET.fromstring(el)
    except ET.ParseError as e:
        raise ValueError(f"element is not well-formed XML: {e}")
    return el


def _members_xml(values: str, label: str) -> str:
    """Turn a comma-separated list into <member>..</member> XML, validating each name."""
    parts = [p.strip() for p in values.split(",") if p.strip()]
    if not parts:
        raise ValueError(f"{label} is required")
    out = []
    for p in parts:
        out.append(f"<member>{_xml_escape(_validate_name(p, label))}</member>")
    return "".join(out)


# ---------------------------------------------------------------------------
# Write gate
# ---------------------------------------------------------------------------

def _write_enabled() -> bool:
    return os.environ.get("PANOS_ENABLE_WRITE", "yes").strip().lower() not in ("no", "false", "0")


def _require_write():
    if not _write_enabled():
        raise ValueError("Write operations are disabled (set PANOS_ENABLE_WRITE=yes to enable)")


# ---------------------------------------------------------------------------
# vsys / xpath helpers
# ---------------------------------------------------------------------------

def _vsys() -> str:
    return os.environ.get("PANOS_VSYS", "vsys1").strip() or "vsys1"


def _vsys_base() -> str:
    return (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/vsys/entry[@name='{_vsys()}']"
    )


# ---------------------------------------------------------------------------
# Shared helper — make an XML API request to the firewall
# ---------------------------------------------------------------------------

def _extract_api_msg(root: ET.Element, default: str) -> str:
    """Pull a human-readable error/status message from a PAN-OS response.

    PAN-OS returns messages as either <msg>text</msg> or <msg><line>text</line></msg>
    (and sometimes a bare <line>). Element truthiness is unreliable here — an
    element with no children is falsy even when it carries text — so each
    candidate is checked explicitly.
    """
    for path in (".//msg/line", ".//line", ".//msg"):
        el = root.find(path)
        if el is not None and el.text and el.text.strip():
            return el.text.strip()
    return default


async def _panos_request(params: dict) -> ET.Element:
    """Make an API request to the firewall and return the parsed XML root."""
    host = os.environ.get("PANOS_HOST", "").strip()
    api_key = os.environ.get("PANOS_API_KEY", "").strip()
    verify_ssl = os.environ.get("PANOS_VERIFY_SSL", "yes").strip().lower() != "no"

    if not host:
        raise ValueError("PANOS_HOST environment variable is not set")
    if not api_key:
        raise ValueError("PANOS_API_KEY environment variable is not set")

    url = f"https://{host}/api/"
    headers = {"X-PAN-KEY": api_key}

    timeout = httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)
    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
        try:
            response = await client.post(url, data=params, headers=headers)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            status = root.attrib.get("status", "")
            if status != "success":
                raise ValueError(f"PAN-OS API error: {_extract_api_msg(root, 'request rejected')}")
            return root
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            if code in (401, 403):
                raise ValueError(f"HTTP {code}: authentication failed (check PANOS_API_KEY and admin role)")
            raise ValueError(f"HTTP {code}: request failed")
        except httpx.ConnectError:
            raise ValueError(f"Could not connect to firewall at {host}")
        except httpx.TimeoutException:
            raise ValueError("Timed out waiting for firewall response")
        except ET.ParseError:
            raise ValueError("Failed to parse XML response from firewall")


async def _poll_job(job_id: str, timeout: int = 180) -> ET.Element:
    """Poll an async PAN-OS job (commit / validate / log) until completion or timeout."""
    elapsed = 0
    while elapsed < timeout:
        root = await _panos_request(
            {"type": "op", "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>"}
        )
        status_el = root.find(".//job/status")
        if status_el is not None and status_el.text == "FIN":
            return root
        await asyncio.sleep(2)
        elapsed += 2
    raise ValueError(f"Job {job_id} did not complete within {timeout} seconds")


def _summarize_job_result(root: ET.Element) -> str:
    """Extract result/progress/details from a finished job element."""
    job = root.find(".//job")
    if job is None:
        return _xml_to_text(root)
    lines = []
    for tag in ["id", "type", "status", "result", "progress"]:
        el = job.find(tag)
        if el is not None and el.text:
            lines.append(f"  {tag}: {el.text}")
    details = job.find("details")
    if details is not None:
        for line_el in details.findall(".//line"):
            if line_el.text:
                lines.append(f"  detail: {line_el.text}")
        if not details.findall(".//line") and details.text and details.text.strip():
            lines.append(f"  detail: {details.text.strip()}")
    warnings = job.find(".//warnings")
    if warnings is not None:
        for line_el in warnings.findall(".//line"):
            if line_el.text:
                lines.append(f"  warning: {line_el.text}")
    return "\n".join(lines) if lines else _xml_to_text(job)


# ---------------------------------------------------------------------------
# Helper — format XML element tree into readable text
# ---------------------------------------------------------------------------

def _xml_to_text(element: ET.Element, indent: int = 0) -> str:
    """Convert an XML element to indented readable text."""
    lines = []
    tag = element.tag
    text = (element.text or "").strip()
    attribs = " ".join(f'{k}="{v}"' for k, v in element.attrib.items())

    prefix = "  " * indent
    header = f"{prefix}{tag}"
    if attribs:
        header += f" [{attribs}]"
    if text:
        header += f": {text}"

    lines.append(header)
    for child in element:
        lines.append(_xml_to_text(child, indent + 1))
    return "\n".join(lines)


def _format_rule_entry(entry: ET.Element) -> str:
    """Format a security/NAT rule entry into a readable string."""
    name = entry.attrib.get("name", "N/A")
    lines = [f"  Rule: {name}"]
    for tag in ["from", "to", "source", "destination", "application",
                "service", "action", "disabled", "log-start", "log-end",
                "description", "tag", "profile-setting",
                "source-translation", "destination-translation"]:
        el = entry.find(tag)
        if el is not None:
            members = el.findall("member")
            if members:
                vals = ", ".join(m.text or "" for m in members)
                lines.append(f"    {tag}: {vals}")
            elif el.text:
                lines.append(f"    {tag}: {el.text}")
            else:
                sub_text = _xml_to_text(el, 2)
                if sub_text.strip():
                    lines.append(sub_text)
    return "\n".join(lines)


async def _config_action(action: str, xpath: str, element: str = "") -> ET.Element:
    """Run a config write action (set/edit/delete) against the candidate config."""
    params = {"type": "config", "action": action, "xpath": xpath}
    if element:
        params["element"] = element
    return await _panos_request(params)


# ===========================================================================
# READ TOOLS
# ===========================================================================

@mcp.tool()
async def get_system_info() -> str:
    """Retrieve firewall system information (hostname, model, serial, version, uptime)."""
    try:
        root = await _panos_request(
            {"type": "op", "cmd": "<show><system><info></info></system></show>"}
        )
        info = root.find(".//system")
        if info is None:
            return "No system info found in response"
        lines = ["System Information:"]
        for child in info:
            if child.text:
                lines.append(f"  {child.tag}: {child.text}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_system_info: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_version_info() -> str:
    """Show PAN-OS version, serial number, and model."""
    try:
        root = await _panos_request({"type": "version"})
        result = root.find(".//result")
        if result is None:
            result = root
        lines = ["Version Information:"]
        for child in result:
            if child.text:
                lines.append(f"  {child.tag}: {child.text}")
        if len(lines) == 1:
            return f"Version Info:\n{_xml_to_text(result)}"
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_version_info: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_ha_status() -> str:
    """Retrieve high-availability status for the firewall."""
    try:
        root = await _panos_request(
            {"type": "op", "cmd": "<show><high-availability><all></all></high-availability></show>"}
        )
        result = root.find(".//result")
        if result is None:
            result = root
        return f"HA Status:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_ha_status: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def run_show_command(cmd_xml: str) -> str:
    """Run any read-only operational 'show' command on the firewall (cmd must start with <show>)."""
    if not cmd_xml.strip():
        return "Error: cmd_xml is required"
    if not _validate_readonly_op(cmd_xml):
        return "Error: Only read-only 'show' commands are allowed. The command must start with '<show>' and cannot contain blocked operations."
    try:
        root = await _panos_request({"type": "op", "cmd": cmd_xml.strip()})
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Command Output:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in run_show_command: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_running_config(xpath: str) -> str:
    """Retrieve the active (running) configuration for a specific XPath (must start with /config)."""
    try:
        xp = _validate_xpath(xpath)
        root = await _panos_request({"type": "config", "action": "show", "xpath": xp})
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Running Config ({xp}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_running_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_candidate_config(xpath: str) -> str:
    """Retrieve the candidate (uncommitted) configuration for a specific XPath (must start with /config)."""
    try:
        xp = _validate_xpath(xpath)
        root = await _panos_request({"type": "config", "action": "get", "xpath": xp})
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Candidate Config ({xp}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_candidate_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_security_rules() -> str:
    """Retrieve security policy rules from the firewall's active vsys."""
    try:
        xpath = f"{_vsys_base()}/rulebase/security/rules"
        root = await _panos_request({"type": "config", "action": "show", "xpath": xpath})
        entries = root.findall(".//rules/entry") or root.findall(".//entry")
        if not entries:
            return "No security rules found"
        lines = [f"Security Rules ({len(entries)} found):"]
        for entry in entries:
            lines.append(_format_rule_entry(entry))
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_security_rules: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_nat_rules() -> str:
    """Retrieve NAT policy rules from the firewall's active vsys."""
    try:
        xpath = f"{_vsys_base()}/rulebase/nat/rules"
        root = await _panos_request({"type": "config", "action": "show", "xpath": xpath})
        entries = root.findall(".//rules/entry") or root.findall(".//entry")
        if not entries:
            return "No NAT rules found"
        lines = [f"NAT Rules ({len(entries)} found):"]
        for entry in entries:
            lines.append(_format_rule_entry(entry))
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_nat_rules: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_address_objects() -> str:
    """Retrieve address objects from the firewall's active vsys."""
    try:
        xpath = f"{_vsys_base()}/address"
        root = await _panos_request({"type": "config", "action": "show", "xpath": xpath})
        entries = root.findall(".//address/entry") or root.findall(".//entry")
        if not entries:
            return "No address objects found"
        lines = [f"Address Objects ({len(entries)} found):"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            value = ""
            for tag in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]:
                el = entry.find(tag)
                if el is not None and el.text:
                    value = f"{tag}={el.text}"
                    break
            desc_el = entry.find("description")
            desc = f" — {desc_el.text}" if desc_el is not None and desc_el.text else ""
            lines.append(f"  {name}: {value}{desc}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_address_objects: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_address_groups() -> str:
    """Retrieve address group objects from the firewall's active vsys."""
    try:
        xpath = f"{_vsys_base()}/address-group"
        root = await _panos_request({"type": "config", "action": "show", "xpath": xpath})
        entries = root.findall(".//address-group/entry") or root.findall(".//entry")
        if not entries:
            return "No address groups found"
        lines = [f"Address Groups ({len(entries)} found):"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            static_members = entry.findall("static/member")
            dynamic_el = entry.find("dynamic/filter")
            if static_members:
                members = ", ".join(m.text or "" for m in static_members)
                lines.append(f"  {name} (static): {members}")
            elif dynamic_el is not None and dynamic_el.text:
                lines.append(f"  {name} (dynamic): filter={dynamic_el.text}")
            else:
                lines.append(f"  {name}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_address_groups: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_service_objects() -> str:
    """Retrieve service objects (custom protocol/port definitions) from the firewall's active vsys."""
    try:
        xpath = f"{_vsys_base()}/service"
        root = await _panos_request({"type": "config", "action": "show", "xpath": xpath})
        entries = root.findall(".//service/entry") or root.findall(".//entry")
        if not entries:
            return "No service objects found"
        lines = [f"Service Objects ({len(entries)} found):"]
        for entry in entries:
            name = entry.attrib.get("name", "N/A")
            parts = []
            for proto in ["tcp", "udp", "sctp"]:
                proto_el = entry.find(f"protocol/{proto}")
                if proto_el is not None:
                    port_el = proto_el.find("port")
                    src_port_el = proto_el.find("source-port")
                    port = port_el.text if port_el is not None and port_el.text else "any"
                    parts.append(f"{proto.upper()}/{port}")
                    if src_port_el is not None and src_port_el.text:
                        parts.append(f"src-port={src_port_el.text}")
            desc_el = entry.find("description")
            desc = f" — {desc_el.text}" if desc_el is not None and desc_el.text else ""
            lines.append(f"  {name}: {' '.join(parts)}{desc}")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_service_objects: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_security_profiles(profile_type: str) -> str:
    """Retrieve security profile configs (virus, spyware, vulnerability, url-filtering, file-blocking, wildfire-analysis, data-filtering, dns-security)."""
    try:
        pt = profile_type.strip()
        if pt not in ALLOWED_PROFILE_TYPES:
            return f"Error: profile_type must be one of: {', '.join(sorted(ALLOWED_PROFILE_TYPES))}"
        xpath = f"{_vsys_base()}/profiles/{pt}"
        root = await _panos_request({"type": "config", "action": "show", "xpath": xpath})
        result = root.find(".//result")
        if result is None:
            result = root
        return f"Security Profiles ({pt}):\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in get_security_profiles: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_logs(log_type: str, query: str = "", nlogs: str = "20", skip: str = "0", direction: str = "backward") -> str:
    """Retrieve logs from the firewall (traffic, threat, url, wildfire, config, system, globalprotect, etc.)."""
    if not log_type.strip():
        return "Error: log_type is required (traffic, threat, url, wildfire, data, config, system, globalprotect, hipmatch, auth, decryption, userid, iptag)"
    try:
        # Stage 1 — enqueue the query job. `skip` is a paging parameter for the
        # fetch call only; PAN-OS rejects it on the enqueue request.
        params = {
            "type": "log",
            "log-type": log_type.strip(),
            "nlogs": nlogs.strip() or "20",
            "dir": direction.strip() or "backward",
        }
        if query.strip():
            params["query"] = query.strip()

        root = await _panos_request(params)
        job_el = root.find(".//job")
        if job_el is None or not job_el.text:
            return "Error: No job ID returned from log query"
        job_id = job_el.text.strip()
        logger.info(f"Log query job initiated: {job_id}")

        # Stage 2 — fetch results from the LOG endpoint (type=log&action=get).
        # The op `show jobs` command reports a log job's status but never carries
        # the log rows, so results must be read from this call.
        fetch_params = {"type": "log", "action": "get", "job-id": job_id}
        if skip.strip() and skip.strip() != "0":
            fetch_params["skip"] = skip.strip()

        elapsed, timeout, result_root = 0, 180, None
        while elapsed < timeout:
            result_root = await _panos_request(fetch_params)
            status_el = result_root.find(".//job/status")
            if status_el is not None and status_el.text == "FIN":
                break
            await asyncio.sleep(2)
            elapsed += 2
        else:
            return f"Error: log job {job_id} did not finish within {timeout}s"

        log_entries = result_root.findall(".//log/logs/entry") or result_root.findall(".//logs/entry")
        if not log_entries:
            count_el = result_root.find(".//logs")
            count = count_el.attrib.get("count", "0") if count_el is not None else "0"
            if count == "0":
                return f"No {log_type} logs found matching the query"
            return f"Log query completed but no entries parsed. Raw:\n{_xml_to_text(result_root)}"

        lines = [f"{log_type.capitalize()} Logs ({len(log_entries)} entries):"]
        for entry in log_entries:
            lines.append("")
            for child in entry:
                if child.text:
                    lines.append(f"  {child.tag}: {child.text}")
            lines.append("  ---")
        return "\n".join(lines)
    except Exception as e:
        logger.error(f"Error in get_logs: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_job_status(job_id: str) -> str:
    """Check the status of an asynchronous job (commit, log, report) by its ID."""
    if not job_id.strip():
        return "Error: job_id is required"
    try:
        jid = _validate_name(job_id, "job_id")
        root = await _panos_request(
            {"type": "op", "cmd": f"<show><jobs><id>{jid}</id></jobs></show>"}
        )
        return f"Job {jid} Status:\n{_summarize_job_result(root)}"
    except Exception as e:
        logger.error(f"Error in get_job_status: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_uncommitted_changes() -> str:
    """Show a summary of changes between the running and candidate configuration (uncommitted edits)."""
    try:
        root = await _panos_request(
            {"type": "op", "cmd": "<show><config><list><change-summary></change-summary></list></config></show>"}
        )
        result = root.find(".//result")
        if result is None:
            result = root
        text = _xml_to_text(result)
        if not text.strip() or text.strip() == "result":
            return "No uncommitted changes detected"
        return f"Uncommitted Changes:\n{text}"
    except Exception as e:
        logger.error(f"Error in get_uncommitted_changes: {e}")
        return f"Error: {str(e)}"


# ===========================================================================
# WRITE TOOLS — structured object / policy management (candidate config)
# ===========================================================================

@mcp.tool()
async def create_address_object(name: str, addr_type: str, value: str, description: str = "", tags: str = "") -> str:
    """Create or update an address object. addr_type: ip-netmask, ip-range, ip-wildcard, or fqdn. Stages to candidate config (commit separately)."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        at = addr_type.strip().lower()
        if at not in ALLOWED_ADDRESS_TYPES:
            return f"Error: addr_type must be one of: {', '.join(sorted(ALLOWED_ADDRESS_TYPES))}"
        val = value.strip()
        if not val:
            return "Error: value is required"
        if len(val) > 256:
            return "Error: value is too long"
        element = f"<{at}>{_xml_escape(val)}</{at}>"
        if description.strip():
            element += f"<description>{_xml_escape(description.strip())}</description>"
        if tags.strip():
            element += f"<tag>{_members_xml(tags, 'tags')}</tag>"
        xpath = f"{_vsys_base()}/address/entry[@name='{nm}']"
        await _config_action("set", xpath, element)
        return f"Address object '{nm}' staged ({at}={val}). Call validate_commit / commit_config to apply."
    except Exception as e:
        logger.error(f"Error in create_address_object: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def delete_address_object(name: str) -> str:
    """Delete an address object from the candidate config (commit separately)."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        xpath = f"{_vsys_base()}/address/entry[@name='{nm}']"
        await _config_action("delete", xpath)
        return f"Address object '{nm}' deleted from candidate config. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in delete_address_object: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def create_address_group(name: str, members: str = "", dynamic_filter: str = "", description: str = "", tags: str = "") -> str:
    """Create or update an address group. Provide either members (comma-separated, static group) or dynamic_filter (DAG). Stages to candidate config."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        if members.strip() and dynamic_filter.strip():
            return "Error: provide either members (static) or dynamic_filter (dynamic), not both"
        if members.strip():
            element = f"<static>{_members_xml(members, 'members')}</static>"
        elif dynamic_filter.strip():
            df = dynamic_filter.strip()
            if len(df) > 1024:
                return "Error: dynamic_filter is too long"
            element = f"<dynamic><filter>{_xml_escape(df)}</filter></dynamic>"
        else:
            return "Error: provide either members or dynamic_filter"
        if description.strip():
            element += f"<description>{_xml_escape(description.strip())}</description>"
        if tags.strip():
            element += f"<tag>{_members_xml(tags, 'tags')}</tag>"
        xpath = f"{_vsys_base()}/address-group/entry[@name='{nm}']"
        await _config_action("set", xpath, element)
        return f"Address group '{nm}' staged. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in create_address_group: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def delete_address_group(name: str) -> str:
    """Delete an address group from the candidate config (commit separately)."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        xpath = f"{_vsys_base()}/address-group/entry[@name='{nm}']"
        await _config_action("delete", xpath)
        return f"Address group '{nm}' deleted from candidate config. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in delete_address_group: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def create_service_object(name: str, protocol: str, port: str, source_port: str = "", description: str = "") -> str:
    """Create or update a service object. protocol: tcp or udp. port: e.g. '443', '80,443', or '1000-2000'. Stages to candidate config."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        proto = protocol.strip().lower()
        if proto not in ("tcp", "udp"):
            return "Error: protocol must be 'tcp' or 'udp'"
        prt = port.strip()
        if not _PORT_RE.match(prt):
            return "Error: port must be a number, range (1000-2000), or list (80,443)"
        inner = f"<port>{prt}</port>"
        if source_port.strip():
            sp = source_port.strip()
            if not _PORT_RE.match(sp):
                return "Error: source_port must be a number, range, or list"
            inner += f"<source-port>{sp}</source-port>"
        element = f"<protocol><{proto}>{inner}</{proto}></protocol>"
        if description.strip():
            element += f"<description>{_xml_escape(description.strip())}</description>"
        xpath = f"{_vsys_base()}/service/entry[@name='{nm}']"
        await _config_action("set", xpath, element)
        return f"Service object '{nm}' staged ({proto}/{prt}). Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in create_service_object: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def delete_service_object(name: str) -> str:
    """Delete a service object from the candidate config (commit separately)."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        xpath = f"{_vsys_base()}/service/entry[@name='{nm}']"
        await _config_action("delete", xpath)
        return f"Service object '{nm}' deleted from candidate config. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in delete_service_object: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def create_tag(name: str, color: str = "", comments: str = "") -> str:
    """Create or update a tag object. color: e.g. 'color1'..'color42'. Stages to candidate config."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        element = ""
        if color.strip():
            c = color.strip().lower()
            if not _COLOR_RE.match(c):
                return "Error: color must be 'color1' through 'color42'"
            element += f"<color>{c}</color>"
        if comments.strip():
            element += f"<comments>{_xml_escape(comments.strip())}</comments>"
        if not element:
            element = "<color>color1</color>"
        xpath = f"{_vsys_base()}/tag/entry[@name='{nm}']"
        await _config_action("set", xpath, element)
        return f"Tag '{nm}' staged. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in create_tag: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def create_security_rule(
    name: str,
    from_zones: str,
    to_zones: str,
    source: str,
    destination: str,
    application: str = "any",
    service: str = "application-default",
    action: str = "allow",
    description: str = "",
    log_end: str = "yes",
    disabled: str = "no",
    tags: str = "",
) -> str:
    """Create or update a security policy rule. Zone/source/destination/application/service are comma-separated ('any' allowed). action: allow/deny/drop/reset-client/reset-server/reset-both. Stages to candidate config."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        act = action.strip().lower()
        if act not in ALLOWED_RULE_ACTIONS:
            return f"Error: action must be one of: {', '.join(sorted(ALLOWED_RULE_ACTIONS))}"
        element = (
            f"<from>{_members_xml(from_zones, 'from_zones')}</from>"
            f"<to>{_members_xml(to_zones, 'to_zones')}</to>"
            f"<source>{_members_xml(source, 'source')}</source>"
            f"<destination>{_members_xml(destination, 'destination')}</destination>"
            f"<application>{_members_xml(application or 'any', 'application')}</application>"
            f"<service>{_members_xml(service or 'application-default', 'service')}</service>"
            f"<action>{act}</action>"
        )
        element += f"<log-end>{'yes' if log_end.strip().lower() != 'no' else 'no'}</log-end>"
        element += f"<disabled>{'yes' if disabled.strip().lower() == 'yes' else 'no'}</disabled>"
        if description.strip():
            element += f"<description>{_xml_escape(description.strip())}</description>"
        if tags.strip():
            element += f"<tag>{_members_xml(tags, 'tags')}</tag>"
        xpath = f"{_vsys_base()}/rulebase/security/rules/entry[@name='{nm}']"
        await _config_action("set", xpath, element)
        return f"Security rule '{nm}' staged ({act}). Call validate_commit / commit_config to apply."
    except Exception as e:
        logger.error(f"Error in create_security_rule: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def delete_security_rule(name: str) -> str:
    """Delete a security policy rule from the candidate config (commit separately)."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        xpath = f"{_vsys_base()}/rulebase/security/rules/entry[@name='{nm}']"
        await _config_action("delete", xpath)
        return f"Security rule '{nm}' deleted from candidate config. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in delete_security_rule: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def move_security_rule(name: str, where: str, dst_rule: str = "") -> str:
    """Reorder a security rule. where: top, bottom, before, or after. dst_rule is required for before/after. Stages to candidate config."""
    try:
        _require_write()
        nm = _validate_name(name, "name")
        wh = where.strip().lower()
        if wh not in ALLOWED_MOVE_WHERE:
            return f"Error: where must be one of: {', '.join(sorted(ALLOWED_MOVE_WHERE))}"
        params = {
            "type": "config",
            "action": "move",
            "xpath": f"{_vsys_base()}/rulebase/security/rules/entry[@name='{nm}']",
            "where": wh,
        }
        if wh in ("before", "after"):
            if not dst_rule.strip():
                return f"Error: dst_rule is required when where={wh}"
            params["dst"] = _validate_name(dst_rule, "dst_rule")
        await _panos_request(params)
        return f"Security rule '{nm}' moved ({wh}). Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in move_security_rule: {e}")
        return f"Error: {str(e)}"


# ===========================================================================
# WRITE TOOLS — generic config edit (advanced, raw XPath)
# ===========================================================================

@mcp.tool()
async def set_config(xpath: str, element: str) -> str:
    """ADVANCED: Merge an XML element into the candidate config at the given XPath (PAN-OS action=set). element must be a well-formed XML fragment. Commit separately."""
    try:
        _require_write()
        xp = _validate_xpath(xpath)
        el = _validate_element(element)
        await _config_action("set", xp, el)
        return f"set applied to candidate config at {xp}. Call validate_commit / commit_config to apply."
    except Exception as e:
        logger.error(f"Error in set_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def edit_config(xpath: str, element: str) -> str:
    """ADVANCED: Replace the node at the given XPath with the supplied XML element (PAN-OS action=edit). Replaces the entire subtree — use carefully. Commit separately."""
    try:
        _require_write()
        xp = _validate_xpath(xpath)
        el = _validate_element(element)
        await _config_action("edit", xp, el)
        return f"edit applied to candidate config at {xp}. Call validate_commit / commit_config to apply."
    except Exception as e:
        logger.error(f"Error in edit_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def delete_config(xpath: str) -> str:
    """ADVANCED: Delete the node at the given XPath from the candidate config (PAN-OS action=delete). Commit separately."""
    try:
        _require_write()
        xp = _validate_xpath(xpath)
        await _config_action("delete", xp)
        return f"delete applied to candidate config at {xp}. Call commit_config to apply."
    except Exception as e:
        logger.error(f"Error in delete_config: {e}")
        return f"Error: {str(e)}"


# ===========================================================================
# WRITE TOOLS — commit lifecycle
# ===========================================================================

@mcp.tool()
async def validate_commit() -> str:
    """Dry-run validate the candidate configuration without committing. Reports errors/warnings before you commit."""
    try:
        _require_write()
        root = await _panos_request(
            {"type": "op", "cmd": "<validate><full></full></validate>"}
        )
        job_el = root.find(".//job")
        if job_el is None or not job_el.text:
            result = root.find(".//result")
            if result is None:
                result = root
            return f"Validation result:\n{_xml_to_text(result)}"
        job_id = job_el.text
        logger.info(f"Validate job initiated: {job_id}")
        result_root = await _poll_job(job_id)
        return f"Validation (job {job_id}):\n{_summarize_job_result(result_root)}"
    except Exception as e:
        logger.error(f"Error in validate_commit: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def commit_config(description: str = "") -> str:
    """Commit the candidate configuration to make it live. This is the only tool that pushes staged changes into production. Polls until the commit job finishes."""
    try:
        _require_write()
        if description.strip():
            cmd = f"<commit><description>{_xml_escape(description.strip())}</description></commit>"
        else:
            cmd = "<commit></commit>"
        root = await _panos_request({"type": "commit", "cmd": cmd})
        job_el = root.find(".//job")
        if job_el is None or not job_el.text:
            msg = _extract_api_msg(root, "no job returned")
            return f"Commit returned no job: {msg} (often means there were no changes to commit)"
        job_id = job_el.text
        logger.info(f"Commit job initiated: {job_id}")
        result_root = await _poll_job(job_id, timeout=600)
        return f"Commit (job {job_id}):\n{_summarize_job_result(result_root)}"
    except Exception as e:
        logger.error(f"Error in commit_config: {e}")
        return f"Error: {str(e)}"


@mcp.tool()
async def discard_changes() -> str:
    """Discard all uncommitted candidate-config changes and revert to the running config. Does NOT touch the live config."""
    try:
        _require_write()
        root = await _panos_request(
            {"type": "op", "cmd": "<revert><config></config></revert>"}
        )
        result = root.find(".//result")
        if result is None:
            result = root.find(".//msg")
        if result is None:
            result = root
        text = _xml_to_text(result).strip()
        return f"Candidate changes discarded (reverted to running config).\n{text}"
    except Exception as e:
        logger.error(f"Error in discard_changes: {e}")
        return f"Error: {str(e)}"


# ---------------------------------------------------------------------------
# Resource — firewall connection info
# ---------------------------------------------------------------------------

@mcp.resource("config://firewall-info")
def firewall_info() -> str:
    """Current firewall connection details and write-mode status."""
    host = os.environ.get("PANOS_HOST", "(not set)")
    verify = os.environ.get("PANOS_VERIFY_SSL", "yes")
    key_set = "yes" if os.environ.get("PANOS_API_KEY", "").strip() else "no"
    write = "enabled" if _write_enabled() else "disabled"
    return (
        f"Host: {host}\nAPI Key configured: {key_set}\n"
        f"SSL Verification: {verify}\nVsys: {_vsys()}\nWrite mode: {write}"
    )


# ---------------------------------------------------------------------------
# Startup checks
# ---------------------------------------------------------------------------

def _startup_checks():
    host = os.environ.get("PANOS_HOST", "").strip()
    api_key = os.environ.get("PANOS_API_KEY", "").strip()
    if not host:
        logger.warning("PANOS_HOST is not set — tools will fail until it is configured")
    if not api_key:
        logger.warning("PANOS_API_KEY is not set — generate one out of band (see README, Step 0)")
    if os.environ.get("PANOS_VERIFY_SSL", "yes").strip().lower() == "no":
        logger.info("SSL verification is DISABLED (PANOS_VERIFY_SSL=no)")
    logger.info(f"Write mode is {'ENABLED' if _write_enabled() else 'DISABLED'} (PANOS_ENABLE_WRITE)")
    logger.info("Palo Alto Firewall MCP Server starting up")


if __name__ == "__main__":
    _startup_checks()
    mcp.run(transport="stdio")
