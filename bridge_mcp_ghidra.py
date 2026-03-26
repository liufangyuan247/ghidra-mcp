# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "mcp>=1.2.0,<2",
# ]
# ///
"""
GhidraMCP Bridge — thin MCP↔HTTP multiplexer.

On startup: exposes list_instances + connect_instance.
On connect_instance: fetches /mcp/schema from the Ghidra server,
dynamically registers every tool. All dynamic tools are generic HTTP dispatchers.

Supports two transports to Ghidra:
  - UDS (Unix domain sockets) — preferred for local instances
  - TCP (HTTP) — fallback for headless/remote servers
"""

import argparse
import asyncio
import json
import logging
import os
import re
import socket
import time
import http.client
import inspect
from pathlib import Path
from urllib.parse import urlencode

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.lowlevel.server import NotificationOptions

# ==========================================================================
# Configuration
# ==========================================================================

REQUEST_TIMEOUT = 30

# Per-endpoint timeout overrides for expensive operations
ENDPOINT_TIMEOUTS = {
    "batch_rename_variables": 120,
    "batch_set_comments": 120,
    "analyze_function_complete": 120,
    "batch_rename_function_components": 120,
    "batch_set_variable_types": 90,
    "analyze_data_region": 90,
    "batch_create_labels": 60,
    "batch_delete_labels": 60,
    "disassemble_bytes": 120,
    "bulk_fuzzy_match": 180,
    "find_similar_functions_fuzzy": 60,
    "import_file": 300,
    "run_ghidra_script": 1800,
    "run_script_inline": 1800,
    "decompile_function": 45,
    "set_function_prototype": 45,
    "rename_function": 45,
    "rename_function_by_address": 45,
    "consolidate_duplicate_types": 60,
    "batch_analyze_completeness": 120,
    "apply_function_documentation": 60,
    "default": 30,
}

DEFAULT_TCP_URL = "http://127.0.0.1:8089"

# Logging
LOG_LEVEL = os.getenv("GHIDRA_MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global state
mcp = FastMCP("ghidra-mcp")

# Enable tools/list_changed notifications so clients re-fetch tools after dynamic registration
_orig_init_options = mcp._mcp_server.create_initialization_options
def _patched_init_options(**kwargs):
    return _orig_init_options(
        notification_options=NotificationOptions(tools_changed=True), **kwargs)
mcp._mcp_server.create_initialization_options = _patched_init_options

_active_socket: str | None = None  # UDS socket path
_active_tcp: str | None = None  # TCP base URL (e.g. "http://127.0.0.1:8089")
_transport_mode: str = "none"  # "uds", "tcp", or "none"
_connected_project: str | None = None  # Project name for auto-reconnect


# ==========================================================================
# UDS Transport
# ==========================================================================


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP connection over a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: int = 30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def get_socket_dir() -> Path:
    """Get the GhidraMCP socket runtime directory."""
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "ghidra-mcp"
    user = os.getenv("USER", "unknown")
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir:
        return Path(tmpdir) / f"ghidra-mcp-{user}"
    return Path(f"/tmp/ghidra-mcp-{user}")


# Enhanced error classes
class GhidraConnectionError(Exception):
    """Raised when connection to Ghidra server fails"""
    pass


class GhidraAnalysisError(Exception):
    """Raised when Ghidra analysis operation fails"""
    pass


class GhidraValidationError(Exception):
    """Raised when input validation fails"""
    pass


# Input validation patterns
HEX_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
SEGMENT_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*:[0-9a-fA-F]+$")
# Handles space:0xHEX form (e.g., mem:0x1000, code:0xFF00).
# Must be checked BEFORE SEGMENT_ADDRESS_PATTERN because the 'x' in '0x' is not
# in [0-9a-fA-F], so the existing pattern rejects this form entirely.
SEGMENT_ADDR_WITH_0X_PATTERN = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*):0[xX]([0-9a-fA-F]+)$"
)
FUNCTION_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # Running but owned by another user
    except OSError as e:
        # Windows may raise WinError 87 for obviously invalid PIDs.
        if getattr(e, "winerror", None) == 87:
            return False
        raise


def validate_server_url(url: str) -> bool:
    """Validate that the server URL is safe to use"""
    try:
        parsed = urlparse(url)
        return parsed.hostname in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


def validate_hex_address(address: str) -> bool:
    """Validate that an address string looks like a valid hex address or segment:offset."""
    if not address:
        return False
    if SEGMENT_ADDR_WITH_0X_PATTERN.match(address):
        return True
    if SEGMENT_ADDRESS_PATTERN.match(address):
        return True
    return bool(HEX_ADDRESS_PATTERN.match(address))


def uds_request(
    socket_path: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over a Unix domain socket. Returns (body, status)."""
    conn = UnixHTTPConnection(socket_path, timeout=timeout)
    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = {}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return result, status
    except Exception:
        conn.close()
        raise


# ==========================================================================
# TCP Transport
# ==========================================================================


def tcp_request(
    base_url: str,
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Make an HTTP request over TCP. Returns (body, status)."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)

    path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if params:
        path = f"{path}?{urlencode(params)}"

    headers = {}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if body:
        headers["Content-Length"] = str(len(body))

    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.read().decode("utf-8")
        status = response.status
        conn.close()
        return result, status
    except Exception:
        conn.close()
        raise


# ==========================================================================
# Unified request function
# ==========================================================================


def do_request(
    method: str,
    endpoint: str,
    params: dict | None = None,
    json_data: dict | None = None,
    timeout: int = 30,
) -> tuple[str, int]:
    """Route request to the active transport (UDS or TCP)."""
    if _transport_mode == "uds" and _active_socket:
        return uds_request(_active_socket, method, endpoint, params, json_data, timeout)
    elif _transport_mode == "tcp" and _active_tcp:
        return tcp_request(_active_tcp, method, endpoint, params, json_data, timeout)
    else:
        raise ConnectionError("No Ghidra instance connected. Use connect_instance() first.")


# ==========================================================================
# Instance discovery
# ==========================================================================


def _unwrap_response_payload(text: str) -> dict:
    """Parse a JSON response and unwrap Response.ok() payloads when present."""
    data = json.loads(text)
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    if isinstance(data, dict):
        return data
    raise ValueError("Response body is not a JSON object")


def _build_tcp_synthetic_instance(base_url: str, text: str) -> dict:
    """Build a synthetic TCP instance record from a reachable plain-text probe."""
    message = text.strip()
    info: dict = {
        "url": base_url,
        "transport": "tcp",
        "project": "tcp",
        "connected": True,
    }
    if message:
        info["status"] = message
    return info


def _probe_uds_instance(socket_path: str, pid: int) -> dict:
    """Collect best-effort instance metadata from a UDS server."""
    info: dict = {"socket": socket_path, "pid": pid, "transport": "uds"}

    try:
        text, status = uds_request(socket_path, "GET", "/mcp/instance_info", timeout=5)
        if status == 200:
            info.update(_unwrap_response_payload(text))
            return info
        logger.debug(f"UDS instance_info unavailable on {socket_path}: HTTP {status}")
    except Exception as e:
        logger.debug(f"UDS instance_info probe failed for {socket_path}: {e}")

    try:
        text, status = uds_request(socket_path, "GET", "/check_connection", timeout=5)
        if status == 200:
            payload = _unwrap_response_payload(text)
            if isinstance(payload, dict):
                info.update(payload)
    except Exception as e:
        logger.debug(f"UDS check_connection probe failed for {socket_path}: {e}")

    return info


def _probe_tcp_instance(base_url: str) -> dict | None:
    """Collect best-effort instance metadata from a TCP server."""
    info: dict = {"url": base_url, "transport": "tcp"}

    try:
        text, status = tcp_request(base_url, "GET", "/mcp/instance_info", timeout=5)
        if status == 200:
            info.update(_unwrap_response_payload(text))
            return info
        logger.debug(f"TCP instance_info unavailable on {base_url}: HTTP {status}")
    except Exception as e:
        logger.debug(f"TCP instance_info probe failed for {base_url}: {e}")

    try:
        text, status = tcp_request(base_url, "GET", "/check_connection", timeout=5)
        if status != 200:
            logger.debug(f"TCP check_connection failed for {base_url}: HTTP {status}")
            return None
        try:
            payload = _unwrap_response_payload(text)
        except (json.JSONDecodeError, ValueError):
            logger.debug(f"TCP check_connection returned plain text for {base_url}; using synthetic instance")
            return _build_tcp_synthetic_instance(base_url, text)
        if isinstance(payload, dict):
            info.update(payload)
        info.setdefault("project", payload.get("project_name") or payload.get("project") or "tcp")
        return info
    except Exception as e:
        logger.debug(f"TCP check_connection probe failed for {base_url}: {e}")
        return None


def discover_instances() -> list[dict]:
    """Discover reachable Ghidra instances over UDS and TCP."""
    instances = []

    socket_dir = get_socket_dir()
    if socket_dir.exists():
        for sock_file in sorted(socket_dir.glob("*.sock")):
            name = sock_file.stem  # ghidra-<pid>
            dash = name.rfind("-")
            if dash < 0:
                continue
            try:
                pid = int(name[dash + 1:])
            except ValueError:
                continue

            if not is_pid_alive(pid):
                logger.debug(f"Cleaning up stale socket: {sock_file}")
                try:
                    sock_file.unlink(missing_ok=True)
                except OSError:
                    pass
                continue

            instances.append(_probe_uds_instance(str(sock_file), pid))

    tcp_url = os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    if tcp_url:
        tcp_info = _probe_tcp_instance(tcp_url)
        if tcp_info:
            instances.append(tcp_info)

    return instances


# ==========================================================================
# HTTP dispatch
# ==========================================================================


def get_timeout(endpoint: str, payload: dict | None = None) -> int:
    """Get timeout for an endpoint, with dynamic scaling for batch ops."""
    name = endpoint.strip("/").split("/")[-1]
    base = ENDPOINT_TIMEOUTS.get(name, ENDPOINT_TIMEOUTS["default"])

    if not payload:
        return base

    if name == "batch_rename_variables":
        count = len(payload.get("variable_renames", {}))
        return min(base + count * 38, 600)

    if name == "batch_set_comments":
        count = len(payload.get("decompiler_comments", []))
        count += len(payload.get("disassembly_comments", []))
        count += 1 if payload.get("plate_comment") else 0
        return min(base + count * 8, 600)

    return base


def _activate_instance(instance: dict) -> None:
    """Set active transport globals from a discovered instance record."""
    global _active_socket, _active_tcp, _transport_mode

    transport = instance.get("transport")
    if transport == "uds" and instance.get("socket"):
        _active_socket = instance["socket"]
        _active_tcp = None
        _transport_mode = "uds"
        return
    if transport == "tcp" and instance.get("url"):
        _active_tcp = instance["url"]
        _active_socket = None
        _transport_mode = "tcp"
        return
    raise ValueError(f"Unsupported instance record: {instance}")


def _try_reconnect() -> bool:
    """Try to reconnect to the previously connected project after Ghidra restarts.

    Scans discovered instances matching _connected_project. If found, updates the
    active transport and re-fetches the schema. Returns True if reconnected.
    """
    global _active_socket, _active_tcp, _transport_mode

    if not _connected_project:
        return False

    instances = discover_instances()
    for inst in instances:
        if inst.get("project", "") == _connected_project:
            try:
                _activate_instance(inst)
                _fetch_and_register_schema()
                logger.info(
                    f"Reconnected to project '{_connected_project}' via "
                    f"{inst.get('socket') or inst.get('url')}"
                )
                return True
            except Exception as e:
                logger.warning(f"Reconnect schema fetch failed: {e}")
                return False

    # Exact match failed, try substring
    for inst in instances:
        if _connected_project.lower() in inst.get("project", "").lower():
            try:
                _activate_instance(inst)
                logger.info(
                    f"Reconnected to project '{inst.get('project')}' via "
                    f"{inst.get('socket') or inst.get('url')}"
                )
                _fetch_and_register_schema()
                return True
            except Exception as e:
                logger.warning(f"Reconnect schema fetch failed: {e}")
                return False

    return False


def _ensure_connected() -> str | None:
    """Check connection and attempt reconnect if needed. Returns error string or None."""
    if _transport_mode == "none":
        if _connected_project:
            if _try_reconnect():
                return None
            return (f"Ghidra instance for project '{_connected_project}' is not running. "
                    "Start Ghidra and open the project, then retry.")
        return "No Ghidra instance connected. Use connect_instance() first."
    return None


def sanitize_address(address: str) -> str:
    """Normalize address format for Ghidra AddressFactory.

    Handles:
    - space:0xHEX  -> space:HEX   (strip 0x from offset; AddressFactory rejects 0x after colon)
    - SPACE:HEX    -> space:HEX   (lowercase space name; AddressFactory is case-sensitive)
    - 0xHEX        -> 0xhex       (lowercase)
    - HEX          -> 0xHEX       (add 0x prefix)
    """
    if not address:
        return address
    address = address.strip()

    # Step 1: handle space:0xHEX form (checked first — 'x' not in [0-9a-fA-F])
    m = SEGMENT_ADDR_WITH_0X_PATTERN.match(address)
    if m:
        # Lowercase space name; preserve offset case (AddressFactory handles hex case)
        return f"{m.group(1).lower()}:{m.group(2)}"

    # Step 2: normalize valid space:HEX form (lowercase space name only)
    if SEGMENT_ADDRESS_PATTERN.match(address):
        space, offset = address.split(":", 1)
        return f"{space.lower()}:{offset}"

    # Step 3: plain hex normalization (unchanged logic)
    if not address.startswith(("0x", "0X")):
        address = "0x" + address
    return address.lower()


def dispatch_get(endpoint: str, params: dict | None = None, retries: int = 3) -> str:
    """GET request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint)
    for attempt in range(retries):
        try:
            text, status = do_request("GET", endpoint, params=params, timeout=timeout)
            if status == 200:
                return text
            if status >= 500 and attempt < retries - 1:
                time.sleep(2**attempt)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


def dispatch_post(endpoint: str, data: dict, retries: int = 3) -> str:
    """POST JSON request via active transport. Returns raw response text."""
    err = _ensure_connected()
    if err:
        return json.dumps({"error": err})

    timeout = get_timeout(endpoint, data)
    for attempt in range(retries):
        try:
            text, status = do_request("POST", endpoint, json_data=data, timeout=timeout)
            if status == 200:
                return text.strip()
            if status >= 500 and attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": f"HTTP {status}: {text.strip()}"})
        except (ConnectionError, OSError) as e:
            # Connection lost — try reconnect once, then retry
            if attempt == 0 and _try_reconnect():
                continue
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
                continue
            return json.dumps({"error": str(e)})

    return json.dumps({"error": "Max retries exceeded"})


# ==========================================================================
# Schema parsing — converts upstream /mcp/schema to internal tool defs
# ==========================================================================

# JSON type → Python type mapping
_TYPE_MAP = {
    "string": str,
    "json": str,
    "integer": int,
    "boolean": bool,
    "number": float,
    "object": dict,
    "array": list,
    "any": str,
    "address": str,
}


def _parse_schema(raw: dict) -> tuple[list[dict], dict[str, str], dict[str, str]]:
    """Convert upstream AnnotationScanner schema to internal tool defs + grouping metadata.

    Upstream format: {"tools": [{"path", "method", "description", "category", "params": [...]}]}
    Internal format: [{"name", "endpoint", "http_method", "description", "input_schema"}]
    """
    tool_defs = []
    tool_groups: dict[str, str] = {}
    group_descriptions: dict[str, str] = {}

    for tool in raw.get("tools", []):
        path = tool["path"]
        name = path.lstrip("/")
        params = tool.get("params", [])

        properties = {}
        required_list = [] # 用一个列表收集必填项

        if isinstance(params, list):
            for p in params:
                p_name = p.get("name")
                if not p_name: continue
                pdef: dict = {"type": p.get("type", "string")}
                if p.get("description"):
                    pdef["description"] = p["description"]
                if "default" in p and p["default"] is not None:
                    pdef["default"] = p["default"]
                properties[p["name"]] = pdef
                if p.get("required") is True:
                    required_list.append(p_name)

        # --- 核心修复逻辑 ---
        input_schema = {
            "type": "object",
            "properties": properties
        }
        
        # 只有当必填项列表【不为空】时，才添加 required 键
        # 如果 required_list 是空的，OpenAI 要求根本不要出现这个键
        if required_list:
            input_schema["required"] = required_list
        # -------------------

        tool_def = {
            "name": name,
            "endpoint": path,
            "http_method": tool.get("method", "GET"),
            "description": tool.get("description", ""),
            "input_schema": input_schema,
        }
        group_name = tool.get("category", "unknown")
        tool_groups[name] = group_name
        if group_name not in group_descriptions and tool.get("category_description"):
            group_descriptions[group_name] = tool["category_description"]

        tool_defs.append(tool_def)
    return tool_defs, tool_groups, group_descriptions

# ==========================================================================
# Dynamic tool registration from /mcp/schema
# ==========================================================================

# Static tool names that should not be overwritten by dynamic registration
STATIC_TOOL_NAMES = {"list_instances", "connect_instance", "list_tool_groups",
                     "load_tool_group", "unload_tool_group", "import_file"}

_dynamic_tool_names: list[str] = []
_full_schema: list[dict] = []  # Complete parsed schema
_loaded_groups: set[str] = set()
_tool_groups: dict[str, str] = {}
_tool_group_descriptions: dict[str, str] = {}

# Core groups always loaded on connect (essential for basic RE workflow)
CORE_GROUPS = {"listing", "function", "program"}

# CLI-configurable: --lazy keeps only default groups, otherwise load all
_lazy_mode = True  # default: lazy (only load default groups on connect)
_default_groups: set[str] = CORE_GROUPS


def _build_tool_function(endpoint: str, http_method: str, params_schema: dict):
    """Build a callable that dispatches to the Ghidra HTTP endpoint."""
    properties = params_schema.get("properties", {})
    required = set(params_schema.get("required", []))
    synthetic_noarg_param = "unused"

    def handler(**kwargs):
# <<<<<<< HEAD
        # Sanitize address parameters before dispatch
        for pname, pdef in properties.items():
            if pdef.get("paramType") == "address" and pname in kwargs and kwargs[pname] is not None:
                kwargs[pname] = sanitize_address(str(kwargs[pname]))
        filtered = {k: v for k, v in kwargs.items() if v is not None}
# =======
        # filtered = {
        #     k: v for k, v in kwargs.items()
        #     if v is not None and k != synthetic_noarg_param
        # }
# >>>>>>> f85b782 (适配roo code)
        if http_method == "GET":
            str_params = {k: str(v) for k, v in filtered.items()}
            return dispatch_get(endpoint, params=str_params if str_params else None)
        else:
            return dispatch_post(endpoint, data=filtered)

    # Build function signature with proper types and defaults
    # Params with defaults must come after params without defaults
    required_params = []
    optional_params = []
    for pname, pdef in properties.items():
        json_type = pdef.get("type", "string")
        py_type = _TYPE_MAP.get(json_type, str)
        default = pdef.get("default", inspect.Parameter.empty)
        if pname not in required and default is inspect.Parameter.empty:
            default = None
            py_type = py_type | None if py_type != str else str | None

        param = inspect.Parameter(pname, inspect.Parameter.KEYWORD_ONLY,
                                  default=default, annotation=py_type)
        if default is inspect.Parameter.empty:
            required_params.append(param)
        else:
            optional_params.append(param)

    if not required_params:
        required_params.append(
            inspect.Parameter(
                synthetic_noarg_param,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=str,
            )
        )

    sig_params = required_params + optional_params
    handler.__signature__ = inspect.Signature(sig_params, return_annotation=str)
    handler.__annotations__ = {p.name: p.annotation for p in sig_params}
    handler.__annotations__["return"] = str

    return handler


def _register_tool_def(tool_def: dict) -> bool:
    """Register a single tool from a schema definition. Returns True if registered."""
    name = tool_def["name"]
    if name in STATIC_TOOL_NAMES:
        return False  # Don't overwrite static tools
    description = tool_def.get("description", "")
    endpoint = tool_def["endpoint"]
    http_method = tool_def.get("http_method", "GET")
    input_schema = tool_def.get("input_schema", {"type": "object", "properties": {}})

    handler = _build_tool_function(endpoint, http_method, input_schema)
    handler.__name__ = name
    handler.__doc__ = description

    mcp.tool(name=name, description=description)(handler)
    _dynamic_tool_names.append(name)
    return True


def register_tools_from_schema(
    schema: list[dict],
    groups: set[str] | None = None,
    tool_groups: dict[str, str] | None = None,
    group_descriptions: dict[str, str] | None = None,
) -> int:
    """Register MCP tools from parsed schema.

    Args:
        schema: List of parsed tool definitions.
        groups: If provided, only register tools in these groups. None = register all.
        tool_groups: Optional mapping of tool name -> group.
        group_descriptions: Optional mapping of group -> description.

    Returns: count of registered tools.
    """
    global _dynamic_tool_names, _full_schema, _loaded_groups, _tool_groups, _tool_group_descriptions

    # Remove previously registered dynamic tools
    for name in _dynamic_tool_names:
        try:
            mcp._tool_manager._tools.pop(name, None)
        except Exception:
            pass
    _dynamic_tool_names.clear()
    _loaded_groups.clear()

    # Store full schema for lazy loading
    _full_schema = schema
    _tool_groups = tool_groups or {td["name"]: "unknown" for td in schema}
    _tool_group_descriptions = group_descriptions or {}

    count = 0
    for tool_def in schema:
        category = _tool_groups.get(tool_def["name"], "unknown")
        if groups is not None and category not in groups:
            continue
        _register_tool_def(tool_def)
        _loaded_groups.add(category)
        count += 1

    return count


def _load_group(group_name: str) -> int:
    """Load tools for a specific group from cached schema. Returns count."""
    count = 0
    for tool_def in _full_schema:
        name = tool_def["name"]
        if _tool_groups.get(name, "unknown") != group_name:
            continue
        if name in _dynamic_tool_names:
            continue  # Already loaded
        _register_tool_def(tool_def)
        count += 1
    if count > 0:
        _loaded_groups.add(group_name)
    return count


def _unload_group(group_name: str) -> int:
    """Unload tools for a specific group. Returns count of removed tools."""
    if group_name in _default_groups:
        return 0  # Default groups can't be unloaded

    to_remove = []
    for tool_def in _full_schema:
        name = tool_def["name"]
        if _tool_groups.get(name, "unknown") == group_name and name in _dynamic_tool_names:
            to_remove.append(name)

    for name in to_remove:
        try:
            mcp._tool_manager._tools.pop(name, None)
            _dynamic_tool_names.remove(name)
        except Exception:
            pass

    if to_remove:
        _loaded_groups.discard(group_name)
    return len(to_remove)


def _get_group_info() -> list[dict]:
    """Get info about all tool groups from cached schema."""
    groups: dict[str, list[str]] = {}
    descriptions: dict[str, str] = {}
    for tool_def in _full_schema:
        tool_name = tool_def["name"]
        cat = _tool_groups.get(tool_name, "unknown")
        groups.setdefault(cat, []).append(tool_name)
        if cat not in descriptions and cat in _tool_group_descriptions:
            descriptions[cat] = _tool_group_descriptions[cat]

    result = []
    for name, tools in sorted(groups.items()):
        info: dict = {
            "group": name,
            "tool_count": len(tools),
            "loaded": name in _loaded_groups,
            "default": name in _default_groups,
        }
        if name in descriptions:
            info["description"] = descriptions[name]
        info["tools"] = sorted(tools)
        result.append(info)
    return result


def _fetch_and_register_schema(load_all: bool = False) -> int:
    """Fetch /mcp/schema from connected instance and register tools.

    Args:
        load_all: If True, register all tools. If False, only default groups.

    Returns: count of registered tools.
    """
    if not load_all:
        load_all = not _lazy_mode
    text, status = do_request("GET", "/mcp/schema", timeout=10)
    if status != 200:
        raise RuntimeError(f"Failed to fetch schema: HTTP {status}")
    raw = json.loads(text)
    schema, tool_groups, group_descriptions = _parse_schema(raw)
    groups = None if load_all else _default_groups
    return register_tools_from_schema(
        schema,
        groups=groups,
        tool_groups=tool_groups,
        group_descriptions=group_descriptions,
    )


async def _notify_tools_changed(ctx: Context | None) -> None:
    """Send tools/list_changed notification if context is available."""
    if ctx is not None and ctx._request_context is not None:
        await ctx.request_context.session.send_tool_list_changed()


# ==========================================================================
# Static MCP tools (always available)
# ==========================================================================


@mcp.tool()
def list_instances(unused: str, ctx: Context = None) -> str:
    """
    List all reachable Ghidra instances discovered via UDS and TCP.

    Returns JSON with each instance's project name, transport details, and any
    metadata exposed by the server. Also shows which instance is currently connected.
    """
    instances = discover_instances()
    if not instances:
        return json.dumps({"instances": [], "note": "No reachable Ghidra instances found."})
    for inst in instances:
        if inst.get("transport") == "uds":
            inst["connected"] = inst.get("socket") == _active_socket
        elif inst.get("transport") == "tcp":
            inst["connected"] = inst.get("url") == _active_tcp
        else:
            inst["connected"] = False
    return json.dumps({"instances": instances}, indent=2)


@mcp.tool()
async def connect_instance(project: str, ctx: Context | None = None) -> str:
    """
    Switch the MCP bridge to a different Ghidra instance by project name.

    After connecting, fetches the tool schema from the instance and dynamically
    registers all available tools. Use list_instances() first to see available instances.

    Args:
        project: Project name (or substring) to connect to
    """
    global _active_socket, _active_tcp, _transport_mode, _connected_project

    instances = discover_instances()

    match = None
    for inst in instances:
        if inst.get("project", "") == project:
            match = inst
            break
    if not match:
        for inst in instances:
            if project.lower() in inst.get("project", "").lower():
                match = inst
                break

    if match:
        try:
            _activate_instance(match)
            _connected_project = match.get("project")
            count = _fetch_and_register_schema()
            total = len(_full_schema)
            await _notify_tools_changed(ctx)
            response = {
                "connected": True,
                "transport": match.get("transport"),
                "project": _connected_project,
                "tools_registered": count,
                "tools_total": total,
                "loaded_groups": sorted(_loaded_groups),
                "note": f"Loaded {count}/{total} tools (core groups). Use load_tool_group() for more.",
            }
            if match.get("socket"):
                response["socket"] = match["socket"]
            if match.get("pid") is not None:
                response["pid"] = match.get("pid")
            if match.get("url"):
                response["url"] = match["url"]
            return json.dumps(response)
        except Exception as e:
            return json.dumps({
                "error": f"Schema fetch failed: {e}",
                "socket": match.get("socket"),
                "url": match.get("url"),
            })

    # Try TCP fallback directly for explicit URL selection or default single-server usage
    tcp_url = project if project.startswith(("http://", "https://")) else os.getenv("GHIDRA_MCP_URL", DEFAULT_TCP_URL)
    try:
        _activate_instance({"transport": "tcp", "url": tcp_url})
        count = _fetch_and_register_schema()
        total = len(_full_schema)
        tcp_info = _probe_tcp_instance(tcp_url) or {"project": project if project != tcp_url else None}
        _connected_project = tcp_info.get("project") or project
        await _notify_tools_changed(ctx)
        return json.dumps({
            "connected": True,
            "transport": "tcp",
            "project": _connected_project,
            "url": tcp_url,
            "tools_registered": count,
            "tools_total": total,
            "loaded_groups": sorted(_loaded_groups),
            "note": f"Loaded {count}/{total} tools (core groups). Use load_tool_group() for more.",
        })
    except Exception as e:
        _transport_mode = "none"
        _active_tcp = None
        _active_socket = None
        available = [inst.get("project", inst.get("url", "unknown")) for inst in instances]
        return json.dumps({
            "error": f"No instance matching '{project}' (discovered: {len(instances)}, TCP {tcp_url}: {e})",
            "available": available,
        })


@mcp.tool()
def list_tool_groups(unused: str, ctx: Context = None) -> str:
    """
    List all available tool groups with their tool counts and loaded status.

    Returns each category with: tool count, loaded status, and tool names.
    Use load_tool_group(group) to load a group's tools.
    """
    if not _full_schema:
        return json.dumps({"error": "No instance connected. Use connect_instance() first."})
    groups = _get_group_info()
    return json.dumps({"groups": groups, "total_tools": len(_full_schema)}, indent=2)


@mcp.tool()
async def load_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Load all tools in a category. Accepts a category name or "all" to load everything.

    Use list_tool_groups() to see available categories.

    Args:
        group: Category name (e.g. "function", "datatype") or "all"
    """
    if not _full_schema:
        return json.dumps({"error": "No instance connected. Use connect_instance() first."})

    if group == "all":
        # Load all unloaded groups
        all_groups = { _tool_groups.get(td["name"], "unknown") for td in _full_schema }
        total = 0
        for g in all_groups:
            total += _load_group(g)
        if total > 0:
            await _notify_tools_changed(ctx)
        return json.dumps({
            "loaded": "all",
            "new_tools": total,
            "total_loaded": len(_dynamic_tool_names),
        })

    count = _load_group(group)
    if count == 0:
        available = sorted({_tool_groups.get(td["name"], "unknown") for td in _full_schema})
        if group in _loaded_groups:
            return json.dumps({"message": f"Group '{group}' is already loaded.", "loaded_groups": sorted(_loaded_groups)})
        return json.dumps({"error": f"No tools found for group '{group}'", "available": available})

    await _notify_tools_changed(ctx)
    return json.dumps({
        "loaded": group,
        "new_tools": count,
        "total_loaded": len(_dynamic_tool_names),
        "loaded_groups": sorted(_loaded_groups),
    })


@mcp.tool()
async def unload_tool_group(group: str, ctx: Context | None = None) -> str:
    """
    Unload all tools in a category. Default groups are protected from unloading.

    Args:
        group: Category name to unload
    """
    if group in _default_groups:
        return json.dumps({"error": f"Cannot unload default group '{group}'", "default_groups": sorted(_default_groups)})

    count = _unload_group(group)
    if count == 0:
        return json.dumps({"message": f"Group '{group}' is not loaded or has no tools."})

    await _notify_tools_changed(ctx)
    return json.dumps({
        "unloaded": group,
        "removed_tools": count,
        "total_loaded": len(_dynamic_tool_names),
        "loaded_groups": sorted(_loaded_groups),
    })


@mcp.tool()
async def import_file(
    file_path: str,
    project_folder: str = "/",
    language: str | None = None,
    compiler_spec: str | None = None,
    auto_analyze: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Import a binary file from disk into the current Ghidra project.

    Imports the file, opens it in the CodeBrowser, and optionally starts auto-analysis.
    When analysis is enabled, sends a log notification when analysis completes.

    For raw firmware binaries, specify language (e.g. "ARM:LE:32:Cortex") and
    optionally compiler_spec (e.g. "default"). Without language, Ghidra auto-detects
    the format (works for ELF, PE, Mach-O, etc.).

    Args:
        file_path: Absolute path to the binary file on disk
        project_folder: Destination folder in the Ghidra project (default: "/")
        language: Language ID for raw binaries (e.g. "ARM:LE:32:Cortex", "x86:LE:64:default")
        compiler_spec: Compiler spec ID (e.g. "default", "gcc"). Uses language default if omitted.
        auto_analyze: Start auto-analysis after import (default: true)
    """
    payload: dict = {
        "file_path": file_path,
        "project_folder": project_folder,
        "auto_analyze": auto_analyze,
    }
    if language:
        payload["language"] = language
    if compiler_spec:
        payload["compiler_spec"] = compiler_spec

    result = dispatch_post("/import_file", payload)

    # Parse result to check if analysis was started
    try:
        data = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return result

    if data.get("data", {}).get("analyzing") and ctx is not None:
        program_name = data["data"].get("name", "unknown")
        # Capture the session before the tool call returns
        session = ctx.request_context.session

        async def _poll_analysis():
            """Poll analysis_status until analysis completes, then send log notification."""
            await asyncio.sleep(5)  # Initial delay
            for _ in range(360):  # Up to 30 minutes
                try:
                    status_text = dispatch_get("/analysis_status", {"program": program_name})
                    status = json.loads(status_text)
                    status_data = status.get("data", status)
                    if not status_data.get("analyzing", True):
                        fn_count = status_data.get("function_count", "?")
                        await session.send_log_message(
                            level="info",
                            data=f"Analysis complete for {program_name}: {fn_count} functions found",
                        )
                        return
                except Exception as e:
                    logger.debug(f"Analysis poll error for {program_name}: {e}")
                await asyncio.sleep(5)

        asyncio.create_task(_poll_analysis())

    return result


# ==========================================================================
# Auto-connect on startup
# ==========================================================================


def _auto_connect():
    """Try to auto-connect to a single running instance on startup."""
    global _active_socket, _active_tcp, _transport_mode, _connected_project

    instances = discover_instances()
    if len(instances) == 1:
        instance = instances[0]
        try:
            _activate_instance(instance)
            _connected_project = instance.get("project")
            logger.info(
                f"Auto-connecting via {instance.get('transport')} to "
                f"{_connected_project or instance.get('url') or 'unknown'}"
            )
            count = _fetch_and_register_schema()
            logger.info(f"Auto-registered {count} tools from {_connected_project or instance.get('url') or 'unknown'}")
            return
        except Exception as e:
            logger.warning(f"Auto-connect schema fetch failed: {e}")
            _active_socket = None
            _active_tcp = None
            _transport_mode = "none"
    elif len(instances) > 1:
        logger.info(f"Multiple Ghidra instances found ({len(instances)}). Use connect_instance() to choose.")
    else:
        logger.info("No Ghidra instances found. Tools will be registered on connect_instance().")


# ==========================================================================
# Main
# ==========================================================================


def main():
    global _lazy_mode, _default_groups

    parser = argparse.ArgumentParser(description="GhidraMCP Bridge — MCP↔HTTP multiplexer")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1", help="Host for SSE transport")
    parser.add_argument("--mcp-port", type=int, help="Port for SSE transport")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="MCP transport")
    parser.add_argument("--lazy", action="store_true", default=True,
                        help="Only load default tool groups on connect (default)")
    parser.add_argument("--no-lazy", dest="lazy", action="store_false",
                        help="Load all tool groups on connect")
    parser.add_argument("--default-groups", type=str, default=None,
                        help="Comma-separated list of default tool groups to load on connect "
                             "(default: listing,function,program)")
    args = parser.parse_args()

    _lazy_mode = args.lazy
    if args.default_groups is not None:
        _default_groups = {g.strip() for g in args.default_groups.split(",") if g.strip()}

    _auto_connect()

    if args.transport == "sse":
        mcp.settings.log_level = "INFO"
        mcp.settings.host = args.mcp_host
        if args.mcp_port:
            mcp.settings.port = args.mcp_port
        logger.info("Starting MCP bridge (SSE)")
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
