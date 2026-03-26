"""
Unit tests for GhidraMCP bridge utility functions.

These tests run WITHOUT requiring a Ghidra server connection.
They test transport utilities, timeout logic, and discovery functions.
"""

import json
import os
import inspect
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


class TestGetSocketDir(unittest.TestCase):
    """Test socket directory resolution."""

    @patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=False)
    def test_xdg_runtime_dir(self):
        from bridge_mcp_ghidra import get_socket_dir
        result = get_socket_dir()
        self.assertEqual(result, Path("/run/user/1000/ghidra-mcp"))

    @patch.dict(os.environ, {"TMPDIR": "/custom/tmp", "USER": "testuser"}, clear=False)
    def test_tmpdir_fallback(self):
        env = os.environ.copy()
        env.pop("XDG_RUNTIME_DIR", None)
        with patch.dict(os.environ, env, clear=True):
            from bridge_mcp_ghidra import get_socket_dir
            result = get_socket_dir()
            self.assertEqual(result, Path("/custom/tmp/ghidra-mcp-testuser"))


class TestIsPidAlive(unittest.TestCase):
    """Test PID liveness check."""

    def test_current_pid_alive(self):
        from bridge_mcp_ghidra import is_pid_alive
        self.assertTrue(is_pid_alive(os.getpid()))

    def test_nonexistent_pid(self):
        from bridge_mcp_ghidra import is_pid_alive
        self.assertFalse(is_pid_alive(4000000))


class TestGetTimeout(unittest.TestCase):
    """Test per-endpoint timeout calculation."""

    def test_default_timeout(self):
        from bridge_mcp_ghidra import get_timeout
        self.assertEqual(get_timeout("/some_unknown_endpoint"), 30)

    def test_decompile_timeout(self):
        from bridge_mcp_ghidra import get_timeout
        self.assertEqual(get_timeout("/decompile_function"), 45)

    def test_script_timeout(self):
        from bridge_mcp_ghidra import get_timeout
        self.assertEqual(get_timeout("/run_ghidra_script"), 1800)

    def test_batch_rename_scaling(self):
        from bridge_mcp_ghidra import get_timeout
        payload = {"variable_renames": {f"var_{i}": f"new_{i}" for i in range(10)}}
        timeout = get_timeout("/batch_rename_variables", payload)
        self.assertGreater(timeout, 120)

    def test_batch_comments_scaling(self):
        from bridge_mcp_ghidra import get_timeout
        payload = {
            "decompiler_comments": [{"addr": "0x1000", "comment": "test"}] * 5,
            "disassembly_comments": [],
        }
        timeout = get_timeout("/batch_set_comments", payload)
        self.assertGreater(timeout, 120)


class TestBuildToolFunction(unittest.TestCase):
    """Test dynamic tool function builder."""

    def test_builds_callable(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {
                "address": {"type": "string"},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/decompile_function", "GET", schema)
        self.assertTrue(callable(fn))

    def test_signature_has_correct_params(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {
                "address": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["address"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIn("address", sig.parameters)
        self.assertIn("limit", sig.parameters)
        self.assertEqual(sig.parameters["limit"].default, 100)

    def test_required_params_no_default(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(sig.parameters["name"].default, inspect.Parameter.empty)

    def test_optional_params_default_none(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertIsNone(sig.parameters["name"].default)

    def test_type_annotations(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "enabled": {"type": "boolean"},
                "ratio": {"type": "number"},
            },
            "required": ["name", "count", "enabled", "ratio"],
        }
        fn = _build_tool_function("/test", "GET", schema)
        annotations = fn.__annotations__
        self.assertEqual(annotations["name"], str)
        self.assertEqual(annotations["count"], int)
        self.assertEqual(annotations["enabled"], bool)
        self.assertEqual(annotations["ratio"], float)

    def test_empty_schema(self):
        from bridge_mcp_ghidra import _build_tool_function
        schema = {"type": "object", "properties": {}}
        fn = _build_tool_function("/test", "GET", schema)
        sig = inspect.signature(fn)
        self.assertEqual(len(sig.parameters), 0)


class TestRegisterToolsFromSchema(unittest.TestCase):
    """Test dynamic tool registration from schema."""

    def test_registers_tools(self):
        from bridge_mcp_ghidra import register_tools_from_schema, _dynamic_tool_names
        schema = [
            {
                "name": "test_tool_reg_1",
                "description": "A test tool",
                "endpoint": "/test1",
                "http_method": "GET",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "test_tool_reg_2",
                "description": "Another test tool",
                "endpoint": "/test2",
                "http_method": "POST",
                "input_schema": {
                    "type": "object",
                    "properties": {"data": {"type": "string"}},
                    "required": ["data"],
                },
            },
        ]
        count = register_tools_from_schema(schema)
        self.assertEqual(count, 2)
        self.assertIn("test_tool_reg_1", _dynamic_tool_names)
        self.assertIn("test_tool_reg_2", _dynamic_tool_names)

    def test_clears_previous_tools(self):
        from bridge_mcp_ghidra import register_tools_from_schema, _dynamic_tool_names
        schema1 = [{"name": "old_tool_clear", "description": "", "endpoint": "/old",
                     "http_method": "GET", "input_schema": {"type": "object", "properties": {}}}]
        schema2 = [{"name": "new_tool_clear", "description": "", "endpoint": "/new",
                     "http_method": "GET", "input_schema": {"type": "object", "properties": {}}}]
        register_tools_from_schema(schema1)
        self.assertIn("old_tool_clear", _dynamic_tool_names)
        register_tools_from_schema(schema2)
        self.assertNotIn("old_tool_clear", _dynamic_tool_names)
        self.assertIn("new_tool_clear", _dynamic_tool_names)


class TestDispatchErrors(unittest.TestCase):
    """Test dispatch functions when no instance connected."""

    def test_dispatch_get_no_connection(self):
        import bridge_mcp_ghidra as bridge
        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_get("/test")
            data = json.loads(result)
            self.assertIn("error", data)
            self.assertIn("connect_instance", data["error"])
        finally:
            bridge._transport_mode = old

    def test_dispatch_post_no_connection(self):
        import bridge_mcp_ghidra as bridge
        old = bridge._transport_mode
        bridge._transport_mode = "none"
        try:
            result = bridge.dispatch_post("/test", {"key": "value"})
            data = json.loads(result)
            self.assertIn("error", data)
        finally:
            bridge._transport_mode = old


class TestUnixHTTPConnection(unittest.TestCase):
    """Test UnixHTTPConnection class."""

    def test_sets_socket_path(self):
        from bridge_mcp_ghidra import UnixHTTPConnection
        conn = UnixHTTPConnection("/tmp/test.sock", timeout=10)
        self.assertEqual(conn.socket_path, "/tmp/test.sock")
        self.assertEqual(conn.timeout, 10)


class TestDiscoveryFallbacks(unittest.TestCase):
    """Test UDS/TCP discovery fallback behavior."""

    def test_discover_instances_uses_tcp_when_no_socket_dir(self):
        import bridge_mcp_ghidra as bridge

        with patch.object(bridge, "get_socket_dir", return_value=Path("/missing-sockets")), \
             patch.dict(os.environ, {"GHIDRA_MCP_URL": "http://127.0.0.1:8089"}, clear=False), \
             patch.object(bridge, "_probe_tcp_instance", return_value={
                 "transport": "tcp",
                 "url": "http://127.0.0.1:8089",
                 "project": "TcpProject",
                 "server_version": "4.3.0",
             }):
            instances = bridge.discover_instances()

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["transport"], "tcp")
        self.assertEqual(instances[0]["project"], "TcpProject")
        self.assertEqual(instances[0]["url"], "http://127.0.0.1:8089")

    def test_probe_tcp_instance_falls_back_to_check_connection(self):
        import bridge_mcp_ghidra as bridge

        responses = [
            ("not found", 404),
            (json.dumps({"data": {"project_name": "TcpProject", "connected": True}}), 200),
        ]

        with patch.object(bridge, "tcp_request", side_effect=responses):
            info = bridge._probe_tcp_instance("http://127.0.0.1:8089")

        self.assertIsNotNone(info)
        self.assertEqual(info["transport"], "tcp")
        self.assertEqual(info["url"], "http://127.0.0.1:8089")
        self.assertEqual(info["project"], "TcpProject")
        self.assertTrue(info["connected"])

    def test_probe_tcp_instance_uses_synthetic_instance_for_plain_text_check_connection(self):
        import bridge_mcp_ghidra as bridge

        responses = [
            ("not found", 404),
            ("Connected: GhidraMCP plugin running, but no program loaded", 200),
        ]

        with patch.object(bridge, "tcp_request", side_effect=responses):
            info = bridge._probe_tcp_instance("http://127.0.0.1:8089")

        self.assertIsNotNone(info)
        self.assertEqual(info["transport"], "tcp")
        self.assertEqual(info["url"], "http://127.0.0.1:8089")
        self.assertEqual(info["project"], "tcp")
        self.assertTrue(info["connected"])
        self.assertEqual(info["status"], "Connected: GhidraMCP plugin running, but no program loaded")

    def test_discover_instances_keeps_plain_text_tcp_instance(self):
        import bridge_mcp_ghidra as bridge

        with patch.object(bridge, "get_socket_dir", return_value=Path("/missing-sockets")), \
             patch.dict(os.environ, {"GHIDRA_MCP_URL": "http://127.0.0.1:8089"}, clear=False), \
             patch.object(bridge, "_probe_tcp_instance", return_value={
                 "transport": "tcp",
                 "url": "http://127.0.0.1:8089",
                 "project": "tcp",
                 "connected": True,
                 "status": "Connected: GhidraMCP plugin running, but no program loaded",
             }):
            instances = bridge.discover_instances()

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["transport"], "tcp")
        self.assertEqual(instances[0]["url"], "http://127.0.0.1:8089")
        self.assertEqual(instances[0]["project"], "tcp")
        self.assertTrue(instances[0]["connected"])

    def test_list_instances_marks_tcp_connection(self):
        import bridge_mcp_ghidra as bridge

        previous_tcp = bridge._active_tcp
        previous_transport = bridge._transport_mode
        bridge._active_tcp = "http://127.0.0.1:8089"
        bridge._transport_mode = "tcp"
        try:
            with patch.object(bridge, "discover_instances", return_value=[{
                "transport": "tcp",
                "url": "http://127.0.0.1:8089",
                "project": "TcpProject",
            }]):
                payload = json.loads(bridge.list_instances(""))
        finally:
            bridge._active_tcp = previous_tcp
            bridge._transport_mode = previous_transport

        self.assertEqual(len(payload["instances"]), 1)
        self.assertTrue(payload["instances"][0]["connected"])


if __name__ == "__main__":
    unittest.main()
