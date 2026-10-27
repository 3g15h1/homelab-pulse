"""MCP endpoint (1.8): read-only tools for AI assistants, same access rule as the dashboard."""
import json
import threading
import unittest

import mcp
import server
from tests.test_server_auth import Client

JSON = {"Content-Type": "application/json"}


def rpc(method, params=None, mid=1):
    msg = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        msg["id"] = mid
    if params is not None:
        msg["params"] = params
    return msg


class HandleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = server.build_collector({"PULSE_PVE": "demo"})
        cls.c.poll_fast()
        cls.c.poll_slow()
        cls.c.poll_discovery()
        cls.c.poll_probes()

    def call(self, name, args=None):
        r = mcp.handle(rpc("tools/call", {"name": name, "arguments": args or {}}), self.c.snapshot, "9.9.9")
        self.assertIn("result", r, r)
        return r["result"]

    def test_initialize_and_list(self):
        r = mcp.handle(rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                          "clientInfo": {"name": "t", "version": "1"}}), self.c.snapshot, "9.9.9")
        self.assertEqual(r["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(r["result"]["serverInfo"], {"name": "homelab-pulse", "version": "9.9.9"})
        unknown = mcp.handle(rpc("initialize", {"protocolVersion": "1999-01-01"}), self.c.snapshot, "x")
        self.assertEqual(unknown["result"]["protocolVersion"], mcp.PROTOCOL_VERSIONS[0])
        tools = mcp.handle(rpc("tools/list"), self.c.snapshot, "x")["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, set(mcp.HANDLERS))
        for t in tools:
            self.assertTrue(t["annotations"]["readOnlyHint"], t["name"])
            self.assertEqual(t["inputSchema"]["type"], "object")

    def test_every_tool_returns_json_text_and_structured_content(self):
        for name in mcp.HANDLERS:
            args = {"guest": self.c.snapshot()["guests"][0]["name"]} if name == "guest_details" else {}
            res = self.call(name, args)
            self.assertFalse(res["isError"], name)
            self.assertEqual(json.loads(res["content"][0]["text"]), res["structuredContent"], name)

    def test_overview_and_filters(self):
        snap = self.c.snapshot()
        ov = self.call("lab_overview")["structuredContent"]
        self.assertEqual([h["name"] for h in ov["hosts"]], [n["name"] for n in snap["nodes"]])
        self.assertEqual(ov["guests"]["total"], len(snap["guests"]))
        running = self.call("list_guests", {"status": "running"})["structuredContent"]
        self.assertTrue(all(g["status"] == "running" for g in running["guests"]))
        node = snap["nodes"][0]["name"]
        on_node = self.call("list_guests", {"host": node})["structuredContent"]["guests"]
        self.assertTrue(on_node and all(g["node"] == node for g in on_node))
        failing = self.call("health_checks", {"only_failing": True})["structuredContent"]["checks"]
        self.assertTrue(all(c["up"] is False for c in failing))

    def test_guest_details_by_name_vmid_and_errors(self):
        g = self.c.snapshot()["guests"][0]
        by_name = self.call("guest_details", {"guest": g["name"].upper()})["structuredContent"]
        by_id = self.call("guest_details", {"guest": str(g["pve_vmid"])})["structuredContent"]
        self.assertEqual(by_name["vmid"], by_id["vmid"])
        miss = self.call("guest_details", {"guest": "no-such-guest-xyz"})
        self.assertTrue(miss["isError"])
        self.assertIn("list_guests", miss["content"][0]["text"])

    def test_recent_events_window_and_bad_args(self):
        ev = self.call("recent_events", {"hours": 168, "limit": 5})["structuredContent"]
        self.assertLessEqual(ev["count"], 5)
        self.assertTrue(self.call("recent_events", {"hours": "lots"})["isError"])

    def test_protocol_errors(self):
        snap = self.c.snapshot
        self.assertIsNone(mcp.handle(rpc("notifications/initialized", mid=None), snap, "x"))
        self.assertEqual(mcp.handle(rpc("nope"), snap, "x")["error"]["code"], -32601)
        self.assertEqual(mcp.handle(rpc("tools/call", {"name": "rm -rf"}), snap, "x")["error"]["code"], -32602)
        self.assertEqual(mcp.handle(rpc("tools/call", {"name": "alerts", "arguments": []}), snap, "x")["error"]["code"],
                         -32602)
        self.assertEqual(mcp.handle({"id": 3, "method": "ping"}, snap, "x")["error"]["code"], -32600)
        self.assertEqual(mcp.handle(rpc("ping"), snap, "x")["result"], {})


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.c = server.build_collector({"PULSE_PVE": "demo"})
        self.c.poll_fast()
        self.c.poll_slow()
        self.srv = server.serve(self.c, "127.0.0.1", 0)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.anon = Client(self.base)

    def post(self, msg, headers=None):
        return self.anon.req("POST", "/mcp", msg, headers=dict(JSON, **(headers or {})))

    def test_open_dashboard_means_open_tools(self):
        code, body, _ = self.post(rpc("initialize", {"protocolVersion": "2025-06-18"}))
        self.assertEqual((code, body["result"]["serverInfo"]["name"]), (200, "homelab-pulse"))
        code, body, _ = self.post(rpc("tools/call", {"name": "lab_overview"}))
        self.assertEqual(code, 200)
        self.assertFalse(body["result"]["isError"])
        self.assertEqual(self.post(rpc("notifications/initialized", mid=None))[0], 202)
        code, body, _ = self.post([rpc("ping", mid=1), rpc("tools/list", mid=2)])           # a batch still works
        self.assertEqual([r["id"] for r in body], [1, 2])

    def test_transport_guards(self):
        self.assertEqual(self.anon.req("GET", "/mcp", headers={})[0], 405)
        self.assertEqual(self.anon.req("POST", "/mcp", rpc("ping"), headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.post(rpc("ping"), {"Origin": "http://evil.example"})[0], 403)
        host = self.base.split("//", 1)[1]
        self.assertEqual(self.post(rpc("ping"), {"Origin": f"http://{host}"})[0], 200)
        self.assertEqual(self.anon.req("POST", "/mcp", raw=b"{oops", headers=JSON)[0], 400)

    def test_login_required_needs_a_view_link_as_bearer(self):
        admin = Client(self.base)
        admin.login()
        doc = admin.req("GET", "/api/settings")[1]["settings"]
        doc["access"]["dashboard"] = "login"
        self.assertEqual(admin.req("PUT", "/api/settings", doc)[0], 200)
        self.assertEqual(self.post(rpc("tools/list"))[0], 401)
        token = admin.req("POST", "/api/access/links", {"name": "AI assistant"})[1]["token"]
        self.assertEqual(self.post(rpc("tools/list"), {"Authorization": f"Bearer {token}"})[0], 200)
        self.assertEqual(self.post(rpc("tools/list"), {"Authorization": "Bearer wrong"})[0], 401)
        # a view link never becomes an admin, whichever header carries it
        self.assertEqual(self.anon.req("GET", "/api/settings", headers={"Authorization": f"Bearer {token}"})[0], 401)


if __name__ == "__main__":
    unittest.main()
