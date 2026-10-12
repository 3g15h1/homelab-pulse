import json
import tempfile
import unittest
from pathlib import Path

import overrides


class TagTests(unittest.TestCase):
    def test_parse_tags(self):
        t = overrides.parse_tags(["prod", "pulse-role-shared-local-ai", "pulse-icon-brain", "pulse-ip-192-168-0-75",
                                  "pulse-noscan"])
        self.assertEqual(t, {"role": "shared local ai", "icon": "brain", "ip": "192.168.0.75", "noscan": True})
        self.assertEqual(overrides.parse_tags(["pulse-ignore"]), {"ignore": True})
        self.assertEqual(overrides.parse_tags([]), {})

    def test_bad_ip_tag_ignored(self):
        self.assertEqual(overrides.parse_tags(["pulse-ip-999-1-1-1", "pulse-ip-abc"]), {})


class LoadTests(unittest.TestCase):
    def write(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write(text)
        f.close()
        self.addCleanup(Path(f.name).unlink)
        return f.name

    def test_missing_file_is_empty(self):
        self.assertEqual(overrides.load("/nonexistent/overrides.json"), {})

    def test_load_valid(self):
        data = {"internet": False, "router": {"name": "Gateway", "ip": "10.0.0.1"},
                "scan": {"ports_add": [7000], "ports_remove": [21]},
                "guests": {"103": {"role": "Home Assistant", "icon": "home", "ip": "192.168.0.75"}},
                "checks": [{"id": "x", "name": "X", "kind": "tcp", "host": "10.0.0.2", "port": 1, "target": 103}],
                "hide_checks": ["105:22"]}
        self.assertEqual(overrides.load(self.write(json.dumps(data))), data)

    def test_load_invalid_json_raises_override_error(self):
        with self.assertRaises(overrides.OverrideError):
            overrides.load(self.write("{not json"))

    def test_unknown_key_rejected(self):
        with self.assertRaisesRegex(overrides.OverrideError, "probes"):
            overrides.load(self.write('{"probes": []}'))

    def test_check_without_kind_rejected(self):
        with self.assertRaises(overrides.OverrideError):
            overrides.load(self.write('{"checks": [{"id": "x", "name": "X"}]}'))
