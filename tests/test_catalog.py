import unittest

import catalog


class IdentifyTests(unittest.TestCase):
    def product(self, blob, port=80):
        hit = catalog.identify(blob.lower(), port)
        return hit and hit[0]

    def test_known_apps_by_title(self):
        self.assertEqual(self.product("title: adguard home"), "AdGuard Home")
        self.assertEqual(self.product("title: paperless-ngx sign in"), "Paperless-ngx")
        self.assertEqual(self.product("title: home assistant", 8123), "Home Assistant")
        self.assertEqual(self.product("title: home - proxmox virtual environment", 8006), "Proxmox VE")

    def test_port_and_body_rules(self):
        self.assertEqual(self.product("body: ollama is running", 11434), "Ollama")
        self.assertEqual(self.product("", 1883), "MQTT broker")
        self.assertEqual(self.product("banner: ssh-2.0-openssh_9.2p1", 22), "SSH")
        self.assertIsNone(catalog.identify("", 12345))

    def test_generic_server_ranks_below_specific(self):
        generic = catalog.identify("server: nginx", 80)
        specific = catalog.identify("server: nginx title: paperless-ngx", 8000)
        self.assertEqual(specific[0], "Paperless-ngx")
        self.assertGreater(generic[2], specific[2])

    def test_icons_exist_for_every_rule(self):
        for rule in catalog.RULES:
            self.assertIn(rule[2], catalog.ICONS, rule)


class NameGuessTests(unittest.TestCase):
    def test_name_hints(self):
        self.assertEqual(catalog.guess_from_name("adguard", None, "lxc")[1], "shield")
        self.assertEqual(catalog.guess_from_name("my-jellyfin", None, "lxc")[0], "Media server")

    def test_short_hints_match_whole_words_only(self):
        self.assertEqual(catalog.guess_from_name("sandbox", None, "lxc"), ("Container", "box"))
        self.assertEqual(catalog.guess_from_name("pg-db", None, "lxc")[0], "Database")
        self.assertEqual(catalog.guess_from_name("nascar-stats", None, "lxc")[0], "Container")

    def test_fallback_by_type(self):
        self.assertEqual(catalog.guess_from_name("zzz", "l26", "qemu"), ("Virtual machine", "box"))
        self.assertEqual(catalog.guess_from_name("zzz", "debian", "lxc"), ("Container", "box"))

    def test_scan_ports(self):
        for p in (22, 53, 80, 443, 8006, 11434, 32400, 7681, 8007):
            self.assertIn(p, catalog.SCAN_PORTS)
        self.assertLessEqual(catalog.TLS_FIRST, set(catalog.SCAN_PORTS))
