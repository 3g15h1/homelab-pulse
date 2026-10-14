import copy
import unittest

import settings
import store


def doc(**patch):
    d = copy.deepcopy(settings.DEFAULTS)
    for path, value in patch.items():
        cur = d
        keys = path.split("__")
        for k in keys[:-1]:
            cur = cur[k]
        cur[keys[-1]] = value
    return d


class ValidateTests(unittest.TestCase):
    def test_defaults_valid(self):
        self.assertEqual(settings.validate(copy.deepcopy(settings.DEFAULTS)), settings.DEFAULTS)
        self.assertEqual(settings.DEFAULTS["alerts"]["down_after_s"], 180)
        self.assertEqual(settings.DEFAULTS["warnings"]["cert_expiry"], {"enabled": True, "warn_days": 21, "crit_days": 7})

    def test_partial_doc_merged_onto_defaults(self):
        d = settings.validate({"alerts": {"down_after_s": 60}})
        self.assertEqual(d["alerts"]["down_after_s"], 60)
        self.assertEqual(d["alerts"]["group_window_s"], 60)
        self.assertFalse(d["notify"]["ntfy"]["enabled"])

    def test_unknown_key_rejected(self):
        with self.assertRaises(settings.SettingsError) as cm:
            settings.validate({"alerts": {"downafter": 1}})
        self.assertEqual(cm.exception.path, "alerts.downafter")

    def test_bad_url_and_topic_rejected(self):
        with self.assertRaises(settings.SettingsError) as cm:
            settings.validate(doc(notify__webhook__url="ftp://x"))
        self.assertEqual(cm.exception.path, "notify.webhook.url")
        with self.assertRaises(settings.SettingsError):
            settings.validate(doc(notify__ntfy__topic="bad topic!"))
        with self.assertRaises(settings.SettingsError):          # enabled needs a url
            settings.validate(doc(notify__webhook__enabled=True))
        settings.validate(doc(notify__ntfy__enabled=True, notify__ntfy__topic="lab-alerts"))

    def test_ranges_and_types(self):
        for bad in (-1, 90000, "180", True):
            with self.assertRaises(settings.SettingsError):
                settings.validate(doc(alerts__down_after_s=bad))
        with self.assertRaises(settings.SettingsError):
            settings.validate(doc(warnings__ssd_wear__warn_pct=120))
        with self.assertRaises(settings.SettingsError):
            settings.validate(doc(notify__webhook__headers={"X": 5}))

    def test_time_format(self):
        with self.assertRaises(settings.SettingsError):
            settings.validate(doc(alerts__quiet__start="25:00"))
        settings.validate(doc(alerts__quiet__start="22:30"))


class MaskTests(unittest.TestCase):
    def test_mask_hides_token_and_headers(self):
        d = doc(notify__ntfy__token="tk_abcdef1234", notify__webhook__headers={"Authorization": "Bearer s3cretXYZ9"})
        m = settings.mask(d)
        self.assertEqual(m["notify"]["ntfy"]["token"], "••••1234")
        self.assertEqual(m["notify"]["webhook"]["headers"], {"Authorization": "••••XYZ9"})
        self.assertEqual(d["notify"]["ntfy"]["token"], "tk_abcdef1234")          # input untouched
        self.assertEqual(settings.mask(doc())["notify"]["ntfy"]["token"], "")

    def test_merge_masked_keeps_secret(self):
        old = doc(notify__ntfy__token="tk_abcdef1234", notify__webhook__headers={"Authorization": "Bearer s3cretXYZ9"})
        new = settings.mask(old)
        new["notify"]["ntfy"]["topic"] = "changed"
        new["notify"]["webhook"]["headers"]["X-Extra"] = "plain"
        merged = settings.merge_masked(new, old)
        self.assertEqual(merged["notify"]["ntfy"]["token"], "tk_abcdef1234")
        self.assertEqual(merged["notify"]["ntfy"]["topic"], "changed")
        self.assertEqual(merged["notify"]["webhook"]["headers"],
                         {"Authorization": "Bearer s3cretXYZ9", "X-Extra": "plain"})
        new["notify"]["ntfy"]["token"] = ""                                       # cleared on purpose
        self.assertEqual(settings.merge_masked(new, old)["notify"]["ntfy"]["token"], "")


class LoadTests(unittest.TestCase):
    def test_load_defaults_and_stored(self):
        s = store.Store(":memory:")
        self.assertEqual(settings.load(s), settings.DEFAULTS)
        s.put("config", {"alerts": {"down_after_s": 30}})
        self.assertEqual(settings.load(s)["alerts"]["down_after_s"], 30)
        s.put("config", {"alerts": {"down_after_s": "junk"}})
        self.assertEqual(settings.load(s), settings.DEFAULTS)


class HealSettingsTests(unittest.TestCase):
    def test_heal_settings_validation(self):
        self.assertEqual(settings.DEFAULTS["heal"], {"mode": "dry_run", "recipes": {}})
        d = settings.validate({"heal": {"mode": "auto", "recipes": {"generic-unit": "ask", "ct-disk-cleanup": "off"}}})
        self.assertEqual(d["heal"]["recipes"]["generic-unit"], "ask")
        for bad in ({"mode": "yolo"}, {"recipes": {"Bad Id": "auto"}}, {"recipes": {"x-y": "sometimes"}}, {"recipes": []}):
            with self.assertRaises(settings.SettingsError):
                settings.validate({"heal": bad})


class NewAlertKindsTests(unittest.TestCase):
    def test_net_kinds_default_on(self):
        for k in ("net_down", "gateway_down", "dns_broken"):
            self.assertTrue(settings.DEFAULTS["alerts"]["kinds"][k], k)

    def test_new_kinds_validate(self):
        d = settings.validate({"alerts": {"kinds": {"net_down": False}}})
        self.assertFalse(d["alerts"]["kinds"]["net_down"])
        self.assertTrue(d["alerts"]["kinds"]["gateway_down"])




class DataSafetyWarningTests(unittest.TestCase):
    def test_new_warning_defaults(self):
        w = settings.DEFAULTS["warnings"]
        self.assertEqual(w["zfs_health"], {"enabled": True})
        self.assertTrue(w["backup_storage_full"]["enabled"])
        self.assertFalse(w["pve_updates"]["enabled"])

    def test_new_warnings_validate(self):
        d = settings.validate({"warnings": {"zfs_health": {"enabled": False},
                                             "backup_storage_full": {"warn_pct": 80},
                                             "pve_updates": {"enabled": True}}})
        self.assertFalse(d["warnings"]["zfs_health"]["enabled"])
        self.assertEqual(d["warnings"]["backup_storage_full"]["warn_pct"], 80)
        self.assertTrue(d["warnings"]["pve_updates"]["enabled"])


class SettingsPageSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        cls.html = (root / "pulse" / "static" / "settings.html").read_text()

    def test_all_kinds_have_labels(self):
        import re
        kinds_block = re.search(r"const KINDS = \[(.*?)\];", self.html, re.S).group(1)
        kinds = re.findall(r'\["([a-z_]+)"', kinds_block)
        for k in settings.DEFAULTS["alerts"]["kinds"]:
            self.assertIn(k, kinds, f"kind {k} missing from settings.html KINDS")

    def test_all_warnings_have_ui(self):
        import re
        warn_block = re.search(r"const WARN = \{(.*?)\n\};", self.html, re.S).group(1)
        rules = re.findall(r"^\s*([a-z_]+):", warn_block, re.M)
        for r in settings.DEFAULTS["warnings"]:
            self.assertIn(r, rules, f"warning {r} missing from settings.html WARN")
        for rule in rules:
            m = re.search(rf"^\s*{rule}: \[.*?,\s*\[(.*)\]\]\],?$", warn_block, re.M)
            fields = re.findall(r'\["([a-z_]+)"', m.group(1)) if m else []
            for f in fields:
                self.assertIn(f, settings.DEFAULTS["warnings"][rule], f"{rule}.{f}")

    def test_old_doc_still_validates(self):
        old = {"alerts": {"down_after_s": 60}, "warnings": {"storage_full": {"enabled": True}}}
        cfg = settings.validate(copy.deepcopy(old))
        self.assertTrue(cfg["alerts"]["kinds"]["net_down"])
        self.assertIn("zfs_health", cfg["warnings"])
        self.assertIn("pve_updates", cfg["warnings"])
