"""Discord, Telegram, Gotify, Pushover and email delivery (1.5)."""
import json
import smtplib
import unittest
import unittest.mock
import urllib.parse

import notify
import settings
import store
from alerts import Notification
from tests.test_notify import Capture

URL = "http://192.168.1.60/"


def note(title="AdGuard Home on adguard is down", severity="critical", state="fire", message=None, actions=None):
    item = {"key": "check:101:80", "title": title, "severity": severity, "state": state, "since": 1.0}
    if actions:
        item["actions"] = actions
    return Notification(title, message or title, severity, state, [item], 1_800_000_000.0)


def cfg(**channels):
    c = {k: dict(v) for k, v in settings.DEFAULTS["notify"].items()}
    for name, over in channels.items():
        c[name].update(enabled=True, **over)
    return c


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.cap = Capture()
        self.st = store.Store(":memory:")
        self.n = notify.Notifier(self.st, URL, sleep=lambda s: None)

    def tearDown(self):
        self.cap.close()

    def sent(self):
        return self.cap.requests[-1]

    def test_discord_embed(self):
        r = self.n.send_now(note(), cfg(discord={"url": self.cap.url + "/api/webhooks/1/abc"}))
        self.assertTrue(r[0]["ok"], r)
        body = json.loads(self.sent()["body"])
        e = body["embeds"][0]
        self.assertEqual((e["title"], e["description"], e["url"]), ("AdGuard Home on adguard is down", "", URL))
        self.assertEqual(e["color"], notify.COLOR["critical"])
        self.assertEqual(body["allowed_mentions"], {"parse": []})      # an alert title can't ping @everyone
        self.n.send_now(note(state="resolve", severity="critical"), cfg(discord={"url": self.cap.url + "/x"}))
        self.assertEqual(json.loads(self.sent()["body"])["embeds"][0]["color"], notify.COLOR["resolve"])

    def test_telegram(self):
        with unittest.mock.patch.object(notify, "TELEGRAM_API", self.cap.url):
            r = self.n.send_now(note(message="AdGuard Home on adguard is down\ntried: restarted AdGuardHome.service"),
                                cfg(telegram={"token": "123456:" + "A" * 30, "chat_id": "-100123"}))
        self.assertTrue(r[0]["ok"], r)
        self.assertEqual(self.sent()["path"], "/bot123456:" + "A" * 30 + "/sendMessage")
        body = json.loads(self.sent()["body"])
        self.assertEqual(body["chat_id"], "-100123")
        self.assertEqual(body["text"], f"AdGuard Home on adguard is down\ntried: restarted AdGuardHome.service\n{URL}")
        self.assertFalse(body["disable_notification"])

    def test_gotify_priority_and_key(self):
        r = self.n.send_now(note(severity="warning"), cfg(gotify={"server": self.cap.url + "/", "token": "Atok"}))
        self.assertTrue(r[0]["ok"], r)
        req = self.sent()
        self.assertEqual((req["path"], req["headers"]["X-Gotify-Key"]), ("/message", "Atok"))
        body = json.loads(req["body"])
        self.assertEqual((body["priority"], body["message"]), (5, "AdGuard Home on adguard is down"))
        self.assertEqual(body["extras"]["client::notification"]["click"]["url"], URL)

    def test_pushover_form(self):
        with unittest.mock.patch.object(notify, "PUSHOVER_API", self.cap.url + "/1/messages.json"):
            r = self.n.send_now(note(), cfg(pushover={"user": "u" * 30, "token": "a" * 30}))
        self.assertTrue(r[0]["ok"], r)
        form = dict(urllib.parse.parse_qsl(self.sent()["body"].decode()))
        self.assertEqual((form["user"], form["token"], form["priority"]), ("u" * 30, "a" * 30, "1"))
        self.assertEqual((form["url"], form["title"]), (URL, "AdGuard Home on adguard is down"))

    def test_waiting_fix_points_to_settings(self):
        n = note(actions=[{"id": "t", "title": "Run fix: restart", "url": URL + "api/heal/run/t"}])
        self.n.send_now(n, cfg(discord={"url": self.cap.url + "/x"}))
        self.assertEqual(json.loads(self.sent()["body"])["embeds"][0]["description"],
                         "A fix is waiting for your approval: http://192.168.1.60/settings")

    def test_missing_fields_reported(self):
        for name, over, msg in (("telegram", {"token": "1:x", "chat_id": ""}, "no chat ID set"),
                                ("pushover", {"user": "", "token": "x"}, "no user key set"),
                                ("email", {"host": "smtp.example.org", "from": "a@b.c", "to": ""}, "no recipient set")):
            r = self.n.send_now(note(), cfg(**{name: over}), channel=name)
            self.assertEqual((r[0]["ok"], r[0]["error"]), (False, msg), name)


class EmailTests(unittest.TestCase):
    def send(self, **over):
        st = store.Store(":memory:")
        n = notify.Notifier(st, URL, sleep=lambda s: None)
        c = cfg(email=dict({"host": "mail.example.org", "from": "pulse@example.org", "to": "me@example.org, you@example.org",
                            "username": "pulse", "password": "pw"}, **over))
        smtp = unittest.mock.MagicMock()
        smtp.return_value.__enter__.return_value = smtp.return_value
        with unittest.mock.patch.object(notify.smtplib, "SMTP", smtp), \
                unittest.mock.patch.object(notify.smtplib, "SMTP_SSL", smtp):
            r = n.send_now(note(), c)
        return r, smtp

    def test_starttls_login_and_message(self):
        r, smtp = self.send()
        self.assertTrue(r[0]["ok"], r)
        self.assertEqual(smtp.call_args.args, ("mail.example.org", 587))
        conn = smtp.return_value
        conn.starttls.assert_called_once()
        conn.login.assert_called_once_with("pulse", "pw")
        msg = conn.send_message.call_args.args[0]
        self.assertEqual(msg["Subject"], "[Pulse] AdGuard Home on adguard is down")
        self.assertEqual(msg["To"], "me@example.org, you@example.org")
        self.assertIn(URL, msg.get_content())

    def test_ssl_and_plain(self):
        _r, smtp = self.send(security="ssl", port=465)
        self.assertEqual(smtp.call_args.args, ("mail.example.org", 465))
        smtp.return_value.starttls.assert_not_called()
        _r, smtp = self.send(security="none", port=25, username="", password="")
        smtp.return_value.starttls.assert_not_called()
        smtp.return_value.login.assert_not_called()

    def test_bad_password_not_retried(self):
        st = store.Store(":memory:")
        sleeps = []
        n = notify.Notifier(st, URL, sleep=sleeps.append)
        smtp = unittest.mock.MagicMock()
        smtp.return_value.login.side_effect = smtplib.SMTPAuthenticationError(535, b"no")
        with unittest.mock.patch.object(notify.smtplib, "SMTP", smtp):
            r = n.send_now(note(), cfg(email={"host": "h", "from": "a@b.c", "to": "d@e.f", "username": "u", "password": "p"}))
        self.assertEqual((r[0]["ok"], r[0]["status"]), (False, "535"))
        self.assertIn("username or password", r[0]["error"])
        self.assertEqual(sleeps, [])


class InternetDownTests(unittest.TestCase):
    def test_cloud_channels_skipped_local_ones_tried(self):
        cap = Capture()
        try:
            st = store.Store(":memory:")
            n = notify.Notifier(st, URL, sleep=lambda s: None)
            down = note()
            down.net_down = True
            r = n.send_now(down, cfg(discord={"url": "https://discord.com/api/webhooks/1/x"},
                                     gotify={"server": cap.url, "token": "t"},
                                     ntfy={"server": "https://ntfy.sh", "topic": "x"}))
        finally:
            cap.close()
        by = {x["channel"]: x for x in r}
        self.assertEqual(by["discord"]["status"], "skipped")
        self.assertEqual(by["ntfy"]["status"], "skipped")
        self.assertTrue(by["gotify"]["ok"])                              # 127.0.0.1: still reachable

    def test_needs_internet(self):
        self.assertTrue(notify.needs_internet("telegram", {}))
        self.assertFalse(notify.needs_internet("webhook", {}))
        self.assertFalse(notify.needs_internet("ntfy", {"server": "http://192.168.1.9:8080"}))
        self.assertFalse(notify.needs_internet("email", {"host": "10.0.0.25"}))
        self.assertTrue(notify.needs_internet("email", {"host": "8.8.8.8"}))


class SettingsTests(unittest.TestCase):
    def test_new_channels_validate_and_mask(self):
        doc = settings.validate({"notify": {
            "discord": {"enabled": True, "url": "https://discord.com/api/webhooks/1/secretpart"},
            "telegram": {"enabled": True, "token": "123456:" + "B" * 35, "chat_id": "@mylab_alerts"},
            "pushover": {"enabled": True, "user": "u" * 30, "token": "a" * 30},
            "email": {"enabled": True, "host": "smtp.example.org", "port": 465, "security": "ssl",
                      "username": "me", "password": "pw1234", "from": "pulse@example.org", "to": "a@b.c,d@e.f"}}})
        masked = settings.mask(doc)
        for ch, f in settings.SECRETS:
            v = masked["notify"][ch][f]
            self.assertTrue(v == "" or v.startswith(settings.MASK), (ch, f))
        self.assertEqual(masked["notify"]["discord"]["url"], settings.MASK + "part")
        back = settings.merge_masked(masked, doc)
        self.assertEqual(settings.validate(back), doc)

    def test_required_fields_and_formats(self):
        bad = ({"telegram": {"enabled": True, "token": "123456:" + "B" * 35}}, "notify.telegram.chat_id"),
        bad += (({"telegram": {"token": "not a token"}}, "notify.telegram.token"),
                ({"email": {"enabled": True, "host": "h", "from": "a@b.c"}}, "notify.email.to"),
                ({"email": {"to": "nope"}}, "notify.email.to"),
                ({"email": {"security": "tls"}}, "notify.email.security"),
                ({"email": {"username": "u"}}, "notify.email.password"),
                ({"gotify": {"enabled": True, "server": "https://g.example"}}, "notify.gotify.token"))
        for notify_doc, path in bad:
            with self.assertRaises(settings.SettingsError) as e:
                settings.validate({"notify": notify_doc})
            self.assertEqual(e.exception.path, path)

    def test_pre_1_5_settings_still_load(self):
        old = {"notify": {"webhook": {"enabled": True, "url": "http://ha/api/webhook/x", "headers": {}, "insecure": False},
                          "ntfy": {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": "", "insecure": False}}}
        d = settings.validate(old)
        self.assertFalse(d["notify"]["telegram"]["enabled"])
        self.assertTrue(d["notify"]["webhook"]["enabled"])


if __name__ == "__main__":
    unittest.main()
