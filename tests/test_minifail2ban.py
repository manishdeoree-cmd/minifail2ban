"""Unit tests. Run from the project root with:  python3 -m unittest discover -s tests -v"""

import ipaddress
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

import minifail2ban as m  # noqa: E402


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class RecordingFirewall(m.Firewall):
    name = "recording"

    def __init__(self):
        self.blocked = set()

    def ban(self, ip):
        self.blocked.add(str(ip))

    def unban(self, ip):
        self.blocked.discard(str(ip))


def fail_line(ip, user="root"):
    return "Oct 26 13:41:10 host sshd[1]: Failed password for %s from %s port 5555 ssh2" % (user, ip)


def make_cfg(**overrides):
    return m.Config(overrides=overrides, search_default=False)


class ParseFailureTests(unittest.TestCase):
    def test_failed_password(self):
        ip, user = m.parse_failure(fail_line("203.0.113.5"))
        self.assertEqual((str(ip), user), ("203.0.113.5", "root"))

    def test_invalid_user(self):
        line = "sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2"
        ip, user = m.parse_failure(line)
        self.assertEqual((str(ip), user), ("203.0.113.5", "admin"))

    def test_publickey_failure(self):
        line = "sshd[1]: Failed publickey for bob from 198.51.100.7 port 22 ssh2"
        self.assertEqual(str(m.parse_failure(line)[0]), "198.51.100.7")

    def test_ipv6(self):
        self.assertEqual(str(m.parse_failure(fail_line("2001:db8::bad"))[0]), "2001:db8::bad")

    def test_ipv4_mapped_ipv6_becomes_ipv4(self):
        self.assertEqual(str(m.parse_failure(fail_line("::ffff:203.0.113.5"))[0]), "203.0.113.5")

    def test_successful_login_ignored(self):
        self.assertIsNone(m.parse_failure("sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2"))

    def test_invalid_user_notice_alone_is_not_counted(self):
        # sshd logs this *and* a "Failed password" line; counting both would double count.
        self.assertIsNone(m.parse_failure("sshd[1]: Invalid user admin from 203.0.113.5 port 22"))

    def test_garbage_ip_ignored(self):
        self.assertIsNone(m.parse_failure(fail_line("999.1.1.1")))


class ParseTimestampTests(unittest.TestCase):
    def test_iso(self):
        ts = m.parse_timestamp("2026-10-26T13:40:01.123456+00:00 host sshd[1]: x")
        self.assertEqual(ts, datetime(2026, 10, 26, 13, 40, 1, 123456, tzinfo=timezone.utc).timestamp())

    def test_syslog_uses_current_year(self):
        now = datetime(2026, 10, 26, 14, 0, 0).timestamp()
        ts = m.parse_timestamp("Oct 26 13:40:01 host sshd[1]: x", now)
        self.assertEqual(ts, datetime(2026, 10, 26, 13, 40, 1).timestamp())

    def test_syslog_december_read_in_january(self):
        now = datetime(2027, 1, 1, 0, 5, 0).timestamp()
        ts = m.parse_timestamp("Dec 31 23:59:59 host sshd[1]: x", now)
        self.assertEqual(ts, datetime(2026, 12, 31, 23, 59, 59).timestamp())

    def test_no_timestamp(self):
        self.assertIsNone(m.parse_timestamp("sshd[1]: no timestamp here"))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = make_cfg()
        self.assertEqual((cfg.maxretry, cfg.findtime, cfg.bantime), (5, 600, 3600))

    def test_rejects_zero_maxretry(self):
        with self.assertRaises(m.ConfigError):
            make_cfg(maxretry=0)

    def test_rejects_bad_whitelist(self):
        with self.assertRaises(m.ConfigError):
            make_cfg(whitelist="not-an-ip")

    def test_rejects_bad_backend(self):
        with self.assertRaises(m.ConfigError):
            make_cfg(backend="pf")

    def test_whitelist_cidr(self):
        cfg = make_cfg(whitelist="10.0.0.0/8, 2001:db8::/32")
        self.assertTrue(cfg.is_whitelisted(ipaddress.ip_address("10.9.8.7")))
        self.assertTrue(cfg.is_whitelisted(ipaddress.ip_address("2001:db8::1")))
        self.assertFalse(cfg.is_whitelisted(ipaddress.ip_address("11.0.0.1")))


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_path = os.path.join(self.tmp.name, "state.json")
        self.clock = FakeClock()
        self.fw = RecordingFirewall()

    def monitor(self, fw=None, clock=None, **cfg):
        cfg.setdefault("maxretry", 3)
        cfg.setdefault("findtime", 60)
        cfg.setdefault("bantime", 100)
        state = m.State(self.state_path)
        state.load()
        return m.Monitor(make_cfg(**cfg), fw or self.fw, state, clock or self.clock)

    def test_bans_after_maxretry(self):
        mon = self.monitor()
        mon.handle_line(fail_line("203.0.113.5"))
        mon.handle_line(fail_line("203.0.113.5"))
        self.assertEqual(self.fw.blocked, set())
        mon.handle_line(fail_line("203.0.113.5"))
        self.assertEqual(self.fw.blocked, {"203.0.113.5"})
        self.assertEqual(mon.state.bans["203.0.113.5"]["attempts"], 3)

    def test_failures_outside_window_do_not_add_up(self):
        mon = self.monitor()
        t = self.clock.now
        mon.handle_line(fail_line("203.0.113.5"), t)
        mon.handle_line(fail_line("203.0.113.5"), t + 40)
        mon.handle_line(fail_line("203.0.113.5"), t + 100)    # first one is now > 60s old
        self.assertEqual(self.fw.blocked, set())

    def test_different_ips_are_counted_separately(self):
        mon = self.monitor()
        for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
            mon.handle_line(fail_line(ip))
        self.assertEqual(self.fw.blocked, set())

    def test_whitelisted_ip_never_banned(self):
        mon = self.monitor(whitelist="127.0.0.0/8 10.0.0.0/8")
        for _ in range(20):
            mon.handle_line(fail_line("127.0.0.1"))
            mon.handle_line(fail_line("10.1.2.3"))
        self.assertEqual(self.fw.blocked, set())
        self.assertEqual(mon.stats["whitelisted"], 40)

    def test_ban_expires(self):
        mon = self.monitor()
        for _ in range(3):
            mon.handle_line(fail_line("203.0.113.5"))
        self.clock.advance(99)
        mon.tick(force=True)
        self.assertEqual(self.fw.blocked, {"203.0.113.5"})
        self.clock.advance(2)
        mon.tick(force=True)
        self.assertEqual(self.fw.blocked, set())
        self.assertEqual(mon.state.bans, {})

    def test_permanent_ban(self):
        mon = self.monitor(bantime=0)
        for _ in range(3):
            mon.handle_line(fail_line("203.0.113.5"))
        self.clock.advance(10 * 365 * 86400)
        mon.tick(force=True)
        self.assertEqual(self.fw.blocked, {"203.0.113.5"})

    def test_banning_twice_is_a_noop(self):
        mon = self.monitor()
        self.assertTrue(mon.ban("203.0.113.5"))
        self.assertFalse(mon.ban("203.0.113.5"))

    def test_failures_from_banned_ip_still_counted_in_totals(self):
        mon = self.monitor()
        for _ in range(5):
            mon.handle_line(fail_line("203.0.113.5", "admin"))
        self.assertEqual(mon.state.totals["203.0.113.5"], 5)
        self.assertEqual(mon.state.users["admin"], 5)

    def test_state_survives_restart_and_is_reapplied(self):
        mon = self.monitor()
        for _ in range(3):
            mon.handle_line(fail_line("203.0.113.5"))
        mon.shutdown()

        fresh_fw = RecordingFirewall()                   # e.g. after a reboot the firewall is empty
        mon2 = self.monitor(fw=fresh_fw)
        mon2.restore()
        self.assertEqual(fresh_fw.blocked, {"203.0.113.5"})

    def test_ban_that_expired_while_stopped_is_dropped(self):
        mon = self.monitor()
        for _ in range(3):
            mon.handle_line(fail_line("203.0.113.5"))
        mon.shutdown()

        later = FakeClock(self.clock.now + 1000)
        fresh_fw = RecordingFirewall()
        mon2 = self.monitor(fw=fresh_fw, clock=later)
        mon2.restore()
        self.assertEqual(fresh_fw.blocked, set())
        self.assertEqual(mon2.state.bans, {})

    def test_daemon_notices_cli_unban(self):
        daemon = self.monitor()
        daemon.ban("203.0.113.5")
        cli_fw = RecordingFirewall()
        cli = self.monitor(fw=cli_fw)                    # a second process reading the same file
        self.assertTrue(cli.unban("203.0.113.5", force=True))
        daemon.tick(force=True)
        self.assertEqual(self.fw.blocked, set())
        self.assertEqual(daemon.state.bans, {})

    def test_daemon_notices_cli_ban(self):
        daemon = self.monitor()
        daemon.tick(force=True)
        cli = self.monitor(fw=RecordingFirewall())
        cli.ban("198.51.100.9", reason="manual (CLI)")
        daemon.tick(force=True)
        self.assertEqual(self.fw.blocked, {"198.51.100.9"})

    def test_corrupt_state_file_is_ignored(self):
        with open(self.state_path, "w") as fh:
            fh.write("{ this is not json")
        mon = self.monitor()
        self.assertEqual(mon.state.bans, {})


class FirewallCommandTests(unittest.TestCase):
    """The real firewall binaries are replaced by a recorder, so no root is needed."""

    class Recorder:
        def __init__(self, returncode=0):
            self.calls = []
            self.returncode = returncode

        def __call__(self, cmd):
            self.calls.append(cmd)
            rc = self.returncode(cmd) if callable(self.returncode) else self.returncode
            return subprocess.CompletedProcess(cmd, rc, "", "")

    def test_nft_ban_and_unban_ipv4(self):
        rec = self.Recorder()
        with mock.patch.object(m, "_run", rec):
            fw = m.NftablesFirewall()
            fw.ban(ipaddress.ip_address("203.0.113.5"))
            fw.unban(ipaddress.ip_address("203.0.113.5"))
        self.assertEqual(rec.calls, [
            ["nft", "add", "element", "inet", "minifail2ban", "blacklist4", "{ 203.0.113.5 }"],
            ["nft", "delete", "element", "inet", "minifail2ban", "blacklist4", "{ 203.0.113.5 }"],
        ])

    def test_nft_ipv6_uses_v6_set(self):
        rec = self.Recorder()
        with mock.patch.object(m, "_run", rec):
            m.NftablesFirewall().ban(ipaddress.ip_address("2001:db8::bad"))
        self.assertIn("blacklist6", rec.calls[0])

    def test_nft_setup_creates_chain_only_when_missing(self):
        missing = self.Recorder(returncode=lambda cmd: 1 if cmd[1] == "list" else 0)
        with mock.patch.object(m, "_run", missing):
            m.NftablesFirewall().setup()
        self.assertEqual(sum(1 for c in missing.calls if c[1:3] == ["add", "rule"]), 2)

        present = self.Recorder(returncode=0)
        with mock.patch.object(m, "_run", present):
            m.NftablesFirewall().setup()
        self.assertEqual(sum(1 for c in present.calls if c[1:3] == ["add", "rule"]), 0)

    def test_iptables_inserts_drop_rule_when_missing(self):
        rec = self.Recorder(returncode=lambda cmd: 1 if "-C" in cmd else 0)
        with mock.patch.object(m, "_run", rec):
            m.IptablesFirewall().ban(ipaddress.ip_address("203.0.113.5"))
        self.assertEqual(rec.calls[-1],
                         ["iptables", "-w", "-I", "MINIFAIL2BAN", "1", "-s", "203.0.113.5", "-j", "DROP"])

    def test_iptables_does_not_duplicate_existing_rule(self):
        rec = self.Recorder(returncode=0)                # -C succeeds => rule already there
        with mock.patch.object(m, "_run", rec):
            m.IptablesFirewall().ban(ipaddress.ip_address("203.0.113.5"))
        self.assertEqual(len(rec.calls), 1)

    def test_iptables_uses_ip6tables_for_ipv6(self):
        rec = self.Recorder(returncode=lambda cmd: 1 if "-C" in cmd else 0)
        with mock.patch.object(m, "_run", rec):
            m.IptablesFirewall().ban(ipaddress.ip_address("2001:db8::bad"))
        self.assertEqual(rec.calls[-1][0], "ip6tables")

    def test_failed_firewall_command_raises(self):
        rec = self.Recorder(returncode=1)
        with mock.patch.object(m, "_run", rec):
            with self.assertRaises(m.FirewallError):
                m.NftablesFirewall().ban(ipaddress.ip_address("203.0.113.5"))

    def test_monitor_survives_firewall_failure(self):
        class Broken(m.Firewall):
            def ban(self, ip):
                raise m.FirewallError("boom")

        state = m.State(None)
        mon = m.Monitor(make_cfg(maxretry=1), Broken(), state, FakeClock())
        mon.handle_line(fail_line("203.0.113.5"))        # must not raise
        self.assertEqual(state.bans, {})                 # and must not pretend the ban worked


class FollowFileTests(unittest.TestCase):
    def test_sees_new_lines_and_survives_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "auth.log")
            with open(path, "w") as fh:
                fh.write("old line\n")
            stop = threading.Event()
            gen = m.follow_file(path, stop)
            self.assertIsNone(next(gen))                 # starts at the end: old lines are skipped

            with open(path, "a") as fh:
                fh.write("new line\n")
            self.assertEqual(next(gen), "new line\n")

            os.rename(path, path + ".1")                 # logrotate
            with open(path, "w") as fh:
                fh.write("after rotation\n")
            got = None
            for _ in range(5):
                item = next(gen)
                if item:
                    got = item
                    break
            self.assertEqual(got, "after rotation\n")
            stop.set()
            gen.close()


class CommandLineTests(unittest.TestCase):
    """End to end: scan the sample log in dry-run mode."""

    def run_cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "src", "minifail2ban.py")] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    def test_once_dry_run_on_sample_log(self):
        res = self.run_cli("run", "--once", "--dry-run",
                           "-c", os.path.join(ROOT, "config", "minifail2ban.conf"),
                           "--logfile", os.path.join(HERE, "sample_auth.log"))
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn("203.0.113.50", out)            # 8 quick failures -> banned
        self.assertIn("2001:db8::bad", out)           # IPv6 attacker -> banned
        self.assertNotIn("198.51.100.23", out)        # only 3 failures
        self.assertNotIn("203.0.113.77", out)         # slow attacker stays under the radar
        self.assertNotIn("127.0.0.1", out)            # whitelisted
        self.assertNotIn("192.0.2.10", out)           # a real user who mistyped once
        self.assertIn("23 failed logins counted, 10 ignored", out)

    def test_missing_logfile_gives_clean_error(self):
        res = self.run_cli("run", "--once", "--dry-run", "--logfile", "/nonexistent/auth.log")
        self.assertEqual(res.returncode, 2)
        self.assertIn("error:", res.stderr)
        self.assertNotIn("Traceback", res.stderr)

    def test_non_root_cannot_use_real_firewall(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        res = self.run_cli("run", "--once", "--logfile", os.path.join(HERE, "sample_auth.log"),
                           "--state-file", "/tmp/x.json", "-c", os.path.join(ROOT, "config", "minifail2ban.conf"))
        self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
