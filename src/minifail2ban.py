#!/usr/bin/env python3
"""minifail2ban - a tiny fail2ban-style blocker for SSH brute-force attacks.

It follows your SSH logs (a log file or the systemd journal), counts failed
logins per IP address inside a sliding time window, and bans offenders with
nftables or iptables. Bans expire automatically and survive restarts/reboots.

Quick tour:
    minifail2ban run --config /etc/minifail2ban/minifail2ban.conf
    minifail2ban run --once --dry-run --logfile tests/sample_auth.log
    minifail2ban status
    minifail2ban report
    minifail2ban ban 203.0.113.9
    minifail2ban unban 203.0.113.9

Only the Python standard library is used. Python 3.8+.
"""

import argparse
import collections
import configparser
import ipaddress
import json
import logging
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

__version__ = "0.1.0"

log = logging.getLogger("minifail2ban")

SECTION = "minifail2ban"
DEFAULT_CONFIG = "/etc/minifail2ban/minifail2ban.conf"

DEFAULTS = {
    "source": "file",                      # file | journal
    "logfile": "/var/log/auth.log",        # used when source = file
    "journal_units": "ssh sshd",           # used when source = journal
    "maxretry": "5",                       # failures allowed inside findtime
    "findtime": "600",                     # sliding window, seconds
    "bantime": "3600",                     # ban length, seconds (0 = permanent)
    "backend": "auto",                     # auto | nftables | iptables | dryrun
    "whitelist": "127.0.0.0/8 ::1",        # never banned (IPs and/or CIDRs)
    "state_file": "/var/lib/minifail2ban/state.json",
    "log_level": "INFO",
}


class ConfigError(Exception):
    """Bad configuration or bad command-line input."""


class FirewallError(Exception):
    """A firewall command failed."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class Config:
    def __init__(self, path=None, overrides=None, search_default=True):
        parser = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
        parser.read_dict({SECTION: DEFAULTS})

        if path is None and search_default and os.path.exists(DEFAULT_CONFIG):
            path = DEFAULT_CONFIG
        if path:
            if not parser.read(path):
                raise ConfigError("config file not found or unreadable: %s" % path)

        sec = parser[SECTION]
        for key, value in (overrides or {}).items():
            if value is not None:
                sec[key] = str(value)

        try:
            self.maxretry = sec.getint("maxretry")
            self.findtime = sec.getint("findtime")
            self.bantime = sec.getint("bantime")
        except ValueError as exc:
            raise ConfigError("maxretry, findtime and bantime must be integers (%s)" % exc)
        if self.maxretry < 1:
            raise ConfigError("maxretry must be at least 1")
        if self.findtime < 1:
            raise ConfigError("findtime must be at least 1 second")

        self.source = sec["source"].strip().lower()
        if self.source not in ("file", "journal"):
            raise ConfigError("source must be 'file' or 'journal'")
        self.logfile = sec["logfile"].strip()
        self.journal_units = sec["journal_units"].split()

        self.backend = sec["backend"].strip().lower()
        if self.backend not in ("auto", "nftables", "iptables", "dryrun"):
            raise ConfigError("backend must be auto, nftables, iptables or dryrun")

        self.state_file = sec["state_file"].strip()
        self.log_level = sec["log_level"].strip().upper()

        self.whitelist = []
        for token in re.split(r"[,\s]+", sec["whitelist"].strip()):
            if not token:
                continue
            try:
                self.whitelist.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                raise ConfigError("invalid whitelist entry: %r" % token)

    def is_whitelisted(self, ip):
        return any(ip in net for net in self.whitelist)


# --------------------------------------------------------------------------
# Log parsing
# --------------------------------------------------------------------------

# Matches the lines sshd writes for a rejected authentication attempt, e.g.
#   Failed password for root from 203.0.113.5 port 52114 ssh2
#   Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2
FAIL_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)

# Classic syslog:  "Oct 26 13:40:01 ..."     rsyslog ISO:  "2026-10-26T13:40:01.123456+05:30 ..."
SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")
ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
)


def parse_failure(line):
    """Return (ip_address, username) for a failed-login line, else None."""
    match = FAIL_RE.search(line)
    if not match:
        return None
    try:
        ip = ipaddress.ip_address(match.group("ip"))
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip, match.group("user")


def parse_timestamp(line, now=None):
    """Best-effort unix timestamp of a log line; None if it has no usable one."""
    now = now if now is not None else time.time()
    try:
        match = ISO_TS.match(line)
        if match:
            text = match.group("ts").replace(" ", "T", 1)
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                return datetime.fromisoformat(text).timestamp()
            except ValueError:
                pass
        match = SYSLOG_TS.match(line)
        if match:
            year = datetime.fromtimestamp(now).year
            stamp = " ".join(match.group("ts").split())
            parsed = datetime.strptime("%d %s" % (year, stamp), "%Y %b %d %H:%M:%S")
            if parsed.timestamp() > now + 86400:      # syslog has no year: Dec log read in Jan
                parsed = parsed.replace(year=year - 1)
            return parsed.timestamp()
    except ValueError:
        pass
    return None


# --------------------------------------------------------------------------
# Firewall backends
# --------------------------------------------------------------------------

def _run(cmd):
    log.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True, timeout=15)
    except FileNotFoundError:
        raise FirewallError("command not found: %s" % cmd[0])
    except subprocess.TimeoutExpired:
        raise FirewallError("command timed out: %s" % " ".join(cmd))


def _must(cmd):
    result = _run(cmd)
    if result.returncode != 0:
        raise FirewallError("%s failed: %s" % (" ".join(cmd), result.stderr.strip()))
    return result


class Firewall:
    name = "base"

    def setup(self):
        """Create whatever chains/tables are needed (must be idempotent)."""

    def ban(self, ip):
        raise NotImplementedError

    def unban(self, ip):
        raise NotImplementedError

    def teardown(self):
        """Remove everything setup() created."""


class DryRunFirewall(Firewall):
    """Pretends to ban. Safe for demos and tests: touches nothing."""
    name = "dryrun"

    def ban(self, ip):
        log.info("[dry-run] would block %s", ip)

    def unban(self, ip):
        log.info("[dry-run] would unblock %s", ip)


class IptablesFirewall(Firewall):
    name = "iptables"
    CHAIN = "MINIFAIL2BAN"

    @staticmethod
    def _binary(ip):
        return "ip6tables" if ip.version == 6 else "iptables"

    def setup(self):
        for binary in ("iptables", "ip6tables"):
            if shutil.which(binary) is None:
                log.warning("%s not found; %s addresses cannot be blocked", binary,
                            "IPv6" if binary == "ip6tables" else "IPv4")
                continue
            if _run([binary, "-w", "-L", self.CHAIN, "-n"]).returncode != 0:
                _must([binary, "-w", "-N", self.CHAIN])
            if _run([binary, "-w", "-C", "INPUT", "-j", self.CHAIN]).returncode != 0:
                _must([binary, "-w", "-I", "INPUT", "1", "-j", self.CHAIN])

    def ban(self, ip):
        binary = self._binary(ip)
        rule = ["-s", str(ip), "-j", "DROP"]
        if _run([binary, "-w", "-C", self.CHAIN] + rule).returncode == 0:
            return                                    # already blocked
        _must([binary, "-w", "-I", self.CHAIN, "1"] + rule)

    def unban(self, ip):
        _run([self._binary(ip), "-w", "-D", self.CHAIN, "-s", str(ip), "-j", "DROP"])

    def teardown(self):
        for binary in ("iptables", "ip6tables"):
            if shutil.which(binary) is None:
                continue
            _run([binary, "-w", "-D", "INPUT", "-j", self.CHAIN])
            _run([binary, "-w", "-F", self.CHAIN])
            _run([binary, "-w", "-X", self.CHAIN])


class NftablesFirewall(Firewall):
    """One table with a v4 set and a v6 set; a drop rule per set."""
    name = "nftables"
    TABLE = "minifail2ban"

    @staticmethod
    def _set(ip):
        return "blacklist6" if ip.version == 6 else "blacklist4"

    def setup(self):
        t = self.TABLE
        _must(["nft", "add", "table", "inet", t])
        _must(["nft", "add", "set", "inet", t, "blacklist4", "{ type ipv4_addr; }"])
        _must(["nft", "add", "set", "inet", t, "blacklist6", "{ type ipv6_addr; }"])
        if _run(["nft", "list", "chain", "inet", t, "input"]).returncode != 0:
            _must(["nft", "add", "chain", "inet", t, "input",
                   "{ type filter hook input priority -10; policy accept; }"])
            _must(["nft", "add", "rule", "inet", t, "input", "ip", "saddr", "@blacklist4", "drop"])
            _must(["nft", "add", "rule", "inet", t, "input", "ip6", "saddr", "@blacklist6", "drop"])

    def ban(self, ip):
        _must(["nft", "add", "element", "inet", self.TABLE, self._set(ip), "{ %s }" % ip])

    def unban(self, ip):
        _run(["nft", "delete", "element", "inet", self.TABLE, self._set(ip), "{ %s }" % ip])

    def teardown(self):
        _run(["nft", "delete", "table", "inet", self.TABLE])


def make_firewall(cfg, dry_run=False):
    backend = "dryrun" if dry_run else cfg.backend
    if backend == "auto":
        if shutil.which("nft"):
            backend = "nftables"
        elif shutil.which("iptables"):
            backend = "iptables"
        else:
            raise ConfigError("neither nft nor iptables found; install one or use --dry-run")
    return {"dryrun": DryRunFirewall, "nftables": NftablesFirewall,
            "iptables": IptablesFirewall}[backend]()


# --------------------------------------------------------------------------
# Persistent state (current bans + long-term counters for the report)
# --------------------------------------------------------------------------

class State:
    """JSON file holding active bans and totals. path=None means 'memory only'."""

    def __init__(self, path=None):
        self.path = path
        self.bans = {}                          # ip -> {banned_at, expires, attempts, reason}
        self.totals = collections.Counter()     # ip -> failed logins seen
        self.users = collections.Counter()      # username -> failed logins seen
        self._signature = None

    def _stat_signature(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def _read(self):
        with open(self.path) as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or not isinstance(data.get("bans", {}), dict):
            raise ValueError("unexpected file layout")
        return data

    def load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            data = self._read()
        except (OSError, ValueError) as exc:
            log.warning("cannot read state file %s (%s); starting fresh", self.path, exc)
            return
        self.bans = data.get("bans", {})
        self.totals = collections.Counter(data.get("totals", {}))
        self.users = collections.Counter(data.get("users", {}))
        self._signature = self._stat_signature()

    def disk_changed(self):
        return bool(self.path) and self._stat_signature() not in (None, self._signature)

    def read_bans(self):
        """Fresh copy of the bans on disk (used to notice CLI ban/unban)."""
        try:
            bans = self._read().get("bans", {})
        except (OSError, ValueError) as exc:
            log.warning("cannot re-read state file: %s", exc)
            return None
        self._signature = self._stat_signature()
        return bans

    def _trim(self):
        if len(self.totals) > 10000:
            self.totals = collections.Counter(dict(self.totals.most_common(5000)))
        if len(self.users) > 5000:
            self.users = collections.Counter(dict(self.users.most_common(1000)))

    def save(self):
        if not self.path:
            return
        self._trim()
        data = {"version": 1, "bans": self.bans,
                "totals": dict(self.totals), "users": dict(self.users)}
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)              # atomic: never a half-written file
        self._signature = self._stat_signature()


# --------------------------------------------------------------------------
# The engine
# --------------------------------------------------------------------------

class Monitor:
    def __init__(self, cfg, firewall, state, clock=time.time):
        self.cfg = cfg
        self.fw = firewall
        self.state = state
        self.clock = clock
        self.attempts = collections.defaultdict(collections.deque)   # ip -> recent failure times
        self.stats = collections.Counter()
        self._dirty = False
        self._last_tick = 0.0
        self._last_save = 0.0

    # -- helpers ----------------------------------------------------------

    def _fw(self, action, key):
        try:
            action(ipaddress.ip_address(key))
            return True
        except FirewallError as exc:
            log.error("firewall error for %s: %s", key, exc)
            return False

    # -- startup ----------------------------------------------------------

    def restore(self):
        """Re-apply saved bans (the firewall forgets them on reboot)."""
        now = self.clock()
        for key, info in list(self.state.bans.items()):
            if info.get("expires") and now >= info["expires"]:
                self.unban(key, reason="expired while stopped")
            else:
                self._fw(self.fw.ban, key)
                log.info("restored ban for %s", key)

    # -- the main entry point: one log line --------------------------------

    def handle_line(self, line, event_time=None):
        self.stats["lines"] += 1
        parsed = parse_failure(line)
        if parsed is None:
            return False
        ip, user = parsed
        if self.cfg.is_whitelisted(ip):
            self.stats["whitelisted"] += 1
            log.debug("ignoring failure from whitelisted %s", ip)
            return False

        key = str(ip)
        when = event_time if event_time is not None else self.clock()
        self.stats["failures"] += 1
        self.state.totals[key] += 1
        self.state.users[user] += 1
        self._dirty = True
        if key in self.state.bans:
            return True                         # already blocked; just keep counting

        window = self.attempts[key]
        window.append(when)
        while window and window[0] < when - self.cfg.findtime:
            window.popleft()
        log.info("failed login from %s (user=%s) [%d/%d in %ds]",
                 key, user, len(window), self.cfg.maxretry, self.cfg.findtime)

        if len(window) >= self.cfg.maxretry:
            count = len(window)
            del self.attempts[key]
            self.ban(key, attempts=count,
                     reason="%d failed logins within %ds" % (count, self.cfg.findtime))
        return True

    # -- ban / unban ---------------------------------------------------------

    def ban(self, ip, attempts=0, reason="manual"):
        key = str(ip)
        self.sync_from_disk()
        if key in self.state.bans:
            return False
        now = self.clock()
        if not self._fw(self.fw.ban, key):
            return False
        self.state.bans[key] = {
            "banned_at": now,
            "expires": 0 if self.cfg.bantime <= 0 else now + self.cfg.bantime,
            "attempts": attempts,
            "reason": reason,
        }
        self.stats["bans"] += 1
        log.warning("BANNED %s (%s)%s", key, reason,
                    "" if self.cfg.bantime <= 0 else " for %s" % fmt_duration(self.cfg.bantime))
        self.state.save()
        return True

    def unban(self, ip, reason="manual", force=False):
        key = str(ip)
        self.sync_from_disk()
        present = key in self.state.bans
        if not present and not force:
            return False
        self._fw(self.fw.unban, key)
        if present:
            del self.state.bans[key]
            self.state.save()
            log.info("UNBANNED %s (%s)", key, reason)
        return present

    # -- housekeeping (called about once a second) ---------------------------

    def sync_from_disk(self):
        """Pick up bans added/removed by the CLI while the daemon is running."""
        if not self.state.disk_changed():
            return
        disk = self.state.read_bans()
        if disk is None:
            return
        for key in set(self.state.bans) - set(disk):
            log.info("ban for %s removed externally; unblocking", key)
            self._fw(self.fw.unban, key)
        for key in set(disk) - set(self.state.bans):
            log.info("ban for %s added externally; blocking", key)
            self._fw(self.fw.ban, key)
        self.state.bans = disk

    def tick(self, force=False):
        now = self.clock()
        if not force and now - self._last_tick < 1.0:
            return
        self._last_tick = now
        self.sync_from_disk()
        for key, info in list(self.state.bans.items()):
            if info.get("expires") and now >= info["expires"]:
                self.unban(key, reason="ban expired")
        for key in list(self.attempts):
            window = self.attempts[key]
            while window and window[0] < now - self.cfg.findtime:
                window.popleft()
            if not window:
                del self.attempts[key]
        if self._dirty and now - self._last_save >= 5:
            self.state.save()
            self._dirty = False
            self._last_save = now

    def shutdown(self):
        self.state.save()


# --------------------------------------------------------------------------
# Log sources (generators; they yield None when idle so the caller can tick)
# --------------------------------------------------------------------------

def follow_file(path, stop):
    """Like `tail -F`: starts at the end, survives rotation and truncation."""
    handle = None
    inode = None
    first = True
    buf = ""
    try:
        while not stop.is_set():
            if handle is None:
                try:
                    handle = open(path, "r", errors="replace")
                except OSError as exc:
                    log.error("cannot open %s: %s (retrying in 5s)", path, exc)
                    yield None
                    stop.wait(5)
                    continue
                inode = os.fstat(handle.fileno()).st_ino
                if first:
                    handle.seek(0, os.SEEK_END)
                    first = False
                buf = ""
            chunk = handle.readline()
            if chunk:
                buf += chunk
                if buf.endswith("\n"):
                    line, buf = buf, ""
                    yield line
                continue
            try:                                  # idle: was the file rotated or truncated?
                st = os.stat(path)
                if st.st_ino != inode or st.st_size < handle.tell():
                    log.info("%s was rotated; reopening", path)
                    handle.close()
                    handle = None
                    continue
            except FileNotFoundError:
                pass
            yield None
            stop.wait(1.0)
    finally:
        if handle:
            handle.close()


def follow_journal(units, stop):
    """Follow `journalctl -f` for the given units."""
    cmd = ["journalctl", "-f", "-n", "0", "-o", "cat"]
    for unit in units:
        cmd += ["-u", unit]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise ConfigError("journalctl not found; use source = file instead")
    fd = proc.stdout.fileno()
    buf = b""
    try:
        while not stop.is_set():
            ready, _, _ = select.select([fd], [], [], 1.0)
            if not ready:
                yield None
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                log.error("journalctl exited unexpectedly")
                return
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                yield raw.decode("utf-8", "replace")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------
# Command-line interface
# --------------------------------------------------------------------------

def fmt_duration(seconds):
    seconds = int(max(0, seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return "%dh%02dm" % (hours, minutes)
    if minutes:
        return "%dm%02ds" % (minutes, secs)
    return "%ds" % secs


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def setup_logging(level):
    fmt = ("%(levelname)s %(message)s" if os.environ.get("JOURNAL_STREAM")
           else "%(asctime)s %(levelname)s %(message)s")
    logging.basicConfig(level=getattr(logging, level, logging.INFO), format=fmt,
                        stream=sys.stderr)


def load_config(args):
    overrides = {"state_file": getattr(args, "state_file", None),
                 "logfile": getattr(args, "logfile", None)}
    cfg = Config(args.config, overrides)
    setup_logging(cfg.log_level)
    return cfg


def parse_ip_arg(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise ConfigError("not a valid IP address: %r" % text)


def require_root(fw):
    if fw.name != "dryrun" and os.geteuid() != 0:
        raise ConfigError("changing firewall rules needs root (try sudo, or use --dry-run)")


def print_bans(bans, now):
    if not bans:
        print("No active bans.")
        return
    print("%-40s %8s  %-19s  %s" % ("IP", "FAILS", "BANNED AT", "EXPIRES IN"))
    for key, info in sorted(bans.items(), key=lambda kv: kv[1].get("banned_at", 0)):
        expires = info.get("expires", 0)
        left = "never" if not expires else fmt_duration(expires - now)
        print("%-40s %8s  %-19s  %s" % (key, info.get("attempts", "-"),
                                        fmt_time(info.get("banned_at", 0)), left))


def cmd_run(args):
    cfg = load_config(args)
    fw = make_firewall(cfg, dry_run=args.dry_run)
    require_root(fw)
    state = State(None if args.dry_run else cfg.state_file)    # dry-run never persists
    state.load()
    monitor = Monitor(cfg, fw, state)
    fw.setup()
    monitor.restore()

    if args.once:                                              # scan the whole file, then exit
        if cfg.source != "file":
            raise ConfigError("--once only works with source = file")
        now = time.time()
        try:
            with open(cfg.logfile, errors="replace") as fh:
                for line in fh:
                    monitor.handle_line(line, parse_timestamp(line, now))
        except OSError as exc:
            raise ConfigError("cannot read %s: %s" % (cfg.logfile, exc))
        monitor.shutdown()
        stats = monitor.stats
        print("\nScanned %d lines: %d failed logins counted, %d ignored (whitelisted)."
              % (stats["lines"], stats["failures"], stats["whitelisted"]))
        print("%s %d IP(s):" % ("Would ban" if args.dry_run else "Banned", len(state.bans)))
        print_bans(state.bans, time.time())
        return 0

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    if cfg.source == "journal":
        lines = follow_journal(cfg.journal_units, stop)
        where = "journal units: %s" % " ".join(cfg.journal_units)
    else:
        lines = follow_file(cfg.logfile, stop)
        where = cfg.logfile
    log.info("minifail2ban %s started (%s, backend=%s, %d failures / %ds -> ban %s)",
             __version__, where, fw.name, cfg.maxretry, cfg.findtime,
             "forever" if cfg.bantime <= 0 else fmt_duration(cfg.bantime))

    for line in lines:
        if line:
            monitor.handle_line(line)
        monitor.tick()
    monitor.shutdown()
    log.info("stopped")
    return 0


def cmd_status(args):
    cfg = load_config(args)
    state = State(cfg.state_file)
    state.load()
    print_bans(state.bans, time.time())
    return 0


def cmd_report(args):
    cfg = load_config(args)
    state = State(cfg.state_file)
    state.load()
    print("Top attacking IPs")
    for key, count in state.totals.most_common(args.top):
        flag = "  [banned]" if key in state.bans else ""
        print("  %-40s %6d%s" % (key, count, flag))
    if not state.totals:
        print("  (nothing recorded yet)")
    print("\nMost targeted usernames")
    for user, count in state.users.most_common(args.top):
        print("  %-40s %6d" % (user, count))
    if not state.users:
        print("  (nothing recorded yet)")
    print("\nCurrently banned: %d" % len(state.bans))
    return 0


def _manual_monitor(args):
    cfg = load_config(args)
    fw = make_firewall(cfg)
    require_root(fw)
    fw.setup()
    state = State(cfg.state_file)
    state.load()
    return cfg, Monitor(cfg, fw, state)


def cmd_ban(args):
    ip = parse_ip_arg(args.ip)
    cfg, monitor = _manual_monitor(args)
    if cfg.is_whitelisted(ip):
        raise ConfigError("%s is whitelisted; refusing to ban it" % ip)
    print("Banned %s." % ip if monitor.ban(ip, reason="manual (CLI)")
          else "%s is already banned (or the firewall refused)." % ip)
    return 0


def cmd_unban(args):
    ip = parse_ip_arg(args.ip)
    _, monitor = _manual_monitor(args)
    if monitor.unban(ip, reason="manual (CLI)", force=True):
        print("Unbanned %s." % ip)
    else:
        print("%s was not in the state file; removed any leftover firewall rule." % ip)
    return 0


def cmd_flush(args):
    cfg = load_config(args)
    fw = make_firewall(cfg)
    require_root(fw)
    state = State(cfg.state_file)
    state.load()
    monitor = Monitor(cfg, fw, state)
    for key in list(state.bans):
        monitor.unban(key, reason="flush")
    if args.remove_rules:
        fw.teardown()
        print("Removed all minifail2ban firewall rules.")
    print("All bans cleared.")
    return 0


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", help="config file (default: %s if it exists)" % DEFAULT_CONFIG)
    common.add_argument("--state-file", help="override the state file path")

    parser = argparse.ArgumentParser(prog="minifail2ban",
                                     description="Tiny fail2ban-style SSH brute-force blocker.")
    parser.add_argument("--version", action="version", version="minifail2ban " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    run = sub.add_parser("run", parents=[common], help="watch the logs and ban attackers")
    run.add_argument("--dry-run", action="store_true",
                     help="never touch the firewall or the state file; just log what would happen")
    run.add_argument("--once", action="store_true",
                     help="scan the whole log file once, print a summary, and exit")
    run.add_argument("--logfile", help="override the log file to read")
    run.set_defaults(func=cmd_run)

    sub.add_parser("status", parents=[common], help="list active bans").set_defaults(func=cmd_status)

    report = sub.add_parser("report", parents=[common], help="top attackers and usernames")
    report.add_argument("--top", type=int, default=10, help="how many rows to show (default 10)")
    report.set_defaults(func=cmd_report)

    ban = sub.add_parser("ban", parents=[common], help="ban an IP manually")
    ban.add_argument("ip")
    ban.set_defaults(func=cmd_ban)

    unban = sub.add_parser("unban", parents=[common], help="unban an IP")
    unban.add_argument("ip")
    unban.set_defaults(func=cmd_unban)

    flush = sub.add_parser("flush", parents=[common], help="remove all bans")
    flush.add_argument("--remove-rules", action="store_true",
                       help="also delete the chain/table (stop the service first)")
    flush.set_defaults(func=cmd_flush)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, FirewallError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
