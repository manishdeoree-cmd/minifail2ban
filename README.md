# minifail2ban

A small fail2ban-style tool that watches your SSH logs, detects brute-force login attempts and blocks the attacking IP addresses with **nftables** or **iptables**. Written in pure Python (standard library only) as a Linux learning project.

```
 sshd ──► /var/log/auth.log ──► follow (tail -F) ──► parse "Failed password…"
                                                          │
                                       sliding window: N failures in M seconds per IP
                                                          │
                          whitelisted? ──yes──► ignore    │ no
                                                          ▼
                                   nftables / iptables DROP  +  state.json
                                                          │
                                   ban expires ──► unblock automatically
```

## Features

- Follows a log file like `tail -F` (survives log rotation) **or** the systemd journal
- Sliding-window detection: `maxretry` failures within `findtime` seconds
- nftables (sets) and iptables (own chain) backends, with IPv4 and IPv6
- Automatic unban after `bantime` (or permanent bans)
- Whitelist with CIDR support, so you don't lock yourself out
- Bans are saved to disk and re-applied after a restart or reboot
- CLI: `status`, `report`, `ban`, `unban`, `flush`; the running daemon notices CLI changes
- `--dry-run` mode that never touches the firewall
- Runs as a hardened systemd service

## Requirements

- Linux with systemd, Python 3.8+, and `nft` or `iptables`
- Root, to change firewall rules and read auth logs

## Try it in 30 seconds (safe, no root needed)

```bash
git clone https://github.com/manishdeoree-cmd/minifail2ban.git
cd minifail2ban
python3 src/minifail2ban.py run --once --dry-run \
    -c config/minifail2ban.conf --logfile tests/sample_auth.log
```

The sample log contains a fast attacker, an IPv6 attacker, a slow attacker, someone who mistyped a password once, and localhost noise. Output:

```
WARNING BANNED 203.0.113.50 (5 failed logins within 600s) for 1h00m
WARNING BANNED 2001:db8::bad (5 failed logins within 600s) for 1h00m

Scanned 40 lines: 23 failed logins counted, 10 ignored (whitelisted).
Would ban 2 IP(s):
IP                                          FAILS  BANNED AT            EXPIRES IN
203.0.113.50                                    5  2026-10-26 08:23:34  59m59s
2001:db8::bad                                   5  2026-10-26 08:23:34  59m59s
```

The slow attacker (`203.0.113.77`, one try every 3 minutes) stays under the 5-in-10-minutes limit, and the user with one typo is never touched.

## Install

```bash
sudo ./install.sh
```

Then **edit `/etc/minifail2ban/minifail2ban.conf` and add your own IP to `whitelist`**, and restart:

```bash
sudo systemctl restart minifail2ban
journalctl -u minifail2ban -f          # live log of everything the tool does
```

Remove it with `sudo ./install.sh --uninstall` (add `--purge` to also delete config and state).

## Usage

```bash
minifail2ban status              # active bans and time left
minifail2ban report --top 10     # top attacking IPs and most-guessed usernames
sudo minifail2ban ban 203.0.113.9
sudo minifail2ban unban 203.0.113.9
sudo minifail2ban flush          # remove all bans
minifail2ban run --help
```

## Configuration

All settings live in `/etc/minifail2ban/minifail2ban.conf` (see [`config/minifail2ban.conf`](config/minifail2ban.conf)).

| Option          | Default                              | Meaning                                            |
|-----------------|--------------------------------------|----------------------------------------------------|
| `source`        | `file`                               | `file` or `journal`                                |
| `logfile`       | `/var/log/auth.log`                  | Use `/var/log/secure` on RHEL/Fedora               |
| `journal_units` | `ssh sshd`                           | Units to follow when `source = journal`            |
| `maxretry`      | `5`                                  | Failures allowed within `findtime`                 |
| `findtime`      | `600`                                | Window in seconds                                  |
| `bantime`       | `3600`                               | Ban length in seconds, `0` = permanent             |
| `backend`       | `auto`                               | `auto`, `nftables`, `iptables`, `dryrun`           |
| `whitelist`     | `127.0.0.0/8 ::1`                    | Never-banned IPs and CIDR ranges                   |
| `state_file`    | `/var/lib/minifail2ban/state.json`   | Bans and statistics                                |

## Testing it for real

Use a throwaway VM or VPS, **never your only access to a remote machine**.

1. Whitelist your own IP, or test from a second machine.
2. From that second machine, fail SSH logins five times:
   `for i in 1 2 3 4 5 6; do ssh wronguser@YOUR_SERVER; done` and enter wrong passwords.
3. Watch `journalctl -u minifail2ban -f` and run `sudo nft list ruleset` (or `sudo iptables -L MINIFAIL2BAN -n`).
4. Run `minifail2ban unban <ip>` to get back in.

Run the unit tests (no root needed):

```bash
python3 -m unittest discover -s tests -v
```

## Project layout

```
minifail2ban/
├── src/minifail2ban.py          # the whole tool (parser, engine, firewall backends, CLI)
├── config/minifail2ban.conf     # annotated sample config
├── systemd/minifail2ban.service # service unit
├── install.sh                   # install / uninstall
├── tests/                       # unit tests + sample_auth.log for the demo
└── README.md
```

## How it works, briefly

- **Parsing**: one regex matches sshd's `Failed password/publickey/…` lines. The separate `Invalid user …` notice is deliberately ignored, because sshd logs it *and* a `Failed password` line for the same attempt.
- **Detection**: a `deque` of timestamps per IP; old entries are dropped as the window slides.
- **Blocking**: nftables uses one table with an IPv4 set and an IPv6 set plus two drop rules, so adding or removing a ban is one cheap set operation. iptables uses a dedicated `MINIFAIL2BAN` chain jumped to from `INPUT`.
- **Persistence**: state is written atomically (temp file + `os.replace`). On start, active bans are re-applied and expired ones dropped.
- **CLI and daemon together**: `ban`/`unban` edit the state file; the daemon checks the file once a second and syncs the firewall.

## Known limitations and ideas

- Only SSH failed-password style lines are detected; add more patterns for other services.
- Blocks the whole IP, not just port 22.
- Notifications (email, Telegram) and a repeat-offender policy (longer bans for recidivists) are not implemented yet.
- If the CLI and the daemon write the state file in the same instant, one change can be lost. Fine for a learning project, but a lock file would fix it.
- The nftables/iptables paths are unit-tested with mocked commands; test them on a real machine before relying on them.

## License

MIT, see [LICENSE](LICENSE).
