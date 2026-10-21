# Sample data

All data here is synthetic. Attacker addresses come from the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which never route on the internet.

| File | Format | Purpose |
|---|---|---|
| `auth.log` | classic syslog | A normal day of staff logins plus four injected attacks. Built by `scripts/generate_sample_data.py --seed 42`. |
| `auth_iso.log` | ISO 8601 timestamps | The same events as `auth.log`, written the way Ubuntu 22.04+ and Debian 12 log them. |
| `clean.log` | classic syslog | Routine internal logins and a few typos. Must produce **no** findings. |
| `expected_results.json` | JSON | What the detectors must report for each file. `tests/test_samples.py` checks it. |

The four injected attacks in `auth.log`:

1. `203.0.113.45` guesses the `root` password 38 times in about 2.5 minutes (brute force).
2. `198.51.100.77` tries 14 different accounts in about 8 minutes (password spraying).
3. `198.51.100.23` signs in as `sysadmin` from outside the internal ranges (privileged login).
4. `192.0.2.88` fails 7 times for `dr.fahad`, then succeeds (brute force plus a likely takeover).
