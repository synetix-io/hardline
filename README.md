# Hardline

**Paste your RouterOS export. Get a graded security report and a copy-paste fix in 10 seconds.**

Live at https://hardline-synetix.fly.dev · built by [Synetix](https://synetix.co.za), Johannesburg.

## What it does

- Parses the text output of `/export` (never connects to the router).
- Runs ~30 deterministic checks: MikroTrick (CVE-2026-67276 chain) exposure, missing input-chain drop,
  telnet/ftp/www/api/winbox exposure, SNMP defaults, open resolver, UPnP, SOCKS/proxy (compromise indicators),
  scheduler `fetch` persistence, IPv6 with no firewall, MAC-server, discovery, RoMON, logging, NTP.
- Two sub-scores — **exposure** (could they get in?) and **evidence** (could you prove it?) — one grade A–F.
  Any critical finding caps the grade at D.
- Each finding: what was observed (with the offending line), why it matters, and RouterOS commands using the
  interface-list and subnet names from *your* export, plus a lock-out caution where relevant.
- Optional AI summary (Claude) that can only explain the findings it is given. Rule IDs it invents are stripped.
- Nothing stored. Secrets redacted before logging or AI. One counter: scans per day.

## Run

```bash
git clone https://github.com/synetix-io/hardline && cd hardline
pip install -e ".[dev]"
python -m pytest -q
uvicorn hardline.app:app --reload --port 8080
```

Run it on your own machine (opens the same UI at http://127.0.0.1:8080, nothing leaves the box):

```bash
pip install git+https://github.com/synetix-io/hardline
hardline
```

CLI, same engine:

```bash
hardline scan fixtures/vulnerable.rsc
hardline scan router.rsc --json --fail-on high     # exit 2 on high/critical — usable in CI
python -m hardline.cli scan router.rsc             # same thing, for machines that block venv .exe shims
```

Install straight from GitHub, no clone: `pip install git+https://github.com/synetix-io/hardline`

AI summary needs an Anthropic credential (`ANTHROPIC_API_KEY` or `ant auth login`). `HARDLINE_AI=0` disables it.
`HARDLINE_MODEL` overrides the model (default `claude-opus-5`).

## Layout

| File | Role |
|---|---|
| `hardline/parser.py` | `/export` text → `Config` (sections, entries, args). No eval, no I/O. |
| `hardline/rules.py` | **The product.** One function per check. Add one rule per real export you see. |
| `hardline/scoring.py` | Deductions, two axes, grade cap. |
| `hardline/redact.py` | Secret stripping — applied to evidence, logs, AI payload. |
| `hardline/ai.py` | Claude summary with guardrails and graceful fallback. |
| `hardline/app.py` | FastAPI: `/` form, `/scan`, `/api/scan`, `/stats`, `/healthz`. Rate-limited, CSP, no-store. |
| `hardline/cli.py` | `hardline scan` |
| `fixtures/` | `vulnerable.rsc` (F), `hardened.rsc` (A/B), `injection.rsc` (prompt-injection case) |

## Adding a rule

```python
@rule("HL-0xx", "Short title", "medium", "exposure")
def r0xx(cfg: Config):
    e = cfg.first("/ip something")
    if not e or not e.flag("enabled"):
        return None
    return dict(observed="...", why="...", fix=["/ip something set enabled=no"], evidence=[e.raw])
```

Return `severity=` in the dict to override the default for this instance (e.g. escalate when there is no firewall).

## Roadmap (only if the free scan gets signal)

1. Deploy + PostHog + "fleet" waitlist.
2. PDF export behind email.
3. Fleet: read-only API user, scheduled rescans, drift + new-CVE alerts, WhatsApp/Telegram.
4. MSP multi-tenant + white-label; Ubiquiti EdgeOS/UniFi rule pack.
5. Approved auto-remediation with signed action log — the agent acting on infrastructure under control + evidence.

## Privacy model

- Passwords, keys, PSKs, SSH keys and SNMP community strings are stripped **in the browser** before upload
  (`hardline/static/app.js`); the report shows how many values were removed. The same rules run again server-side
  (`hardline/redact.py`) as a second wall.
- The export is parsed in memory and discarded when the response is sent. Nothing is written except a daily scan count.
- The optional AI summary receives only the redacted finding list, never the export, and cannot add findings.
- Prefer nothing leaves your machine? `hardline scan router.rsc` runs the same rules offline.

## License

AGPL-3.0. Use it, read it, run it yourself; if you host a modified version, share the changes.
