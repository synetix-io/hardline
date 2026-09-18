# Deploying Hardline

Target: Fly.io, region `jnb` (Johannesburg). No Docker needed locally — Fly builds the image.

## One-time

```powershell
# 1. Install flyctl
pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"
# close and reopen the terminal so `fly` is on PATH

# 2. Sign up / log in (opens the browser; a card is required for a new account, the free allowance covers this app)
fly auth login

# 3. Create the app (if "hardline-synetix" is taken, pick another name and update fly.toml)
cd C:\Yukesh\Synetix\hardline
fly apps create hardline-synetix

# 4. AI summary credential (skip this and the report simply ships without the summary panel)
fly secrets set ANTHROPIC_API_KEY=sk-ant-...
```

## Every release

```powershell
cd C:\Yukesh\Synetix\hardline
python -m pytest -q
fly deploy
```

Live at `https://hardline-synetix.fly.dev`. `fly logs` tails the server; `fly status` shows the machine.

## Custom domain (optional)

```powershell
fly certs add hardline.synetix.co.za
```
Then add the CNAME it prints at your DNS host. Fly issues the certificate automatically.

## Notes

- Nothing is persisted except `data/scans.json` (the daily scan counter). It survives stop/start but not a redeploy.
  If the count matters, attach a volume: `fly volumes create data --size 1 --region jnb` and mount it at `/app/data` in `fly.toml`.
- `auto_stop_machines = "stop"` means the first request after idle takes ~2 s to wake. Fine for a customer trial; set
  `min_machines_running = 1` for a launch day.
- Rate limit is 20 scans/minute/IP (`HARDLINE_RATE_PER_MIN`). The Fly proxy passes the real client IP.
- `/stats` is public and shows only aggregate counts. Put it behind auth before there is anything worth hiding.
