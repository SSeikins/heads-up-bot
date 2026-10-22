# heads-up-bot

Polls status pages and security feeds every 10 minutes (GitHub Actions) and posts to a Telegram group.

| Source | Now (🔥 / ✅) | Daily digest (ℹ️) |
|---|---|---|
| GitHub, Cloudflare (Statuspage) | new incident with impact major/critical, its resolution | minor incidents |
| GitLab (status.io RSS), Docker (Atom) | new incident / update, resolution | maintenance |
| GCP status | high severity, or our products in our locations; resolution | our products elsewhere |
| php.net news | security / critical posts | releases |
| CERT.LV | stack keyword + security wording | everything else |
| CISA KEV | actively exploited CVE in our stack | other KEV additions |
| NVD | CVSS critical with a CPE from `nvd_cpe_products` | — |

Everything is in `config.json` (keywords, products, locations, digest hour UTC).
Sources are seeded silently on the first run (no flood); new sources added later are seeded the same way.
A source that fails `source_fail_alert_after` runs in a row sends one ⚠️, and ✅ when it is back.
The digest is sent every day after `digest_hour_utc`, also when empty (heartbeat).

## Setup
1. @BotFather → `/newbot` → token. Create a group, add the bot, send any message in the group.
2. Chat id: `curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"` → `message.chat.id` (negative number).
3. Repo → Settings → Secrets and variables → Actions → Repository secrets: `HEADS_UP_BOT` (bot token), `TELEGRAM_CHAT_ID`.
4. Actions → heads-up → Run workflow (first run = seeding + "started" message).

State (`state.json`) is committed by the workflow; the commits also keep the schedule from being disabled after 60 days.

## Local
```bash
python3 bot.py --dry-run          # prints messages, uses state.dry.json
TELEGRAM_TOKEN=… TELEGRAM_CHAT_ID=… python3 bot.py --state /tmp/s.json
```
Python 3.9+, standard library only.
