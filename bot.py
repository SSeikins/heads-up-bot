#!/usr/bin/env python3
"""heads-up-bot: polls status pages and security feeds, posts critical events to Telegram.

Usage: bot.py [--dry-run] [--state FILE]
Env:   TELEGRAM_TOKEN, TELEGRAM_CHAT_ID (not needed with --dry-run)
"""
import argparse
import datetime as dt
import html
import json
import os
import sys
import urllib.parse
import urllib.request

import sources

HERE = os.path.dirname(os.path.abspath(__file__))
ICON = {"crit": "🔥", "ok": "✅", "info": "ℹ️", "warn": "⚠️"}
SEEN_TTL_DAYS = 60
TG_LIMIT = 4000


def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def fmt(ev):
    line = "%s <b>%s</b>: %s" % (ICON[ev["level"]], html.escape(ev["source"], quote=False), html.escape(ev["title"], quote=False))
    if ev.get("text"):
        line += "\n" + html.escape(ev["text"], quote=False)
    if ev.get("url"):
        line += '\n<a href="%s">link</a>' % html.escape(ev["url"], quote=True)
    return line


def chunks(lines, header=""):
    buf = header
    for l in lines:
        if len(buf) + len(l) + 2 > TG_LIMIT:
            yield buf
            buf = ""
        buf += ("\n\n" if buf else "") + l
    if buf:
        yield buf


class Telegram:
    def __init__(self, dry):
        self.dry = dry
        self.token = os.environ.get("TELEGRAM_TOKEN", "")
        self.chat = os.environ.get("TELEGRAM_CHAT_ID", "")
        if not dry and not (self.token and self.chat):
            sys.exit("TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set")

    def send(self, text):
        if self.dry:
            print("----- would send -----\n" + text)
            return
        data = urllib.parse.urlencode({"chat_id": self.chat, "text": text, "parse_mode": "HTML",
                                       "disable_web_page_preview": "true"}).encode()
        req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % self.token, data=data)
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print messages, do not send")
    ap.add_argument("--state", help="default: state.json (state.dry.json with --dry-run)")
    args = ap.parse_args()
    args.state = args.state or os.path.join(HERE, "state.dry.json" if args.dry_run else "state.json")

    cfg = load(os.path.join(HERE, "config.json"), None)
    state = load(args.state, {})
    seen = state.setdefault("seen", {})
    per_src = state.setdefault("sources", {})
    digest = state.setdefault("digest", [])
    tg = Telegram(args.dry_run)
    now = dt.datetime.now(dt.timezone.utc)
    today = now.strftime("%Y-%m-%d")
    first_run = not per_src
    urgent, started = [], []

    for name, fn in sources.all_sources(cfg):
        st = per_src.setdefault(name, {"seeded": False, "fails": 0})
        try:
            events = fn(cfg, st)
        except Exception as e:
            st["fails"] += 1
            print("source %s failed (%d): %s" % (name, st["fails"], e), file=sys.stderr)
            if st["fails"] == cfg["source_fail_alert_after"]:
                urgent.append({"key": "", "level": "warn", "source": name,
                               "title": "source is failing (%d runs in a row): %s" % (st["fails"], str(e)[:200])})
            continue
        if st["fails"] >= cfg["source_fail_alert_after"]:
            urgent.append({"key": "", "level": "ok", "source": name, "title": "source is back"})
        st["fails"] = 0
        for ev in events:
            new = ev["key"] not in seen
            seen[ev["key"]] = today
            if not new or not st["seeded"]:
                continue
            if ev["level"] == "info":
                digest.append(fmt(ev))
            else:
                urgent.append(ev)
        if not st["seeded"]:
            st["seeded"] = True
            started.append(name)

    if started:
        msg = "👋 heads-up-bot %s: watching %s" % ("started" if first_run else "added sources", ", ".join(started))
        tg.send(html.escape(msg))
        if first_run:
            state["last_digest"] = today

    for text in chunks([fmt(e) for e in urgent]):
        tg.send(text)

    if now.hour >= cfg["digest_hour_utc"] and state.get("last_digest") != today:
        failing = [n for n, s in per_src.items() if s["fails"]]
        head = "☀️ <b>Daily digest</b> — %d item(s)" % len(digest)
        if failing:
            head += "\n⚠️ failing now: " + html.escape(", ".join(failing))
        if not digest:
            head += "\nAll quiet."
        for text in chunks(digest, head):
            tg.send(text)
        state["digest"] = []
        state["last_digest"] = today

    cutoff = (now - dt.timedelta(days=SEEN_TTL_DAYS)).strftime("%Y-%m-%d")
    state["seen"] = {k: v for k, v in seen.items() if v >= cutoff}
    state["last_run"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(args.state, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
