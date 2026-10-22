"""Sources. Each source returns a list of events and may update its own part of the state.

Event: {"key", "level", "source", "title", "url", "text"}
level: "crit" (send now), "ok" (resolved, send now), "info" (daily digest).
"""
import datetime as dt
import json
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html import unescape

UA = "heads-up-bot (+https://github.com/SSeikins/heads-up-bot)"
ATOM = "{http://www.w3.org/2005/Atom}"


def http_get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_json(url, timeout):
    return json.loads(http_get(url, timeout))


def strip_html(s, limit=300):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = re.sub(r"\s+", " ", unescape(s)).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def event(key, level, source, title, url="", text=""):
    return {"key": key, "level": level, "source": source, "title": title, "url": url, "text": text}


def kw_match(text, keywords):
    t = (text or "").lower()
    for k in keywords:
        if re.search(r"(?<![a-z0-9])" + re.escape(k.lower()) + r"(?![a-z0-9])", t):
            return k
    return None


def parse_feed(raw):
    """RSS 2.0 or Atom -> [{"id", "title", "link", "body"}]"""
    root = ET.fromstring(raw)
    items = []
    for it in root.iter("item"):
        items.append({
            "id": (it.findtext("guid") or it.findtext("link") or it.findtext("title") or "").strip(),
            "title": (it.findtext("title") or "").strip(),
            "link": (it.findtext("link") or "").strip(),
            "body": it.findtext("description") or "",
        })
    for e in root.iter(ATOM + "entry"):
        link = e.find(ATOM + "link")
        items.append({
            "id": (e.findtext(ATOM + "id") or "").strip(),
            "title": (e.findtext(ATOM + "title") or "").strip(),
            "link": link.get("href", "") if link is not None else "",
            "body": e.findtext(ATOM + "content") or e.findtext(ATOM + "summary") or "",
        })
    return items


# --- status pages -------------------------------------------------------------

def track_open(name, current, open_map, crit_levels_on_resolve=("crit",)):
    """current: {key: (level, title, url, text)}. New key -> event, key gone -> resolved event."""
    events = []
    for key, (level, title, url, text) in current.items():
        if key not in open_map:
            events.append(event(key, level, name, title, url, text))
            open_map[key] = {"level": level, "title": title, "url": url}
    for key in [k for k in open_map if k not in current]:
        old = open_map.pop(key)
        lvl = "ok" if old["level"] in crit_levels_on_resolve else "info"
        events.append(event(key + ":resolved", lvl, name, "Resolved: " + old["title"], old["url"]))
    return events


def statuspage(name, base, cfg, st):
    data = get_json(base.rstrip("/") + "/api/v2/incidents/unresolved.json", cfg["http_timeout"])
    current = {}
    for inc in data.get("incidents", []):
        level = "crit" if inc.get("impact") in cfg["statuspage_critical_impact"] else "info"
        upd = (inc.get("incident_updates") or [{}])[0]
        current["sp:%s:%s" % (name, inc["id"])] = (
            level, "%s [%s, %s]" % (inc["name"], inc.get("impact"), inc.get("status")),
            inc.get("shortlink") or base, strip_html(upd.get("body")))
    return track_open(name, current, st.setdefault("open", {}))


FEED_STATUSES = {"investigating", "identified", "monitoring", "update", "resolved", "completed", "complete", "postmortem",
                 "scheduled", "in progress", "verifying", "degraded performance", "partial outage", "major outage"}


def status_feed(name, url, cfg, st):
    """status.io RSS (GitLab) / Statuspage Atom (Docker): one item per incident, latest update first."""
    events = []
    for it in parse_feed(http_get(url, cfg["http_timeout"])):
        body = unescape(it["body"])
        marks = [m for m in re.finditer(r"<(?:b|strong)>\s*(?:Status:\s*)?([^<]+?)\s*</(?:b|strong)>", body, re.I)
                 if m.group(1).lower() in FEED_STATUSES]
        status = marks[-1].group(1).lower() if marks else ""
        text = strip_html(body[marks[-1].start():] if marks else body)
        base = "feed:%s:%s" % (name, it["id"])
        if re.search(r"maintenance|scheduled", it["title"] + " " + status, re.I):
            events.append(event(base, "info", name, it["title"], it["link"], text))
        elif status in ("resolved", "completed", "postmortem"):
            events.append(event(base, "info", name, it["title"], it["link"], text))
            events.append(event(base + ":resolved", "ok", name, "Resolved: " + it["title"], it["link"]))
        else:
            events.append(event(base, "crit", name, it["title"] + (" [%s]" % status if status else ""), it["link"], text))
    return events


def gcp(cfg, st):
    g = cfg["gcp"]
    current = {}
    for inc in get_json(g["url"], cfg["http_timeout"]):
        if inc.get("end"):
            continue
        products = [p.get("title", "") for p in inc.get("affected_products", [])]
        locations = [l.get("title", "") for l in inc.get("currently_affected_locations", [])] + \
                    [l.get("id", "") for l in inc.get("currently_affected_locations", [])]
        ours = [p for p in products if p in g["products"]]
        here = any(l in g["locations"] for l in locations)
        if inc.get("severity") == "high" or (ours and here):
            level = "crit"
        elif ours:
            level = "info"
        else:
            continue
        current["gcp:%s" % inc["id"]] = (
            level, "%s [%s]" % (inc.get("external_desc", "")[:150], inc.get("severity")),
            "https://status.cloud.google.com/" + inc.get("uri", ""),
            "Products: %s. Locations: %s" % (", ".join(products)[:150], ", ".join(sorted(set(locations)))[:150]))
    return track_open("GCP", current, st.setdefault("open", {}))


# --- security -----------------------------------------------------------------

SEC = r"security|vulnerab|cve-\d|critical|exploit|remote code|rce\b"


def php_news(cfg, st):
    events = []
    for it in parse_feed(http_get(cfg["php_feed"], cfg["http_timeout"])):
        level = "crit" if re.search(SEC, it["title"], re.I) else "info"
        events.append(event("php:" + it["id"], level, "php.net", it["title"], it["link"] or it["id"], strip_html(it["body"])))
    return events


def certlv(cfg, st):
    events = []
    for it in parse_feed(http_get(cfg["certlv_feed"], cfg["http_timeout"])):
        blob = it["title"] + " " + strip_html(it["body"], 2000)
        hit = kw_match(blob, cfg["stack_keywords"])
        level = "crit" if hit and re.search(SEC + r"|kritisk|ievainojam", blob, re.I) else "info"
        events.append(event("certlv:" + it["id"], level, "CERT.LV", it["title"], it["link"], strip_html(it["body"])))
    return events


def kev(cfg, st):
    events = []
    for v in get_json(cfg["kev_url"], cfg["http_timeout"]).get("vulnerabilities", []):
        blob = " ".join([v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", "")])
        level = "crit" if kw_match(blob, cfg["stack_keywords"]) else "info"
        events.append(event("kev:" + v["cveID"], level, "CISA KEV",
                            "%s — %s" % (v["cveID"], v.get("vulnerabilityName", "")),
                            "https://nvd.nist.gov/vuln/detail/" + v["cveID"],
                            "Actively exploited. " + strip_html(v.get("shortDescription"))))
    return events


def _nvd_cpes(cve):
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    yield parts[3] + ":" + parts[4]


def nvd(cfg, st):
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=cfg["nvd_window_hours"])
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    seen, events = set(), []
    for sev in ("cvssV3Severity", "cvssV4Severity"):
        q = urllib.parse.urlencode({sev: "CRITICAL", "pubStartDate": start.strftime(fmt),
                                    "pubEndDate": now.strftime(fmt), "resultsPerPage": 2000})
        for item in get_json(cfg["nvd_url"] + "?" + q, cfg["http_timeout"]).get("vulnerabilities", []):
            cve = item["cve"]
            if cve["id"] in seen:
                continue
            seen.add(cve["id"])
            cpes = set(_nvd_cpes(cve))
            hit = next((p for p in cfg["nvd_cpe_products"] for c in cpes if c.startswith(p)), None)
            if not hit:
                continue
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            events.append(event("nvd:" + cve["id"], "crit", "NVD", "%s (CVSS critical, %s)" % (cve["id"], hit.rstrip(":")),
                                "https://nvd.nist.gov/vuln/detail/" + cve["id"], strip_html(desc)))
    return events


def all_sources(cfg):
    """[(name, fn(cfg, state_part))]"""
    out = [(n, (lambda n, u: lambda c, s: statuspage(n, u, c, s))(n, u)) for n, u in cfg["statuspage"].items()]
    out += [(n, (lambda n, u: lambda c, s: status_feed(n, u, c, s))(n, u)) for n, u in cfg["status_feeds"].items()]
    out += [("GCP", gcp), ("php.net", php_news), ("CERT.LV", certlv), ("CISA KEV", kev), ("NVD", nvd)]
    return out
