"""Consolidated, multi-format run reports built from one structured model.

The pipeline records every tool it runs as a ToolRun. At the end of a host's
run we distill those into a single canonical document — open ports, web
findings, discovery, warnings — and render it into whatever formats the config
selects: summary txt, raw txt, JSON, XML, Markdown.

This is separate from the per-tool artifacts (nmap_quick.txt,
gobuster_dir_80.txt, ...) that tools.py writes as raw evidence; those are
always written regardless of the selected formats. These are the
*consolidated* reports.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .tools import (
    DIG_RECORD_TYPES,
    GOBUSTER_INTERESTING,
    ToolRun,
    build_dns_map,
    nuclei_severity_rank,
    parse_ffuf_structured,
    parse_gobuster_hits,
    parse_nuclei,
    parse_searchsploit,
    parse_tls_cert,
)

SCHEMA_VERSION = 1

# Canonical selectable formats: key -> (label, filename). The config dict
# DEFAULT_CONFIG["output_formats"] uses these same keys.
REPORT_FORMATS: list[tuple[str, str, str]] = [
    ("summary", "Summary (human-readable txt)", "report.txt"),
    ("raw", "Raw combined tool output (txt)", "report.raw.txt"),
    ("json", "JSON (structured)", "report.json"),
    ("xml", "XML (structured)", "report.xml"),
    ("markdown", "Markdown report", "report.md"),
]


# --------------------------------------------------------------------------- #
# Parsing tool output into structured findings
# --------------------------------------------------------------------------- #

# gobuster dir line: "/admin   (Status: 301) [Size: 312] [--> /admin/]"
_GOBUSTER_DIR_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]*)\])?"
)


def parse_gobuster_structured(stdout: str) -> list[dict[str, Any]]:
    """Parse gobuster dir output into {path, status, size, redirect} records."""
    hits: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "Status:" not in line:
            continue
        m = _GOBUSTER_DIR_RE.match(line)
        if not m:
            continue
        status = int(m.group("status"))
        if status not in GOBUSTER_INTERESTING:
            continue
        size = m.group("size")
        redirect = (m.group("redirect") or "").strip()
        hits.append({
            "path": m.group("path"),
            "status": status,
            "size": int(size) if size is not None else None,
            "redirect": redirect or None,
        })
    return hits


def extract_whatweb(stdout: str) -> str:
    """Collapse whatweb's per-URL output into a single summary line."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    return " ".join(lines)


def extract_headers(stdout: str) -> dict[str, Any]:
    """Pull the status line and a few key headers out of `curl -D -` output."""
    status_chain: list[str] = []
    headers: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("HTTP/"):
            status_chain.append(line.strip())
        elif ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()
    return {
        "status": status_chain[-1] if status_chain else "",
        "status_chain": status_chain,
        "server": headers.get("server", ""),
        "location": headers.get("location", ""),
        "content_type": headers.get("content-type", ""),
    }


# --------------------------------------------------------------------------- #
# Canonical document
# --------------------------------------------------------------------------- #

def build_document(
    *,
    host: str,
    run_dir: Path,
    started: datetime,
    finished: datetime,
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None,
    vhosts: list[str],
    ports: list[Any],
    tool_runs: list[ToolRun],
    warnings: list[str],
) -> dict[str, Any]:
    """Distill a host run into the single dict that drives every renderer."""
    ports_doc = [{
        "number": p.number,
        "proto": p.proto,
        "state": "open",
        "service": p.service,
        "version": p.version,
        "web": p.is_web,
        "https": p.is_https,
    } for p in ports]

    # Group content tools (dir/ffuf/whatweb/curl) by web context = (port, vhost).
    web_map: dict[tuple[int | None, str | None], dict[str, Any]] = {}
    discovery: dict[str, list[str]] = {"vhost": [], "dns": []}
    exploits: list[dict[str, str]] = []
    findings: list[dict[str, Any]] = []
    tls: list[dict[str, Any]] = []
    for tr in tool_runs:
        out = tr.result.stdout or ""
        if tr.kind == "tls":
            # SAN/CN/issuer/expiry are parsed from the JSON content stored in
            # ToolResult.grepable (not a path — same convention as nuclei).
            if tr.result.ok:
                tls.append({"port": tr.port, **parse_tls_cert(tr.result.grepable)})
            continue
        if tr.kind in ("dir", "ffuf", "whatweb", "curl"):
            key = (tr.port, tr.vhost)
            entry = web_map.get(key)
            if entry is None:
                entry = {"url": tr.title, "port": tr.port, "vhost": tr.vhost,
                         "whatweb": "", "headers": {}, "gobuster": [], "ffuf": []}
                web_map[key] = entry
            if not entry["url"]:
                entry["url"] = tr.title
            if tr.kind == "dir":
                entry["gobuster"] = parse_gobuster_structured(out)
            elif tr.kind == "ffuf":
                entry["ffuf"] = parse_ffuf_structured(out)
            elif tr.kind == "whatweb":
                entry["whatweb"] = extract_whatweb(out)
            elif tr.kind == "curl":
                entry["headers"] = extract_headers(out)
        elif tr.kind == "vhost":
            discovery["vhost"] = parse_gobuster_hits(out)
        elif tr.kind == "dns":
            discovery["dns"] = parse_gobuster_hits(out)
        elif tr.kind == "searchsploit":
            exploits = parse_searchsploit(out)
        elif tr.kind == "nuclei":
            # nuclei's JSONL lands in .grepable (not stdout); tag each finding
            # with the web context it came from for the dedicated section.
            for f in parse_nuclei(tr.result.grepable or ""):
                findings.append({**f, "port": tr.port, "vhost": tr.vhost,
                                 "url": tr.title})
    findings.sort(key=lambda f: (nuclei_severity_rank(f["severity"]), f["name"]))
    tls.sort(key=lambda c: (c.get("port") is None, c.get("port") or 0))

    # Per-tool evidence files already in the run dir (reports not yet written).
    artifacts = sorted(
        p.name for p in run_dir.iterdir()
        if p.is_file() and not p.name.startswith("report.")
    ) if run_dir.exists() else []

    return {
        "tool": "reconion",
        "schema_version": SCHEMA_VERSION,
        "target": host,
        "started": started.isoformat(timespec="seconds"),
        "finished": finished.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 1),
        "scan": {
            "nmap_timing": config.get("nmap_timing", "-T4"),
            "domain": domain,
            "vhosts": list(vhosts),
            "toggles": dict(toggles),
            "wordlists": dict(config.get("wordlists", {})),
        },
        "ports": ports_doc,
        # DNS fingerprint, re-parsed from the whois/dig/axfr runs (same dual-parse
        # the pipeline does for its live map).
        "dns": build_dns_map(host, domain, tool_runs),
        # TLS certs per HTTPS port, re-parsed from the tls runs (dual-parse).
        "tls": tls,
        "web": list(web_map.values()),
        "discovery": discovery,
        "exploits": exploits,
        "findings": findings,
        "warnings": list(warnings),
        "artifacts": artifacts,
    }


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #

def _fmt_duration(seconds: float) -> str:
    return f"{seconds:.1f}s"


def _dns_has_data(dns: dict[str, Any]) -> bool:
    return bool(dns and any(dns.get(k) for k in
                ("ip_whois", "domain_whois", "records", "ptr", "axfr")))


def _ordered_records(records: dict[str, list[str]]) -> list[tuple[str, list[str]]]:
    """Record (type, values) pairs in canonical order, extras appended."""
    ordered = [(t, records[t]) for t in DIG_RECORD_TYPES if records.get(t)]
    ordered += [(t, v) for t, v in records.items() if t not in DIG_RECORD_TYPES and v]
    return ordered


_SEVERITY_DISPLAY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _severity_line(counts: dict[str, int]) -> str:
    """One-line severity breakdown, e.g. 'critical: 1  high: 3  medium: 2'."""
    return "  ".join(f"{s}: {counts[s]}" for s in _SEVERITY_DISPLAY_ORDER
                     if counts.get(s))


def _render_summary_text(doc: dict[str, Any]) -> str:
    lines: list[str] = ["recon onion — report"]
    lines.append(f"Target:        {doc['target']}")
    lines.append(f"Started:       {doc['started']}")
    lines.append(f"Finished:      {doc['finished']}")
    lines.append(f"Duration:      {_fmt_duration(doc['duration_seconds'])}")
    scan = doc["scan"]
    lines.append(f"nmap timing:   {scan.get('nmap_timing', '')}")
    if scan.get("domain"):
        lines.append(f"Domain:        {scan['domain']}")
    if scan.get("vhosts"):
        lines.append(f"Virtual hosts: {', '.join(scan['vhosts'])}")
    lines.append("")

    ports = doc["ports"]
    lines.append(f"Open ports ({len(ports)})")
    if ports:
        for p in ports:
            label = f"{p['number']}/{p['proto']}"
            svc = p["service"] or "-"
            ver = f"  {p['version']}" if p["version"] else ""
            lines.append(f"  {label:<10} {svc}{ver}")
    else:
        lines.append("  none")
    lines.append("")

    dns = doc.get("dns") or {}
    if _dns_has_data(dns):
        lines.append("DNS")
        for title, whois in (("whois (IP)", dns.get("ip_whois")),
                             ("whois (domain)", dns.get("domain_whois"))):
            if whois:
                lines.append(f"  {title}")
                for key, val in whois.items():
                    lines.append(f"    {key}: {val}")
        records = dns.get("records") or {}
        if records:
            lines.append("  Records")
            for rtype, vals in _ordered_records(records):
                lines.append(f"    {rtype}: {', '.join(vals)}")
        ptr = dns.get("ptr") or []
        if ptr:
            lines.append(f"  Reverse PTR: {', '.join(ptr)}")
        axfr = dns.get("axfr") or {}
        if axfr:
            lines.append("  Zone transfer (AXFR)")
            for ns, status in axfr.items():
                note = "  <-- zone exposed" if status == "OPEN" else ""
                lines.append(f"    {ns}: {status}{note}")
        lines.append("")

    tls = doc.get("tls") or []
    if tls:
        lines.append("TLS certificates")
        for cert in tls:
            port = cert.get("port")
            lines.append(f"  Port {port}" if port is not None else "  Certificate")
            if cert.get("cn"):
                lines.append(f"    CN:       {cert['cn']}")
            sans = cert.get("sans") or []
            if sans:
                lines.append(f"    SANs:     {', '.join(sans)}")
            if cert.get("issuer"):
                lines.append(f"    Issuer:   {cert['issuer']}")
            if cert.get("not_after"):
                lines.append(f"    Expires:  {cert['not_after']}")
        lines.append("")

    web = doc["web"]
    if web:
        lines.append("Web findings")
        for w in web:
            lines.append(f"  {w['url']}")
            if w.get("whatweb"):
                lines.append(f"    whatweb:  {w['whatweb']}")
            headers = w.get("headers") or {}
            if headers.get("status"):
                extra = []
                if headers.get("server"):
                    extra.append(f"Server: {headers['server']}")
                if headers.get("location"):
                    extra.append(f"Location: {headers['location']}")
                tail = ("  |  " + "  ".join(extra)) if extra else ""
                lines.append(f"    response: {headers['status']}{tail}")
            hits = w.get("gobuster") or []
            if hits:
                lines.append(f"    gobuster ({len(hits)}):")
                for hit in hits:
                    size = "" if hit["size"] is None else f"  size={hit['size']}"
                    redir = f"  --> {hit['redirect']}" if hit["redirect"] else ""
                    lines.append(f"      {hit['status']}  {hit['path']}{size}{redir}")
            ffuf_hits = w.get("ffuf") or []
            if ffuf_hits:
                lines.append(f"    ffuf ({len(ffuf_hits)}):")
                for hit in ffuf_hits:
                    size = "" if hit["size"] is None else f"  size={hit['size']}"
                    lines.append(f"      {hit['status']}  {hit['path']}{size}")
        lines.append("")

    findings = doc.get("findings", [])
    if findings:
        lines.append(f"Vulnerabilities — nuclei ({len(findings)})")
        summ = _severity_line(_severity_counts(findings))
        if summ:
            lines.append(f"  {summ}")
        for f in findings:
            name = f.get("name") or f.get("template_id") or "(finding)"
            lines.append(f"  [{f['severity'].upper()}] {name}")
            loc = f.get("matched_at") or f.get("url") or ""
            tid = f"  [{f['template_id']}]" if f.get("template_id") else ""
            if loc or tid:
                lines.append(f"    {loc}{tid}".rstrip())
        lines.append("")

    exploits = doc.get("exploits", [])
    if exploits:
        lines.append(f"Exploits — searchsploit ({len(exploits)})")
        for ex in exploits:
            lines.append(f"  {ex['title']}")
            lines.append(f"    {ex['path']}")
        lines.append("")

    disc = doc.get("discovery", {})
    if disc.get("vhost") or disc.get("dns"):
        lines.append("Discovery")
        for item in disc.get("vhost", []):
            lines.append(f"  vhost: {item}")
        for item in disc.get("dns", []):
            lines.append(f"  dns:   {item}")
        lines.append("")

    warnings = doc.get("warnings", [])
    if warnings:
        lines.append(f"Warnings ({len(warnings)})")
        for w in warnings:
            lines.append(f"  - {w}")
        lines.append("")

    artifacts = doc.get("artifacts", [])
    if artifacts:
        lines.append("Artifacts")
        for a in artifacts:
            lines.append(f"  - {a}")

    return "\n".join(lines).rstrip("\n") + "\n"


def _md_escape(value: Any) -> str:
    """Escape pipe chars so values don't break Markdown table cells."""
    return str(value).replace("|", "\\|")


def _render_markdown(doc: dict[str, Any]) -> str:
    lines: list[str] = [f"# recon onion report — {doc['target']}", ""]
    lines.append(f"- **Target:** {doc['target']}")
    lines.append(f"- **Started:** {doc['started']}")
    lines.append(f"- **Finished:** {doc['finished']}")
    lines.append(f"- **Duration:** {_fmt_duration(doc['duration_seconds'])}")
    scan = doc["scan"]
    lines.append(f"- **nmap timing:** `{scan.get('nmap_timing', '')}`")
    if scan.get("domain"):
        lines.append(f"- **Domain:** {scan['domain']}")
    if scan.get("vhosts"):
        lines.append(f"- **Virtual hosts:** {', '.join(scan['vhosts'])}")
    lines.append("")

    lines.append("## Open ports")
    lines.append("")
    ports = doc["ports"]
    if ports:
        lines.append("| Port | Proto | Service | Version |")
        lines.append("|---:|---|---|---|")
        for p in ports:
            lines.append(
                f"| {p['number']} | {p['proto']} | "
                f"{_md_escape(p['service'] or '-')} | {_md_escape(p['version'] or '-')} |"
            )
    else:
        lines.append("_No open ports found._")
    lines.append("")

    dns = doc.get("dns") or {}
    if _dns_has_data(dns):
        lines.append("## DNS")
        lines.append("")
        for title, whois in (("whois (IP)", dns.get("ip_whois")),
                             ("whois (domain)", dns.get("domain_whois"))):
            if whois:
                lines.append(f"**{title}**")
                lines.append("")
                for key, val in whois.items():
                    lines.append(f"- {key}: {_md_escape(val)}")
                lines.append("")
        records = dns.get("records") or {}
        if records:
            lines.append("| Type | Records |")
            lines.append("|---|---|")
            for rtype, vals in _ordered_records(records):
                lines.append(f"| {rtype} | {_md_escape(', '.join(vals))} |")
            lines.append("")
        ptr = dns.get("ptr") or []
        if ptr:
            lines.append(f"- **Reverse PTR:** {_md_escape(', '.join(ptr))}")
            lines.append("")
        axfr = dns.get("axfr") or {}
        if axfr:
            lines.append("**Zone transfer (AXFR)**")
            lines.append("")
            for ns, status in axfr.items():
                note = " — zone exposed" if status == "OPEN" else ""
                lines.append(f"- {_md_escape(ns)}: {status}{note}")
            lines.append("")

    tls = doc.get("tls") or []
    if tls:
        lines.append("## TLS certificates")
        lines.append("")
        lines.append("| Port | CN | SANs | Issuer | Expires |")
        lines.append("|---:|---|---|---|---|")
        for cert in tls:
            port = "" if cert.get("port") is None else str(cert["port"])
            sans = ", ".join(cert.get("sans") or [])
            lines.append(
                f"| {port} | {_md_escape(cert.get('cn') or '-')} | "
                f"{_md_escape(sans or '-')} | "
                f"{_md_escape(cert.get('issuer') or '-')} | "
                f"{_md_escape(cert.get('not_after') or '-')} |"
            )
        lines.append("")

    web = doc["web"]
    if web:
        lines.append("## Web findings")
        lines.append("")
        for w in web:
            lines.append(f"### {w['url']}")
            lines.append("")
            if w.get("whatweb"):
                lines.append(f"- **whatweb:** {w['whatweb']}")
            headers = w.get("headers") or {}
            if headers.get("status"):
                bits = [f"`{headers['status']}`"]
                if headers.get("server"):
                    bits.append(f"Server: `{headers['server']}`")
                if headers.get("location"):
                    bits.append(f"Location: `{headers['location']}`")
                lines.append("- **Response:** " + " — ".join(bits))
            hits = w.get("gobuster") or []
            if hits:
                lines.append("")
                lines.append("| Path | Status | Size | Redirect |")
                lines.append("|---|---:|---:|---|")
                for hit in hits:
                    size = "" if hit["size"] is None else str(hit["size"])
                    lines.append(
                        f"| {_md_escape(hit['path'])} | {hit['status']} | "
                        f"{size} | {_md_escape(hit['redirect'] or '')} |"
                    )
            ffuf_hits = w.get("ffuf") or []
            if ffuf_hits:
                lines.append("")
                lines.append("| Path (ffuf) | Status | Size |")
                lines.append("|---|---:|---:|")
                for hit in ffuf_hits:
                    size = "" if hit["size"] is None else str(hit["size"])
                    lines.append(
                        f"| {_md_escape(hit['path'])} | {hit['status']} | {size} |"
                    )
            lines.append("")

    findings = doc.get("findings", [])
    if findings:
        lines.append("## Vulnerabilities (nuclei)")
        lines.append("")
        summ = _severity_line(_severity_counts(findings))
        if summ:
            lines.append(f"_{summ}_")
            lines.append("")
        lines.append("| Severity | Finding | Location | Template | Context |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            loc = f.get("matched_at") or f.get("url") or ""
            ctx = f.get("vhost") or (f"port {f['port']}" if f.get("port") else "")
            lines.append(
                f"| {f['severity']} | {_md_escape(f.get('name') or '')} | "
                f"{_md_escape(loc)} | {_md_escape(f.get('template_id') or '')} | "
                f"{_md_escape(ctx)} |"
            )
        lines.append("")

    exploits = doc.get("exploits", [])
    if exploits:
        lines.append("## Exploits (searchsploit)")
        lines.append("")
        lines.append("| Title | Path |")
        lines.append("|---|---|")
        for ex in exploits:
            lines.append(f"| {_md_escape(ex['title'])} | {_md_escape(ex['path'])} |")
        lines.append("")

    disc = doc.get("discovery", {})
    if disc.get("vhost") or disc.get("dns"):
        lines.append("## Discovery")
        lines.append("")
        for item in disc.get("vhost", []):
            lines.append(f"- vhost: {_md_escape(item)}")
        for item in disc.get("dns", []):
            lines.append(f"- dns: {_md_escape(item)}")
        lines.append("")

    warnings = doc.get("warnings", [])
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in warnings:
            lines.append(f"- {_md_escape(w)}")
        lines.append("")

    artifacts = doc.get("artifacts", [])
    if artifacts:
        lines.append("## Artifacts")
        lines.append("")
        for a in artifacts:
            lines.append(f"- `{a}`")
        lines.append("")

    return "\n".join(lines).rstrip("\n") + "\n"


def _sub(parent: ET.Element, tag: str, text: Any = None, **attrs: Any) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: str(v) for k, v in attrs.items()})
    if text is not None:
        el.text = str(text)
    return el


def _render_xml(doc: dict[str, Any]) -> str:
    root = ET.Element("reconReport", {
        "tool": doc["tool"], "schemaVersion": str(doc["schema_version"])})
    _sub(root, "target", doc["target"])
    _sub(root, "started", doc["started"])
    _sub(root, "finished", doc["finished"])
    _sub(root, "durationSeconds", _fmt_duration(doc["duration_seconds"]).rstrip("s"))

    scan = doc["scan"]
    scan_el = ET.SubElement(root, "scan")
    _sub(scan_el, "nmapTiming", scan.get("nmap_timing", ""))
    _sub(scan_el, "domain", scan.get("domain") or "")
    vhosts_el = ET.SubElement(scan_el, "vhosts")
    for vh in scan.get("vhosts", []):
        _sub(vhosts_el, "vhost", vh)
    toggles_el = ET.SubElement(scan_el, "toggles")
    for key, val in scan.get("toggles", {}).items():
        _sub(toggles_el, "toggle", name=key, enabled=str(bool(val)).lower())
    wl_el = ET.SubElement(scan_el, "wordlists")
    for mode, path in scan.get("wordlists", {}).items():
        _sub(wl_el, "wordlist", path, mode=mode)

    ports_el = ET.SubElement(root, "ports")
    for p in doc["ports"]:
        port_el = ET.SubElement(ports_el, "port", {
            "number": str(p["number"]), "proto": p["proto"], "state": p["state"],
            "web": str(p["web"]).lower(), "https": str(p["https"]).lower()})
        _sub(port_el, "service", p["service"] or "")
        _sub(port_el, "version", p["version"] or "")

    dns = doc.get("dns") or {}
    dns_el = ET.SubElement(root, "dns", {
        "target": dns.get("target") or doc["target"],
        "domain": dns.get("domain") or ""})
    ipw_el = ET.SubElement(dns_el, "ipWhois")
    for key, val in (dns.get("ip_whois") or {}).items():
        _sub(ipw_el, "field", val, name=key)
    dw_el = ET.SubElement(dns_el, "domainWhois")
    for key, val in (dns.get("domain_whois") or {}).items():
        _sub(dw_el, "field", val, name=key)
    recs_el = ET.SubElement(dns_el, "records")
    for rtype, vals in _ordered_records(dns.get("records") or {}):
        for val in vals:
            _sub(recs_el, "record", val, type=rtype)
    rev_el = ET.SubElement(dns_el, "reverse")
    for ptr in (dns.get("ptr") or []):
        _sub(rev_el, "ptr", ptr)
    axfr_el = ET.SubElement(dns_el, "zoneTransfer")
    for ns, status in (dns.get("axfr") or {}).items():
        ET.SubElement(axfr_el, "nameserver", {"name": ns, "status": status})

    tls_el = ET.SubElement(root, "tls")
    for cert in doc.get("tls", []):
        cert_el = ET.SubElement(tls_el, "cert", {
            "port": "" if cert.get("port") is None else str(cert["port"])})
        _sub(cert_el, "cn", cert.get("cn") or "")
        _sub(cert_el, "issuer", cert.get("issuer") or "")
        _sub(cert_el, "notAfter", cert.get("not_after") or "")
        sans_el = ET.SubElement(cert_el, "sans")
        for san in cert.get("sans") or []:
            _sub(sans_el, "san", san)

    web_el = ET.SubElement(root, "web")
    for w in doc["web"]:
        target_el = ET.SubElement(web_el, "target", {
            "url": w["url"] or "",
            "port": "" if w["port"] is None else str(w["port"]),
            "vhost": w["vhost"] or ""})
        _sub(target_el, "whatweb", w.get("whatweb", ""))
        headers = w.get("headers") or {}
        headers_el = ET.SubElement(target_el, "headers",
                                   {"status": headers.get("status", "")})
        _sub(headers_el, "server", headers.get("server", ""))
        _sub(headers_el, "location", headers.get("location", ""))
        _sub(headers_el, "contentType", headers.get("content_type", ""))
        gob_el = ET.SubElement(target_el, "gobuster")
        for hit in w.get("gobuster", []):
            ET.SubElement(gob_el, "hit", {
                "path": hit["path"], "status": str(hit["status"]),
                "size": "" if hit["size"] is None else str(hit["size"]),
                "redirect": hit["redirect"] or ""})
        ffuf_el = ET.SubElement(target_el, "ffuf")
        for hit in w.get("ffuf", []):
            ET.SubElement(ffuf_el, "hit", {
                "path": hit["path"], "status": str(hit["status"]),
                "size": "" if hit["size"] is None else str(hit["size"])})

    exploits_el = ET.SubElement(root, "exploits")
    for ex in doc.get("exploits", []):
        ET.SubElement(exploits_el, "exploit",
                      {"title": ex["title"], "path": ex["path"]})

    findings_el = ET.SubElement(root, "findings")
    for f in doc.get("findings", []):
        fel = ET.SubElement(findings_el, "finding", {
            "severity": f.get("severity", ""),
            "templateId": f.get("template_id", ""),
            "type": f.get("type", ""),
            "port": "" if f.get("port") is None else str(f["port"]),
            "vhost": f.get("vhost") or ""})
        _sub(fel, "name", f.get("name", ""))
        _sub(fel, "matchedAt", f.get("matched_at", ""))
        tags_el = ET.SubElement(fel, "tags")
        for t in f.get("tags", []):
            _sub(tags_el, "tag", t)

    disc = doc.get("discovery", {})
    disc_el = ET.SubElement(root, "discovery")
    disc_vhosts = ET.SubElement(disc_el, "vhosts")
    for item in disc.get("vhost", []):
        _sub(disc_vhosts, "item", item)
    disc_dns = ET.SubElement(disc_el, "dns")
    for item in disc.get("dns", []):
        _sub(disc_dns, "item", item)

    warnings_el = ET.SubElement(root, "warnings")
    for w in doc.get("warnings", []):
        _sub(warnings_el, "warning", w)

    artifacts_el = ET.SubElement(root, "artifacts")
    for a in doc.get("artifacts", []):
        _sub(artifacts_el, "artifact", a)

    ET.indent(root)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            + ET.tostring(root, encoding="unicode") + "\n")


def _render_raw(tool_runs: list[ToolRun]) -> str:
    blocks: list[str] = []
    for tr in tool_runs:
        res = tr.result
        head = "=" * 72 + f"\n{tr.title or tr.name}\n$ {res.cmdline}\n" + "-" * 72
        if res.skipped:
            body = f"skipped — {res.error}"
        else:
            body = (res.stdout or "").rstrip("\n") or "(no output)"
            if res.stderr and res.stderr.strip() and not res.ok:
                body += "\n\n--- stderr ---\n" + res.stderr.rstrip("\n")
            if res.error:
                body += f"\n! {res.error}"
        blocks.append(f"{head}\n{body}")
    return "\n\n\n".join(blocks).rstrip("\n") + "\n"


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

def write_reports(
    run_dir: Path,
    document: dict[str, Any],
    tool_runs: list[ToolRun],
    formats: dict[str, bool],
) -> list[str]:
    """Write each selected consolidated report into *run_dir*; return filenames."""
    written: list[str] = []

    def emit(key: str, filename: str, text: str) -> None:
        if formats.get(key):
            (run_dir / filename).write_text(text, encoding="utf-8")
            written.append(filename)

    emit("summary", "report.txt", _render_summary_text(document))
    emit("raw", "report.raw.txt", _render_raw(tool_runs))
    emit("json", "report.json",
         json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    emit("xml", "report.xml", _render_xml(document))
    emit("markdown", "report.md", _render_markdown(document))
    return written
