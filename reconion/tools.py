"""Subprocess wrappers around the external recon tools.

Every wrapper:
  * builds an argv list,
  * runs it (capturing stdout/stderr),
  * writes a human-readable artifact into the run directory,
  * returns a ToolResult describing what happened.

Parsing helpers turn nmap grepable output into structured port/service
data and pull notable hits out of gobuster output.
"""

from __future__ import annotations

import json
import random
import re
import shutil
import string
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import flag_list

# Generous default; full port scans can take a while.
DEFAULT_TIMEOUT = 1800


@dataclass
class Port:
    """A single open port discovered by nmap."""

    number: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""

    @property
    def is_web(self) -> bool:
        name = self.service.lower()
        return (
            "http" in name
            or "https" in name
            or self.number in (80, 443, 8080, 8443)
        )

    @property
    def is_https(self) -> bool:
        name = self.service.lower()
        return "https" in name or "ssl" in name or self.number in (443, 8443)


@dataclass
class ToolResult:
    """Outcome of running one external tool."""

    name: str
    command: list[str] = field(default_factory=list)
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifact: Path | None = None
    skipped: bool = False
    error: str = ""
    # Secondary machine-parseable output captured to a side file (nmap grepable
    # or nuclei JSONL), kept separate from the human-readable stdout shown to the
    # user. Structured parsing reads from here, never from stdout.
    grepable: str = ""
    # Optional one-line note surfaced in the live block + artifact header (e.g.
    # an auto-calibration summary). Cosmetic; never parsed.
    note: str = ""

    @property
    def ok(self) -> bool:
        return not self.skipped and not self.error and self.returncode == 0

    @property
    def cmdline(self) -> str:
        return " ".join(self.command)


@dataclass
class ToolRun:
    """One executed tool within a host run, plus the context needed to fold it
    into consolidated reports (which web target/port/vhost it belonged to)."""

    name: str
    title: str
    result: "ToolResult"
    kind: str = ""  # scan | whois | dig | axfr | tls | dir | ffuf | vhost | dns | whatweb | curl | declared | searchsploit | nuclei
    port: int | None = None
    vhost: str | None = None


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(
    name: str,
    command: list[str],
    artifact: Path,
    *,
    write_stdout: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    note: str = "",
) -> ToolResult:
    """Run *command*, writing an artifact, and return a ToolResult.

    When *write_stdout* is True the captured stdout is written to *artifact*
    (used for tools whose primary output is stdout). When False, the tool is
    assumed to have written *artifact* itself (e.g. nmap -oN) and we only
    record a header if it didn't. *note*, when given, is recorded on the result
    and prepended to the artifact as a leading comment.
    """
    binary = command[0]
    if not tool_available(binary):
        return ToolResult(name=name, command=command, skipped=True,
                          error=f"{binary} not installed", note=note)
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(name=name, command=command, error="timed out",
                          artifact=artifact, note=note)
    except OSError as exc:  # pragma: no cover - defensive
        return ToolResult(name=name, command=command, error=str(exc), note=note)

    result = ToolResult(
        name=name,
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        artifact=artifact,
        note=note,
    )

    artifact.parent.mkdir(parents=True, exist_ok=True)
    if write_stdout:
        header = f"# {note}\n$ {result.cmdline}\n\n" if note else f"$ {result.cmdline}\n\n"
        body = proc.stdout
        if proc.stderr.strip():
            body += f"\n--- stderr ---\n{proc.stderr}"
        artifact.write_text(header + body, encoding="utf-8")
    elif not artifact.exists():
        # Tool was meant to write the file but produced nothing useful.
        artifact.write_text(
            f"$ {result.cmdline}\n\n{proc.stdout}\n{proc.stderr}",
            encoding="utf-8",
        )
    return result


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #

def _nmap(
    name: str,
    mode_flags: list[str],
    target: str,
    artifact: Path,
    *,
    timing: str,
    extra: str,
    xml: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ToolResult:
    """Run nmap with the human report on stdout (shown + saved) and grepable
    output to a side file (parsed into ports/hosts). When *xml* is given, an
    XML copy is emitted too (consumed by searchsploit --nmap)."""
    grep_path = artifact.with_suffix(".gnmap")
    command = [
        "nmap",
        *flag_list(timing),
        *mode_flags,
        *flag_list(extra),
        "-oN", "-",
        "-oG", str(grep_path),
    ]
    if xml is not None:
        command += ["-oX", str(xml)]
    command.append(target)
    result = _run(name, command, artifact, write_stdout=True, timeout=timeout)
    try:
        result.grepable = grep_path.read_text(encoding="utf-8")
    except OSError:
        result.grepable = result.stdout  # fall back to parsing the report
    return result


def nmap_sweep(target: str, artifact: Path, *, timing: str, extra: str) -> ToolResult:
    """Host-discovery ping sweep across a CIDR / range."""
    return _nmap("nmap_sweep", ["-sn"], target, artifact, timing=timing, extra=extra)


def nmap_quick(target: str, artifact: Path, *, timing: str, extra: str) -> ToolResult:
    """Fast top-ports scan (-F = top 100)."""
    return _nmap("nmap_quick", ["-F"], target, artifact, timing=timing, extra=extra)


def nmap_full(target: str, artifact: Path, *, timing: str, extra: str) -> ToolResult:
    """All 65535 TCP ports."""
    return _nmap("nmap_full", ["-p-"], target, artifact, timing=timing, extra=extra)


def nmap_service(
    target: str, ports: list[int], artifact: Path, *, timing: str, extra: str,
    xml_path: Path | None = None,
) -> ToolResult:
    """Service/version + default-script scan limited to discovered ports.

    *xml_path*, when given, captures an XML copy of the scan that searchsploit
    can consume via ``searchsploit --nmap``.
    """
    port_arg = ",".join(str(p) for p in sorted(ports))
    return _nmap(
        "nmap_service",
        ["-sV", "-sC", "-p", port_arg],
        target,
        artifact,
        timing=timing,
        extra=extra,
        xml=xml_path,
    )


def parse_grepable_hosts(stdout: str) -> list[str]:
    """Return IPs reported 'Up' in nmap grepable (-sn) output."""
    hosts: list[str] = []
    for line in stdout.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            # Format: "Host: 10.0.0.5 ()\tStatus: Up"
            parts = line.split()
            if len(parts) >= 2:
                hosts.append(parts[1])
    return hosts


def parse_grepable_ports(stdout: str) -> list[Port]:
    """Parse open ports from nmap grepable (-oG) output."""
    ports: list[Port] = []
    for line in stdout.splitlines():
        if "Ports:" not in line:
            continue
        _, _, ports_section = line.partition("Ports:")
        # Strip a trailing "\tIgnored State: ..." if present.
        ports_section = ports_section.split("\tIgnored")[0]
        for entry in ports_section.split(","):
            fields = entry.strip().split("/")
            # port/state/proto/owner/service/rpc/version
            if len(fields) < 5 or fields[1] != "open":
                continue
            try:
                number = int(fields[0])
            except ValueError:
                continue
            version = fields[6] if len(fields) > 6 else ""
            ports.append(
                Port(
                    number=number,
                    proto=fields[2] or "tcp",
                    service=fields[4],
                    version=version.strip(),
                )
            )
    # De-dupe by port number, preferring entries that carry a service name.
    best: dict[int, Port] = {}
    for p in ports:
        existing = best.get(p.number)
        if existing is None or (not existing.service and p.service):
            best[p.number] = p
    return [best[n] for n in sorted(best)]


# --------------------------------------------------------------------------- #
# Fast port scanners — rustscan + masscan
# --------------------------------------------------------------------------- #
# Speed-oriented alternatives to nmap's port discovery: they sweep all 65535
# TCP ports far faster than `nmap -p-`, then hand the open ports to the existing
# nmap_service stage for version/script detection (kept as the single source of
# service data). rustscan is the default primary full-range discovery; the
# pipeline holds nmap_full back as a fallback that runs only if the fast
# scanner(s) fail (see run_host).


def rustscan(target: str, artifact: Path, *, extra: str) -> ToolResult:
    """Fast all-ports TCP discovery with rustscan (greppable, no built-in nmap).

    ``-g`` makes rustscan emit just the open ports (``<ip> -> [22,80]``) and skip
    its own nmap hand-off, so nmap_service stays the single source of
    service/version data. ``--no-config`` ignores any ~/.rustscan.toml for
    deterministic runs. rustscan uses a TCP connect scan by default, so unlike
    masscan it needs no special privileges. Its output is already greppable, so
    it is parsed (parse_rustscan) straight from stdout, mirrored into .grepable
    to keep the "parse structured data from .grepable" invariant uniform.
    """
    command = ["rustscan", "-a", target, "-g", "--no-config", *flag_list(extra)]
    result = _run("rustscan", command, artifact, write_stdout=True)
    result.grepable = result.stdout
    return result


def masscan(target: str, artifact: Path, *, extra: str,
            prefix: str = "") -> ToolResult:
    """Fast all-ports TCP discovery with masscan; ports feed the nmap service scan.

    masscan needs raw-socket privileges (root). Per config, an optional *prefix*
    (e.g. ``sudo``) is prepended; with an empty prefix masscan is run directly
    and errors clearly if unprivileged (no auto-sudo — honours the opt-in-sudo
    convention). Results are written in nmap grepable format to a side file
    (``-oG``) and parsed by parse_grepable_ports — the same human/structured
    split as nmap. The packet rate stays conservative (config tool_flags default
    ``--rate 1000``) so the scan observes without flooding the target; never
    raise it to a level that could DoS the target (recon-only invariant).
    """
    if not tool_available("masscan"):
        return ToolResult(name="masscan", command=["masscan"], skipped=True,
                          error="masscan not installed")
    grep_path = artifact.with_suffix(".gnmap")
    # prefix (e.g. "sudo") leads the argv when set; _run re-checks command[0],
    # which is then "sudo" (present) — masscan itself was verified just above.
    command = [*flag_list(prefix), "masscan", "-p", "1-65535",
               "-oG", str(grep_path), *flag_list(extra), target]
    result = _run("masscan", command, artifact, write_stdout=True)
    try:
        result.grepable = grep_path.read_text(encoding="utf-8")
    except OSError:
        result.grepable = result.stdout  # privilege error / no results -> no file
    return result


# rustscan greppable line: "127.0.0.1 -> [22,80,443]" (empty list when none).
_RUSTSCAN_LINE_RE = re.compile(r"->\s*\[([0-9,\s]*)\]")


def parse_rustscan(text: str) -> list[Port]:
    """Parse rustscan greppable output into Ports (numbers only; no service yet).

    rustscan -g lists open TCP port numbers per host; the nmap_service stage
    fills in service/version later. Ports across all lines are merged and sorted.
    """
    found: dict[int, Port] = {}
    for line in text.splitlines():
        m = _RUSTSCAN_LINE_RE.search(line)
        if not m:
            continue
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                num = int(tok)
            except ValueError:
                continue
            found.setdefault(num, Port(number=num, proto="tcp"))
    return [found[n] for n in sorted(found)]


# --------------------------------------------------------------------------- #
# DNS infrastructure fingerprinting — whois + dig
# --------------------------------------------------------------------------- #

# Forward record types queried by dig_records (PTR comes from the -x reverse
# query). Also the canonical display order for the DNS map.
DIG_RECORD_TYPES = ["A", "AAAA", "NS", "SOA", "MX", "TXT", "CNAME"]


def whois_lookup(target: str, artifact: Path, *, extra: str) -> ToolResult:
    """Whois for an IP (netblock / org / abuse) or a domain (registrar / NS)."""
    command = ["whois", *flag_list(extra), target]
    return _run("whois", command, artifact, timeout=30)


def dig_records(domain: str | None, ip: str | None, artifact: Path, *,
                types: list[str], extra: str) -> ToolResult:
    """Forward DNS records for *domain* plus a reverse PTR for *ip*, one dig call.

    ``+noall +answer`` keeps only the answer-section records on stdout, parsed by
    parse_dig_answers and bucketed by record type (the PTR lands under "PTR").
    """
    command = ["dig", "+noall", "+answer", "+time=5", "+tries=2"]
    if domain:
        for t in (types or DIG_RECORD_TYPES):
            command += [domain, t]
    if ip:
        command += ["-x", ip]
    command += flag_list(extra)
    return _run("dig", command, artifact, timeout=30)


def dig_axfr(domain: str, nameservers: list[str], artifact: Path, *,
             extra: str) -> ToolResult:
    """Attempt a zone transfer (AXFR) of *domain* against each nameserver.

    A successful transfer means a misconfigured DNS server is exposing the whole
    zone — a recon *finding*, not an action (AXFR is a read-only query). Per-NS
    results are aggregated into one human-readable artifact, with the status
    encoded in a header line per NS so the live map and the report can both
    re-parse it (parse_axfr).
    """
    if not tool_available("dig"):
        return ToolResult(name="dig_axfr", command=["dig", "axfr"],
                          skipped=True, error="dig not installed")
    blocks: list[str] = []
    for ns in nameservers:
        command = ["dig", "+noall", "+answer", "+time=5", "+tries=1",
                   "axfr", domain, f"@{ns}", *flag_list(extra)]
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=30)
            out = (proc.stdout or "").strip()
        except (subprocess.TimeoutExpired, OSError) as exc:  # pragma: no cover
            out = f"; transfer failed: {exc}"
        answers = [ln for ln in out.splitlines()
                   if ln.strip() and not ln.startswith(";")]
        status = "OPEN" if answers else "REFUSED"
        blocks.append(f"=== AXFR {domain} @{ns} [{status}] ===\n{out or '(no data)'}")
    text = "\n\n".join(blocks)
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(text + "\n", encoding="utf-8")
    return ToolResult(name="dig_axfr", command=["dig", "axfr", domain],
                      returncode=0, stdout=text, artifact=artifact)


# whois field extraction: (display label, candidate keys [first match wins],
# multi-valued?). Keys are matched case-insensitively against the exact text
# before the first ":" on each line, so domain fields (e.g. "registrant
# organization") don't collide with IP fields (e.g. "organization").
_WHOIS_FIELDS: list[tuple[str, list[str], bool]] = [
    ("NetRange", ["netrange", "inetnum"], False),
    ("CIDR", ["cidr", "route"], False),
    ("NetName", ["netname"], False),
    ("Org", ["org-name", "orgname", "organization", "organisation", "descr"], False),
    ("Country", ["country"], False),
    ("Origin AS", ["originas", "origin"], False),
    ("Abuse", ["orgabuseemail", "abuse-mailbox"], False),
    ("Registrar", ["registrar"], False),
    ("Registrant", ["registrant organization", "registrant org", "registrant"], False),
    ("Created", ["creation date", "created"], False),
    ("Updated", ["updated date"], False),
    ("Expires", ["registry expiry date", "registrar registration expiration date",
                 "expiration date", "paid-till"], False),
    ("Name servers", ["name server", "nserver"], True),
    ("DNSSEC", ["dnssec"], False),
]


def parse_whois(text: str) -> dict[str, str]:
    """Pull a curated set of high-signal fields out of whois output (IP or domain).

    whois formats vary by RIR / registrar, so we gather every ``key: value`` line
    (case-insensitively) and select the fields in _WHOIS_FIELDS. Only fields that
    are actually present are returned, in _WHOIS_FIELDS order for stable display.
    """
    collected: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "%#*>" or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key and val:
            collected.setdefault(key, []).append(val)

    out: dict[str, str] = {}
    for label, keys, multi in _WHOIS_FIELDS:
        values: list[str] = next((collected[k] for k in keys if k in collected), [])
        if not values:
            continue
        if multi:
            deduped: list[str] = []
            for v in values:
                if v not in deduped:
                    deduped.append(v)
            out[label] = ", ".join(deduped)
        else:
            out[label] = values[0]
    return out


def parse_dig_answers(text: str) -> dict[str, list[str]]:
    """Bucket dig ``+answer`` lines by record type, preserving order, de-duped.

    Each answer line is ``name  ttl  IN  TYPE  value``; we key on TYPE and keep
    the value (which, for SOA/MX, includes the priority / serial fields).
    """
    records: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        rtype, value = parts[3], parts[4].strip()
        bucket = records.setdefault(rtype, [])
        if value not in bucket:
            bucket.append(value)
    return records


def parse_axfr(text: str) -> dict[str, str]:
    """Map nameserver -> AXFR status (OPEN / REFUSED) from dig_axfr's headers."""
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("=== AXFR") and "@" in line and "[" in line:
            ns = line.split("@", 1)[1].split()[0]
            status = line.split("[", 1)[1].split("]", 1)[0].strip()
            statuses[ns] = status
    return statuses


def build_dns_map(host: str, domain: str | None,
                  tool_runs: list["ToolRun"]) -> dict:
    """Assemble the consolidated DNS map from the whois / dig / axfr tool runs.

    Shared by the live summary (output.py) and the report (report.py) so both
    render the same structure — the dual-parse pattern used for nuclei findings.
    The whois run whose title matches *host* is the IP lookup; any other is the
    domain lookup.
    """
    ip_whois: dict[str, str] = {}
    domain_whois: dict[str, str] = {}
    records: dict[str, list[str]] = {}
    axfr: dict[str, str] = {}
    for tr in tool_runs:
        out = tr.result.stdout or ""
        if tr.kind == "whois":
            parsed = parse_whois(out)
            if not parsed:
                continue
            if tr.title == host:
                ip_whois = parsed
            else:
                domain_whois = parsed
        elif tr.kind == "dig":
            for rtype, vals in parse_dig_answers(out).items():
                bucket = records.setdefault(rtype, [])
                for v in vals:
                    if v not in bucket:
                        bucket.append(v)
        elif tr.kind == "axfr":
            axfr.update(parse_axfr(out))
    ptr = records.pop("PTR", [])
    return {
        "target": host,
        "domain": domain,
        "ip_whois": ip_whois,
        "domain_whois": domain_whois,
        "records": records,
        "ptr": ptr,
        "axfr": axfr,
    }


def ns_hostnames(records: dict[str, list[str]]) -> list[str]:
    """Nameserver hostnames (trailing dot stripped, de-duped) from NS records."""
    hosts: list[str] = []
    for v in records.get("NS", []):
        h = v.strip().rstrip(".")
        if h and h not in hosts:
            hosts.append(h)
    return hosts


# --------------------------------------------------------------------------- #
# TLS certificate inspection + SAN discovery
# --------------------------------------------------------------------------- #

# How long to wait for openssl s_client to connect / hand back the cert.
_TLS_TIMEOUT = 20

# SANs in the x509 text are a comma-separated list like
# "DNS:foo.com, DNS:*.bar.com, IP Address:1.2.3.4"; pull only the DNS entries.
_TLS_SAN_RE = re.compile(r"DNS:([^,\s]+)")
# "Subject: ... CN = example.com" — tolerate "CN=" and "CN = " spacing.
_TLS_CN_RE = re.compile(r"Subject:.*?\bCN\s*=\s*([^\n,/]+)")
# Prefer the issuer org, fall back to the issuer CN.
_TLS_ISSUER_O_RE = re.compile(r"Issuer:.*?\bO\s*=\s*([^\n,/]+)")
_TLS_ISSUER_CN_RE = re.compile(r"Issuer:.*?\bCN\s*=\s*([^\n,/]+)")
_TLS_NOT_AFTER_RE = re.compile(r"Not After\s*:\s*(.+)")


def _extract_tls_fields(x509_text: str) -> dict:
    """Pull SANs / CN / issuer / expiry out of ``openssl x509 -noout -text``.

    SANs are de-duped, order-preserving, with wildcards (``*.``) dropped (they
    aren't concrete vhost candidates). CN is included as a SAN candidate too when
    it's a plain hostname, since older certs may carry it without a SAN entry.
    """
    sans: list[str] = []
    for raw in _TLS_SAN_RE.findall(x509_text):
        name = raw.strip().rstrip(".")
        if not name or name.startswith("*."):
            continue
        if name not in sans:
            sans.append(name)

    cn = ""
    m = _TLS_CN_RE.search(x509_text)
    if m:
        cn = m.group(1).strip()

    # Surface the CN as a vhost candidate when it's a concrete hostname.
    if cn and not cn.startswith("*.") and "." in cn and cn not in sans:
        sans.append(cn)

    issuer = ""
    mi = _TLS_ISSUER_O_RE.search(x509_text) or _TLS_ISSUER_CN_RE.search(x509_text)
    if mi:
        issuer = mi.group(1).strip()

    not_after = ""
    ma = _TLS_NOT_AFTER_RE.search(x509_text)
    if ma:
        not_after = ma.group(1).strip()

    return {"sans": sans, "cn": cn, "issuer": issuer, "not_after": not_after}


def tls_cert(host: str, port: int, artifact: Path, *, extra: str = "") -> ToolResult:
    """Fetch and decode the TLS certificate presented on *host*:*port*.

    Two chained openssl calls (no shell, no string interpolation): (a)
    ``openssl s_client -connect host:port -servername host`` with empty stdin
    (s_client otherwise blocks waiting for input), then (b) the captured PEM is
    fed into ``openssl x509 -noout -text`` to decode it. The decoded text is the
    human artifact; the parsed SAN/CN/issuer/expiry is stored as a JSON string
    in ``ToolResult.grepable`` (the structured copy — same human/structured split
    as the nuclei wrapper, which also stores content rather than a path).

    *extra* flags (config ``tool_flags["tls_cert"]``) are appended to the
    s_client invocation, e.g. ``-tls1_2`` to pin a protocol version.
    """
    command = ["openssl", "s_client", "-connect", f"{host}:{port}",
               "-servername", host, *flag_list(extra)]
    json_path = artifact.with_suffix(".json")
    if not tool_available("openssl"):
        return ToolResult(name="tls_cert", command=command, skipped=True,
                          error="openssl not installed", artifact=artifact)

    artifact.parent.mkdir(parents=True, exist_ok=True)
    try:
        connect = subprocess.run(
            command, input=b"", capture_output=True, timeout=_TLS_TIMEOUT)
    except subprocess.TimeoutExpired:
        artifact.write_text(f"$ {' '.join(command)}\n\ntimed out\n",
                            encoding="utf-8")
        return ToolResult(name="tls_cert", command=command,
                          error="timed out", artifact=artifact)
    except OSError as exc:  # pragma: no cover - defensive
        return ToolResult(name="tls_cert", command=command, error=str(exc),
                          artifact=artifact)

    pem = connect.stdout or b""
    if b"BEGIN CERTIFICATE" not in pem:
        # No cert handed back: not a TLS port, handshake failed, or refused.
        msg = (connect.stderr or b"").decode("utf-8", "replace").strip()
        artifact.write_text(
            f"$ {' '.join(command)}\n\nno certificate returned\n{msg}\n",
            encoding="utf-8")
        return ToolResult(name="tls_cert", command=command,
                          returncode=connect.returncode,
                          error="no certificate returned", artifact=artifact)

    decode_cmd = ["openssl", "x509", "-noout", "-text"]
    try:
        decode = subprocess.run(
            decode_cmd, input=pem, capture_output=True, timeout=_TLS_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError) as exc:  # pragma: no cover
        return ToolResult(name="tls_cert", command=command,
                          error=f"decode failed: {exc}", artifact=artifact)

    x509_text = (decode.stdout or b"").decode("utf-8", "replace")
    artifact.write_text(
        f"$ {' '.join(command)} | {' '.join(decode_cmd)}\n\n{x509_text}",
        encoding="utf-8")

    parsed = _extract_tls_fields(x509_text)
    json_content = json.dumps(parsed, indent=2, ensure_ascii=False) + "\n"
    try:
        json_path.write_text(json_content, encoding="utf-8")
    except OSError:  # pragma: no cover - defensive; grepable carries the content
        pass

    return ToolResult(name="tls_cert", command=command, returncode=0,
                      stdout=x509_text, artifact=artifact,
                      grepable=json_content)


def parse_tls_cert(grepable: str) -> dict:
    """Parse the JSON content stored in ``ToolResult.grepable`` by tls_cert.

    *grepable* is the JSON string (content, not a path — same convention as
    nuclei). Returns a dict with keys ``sans`` (list), ``cn``, ``issuer``,
    ``not_after``.
    """
    if not grepable:
        return {}
    try:
        data = json.loads(grepable)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    sans = data.get("sans")
    return {
        "sans": list(sans) if isinstance(sans, list) else [],
        "cn": data.get("cn") or "",
        "issuer": data.get("issuer") or "",
        "not_after": data.get("not_after") or "",
    }


# --------------------------------------------------------------------------- #
# Web tools
# --------------------------------------------------------------------------- #

GOBUSTER_INTERESTING = {200, 204, 301, 302, 307, 308, 401, 403, 405}


# --------------------------------------------------------------------------- #
# Auto-calibration: catch-all ("wildcard") response detection
# --------------------------------------------------------------------------- #
# Some servers answer *every* path with the same response (a custom 403/302, a
# SPA's index.html, a WAF block, ...), so naive content discovery reports every
# wordlist entry as a "hit" and the artifact balloons to megabytes of identical
# noise. Before a gobuster/ffuf run we probe a handful of random, almost-
# certainly-absent paths; if the server answers them uniformly we inject the
# matching exclude flag so the real run filters the flood out up front instead
# of drowning in it (and gobuster doesn't abort on its own wildcard check).

# Number of random probe paths, split between two lengths so a catch-all that
# *reflects* the requested path back into the body surfaces as varying sizes.
CALIBRATION_SAMPLES = 10
_CALIB_SHORT, _CALIB_LONG = 10, 30
# Minimum usable probe responses before we trust a verdict.
_CALIB_MIN_SAMPLES = 6
# Statuses safe to blanket-filter when uniform: the "interesting" set minus the
# high-value 200/204, which we never blanket (that would hide real pages).
_BLANKET_STATUS = GOBUSTER_INTERESTING - {200, 204}

# Filter/match flags a user might set in a tool's extra flags; if any are
# present we leave calibration off and respect the explicit choice.
_GOBUSTER_FILTER_FLAGS = {"-b", "--status-codes-blacklist", "-s",
                          "--status-codes", "--exclude-length", "--wildcard"}
_FFUF_FILTER_FLAGS = {"-fc", "-fs", "-fl", "-fw", "-fr", "-ac", "-acc", "-ach",
                      "-mc", "-ms", "-ml", "-mw", "-mr"}


@dataclass
class Calibration:
    """Verdict from probing a web target for catch-all behaviour.

    ``kind`` is one of: ``none`` (no catch-all / undecidable — do nothing),
    ``size`` (every probe returned the same body size — filter that size),
    ``status`` (every probe returned the same low-value status — filter it), or
    ``warn`` (a high-value catch-all, e.g. uniform 200 with a varying body, that
    can't be filtered without hiding real pages — surface a note, filter nothing).
    """

    kind: str = "none"
    status: int = 0
    size: int = 0
    samples: list[tuple[int, int]] = field(default_factory=list)
    note: str = ""

    def gobuster_args(self) -> list[str]:
        if self.kind == "size":
            # --wildcard stops gobuster aborting on its own wildcard check; the
            # exclude-length then drops the catch-all responses from the results.
            return ["--wildcard", "--exclude-length", str(self.size)]
        if self.kind == "status":
            return ["-b", f"404,{self.status}"]
        return []

    def ffuf_args(self) -> list[str]:
        if self.kind == "size":
            return ["-fs", str(self.size)]
        if self.kind == "status":
            return ["-fc", str(self.status)]
        return []


def _random_path(length: int) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits,
                                  k=length))


def _decide_calibration(samples: list[tuple[int, int]]) -> Calibration:
    """Turn (status, size) probe samples into a Calibration verdict.

    Pure (no I/O) so the policy is unit-testable. Prefers an exact body-size
    filter (surgical — a real page of a different size still shows) and falls
    back to a status filter (robust to a catch-all that varies its body per
    path); never blanket-filters the high-value 200/204.
    """
    valid = [(c, s) for c, s in samples if c]  # drop connect failures (code 0)
    if len(valid) < _CALIB_MIN_SAMPLES:
        return Calibration()
    statuses = {c for c, _ in valid}
    sizes = {s for _, s in valid}
    if statuses == {404}:
        return Calibration()  # proper 404s; the default 404 exclusion handles it
    if len(sizes) == 1:
        size = next(iter(sizes))
        if size > 0:
            return Calibration(
                kind="size", size=size, samples=valid,
                note=f"auto-calibration: catch-all detected (every probe -> "
                     f"size {size}); filtering responses of size {size}")
    if len(statuses) == 1:
        status = next(iter(statuses))
        if status in _BLANKET_STATUS:
            return Calibration(
                kind="status", status=status, samples=valid,
                note=f"auto-calibration: catch-all detected (every probe -> "
                     f"HTTP {status}); filtering status {status}")
        if status in (200, 204):
            return Calibration(
                kind="warn", status=status, samples=valid,
                note=f"auto-calibration: catch-all HTTP {status} with a varying "
                     f"body; not auto-filtering (would hide real pages) -- add a "
                     f"manual size/regex filter if the output floods")
    return Calibration()


def calibrate_web(url: str, *, host_header: str | None = None) -> Calibration:
    """Probe *url* with random absent paths and judge catch-all behaviour.

    One curl call fetches CALIBRATION_SAMPLES random paths (mixed lengths) and
    reports each response's status + body size; _decide_calibration turns the
    samples into a verdict. Any failure (curl missing, target down, timeout)
    degrades to a no-op ``none`` verdict so a flaky probe never invents a filter.
    """
    if not tool_available("curl"):
        return Calibration()
    base = url.rstrip("/")
    insecure = base.lower().startswith("https://")
    half = CALIBRATION_SAMPLES // 2
    lengths = [_CALIB_SHORT] * half + [_CALIB_LONG] * (CALIBRATION_SAMPLES - half)
    probe_urls = [f"{base}/{_random_path(n)}" for n in lengths]
    command = ["curl", "-sS", "--connect-timeout", "4", "--max-time", "20",
               "-w", "%{http_code} %{size_download}\n"]
    if insecure:
        command.append("-k")
    if host_header:
        command += ["-H", f"Host: {host_header}"]
    # curl applies -o per URL: pair a /dev/null sink with each probe path. A
    # single shared -o would only sink the first URL, leaking the other response
    # bodies onto stdout and corrupting the -w samples.
    for probe in probe_urls:
        command += ["-o", "/dev/null", probe]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return Calibration()
    samples: list[tuple[int, int]] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            code, size = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        samples.append((code, size))  # code 0 (== curl 000) means connect failed
    return _decide_calibration(samples)


def calibrate_vhost(url: str, base_domain: str, *, insecure: bool) -> Calibration:
    """The vhost analogue of calibrate_web: probe random Host headers under
    *base_domain* against *url* (the target IP) and judge catch-all behaviour.

    Used as the false-positive guard before a *recursive* vhost sweep: if the
    server answers a handful of random, certainly-nonexistent virtual hosts
    (``<random>.<base_domain>``) with a uniform status/size, it's a catch-all and
    any vhost 'discovered' under it is bogus — so recursing would never end. A
    non-``none`` verdict means catch-all. Unlike calibrate_web the Host header is
    what varies, and curl applies ``-H`` to the whole invocation (not per-URL),
    so each probe is its own curl call. Any failure degrades to ``none`` — but
    callers should treat that conservatively, since 'undecidable' is not 'safe'.
    """
    if not tool_available("curl"):
        return Calibration()
    base = url.rstrip("/")
    half = CALIBRATION_SAMPLES // 2
    lengths = [_CALIB_SHORT] * half + [_CALIB_LONG] * (CALIBRATION_SAMPLES - half)
    samples: list[tuple[int, int]] = []
    for n in lengths:
        host_header = f"{_random_path(n)}.{base_domain}"
        command = ["curl", "-sS", "--connect-timeout", "4", "--max-time", "15",
                   "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
                   "-H", f"Host: {host_header}"]
        if insecure:
            command.append("-k")
        command.append(base)
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=20)
        except (subprocess.TimeoutExpired, OSError):
            continue
        parts = proc.stdout.split()
        if len(parts) != 2:
            continue
        try:
            samples.append((int(parts[0]), int(parts[1])))
        except ValueError:
            continue
    return _decide_calibration(samples)


def _user_filters_present(extra: str, flags: set[str]) -> bool:
    """True if *extra* already sets one of *flags* (so we skip calibration)."""
    for tok in flag_list(extra):
        if tok in flags or tok.split("=", 1)[0] in flags:
            return True
    return False


def gobuster_dir(url: str, wordlist: str, artifact: Path, *, extra: str,
                 insecure: bool, host_header: str | None = None,
                 calibrate: bool = False) -> ToolResult:
    command = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-color"]
    if insecure:
        command.append("-k")
    if host_header:
        # Target the IP but route to the right virtual host via the Host header,
        # so no /etc/hosts entry is required.
        command += ["-H", f"Host: {host_header}"]
    note = ""
    if (calibrate and tool_available("gobuster")
            and not _user_filters_present(extra, _GOBUSTER_FILTER_FLAGS)):
        cal = calibrate_web(url, host_header=host_header)
        command += cal.gobuster_args()
        note = cal.note
    command += flag_list(extra)
    return _run("gobuster_dir", command, artifact, note=note)


def ffuf_dir(url: str, wordlist: str, artifact: Path, *, extra: str,
             host_header: str | None = None,
             calibrate: bool = False) -> ToolResult:
    """Fast content discovery: fuzz the FUZZ keyword at the URL path.

    ffuf ignores TLS cert errors by default, so no insecure flag is needed for
    https targets. Like gobuster_dir, a Host header can target a virtual host on
    the same IP without an /etc/hosts entry.
    """
    fuzz_url = url.rstrip("/") + "/FUZZ"
    command = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-noninteractive"]
    if host_header:
        command += ["-H", f"Host: {host_header}"]
    note = ""
    if (calibrate and tool_available("ffuf")
            and not _user_filters_present(extra, _FFUF_FILTER_FLAGS)):
        # Calibrate against the base URL, not the FUZZ path.
        cal = calibrate_web(url, host_header=host_header)
        command += cal.ffuf_args()
        note = cal.note
    command += flag_list(extra)
    return _run("ffuf", command, artifact, note=note)


def gobuster_dns(domain: str, wordlist: str, artifact: Path, *, extra: str) -> ToolResult:
    command = ["gobuster", "dns", "-d", domain, "-w", wordlist, "-q", "--no-color"]
    command += flag_list(extra)
    return _run("gobuster_dns", command, artifact)


def gobuster_vhost(url: str, wordlist: str, artifact: Path, *, extra: str,
                   insecure: bool, domain: str | None = None) -> ToolResult:
    """Virtual-host discovery against *url* (the target IP).

    When *domain* is given, gobuster appends it to every wordlist word
    (``--domain <domain> --append-domain``): a bare subdomain wordlist (www, dev,
    ...) becomes Host headers ``www.<domain>`` etc. sent to the IP — the rootless
    pattern. The explicit ``--domain`` is essential for an IP target: plain
    ``--append-domain`` appends the *URL host*, i.e. the IP, giving useless
    ``www.<ip>`` probes. When *domain* is None the wordlist entries are sent
    verbatim as fully-qualified Host headers.
    """
    command = ["gobuster", "vhost", "-u", url, "-w", wordlist, "-q", "--no-color"]
    if domain:
        command += ["--domain", domain, "--append-domain"]
    if insecure:
        command.append("-k")
    command += flag_list(extra)
    return _run("gobuster_vhost", command, artifact)


def whatweb(url: str, artifact: Path, *, extra: str,
            host_header: str | None = None) -> ToolResult:
    command = ["whatweb", "--color=never"]
    if host_header:
        command += ["--header", f"Host: {host_header}"]
    command += [*flag_list(extra), url]
    return _run("whatweb", command, artifact)


def curl_headers(url: str, artifact: Path, *, insecure: bool, extra: str,
                 resolve: tuple[str, int, str] | None = None) -> ToolResult:
    command = ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", "20"]
    if insecure:
        command.append("-k")
    if resolve:
        # --resolve host:port:ip pins DNS *and* TLS SNI to the target IP while
        # the URL keeps the hostname — the rootless equivalent of /etc/hosts.
        host, port, ip = resolve
        command += ["--resolve", f"{host}:{port}:{ip}"]
    command += flag_list(extra)
    command.append(url)
    return _run("curl", command, artifact)


def parse_gobuster_hits(stdout: str) -> list[str]:
    """Return notable path lines from gobuster dir/vhost output."""
    hits: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("===", "Progress:", "[")):
            continue
        if "Status:" in line:
            status_token = line.split("Status:")[1].strip().split(")")[0].strip()
            try:
                status = int(status_token)
            except ValueError:
                hits.append(line)
                continue
            if status in GOBUSTER_INTERESTING:
                hits.append(line)
        elif line.startswith("Found:"):  # dns mode
            hits.append(line)
    return hits


# Recursion helpers: pull the *recursable* targets out of gobuster output.
# A directory hit, e.g.:  /admin   (Status: 301) [Size: 312] [--> /admin/]
_DIR_LINE_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s*\[Size:\s*\d+\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]*)\])?"
)
# 30x to "<path>/" is gobuster's canonical "this is a folder" signal.
_DIR_REDIRECT_STATUS = {301, 302, 307, 308}
# A vhost hit, e.g.:  Found: admin.example.com Status: 200 [Size: 1234]
_VHOST_LINE_RE = re.compile(r"^Found:\s*(?P<host>[^\s(]+)")


def recursable_dirs(stdout: str) -> list[str]:
    """Word-paths from gobuster *dir* output worth recursing into.

    A hit is treated as a directory when it redirects (30x) to its own path with
    a trailing slash, or returns 200/401/403 on an extension-less path. Leaf
    files (a 200 on /index.php, a redirect off elsewhere, ...) are skipped so
    recursion drills into structure, not files. Paths are returned relative to
    the scanned base (the leading slash stripped) de-duplicated in first-seen
    order — gobuster reports each hit relative to its ``-u`` URL, so the caller
    rebuilds the full path itself.
    """
    found: list[str] = []
    seen: set[str] = set()
    for raw in stdout.splitlines():
        line = raw.strip()
        if "Status:" not in line:
            continue
        m = _DIR_LINE_RE.match(line)
        if not m:
            continue
        status = int(m.group("status"))
        if status not in GOBUSTER_INTERESTING:
            continue
        path = m.group("path").strip("/")
        if not path or path in seen:
            continue
        redirect = (m.group("redirect") or "").strip()
        is_dir = False
        if status in _DIR_REDIRECT_STATUS:
            # No captured redirect (older gobuster) or one ending in "/" -> folder.
            is_dir = not redirect or redirect.rstrip().endswith("/")
        elif status in (200, 401, 403):
            # Extension-less final segment -> treat as a directory, not a file.
            is_dir = "." not in path.rsplit("/", 1)[-1]
        if is_dir:
            seen.add(path)
            found.append(path)
    return found


def found_vhosts(stdout: str) -> list[str]:
    """Virtual-host names reported by gobuster *vhost* output (``Found:`` lines),
    de-duplicated in first-seen order, trailing dots stripped."""
    hosts: list[str] = []
    seen: set[str] = set()
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line.startswith("Found:"):
            continue
        m = _VHOST_LINE_RE.match(line)
        if not m:
            continue
        name = m.group("host").strip().rstrip(".")
        if name and name not in seen:
            seen.add(name)
            hosts.append(name)
    return hosts


# ffuf result line: "admin   [Status: 301, Size: 312, Words: 20, Lines: 10, ...]"
_FFUF_LINE_RE = re.compile(
    r"^\s*(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),"
    r"\s*Size:\s*(?P<size>\d+)"
)


def parse_ffuf_hits(stdout: str) -> list[str]:
    """Return notable result lines from ffuf output (status-filtered)."""
    hits: list[str] = []
    for line in stdout.splitlines():
        m = _FFUF_LINE_RE.match(line)
        if m and int(m.group("status")) in GOBUSTER_INTERESTING:
            hits.append(line.strip())
    return hits


def parse_ffuf_structured(stdout: str) -> list[dict]:
    """Parse ffuf output into {path, status, size} records."""
    hits: list[dict] = []
    for line in stdout.splitlines():
        m = _FFUF_LINE_RE.match(line)
        if not m:
            continue
        status = int(m.group("status"))
        if status not in GOBUSTER_INTERESTING:
            continue
        hits.append({
            "path": m.group("path"),
            "status": status,
            "size": int(m.group("size")),
        })
    return hits


# --------------------------------------------------------------------------- #
# Passive path discovery — server-declared files
# --------------------------------------------------------------------------- #
# robots.txt, sitemap.xml and .well-known/security.txt are files a server
# *publishes about itself*: disallowed paths, the site's URL map, a security
# contact. Reading them turns up real paths/hosts with no brute force at all, so
# this stays strictly recon-only (unlike gobuster, which guesses). Each file is
# fetched with its own curl call (mirroring curl_headers, incl. --resolve for a
# rootless vhost context); the concatenated bodies are the human artifact and
# the extracted structure is a JSON string in ToolResult.grepable (content, not
# a path — the tls_cert / nuclei convention) for the report's dual-parse.

_DECLARED_FILES = ("robots.txt", "sitemap.xml", ".well-known/security.txt")
# Cap the body kept per file in the artifact (a sitemap can be huge) and the
# number of sitemap <loc> URLs retained (bounds report / JSON size).
_DECLARED_MAX_BODY = 20000
_DECLARED_SITEMAP_LIMIT = 100
# Known security.txt fields (RFC 9116); other lines are ignored so an HTML or
# catch-all body can't inject noise.
_SECURITY_FIELDS = {
    "contact", "expires", "encryption", "acknowledgments", "acknowledgements",
    "preferred-languages", "canonical", "policy", "hiring", "csaf",
}
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)
# curl -w marker appended after each body so the status code can be split back
# out of stdout without a second request.
_DECLARED_STATUS_MARKER = "<<<HTTP {code}>>>"
_DECLARED_STATUS_RE = re.compile(r"<<<HTTP (\d+)>>>")


def _looks_like_html(body: str) -> bool:
    """True when a supposedly plaintext/xml file is actually an HTML page — the
    tell-tale of a catch-all / SPA answering every path with index.html."""
    head = body.lstrip()[:512].lower()
    return head.startswith("<!doctype html") or "<html" in head


def _split_declared_output(raw: str) -> tuple[str, str]:
    """Split a curl body from the trailing '<<<HTTP nnn>>>' status marker."""
    idx = raw.rfind("<<<HTTP ")
    if idx == -1:
        return raw, ""
    m = _DECLARED_STATUS_RE.search(raw[idx:])
    return raw[:idx].rstrip("\n"), (m.group(1) if m else "")


def parse_robots(text: str) -> dict[str, list[str]]:
    """Extract declared paths (Disallow/Allow) and Sitemap URLs from robots.txt.

    Only the directive lines are read, so an HTML/catch-all body yields nothing.
    An empty ``Disallow:`` (= allow all) carries no path, so it is skipped.
    """
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key, val = key.strip().lower(), val.strip()
        if not val:
            continue
        if key in ("disallow", "allow"):
            if val not in paths:
                paths.append(val)
        elif key == "sitemap":
            if val not in sitemaps:
                sitemaps.append(val)
    return {"paths": paths, "sitemaps": sitemaps}


def parse_sitemap(xml: str, *, limit: int = _DECLARED_SITEMAP_LIMIT) -> list[str]:
    """Extract <loc> URLs from a sitemap (or sitemap index), de-duped, capped.

    Regex rather than an XML parse so namespaced / slightly-malformed sitemaps
    still yield their URLs. Handles both a URL set (page URLs) and a sitemap
    index (child-sitemap URLs); either is surfaced without chasing nested files.
    """
    urls: list[str] = []
    for raw in _SITEMAP_LOC_RE.findall(xml):
        u = raw.strip()
        if u and u not in urls:
            urls.append(u)
            if len(urls) >= limit:
                break
    return urls


def parse_security_txt(text: str) -> dict[str, list[str]]:
    """Parse .well-known/security.txt into {field: [values]} for known fields."""
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key, val = key.strip().lower(), val.strip()
        if key in _SECURITY_FIELDS and val:
            bucket = fields.setdefault(key, [])
            if val not in bucket:
                bucket.append(val)
    return fields


def fetch_declared(url: str, artifact: Path, *, insecure: bool, extra: str,
                   resolve: tuple[str, int, str] | None = None) -> ToolResult:
    """Fetch the server-declared files under *url* and extract what they expose.

    Composite wrapper (like dig_axfr / tls_cert): one curl per file, a header
    line per file recording its HTTP status, and a JSON structure in
    ToolResult.grepable. Only an HTTP 200 text body is mined; a non-200, empty,
    or HTML (catch-all) body is recorded but not parsed, so no false paths leak
    in. *resolve* pins DNS+SNI to the target IP for a vhost context (curl
    --resolve), exactly like curl_headers, so no /etc/hosts entry is needed.
    """
    if not tool_available("curl"):
        return ToolResult(name="declared", command=["curl"], skipped=True,
                          error="curl not installed", artifact=artifact)
    base = url.rstrip("/")
    data: dict[str, Any] = {"found": [], "robots_paths": [], "sitemaps": [],
                            "sitemap_urls": [], "security": {}}
    blocks: list[str] = []
    shown: list[str] | None = None
    for fname in _DECLARED_FILES:
        command = ["curl", "-sS", "-L", "--max-redirs", "3",
                   "--connect-timeout", "5", "--max-time", "20", "-w",
                   "\n" + _DECLARED_STATUS_MARKER.format(code="%{http_code}")]
        if insecure:
            command.append("-k")
        if resolve:
            rhost, rport, rip = resolve
            command += ["--resolve", f"{rhost}:{rport}:{rip}"]
        command += flag_list(extra)
        command.append(f"{base}/{fname}")
        if shown is None:
            shown = command  # a representative command for the header / report
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  timeout=30)
        except (subprocess.TimeoutExpired, OSError) as exc:  # pragma: no cover
            blocks.append(f"=== {fname} [ERROR] ===\n{exc}")
            continue
        body, status = _split_declared_output(proc.stdout or "")
        label = f"=== {fname} [HTTP {status or '000'}] ==="
        if status != "200" or not body.strip():
            blocks.append(f"{label}\n(no content)")
            continue
        if _looks_like_html(body):
            blocks.append(f"{label}\n(looks like HTML — treated as catch-all, "
                          "not parsed)")
            continue
        shown_body = (body if len(body) <= _DECLARED_MAX_BODY
                      else body[:_DECLARED_MAX_BODY] + "\n... (truncated)")
        blocks.append(f"{label}\n{shown_body}")
        data["found"].append(fname)
        if fname == "robots.txt":
            parsed = parse_robots(body)
            data["robots_paths"], data["sitemaps"] = (
                parsed["paths"], parsed["sitemaps"])
        elif fname == "sitemap.xml":
            data["sitemap_urls"] = parse_sitemap(body)
        else:
            data["security"] = parse_security_txt(body)

    text = "\n\n".join(blocks) + "\n"
    command = shown or ["curl"]
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(f"$ {' '.join(command)}\n\n{text}", encoding="utf-8")
    return ToolResult(name="declared", command=command, returncode=0,
                      stdout=text, artifact=artifact,
                      grepable=json.dumps(data, ensure_ascii=False))


def parse_declared(grepable: str) -> dict[str, Any]:
    """Re-read the JSON that fetch_declared stored in ToolResult.grepable.

    Content, not a path (same convention as parse_tls_cert / parse_nuclei); the
    report re-parses it independently of the pipeline (dual-parse).
    """
    if not grepable:
        return {}
    try:
        data = json.loads(grepable)
    except (json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    sec = data.get("security")
    return {
        "found": list(data.get("found") or []),
        "robots_paths": list(data.get("robots_paths") or []),
        "sitemaps": list(data.get("sitemaps") or []),
        "sitemap_urls": list(data.get("sitemap_urls") or []),
        "security": {k: list(v) for k, v in sec.items()}
                    if isinstance(sec, dict) else {},
    }


def _preview(items: list[str], n: int) -> str:
    """A comma-joined preview of the first *n* items, with a '+N more' tail."""
    head = ", ".join(items[:n])
    return head + (f"  (+{len(items) - n} more)" if len(items) > n else "")


def declared_items(d: dict[str, Any]) -> list[tuple[str, str]]:
    """Flatten a parsed 'declared' dict into (label, value) rows for display.

    Shared by the live summary and the text / markdown reports so all three show
    the same rows (the XML report emits the full lists instead). Long lists are
    previewed; returns [] when nothing worth showing was declared.
    """
    items: list[tuple[str, str]] = []
    robots = d.get("robots_paths") or []
    if robots:
        items.append((f"robots.txt ({len(robots)} paths)", _preview(robots, 12)))
    sitemaps = d.get("sitemaps") or []
    if sitemaps:
        items.append(("declared sitemaps", ", ".join(sitemaps)))
    sm_urls = d.get("sitemap_urls") or []
    if sm_urls:
        items.append((f"sitemap.xml ({len(sm_urls)} URLs)", _preview(sm_urls, 8)))
    security = d.get("security") or {}
    for key in ("contact", "policy", "expires", "encryption", "canonical",
                "acknowledgments", "acknowledgements", "preferred-languages",
                "hiring", "csaf"):
        if security.get(key):
            items.append((f"security.txt {key}", ", ".join(security[key])))
    return items


# --------------------------------------------------------------------------- #
# Exploit search
# --------------------------------------------------------------------------- #

def searchsploit_nmap(xml_path: Path, artifact: Path, *, extra: str) -> ToolResult:
    """Search Exploit-DB for the services in an nmap service-scan XML file.

    `searchsploit --nmap` parses the XML itself and searches each product /
    version it finds — far more reliable than building search terms by hand.
    Output is uncoloured automatically when not attached to a tty.
    """
    command = ["searchsploit", "--nmap", str(xml_path)]
    command += flag_list(extra)
    return _run("searchsploit", command, artifact)


def parse_searchsploit(stdout: str) -> list[dict]:
    """Parse searchsploit's two-column table into {title, path} records.

    Tolerant of the box-drawing layout: data rows are 'Title | path'; header,
    separator and 'No Results' lines are skipped.
    """
    results: list[dict] = []
    for raw in stdout.splitlines():
        if "|" not in raw:
            continue
        stripped = raw.strip()
        if not stripped or set(stripped) <= set("-=| "):
            continue  # separator / rule line
        title, _, path = raw.rpartition("|")
        title, path = title.strip(), path.strip()
        if not title or not path:
            continue
        if title.lower().startswith(("exploit title", "shellcode title",
                                     "paper title")):
            continue  # column header
        results.append({"title": title, "path": path})
    return results


# --------------------------------------------------------------------------- #
# Recon scanning — nuclei (template-based, detection + version CVEs only)
# --------------------------------------------------------------------------- #

# Severity ranking for sorting findings most-urgent first (unknown sorts last).
NUCLEI_SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
}


def nuclei_severity_rank(severity: str) -> int:
    """Sort key for a nuclei severity (lower = more urgent)."""
    return NUCLEI_SEVERITY_ORDER.get((severity or "unknown").lower(), 5)


def nuclei(url: str, artifact: Path, *, extra: str,
           host_header: str | None = None) -> ToolResult:
    """Run nuclei against a single URL and capture its findings.

    Human-readable findings go to stdout (shown live + saved to *artifact*); a
    JSONL copy is exported to a side file and read into ToolResult.grepable for
    structured parsing — the same human/structured split as the nmap wrappers.

    Update checks are disabled so runs stay offline and deterministic: templates
    must already be installed (run ``nuclei -update-templates`` out of band).
    nuclei's HTTP client ignores TLS errors by default, so https needs no extra
    flag. A Host header targets a virtual host on the same IP — the rootless
    equivalent of an /etc/hosts entry. The recon-only template scope (detection
    + version CVEs, nothing intrusive) lives in config tool_flags["nuclei"].
    """
    jsonl_path = artifact.with_suffix(".jsonl")
    command = [
        "nuclei", "-target", url,
        "-jsonl-export", str(jsonl_path),
        "-disable-update-check", "-no-color",
    ]
    if host_header:
        command += ["-H", f"Host: {host_header}"]
    command += flag_list(extra)
    result = _run("nuclei", command, artifact)
    try:
        result.grepable = jsonl_path.read_text(encoding="utf-8")
    except OSError:
        result.grepable = ""  # no findings -> nuclei writes no export file
    return result


def parse_nuclei(jsonl: str) -> list[dict]:
    """Parse nuclei's JSONL export into severity-sorted finding records.

    Each line is one JSON finding; malformed/blank lines are skipped. Returns
    {template_id, name, severity, matched_at, tags, type} dicts, most-urgent
    first.
    """
    findings: list[dict] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info")
        info = info if isinstance(info, dict) else {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        findings.append({
            "template_id": obj.get("template-id") or "",
            "name": (info.get("name") or "").strip(),
            "severity": (info.get("severity") or "unknown").strip().lower(),
            "matched_at": (obj.get("matched-at") or obj.get("host") or "").strip(),
            "tags": list(tags),
            "type": (obj.get("type") or "").strip(),
        })
    findings.sort(key=lambda f: (nuclei_severity_rank(f["severity"]), f["name"]))
    return findings
