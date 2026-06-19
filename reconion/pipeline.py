"""Per-host pipeline orchestration.

Stage flow for a single host:
  1. quick (top-ports) + 2. full (all ports)   -> run in parallel
  3. service/version/script scan                -> on the union of open ports
  4. gobuster + whatweb + curl                  -> in parallel, per web port

Hosts are processed one at a time by the caller; the parallelism here is
*within* a single host.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from rich.console import Console

from . import report, tools
from .output import make_run_dir, print_summary, print_tool_block
from .tools import Port, ToolResult, ToolRun

# Toggle keys, all default-on except the optional gobuster modes and ffuf.
DEFAULT_TOGGLES: dict[str, bool] = {
    "nmap_quick": True,
    "nmap_full": True,
    "nmap_service": True,
    "whois": True,
    "dig": True,
    "tls_cert": True,
    "searchsploit": True,
    "gobuster_dir": True,
    "ffuf": False,           # opt-in: enable manually via 'Modify run'
    "gobuster_dns": False,
    "gobuster_vhost": False,
    "whatweb": True,
    "curl": True,
    "nuclei": False,         # opt-in: heavy/noisy; enable via 'Modify run'
    # Not a tool: a pre-scan probe that auto-detects catch-all ("wildcard")
    # responses and injects the matching exclude flag into gobuster_dir / ffuf.
    "auto_calibrate": True,
}


@dataclass
class HostResult:
    host: str
    run_dir: Path
    ports: list[Port] = field(default_factory=list)
    gobuster_hits: dict[str, list[str]] = field(default_factory=dict)
    ffuf_hits: dict[str, list[str]] = field(default_factory=dict)
    exploits: list[dict] = field(default_factory=list)
    # TLS certs per HTTPS port: {port, cn, sans, issuer, not_after}.
    tls: list[dict] = field(default_factory=list)
    # nuclei findings, flat across all web ports/vhosts (context on each record).
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Every tool executed this run, in completion order, for report building.
    tool_runs: list[ToolRun] = field(default_factory=list)


def _record(result: ToolResult, errors: list[str]) -> None:
    if result.skipped:
        errors.append(f"{result.name}: skipped ({result.error})")
    elif result.error:
        errors.append(f"{result.name}: {result.error}")
    elif result.returncode not in (0, None):
        errors.append(f"{result.name}: exit {result.returncode}")


def _merge_ports(*groups: list[Port]) -> dict[int, Port]:
    merged: dict[int, Port] = {}
    for group in groups:
        for p in group:
            existing = merged.get(p.number)
            if existing is None:
                merged[p.number] = p
            else:
                # Prefer richer service/version info.
                if not existing.service and p.service:
                    existing.service = p.service
                if not existing.version and p.version:
                    existing.version = p.version
    return merged


def run_host(
    console: Console,
    host: str,
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None = None,
    vhosts: list[str] | None = None,
) -> HostResult:
    """Run the full pipeline against one host and return its results.

    *vhosts* are virtual-host names to enumerate via Host-header injection
    (gobuster -H / curl --resolve / whatweb --header) against the target IP.
    """
    timing = config.get("nmap_timing", "-T4")
    tflags = config.get("tool_flags", {})
    wordlists = config.get("wordlists", {})
    run_dir = make_run_dir(config.get("output_dir", "./recon"), host)
    result = HostResult(host=host, run_dir=run_dir)
    started = datetime.now()

    console.rule(f"[bold cyan]Recon — {host}[/bold cyan]")
    console.print(f"[dim]Output: {run_dir}[/dim]")

    # ---- Stage 1: initial recon — port scan + DNS, all in parallel ---------
    # nmap quick/full and the DNS fingerprint (whois + dig) have no dependency
    # on each other, so they run together as the opening recon burst. Each job
    # is (name, kind, title, callable); the kind routes how its result is used.
    quick_ports: list[Port] = []
    full_ports: list[Port] = []
    record_types = (config.get("dns", {}).get("record_types") or "").split()
    init_jobs: list[tuple[str, str, str, Callable[[], ToolResult]]] = []
    if toggles.get("nmap_quick", True):
        init_jobs.append(("nmap_quick", "scan", "nmap_quick", lambda:
            tools.nmap_quick(host, run_dir / "nmap_quick.txt", timing=timing,
                             extra=tflags.get("nmap_quick", ""))))
    if toggles.get("nmap_full", True):
        init_jobs.append(("nmap_full", "scan", "nmap_full", lambda:
            tools.nmap_full(host, run_dir / "nmap_full.txt", timing=timing,
                            extra=tflags.get("nmap_full", ""))))
    if toggles.get("whois", True):
        init_jobs.append(("whois", "whois", host, lambda ip=host:
            tools.whois_lookup(ip, run_dir / "whois_ip.txt",
                               extra=tflags.get("whois", ""))))
        if domain:
            init_jobs.append(("whois", "whois", domain, lambda d=domain:
                tools.whois_lookup(d, run_dir / f"whois_{_slug(d)}.txt",
                                   extra=tflags.get("whois", ""))))
    if toggles.get("dig", True):
        init_jobs.append(("dig", "dig", domain or host,
            lambda d=domain, ip=host, rt=record_types: tools.dig_records(
                d, ip, run_dir / "dig.txt", types=rt,
                extra=tflags.get("dig", ""))))

    if init_jobs:
        console.print("\n[bold]▶ Initial recon — port scan + DNS (parallel)[/bold]")
        with ThreadPoolExecutor(max_workers=len(init_jobs)) as ex:
            futures = {ex.submit(fn): (name, kind, title)
                       for name, kind, title, fn in init_jobs}
            for fut in as_completed(futures):
                name, kind, title = futures[fut]
                res = fut.result()
                _record(res, result.errors)
                disp = name if kind == "scan" else f"{name} — {title}"
                print_tool_block(console, disp, res)
                result.tool_runs.append(
                    ToolRun(name=name, title=title, result=res, kind=kind))
                if kind == "scan":
                    found = tools.parse_grepable_ports(res.grepable)
                    if name == "nmap_quick":
                        quick_ports = found
                    else:
                        full_ports = found

    merged = _merge_ports(quick_ports, full_ports)
    open_ports = sorted(merged.values(), key=lambda p: p.number)
    if open_ports:
        console.print(
            "  Open ports: "
            + ", ".join(str(p.number) for p in open_ports)
        )

    # ---- Stage 1b: DNS zone transfer (AXFR) against discovered nameservers --
    # Depends on the NS records from the dig stage above, so it follows it.
    if toggles.get("dig", True) and domain:
        ns_hosts = tools.ns_hostnames(
            tools.build_dns_map(host, domain, result.tool_runs)["records"])
        if ns_hosts:
            console.print("\n[bold]▶ DNS zone transfer — AXFR[/bold]")
            res = tools.dig_axfr(domain, ns_hosts, run_dir / "dig_axfr.txt",
                                 extra=tflags.get("dig", ""))
            _record(res, result.errors)
            print_tool_block(console, f"dig_axfr — {domain}", res)
            result.tool_runs.append(ToolRun(
                name="dig_axfr", title=domain, result=res, kind="axfr"))

    # ---- Stage 3: service/version/script scan ------------------------------
    service_xml = run_dir / "nmap_service.xml"
    if open_ports and toggles.get("nmap_service", True):
        console.print("\n[bold]▶ Service / version / script scan[/bold]")
        res = tools.nmap_service(
            host, [p.number for p in open_ports],
            run_dir / "nmap_service.txt", timing=timing,
            extra=tflags.get("nmap_service", ""), xml_path=service_xml)
        _record(res, result.errors)
        print_tool_block(console, "nmap_service", res)
        result.tool_runs.append(
            ToolRun(name="nmap_service", title="nmap_service", result=res,
                    kind="scan"))
        svc_ports = tools.parse_grepable_ports(res.grepable)
        merged = _merge_ports(open_ports, svc_ports)
        # service scan is authoritative for service/version
        for sp in svc_ports:
            if sp.number in merged:
                if sp.service:
                    merged[sp.number].service = sp.service
                if sp.version:
                    merged[sp.number].version = sp.version
        open_ports = sorted(merged.values(), key=lambda p: p.number)

    result.ports = open_ports

    # ---- Stage 3b: searchsploit against the service-scan XML ---------------
    if toggles.get("searchsploit", True):
        if service_xml.exists():
            console.print("\n[bold]▶ Exploit search — searchsploit[/bold]")
            res = tools.searchsploit_nmap(
                service_xml, run_dir / "searchsploit.txt",
                extra=tflags.get("searchsploit", ""))
            _record(res, result.errors)
            print_tool_block(console, "searchsploit", res)
            result.tool_runs.append(ToolRun(
                name="searchsploit", title="searchsploit", result=res,
                kind="searchsploit"))
            if res.ok:
                result.exploits = tools.parse_searchsploit(res.stdout)
        elif open_ports:
            result.errors.append(
                "searchsploit: skipped (needs the nmap service scan — enable it)")

    # ---- Stage 3.5: TLS certificate inspection + SAN discovery -------------
    # For each HTTPS port, pull the cert and decode it. Concrete SAN hostnames
    # are auto-offered as vhost candidates for the web stage *only* when the user
    # didn't specify vhosts themselves (session-only; never persisted to config).
    vhosts = list(vhosts or [])
    if toggles.get("tls_cert", True):
        https_ports = [p for p in open_ports if p.is_https]
        if https_ports:
            console.print("\n[bold]▶ TLS certificate inspection[/bold]")
        discovered_sans: list[str] = []
        for port in https_ports:
            res = tools.tls_cert(
                host, port.number, run_dir / f"tls_cert_{port.number}.txt",
                extra=tflags.get("tls_cert", ""))
            _record(res, result.errors)
            print_tool_block(console, f"tls_cert — :{port.number}", res)
            result.tool_runs.append(ToolRun(
                name="tls_cert", title=f"{host}:{port.number}", result=res,
                kind="tls", port=port.number))
            if not res.ok:
                continue
            parsed = tools.parse_tls_cert(res.grepable)
            result.tls.append({"port": port.number, **parsed})
            for san in parsed.get("sans", []):
                if (san and san != host and san not in vhosts
                        and san not in discovered_sans):
                    discovered_sans.append(san)
        if discovered_sans:
            console.print(
                "  [cyan]TLS SANs discovered:[/cyan] "
                + ", ".join(discovered_sans))
            if vhosts:
                console.print(
                    "  [dim]Virtual hosts already set; not auto-adding SANs. "
                    "Re-run with them if you want to enumerate them.[/dim]")
            else:
                vhosts = discovered_sans
                console.print(
                    "  [green]Auto-adding discovered SANs as virtual hosts "
                    "for this run.[/green]")

    # ---- Stage 4: web tools, per detected web port -------------------------
    web_ports = [p for p in open_ports if p.is_web]
    if web_ports:
        console.print(
            "  Web ports: "
            + ", ".join(f"{p.number}({'https' if p.is_https else 'http'})"
                        for p in web_ports)
        )
        if vhosts:
            console.print("  Virtual hosts (Host header): " + ", ".join(vhosts))
        _run_web_stage(console, host, web_ports, config, toggles, domain,
                       vhosts or [], wordlists, tflags, run_dir, result)
    else:
        console.print("  [dim]No web ports detected; skipping web tools.[/dim]")

    result.findings.sort(
        key=lambda f: (tools.nuclei_severity_rank(f["severity"]), f["name"]))
    dns_map = tools.build_dns_map(host, domain, result.tool_runs)
    print_summary(console, host, run_dir, result.ports, result.gobuster_hits,
                  result.errors, ffuf_hits=result.ffuf_hits,
                  exploits=result.exploits, findings=result.findings,
                  dns_map=dns_map, tls=result.tls)

    # ---- Consolidated reports (formats chosen in config) -------------------
    document = report.build_document(
        host=host, run_dir=run_dir, started=started, finished=datetime.now(),
        config=config, toggles=toggles, domain=domain, vhosts=vhosts or [],
        ports=result.ports, tool_runs=result.tool_runs, warnings=result.errors,
    )
    written = report.write_reports(
        run_dir, document, result.tool_runs, config.get("output_formats", {}))
    if written:
        console.print(f"[dim]Reports: {', '.join(written)}[/dim]")
    return result


def _wordlist_ok(path: str, label: str, errors: list[str]) -> bool:
    if not path or not Path(path).expanduser().exists():
        errors.append(f"{label}: wordlist not found ({path or 'unset'})")
        return False
    return True


def _slug(name: str) -> str:
    """Filesystem-safe slug for a hostname (for per-vhost artifact names)."""
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in name)


def _run_web_stage(
    console: Console,
    host: str,
    web_ports: list[Port],
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None,
    vhosts: list[str],
    wordlists: dict[str, str],
    tflags: dict[str, str],
    run_dir: Path,
    result: HostResult,
) -> None:
    """Run gobuster/whatweb/curl in parallel across all web ports.

    Discovery modes (gobuster vhost/dns) run once against the IP. The
    content tools (gobuster dir / whatweb / curl) run once per Host-header
    *context*: the bare IP when no vhosts are given, otherwise one pass per
    supplied virtual host (Host header injected, IP unchanged).
    """
    # Each job: (display_url, kind, port, vhost, callable).
    jobs: list[tuple[str, str, int | None, str | None, Callable[[], ToolResult]]] = []
    dns_done = False
    # Each context is (host_header_or_None, filename_suffix).
    contexts: list[tuple[str | None, str]] = (
        [(vh, f"_{_slug(vh)}") for vh in vhosts] if vhosts else [(None, "")]
    )
    # Pre-scan catch-all detection for the content-discovery tools (dir / ffuf).
    auto_cal = toggles.get("auto_calibrate", True)

    for p in web_ports:
        scheme = "https" if p.is_https else "http"
        insecure = p.is_https
        ip_url = f"{scheme}://{host}:{p.number}"

        # ---- discovery modes: against the IP, independent of Host header ----
        if toggles.get("gobuster_vhost", False) and domain:
            wl = wordlists.get("vhost", "")
            if _wordlist_ok(wl, "gobuster_vhost", result.errors):
                jobs.append((f"{ip_url} (vhost)", "vhost", p.number, None,
                             lambda url=ip_url, wl=wl, p=p, insecure=insecure:
                             tools.gobuster_vhost(
                                 url, wl, run_dir / f"gobuster_vhost_{p.number}.txt",
                                 extra=tflags.get("gobuster", ""), insecure=insecure)))

        if toggles.get("gobuster_dns", False) and domain and not dns_done:
            wl = wordlists.get("dns", "")
            if _wordlist_ok(wl, "gobuster_dns", result.errors):
                dns_done = True
                jobs.append((f"dns:{domain}", "dns", None, None, lambda wl=wl:
                             tools.gobuster_dns(
                                 domain, wl, run_dir / "gobuster_dns.txt",
                                 extra=tflags.get("gobuster", ""))))

        # ---- content tools: once per Host-header context --------------------
        for host_header, suffix in contexts:
            # Display URL shows the vhost when set; curl pins it to the IP.
            disp = (f"{scheme}://{host_header}:{p.number}"
                    if host_header else ip_url)

            if toggles.get("gobuster_dir", True):
                wl = wordlists.get("dir", "")
                if _wordlist_ok(wl, "gobuster_dir", result.errors):
                    jobs.append((disp, "dir", p.number, host_header,
                                 lambda url=ip_url, wl=wl, p=p, insecure=insecure,
                                 hh=host_header, sfx=suffix: tools.gobuster_dir(
                                     url, wl,
                                     run_dir / f"gobuster_dir_{p.number}{sfx}.txt",
                                     extra=tflags.get("gobuster", ""),
                                     insecure=insecure, host_header=hh,
                                     calibrate=auto_cal)))

            if toggles.get("ffuf", False):
                wl = wordlists.get("ffuf", "")
                if _wordlist_ok(wl, "ffuf", result.errors):
                    jobs.append((disp, "ffuf", p.number, host_header,
                                 lambda url=ip_url, wl=wl, p=p,
                                 hh=host_header, sfx=suffix: tools.ffuf_dir(
                                     url, wl,
                                     run_dir / f"ffuf_{p.number}{sfx}.txt",
                                     extra=tflags.get("ffuf", ""),
                                     host_header=hh, calibrate=auto_cal)))

            if toggles.get("nuclei", False):
                jobs.append((disp, "nuclei", p.number, host_header,
                             lambda url=ip_url, p=p, hh=host_header, sfx=suffix:
                             tools.nuclei(
                                 url, run_dir / f"nuclei_{p.number}{sfx}.txt",
                                 extra=tflags.get("nuclei", ""), host_header=hh)))

            if toggles.get("whatweb", True):
                jobs.append((disp, "whatweb", p.number, host_header,
                             lambda url=ip_url, p=p, hh=host_header, sfx=suffix:
                             tools.whatweb(
                                 url, run_dir / f"whatweb_{p.number}{sfx}.txt",
                                 extra=tflags.get("whatweb", ""), host_header=hh)))

            if toggles.get("curl", True):
                resolve = ((host_header, p.number, host) if host_header else None)
                curl_url = disp if host_header else ip_url
                jobs.append((disp, "curl", p.number, host_header,
                             lambda url=curl_url, p=p, insecure=insecure,
                             res=resolve, sfx=suffix: tools.curl_headers(
                                 url, run_dir / f"curl_{p.number}{sfx}.txt",
                                 insecure=insecure, extra=tflags.get("curl", ""),
                                 resolve=res)))

    if not jobs:
        return

    console.print("\n[bold]▶ Web enumeration — gobuster / whatweb / curl "
                  "(parallel)[/bold]")
    with ThreadPoolExecutor(max_workers=min(8, len(jobs))) as ex:
        futures = {ex.submit(fn): (url, kind, port, vhost)
                   for url, kind, port, vhost, fn in jobs}
        for fut in as_completed(futures):
            url, kind, port, vhost = futures[fut]
            res = fut.result()
            _record(res, result.errors)
            print_tool_block(console, f"{res.name} — {url}", res)
            result.tool_runs.append(ToolRun(
                name=res.name, title=url, result=res, kind=kind,
                port=port, vhost=vhost))
            if kind in ("dir", "vhost", "dns"):
                result.gobuster_hits[url] = tools.parse_gobuster_hits(res.stdout)
            elif kind == "ffuf":
                result.ffuf_hits[url] = tools.parse_ffuf_hits(res.stdout)
            elif kind == "nuclei":
                for f in tools.parse_nuclei(res.grepable):
                    result.findings.append(
                        {**f, "port": port, "vhost": vhost, "url": url})
