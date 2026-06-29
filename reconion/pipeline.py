"""Per-host pipeline orchestration.

Stage flow for a single host:
  1.  initial recon burst (parallel): the primary fast scanner (rustscan/
      masscan) + DNS. nmap quick+full join the burst only when no fast scanner
      is usable (the plain nmap-only flow).
  1a. nmap full fallback (sequential): runs only when every usable fast scanner
      failed — guarantees full-range discovery.
  3.  service/version/script scan -> on the union of open ports.
  4.  gobuster + whatweb + curl   -> in parallel, per web port.

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
from rich.prompt import Confirm

from . import report, tools
from .output import make_run_dir, print_summary, print_tool_block
from .tools import Port, ToolResult, ToolRun

# Hard ceiling on recursive gobuster scans per host: a safety net independent of
# max_depth / the catch-all guard, so a pathological tree can never run away.
_RECURSION_MAX_SCANS = 50

# Toggle keys, all default-on except the optional gobuster modes and ffuf.
DEFAULT_TOGGLES: dict[str, bool] = {
    # nmap_quick/full are the nmap *discovery* path; they run only when there's
    # no usable fast scanner (then both run as primary in the burst), with
    # nmap_full also the sequential fallback if a fast scanner fails (see
    # run_host). A successful rustscan/masscan covers every port, so both nmap
    # discovery scans are skipped and nmap is used for service detection only.
    "nmap_quick": True,
    "nmap_full": True,
    # rustscan is the default primary full-range discovery (fast, rootless).
    # masscan is opt-in (needs root / config privileged_prefix). Either feeds
    # the same port union, then nmap_service does version/script detection.
    "rustscan": True,
    "masscan": False,
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
    scan_groups: list[list[Port]] = []
    record_types = (config.get("dns", {}).get("record_types") or "").split()
    # Fast scanners are the primary full-range discovery; nmap_full is held back
    # as a fallback (run sequentially below) that only fires when every usable
    # fast scanner fails. With no fast scanner installed+enabled, nmap_full runs
    # as the primary inside the parallel burst (the plain nmap-only flow).
    fast_toggles = ("rustscan", "masscan")
    fast_available = any(
        toggles.get(t, False) and tools.tool_available(t) for t in fast_toggles)
    init_jobs: list[tuple[str, str, str, Callable[[], ToolResult]]] = []
    if toggles.get("nmap_quick", True) and not fast_available:
        init_jobs.append(("nmap_quick", "scan", "nmap_quick", lambda:
            tools.nmap_quick(host, run_dir / "nmap_quick.txt", timing=timing,
                             extra=tflags.get("nmap_quick", ""))))
    if toggles.get("nmap_full", True) and not fast_available:
        init_jobs.append(("nmap_full", "scan", "nmap_full", lambda:
            tools.nmap_full(host, run_dir / "nmap_full.txt", timing=timing,
                            extra=tflags.get("nmap_full", ""))))
    if toggles.get("rustscan", True):
        init_jobs.append(("rustscan", "scan", "rustscan", lambda:
            tools.rustscan(host, run_dir / "rustscan.txt",
                           extra=tflags.get("rustscan", ""))))
    if toggles.get("masscan", False):
        prefix = config.get("privileged_prefix", "")
        init_jobs.append(("masscan", "scan", "masscan", lambda pfx=prefix:
            tools.masscan(host, run_dir / "masscan.txt",
                          extra=tflags.get("masscan", ""), prefix=pfx)))
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
                    # rustscan emits "ip -> [ports]"; nmap/masscan emit nmap
                    # grepable. Both feed the same union of open ports.
                    if name == "rustscan":
                        scan_groups.append(tools.parse_rustscan(res.grepable))
                    else:
                        scan_groups.append(tools.parse_grepable_ports(res.grepable))

    merged = _merge_ports(*scan_groups)

    # ---- Stage 1a: nmap_full fallback --------------------------------------
    # If a usable fast scanner was tried but none succeeded, fall back to nmap
    # -p- so a fast-scanner failure (crash, no root, ...) never costs us
    # full-range discovery. If a fast scanner did succeed, the held-back
    # nmap_full is unnecessary and stays skipped.
    if fast_available and toggles.get("nmap_full", True):
        fast_ok = any(tr.result.ok for tr in result.tool_runs
                      if tr.name in fast_toggles)
        if not fast_ok:
            console.print("\n[bold]▶ Fallback — nmap full port scan (-p-)[/bold]")
            console.print("  [yellow]rustscan/masscan did not succeed; falling "
                          "back to nmap.[/yellow]")
            res = tools.nmap_full(host, run_dir / "nmap_full.txt",
                                  timing=timing, extra=tflags.get("nmap_full", ""))
            _record(res, result.errors)
            print_tool_block(console, "nmap_full", res)
            result.tool_runs.append(ToolRun(
                name="nmap_full", title="nmap_full", result=res, kind="scan"))
            scan_groups.append(tools.parse_grepable_ports(res.grepable))
            merged = _merge_ports(*scan_groups)
        else:
            console.print("  [dim]nmap discovery scans skipped — rustscan/masscan "
                          "covered all ports; nmap runs for service/version "
                          "detection only.[/dim]")

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

    # Recursive gobuster: capture the context each dir/vhost scan needs to be
    # re-run one level deeper, then drill in (sequentially, on the main thread so
    # 'prompt' mode can ask) after the parallel pass below.
    rec_mode, rec_depth = _recursion_settings(config)
    recurse_on = rec_mode != "never" and rec_depth > 0
    dir_ctx: dict[tuple[int, str | None], dict[str, Any]] = {}
    vhost_ctx: dict[int, dict[str, Any]] = {}
    dir_seeds: list[tuple[tuple[int, str | None], str]] = []
    vhost_seeds: list[tuple[int, str]] = []

    for p in web_ports:
        scheme = "https" if p.is_https else "http"
        insecure = p.is_https
        ip_url = f"{scheme}://{host}:{p.number}"

        # ---- discovery modes: against the IP, independent of Host header ----
        if toggles.get("gobuster_vhost", False) and domain:
            wl = wordlists.get("vhost", "")
            if _wordlist_ok(wl, "gobuster_vhost", result.errors):
                jobs.append((f"{ip_url} (vhost)", "vhost", p.number, None,
                             lambda url=ip_url, wl=wl, p=p, insecure=insecure,
                             dom=domain: tools.gobuster_vhost(
                                 url, wl, run_dir / f"gobuster_vhost_{p.number}.txt",
                                 extra=tflags.get("gobuster", ""),
                                 insecure=insecure, domain=dom)))
                if recurse_on:
                    vhost_ctx[p.number] = {
                        "ip_url": ip_url, "insecure": insecure, "wordlist": wl}

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
                    if recurse_on:
                        dir_ctx[(p.number, host_header)] = {
                            "ip_url": ip_url, "insecure": insecure,
                            "suffix": suffix, "wordlist": wl, "disp": disp}

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
                if recurse_on and kind == "dir" and (port, vhost) in dir_ctx:
                    for word in tools.recursable_dirs(res.stdout):
                        dir_seeds.append(((port, vhost), word))
                elif recurse_on and kind == "vhost" and port in vhost_ctx:
                    for vh in tools.found_vhosts(res.stdout):
                        vhost_seeds.append((port, vh))
            elif kind == "ffuf":
                result.ffuf_hits[url] = tools.parse_ffuf_hits(res.stdout)
            elif kind == "nuclei":
                for f in tools.parse_nuclei(res.grepable):
                    result.findings.append(
                        {**f, "port": port, "vhost": vhost, "url": url})

    # ---- recursion: drill into discovered directories / vhosts --------------
    if recurse_on and (dir_seeds or vhost_seeds):
        console.print(
            f"\n[bold]▶ Recursive enumeration[/bold] [dim](mode: {rec_mode}, "
            f"max depth: {rec_depth})[/dim]")
        stats = {"scans": 0}
        if dir_seeds:
            _recurse_dirs(console, rec_mode, rec_depth, dir_seeds, dir_ctx,
                          tflags, run_dir, result, stats, auto_cal)
        if vhost_seeds and domain:
            _recurse_vhosts(console, rec_mode, rec_depth, vhost_seeds, vhost_ctx,
                            tflags, run_dir, result, stats)


# --------------------------------------------------------------------------- #
# Recursive gobuster (dir / vhost)
# --------------------------------------------------------------------------- #
# When a discovery scan finds a directory (or vhost), drill into it and scan
# again, up to max_depth levels. The orchestration here is the *policy* (depth,
# visited-set, caps, the catch-all false-positive guard, and prompt/always
# gating); the tool-specific *mechanism* (run gobuster, record it, find the next
# level) lives in the per-kind `scan` closures below. Runs sequentially on the
# caller's thread — after the parallel web pass — so 'prompt' mode can ask
# without two threads fighting over the console.

# Independent of max_depth and the catch-all guard: a hard ceiling on how many
# *candidates* we even examine (each costs a probe), so a wildcard server that
# reports thousands of bogus hits can't tie us up forever.
_RECURSION_MAX_CANDIDATES = 200


def _recursion_settings(config: dict[str, Any]) -> tuple[str, int]:
    """Return (mode, max_depth) for gobuster recursion from config.

    mode is never|prompt|always (anything else -> never). max_depth is a
    non-negative int, stored as a string in config for the field editor.
    """
    rec = config.get("recursion", {}) or {}
    mode = str(rec.get("mode", "never")).strip().lower()
    if mode not in ("never", "prompt", "always"):
        mode = "never"
    try:
        depth = int(str(rec.get("max_depth", "2")).strip())
    except (TypeError, ValueError):
        depth = 2
    return mode, max(0, depth)


# A recursion work item: (tid, depth, display, payload). `tid` is the identity
# used for the visited-set; `payload` is whatever the kind's callbacks need.
_WorkItem = tuple[Any, int, str, Any]


def _drive_recursion(
    console: Console,
    mode: str,
    max_depth: int,
    *,
    queue: list[_WorkItem],
    fp_check: Callable[[Any], tuple[bool, str]],
    scan: Callable[[Any, int], list[_WorkItem]],
    stats: dict[str, int],
) -> None:
    """Breadth-first driver shared by dir/vhost recursion.

    For each candidate: skip if already visited or past max_depth; enforce the
    scan and candidate caps; run the catch-all false-positive guard (always — so
    a wildcard can never recurse forever, in *any* auto/prompt mode); in 'prompt'
    mode ask the user; otherwise scan it and enqueue the next level.
    """
    visited: set[Any] = set()
    stats.setdefault("seen", 0)
    while queue:
        tid, depth, disp, payload = queue.pop(0)
        if tid in visited or depth > max_depth:
            continue
        visited.add(tid)
        if stats["scans"] >= _RECURSION_MAX_SCANS:
            console.print(f"  [yellow]recursion cap ({_RECURSION_MAX_SCANS} "
                          f"scans) reached; stopping.[/yellow]")
            return
        if stats["seen"] >= _RECURSION_MAX_CANDIDATES:
            console.print(f"  [yellow]recursion cap "
                          f"({_RECURSION_MAX_CANDIDATES} candidates) reached; "
                          f"stopping.[/yellow]")
            return
        stats["seen"] += 1
        is_fp, note = fp_check(payload)
        if is_fp:
            console.print(f"  [dim]skip {disp} — {note}[/dim]")
            continue
        if mode == "prompt" and not Confirm.ask(
                f"  Recurse into [bold]{disp}[/bold]?", default=False):
            continue
        stats["scans"] += 1
        for child in scan(payload, depth):
            ctid, cdepth, _, _ = child
            if ctid not in visited and cdepth <= max_depth:
                queue.append(child)


def _recurse_dirs(
    console: Console,
    mode: str,
    max_depth: int,
    seeds: list[tuple[tuple[int, str | None], str]],
    dir_ctx: dict[tuple[int, str | None], dict[str, Any]],
    tflags: dict[str, str],
    run_dir: Path,
    result: HostResult,
    stats: dict[str, int],
    auto_cal: bool,
) -> None:
    """Recurse gobuster dir into discovered directories.

    A payload is (ctx_key, full_path), where ctx_key=(port, host_header) selects
    the web context and full_path is the directory path relative to that
    context's base URL (gobuster reports hits relative to its -u URL, so each
    level's children get the parent path prepended).
    """
    gflags = tflags.get("gobuster", "")

    def tid(ctx_key, full):
        return ("dir", ctx_key, full)

    def disp_for(ctx_key, full):
        return f"{dir_ctx[ctx_key]['disp'].rstrip('/')}/{full}"

    def fp_check(payload):
        ctx_key, full = payload
        ctx = dir_ctx[ctx_key]
        probe = f"{ctx['ip_url'].rstrip('/')}/{full}"
        cal = tools.calibrate_web(probe, host_header=ctx_key[1])
        if cal.kind != "none":
            return True, f"catch-all ({cal.kind}); not a real directory"
        return False, ""

    def scan(payload, depth):
        ctx_key, full = payload
        port, host_header = ctx_key
        ctx = dir_ctx[ctx_key]
        disp = disp_for(ctx_key, full)
        scan_url = f"{ctx['ip_url'].rstrip('/')}/{full}"
        artifact = run_dir / f"gobuster_dir_{port}{ctx['suffix']}_{_slug(full)}.txt"
        res = tools.gobuster_dir(
            scan_url, ctx["wordlist"], artifact, extra=gflags,
            insecure=ctx["insecure"], host_header=host_header, calibrate=auto_cal)
        _record(res, result.errors)
        print_tool_block(console, f"gobuster_dir — {disp} (depth {depth})", res)
        result.tool_runs.append(ToolRun(
            name="gobuster_dir", title=disp, result=res, kind="dir",
            port=port, vhost=host_header))
        result.gobuster_hits[disp] = tools.parse_gobuster_hits(res.stdout)
        children: list[_WorkItem] = []
        for word in tools.recursable_dirs(res.stdout):
            child = (ctx_key, f"{full}/{word}")
            children.append((tid(*child), depth + 1, disp_for(*child), child))
        return children

    queue: list[_WorkItem] = []
    for ctx_key, word in seeds:
        if ctx_key in dir_ctx:
            payload = (ctx_key, word)
            queue.append((tid(*payload), 1, disp_for(*payload), payload))
    _drive_recursion(console, mode, max_depth, queue=queue, fp_check=fp_check,
                     scan=scan, stats=stats)


def _recurse_vhosts(
    console: Console,
    mode: str,
    max_depth: int,
    seeds: list[tuple[int, str]],
    vhost_ctx: dict[int, dict[str, Any]],
    tflags: dict[str, str],
    run_dir: Path,
    result: HostResult,
    stats: dict[str, int],
) -> None:
    """Recurse gobuster vhost into discovered virtual hosts (nested subdomains).

    A payload is (port, fqdn). To look for <word>.<fqdn> while still hitting the
    target IP, the found vhost is passed as gobuster's --domain (appended to each
    bare wordlist word), so the Host headers <word>.<fqdn> go to the IP.
    """
    gflags = tflags.get("gobuster", "")

    def tid(port, fqdn):
        return ("vhost", port, fqdn)

    def disp_for(port, fqdn):
        return f"{vhost_ctx[port]['ip_url']} (vhost: {fqdn})"

    def fp_check(payload):
        port, fqdn = payload
        ctx = vhost_ctx[port]
        cal = tools.calibrate_vhost(ctx["ip_url"], fqdn, insecure=ctx["insecure"])
        if cal.kind != "none":
            return True, f"catch-all vhost ({cal.kind}); not recursing"
        return False, ""

    def scan(payload, depth):
        port, fqdn = payload
        ctx = vhost_ctx[port]
        disp = disp_for(port, fqdn)
        artifact = run_dir / f"gobuster_vhost_{port}_{_slug(fqdn)}.txt"
        res = tools.gobuster_vhost(
            ctx["ip_url"], ctx["wordlist"], artifact, extra=gflags,
            insecure=ctx["insecure"], domain=fqdn)
        _record(res, result.errors)
        print_tool_block(console, f"gobuster_vhost — {disp} (depth {depth})", res)
        result.tool_runs.append(ToolRun(
            name="gobuster_vhost", title=disp, result=res, kind="vhost",
            port=port, vhost=None))
        result.gobuster_hits[disp] = tools.parse_gobuster_hits(res.stdout)
        children: list[_WorkItem] = []
        for child_fqdn in tools.found_vhosts(res.stdout):
            child = (port, child_fqdn)
            children.append((tid(*child), depth + 1, disp_for(*child), child))
        return children

    queue: list[_WorkItem] = []
    for port, fqdn in seeds:
        if port in vhost_ctx:
            payload = (port, fqdn)
            queue.append((tid(*payload), 1, disp_for(*payload), payload))
    _drive_recursion(console, mode, max_depth, queue=queue, fp_check=fp_check,
                     scan=scan, stats=stats)
