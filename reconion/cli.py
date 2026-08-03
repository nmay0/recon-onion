"""Interactive rich-based CLI: menu, target handling, host selection."""

from __future__ import annotations

import copy
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import hosts, tools
from .config import (
    CONFIG_PATH,
    DEFAULT_CONFIG,
    load_config,
    save_custom_config,
)
from .output import print_tool_block
from .pipeline import DEFAULT_TOGGLES, run_host
from .presets import PRESETS, enabled_stages, profile_name
from .report import REPORT_FORMATS

# Tools checked at startup. Opt-in tools (ffuf, nuclei) and tools that degrade
# gracefully when absent (openssl/tls_cert returns a skipped ToolResult) are
# omitted — their absence is surfaced at run time, not as a startup warning.
REQUIRED_TOOLS = ["nmap", "whois", "dig", "gobuster", "whatweb",
                  "curl", "searchsploit"]


class Session:
    """Per-session, non-persisted state (the 'Modify run' toggles + domain + vhosts)."""

    def __init__(self) -> None:
        self.toggles: dict[str, bool] = copy.deepcopy(DEFAULT_TOGGLES)
        self.target: str | None = None
        self.domain: str | None = None
        self.vhosts: list[str] = []


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #

def parse_target(raw: str) -> tuple[str | None, list[str], str | None]:
    """Classify a target string.

    Returns (single_host, range_hosts, error):
      * single host -> (host, [], None)
      * CIDR/range  -> (None, [host, ...], None) with the network string used
                       for the sweep stored as the last element marker is NOT
                       used; the network itself is returned via range_net below.
    """
    raw = raw.strip()
    try:
        addr = ipaddress.ip_address(raw)
        return str(addr), [], None
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        return None, [], f"Not a valid IP or CIDR: {exc}"
    if net.num_addresses == 1:
        return str(net.network_address), [], None
    return None, [str(net), *[str(h) for h in net.hosts()]], None


# --------------------------------------------------------------------------- #
# Presets (pipeline profiles)
# --------------------------------------------------------------------------- #

def choose_preset(console: Console,
                  current: dict[str, bool]) -> dict[str, bool] | None:
    """Show the presets and return the chosen one's toggles (None = keep current)."""
    table = Table(title="Pipeline presets", title_style="bold cyan",
                  header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Preset")
    table.add_column("What it answers", overflow="fold")
    table.add_column("Stages", overflow="fold", style="dim")
    for i, preset in enumerate(PRESETS, start=1):
        active = " [green](active)[/green]" if preset.toggles() == current else ""
        table.add_row(str(i), preset.label + active, preset.description,
                      preset.stage_summary())
    console.print(table)
    raw = Prompt.ask(
        "Preset # (or [bold]Enter[/bold] to keep the current selection)",
        default="").strip()
    if not raw:
        return None
    if not raw.isdigit() or not (1 <= int(raw) <= len(PRESETS)):
        console.print("[yellow]Invalid selection; keeping current stages.[/yellow]")
        return None
    return PRESETS[int(raw) - 1].toggles()


def preset_flow(console: Console, session: Session) -> None:
    console.print(Panel(
        "A preset picks which pipeline stages run, so you can skip everything "
        "a run doesn't need. Session-only — [bold]never[/bold] saved to config; "
        "fine-tune afterwards in 'Modify run'.", border_style="cyan"))
    chosen = choose_preset(console, session.toggles)
    if chosen is None:
        console.print(f"[dim]Unchanged — {profile_name(session.toggles)}.[/dim]")
        return
    session.toggles = chosen
    console.print(f"[green]Preset applied:[/green] "
                  f"{profile_name(session.toggles)} — "
                  + ", ".join(enabled_stages(session.toggles)))
    session.domain = _maybe_domain(console, session.toggles, session.domain)


# --------------------------------------------------------------------------- #
# Toggle editing (shared by 'Modify run' and per-host CIDR prompts)
# --------------------------------------------------------------------------- #

def _toggle_table(toggles: dict[str, bool]) -> Table:
    table = Table(title=f"Pipeline profile: {profile_name(toggles)}",
                  title_style="bold cyan", show_header=True,
                  header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Tool / stage")
    table.add_column("Enabled")
    for i, (key, val) in enumerate(toggles.items(), start=1):
        table.add_row(str(i), key,
                      "[green]on[/green]" if val else "[red]off[/red]")
    return table


def edit_toggles(console: Console, toggles: dict[str, bool]) -> dict[str, bool]:
    """Interactively flip toggles on a copy and return it."""
    working = copy.deepcopy(toggles)
    keys = list(working.keys())
    while True:
        console.print(_toggle_table(working))
        raw = Prompt.ask(
            "Toggle which # (comma-separated), [bold]p[/bold]=load a preset, "
            "or [bold]Enter[/bold] to accept",
            default="",
        ).strip()
        if not raw:
            return working
        if raw.lower() == "p":
            chosen = choose_preset(console, working)
            if chosen is not None:
                working = chosen
            continue
        for tok in raw.split(","):
            tok = tok.strip()
            if not tok.isdigit() or not (1 <= int(tok) <= len(keys)):
                console.print(f"[yellow]Ignoring invalid selection: {tok}[/yellow]")
                continue
            key = keys[int(tok) - 1]
            working[key] = not working[key]


def edit_output_formats(console: Console,
                        formats: dict[str, bool]) -> dict[str, bool]:
    """Interactively flip which consolidated report formats are emitted."""
    working = copy.deepcopy(formats)
    keys = [key for key, _, _ in REPORT_FORMATS]
    for key in keys:  # fill any missing keys so toggling is well-defined
        working.setdefault(key, False)
    while True:
        table = Table(header_style="bold")
        table.add_column("#", justify="right")
        table.add_column("Format")
        table.add_column("File", style="dim")
        table.add_column("Enabled")
        for i, (key, label, filename) in enumerate(REPORT_FORMATS, start=1):
            table.add_row(str(i), label, filename,
                          "[green]on[/green]" if working.get(key)
                          else "[red]off[/red]")
        console.print(table)
        raw = Prompt.ask(
            "Toggle which # (comma-separated), or [bold]Enter[/bold] to accept",
            default="",
        ).strip()
        if not raw:
            return working
        for tok in raw.split(","):
            tok = tok.strip()
            if not tok.isdigit() or not (1 <= int(tok) <= len(keys)):
                console.print(f"[yellow]Ignoring invalid selection: {tok}[/yellow]")
                continue
            key = keys[int(tok) - 1]
            working[key] = not working.get(key, False)


def _maybe_domain(console: Console, toggles: dict[str, bool],
                  current: str | None) -> str | None:
    """Prompt for a domain when a stage can use one (DNS recon / gobuster modes).

    The dig stage works on the bare IP (reverse PTR) without a domain, but a
    domain unlocks the forward records, domain whois and the AXFR attempt;
    gobuster dns/vhost require one outright.
    """
    if (toggles.get("dig") or toggles.get("gobuster_dns")
            or toggles.get("gobuster_vhost")):
        dflt = current or ""
        val = Prompt.ask(
            "Domain for DNS recon / gobuster dns/vhost (blank to skip)",
            default=dflt,
        ).strip()
        return val or None
    return current


def _prompt_vhosts(console: Console, default: list[str]) -> list[str]:
    """Ask for virtual-host names to enumerate via Host-header injection."""
    raw = Prompt.ask(
        "Virtual host name(s) for Host-header enum (comma-separated, blank = none)",
        default=",".join(default),
    ).strip()
    if not raw:
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _run_target(
    console: Console,
    ip: str,
    config: dict[str, Any],
    toggles: dict[str, bool],
    domain: str | None,
    vhosts: list[str],
) -> None:
    """Optionally seed /etc/hosts, run the pipeline, then offer cleanup.

    Header injection makes /etc/hosts unnecessary for the scan itself; the
    entries are purely a convenience for other tools/browsers, so they're
    opt-in and removed again on request.
    """
    console.print(f"[dim]Pipeline: {profile_name(toggles)} — "
                  + ", ".join(enabled_stages(toggles)) + "[/dim]")
    added: list[str] = []
    if vhosts:
        added = hosts.add_entries(console, ip, vhosts)
    try:
        run_host(console, ip, config, toggles, domain, vhosts)
    finally:
        if added and Confirm.ask(
            f"Remove the {len(added)} /etc/hosts entry(ies) added for {ip}?",
            default=True,
        ):
            hosts.remove_entries(console, ip, added)


# --------------------------------------------------------------------------- #
# Run flow
# --------------------------------------------------------------------------- #

def _ask_config(console: Console, label: str = "Config") -> dict[str, Any]:
    choice = Prompt.ask(f"{label}", choices=["default", "custom"], default="default")
    if choice == "custom" and not CONFIG_PATH.exists():
        console.print("[yellow]No custom config saved yet; using defaults.[/yellow]")
    return load_config(choice == "custom")


def _sweep_live_hosts(console: Console, network: str,
                      config: dict[str, Any]) -> list[str]:
    sweep_dir = Path(config.get("output_dir", "./recon")).expanduser() / "_sweeps"
    sweep_dir.mkdir(parents=True, exist_ok=True)
    artifact = sweep_dir / f"sweep_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    console.print(f"\n[bold]▶ Host discovery sweep — {network}[/bold]")
    res = tools.nmap_sweep(
        network, artifact, timing=config.get("nmap_timing", "-T4"),
        extra=config.get("tool_flags", {}).get("nmap_sweep", ""))
    print_tool_block(console, "nmap_sweep", res)
    if res.skipped or res.error:
        console.print(f"[red]Sweep failed: {res.error or res.returncode}[/red]")
        return []
    return tools.parse_grepable_hosts(res.grepable)


def _select_hosts(console: Console, live: list[str]) -> list[str]:
    table = Table(title="Live hosts", title_style="bold", header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Host", style="green")
    for i, h in enumerate(live, start=1):
        table.add_row(str(i), h)
    console.print(table)
    raw = Prompt.ask(
        "Hosts to [bold red]EXCLUDE[/bold red] (comma-separated #, blank = keep all)",
        default="",
    ).strip()
    if not raw:
        return live
    excluded = set()
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit() and 1 <= int(tok) <= len(live):
            excluded.add(int(tok) - 1)
    return [h for i, h in enumerate(live) if i not in excluded]


def run_flow(console: Console, session: Session) -> None:
    # The prompt defaults to the last target so repeat runs (e.g. after a config
    # tweak) need no retyping; delete it and type a new one to change targets.
    raw = Prompt.ask("Target [bold]IP or CIDR[/bold]",
                     default=session.target or "").strip()
    if not raw:
        return
    single, range_hosts, err = parse_target(raw)
    if err:
        console.print(f"[red]{err}[/red]")
        return

    # Remember the (normalised) target so the next run pre-fills it.
    session.target = single if single is not None else raw

    # ---- single host -------------------------------------------------------
    if single is not None:
        config = _ask_config(console)
        domain = _maybe_domain(console, session.toggles, session.domain)
        vhosts = _prompt_vhosts(console, session.vhosts)
        # Persist what was entered so the DNS/vhost prompts pre-fill next run.
        session.domain, session.vhosts = domain, vhosts
        _run_target(console, single, config, session.toggles, domain, vhosts)
        return

    # ---- CIDR / range: sweep -> review/exclude -> per-host -----------------
    network, hosts = range_hosts[0], range_hosts[1:]
    console.print(Panel(
        f"CIDR target [bold]{network}[/bold] expands to {len(hosts)} addresses.\n"
        "Running a discovery sweep first; you'll review live hosts before any "
        "deep enumeration.", border_style="cyan"))
    # Sweep uses the *default* config's nmap settings (config is chosen per host).
    live = _sweep_live_hosts(console, network, load_config(False))
    if not live:
        console.print("[yellow]No live hosts found.[/yellow]")
        return
    kept = _select_hosts(console, live)
    if not kept:
        console.print("[yellow]All hosts excluded; nothing to do.[/yellow]")
        return

    console.print(f"[bold]Will enumerate {len(kept)} host(s):[/bold] "
                  + ", ".join(kept))
    for host in kept:
        console.rule(f"[bold]Configure {host}[/bold]")
        config = _ask_config(console, label=f"Config for {host}")
        if Confirm.ask(f"Adjust tool toggles for {host}?", default=False):
            toggles = edit_toggles(console, session.toggles)
        else:
            toggles = copy.deepcopy(session.toggles)
        domain = _maybe_domain(console, toggles, session.domain)
        vhosts = _prompt_vhosts(console, session.vhosts)
        _run_target(console, host, config, toggles, domain, vhosts)


# --------------------------------------------------------------------------- #
# Edit config flow
# --------------------------------------------------------------------------- #

def _set_nested(cfg: dict[str, Any], path: list[str], value: str) -> None:
    node = cfg
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def _get_nested(cfg: dict[str, Any], path: list[str]) -> Any:
    node: Any = cfg
    for key in path:
        node = node.get(key, {}) if isinstance(node, dict) else ""
    return node


# Editable fields: label -> path into the config dict.
EDITABLE_FIELDS: list[tuple[str, list[str]]] = [
    ("nmap timing flag", ["nmap_timing"]),
    ("privileged prefix (e.g. sudo, for masscan)", ["privileged_prefix"]),
    ("output directory", ["output_dir"]),
    ("web ports assumed when no port scan runs", ["web_ports"]),
    ("dns record types", ["dns", "record_types"]),
    ("gobuster recursion mode (never/prompt/always)", ["recursion", "mode"]),
    ("gobuster recursion max depth", ["recursion", "max_depth"]),
    ("wordlist: dir", ["wordlists", "dir"]),
    ("wordlist: dns", ["wordlists", "dns"]),
    ("wordlist: vhost", ["wordlists", "vhost"]),
    ("wordlist: ffuf", ["wordlists", "ffuf"]),
    ("extra flags: nmap_sweep", ["tool_flags", "nmap_sweep"]),
    ("extra flags: nmap_quick", ["tool_flags", "nmap_quick"]),
    ("extra flags: nmap_full", ["tool_flags", "nmap_full"]),
    ("extra flags: nmap_service", ["tool_flags", "nmap_service"]),
    ("extra flags: rustscan", ["tool_flags", "rustscan"]),
    ("extra flags: masscan", ["tool_flags", "masscan"]),
    ("extra flags: whois", ["tool_flags", "whois"]),
    ("extra flags: dig", ["tool_flags", "dig"]),
    ("extra flags: tls_cert", ["tool_flags", "tls_cert"]),
    ("extra flags: gobuster", ["tool_flags", "gobuster"]),
    ("extra flags: ffuf", ["tool_flags", "ffuf"]),
    ("extra flags: whatweb", ["tool_flags", "whatweb"]),
    ("extra flags: curl", ["tool_flags", "curl"]),
    ("extra flags: declared", ["tool_flags", "declared"]),
    ("extra flags: searchsploit", ["tool_flags", "searchsploit"]),
    ("extra flags: nuclei", ["tool_flags", "nuclei"]),
]


def edit_config_flow(console: Console) -> None:
    # Start from the current effective custom config (defaults + saved overrides).
    cfg = load_config(True)
    console.print(Panel(
        f"Editing custom config. Only values that differ from the defaults are "
        f"saved to [bold]{CONFIG_PATH}[/bold].", border_style="cyan"))
    while True:
        table = Table(header_style="bold")
        table.add_column("#", justify="right")
        table.add_column("Field")
        table.add_column("Current value", overflow="fold")
        table.add_column("Default", overflow="fold", style="dim")
        for i, (label, path) in enumerate(EDITABLE_FIELDS, start=1):
            cur = str(_get_nested(cfg, path))
            dflt = str(_get_nested(DEFAULT_CONFIG, path))
            table.add_row(str(i), label, cur or "[dim](empty)[/dim]",
                          dflt or "(empty)")
        console.print(table)

        fmts = cfg.get("output_formats", {})
        enabled = [label for key, label, _ in REPORT_FORMATS if fmts.get(key)]
        console.print(
            "[bold]Output formats[/bold] ([cyan]o[/cyan] to edit): "
            + (", ".join(enabled) if enabled else "[yellow]none[/yellow]"))

        raw = Prompt.ask(
            "Edit which # ([bold]o[/bold]=formats, [bold]s[/bold]=save, "
            "[bold]q[/bold]=cancel)",
            default="s").strip().lower()
        if raw in ("q", "quit"):
            console.print("[yellow]Cancelled; no changes saved.[/yellow]")
            return
        if raw == "o":
            cfg["output_formats"] = edit_output_formats(
                console, cfg.get("output_formats", {}))
            continue
        if raw in ("s", "save", ""):
            overrides = save_custom_config(cfg)
            if overrides:
                console.print(f"[green]Saved {len(overrides)} override group(s) "
                              f"to {CONFIG_PATH}.[/green]")
            else:
                console.print("[green]No overrides (matches defaults); "
                              "saved empty config.[/green]")
            return
        if not raw.isdigit() or not (1 <= int(raw) <= len(EDITABLE_FIELDS)):
            console.print("[yellow]Invalid selection.[/yellow]")
            continue
        label, path = EDITABLE_FIELDS[int(raw) - 1]
        current = str(_get_nested(cfg, path))
        new = Prompt.ask(f"New value for [bold]{label}[/bold]", default=current)
        _set_nested(cfg, path, new)


# --------------------------------------------------------------------------- #
# Modify run flow
# --------------------------------------------------------------------------- #

def modify_run_flow(console: Console, session: Session) -> None:
    console.print(Panel(
        "Session-only tool toggles. These are [bold]never[/bold] saved to config.",
        border_style="cyan"))
    session.toggles = edit_toggles(console, session.toggles)
    session.domain = _maybe_domain(console, session.toggles, session.domain)
    session.vhosts = _prompt_vhosts(console, session.vhosts)


# --------------------------------------------------------------------------- #
# Main menu
# --------------------------------------------------------------------------- #

def _preflight(console: Console) -> None:
    missing = [t for t in REQUIRED_TOOLS if not tools.tool_available(t)]
    if missing:
        console.print(Panel(
            "Missing tools (related stages will be skipped): "
            + "[bold red]" + ", ".join(missing) + "[/bold red]\n"
            "Install e.g. `brew install " + " ".join(missing) + "`.",
            title="Preflight", border_style="yellow", title_align="left"))


def main() -> None:
    console = Console()
    session = Session()
    console.print(Panel.fit(
        "[bold]recon onion[/bold] — pentesting recon automation\n"
        "[dim]Authorized testing only.[/dim]", border_style="green"))
    _preflight(console)

    actions = {
        "1": "Run",
        "2": "Preset (pick which stages run)",
        "3": "Edit config",
        "4": "Modify run (session toggles)",
        "5": "Quit",
    }
    while True:
        console.print()
        table = Table(show_header=False, box=None)
        for key, label in actions.items():
            marker = (f" [dim](current: {profile_name(session.toggles)})[/dim]"
                      if key == "2" else "")
            table.add_row(f"[bold cyan]{key}[/bold cyan]", label + marker)
        console.print(table)
        choice = Prompt.ask("Select", choices=list(actions), default="1")
        if choice == "1":
            run_flow(console, session)
        elif choice == "2":
            preset_flow(console, session)
        elif choice == "3":
            edit_config_flow(console)
        elif choice == "4":
            modify_run_flow(console, session)
        elif choice == "5":
            console.print("Bye.")
            return
