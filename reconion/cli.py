"""Interactive rich-based CLI: menu, target handling, host selection."""

from __future__ import annotations

import copy
import ipaddress
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import db, hosts, tools
from .config import (
    CONFIG_PATH,
    DEFAULT_CONFIG,
    load_config,
    override_error,
    override_notice,
    save_custom_config,
)
from .output import print_tool_block
from .pipeline import DEFAULT_TOGGLES, run_host
from .presets import PRESETS, enabled_stages, profile_name
from .prompts import ask as _ask, confirm as _confirm
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
        # Database browsing state: which file/workspace is being looked at and
        # whether the views are scoped to one host. Resolved from the config on
        # first use (see _db_context), then remembered for the session.
        self.db_file: Path | None = None
        self.db_workspace: str = db.DEFAULT_WORKSPACE
        self.db_host: str | None = None


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
    raw = _ask(
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

# Short caveats for stages whose default state needs explaining — shown dim in
# the toggle table so the user knows what turning one on actually means.
_TOGGLE_NOTES = {
    "rustscan": "aggressive: much faster packet rate than nmap; replaces the "
                "nmap discovery scans",
    "masscan": "aggressive: needs root (privileged_prefix), rate-capped in "
               "config; replaces the nmap discovery scans",
}


def _toggle_table(toggles: dict[str, bool]) -> Table:
    table = Table(title=f"Pipeline profile: {profile_name(toggles)}",
                  title_style="bold cyan", show_header=True,
                  header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Tool / stage")
    table.add_column("Enabled")
    table.add_column("Notes", style="dim", overflow="fold")
    for i, (key, val) in enumerate(toggles.items(), start=1):
        table.add_row(str(i), key,
                      "[green]on[/green]" if val else "[red]off[/red]",
                      _TOGGLE_NOTES.get(key, ""))
    return table


def edit_toggles(console: Console, toggles: dict[str, bool]) -> dict[str, bool]:
    """Interactively flip toggles on a copy and return it."""
    working = copy.deepcopy(toggles)
    keys = list(working.keys())
    while True:
        console.print(_toggle_table(working))
        raw = _ask(
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
        raw = _ask(
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
        val = _ask(
            "Domain for DNS recon / gobuster dns/vhost (blank to skip)",
            default=dflt,
        ).strip()
        return val or None
    return current


def _prompt_vhosts(console: Console, default: list[str]) -> list[str]:
    """Ask for virtual-host names to enumerate via Host-header injection."""
    raw = _ask(
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
        if added and _confirm(
            f"Remove the {len(added)} /etc/hosts entry(ies) added for {ip}?",
            default=True,
        ):
            hosts.remove_entries(console, ip, added)


# --------------------------------------------------------------------------- #
# Run flow
# --------------------------------------------------------------------------- #

def _ask_config(console: Console, label: str = "Config") -> dict[str, Any]:
    choice = _ask(f"{label}", choices=["default", "custom"], default="default")
    # CONFIG_PATH is relative, so it is only found when the working directory is
    # the one the config was saved from. Every way of ending up on the defaults
    # used to be silent, which made a customised output_dir look like it had
    # been ignored at random — say which config is actually in force instead.
    if choice == "custom":
        if not CONFIG_PATH.exists():
            console.print(
                f"[yellow]No custom config at {CONFIG_PATH.resolve()} — "
                f"using defaults.[/yellow]")
        else:
            problem = override_error()
            if problem:
                console.print(f"[red]! {problem}[/red]")
            notice = override_notice()
            if notice:
                console.print(f"[yellow]! {notice}[/yellow]")
    elif CONFIG_PATH.exists():
        console.print(
            f"[yellow]Note: a custom config exists at {CONFIG_PATH.resolve()} "
            f"but 'default' was chosen — its overrides are not in effect.[/yellow]")

    config = load_config(choice == "custom")
    out = Path(config.get("output_dir", "./recon")).expanduser().resolve()
    console.print(f"[dim]Output directory: {out}[/dim]")
    return config


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
    raw = _ask(
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
    raw = _ask("Target [bold]IP or CIDR[/bold]",
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
        if _confirm(f"Adjust tool toggles for {host}?", default=False):
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
    ("database enabled (true/false)", ["database", "enabled"]),
    ("database file (blank = <output dir>/reconion.db)", ["database", "path"]),
    ("database workspace", ["database", "workspace"]),
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

        raw = _ask(
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
        new = _ask(f"New value for [bold]{label}[/bold]", default=current)
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
# Database flow
# --------------------------------------------------------------------------- #

def _db_context(session: Session) -> tuple[Path, str]:
    """Resolve which database file and workspace the browser is looking at.

    Derived from the effective custom config (defaults when nothing is saved),
    which is where a run would have written it. The resolved path is always
    printed rather than assumed: a config saved under a different working
    directory, or a run made with 'default' against a customised output_dir,
    puts the database somewhere the user did not expect — and an empty table is
    an ambiguous way to find that out. 'f' in the menu repoints it.
    """
    if session.db_file is None:
        _, db_file, workspace = db.database_settings(load_config(True))
        session.db_file, session.db_workspace = db_file, workspace
    return session.db_file, session.db_workspace


def _cell(value: Any) -> str:
    """Render a database value as a table cell rich will not read as markup.

    Every cell here is scan output, and square brackets are everywhere in it:
    whatweb reports ``HTTPServer[nginx/1.18.0], Title[Index of /]``. Unescaped,
    rich drops each bracket group as an unknown style tag — the version data,
    which is the whole point of the note — and a redirect such as
    ``RedirectLocation[/login]`` reads as a closing tag with nothing open,
    raising MarkupError out of the browser and off the top of the CLI.
    """
    return "" if value is None else escape(str(value))


def _db_table(title: str, columns: list[tuple[str, str]],
              rows: list[dict[str, Any]]) -> Table:
    """Build a rich table from (header, key) pairs and a list of row dicts."""
    table = Table(title=title, title_style="bold cyan", header_style="bold")
    for header, _ in columns:
        table.add_column(header, overflow="fold")
    for row in rows:
        table.add_row(*[_cell(row.get(key)) for _, key in columns])
    return table


def _db_show(console: Console, title: str, columns: list[tuple[str, str]],
             rows: list[dict[str, Any]]) -> None:
    if not rows:
        console.print(f"[yellow]No {title.lower()} recorded yet.[/yellow]")
        return
    console.print(_db_table(f"{title} ({len(rows)})", columns, rows))


def _db_search(what: str) -> str | None:
    raw = _ask(f"Search {what} (blank = all)", default="").strip()
    return raw or None


def _db_hosts_view(console: Console, session: Session,
                   db_file: Path, workspace: str) -> None:
    """List hosts and let one be picked as the scope for every other view."""
    rows = db.list_hosts(db_file, workspace)
    if not rows:
        console.print("[yellow]No hosts recorded yet — run a scan first.[/yellow]")
        return
    table = Table(title=f"Hosts ({len(rows)})", title_style="bold cyan",
                  header_style="bold")
    table.add_column("#", justify="right")
    for header in ("Address", "Domain", "Services", "Paths", "Vulns",
                   "First seen", "Last seen"):
        table.add_column(header, overflow="fold")
    for i, row in enumerate(rows, start=1):
        table.add_row(str(i), _cell(row["address"]), _cell(row["domain"]),
                      _cell(row["services"]), _cell(row["paths"]),
                      _cell(row["vulns"]), _cell(row["first_seen"]),
                      _cell(row["last_seen"]))
    console.print(table)
    raw = _ask("Scope every view to host # ([bold]0[/bold] = all hosts, "
               "[bold]Enter[/bold] = leave as is)", default="").strip()
    if not raw:
        return
    if raw == "0":
        session.db_host = None
        console.print("[green]Scope cleared — showing all hosts.[/green]")
        return
    if raw.isdigit() and 1 <= int(raw) <= len(rows):
        session.db_host = rows[int(raw) - 1]["address"]
        console.print(f"[green]Scoped to {session.db_host}.[/green]")
    else:
        console.print("[yellow]Invalid selection; scope unchanged.[/yellow]")


def _db_workspaces_view(console: Console, session: Session,
                        db_file: Path) -> None:
    rows = db.list_workspaces(db_file)
    table = Table(title="Workspaces", title_style="bold cyan",
                  header_style="bold")
    table.add_column("#", justify="right")
    for header in ("Name", "Hosts", "Runs", "Created"):
        table.add_column(header, overflow="fold")
    for i, row in enumerate(rows, start=1):
        active = (" [green](current)[/green]"
                  if row["name"] == session.db_workspace else "")
        table.add_row(str(i), _cell(row["name"]) + active, _cell(row["hosts"]),
                      _cell(row["runs"]), _cell(row["created_at"]))
    console.print(table)
    console.print("[dim]Switching here affects browsing only. Runs write to "
                  "the workspace in the config (Edit config).[/dim]")
    raw = _ask("Switch to workspace # , [bold]n[/bold]=new, "
               "[bold]Enter[/bold]=back", default="").strip().lower()
    if not raw:
        return
    if raw == "n":
        name = _ask("New workspace name", default="").strip()
        if not name:
            return
        db.create_workspace(db_file, name)
        session.db_workspace, session.db_host = name, None
        console.print(f"[green]Created and switched to '{name}'.[/green]")
        return
    if raw.isdigit() and 1 <= int(raw) <= len(rows):
        session.db_workspace = rows[int(raw) - 1]["name"]
        session.db_host = None
        console.print(f"[green]Now browsing '{session.db_workspace}'.[/green]")
    else:
        console.print("[yellow]Invalid selection.[/yellow]")


def _db_delete_view(console: Console, session: Session, db_file: Path,
                    workspace: str) -> None:
    """Delete a host (with everything hanging off it) or a whole workspace."""
    what = _ask("Delete [bold]h[/bold]=a host, [bold]w[/bold]=a workspace, "
                "[bold]Enter[/bold]=cancel",
                default="").strip().lower()
    if what == "h":
        rows = db.list_hosts(db_file, workspace)
        if not rows:
            console.print("[yellow]Nothing to delete.[/yellow]")
            return
        _db_show(console, "Hosts",
                 [("Address", "address"), ("Services", "services"),
                  ("Paths", "paths"), ("Vulns", "vulns")], rows)
        address = _ask("Address to delete (blank = cancel)", default="").strip()
        if not address:
            return
        if address not in [r["address"] for r in rows]:
            console.print("[yellow]No such host in this workspace.[/yellow]")
            return
        if not _confirm(f"Delete {address} and all its services, paths, "
                        f"findings and notes?", default=False):
            return
        db.delete_host(db_file, workspace, address)
        if session.db_host == address:
            session.db_host = None
        console.print(f"[green]Deleted {address}.[/green]")
    elif what == "w":
        name = _ask("Workspace to delete (blank = cancel)", default="").strip()
        if not name:
            return
        stats = db.workspace_stats(db_file, name)
        if not _confirm(f"Delete workspace '{name}' with its "
                        f"{stats['hosts']} host(s) and {stats['runs']} run(s)?",
                        default=False):
            return
        db.delete_workspace(db_file, name)
        if session.db_workspace == name:
            session.db_workspace, session.db_host = db.DEFAULT_WORKSPACE, None
        console.print(f"[green]Deleted workspace '{name}'.[/green]")


_DB_ACTIONS = {
    "1": "Hosts (and pick the host to scope to)",
    "2": "Services",
    "3": "Web paths",
    "4": "Findings & exploit leads",
    "5": "Virtual hosts & DNS records",
    "6": "Notes (fingerprints, headers, certs, whois)",
    "7": "Runs",
    "8": "Workspaces",
    "9": "Delete a host or workspace",
    "f": "Point at a different database file",
    "q": "Back to the main menu",
}


def db_flow(console: Console, session: Session) -> None:
    db_file, _ = _db_context(session)
    if not db.exists(db_file):
        console.print(Panel(
            f"No database at [bold]{db_file}[/bold] yet.\n"
            "It is created by the first run with the database enabled "
            "(Edit config → database). Use [cyan]f[/cyan] below if it lives "
            "somewhere else.", border_style="yellow"))
    while True:
        db_file, workspace = session.db_file, session.db_workspace
        scope = (f"host [bold]{session.db_host}[/bold]" if session.db_host
                 else "all hosts")
        console.print(Panel(
            f"[bold]{db_file}[/bold]\nworkspace [bold]{workspace}[/bold] — "
            f"showing {scope}", title="Database", title_align="left",
            border_style="cyan"))
        table = Table(show_header=False, box=None)
        for key, label in _DB_ACTIONS.items():
            table.add_row(f"[bold cyan]{key}[/bold cyan]", label)
        console.print(table)
        choice = _ask("Select", choices=list(_DB_ACTIONS), default="1")
        if choice == "q":
            return
        if choice == "f":
            raw = _ask("Database file", default=str(db_file)).strip()
            if raw:
                session.db_file = Path(raw).expanduser().resolve()
                session.db_host = None
            continue
        # Every view reads the file, so a missing/unreadable database is
        # reported once here instead of in each branch.
        try:
            _db_dispatch(console, session, choice, db_file, workspace)
        except db.DatabaseError as exc:
            console.print(f"[yellow]{exc}[/yellow]")
        except sqlite3.Error as exc:
            console.print(f"[red]Database error: {exc}[/red]")


def _db_dispatch(console: Console, session: Session, choice: str,
                 db_file: Path, workspace: str) -> None:
    host = session.db_host
    if choice == "1":
        _db_hosts_view(console, session, db_file, workspace)
    elif choice == "2":
        _db_show(console, "Services",
                 [("Host", "host"), ("Port", "port"), ("Proto", "proto"),
                  ("State", "state"), ("Service", "name"),
                  ("Version", "version"), ("Last seen", "last_seen")],
                 db.list_services(db_file, workspace, host,
                                  _db_search("service, version or port")))
    elif choice == "3":
        _db_show(console, "Web paths",
                 [("Host", "host"), ("Port", "port"), ("Vhost", "vhost"),
                  ("Path", "path"), ("Status", "status"), ("Size", "length"),
                  ("Redirect", "redirect"), ("Source", "source")],
                 db.list_web_paths(db_file, workspace, host, _db_search("path")))
    elif choice == "4":
        _db_show(console, "Findings & exploit leads",
                 [("Host", "host"), ("Port", "port"), ("Severity", "severity"),
                  ("Name", "name"), ("Source", "source"), ("URL", "url")],
                 db.list_vulns(db_file, workspace, host,
                               _db_search("finding name or template")))
    elif choice == "5":
        _db_show(console, "Virtual hosts",
                 [("Host", "host"), ("Name", "name"), ("Source", "source"),
                  ("First seen", "first_seen")],
                 db.list_vhosts(db_file, workspace, host))
        _db_show(console, "DNS records",
                 [("Host", "host"), ("Name", "name"), ("Type", "rtype"),
                  ("Value", "value")],
                 db.list_dns_records(db_file, workspace, host))
    elif choice == "6":
        rows = db.list_notes(db_file, workspace, host)
        for row in rows:  # the payload is JSON; show a readable slice of it
            row["preview"] = _json_preview(row.get("data", ""))
        _db_show(console, "Notes",
                 [("Host", "host"), ("Port", "port"), ("Vhost", "vhost"),
                  ("Type", "ntype"), ("Content", "preview"),
                  ("Last seen", "last_seen")], rows)
    elif choice == "7":
        _db_show(console, "Runs",
                 [("#", "id"), ("Target", "target"), ("Started", "started"),
                  ("Seconds", "duration_seconds"), ("Stages", "stages"),
                  ("Artifacts", "run_dir")],
                 db.list_runs(db_file, workspace, host))
    elif choice == "8":
        _db_workspaces_view(console, session, db_file)
    elif choice == "9":
        _db_delete_view(console, session, db_file, workspace)


_NOTE_PREVIEW_CHARS = 300


def _json_preview(data: str) -> str:
    """Flatten a note's JSON payload into one readable, truncated line."""
    try:
        parsed = json.loads(data)
    except (json.JSONDecodeError, ValueError):
        return data[:_NOTE_PREVIEW_CHARS]
    def flat(value: Any) -> str:
        if isinstance(value, list):
            return ", ".join(flat(v) for v in value)
        if isinstance(value, dict):
            return "; ".join(f"{k}={flat(v)}" for k, v in value.items() if v)
        return str(value)

    text = flat(parsed)
    return (text[:_NOTE_PREVIEW_CHARS] + "…"
            if len(text) > _NOTE_PREVIEW_CHARS else text)


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
        "5": "Database (findings kept across runs)",
        "6": "Quit",
    }
    while True:
        console.print()
        table = Table(show_header=False, box=None)
        for key, label in actions.items():
            marker = (f" [dim](current: {profile_name(session.toggles)})[/dim]"
                      if key == "2" else "")
            table.add_row(f"[bold cyan]{key}[/bold cyan]", label + marker)
        console.print(table)
        choice = _ask("Select", choices=list(actions), default="1")
        if choice == "1":
            run_flow(console, session)
        elif choice == "2":
            preset_flow(console, session)
        elif choice == "3":
            edit_config_flow(console)
        elif choice == "4":
            modify_run_flow(console, session)
        elif choice == "5":
            db_flow(console, session)
        elif choice == "6":
            console.print("Bye.")
            return
