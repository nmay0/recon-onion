"""Optional /etc/hosts management for virtual-host enumeration.

Header injection (gobuster -H / curl --resolve / whatweb --header) means we
*never strictly need* an /etc/hosts entry. But some workflows want one anyway
so that a browser or other external tools resolve the name too. These helpers
detect missing mappings and, with explicit consent, add/remove tagged entries
via sudo.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from rich.console import Console

from .prompts import confirm

HOSTS_PATH = Path("/etc/hosts")
# Tag appended to lines we add, so cleanup only ever touches our own entries.
TAG = "# added by reconion"


def resolves_to(name: str, ip: str) -> bool:
    """True if *name* already resolves to *ip* (via DNS or /etc/hosts)."""
    try:
        return ip in {info[4][0] for info in socket.getaddrinfo(name, None)}
    except (socket.gaierror, OSError):
        return False


def _sudo_write(content: str, *, append: bool) -> tuple[bool, str]:
    """Write *content* to /etc/hosts via sudo tee. Returns (ok, message)."""
    cmd = ["sudo", "tee", "-a" if append else "", str(HOSTS_PATH)]
    cmd = [c for c in cmd if c]  # drop the empty flag when not appending
    try:
        proc = subprocess.run(cmd, input=content, text=True, capture_output=True)
    except OSError as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, proc.stderr.strip() or f"sudo tee exit {proc.returncode}"
    return True, ""


def add_entries(
    console: Console, ip: str, names: list[str], *, assume_yes: bool = False
) -> list[str]:
    """Offer to add 'ip name' lines for any *names* not resolving to *ip*.

    Returns the list of names actually added (so the caller can offer cleanup).
    Requires sudo; sudo will prompt on the controlling terminal as needed.
    """
    needed = [n for n in names if n and not resolves_to(n, ip)]
    if not needed:
        return []

    console.print(
        f"[yellow]These names don't resolve to {ip}:[/yellow] "
        + ", ".join(needed)
    )
    if not assume_yes and not confirm(
        f"Add them to {HOSTS_PATH} (needs sudo)?", default=False
    ):
        console.print("[dim]Skipping /etc/hosts; header injection still applies.[/dim]")
        return []

    lines = "".join(f"{ip}\t{name}\t{TAG}\n" for name in needed)
    ok, msg = _sudo_write(lines, append=True)
    if not ok:
        console.print(f"[red]Failed to update /etc/hosts: {msg}[/red]")
        return []
    console.print(f"[green]Added {len(needed)} entry(ies) to {HOSTS_PATH}.[/green]")
    return needed


def remove_entries(console: Console, ip: str, names: list[str]) -> None:
    """Remove the tagged 'ip name' lines we previously added."""
    if not names:
        return
    try:
        current = HOSTS_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Could not read /etc/hosts: {exc}[/red]")
        return

    targets = {f"{ip}\t{name}\t{TAG}" for name in names}
    kept = [
        line for line in current.splitlines()
        if line.rstrip("\n") not in targets
    ]
    new_content = "\n".join(kept) + "\n"
    ok, msg = _sudo_write(new_content, append=False)
    if ok:
        console.print(f"[green]Removed reconion entries from {HOSTS_PATH}.[/green]")
    else:
        console.print(f"[red]Failed to clean /etc/hosts: {msg}[/red]")
