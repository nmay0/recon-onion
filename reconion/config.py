"""Configuration: hardcoded defaults plus a JSON override file.

The custom config stores *only* the keys that differ from the defaults.
Loading deep-merges the overrides on top of the defaults so any missing
key transparently falls back to its default value.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

# Where the custom (override-only) config lives.
CONFIG_PATH = Path("./recon_config.json")

# ANSI escape sequences (CSI form plus the two-character form), e.g. the arrow
# keys, which arrive as literal bytes when the terminal is not editing the line.
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")


def sanitize_text(raw: str) -> str:
    """Return *raw* with terminal line-editing keys applied and control bytes dropped.

    A prompt answer can arrive with raw editing bytes still in it when the
    terminal's ERASE character and the key the keyboard actually sends disagree
    (Backspace sending DEL, 0x7f, against an ERASE of ^H is the common case): the
    line discipline erases nothing and hands the program every byte typed. The
    value looks right on screen and is wrong in the config, and for a *path* it
    is quietly destructive — a leading run of DELs makes an absolute path
    relative, so the run lands in <cwd>/<junk>/<the path you typed> instead.
    Replay the edits the user meant, then drop whatever is still unprintable.
    """
    out: list[str] = []
    for ch in _ANSI_RE.sub("", raw):
        if ch in ("\x7f", "\x08"):      # DEL / Backspace: erase one character
            if out:
                out.pop()
        elif ch == "\x15":              # ^U: kill the line
            out.clear()
        elif ch == "\x17":              # ^W: kill the previous word
            while out and out[-1].isspace():
                out.pop()
            while out and not out[-1].isspace():
                out.pop()
        elif ch.isprintable():
            out.append(ch)
    return "".join(out)


def _sanitize_loaded(value: Any) -> Any:
    """Recursively apply sanitize_text() to every string in a loaded config.

    Keys are left alone: they come from EDITABLE_FIELDS, never from typed text,
    and rewriting them could silently collide two entries into one.
    """
    if isinstance(value, dict):
        return {key: _sanitize_loaded(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_sanitize_loaded(val) for val in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value

# The full default config. Anything not overridden falls back to this.
DEFAULT_CONFIG: dict[str, Any] = {
    # Wordlists used by the three gobuster modes plus ffuf content discovery.
    "wordlists": {
        "dir": "/usr/share/wordlists/dirb/common.txt",
        "dns": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "vhost": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "ffuf": "/usr/share/wordlists/dirb/common.txt",
    },
    # nmap timing template applied to every nmap stage.
    "nmap_timing": "-T4",
    # Optional command prefix for tools needing raw-socket privileges (masscan).
    # Empty = run the tool directly (no auto-sudo; honours the opt-in-sudo rule).
    # Set to "sudo" to run masscan privileged — needs a non-interactive/NOPASSWD
    # sudo or it will hang waiting for a password during the parallel scan burst.
    "privileged_prefix": "",
    # DNS infrastructure fingerprinting (whois + dig), run alongside the port
    # scan. record_types is the space-separated list dig queries for the domain;
    # a reverse PTR for the target IP and an AXFR attempt per discovered NS are
    # always included when the dig stage runs.
    "dns": {
        "record_types": "A AAAA NS SOA MX TXT CNAME",
    },
    # Recursive gobuster dir/vhost: when a scan finds a directory (or vhost),
    # drill into it and scan again, up to max_depth levels deep, to map as much
    # structure as possible. mode is never | prompt | always:
    #   never  - no recursion (the discovery scans run once, as before).
    #   prompt - ask before recursing into each discovered directory/vhost.
    #   always - recurse automatically into every discovered directory/vhost.
    # In prompt AND always, a catch-all probe first confirms the hit is not a
    # false positive (a wildcard server that answers everything), so recursion
    # can never run away forever. max_depth is stored as a string for the config
    # editor and parsed to an int (mirrors dns.record_types).
    "recursion": {
        "mode": "never",
        "max_depth": "2",
    },
    # Web ports assumed when no port-discovery stage is enabled (e.g. the
    # 'fuzz' preset). Space-separated; each is TCP-probed and only the ones
    # that answer are used, so the web stages have somewhere to point without
    # running a scanner. Ignored whenever a discovery scan runs.
    "web_ports": "80 443 8080 8443",
    # Root output directory; runs land under <output_dir>/<host>/<timestamp>/.
    "output_dir": "./recon",
    # Persistent findings database (SQLite). Every run's distilled results are
    # upserted into it so hosts/services/paths/findings accumulate across runs
    # instead of being frozen in one timestamped directory. A blank path means
    # <output_dir>/reconion.db, so the database travels with the engagement
    # folder. workspace separates unrelated engagements (msfconsole's idea);
    # enabled is a string because the config editor edits strings only.
    "database": {
        "enabled": "true",
        "path": "",
        "workspace": "default",
    },
    # Extra flags appended per tool/stage (a single string each, split on spaces).
    "tool_flags": {
        "nmap_sweep": "",
        "nmap_quick": "",
        "nmap_full": "",
        "nmap_service": "",
        # Fast port scanners. masscan's rate is capped low by default so the scan
        # never floods the target (recon-only: never DoS) — tune with care.
        "rustscan": "",
        "masscan": "--rate 1000",
        "whois": "",
        "dig": "",
        "tls_cert": "",
        "gobuster": "",
        "ffuf": "",
        "whatweb": "",
        "curl": "",
        # Passive path discovery (robots.txt / sitemap.xml / security.txt) via
        # curl — reads only files the server publishes; brute-forces nothing.
        "declared": "",
        "searchsploit": "",
        # nuclei runs detection + version-CVE templates only: exclude every tag
        # that *acts* on the target so the tool stays pure recon. Tune the tags
        # here to widen/narrow scope.
        "nuclei": "-exclude-tags fuzz,dos,brute-force,intrusive,default-login",
    },
    # Consolidated reports emitted at the end of each host run (in addition to
    # the always-written per-tool artifacts). Keys must match report.REPORT_FORMATS.
    "output_formats": {
        "summary": True,    # report.txt   — human-readable findings
        "raw": False,       # report.raw.txt — every tool's raw output, one file
        "json": True,       # report.json  — structured, machine-readable
        "xml": False,       # report.xml   — structured (custom schema)
        "markdown": True,   # report.md    — reporting / notes
    },
}


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of *base* with *overrides* recursively merged in."""
    result = copy.deepcopy(base)
    for key, value in overrides.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _diff_overrides(base: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return only the parts of *current* that differ from *base* (recursively)."""
    overrides: dict[str, Any] = {}
    for key, value in current.items():
        if key not in base:
            overrides[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(base[key], dict):
            sub = _diff_overrides(base[key], value)
            if sub:
                overrides[key] = sub
        elif value != base[key]:
            overrides[key] = copy.deepcopy(value)
    return overrides


def load_overrides(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load the override-only JSON file, or an empty dict if none exists.

    Values are sanitized on the way in, so a config already saved with control
    characters in it (see sanitize_text) yields the value the user meant rather
    than the one that got typed. override_notice() reports when that happened.
    """
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return _sanitize_loaded(data) if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def override_error(path: Path = CONFIG_PATH) -> str | None:
    """Return a message if the override file exists but cannot be used.

    load_overrides() deliberately degrades to {} so a bad file never crashes a
    run — but silently reverting every override (output_dir included) is worse
    than useless when the user believes their config is in effect. The CLI calls
    this to say so out loud. Returns None when the file is absent or usable.
    """
    if not path.exists():
        return None
    where = path.resolve()
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        return f"{where} is not valid JSON ({exc}); every override was ignored."
    except OSError as exc:
        return f"{where} could not be read ({exc}); every override was ignored."
    if not isinstance(data, dict):
        return f"{where} must contain a JSON object; every override was ignored."
    return None


def override_notice(path: Path = CONFIG_PATH) -> str | None:
    """Return a message if the saved overrides hold control characters.

    load_overrides() repairs them for the run, but the file keeps the junk until
    it is re-saved — and quietly changing a value the user believes is stored is
    the same trap as quietly ignoring it. Returns None when nothing was altered.
    """
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None  # override_error() already reports an unusable file
    if not isinstance(data, dict) or _sanitize_loaded(data) == data:
        return None
    return (f"{path.resolve()} contains terminal control characters (stray "
            f"Backspace/arrow keys captured while typing a value). They are "
            f"being ignored for this run — re-save the config to clear them.")


def load_config(use_custom: bool, path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Return the effective config.

    If *use_custom* is True, deep-merge the saved overrides onto the defaults;
    otherwise return a clean copy of the defaults.
    """
    if not use_custom:
        return copy.deepcopy(DEFAULT_CONFIG)
    return _deep_merge(DEFAULT_CONFIG, load_overrides(path))


def save_custom_config(current: dict[str, Any], path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Persist *current* as override-only JSON (diff against defaults). Returns the saved overrides."""
    overrides = _diff_overrides(DEFAULT_CONFIG, current)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(overrides, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return overrides


def flag_list(flags: str) -> list[str]:
    """Split a config flag string into argv tokens (empty string -> [])."""
    return flags.split() if flags and flags.strip() else []
