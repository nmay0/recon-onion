"""Configuration: hardcoded defaults plus a JSON override file.

The custom config stores *only* the keys that differ from the defaults.
Loading deep-merges the overrides on top of the defaults so any missing
key transparently falls back to its default value.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

# Where the custom (override-only) config lives.
CONFIG_PATH = Path("./recon_config.json")

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
    """Load the override-only JSON file, or an empty dict if none exists."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
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
