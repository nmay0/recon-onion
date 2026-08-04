"""Pipeline presets: named stage selections, so a run can skip what it doesn't need.

Each preset answers one question about a target ("what is this host?", "what
does DNS say?", "what content is exposed?") and enables only the stages that
answer it. A preset is a **whitelist**: every toggle it doesn't name is off, so
a stage added later can never quietly join a narrow preset — it only joins
`full`, which is `DEFAULT_TOGGLES` verbatim (the default, unchanged behaviour).

Presets only *seed* the session toggles; 'Modify run' fine-tunes them
afterwards, at which point the CLI reports the profile as 'custom'. Like the
toggles they set, a preset is session-only and never saved to config.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass

from .pipeline import DEFAULT_TOGGLES


@dataclass(frozen=True)
class Preset:
    key: str
    label: str
    description: str
    # Toggles switched on; every other toggle is off. None = the full default
    # set (whatever DEFAULT_TOGGLES says, including future additions).
    enable: tuple[str, ...] | None = None

    def toggles(self) -> dict[str, bool]:
        """Return the full toggle dict this preset selects."""
        if self.enable is None:
            return copy.deepcopy(DEFAULT_TOGGLES)
        return {key: key in self.enable for key in DEFAULT_TOGGLES}

    def stage_summary(self) -> str:
        if self.enable is None:
            return "all default-on stages"
        return ", ".join(self.enable)


PRESETS: tuple[Preset, ...] = (
    Preset(
        "full", "Full pipeline",
        "Everything: port discovery, DNS, service scan, TLS, exploit search "
        "and web enumeration.",
        None,
    ),
    Preset(
        "recon", "Initial recon",
        "What is this host? Port discovery, service/version detection, TLS "
        "certs, HTTP fingerprint and the offline exploit search. No brute "
        "forcing of any kind.",
        ("nmap_quick", "nmap_full", "nmap_service", "tls_cert",
         "searchsploit", "whatweb", "curl"),
    ),
    Preset(
        "dns", "DNS recon",
        "What does DNS say? whois, dig records + reverse PTR, AXFR zone "
        "transfers and subdomain brute force. No port scan, no web tools. "
        "Give it a domain — an IP alone only yields whois + PTR.",
        ("whois", "dig", "gobuster_dns"),
    ),
    Preset(
        "fuzz", "Content discovery",
        "What content is exposed? Directory brute force only, with catch-all "
        "calibration. Skips port discovery, so it probes the configured "
        "web_ports to find where to point.",
        ("gobuster_dir", "auto_calibrate"),
    ),
)

# Fail loudly at import on a typo'd toggle name rather than silently dropping it.
for _preset in PRESETS:
    _unknown = sorted(set(_preset.enable or ()) - set(DEFAULT_TOGGLES))
    if _unknown:
        raise ValueError(
            f"preset {_preset.key!r} names unknown toggle(s): {', '.join(_unknown)}")


def find_preset(key: str) -> Preset | None:
    for preset in PRESETS:
        if preset.key == key:
            return preset
    return None


def match_preset(toggles: dict[str, bool]) -> Preset | None:
    """Return the preset *toggles* exactly matches, or None if it's hand-tuned."""
    for preset in PRESETS:
        if preset.toggles() == dict(toggles):
            return preset
    return None


def profile_name(toggles: dict[str, bool]) -> str:
    """Human label for the current stage selection ('custom' when hand-tuned)."""
    preset = match_preset(toggles)
    return preset.label if preset else "custom"


def enabled_stages(toggles: dict[str, bool]) -> list[str]:
    return [key for key, on in toggles.items() if on]
