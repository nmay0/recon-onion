# recon onion

A Python recon-automation tool that orchestrates `nmap`, `rustscan`/`masscan`,
`whois`, `dig`, `gobuster`, `ffuf`, `whatweb`, `curl`, `nuclei`, and
`searchsploit` into a staged, partly-parallel pipeline with a small `rich`-based
CLI.

> **Authorized testing only.** Use exclusively against systems you own or have
> explicit written permission to assess.

## Pipeline

For each target host, in stages (some parallel, some dependent):

1. **Port discovery + DNS (parallel burst).**
   - *Ports:* `nmap -F` + `nmap -p-` are the default discovery — gentle,
     well-behaved traffic. The fast scanners `rustscan` (rootless) and `masscan`
     (needs root — see `privileged_prefix`) are **opt-in**: they sweep all 65535
     ports far quicker but at a much more aggressive packet rate, so you enable
     them deliberately. Enabling one makes it the primary discovery and the nmap
     discovery scans stand down; if it was tried but failed, `nmap -p-` runs as a
     fallback so full-range discovery is never lost. Open ports from whatever ran
     feed one union.
   - *DNS infrastructure:* `whois` (target IP, plus the domain if you give one)
     and `dig` (forward records + reverse PTR) run alongside the port scan; a
     `dig AXFR` zone-transfer attempt then follows against each discovered
     nameserver.
2. **Service scan** — `nmap -sV -sC` runs against the union of open ports (also
   emitting an XML copy for the next step).
3. **Exploit search** — `searchsploit --nmap` reads the service-scan XML and
   searches Exploit-DB for each detected product/version.
4. **TLS certificates** — for each HTTPS port, the certificate is pulled and
   decoded (CN, SANs, issuer, expiry). Concrete SAN hostnames are auto-offered as
   virtual-host candidates for the web stage (only when you didn't specify vhosts
   yourself).
5. **Web enumeration** — for every detected web port, `gobuster dir` + `whatweb` +
   `curl -I` (and `ffuf` / `nuclei`, if enabled) run *in parallel*, once per
   Host-header context. `gobuster dns` (subdomain brute force) shares the pool
   but is port-independent — it runs off the domain alone. Discovered
   directories/virtual hosts are then recursed
   into (see [Recursive enumeration](#recursive-enumeration)).
   - HTTPS-aware: `https://` scheme for gobuster/whatweb and `-k` for curl on
     443/8443 (or any `ssl`/`https` service), so self-signed certs don't break.
   - Auto-calibration: before each `gobuster dir`/`ffuf` run, a quick probe
     detects catch-all ("wildcard") servers and injects the matching filter so
     the results aren't drowned in identical noise.

Default-on stages: the nmap port + service scans, whois, dig, TLS, searchsploit,
`gobuster dir`, whatweb, curl, declared files. Opt-in (enable via *Modify run* or
the per-host CIDR prompt): rustscan, masscan, ffuf, nuclei, `gobuster dns`/`vhost`.
Recursion is off by
default too, switched on in *Edit config* (see [Recursive enumeration](#recursive-enumeration)).
`searchsploit` only runs when the service scan produced results; `nuclei` is
scoped to detection/version-CVE templates (it never acts on the target).

Not every run needs every stage — **presets** (menu option 2) select a subset,
e.g. DNS recon or directory fuzzing alone. See [Presets](#presets).

CIDR ranges run an `nmap -sn` discovery sweep first, then **pause** so you can
review the live hosts and exclude any before enumeration. Each kept host is then
configured (config + tool toggles) and run **one at a time**.

## Install

`./reconion.sh` sets up the virtualenv and launches in one step (see
[Run](#run)). To manage the venv by hand instead:

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

Built for Linux (Debian/Kali, where these tools and the default
`/usr/share/wordlists` paths live). External tools install separately; any
missing one is skipped with a warning:

```bash
sudo apt install nmap gobuster ffuf whatweb exploitdb curl seclists \
                 whois dnsutils masscan
```

(`exploitdb` provides `searchsploit`; `seclists` provides the dns/vhost
wordlists; `dnsutils` provides `dig`. On Kali most of these ship preinstalled.
`rustscan` and `nuclei` aren't in apt — install them from their own releases.
All of `rustscan`/`masscan`/`nuclei`/`ffuf` are opt-in and simply skipped unless
enabled; port discovery uses `nmap` by default either way.)

## Run

```bash
./reconion.sh
```

`reconion.sh` (re)creates `.venv`, installs `requirements.txt`, then launches
recon onion. Run it from the repo root; it's safe to re-run (the venv and deps
are reused). If the virtualenv is already set up, you can launch directly
instead:

```bash
./.venv/bin/python -m reconion
```

Menu:

- **1. Run** — prompts for an IP or CIDR, then which config (default/custom),
  then runs the pipeline. For a CIDR it sweeps → lets you exclude hosts →
  prompts config + toggles per kept host.
- **2. Preset** — pick which stages run (see [Presets](#presets)). The menu shows
  the active profile.
- **3. Edit config** — edit the custom config; only values that differ from the
  defaults are saved (to `./recon_config.json`).
- **4. Modify run** — toggle which tools run this session. Session-only; never
  saved to config.
- **5. Database** — browse everything past runs found (see
  [Findings database](#findings-database)).

### Presets

A preset is a named stage selection, so you don't have to run the whole pipeline
to do one thing. Pick one in **2. Preset** (or with `p` inside the toggle
editor):

| Preset | Answers | Stages |
| --- | --- | --- |
| **Full pipeline** | everything (the default) | all default-on stages |
| **Initial recon** | *what is this host?* | nmap port discovery, nmap service scan, TLS certs, searchsploit, whatweb, curl |
| **DNS recon** | *what does DNS say?* | whois, dig records + PTR, AXFR, `gobuster dns` |
| **Content discovery** | *what content is exposed?* | `gobuster dir` + catch-all calibration |

Presets are **session-only** (never saved to config) and are a starting point,
not a straitjacket: flip individual stages afterwards in *Modify run* and the
profile is reported as `custom`. A preset is a whitelist — any stage it doesn't
name is off, so a stage added in a future version never quietly joins a narrow
preset.

Two stages adapt so the narrow presets still work standalone:

- `gobuster dns` runs off the domain alone, so **DNS recon** enumerates
  subdomains even though it never scans a port.
- **Content discovery** has no port scan to tell it where the web servers are,
  so it TCP-probes the configured `web_ports` (default `80 443 8080 8443`) and
  uses the ones that answer — https vs http is decided by an actual TLS
  handshake, so non-standard ports get the right scheme. The reports note that
  those ports were assumed rather than scanned.

### gobuster modes

`dir` is the default. Enable `gobuster_dns` / `gobuster_vhost` via *Modify run*
(or the per-host prompt on a CIDR); you'll be asked for a domain, since those
modes enumerate names rather than scan an IP.

### Recursive enumeration

When a `gobuster dir`/`vhost` scan finds a directory (or virtual host), recon
onion can drill into it and scan again, building out the tree. It's controlled by
the `recursion` config setting (**Edit config**):

| Setting | Values | Default |
| --- | --- | --- |
| `recursion.mode` | `never` · `prompt` · `always` | `never` |
| `recursion.max_depth` | how many levels deep to drill | `2` |

- **never** — no recursion (discovery scans run once).
- **prompt** — asks before recursing into each discovered directory/vhost.
- **always** — recurses automatically into every confirmed hit.

In **prompt** and **always**, a catch-all probe first confirms each hit is a real
directory/vhost and not a wildcard server answering everything — so recursion can
never run away forever. Recursion runs after the parallel web pass (so `prompt`
can ask cleanly), and is additionally bounded by a depth limit, a visited-set,
and per-host scan caps. Recursive hits fold into the normal summary and reports
(directory paths shown absolute, e.g. `/admin/users`).

### Virtual hosts (no /etc/hosts edit required)

Name-based virtual hosts normally won't respond correctly when you hit the raw
IP — the server needs the right `Host:` header (and, over HTTPS, the right SNI).
The usual fix is editing `/etc/hosts`; recon onion avoids that.

When prompted for **"Virtual host name(s)"**, enter one or more hostnames
(comma-separated). For each, the content tools run against the target **IP**
with the host pinned explicitly:

| Tool | How the host is set |
|------|---------------------|
| `gobuster dir` | `-H "Host: <name>"` |
| `whatweb` | `--header "Host: <name>"` |
| `curl` | `--resolve <name>:<port>:<ip>` (covers DNS **and** TLS SNI) |

Artifacts are written per vhost (e.g. `gobuster_dir_80_app.htb.txt`). To
*discover* unknown vhosts in the first place, enable `gobuster_vhost`.

If you also want a real `/etc/hosts` entry (so a browser or other tools resolve
the name too), recon onion detects names that don't resolve to the target and
**offers** to add `IP  hostname` lines via `sudo` — opt-in, tagged, and removed
again at the end if you choose. Header injection works regardless, so this is
purely a convenience.

## Configuration

Defaults are hardcoded; the custom config (`./recon_config.json`) stores **only
your overrides** and missing keys fall back to defaults automatically.

| Setting | Default |
| --- | --- |
| `nmap_timing` | `-T4` |
| `output_dir` | `./recon` |
| `privileged_prefix` | empty (set to `sudo` to run `masscan` privileged) |
| `web_ports` | `80 443 8080 8443` (assumed only when no port scan runs — see [Presets](#presets)) |
| `dns.record_types` | `A AAAA NS SOA MX TXT CNAME` |
| `database.enabled` / `database.path` / `database.workspace` | `true` / empty (= `<output_dir>/reconion.db`) / `default` |
| `wordlists.dir` / `wordlists.ffuf` | `/usr/share/wordlists/dirb/common.txt` |
| `wordlists.dns` / `wordlists.vhost` | seclists subdomains top-5000 |
| `recursion.mode` / `recursion.max_depth` | `never` / `2` (see [Recursive enumeration](#recursive-enumeration)) |
| `tool_flags.<tool>` | empty (extra flags per stage) |
| `output_formats.<fmt>` | `summary`, `json`, `markdown` on; `raw`, `xml` off |

Output formats are toggled in **Edit config** with the `o` key (see [Output](#output)).

## Output

As the pipeline runs, each tool's **raw output is printed live** as a block the
moment it completes — so it reads like a script running the tools, even though
stages still run in parallel under the hood. A summary prints at the end of
each host: open ports/services, the DNS map (whois/records/PTR/AXFR), TLS
certificates, notable gobuster/ffuf hits, `nuclei` findings, and `searchsploit`
matches.

Everything is also saved to disk:

```
recon/<target-ip>/<timestamp>/
  rustscan.txt  masscan.txt                            # fast port discovery (if used)
  nmap_quick.txt   nmap_full.txt   nmap_service.txt    # nmap human-readable reports
  nmap_quick.gnmap nmap_full.gnmap nmap_service.gnmap  # grepable (machine) output
  nmap_service.xml                                     # XML copy (fed to searchsploit)
  whois_ip.txt  whois_<domain>.txt  dig.txt  dig_axfr.txt   # DNS infrastructure
  tls_cert_<port>.txt                                  # TLS cert: CN / SANs / issuer / expiry
  searchsploit.txt                                     # Exploit-DB matches
  gobuster_dir_<port>[_<vhost>][_<path>].txt  gobuster_vhost_<port>.txt  gobuster_dns.txt
  ffuf_<port>[_<vhost>].txt  nuclei_<port>[_<vhost>].txt
  whatweb_<port>[_<vhost>].txt  curl_<port>[_<vhost>].txt
  declared_<port>[_<vhost>].txt                        # robots.txt / sitemap.xml / security.txt
  report.txt  report.raw.txt  report.json  report.xml  report.md  # consolidated
```

(Recursive `gobuster dir` runs add a `_<path>` suffix, e.g.
`gobuster_dir_80_admin.txt`, so each level's evidence is kept separately.)

The per-tool files above are **always** written as raw evidence. On top of those,
each host run emits one **consolidated report** per format you've enabled — a
single document built from the run's findings (open ports + services, the DNS
map, TLS certificates, web findings with parsed gobuster/ffuf hits / `whatweb`
tech / response headers, `nuclei` findings, `searchsploit` matches, warnings):

| Format | File | Use |
|--------|------|-----|
| Summary (txt) | `report.txt` | quick human-readable wrap-up |
| Raw (txt) | `report.raw.txt` | every tool's raw output stitched into one file |
| JSON | `report.json` | structured, machine-readable — pipe into other tooling |
| XML | `report.xml` | structured (custom schema) |
| Markdown | `report.md` | drop straight into a report or notes |

Pick formats in **Edit config → `o`**; the choice is saved like any other config
override. Defaults: `summary`, `json`, and `markdown` on.

Timestamped per run, so previous runs are never overwritten.

## Findings database

Artifacts and reports are frozen to one timestamped directory, which makes them
useless for questions that span runs — *which of these boxes runs SSH?*, *was
8080 open last week?*, *where did I see that subdomain?* So every run is also
recorded into a SQLite database (`<output_dir>/reconion.db` by default), in the
spirit of msfconsole's database. Browse it in **5. Database**:

| Table | Holds |
| --- | --- |
| Hosts | every address scanned, its domain, and when it was first/last seen |
| Services | open ports with service name and version |
| Web paths | discovered paths, with status/size and whether they came from `gobuster`, `ffuf`, `robots.txt` or a sitemap |
| Findings | `nuclei` results (severity-sorted) and `searchsploit` leads |
| Virtual hosts | names pointing at the host, tagged by how they were found (manual, `gobuster vhost/dns`, TLS SAN) |
| DNS records | forward records and PTR |
| Notes | `whatweb` fingerprints, response headers, TLS certificates, whois, declared files — kept as JSON |
| Runs | each run's target, duration, stages and artifact directory |

Rows are **upserted on what they are**, not when they were seen: re-scanning a
target updates `last_seen` in place rather than inserting a duplicate, while
`first_seen` records when it originally turned up. So the tables always show
current truth, and a new port appearing is visible as a new row rather than
buried in a second copy of everything. Each row also records the run that last
touched it, so anything can be traced back to the raw artifacts.

Pick a host in the Hosts view to scope every other view to it. **Workspaces**
keep unrelated engagements apart — everything lands in `default` unless you set
`database.workspace`; switching workspaces in the menu affects browsing only.

The database never holds credentials or extracted data: recon onion observes and
never authenticates, so msf's `creds`/`loot` equivalents don't exist here. If
writing to it fails the run is unaffected — the artifacts and reports are
already on disk, and the error is reported rather than swallowed. Set
`database.enabled` to `false` to turn the whole thing off.
