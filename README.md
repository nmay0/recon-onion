# recon onion

A Python recon-automation tool that orchestrates `nmap`, `gobuster`, `ffuf`,
`whatweb`, `curl`, and `searchsploit` into a staged, partly-parallel pipeline
with a small `rich`-based CLI.

> **Authorized testing only.** Use exclusively against systems you own or have
> explicit written permission to assess.

## Pipeline

For each target host:

1. **Quick scan** — `nmap -F` (top ports) fires immediately.
2. **Full scan** — `nmap -p-` runs *in parallel* with the quick scan.
3. **Service scan** — once ports are known, `nmap -sV -sC` runs against the
   union of all discovered open ports (also emitting an XML copy for the next step).
4. **Exploit search** — `searchsploit --nmap` reads the service-scan XML and
   searches Exploit-DB for each detected product/version.
5. **Web enumeration** — for every detected web port, `gobuster` + `whatweb` +
   `curl -I` (and `ffuf`, if enabled) run *in parallel*.
   - HTTPS-aware: `https://` scheme for gobuster/whatweb and `-k` for curl on
     443/8443 (or any `ssl`/`https` service), so self-signed certs don't break.

`ffuf` is **off by default** (content discovery overlaps with `gobuster dir`);
enable it via *Modify run* or the per-host CIDR prompt. `searchsploit` is on by
default and only runs when the service scan produced results.

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
sudo apt install nmap gobuster ffuf whatweb exploitdb curl seclists
```

(`exploitdb` provides `searchsploit`; `seclists` provides the dns/vhost
wordlists. On Kali most of these ship preinstalled. `ffuf` is only needed if you
enable it.)

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
- **2. Edit config** — edit the custom config; only values that differ from the
  defaults are saved (to `./recon_config.json`).
- **3. Modify run** — toggle which tools run this session. Session-only; never
  saved to config.

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
| `wordlists.dir` / `wordlists.ffuf` | `/usr/share/wordlists/dirb/common.txt` |
| `wordlists.dns` / `wordlists.vhost` | seclists subdomains top-5000 |
| `recursion.mode` / `recursion.max_depth` | `never` / `2` (see [Recursive enumeration](#recursive-enumeration)) |
| `tool_flags.<tool>` | empty (extra flags per stage) |
| `output_formats.<fmt>` | `summary`, `json`, `markdown` on; `raw`, `xml` off |

Output formats are toggled in **Edit config** with the `o` key (see [Output](#output)).

## Output

As the pipeline runs, each tool's **raw output is printed live** as a block the
moment it completes — so it reads like a script running the tools, even though
stages still run in parallel under the hood. A summary table (open ports,
services, notable gobuster/ffuf hits, `searchsploit` matches) prints at the end
of each host.

Everything is also saved to disk:

```
recon/<target-ip>/<timestamp>/
  nmap_quick.txt   nmap_full.txt   nmap_service.txt    # human-readable reports
  nmap_quick.gnmap nmap_full.gnmap nmap_service.gnmap  # grepable (machine) output
  nmap_service.xml                                     # XML copy (fed to searchsploit)
  searchsploit.txt                                     # Exploit-DB matches
  gobuster_dir_<port>[_<vhost>].txt  gobuster_vhost_<port>.txt  gobuster_dns.txt
  ffuf_<port>[_<vhost>].txt
  whatweb_<port>[_<vhost>].txt  curl_<port>[_<vhost>].txt
  report.txt  report.raw.txt  report.json  report.xml  report.md  # consolidated
```

The per-tool files above are **always** written as raw evidence. On top of those,
each host run emits one **consolidated report** per format you've enabled — a
single document built from the run's findings (open ports + services, web
findings with parsed gobuster/ffuf hits / `whatweb` tech / response headers,
`searchsploit` matches, warnings):

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
