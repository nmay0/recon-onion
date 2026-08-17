"""Persistent findings database — what every run learned, kept across runs.

A run already produces per-tool artifacts and consolidated reports, but both are
frozen to one `recon/<host>/<timestamp>/` directory: nothing answers "which of
these boxes runs SSH?" or "was 8080 open last week?". This module keeps the
distilled results in a SQLite file so the answers survive the run, in the spirit
of msfconsole's database.

Two properties make it a database rather than a pile of reports:

* **Upsert on the natural key.** A host/service/path/vuln is identified by what
  it *is* (address, port+proto, path, name), not by when it was seen. Re-scanning
  a target updates ``last_seen`` instead of inserting a duplicate, so the tables
  show current truth while ``first_seen`` records when it turned up, and every
  row carries the run that last touched it for tracing back to the artifacts.
* **One writer, one source.** ``record_run`` consumes the canonical document
  ``report.build_document`` already builds — no second parse of tool output, and
  no way for the DB and the reports to disagree about a run.

Deliberately absent: msf's ``creds`` and ``loot``. reconion observes and never
authenticates or extracts, so those tables could only ever be empty; providing
them would invite the tool across the line it does not cross (see "Recon only").

The module is stdlib-only and imports nothing else from the package: it takes
plain dicts and paths, so it can never participate in an import cycle.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

# Default filename, created alongside the run output so a database travels with
# the engagement folder it describes.
DB_FILENAME = "reconion.db"
DEFAULT_WORKSPACE = "default"

# Note types stored in the `notes` table (JSON payload each).
NOTE_TYPES = ("whatweb", "headers", "declared", "tls", "whois_ip",
              "whois_domain", "axfr")


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
# Migrations are applied in order and the count is stored in PRAGMA
# user_version. To change the schema, APPEND a script — never edit one that has
# shipped, or databases in the field will skip the change.

_V1 = """
CREATE TABLE workspaces (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE hosts (
    id            INTEGER PRIMARY KEY,
    workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    address       TEXT NOT NULL,
    domain        TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    last_run_id   INTEGER,
    UNIQUE (workspace_id, address)
);

CREATE TABLE runs (
    id                INTEGER PRIMARY KEY,
    workspace_id      INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    host_id           INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    target            TEXT NOT NULL,
    started           TEXT,
    finished          TEXT,
    duration_seconds  REAL,
    stages            TEXT,
    run_dir           TEXT,
    schema_version    TEXT
);

CREATE TABLE services (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    proto       TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT,
    name        TEXT,
    version     TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_run_id INTEGER,
    UNIQUE (host_id, port, proto)
);

CREATE TABLE web_paths (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_id  INTEGER REFERENCES services(id) ON DELETE CASCADE,
    vhost       TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL,
    status      INTEGER,
    length      INTEGER,
    redirect    TEXT,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_run_id INTEGER
);
CREATE UNIQUE INDEX web_paths_key ON web_paths
    (host_id, COALESCE(service_id, -1), vhost, path, source);

CREATE TABLE vulns (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_id  INTEGER REFERENCES services(id) ON DELETE CASCADE,
    vhost       TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    severity    TEXT,
    source      TEXT NOT NULL,
    template    TEXT,
    info        TEXT,
    url         TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_run_id INTEGER
);
CREATE UNIQUE INDEX vulns_key ON vulns
    (host_id, COALESCE(service_id, -1), vhost, name, source);

CREATE TABLE vhosts (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_run_id INTEGER,
    UNIQUE (host_id, name, source)
);

CREATE TABLE dns_records (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    rtype       TEXT NOT NULL,
    value       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_run_id INTEGER,
    UNIQUE (host_id, name, rtype, value)
);

CREATE TABLE notes (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    service_id  INTEGER REFERENCES services(id) ON DELETE CASCADE,
    vhost       TEXT NOT NULL DEFAULT '',
    ntype       TEXT NOT NULL,
    data        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    last_run_id INTEGER
);
CREATE UNIQUE INDEX notes_key ON notes
    (host_id, COALESCE(service_id, -1), vhost, ntype);

CREATE INDEX hosts_workspace ON hosts (workspace_id);
CREATE INDEX services_host ON services (host_id);
CREATE INDEX web_paths_host ON web_paths (host_id);
CREATE INDEX vulns_host ON vulns (host_id);
"""

_MIGRATIONS: list[str] = [_V1]
SCHEMA_VERSION = len(_MIGRATIONS)


class DatabaseError(RuntimeError):
    """Raised for conditions the caller should report rather than crash on."""


# --------------------------------------------------------------------------- #
# Settings / connection
# --------------------------------------------------------------------------- #

def _truthy(value: Any) -> bool:
    """Read a config flag that the string-only config editor may have touched."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def database_settings(config: dict[str, Any]) -> tuple[bool, Path, str]:
    """Return (enabled, db_file, workspace) from the effective config.

    A blank ``database.path`` means "next to the output directory", so the
    database follows the engagement folder without being configured twice. The
    path is expanded and resolved for the same reason ``make_run_dir`` is: a
    relative path silently means something different from another cwd.
    """
    section = config.get("database") or {}
    enabled = _truthy(section.get("enabled", True))
    workspace = (str(section.get("workspace") or "").strip()
                 or DEFAULT_WORKSPACE)
    raw = str(section.get("path") or "").strip()
    if raw:
        db_file = Path(raw).expanduser()
    else:
        out = Path(str(config.get("output_dir") or "./recon")).expanduser()
        db_file = out / DB_FILENAME
    return enabled, db_file.resolve(), workspace


def _migrate(conn: sqlite3.Connection) -> None:
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version > len(_MIGRATIONS):
        raise DatabaseError(
            f"database schema version {version} is newer than this reconion "
            f"understands ({SCHEMA_VERSION}); upgrade reconion or point "
            f"database.path at a different file")
    for step, script in enumerate(_MIGRATIONS[version:], start=version + 1):
        conn.executescript(script)
        conn.execute(f"PRAGMA user_version = {step}")  # PRAGMA takes no params


@contextmanager
def connect(db_file: Path, *, create: bool = True) -> Iterator[sqlite3.Connection]:
    """Open (and migrate) the database, committing on clean exit.

    With *create* False a missing file raises instead of being created — the
    browse/query paths should not conjure an empty database as a side effect of
    looking at one.
    """
    db_file = Path(db_file)
    if not db_file.exists():
        if not create:
            raise DatabaseError(f"no database at {db_file}")
        db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _migrate(conn)
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Write helpers
# --------------------------------------------------------------------------- #

def _upsert(conn: sqlite3.Connection, table: str, conflict: str,
            key: dict[str, Any], values: dict[str, Any],
            now: str, run_id: int | None) -> None:
    """Insert *key* + *values*, or refresh an existing row with the same key.

    ``first_seen`` is set on insert and deliberately never updated: it is the
    answer to "when did this turn up?", which a re-scan must not overwrite.
    Table and column names are module literals; every value is parameterised.
    """
    cols = {**key, **values, "first_seen": now, "last_seen": now,
            "last_run_id": run_id}
    names = list(cols)
    updates = ", ".join(f"{c}=excluded.{c}"
                        for c in (*values, "last_seen", "last_run_id"))
    conn.execute(
        f"INSERT INTO {table} ({', '.join(names)}) "
        f"VALUES ({', '.join('?' for _ in names)}) "
        f"ON CONFLICT({conflict}) DO UPDATE SET {updates}",
        [cols[n] for n in names],
    )


def _lookup_id(conn: sqlite3.Connection, table: str,
               where: dict[str, Any]) -> int:
    clause = " AND ".join(f"{c}=?" for c in where)
    row = conn.execute(f"SELECT id FROM {table} WHERE {clause}",
                       list(where.values())).fetchone()
    return int(row["id"])


def workspace_id(conn: sqlite3.Connection, name: str, now: str) -> int:
    """Return the workspace's id, creating it if this is its first sighting."""
    conn.execute(
        "INSERT INTO workspaces (name, created_at) VALUES (?, ?) "
        "ON CONFLICT(name) DO NOTHING", (name, now))
    return _lookup_id(conn, "workspaces", {"name": name})


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _found_name(line: str) -> str:
    """The host token from a gobuster ``Found: name Status: 200 ...`` line.

    Kept here as three lines rather than importing tools.py, so this module
    stays stdlib-only and dependency-free.
    """
    rest = line.split(":", 1)[1] if line.lower().startswith("found:") else line
    return rest.strip().split()[0].rstrip(".") if rest.strip() else ""


# --------------------------------------------------------------------------- #
# Recording a run
# --------------------------------------------------------------------------- #

def record_run(doc: dict[str, Any], *, db_file: Path, workspace: str,
               run_dir: Path | None = None) -> dict[str, int]:
    """Store one host run's canonical document; return per-table row counts.

    *doc* is exactly what ``report.build_document`` produced, so everything here
    is a mapping exercise: no tool output is parsed a second time.
    """
    now = datetime.now().isoformat(timespec="seconds")
    counts: dict[str, int] = {}
    with connect(db_file) as conn:
        ws_id = workspace_id(conn, workspace, now)
        scan = doc.get("scan") or {}
        address = str(doc.get("target") or "").strip()
        if not address:
            raise DatabaseError("run document has no target to record")

        # Only a run that learned a domain writes one. The domain is prompted
        # for solely when a DNS stage is on (dig/gobuster_dns/gobuster_vhost),
        # so a later fuzz-only run — or an Enter at the prompt — would other-
        # wise write NULL over the domain an earlier run recorded, which is the
        # one way this schema loses what it has already seen.
        domain = str(scan.get("domain") or "").strip()
        _upsert(conn, "hosts", "workspace_id, address",
                {"workspace_id": ws_id, "address": address},
                {"domain": domain} if domain else {}, now, None)
        host_id = _lookup_id(conn, "hosts",
                             {"workspace_id": ws_id, "address": address})

        toggles = scan.get("toggles") or {}
        cur = conn.execute(
            "INSERT INTO runs (workspace_id, host_id, target, started, "
            "finished, duration_seconds, stages, run_dir, schema_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ws_id, host_id, address, doc.get("started"), doc.get("finished"),
             doc.get("duration_seconds"),
             ",".join(k for k, v in toggles.items() if v),
             str(run_dir) if run_dir else None,
             str(doc.get("schema_version") or "")))
        run_id = int(cur.lastrowid)
        conn.execute("UPDATE hosts SET last_run_id=? WHERE id=?",
                     (run_id, host_id))

        services = _store_services(conn, host_id, run_id, doc, now)
        counts["services"] = len(services)
        counts["web_paths"] = _store_web(conn, host_id, run_id, doc, services, now)
        counts["vulns"] = _store_vulns(conn, host_id, run_id, doc, services, now)
        counts["vhosts"] = _store_vhosts(conn, host_id, run_id, doc, now)
        counts["dns_records"] = _store_dns(conn, host_id, run_id, doc, now)
        counts["notes"] = _store_notes(conn, host_id, run_id, doc, services, now)
    return counts


def _store_services(conn: sqlite3.Connection, host_id: int, run_id: int,
                    doc: dict[str, Any], now: str) -> dict[int, int]:
    """Upsert the open ports; return {port number: service row id}."""
    ids: dict[int, int] = {}
    for port in doc.get("ports") or []:
        number, proto = port.get("number"), port.get("proto") or "tcp"
        if number is None:
            continue
        _upsert(conn, "services", "host_id, port, proto",
                {"host_id": host_id, "port": int(number), "proto": proto},
                {"state": port.get("state") or "open",
                 "name": port.get("service") or "",
                 "version": port.get("version") or ""}, now, run_id)
        ids[int(number)] = _lookup_id(
            conn, "services",
            {"host_id": host_id, "port": int(number), "proto": proto})
    return ids


def _store_web(conn: sqlite3.Connection, host_id: int, run_id: int,
               doc: dict[str, Any], services: dict[int, int], now: str) -> int:
    """Store discovered paths from every web context, tagged with their source."""
    stored = 0

    def put(service_id: int | None, vhost: str, path: str, *, source: str,
            status: Any = None, length: Any = None, redirect: Any = None) -> None:
        nonlocal stored
        if not path:
            return
        _upsert(conn, "web_paths",
                "host_id, COALESCE(service_id, -1), vhost, path, source",
                {"host_id": host_id, "service_id": service_id, "vhost": vhost,
                 "path": path, "source": source},
                {"status": status, "length": length, "redirect": redirect},
                now, run_id)
        stored += 1

    for entry in doc.get("web") or []:
        port = entry.get("port")
        service_id = services.get(int(port)) if port is not None else None
        vhost = entry.get("vhost") or ""
        for hit in entry.get("gobuster") or []:
            put(service_id, vhost, hit.get("path"), source="gobuster",
                status=hit.get("status"), length=hit.get("size"),
                redirect=hit.get("redirect"))
        for hit in entry.get("ffuf") or []:
            put(service_id, vhost, hit.get("path"), source="ffuf",
                status=hit.get("status"), length=hit.get("size"))
        # Passive finds: paths the server volunteered, no status attached.
        declared = entry.get("declared") or {}
        for path in declared.get("robots_paths") or []:
            put(service_id, vhost, path, source="robots")
        for url in declared.get("sitemap_urls") or []:
            put(service_id, vhost, url, source="sitemap")
    return stored


def _store_vulns(conn: sqlite3.Connection, host_id: int, run_id: int,
                 doc: dict[str, Any], services: dict[int, int], now: str) -> int:
    """Store nuclei findings and searchsploit candidates in one table.

    Both answer "what might be wrong here?", so they share a table and are told
    apart by ``source``. searchsploit runs off the whole service scan, so its
    rows are host-level (no service_id) — they are candidate leads, not
    confirmed issues, and severity is left unknown to say so.
    """
    stored = 0
    for finding in doc.get("findings") or []:
        port = finding.get("port")
        name = finding.get("name") or finding.get("template_id") or "(unnamed)"
        _upsert(conn, "vulns",
                "host_id, COALESCE(service_id, -1), vhost, name, source",
                {"host_id": host_id,
                 "service_id": services.get(int(port)) if port is not None else None,
                 "vhost": finding.get("vhost") or "", "name": name,
                 "source": "nuclei"},
                {"severity": finding.get("severity") or "unknown",
                 "template": finding.get("template_id") or "",
                 "info": _json({"tags": finding.get("tags") or [],
                                "type": finding.get("type") or ""}),
                 "url": finding.get("matched_at") or finding.get("url") or ""},
                now, run_id)
        stored += 1
    for exploit in doc.get("exploits") or []:
        title = exploit.get("title")
        if not title:
            continue
        _upsert(conn, "vulns",
                "host_id, COALESCE(service_id, -1), vhost, name, source",
                {"host_id": host_id, "service_id": None, "vhost": "",
                 "name": title, "source": "searchsploit"},
                {"severity": "unknown", "template": "",
                 "info": exploit.get("path") or "", "url": ""}, now, run_id)
        stored += 1
    return stored


def _store_vhosts(conn: sqlite3.Connection, host_id: int, run_id: int,
                  doc: dict[str, Any], now: str) -> int:
    """Store every name that points at this host, tagged with how it was found."""
    stored = 0
    seen: list[tuple[str, str]] = []
    for name in (doc.get("scan") or {}).get("vhosts") or []:
        seen.append((str(name).strip(), "manual"))
    discovery = doc.get("discovery") or {}
    for line in discovery.get("vhost") or []:
        seen.append((_found_name(line), "gobuster_vhost"))
    for line in discovery.get("dns") or []:
        seen.append((_found_name(line), "gobuster_dns"))
    for cert in doc.get("tls") or []:
        for san in cert.get("sans") or []:
            seen.append((str(san).strip(), "tls_san"))
    for name, source in seen:
        if not name:
            continue
        _upsert(conn, "vhosts", "host_id, name, source",
                {"host_id": host_id, "name": name, "source": source},
                {}, now, run_id)
        stored += 1
    return stored


def _store_dns(conn: sqlite3.Connection, host_id: int, run_id: int,
               doc: dict[str, Any], now: str) -> int:
    dns = doc.get("dns") or {}
    domain = dns.get("domain") or ""
    target = dns.get("target") or doc.get("target") or ""
    stored = 0
    pairs: list[tuple[str, str, str]] = []
    for rtype, values in (dns.get("records") or {}).items():
        for value in values:
            pairs.append((domain or target, rtype, str(value)))
    for value in dns.get("ptr") or []:
        pairs.append((target, "PTR", str(value)))
    for name, rtype, value in pairs:
        if not (name and rtype and value):
            continue
        _upsert(conn, "dns_records", "host_id, name, rtype, value",
                {"host_id": host_id, "name": name, "rtype": rtype,
                 "value": value}, {}, now, run_id)
        stored += 1
    return stored


def _store_notes(conn: sqlite3.Connection, host_id: int, run_id: int,
                 doc: dict[str, Any], services: dict[int, int], now: str) -> int:
    """Store the structured-but-varied evidence as typed JSON notes.

    Fingerprints, headers, certificates and whois output all have their own
    shapes and change between tool versions. Giving each a table would mean a
    migration every time one gains a field, so they live here as JSON keyed by
    type — the same pressure valve msf's notes table provides.
    """
    stored = 0

    def put(ntype: str, data: Any, *, service_id: int | None = None,
            vhost: str = "") -> None:
        nonlocal stored
        if not data:
            return
        _upsert(conn, "notes", "host_id, COALESCE(service_id, -1), vhost, ntype",
                {"host_id": host_id, "service_id": service_id, "vhost": vhost,
                 "ntype": ntype}, {"data": _json(data)}, now, run_id)
        stored += 1

    for entry in doc.get("web") or []:
        port = entry.get("port")
        service_id = services.get(int(port)) if port is not None else None
        vhost = entry.get("vhost") or ""
        put("whatweb", entry.get("whatweb"), service_id=service_id, vhost=vhost)
        put("headers", entry.get("headers"), service_id=service_id, vhost=vhost)
        put("declared", entry.get("declared"), service_id=service_id, vhost=vhost)
    for cert in doc.get("tls") or []:
        port = cert.get("port")
        put("tls", {k: v for k, v in cert.items() if k != "port"},
            service_id=services.get(int(port)) if port is not None else None)
    dns = doc.get("dns") or {}
    put("whois_ip", dns.get("ip_whois"))
    put("whois_domain", dns.get("domain_whois"))
    put("axfr", dns.get("axfr"))
    return stored


# --------------------------------------------------------------------------- #
# Queries (the browse surface)
# --------------------------------------------------------------------------- #
# Each opens its own read-only-ish connection and returns plain dicts, so the
# CLI never handles a cursor or a schema detail.

def _rows(db_file: Path, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    with connect(db_file, create=False) as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def exists(db_file: Path) -> bool:
    return Path(db_file).exists()


def list_workspaces(db_file: Path) -> list[dict[str, Any]]:
    return _rows(db_file, """
        SELECT w.name, w.created_at,
               (SELECT COUNT(*) FROM hosts h WHERE h.workspace_id = w.id) AS hosts,
               (SELECT COUNT(*) FROM runs r WHERE r.workspace_id = w.id) AS runs
        FROM workspaces w ORDER BY w.name
    """)


def list_hosts(db_file: Path, workspace: str,
               search: str | None = None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.address, h.domain, h.first_seen, h.last_seen,
               (SELECT COUNT(*) FROM services s WHERE s.host_id = h.id) AS services,
               (SELECT COUNT(*) FROM web_paths p WHERE p.host_id = h.id) AS paths,
               (SELECT COUNT(*) FROM vulns v WHERE v.host_id = h.id) AS vulns
        FROM hosts h JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if search:
        sql += " AND (h.address LIKE ? OR IFNULL(h.domain,'') LIKE ?)"
        params += (f"%{search}%", f"%{search}%")
    return _rows(db_file, sql + " ORDER BY h.last_seen DESC, h.address", params)


def list_services(db_file: Path, workspace: str, host: str | None = None,
                  search: str | None = None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.address AS host, s.port, s.proto, s.state, s.name, s.version,
               s.first_seen, s.last_seen
        FROM services s
        JOIN hosts h ON h.id = s.host_id
        JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND h.address = ?"
        params += (host,)
    if search:
        sql += (" AND (IFNULL(s.name,'') LIKE ? OR IFNULL(s.version,'') LIKE ?"
                " OR CAST(s.port AS TEXT) = ?)")
        params += (f"%{search}%", f"%{search}%", search)
    return _rows(db_file, sql + " ORDER BY h.address, s.port", params)


def list_web_paths(db_file: Path, workspace: str, host: str | None = None,
                   search: str | None = None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.address AS host, s.port, p.vhost, p.path, p.status, p.length,
               p.redirect, p.source, p.last_seen
        FROM web_paths p
        JOIN hosts h ON h.id = p.host_id
        LEFT JOIN services s ON s.id = p.service_id
        JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND h.address = ?"
        params += (host,)
    if search:
        sql += " AND p.path LIKE ?"
        params += (f"%{search}%",)
    return _rows(db_file, sql + " ORDER BY h.address, s.port, p.path", params)


# Most-urgent first; the CASE mirrors tools.NUCLEI_SEVERITY_ORDER.
_SEVERITY_SORT = ("CASE LOWER(IFNULL(v.severity,'unknown')) "
                  "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                  "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 "
                  "WHEN 'info' THEN 4 ELSE 5 END")


def list_vulns(db_file: Path, workspace: str, host: str | None = None,
               search: str | None = None) -> list[dict[str, Any]]:
    sql = f"""
        SELECT h.address AS host, s.port, v.vhost, v.name, v.severity,
               v.source, v.template, v.info, v.url, v.last_seen
        FROM vulns v
        JOIN hosts h ON h.id = v.host_id
        LEFT JOIN services s ON s.id = v.service_id
        JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND h.address = ?"
        params += (host,)
    if search:
        sql += " AND (v.name LIKE ? OR IFNULL(v.template,'') LIKE ?)"
        params += (f"%{search}%", f"%{search}%")
    return _rows(db_file, sql + f" ORDER BY {_SEVERITY_SORT}, h.address, v.name",
                 params)


def list_vhosts(db_file: Path, workspace: str,
                host: str | None = None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.address AS host, vh.name, vh.source, vh.first_seen, vh.last_seen
        FROM vhosts vh
        JOIN hosts h ON h.id = vh.host_id
        JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND h.address = ?"
        params += (host,)
    return _rows(db_file, sql + " ORDER BY h.address, vh.name", params)


def list_dns_records(db_file: Path, workspace: str,
                     host: str | None = None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.address AS host, d.name, d.rtype, d.value, d.last_seen
        FROM dns_records d
        JOIN hosts h ON h.id = d.host_id
        JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND h.address = ?"
        params += (host,)
    return _rows(db_file, sql + " ORDER BY h.address, d.rtype, d.value", params)


def list_notes(db_file: Path, workspace: str, host: str | None = None,
               ntype: str | None = None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.address AS host, s.port, n.vhost, n.ntype, n.data, n.last_seen
        FROM notes n
        JOIN hosts h ON h.id = n.host_id
        LEFT JOIN services s ON s.id = n.service_id
        JOIN workspaces w ON w.id = h.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND h.address = ?"
        params += (host,)
    if ntype:
        sql += " AND n.ntype = ?"
        params += (ntype,)
    return _rows(db_file, sql + " ORDER BY h.address, s.port, n.ntype", params)


def list_runs(db_file: Path, workspace: str, host: str | None = None,
              limit: int = 50) -> list[dict[str, Any]]:
    sql = """
        SELECT r.id, r.target, r.started, r.finished, r.duration_seconds,
               r.stages, r.run_dir
        FROM runs r JOIN workspaces w ON w.id = r.workspace_id
        WHERE w.name = ?
    """
    params: tuple = (workspace,)
    if host:
        sql += " AND r.target = ?"
        params += (host,)
    return _rows(db_file, sql + " ORDER BY r.id DESC LIMIT ?", params + (limit,))


def workspace_stats(db_file: Path, workspace: str) -> dict[str, int]:
    """Row counts per table for one workspace (all zero if it has no rows)."""
    counts: dict[str, int] = {}
    with connect(db_file, create=False) as conn:
        row = conn.execute("SELECT id FROM workspaces WHERE name = ?",
                           (workspace,)).fetchone()
        if row is None:
            return {t: 0 for t in ("hosts", "services", "web_paths", "vulns",
                                   "vhosts", "dns_records", "notes", "runs")}
        ws_id = int(row["id"])
        counts["hosts"] = conn.execute(
            "SELECT COUNT(*) FROM hosts WHERE workspace_id = ?",
            (ws_id,)).fetchone()[0]
        counts["runs"] = conn.execute(
            "SELECT COUNT(*) FROM runs WHERE workspace_id = ?",
            (ws_id,)).fetchone()[0]
        for table in ("services", "web_paths", "vulns", "vhosts",
                      "dns_records", "notes"):
            counts[table] = conn.execute(
                f"SELECT COUNT(*) FROM {table} t JOIN hosts h ON h.id = t.host_id "
                f"WHERE h.workspace_id = ?", (ws_id,)).fetchone()[0]
    return counts


# --------------------------------------------------------------------------- #
# Mutations driven from the UI
# --------------------------------------------------------------------------- #

def create_workspace(db_file: Path, name: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with connect(db_file) as conn:
        workspace_id(conn, name, now)


def delete_host(db_file: Path, workspace: str, address: str) -> int:
    """Delete one host and everything hanging off it. Returns rows deleted."""
    with connect(db_file, create=False) as conn:
        cur = conn.execute(
            "DELETE FROM hosts WHERE address = ? AND workspace_id = "
            "(SELECT id FROM workspaces WHERE name = ?)", (address, workspace))
        return cur.rowcount


def delete_workspace(db_file: Path, name: str) -> int:
    with connect(db_file, create=False) as conn:
        cur = conn.execute("DELETE FROM workspaces WHERE name = ?", (name,))
        return cur.rowcount
