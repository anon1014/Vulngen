"""SQLite metadata plus a folder per case on disk.

Layout of data/cases/<case_id>/:
    vulnerable/target.<ext>   code shown to detectors
    patched/target.<ext>      patched twin, also shown to detectors
    trigger.<py|txt>          proof-of-concept trigger (never shown to detectors)
"""

import datetime
import difflib
import json
import shutil
import sqlite3
import uuid
from pathlib import Path

from . import config
from .catalog import LANGUAGES
from .models import GeneratedCase

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    created TEXT,
    source TEXT,
    title TEXT,
    language TEXT,
    cwe TEXT,
    explanation TEXT,
    vuln_lines TEXT,
    verified INTEGER,
    verify_log TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    tool TEXT,
    variant TEXT,
    line INTEGER,
    cwe TEXT,
    message TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    case_id TEXT,
    tool TEXT,
    variant TEXT,
    status TEXT,
    PRIMARY KEY (case_id, tool, variant)
);
"""


def conn() -> sqlite3.Connection:
    config.CASES_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def changed_lines(vulnerable: str, patched: str) -> list[int]:
    """Ground-truth lines: the lines in the vulnerable file that the patch touches."""
    a, b = vulnerable.splitlines(), patched.splitlines()
    lines: set[int] = set()
    for tag, i1, i2, _j1, _j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if i2 > i1:
            lines.update(range(i1 + 1, i2 + 1))
        else:  # pure insertion: mark the lines on either side of it
            lines.update(x for x in (i1, i1 + 1) if 1 <= x <= len(a))
    return sorted(lines)


def case_dir(case_id: str) -> Path:
    return config.CASES_DIR / case_id


def paths(case_id: str, language: str) -> dict[str, Path]:
    d = case_dir(case_id)
    ext = LANGUAGES[language]["ext"]
    return {
        "vulnerable": d / "vulnerable" / f"target.{ext}",
        "patched": d / "patched" / f"target.{ext}",
        "trigger": d / LANGUAGES[language]["trigger_file"],
    }


def save_case(gc: GeneratedCase, language: str, cwe: str, source: str) -> str:
    case_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    p = paths(case_id, language)
    for key in ("vulnerable", "patched"):
        p[key].parent.mkdir(parents=True, exist_ok=True)
    p["vulnerable"].write_text(gc.vulnerable_code.rstrip() + "\n")
    p["patched"].write_text(gc.patched_code.rstrip() + "\n")
    p["trigger"].write_text(gc.trigger.rstrip() + "\n")
    (case_dir(case_id) / "INTENTIONALLY_VULNERABLE.txt").write_text(
        "This folder contains deliberately vulnerable code generated for security-tool testing.\n"
        "Do not deploy, publish, or reuse it.\n"
    )
    lines = changed_lines(gc.vulnerable_code, gc.patched_code)
    with conn() as c:
        c.execute(
            "INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                case_id,
                datetime.datetime.now().isoformat(timespec="seconds"),
                source,
                gc.title,
                language,
                cwe,
                gc.explanation,
                json.dumps(lines),
                None,
                "",
            ),
        )
    return case_id


def set_verified(case_id: str, ok: bool, log: str) -> None:
    with conn() as c:
        c.execute("UPDATE cases SET verified=?, verify_log=? WHERE id=?", (1 if ok else 0, log, case_id))


def list_cases() -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT * FROM cases ORDER BY created DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["vuln_lines"] = json.loads(d["vuln_lines"] or "[]")
        out.append(d)
    return out


def get_case(case_id: str) -> dict | None:
    return next((c for c in list_cases() if c["id"] == case_id), None)


def delete_case(case_id: str) -> None:
    with conn() as c:
        c.execute("DELETE FROM cases WHERE id=?", (case_id,))
        c.execute("DELETE FROM findings WHERE case_id=?", (case_id,))
        c.execute("DELETE FROM scans WHERE case_id=?", (case_id,))
    shutil.rmtree(case_dir(case_id), ignore_errors=True)


def record_scan(case_id: str, tool: str, variant: str, status: str, findings: list[dict]) -> None:
    with conn() as c:
        c.execute("DELETE FROM findings WHERE case_id=? AND tool=? AND variant=?", (case_id, tool, variant))
        c.executemany(
            "INSERT INTO findings (case_id, tool, variant, line, cwe, message) VALUES (?,?,?,?,?,?)",
            [(case_id, tool, variant, f["line"], f.get("cwe", ""), f.get("message", "")) for f in findings],
        )
        c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?)", (case_id, tool, variant, status))


def all_findings() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM findings").fetchall()]


def all_scans() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM scans").fetchall()]
