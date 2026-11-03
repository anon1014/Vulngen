"""Score each detector against ground truth.

Per verified case and tool:
  detected      - a finding on the vulnerable file lands within LINE_TOLERANCE of a ground-truth line
  cwe_match     - detected AND the finding's CWE matches the case's CWE
  patch_alarm   - the tool still reports something near those lines on the PATCHED file (false positive)
  other         - findings on the vulnerable file away from the ground-truth lines (noise or unknown)
"""

import pandas as pd

from . import config
from .scanners import TOOLS


def _near(line: int, targets: list[int], tol: int) -> bool:
    return any(abs(line - t) <= tol for t in targets)


def per_case(cases: list[dict], findings: list[dict], scans: list[dict], tol: int | None = None) -> pd.DataFrame:
    tol = config.LINE_TOLERANCE if tol is None else tol
    ran = {(s["case_id"], s["tool"], s["variant"]) for s in scans if s["status"] == "ok"}
    rows = []
    for case in cases:
        if not case["verified"]:
            continue
        for tool, meta in TOOLS.items():
            if case["language"] not in meta["languages"]:
                continue
            if (case["id"], tool, "vulnerable") not in ran:
                continue
            fv = [f for f in findings if f["case_id"] == case["id"] and f["tool"] == tool and f["variant"] == "vulnerable"]
            fp = [f for f in findings if f["case_id"] == case["id"] and f["tool"] == tool and f["variant"] == "patched"]
            hits = [f for f in fv if _near(f["line"], case["vuln_lines"], tol)]
            rows.append({
                "case": case["id"],
                "title": case["title"],
                "language": case["language"],
                "cwe": case["cwe"],
                "tool": meta["label"],
                "detected": bool(hits),
                "cwe_match": any(f["cwe"] == case["cwe"] for f in hits),
                "patch_alarm": any(_near(f["line"], case["vuln_lines"], tol) for f in fp)
                if (case["id"], tool, "patched") in ran else None,
                "other_findings": len(fv) - len(hits),
            })
    return pd.DataFrame(rows)


def scoreboard(detail: pd.DataFrame) -> pd.DataFrame:
    if detail.empty:
        return detail
    g = detail.groupby("tool")
    board = pd.DataFrame({
        "Cases": g.size(),
        "Detection rate": g["detected"].mean(),
        "Exact-CWE rate": g["cwe_match"].mean(),
        "Patch false-alarm rate": g["patch_alarm"].apply(lambda s: s.dropna().astype(float).mean()),
        "Avg other findings": g["other_findings"].mean(),
    })
    return board.sort_values("Detection rate", ascending=False)
