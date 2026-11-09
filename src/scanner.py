from __future__ import annotations
import math
import re
from pathlib import Path

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_like", "high"),
    (r"(?i)password\s*=\s*.+", "password_assignment", "high"),
    (r"(?i)api[_-]?key\s*=\s*.+", "api_key_assignment", "high"),
]
IAC_PATTERNS = [
    (r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', "sg_open_cidr", "high"),
]

def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())

def scan_file(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    findings = []
    patterns = list(SECRET_PATTERNS)
    if path.suffix in {".tf", ".yml", ".yaml"}:
        patterns += IAC_PATTERNS
    for pattern, name, sev in patterns:
        for m in re.finditer(pattern, text):
            findings.append({"file": str(path), "rule": name, "severity": sev, "match": m.group(0)[:80]})
    for m in re.finditer(r"(?i)(secret|token|key)\s*[:=]\s*([A-Za-z0-9/+=_-]{20,})", text):
        val = m.group(2)
        if shannon(val) >= 3.5:
            findings.append({"file": str(path), "rule": "high_entropy_token", "severity": "medium", "match": val[:12] + "..."})
    return findings

def scan_tree(root: Path) -> dict:
    findings = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in {".venv", ".git", "node_modules"} for part in p.parts):
            continue
        if p.suffix.lower() in {".env", ".tf", ".py", ".js", ".ts", ".yml", ".yaml", ".json", ".txt"}:
            findings.extend(scan_file(p))
    return {"finding_count": len(findings), "findings": findings}
