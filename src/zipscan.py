"""
zipscan.py — Scan securitate pe repo/ZIP uploadat (NS-FLOW).

Flux: ZIP (multipart) -> safe extract (zip-slip protection) -> scan_code per fisier
      -> raport per fisier + agregat -> translator (raport uman).

Reguli securitate:
  - zip-slip: refuza entry-uri cu '..' sau cai absolute; nimic nu iese din tmpdir.
  - Limite: max fisiere, max dimensiune totala (decomprimat), max per fisier, max zip.
  - Doar fisiere de cod/extensii relevante; binarele sunt sarite (null bytes).
  - Codul NU se stocheaza — doar metadate + findings.
"""
import io
import os
import re
import tempfile
import zipfile
from pathlib import Path

from scanner import scan_code, is_lockfile
from translator import translate_findings

# Extensii considerate cod (se scaneaza)
CODE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.htm', '.java', '.go', '.rb',
    '.php', '.sql', '.json', '.yml', '.yaml', '.env', '.sh', '.bash', '.cs',
    '.c', '.cpp', '.h', '.kt', '.swift', '.rs', '.tf', '.vue', '.svelte',
}
# Fisiere fara extensie care merita scanate
NAKED_NAMES = {'.env', 'dockerfile', 'makefile', 'procfile'}

# .env + variantele lui (.env.local, .env.production, ...) — ACESTEA sunt fisierele cu
# secrete (fix 2026-09-26: inainte erau SĂRITE; suffixul '.local' nu era in
# CODE_EXTENSIONS, deci un zip cu secrete trecea curat).
ENV_NAME_PREFIX = '.env'
# ...dar NU sabloanele fara secrete reale (zgomot eliminat).
ENV_PLACEHOLDER_NAMES = {
    '.env.example', '.env.sample', '.env.template', '.env.dist', '.env.defaults',
}

# Directoare ignorate COMPLET (fix 2026-09-26: node_modules umplea limita de 300
# fisiere si un export Lovable/Bolt pica cu 400 fara niciun rezultat).
EXCLUDED_DIRS = {
    'node_modules', 'bower_components', 'vendor', '.git', '.svn', '.hg',
    'dist', 'build', 'out', 'target', 'coverage', 'htmlcov',
    '__pycache__', '.venv', 'venv', 'env', 'site-packages',
    '.next', '.nuxt', '.svelte-kit', '.cache', '.parcel-cache',
    '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox', '.terraform',
}

MAX_ZIP_BYTES = 5 * 1024 * 1024       # zip brut max 5MB
MAX_TOTAL_UNCOMPRESSED = 15 * 1024 * 1024  # 15MB decomprimat
MAX_FILES = 300
MAX_FILE_BYTES = 1024 * 1024          # 1MB per fisier
MAX_FINDINGS_PER_FILE = 100
MAX_FINDINGS_TOTAL = 500


def _is_excluded_dir(name: str) -> bool:
    """True daca vreun director din cale e in lista de exclusiuni."""
    parts = name.replace('\\', '/').lower().split('/')[:-1]
    return any(p in EXCLUDED_DIRS for p in parts)


def _is_scannable(name: str) -> bool:
    lower = name.lower()
    fname = Path(lower).name
    if _is_excluded_dir(lower):
        return False
    # Fix 2026-10-09: lockfiles = zgomot (hash-uri, nu secrete) → sarite.
    if is_lockfile(fname):
        return False
    if fname in NAKED_NAMES:
        return True
    # .env si TOATE variantele lui, mai putin sabloanele
    if fname.startswith(ENV_NAME_PREFIX):
        return fname not in ENV_PLACEHOLDER_NAMES
    return Path(lower).suffix in CODE_EXTENSIONS


def _looks_binary(content: bytes) -> bool:
    return b'\x00' in content[:8192]


def _safe_member_name(info: zipfile.ZipInfo) -> str:
    """Normalizeaza numele; arunca ValueError daca e zip-slip (.. sau absolut)."""
    raw = info.filename.replace('\\', '/')
    # cai absolute sau cu drive
    if raw.startswith('/') or re.match(r'^[a-zA-Z]:', raw):
        raise ValueError(f"zip-slip: cale absoluta ({raw[:60]})")
    parts = []
    for part in raw.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            raise ValueError(f"zip-slip: '..' in cale ({raw[:60]})")
        parts.append(part)
    if not parts:
        raise ValueError("zip: entry gol")
    return '/'.join(parts)


def _scan_content(code: str, filename: str) -> list:
    try:
        return scan_code(code, filename)
    except Exception:
        return []


def scan_zip(data: bytes, zip_name: str = 'repo.zip') -> dict:
    """Scaneaza un ZIP din memorie. Intoarce raport agregat + per fisier."""
    if len(data) > MAX_ZIP_BYTES:
        raise ValueError("zip prea mare (max 5MB)")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ValueError("fisierul nu e un ZIP valid")

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        # Selectam fisierele relevante INAINTE de limite: node_modules/.git/dist nu
        # trebuie sa consume bugetul (altfel un proiect real pica cu 400).
        # Zip-slip se verifica pe TOATE entry-urile (inclusiv cele sarite).
        targets = []
        for info in infos:
            if info.is_dir():
                continue
            name = _safe_member_name(info)
            if not _is_scannable(name):
                continue
            targets.append((info, name))

        if len(targets) > MAX_FILES:
            raise ValueError(
                f"prea multe fisiere de cod in zip ({len(targets)}, max {MAX_FILES}) "
                "— ignora node_modules/.git/dist sau imparte proiectul"
            )
        total_uncompressed = sum(i.file_size for i, _ in targets)
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
            raise ValueError("zip prea mare decomprimat (max 15MB)")

        findings_by_file = []
        total_findings = 0
        files_scanned = 0
        files_with_findings = 0
        all_findings = []

        for info, name in targets:
            if info.file_size > MAX_FILE_BYTES:
                continue  # fisier prea mare — sarit, nu eroare

            content = zf.read(info)
            if _looks_binary(content):
                continue

            files_scanned += 1
            try:
                code = content.decode('utf-8', errors='replace')
            except Exception:
                continue

            findings = _scan_content(code, name)
            # anti-abuz: limiteaza findings per fisier si total
            if len(findings) > MAX_FINDINGS_PER_FILE:
                findings = findings[:MAX_FINDINGS_PER_FILE]
            remaining = MAX_FINDINGS_TOTAL - total_findings
            if remaining <= 0:
                break
            if len(findings) > remaining:
                findings = findings[:remaining]
            if findings:
                files_with_findings += 1
            total_findings += len(findings)
            reports = translate_findings(findings, code)

            findings_by_file.append({
                "file": name,
                "findings": findings,
                "report": reports,
                "count": len(findings),
            })
            all_findings.extend(findings)

    summary = {
        "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "high"),
        "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "low"),
    }

    return {
        "status": "ok",
        "source": zip_name,
        "files_scanned": files_scanned,
        "files_with_findings": files_with_findings,
        "total": total_findings,
        "summary": summary,
        "findings_by_file": findings_by_file,
    }
