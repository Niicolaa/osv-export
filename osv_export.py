#!/usr/bin/env python3
"""
Fetch OSV data and write CSVs that KQL `externaldata()` (and anything else that
reads a URL) can consume directly:

- csv/malicious_all.csv          every malicious package report (MAL-*)
- csv/malicious_high_signal.csv  the same, minus the amazon-inspector-only
                                 tea.xyz spam flood
- csv/vulnerable_all.csv         every non-malicious vulnerability, one row per
                                 (ecosystem, package, osv_id)
- csv/vulnerable_exploited.csv   only those known or likely to be exploited
                                 (CISA KEV, or EPSS >= --epss-threshold)

Upstream publishes ~285k individual JSON documents, which no query engine can
read. This flattens them once so consumers fetch a single CSV.

Sources:
  https://github.com/ossf/malicious-packages                     (malicious, Apache 2.0)
  https://osv-vulnerabilities.storage.googleapis.com             (vulnerabilities, per ecosystem)
  https://www.cisa.gov/.../known_exploited_vulnerabilities.json  (KEV)
  https://epss.empiricalsecurity.com/epss_scores-current.csv.gz  (EPSS)

Usage:
  python osv_export.py
  python osv_export.py --base-dir ./
  python osv_export.py --skip-vulnerable
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

MALICIOUS_TARBALL = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
MALICIOUS_PREFIX = "osv/malicious/"
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# Ecosystems pulled for the vulnerability export. OSV also carries OS distro
# data (Debian, Alpine, ...) which is out of scope here: this is about software
# supply chain packages.
ECOSYSTEMS = [
    "npm",
    "PyPI",
    "Maven",
    "Go",
    "NuGet",
    "RubyGems",
    "crates.io",
    "Packagist",
    "Hex",
    "Pub",
]

# Ecosystem as spelled by OSV -> the token typically seen in a package
# repository path. Anything not listed is still emitted with repo_hint empty,
# so a new ecosystem never silently disappears from the output.
REPO_HINTS = {
    "npm": "npm",
    "pypi": "pypi",
    "rubygems": "gems",
    "nuget": "nuget",
    "crates.io": "cargo",
    "packagist": "composer",
    "maven": "maven",
    "go": "go",
    "hex": "hex",
    "pub": "pub",
}

MALICIOUS_COLS = [
    "ecosystem", "package", "package_lc", "repo_hint",
    "mal_id", "source", "published", "modified", "summary",
]

VULNERABLE_COLS = [
    "ecosystem", "package", "package_lc", "repo_hint",
    "osv_id", "cve", "aliases",
    "kev", "kev_ransomware", "epss", "epss_percentile",
    "cvss_v3", "cvss_v4",
    "introduced", "fixed",
    "published", "modified", "summary",
]

# externaldata() reads external artifacts up to 100 MB. Anything larger has to
# be ingested as a table or watchlist instead, so the build says so loudly.
EXTERNALDATA_LIMIT = 100 * 1024 * 1024

log = logging.getLogger("osv-export")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def fetch(url: str, timeout: int = 600) -> bytes:
    log.info("fetching %s", url)
    request = urllib.request.Request(url, headers={"User-Agent": "osv-export"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        blob = response.read()
    log.info("  %.1f MiB", len(blob) / 1024 / 1024)
    return blob


def clean(value: str | None) -> str:
    """Collapse whitespace; newlines would break the CSV row for externaldata."""
    return " ".join((value or "").split())


def repo_hint(ecosystem: str) -> str:
    return REPO_HINTS.get(ecosystem.lower(), "")


def write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    size = path.stat().st_size
    log.info("wrote %s: %d rows, %.1f MiB", path, len(rows), size / 1024 / 1024)
    if size > EXTERNALDATA_LIMIT:
        log.warning("%s exceeds the 100 MB externaldata() limit - consumers "
                    "will need to ingest it as a table instead", path)


# --------------------------------------------------------------------------- #
# malicious packages
# --------------------------------------------------------------------------- #

def malicious_sources(record: dict) -> str:
    """Reporting sources, e.g. 'amazon-inspector' or 'checkmarx|ghsa-malware'.

    Lets consumers down-weight the tea.xyz npm spam flood (almost all
    amazon-inspector) without dropping it from the output entirely.
    """
    specific = record.get("database_specific") or {}
    origins = specific.get("malicious-packages-origins") or []
    found = {o["source"] for o in origins if isinstance(o, dict) and o.get("source")}
    return "|".join(sorted(found))


def build_malicious(tarball: Path | None) -> list[dict]:
    if tarball is None:
        tar = tarfile.open(fileobj=io.BytesIO(fetch(MALICIOUS_TARBALL)), mode="r:gz")
    else:
        log.info("reading local tarball %s", tarball)
        tar = tarfile.open(tarball, mode="r:gz")

    rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    with tar:
        for member in tar:
            if not member.isfile():
                continue
            if MALICIOUS_PREFIX not in member.name or not member.name.endswith(".json"):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                record = json.load(handle)
            except json.JSONDecodeError:
                log.warning("skipping unparseable record: %s", member.name)
                continue

            mal_id = record.get("id", "")
            if not mal_id.startswith("MAL-"):
                continue
            source = malicious_sources(record)

            for affected in record.get("affected") or []:
                package = (affected or {}).get("package") or {}
                ecosystem = package.get("ecosystem") or ""
                name = package.get("name") or ""
                if not ecosystem or not name:
                    continue
                key = (ecosystem, name.lower(), mal_id)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "ecosystem": ecosystem,
                    "package": name,
                    "package_lc": name.lower(),
                    "repo_hint": repo_hint(ecosystem),
                    "mal_id": mal_id,
                    "source": source,
                    "published": record.get("published", ""),
                    "modified": record.get("modified", ""),
                    "summary": clean(record.get("summary")),
                })
    return rows


# --------------------------------------------------------------------------- #
# vulnerabilities
# --------------------------------------------------------------------------- #

def load_kev() -> dict[str, bool]:
    """CVE id -> whether it is flagged as used in ransomware campaigns."""
    catalog = json.loads(fetch(KEV_URL, timeout=180))
    kev = {
        entry["cveID"]: str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
        for entry in catalog.get("vulnerabilities", [])
        if entry.get("cveID")
    }
    log.info("KEV catalog %s: %d CVEs", catalog.get("catalogVersion", "?"), len(kev))
    return kev


def load_epss() -> dict[str, tuple[str, str]]:
    """CVE id -> (probability, percentile)."""
    raw = gzip.decompress(fetch(EPSS_URL, timeout=180)).decode("utf-8", "replace")
    scores: dict[str, tuple[str, str]] = {}
    for line in raw.splitlines():
        if line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            scores[parts[0]] = (parts[1], parts[2])
    log.info("EPSS: %d CVEs", len(scores))
    return scores


def severity_vectors(record: dict, affected: dict) -> tuple[str, str]:
    """CVSS v3 and v4 vector strings, verbatim.

    Deliberately not converted to a numeric base score: reimplementing CVSS
    scoring is a good way to publish subtly wrong numbers. KEV and EPSS are
    better exploitation signals anyway, and consumers who want a score can
    parse the vector themselves.
    """
    v3 = v4 = ""
    for entry in (affected.get("severity") or []) + (record.get("severity") or []):
        if not isinstance(entry, dict):
            continue
        score = entry.get("score") or ""
        kind = entry.get("type") or ""
        if not v3 and (kind == "CVSS_V3" or score.startswith("CVSS:3")):
            v3 = score
        elif not v4 and (kind == "CVSS_V4" or score.startswith("CVSS:4")):
            v4 = score
    return v3, v4


def version_bounds(affected: dict) -> tuple[str, str]:
    """Flatten range events to pipe-separated introduced / fixed versions.

    This loses the pairing between an introduced and its matching fixed
    version. It is enough to answer "is this package affected at all", which
    is what a lookup join needs; confirm the exact version against the
    upstream record before acting.
    """
    introduced: list[str] = []
    fixed: list[str] = []
    for rng in affected.get("ranges") or []:
        for event in (rng or {}).get("events") or []:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced.append(str(event["introduced"]))
            if "fixed" in event:
                fixed.append(str(event["fixed"]))
            if "last_affected" in event:
                fixed.append(f"<={event['last_affected']}")
    return "|".join(dict.fromkeys(introduced)), "|".join(dict.fromkeys(fixed))


def build_vulnerable(kev: dict[str, bool],
                     epss: dict[str, tuple[str, str]]) -> list[dict]:
    rows: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for ecosystem in ECOSYSTEMS:
        try:
            blob = fetch(f"{OSV_BUCKET}/{ecosystem}/all.zip")
        except Exception as exc:  # noqa: BLE001 - one bad ecosystem must not
            log.error("skipping %s: %s", ecosystem, exc)  # sink the whole run
            continue

        count = 0
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    record = json.loads(archive.read(name))
                except json.JSONDecodeError:
                    log.warning("skipping unparseable record: %s/%s", ecosystem, name)
                    continue

                osv_id = record.get("id", "")
                # Malicious packages have their own, richer export.
                if osv_id.startswith("MAL-"):
                    continue
                # Withdrawn advisories are no longer considered valid.
                if record.get("withdrawn"):
                    continue

                aliases = [a for a in (record.get("aliases") or []) if isinstance(a, str)]
                cves = [a for a in aliases if a.startswith("CVE-")]
                cve = cves[0] if cves else ""
                probability, percentile = epss.get(cve, ("", ""))

                for affected in record.get("affected") or []:
                    package = (affected or {}).get("package") or {}
                    pkg_name = package.get("name") or ""
                    eco = package.get("ecosystem") or ecosystem
                    if not pkg_name:
                        continue
                    key = (eco, pkg_name.lower(), osv_id)
                    if key in seen:
                        continue
                    seen.add(key)

                    v3, v4 = severity_vectors(record, affected)
                    introduced, fixed = version_bounds(affected)
                    rows.append({
                        "ecosystem": eco,
                        "package": pkg_name,
                        "package_lc": pkg_name.lower(),
                        "repo_hint": repo_hint(eco),
                        "osv_id": osv_id,
                        "cve": cve,
                        "aliases": "|".join(aliases),
                        "kev": "true" if cve in kev else "false",
                        "kev_ransomware": "true" if kev.get(cve) else "false",
                        "epss": probability,
                        "epss_percentile": percentile,
                        "cvss_v3": v3,
                        "cvss_v4": v4,
                        "introduced": introduced,
                        "fixed": fixed,
                        "published": record.get("published", ""),
                        "modified": record.get("modified", ""),
                        "summary": clean(record.get("summary")),
                    })
                    count += 1
        log.info("%s: %d rows", ecosystem, count)

    return rows


# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-dir", type=Path, default=Path("."),
                        help="directory containing csv/ (default: .)")
    parser.add_argument("--tarball", type=Path, default=None,
                        help="reuse an already-downloaded malicious-packages tarball")
    parser.add_argument("--skip-malicious", action="store_true")
    parser.add_argument("--skip-vulnerable", action="store_true")
    parser.add_argument("--epss-threshold", type=float, default=0.1,
                        help="EPSS probability at or above which a vulnerability "
                             "counts as likely exploited (default: 0.1)")
    parser.add_argument("--min-malicious-rows", type=int, default=100_000,
                        help="fail rather than publish a truncated malicious "
                             "export (default: 100000)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    csv_dir = args.base_dir / "csv"

    if not args.skip_malicious:
        rows = build_malicious(args.tarball)
        if len(rows) < args.min_malicious_rows:
            log.error("only %d malicious rows (< %d), refusing to publish",
                      len(rows), args.min_malicious_rows)
            return 1
        write_csv(csv_dir / "malicious_all.csv", MALICIOUS_COLS, rows)

        # Everything except records whose only reporter is amazon-inspector,
        # which is overwhelmingly the tea.xyz npm token-farming flood.
        high = [r for r in rows if r["source"] != "amazon-inspector"]
        write_csv(csv_dir / "malicious_high_signal.csv", MALICIOUS_COLS, high)

    if not args.skip_vulnerable:
        rows = build_vulnerable(load_kev(), load_epss())
        if not rows:
            log.error("no vulnerability rows produced, refusing to publish")
            return 1
        write_csv(csv_dir / "vulnerable_all.csv", VULNERABLE_COLS, rows)

        def exploited(row: dict) -> bool:
            if row["kev"] == "true":
                return True
            try:
                return float(row["epss"]) >= args.epss_threshold
            except ValueError:
                return False

        write_csv(csv_dir / "vulnerable_exploited.csv",
                  VULNERABLE_COLS, [r for r in rows if exploited(r)])

    return 0


if __name__ == "__main__":
    sys.exit(main())
