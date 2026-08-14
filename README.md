# osv-export

This repository automatically downloads and republishes data from
[**OSV**](https://osv.dev), the [**OpenSSF malicious-packages**](https://github.com/ossf/malicious-packages)
corpus, [**CISA KEV**](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and [**EPSS**](https://www.first.org/epss/), converted to CSV.

It stores the **CSV-converted** datasets in `csv/`:

- **Malicious packages** — packages published *to attack you*
  - `csv/malicious_all.csv` — every malicious package report (`MAL-*`)
  - `csv/malicious_high_signal.csv` — the same, minus the tea.xyz spam flood
- **Vulnerable packages** — packages with a known CVE
  - `csv/vulnerable_all.csv` — one row per (ecosystem, package, advisory)
  - `csv/vulnerable_exploited.csv` — only those in CISA KEV, or with EPSS ≥ 0.1

A GitHub Actions workflow runs **daily** to update the data automatically.

## Why this exists

OSV publishes ~285,000 records as *individual JSON documents*, one per file.
That is right for a database and wrong for a query engine. The only bulk
artifacts upstream are archives of those files:

| Upstream artifact | Size | Usable by a query engine? |
|---|---|---|
| `npm/all.zip` | 219 MB | archive of ~227k JSON documents |
| `all.zip` (all ecosystems) | 1.45 GB | same |
| `modified_id.csv` | 8.5 MB | record IDs only, no package names |

`externaldata()` needs a single delimited file. It can't walk an archive of a
quarter-million documents and pull `affected[].package.name` out of each. This
repo does that once a day and commits the result.

## Example usage in Kusto

Malicious packages, filtered to the reporters worth alerting on:

```kusto
let MaliciousPackages =
externaldata (
  ecosystem:string, package:string, package_lc:string, repo_hint:string,
  mal_id:string, source:string, published:string, modified:string, summary:string
)
[
  @"https://raw.githubusercontent.com/Niicolaa/osv-export/main/csv/malicious_high_signal.csv"
]
with (format="csv", ignoreFirstRecord=true);
MaliciousPackages
| where source has_any ("checkmarx", "reversing-labs", "ghsa-malware")
```

Vulnerabilities that are actually being exploited:

```kusto
let ExploitedPackages =
externaldata (
  ecosystem:string, package:string, package_lc:string, repo_hint:string,
  osv_id:string, cve:string, aliases:string,
  kev:string, kev_ransomware:string, epss:string, epss_percentile:string,
  cvss_v3:string, cvss_v4:string, introduced:string, fixed:string,
  published:string, modified:string, summary:string
)
[
  @"https://raw.githubusercontent.com/Niicolaa/osv-export/main/csv/vulnerable_exploited.csv"
]
with (format="csv", ignoreFirstRecord=true);
ExploitedPackages
| where kev_ransomware == "true"
```

Join either against whatever records what your organisation pulled — artifact
repository access logs, package manager telemetry, build logs, SBOMs — on
`package_lc`.

> **Note:** Microsoft Defender XDR advanced hunting does not support
> `externaldata()`. Use ADX or Sentinel, or import the CSV as a watchlist.

## Schemas

### Malicious

| Column | Example |
|---|---|
| `ecosystem` | `npm` |
| `package` / `package_lc` | `node-sass-cli-phenomic-webpack` |
| `repo_hint` | `npm` |
| `mal_id` | `MAL-2025-145531` |
| `source` | `amazon-inspector\|ghsa-malware` |
| `published` / `modified` | `2025-11-12T04:29:11Z` |
| `summary` | `Malicious code in ... (npm)` |

### Vulnerable

| Column | Example |
|---|---|
| `ecosystem` | `PyPI` |
| `package` / `package_lc` | `open-webui` |
| `osv_id` | `GHSA-226f-f24g-524w` |
| `cve` | `CVE-2026-54008` |
| `aliases` | `CVE-2026-54008\|PYSEC-2026-2690` |
| `kev` / `kev_ransomware` | `true` |
| `epss` / `epss_percentile` | `0.94` / `0.99` |
| `cvss_v3` / `cvss_v4` | `CVSS:3.1/AV:N/AC:L/...` |
| `introduced` / `fixed` | `0` / `0.9.6` |
| `summary` | `Open WebUI: Redirect-Bypass SSRF ...` |

Join on `package_lc` in both. One row per `(ecosystem, package, id)`.

## Read this before you alert on it

**The malicious npm data is mostly junk.** 219,321 of the 235,286 malicious
rows are npm, and **144,078 of those come from `source=amazon-inspector`** —
the tea.xyz token-farming spam flood. Those packages are garbage, but they are
not targeted attacks, and treating every hit as an incident will bury you.
`csv/malicious_high_signal.csv` drops them, leaving 91,208 rows.

**Version ranges are flattened.** `introduced` and `fixed` are pipe-separated
lists, so the pairing between an introduced version and its matching fix is
lost. That is enough to answer "is this package affected at all", which is what
a lookup join needs. Confirm the exact version against the upstream record
before acting.

**CVSS is carried as a vector, not a score.** Reimplementing CVSS scoring is a
good way to publish subtly wrong numbers. `kev` and `epss` are better
exploitation signals anyway; parse the vector yourself if you want a base score.

**`cve` is the first CVE alias only.** A handful of advisories carry several;
the full list is in `aliases`.

## `externaldata()` limits and hosting

### Size limit
`externaldata()` supports external artifacts **up to 100 MB**. For larger
datasets, ingest into a table or watchlist instead. The export logs a warning
if any file crosses that line.

### Current sizes
- `csv/malicious_all.csv` — ~42 MB (235,286 rows)
- `csv/malicious_high_signal.csv` — ~16 MB (91,208 rows)
- `csv/vulnerable_all.csv` — ~48k rows
- `csv/vulnerable_exploited.csv` — small

### Why this repo doesn't use GitHub Releases
Files are served via **`raw.githubusercontent.com`** as regular repository
files. Many **GitHub Releases asset URLs redirect**, and `externaldata()`
fetches fail with **"redirects are not allowed"**. So the artifacts stay
committed in the repo (or host them on Azure Blob Storage), not as Release
attachments.

## Local usage

```bash
python osv_export.py
```

No dependencies — standard library only, deliberately: a supply chain data feed
should not itself pull a supply chain.

```bash
python osv_export.py --skip-vulnerable      # malicious only (fast)
python osv_export.py --epss-threshold 0.5   # stricter "exploited" cutoff
```

## Licence and attribution

This tooling is Apache 2.0. See [LICENSE](LICENSE).

The published CSVs are derived works of
[github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages)
(Apache 2.0) and [osv.dev](https://osv.dev) (per-record licences, see upstream).
**Modifications:** OSV JSON records are flattened to CSV rows; version ranges
are collapsed to pipe-separated lists; package names are additionally
lowercased; withdrawn advisories are dropped. No records are added.

Malicious package reports are contributed by Amazon Inspector, Checkmarx,
ReversingLabs, Datadog, OSSF Package Analysis and GitHub Security Advisories,
aggregated by OSSF. KEV data is published by CISA (public domain). EPSS scores
are published by FIRST.

This project is not affiliated with or endorsed by OpenSSF, OSV, CISA or FIRST.
