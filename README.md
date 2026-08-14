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
  - `csv/versions/<ecosystem>.csv` — one row per *affected version*, for exact
    `(package, version)` joins

Rows carry an `ecosystem` from the advisory itself, so a few entries appear
under an ecosystem other than the archive they came from (a Go advisory that
also names a GitHub Actions package, for example).

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
  mal_id:string, source:string, all_versions:string, versions:string,
  published:string, modified:string, summary:string
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
  cvss_v3:string, cvss_v4:string,
  all_versions:string, introduced:string, fixed:string, versions:string,
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
| `all_versions` | `true` (any version is malicious) |
| `versions` | `\|1.0.0\|1.0.1\|` (empty when `all_versions`) |
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
| `all_versions` | `false` |
| `introduced` / `fixed` | `0` / `0.9.6` |
| `versions` | `\|0.13.0\|0.14.0\|` |
| `summary` | `Open WebUI: Redirect-Bypass SSRF ...` |

Join on `package_lc` in both. One row per `(ecosystem, package, id)`.

## Matching on versions

Matching on package name alone is noisy: `lodash` appears in the vulnerability
data, but only some versions were ever affected, so a name-only join flags
every `lodash` your organisation has ever pulled.

Three fields support version matching:

- `all_versions` — `true` when the advisory covers the package from version 0
  with no fix, i.e. **any** version matches. This is the normal case for
  malicious packages (211,487 of 235,306 rows).
- `versions` — explicit affected versions, pipe-delimited *and pipe-padded*:
  `|1.0.0|1.0.1|`. The padding lets you test membership with a plain substring
  match without `1.0.1` also matching `1.0.10`.
- `introduced` / `fixed` — range bounds, for advisories that express ranges
  rather than enumerating versions.

### Coverage is uneven, and npm is the weak spot

Some ecosystems enumerate affected versions; others only publish SEMVER ranges.

| Ecosystem | Rows | With explicit `versions` |
|---|---|---|
| NuGet | 4,993 | 4,834 (97 %) |
| PyPI | 13,785 | 13,264 (96 %) |
| RubyGems | 1,128 | 1,098 (97 %) |
| Packagist | 7,087 | 6,395 (90 %) |
| Maven | 8,256 | 7,323 (89 %) |
| **npm** | 7,387 | **269 (4 %)** |
| **crates.io** | 3,182 | **51 (2 %)** |
| **Go** | 11,162 | **100 (1 %)** |

For npm, Go and crates.io you have to compare against `introduced` / `fixed`.
There is no way around this short of enumerating every published version of
every package from each registry, which this project does not attempt.

### Exact match, where versions are enumerated

`csv/versions/<ecosystem>.csv` holds one row per affected version
(`package_lc`, `version`, `osv_id`). Join your inventory on both columns, then
join back to `vulnerable_all.csv` on `osv_id` for CVE / KEV / EPSS:

```kusto
let AffectedVersions =
externaldata (package_lc:string, version:string, osv_id:string)
[
  @"https://raw.githubusercontent.com/Niicolaa/osv-export/main/csv/versions/pypi.csv"
]
with (format="csv", ignoreFirstRecord=true);
MyPackagePulls
| join kind=inner AffectedVersions on $left.name == $right.package_lc,
                                      $left.version == $right.version
```

### Range match, for npm / Go / crates.io

`parse_version()` turns a dotted version into something comparable. Note it
handles at most four numeric parts and does not understand pre-release tags
(`1.8.0-rc.0`), so strip or exclude those:

```kusto
Vulnerable
| where ecosystem == "npm"
| mv-expand fixed_one = split(fixed, "|") to typeof(string)
| where isnotempty(fixed_one)
| join kind=inner MyPackagePulls on $left.package_lc == $right.name
| where parse_version(version) < parse_version(fixed_one)
```

### Malicious packages barely need this

211,487 of 235,306 malicious rows have `all_versions = true` — the package is
malicious in its entirety, so any version is a hit. Version matching is not
what reduces noise there; filtering on `source` is (see below).

## Read this before you alert on it

**The malicious npm data is mostly junk.** Of the 235,306 malicious rows,
219,321 are npm, and **144,078 come from `source=amazon-inspector`** — the
tea.xyz token-farming spam flood. Those packages are garbage, but they are not
targeted attacks, and treating every hit as an incident will bury you.
`csv/malicious_high_signal.csv` drops them, leaving 91,207 rows.

**Version ranges are flattened.** `introduced` and `fixed` are pipe-separated
lists, so the pairing between an introduced version and its matching fix is
lost when an advisory has several ranges. Use `csv/versions/` for exact
matching where it is available (see below), and treat `introduced`/`fixed` as
a range check otherwise.

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
- `csv/malicious_all.csv` — ~45 MB (235,306 rows)
- `csv/malicious_high_signal.csv` — ~17 MB (91,207 rows)
- `csv/vulnerable_all.csv` — ~39 MB (57,740 rows)
- `csv/vulnerable_exploited.csv` — ~1.5 MB (2,251 rows: 296 in KEV, 71 of those
  linked to ransomware campaigns; the rest EPSS ≥ 0.1)
- `csv/versions/*.csv` — 2.66M rows total, largest `pypi.csv` at ~48 MB

The exploded version files are split per ecosystem precisely because the
combined form would be ~170 MB, well past what `externaldata()` will read.

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
