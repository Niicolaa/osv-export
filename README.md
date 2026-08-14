# osv-export

This repository automatically downloads and republishes data from
[**OSV**](https://osv.dev), the [**OpenSSF malicious-packages**](https://github.com/ossf/malicious-packages)
corpus, [**CISA KEV**](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and [**EPSS**](https://www.first.org/epss/), converted to CSV.

It stores the **CSV-converted** datasets in `csv/`, split into a *packages*
side (what you match on) and an *advisories* side (what you enrich with),
joined on the advisory id:

| File | Rows | Size | |
|---|---|---|---|
| `csv/malicious_packages.csv` | 235,308 | 20 MB | package, ecosystem, affected versions |
| `csv/malicious_advisories.csv` | 235,309 | 29 MB | reporter, dates, summary |
| `csv/vulnerable_packages.csv` | 57,740 | 26 MB | package, ecosystem, version ranges |
| `csv/vulnerable_advisories.csv` | 46,364 | 12 MB | CVE, KEV, EPSS, CVSS, summary |

Fetch only the side you need, or fetch both and join. A GitHub Actions workflow
runs **daily** to update the data automatically.

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

## Match on versions, not just names

**This is the whole point.** In September 2025 `chalk` was hijacked — but only
version **5.6.1**. `chalk` is one of the most-downloaded packages on npm, so a
name-only match flags every install your organisation has ever done. A version
match flags the compromise.

```
chalk            all_versions=false   versions=|5.6.1|
debug            all_versions=false   versions=|4.4.2|
ansi-styles      all_versions=false   versions=|6.2.2|
@ctrl/tinycolor  all_versions=false   versions=|4.1.2|4.1.1|
```

Three fields carry this:

- **`all_versions`** — `true` when the advisory covers the package from version
  0 with no fix, i.e. *any* version is a match. The normal case for
  purpose-built malicious packages (205,041 of 219,341 npm rows).
- **`versions`** — explicit affected versions, pipe-delimited *and
  pipe-padded*: `|5.6.1|`. The padding is deliberate: it lets you test
  membership with a substring match without `1.0.1` also matching `1.0.10`.
- **`introduced` / `fixed`** — range bounds, for advisories that express ranges
  instead of enumerating versions.

### Matching in Kusto

Split the field at query time rather than downloading a pre-exploded one — the
exploded form is 2.66M rows and ~130 MB, and `mv-expand` costs nothing:

```kusto
let MaliciousPackages =
externaldata (
  ecosystem:string, package:string, package_lc:string, repo_hint:string,
  mal_id:string, all_versions:string, versions:string
)
[
  @"https://raw.githubusercontent.com/Niicolaa/osv-export/main/csv/malicious_packages.csv"
]
with (format="csv", ignoreFirstRecord=true);
MyPackagePulls
| join kind=inner MaliciousPackages on $left.name == $right.package_lc
| where all_versions == "true"                       // whole package is bad
     or versions has strcat("|", my_version, "|")    // or this exact version
```

To enrich the hits — who reported it, when, and what it does — fetch the
advisory side and join on `mal_id`. Do it *after* the match, so the prose is
only carried for rows you kept:

```kusto
let MaliciousAdvisories =
externaldata (
  mal_id:string, source:string, published:string, modified:string, summary:string
)
[
  @"https://raw.githubusercontent.com/Niicolaa/osv-export/main/csv/malicious_advisories.csv"
]
with (format="csv", ignoreFirstRecord=true);
Hits
| join kind=leftouter MaliciousAdvisories on mal_id
| where source has_any ("checkmarx", "reversing-labs", "ghsa-malware")
```

Vulnerabilities work the same way, joining `vulnerable_packages` to
`vulnerable_advisories` on `osv_id`:

```kusto
VulnerablePackages
| join kind=inner MyPackagePulls on $left.package_lc == $right.name
| where versions has strcat("|", my_version, "|")
| join kind=leftouter VulnerableAdvisories on osv_id
| where kev == "true" or toreal(epss) >= 0.1     // actually exploited
```

> **Note:** Microsoft Defender XDR advanced hunting does not support
> `externaldata()`. Use ADX or Sentinel, or import the CSV as a watchlist.

## Schemas

**`malicious_packages`** — `ecosystem`, `package`, `package_lc`, `repo_hint`,
`mal_id`, `all_versions`, `versions`

**`malicious_advisories`** — `mal_id`, `source`, `published`, `modified`,
`summary`

**`vulnerable_packages`** — `ecosystem`, `package`, `package_lc`, `repo_hint`,
`osv_id`, `all_versions`, `introduced`, `fixed`, `versions`

**`vulnerable_advisories`** — `osv_id`, `cve`, `aliases`, `kev`,
`kev_ransomware`, `epss`, `epss_percentile`, `cvss_v3`, `cvss_v4`,
`published`, `modified`, `summary`

Join on `package_lc`. One package row per `(ecosystem, package, advisory id)`.

## Read this before you alert on it

**Most of the malicious npm data is junk.** Of 235,308 malicious package rows,
219,341 are npm, and **144,078 come from `source=amazon-inspector`** — the
tea.xyz token-farming spam flood. Those packages are garbage, but they are not
targeted attacks. Filter them out on the advisory side:

```kusto
| where source != "amazon-inspector"    // leaves ~91k rows
```

The reporters worth alerting on are `checkmarx`, `reversing-labs` and
`ghsa-malware` — the September 2025 npm compromises all came in via
`ghsa-malware`.

**Version coverage is uneven, and npm is the weak spot — for vulnerabilities.**
Some ecosystems enumerate affected versions; others publish only SEMVER ranges:

| Ecosystem | Vulnerable rows | With explicit `versions` |
|---|---|---|
| NuGet | 4,993 | 4,834 (97 %) |
| RubyGems | 1,128 | 1,098 (97 %) |
| PyPI | 13,785 | 13,264 (96 %) |
| Packagist | 7,087 | 6,395 (90 %) |
| Maven | 8,256 | 7,323 (89 %) |
| **npm** | 7,387 | **269 (4 %)** |
| **crates.io** | 3,182 | **51 (2 %)** |
| **Go** | 11,162 | **100 (1 %)** |

For those three, compare against `introduced` / `fixed` instead.
`parse_version()` handles at most four numeric parts and does not understand
pre-release tags like `1.8.0-rc.0`:

```kusto
| mv-expand fixed_one = split(fixed, "|") to typeof(string)
| where isnotempty(fixed_one) and parse_version(my_version) < parse_version(fixed_one)
```

This table is about the **vulnerability** data only. The *malicious* data is
the opposite: npm dominates it, and 22,035 npm rows carry explicit versions —
which are exactly the hijacked-legitimate-package cases like `chalk`.

**Version ranges are flattened.** `introduced` and `fixed` are pipe-separated
lists, so when an advisory has several ranges the pairing between an introduced
version and its matching fix is lost.

**CVSS is carried as a vector, not a score.** Reimplementing CVSS scoring is a
good way to publish subtly wrong numbers. `kev` and `epss` are better
exploitation signals anyway; parse the vector yourself if you want a base score.

**`cve` is the first CVE alias only.** A handful of advisories carry several;
the full list is in `aliases`.

## `externaldata()` limits and hosting

`externaldata()` supports external artifacts **up to 100 MB**. For larger
datasets, ingest into a table or watchlist instead. The export logs a warning
if any file crosses that line — the largest here is 29 MB.

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
should not itself pull a supply chain. A full run takes about 80 seconds and
downloads ~300 MB.

```bash
python osv_export.py --skip-vulnerable   # malicious only (fast)
python osv_export.py --base-dir ./
```

## Licence and attribution

This tooling is Apache 2.0. See [LICENSE](LICENSE).

The published CSVs are derived works of
[github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages)
(Apache 2.0) and [osv.dev](https://osv.dev) (per-record licences, see upstream).
**Modifications:** OSV JSON records are flattened to CSV rows and split across
a package and an advisory file; version ranges are collapsed to pipe-separated
lists; package names are additionally lowercased; withdrawn advisories are
dropped. No records are added.

Malicious package reports are contributed by Amazon Inspector, Checkmarx,
ReversingLabs, Datadog, OSSF Package Analysis and GitHub Security Advisories,
aggregated by OSSF. KEV data is published by CISA (public domain). EPSS scores
are published by FIRST.

This project is not affiliated with or endorsed by OpenSSF, OSV, CISA or FIRST.
