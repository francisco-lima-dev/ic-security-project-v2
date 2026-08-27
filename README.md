# IC Security Project — SAST vs. DAST on JavaScript/TypeScript

Static analysis (SAST) pipeline over the **OpenSSF CVE Benchmark**, built to be
compared against dynamic analysis (DAST) results in an undergraduate research
project.

Each of the benchmark's **223 CVEs** is analyzed at its *vulnerable commit* by
three tools — **CodeQL**, **Semgrep** and **Snyk Code** — and the findings are
normalized into a common schema so detection metrics can be computed (true
positives, false negatives, coverage per CWE).

> **Status:** Stage 1 complete (project structure + input lists).
> Stage 2 (Docker images and analysis scripts) and stage 3 (execution and
> post-processing) are not implemented yet.

---

## Core concept: the unit is the CVE, not the repository

This is the decision that shapes everything else in the pipeline.

The 223 CVEs point to only **186 distinct repositories**. The same repo shows up
across several CVEs, always at **different commits**:

| Repository | CVEs |
|---|---:|
| `twbs/bootstrap` | 7 |
| `lodash/lodash` | 5 |
| `jquery/jquery` | 4 |
| `GoogleChrome/rendertron` | 4 |
| `zeit/next.js`, `tnantoka/public`, `markedjs/marked` | 3 each |

Deduplicating by repository would destroy the experiment: `CVE-2018-14040` and
`CVE-2018-14041` are both bootstrap, but at distinct commits (`13bf8aea…` and
`14909601…`) and in different files (`js/collapse.js` vs. `js/src/scrollspy.js`).
They are two independent analyses.

Practical consequences, binding for stages 2 and 3:

- every output (raw and treated) is named by **CVE**, never by repository;
- each analysis checks out the `PrePatchCommit` — the **vulnerable** commit;
- two CVEs from the same repo must not share a clone directory or a CodeQL
  database.

---

## Prerequisites

- **Node.js** ≥ 24 — the scripts use only the stdlib, no dependencies: there is
  no `package.json` and no `npm install`. Developed on **v26.4.0**.
- **git**
- From stage 2 onward: Docker, and Snyk Code credentials

> **Why 24 and not lower.** The Node lines still in support are 22, 24 and 26 —
> 18 went end-of-life in April 2025 and 20 in April 2026. Line 24 is Active LTS
> until April 2028, comfortably covering the project's horizon, and it is the
> same line as the `node:24-bookworm` used by the CodeQL image in stage 2 — so
> the local environment and the container do not drift apart.

### Cloning the benchmark (external dependency)

The benchmark clone is **not versioned** in this repository (it is in
`.gitignore`): it is third-party content, heavy, and reproducible. Clone it at
the project root before running any script:

```bash
git clone https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git
```

Reference used during development — worth pinning this commit if you need to
reproduce the numbers exactly:

```
91c59fd54b2b768c0f310bb0027d2ac59cdf74d4  (2023-11-29)
```

Only the `ossf-cve-benchmark/CVEs/` directory is read (223 JSON files). No
application source code is cloned at this stage.

---

## Project structure

```
.
├── datasets/
│   ├── cve-metadata.csv           # 223 CVEs, 8 columns (VERSIONED)
│   ├── cve-metadata.json          # same data, full structure
│   └── listas/                    # pipeline input (VERSIONED)
│       ├── cves-sast.txt          # full list — 223 lines
│       ├── cves-sast-teste        # smoke test — 5 CVEs
│       └── cves-sast-batch-aa..ah # sliced execution — 30 lines/batch
├── tools/
│   ├── extract-urls.js            # benchmark JSON → cve-metadata.{csv,json}
│   └── generate-lists.js          # cve-metadata.csv → listas/
├── ic-security-lab-codeql/        # image + scripts    (stage 2)
├── ic-security-lab-semgrep/       # image + scripts    (stage 2)
├── ic-security-lab-snyk-code/     # image + scripts    (stage 2)
├── results/
│   ├── codeql/{raw,treated}/      # raw ignored · treated versioned
│   ├── semgrep/{raw,treated}/
│   └── snyk-code/{raw,treated}/
├── logs/                          # execution-log-*.csv (VERSIONED)
├── ossf-cve-benchmark/            # external clone (IGNORED)
├── .gitignore
└── README.md
```

> Directory and file names are kept in Portuguese (`listas/`, `cves-sast-teste`)
> because they are referenced by generated data and by the scripts. Renaming
> them is a deliberate change, not a translation detail.

### Versioning policy

| Path | Git | Why |
|---|:---:|---|
| `datasets/**` | ✅ | the experiment's input; must be citable and stable |
| `tools/**` | ✅ | reproducibility — this is what generates the lists |
| `results/*/treated/**` | ✅ | common schema, small, this is the research output |
| `logs/**` | ✅ | duration, exit code and tool version per CVE |
| `results/*/raw/**` | ❌ | raw SARIF/JSON, large and regenerable |
| `ossf-cve-benchmark/` | ❌ | external dependency, not our content |
| `src-CVE-*/`, `codeql-db-*/` | ❌ | temporary clones and databases |

The order inside `.gitignore` matters: the generic ignores (`node_modules/`,
`.env`) come **after** the `!datasets/**`, `!tools/**` exceptions precisely so
they take precedence over them — that way a stray `datasets/node_modules/` or
`tools/.env` still stays out of the repository.

---

## Regenerating everything from scratch

```bash
# 1. clone the benchmark (see above)
git clone https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git

# 2. benchmark JSON → datasets/cve-metadata.{csv,json}
node tools/extract-urls.js

# 3. cve-metadata.csv → datasets/listas/
node tools/generate-lists.js --force
```

> **`--force` is required from the second run onward.** Regenerating deletes the
> old batches (otherwise a smaller dataset would leave orphan batches behind),
> and since those files are versioned the deletion is made explicit. Without the
> flag, the generator lists what it would remove and aborts **without writing
> anything**:
>
> ```
> ❌ Já existem 8 batch(es) em datasets/listas/ — nada foi escrito
>    • seria removido: datasets/listas/cves-sast-batch-aa
>    ...
>    • Confirme com:  node tools/generate-lists.js --force
> ```
>
> `--force` does **not** bypass the validations: if the CSV is corrupted,
> validation aborts before any deletion and the batches stay intact.

`generate-lists.js` exit codes: `0` success · `1` validation failure or batch
guard · `2` unknown argument.

> The scripts' console output and code comments are in Portuguese; only this
> README is in English.

---

## List format

Every line of `cves-sast.txt`, of the batches and of `cves-sast-teste` has
**6 comma-separated fields**:

```
CVE,URL,COMMIT,CWES,FILEPATH,FILELINE
```

| Field | Description |
|---|---|
| `CVE` | identifier, unique across the file |
| `URL` | repository clone URL (`https://…​.git`) |
| `COMMIT` | **PrePatchCommit** — vulnerable commit, 40 hex chars |
| `CWES` | CWEs separated by `\|`, normalized to 3 digits; may be empty |
| `FILEPATH` | vulnerable file according to the benchmark (*ground truth*) |
| `FILELINE` | vulnerable line(s), separated by `\|` — multi-valued for 3 CVEs |

Example (`cves-sast-teste` in full):

```
CVE-2018-14040,https://github.com/twbs/bootstrap.git,13bf8aeae3db71e28af69782328c22215795c169,CWE-079|CWE-116,js/collapse.js,140
CVE-2018-14041,https://github.com/twbs/bootstrap.git,149096016f70fd815540d62c0989fd99cdc809e0,CWE-079|CWE-116,js/src/scrollspy.js,118
CVE-2019-10744,https://github.com/lodash/lodash.git,1f8ea07746963a535385a5befc19fa687a627d2b,CWE-094|CWE-079|CWE-116,lodash.js,6608
CVE-2016-1000229,https://github.com/linxiaowu66/swagger-ui.git,14fad2b4c76efe249db515c98432eb609aa77691,CWE-079|CWE-116,src/main/javascript/helpers/handlebars.js,68
CVE-2017-16042,https://github.com/tj/node-growl.git,dc8aae046df328edd32dd69f3cd2d6b114d7018e,CWE-078|CWE-088,lib/growl.js,289
```

Reading it in bash:

```bash
while IFS=, read -r CVE URL COMMIT CWES FILEPATH FILELINE; do
  echo "$CVE → $URL @ ${COMMIT:0:8}"
done < datasets/listas/cves-sast-teste
```

Every file ends with a **trailing newline** — without it `while read` silently
drops the last line (which would lose 1 CVE per batch, 8 in total).

### Why `|` instead of `,` in CWES and FILELINE

The original CSV carries `"CWE-079, CWE-116"` — a comma inside a quoted field.
Switching to `|` keeps the line splittable on commas with no parser at all,
which is what the bash scripts in stages 2 and 3 need. The generator validates
that neither `URL` nor `FILEPATH` contains a comma, guaranteeing the 6 fields
never drift out of alignment.

`FILELINE` uses the same separator for the same reason — see note 6 below on
the CVEs with several locations. In bash,
`IFS='|' read -ra LINES <<< "$FILELINE"` handles both cases.

### Why CWEs are normalized to 3 digits

The benchmark mixes both forms: `CWE-79` and `CWE-079` coexist, as do
`CWE-20`/`CWE-020`, `CWE-22`/`CWE-022` and `CWE-94`/`CWE-094`. Without
normalizing, any aggregation per CWE would count the same weakness class twice.
After normalizing, **38 distinct CWEs** remain (they were 42 textual forms).

---

## Batches

`cves-sast.txt` is sliced into **8 batches of at most 30 lines** — seven with 30
and the last one (`ah`) with 13. The batches are plain sequential slices:

```bash
cat datasets/listas/cves-sast-batch-* | diff - datasets/listas/cves-sast.txt   # empty
```

They exist so the pipeline can run in chunks (resume after a failure,
parallelize across machines, fit inside CI time limits) without losing
traceability.

### Test batch

`cves-sast-teste` holds 5 CVEs picked to exercise the pipeline's known pitfalls
before spending hours on the full run:

| CVE | Repo | What it validates |
|---|---|---|
| `CVE-2018-14040` | twbs/bootstrap | same repo as the next one, **different commit** |
| `CVE-2018-14041` | twbs/bootstrap | the two outputs must come out separate |
| `CVE-2019-10744` | lodash/lodash | large repo — measures the shallow-fetch gain |
| `CVE-2016-1000229` | linxiaowu66/swagger-ui | end of the name collision (see below) |
| `CVE-2017-16042` | tj/node-growl | small repo, old CVE |

---

## Generator validations

`generate-lists.js` aborts with **exit 1 and no file written** if any of these
fails. That is deliberate: better to generate no list at all than to run 223
analyses over a silently corrupted one.

- CSV header exactly as expected (8 columns)
- exactly **223 records** read
- every `PrePatchCommit` is 40 `[0-9a-f]` chars
- no duplicate CVE (reported with the line number of the first occurrence)
- every CWE is `CWE-` + 3 digits after normalization
- `FILEPATH` **non-empty** — it is stage 3's location *ground truth*; empty means
  `extract-urls.js` silently degraded a missing `location.file`, and the CVE
  would become a guaranteed false negative in the metrics
- `FILELINE` is numeric lines separated by `|`, without repetition, **or empty** —
  the asymmetry with `FILEPATH` is intentional: without the line you can still
  match findings per file
- `Repository` and `FilePath` contain no comma (that would break the 6-field
  format)
- the 5 test-batch CVEs are present in the CSV

At the end it prints: total lines, CVEs without CWE, total locations,
multi-location CVEs, distinct CWEs, distinct repositories, number of batches,
per-batch distribution and the most frequent CWEs.

---

## Data quality notes

Surveyed during stage 1. None of these blocks the SAST pipeline, but all of them
affect how the results should be read.

### 1. Two broken `PostPatchCommit` values **in the original benchmark**

Investigated and confirmed: the defect is in OpenSSF's own JSON files, it was
**not** introduced by `extract-urls.js` (which copies the field verbatim).

| CVE | Repo | Value in the JSON | Problem |
|---|---|---|---|
| `CVE-2017-18352` | GoogleChrome/rendertron | `324ac99732c943d7b16aead2fceaa8b31a458e` | 38 chars (2 missing) |
| `CVE-2018-11093` | ckeditor/ckeditor5-link | `8cb782e` | abbreviated hash, 7 chars |

Both `prePatch` values are intact (40 chars), and the SAST pipeline only ever
checks those out — **no analysis is affected**. That is why the generator treats
this as a **non-blocking warning**, not an error:

```
⚠️  AVISO (não-bloqueante): 2 PostPatchCommit fora do padrão de 40 hex
   • CVE-2017-18352: "324ac99732c943d7b16aead2fceaa8b31a458e" (38 chars)
   • CVE-2018-11093: "8cb782e" (7 chars)
```

If a future stage uses `PostPatchCommit` (diff analysis, false-positive
measurement on patched code), these two will need to be resolved by hand —
`8cb782e` will most likely resolve via `git rev-parse` in the cloned repo.

### 2. One CVE without a CWE

`CVE-2018-1000096` (`brianleroux/tiny-json-http`) has an empty `CWEs` field in
the benchmark. **It is analyzed normally** — it just enters the list with an
empty `CWES` field. It is excluded only from the per-CWE metrics, in stage 3.

### 3. Unescaped quotes in the CSV — fixed

`extract-urls.js` used to wrap fields in quotes without escaping inner quotes.
The 7 CVEs whose explanation cites `"Zip Slip"` came out as malformed CSV, and
any strict parser (Excel, `pandas`, Python's `csv`) **misaligned the following
columns** (`FilePath`, `FileLine`) on those rows:

```
..."Arbitrary file write during zip extraction ("Zip Slip")",...
```

It affected `CVE-2018-1002203`, `CVE-2018-1002204`, `CVE-2018-20834`,
`CVE-2018-20835`, `CVE-2019-13173`, `CVE-2019-5484`, `CVE-2020-12265`.

Fixed with RFC 4180 escaping (inner quote → doubled quote), applied to every
quoted field. `cve-metadata.json` did not change (the bug was only in the CSV
serialization) and the generated lists stayed byte-identical — the parser in
`generate-lists.js` was already tolerant of that breakage and keeps that
tolerance as defense in depth, for an old CSV or one produced by another tool.

### 4. Name collision: two `swagger-ui`

`CVE-2016-1000229` points to **`linxiaowu66/swagger-ui`** and `CVE-2019-17495`
to **`swagger-api/swagger-ui`**. They are different repositories sharing a
basename. Naming directories or outputs after the repo basename would make one
overwrite the other — one more reason to name everything by CVE.

### 5. Dataset distribution

Useful when interpreting the metrics: the benchmark is heavily skewed toward XSS
and injection, so aggregate coverage hides a lot of per-class variation.

| CWE | CVEs | | Year | CVEs |
|---|---:|---|---|---:|
| CWE-079 (XSS) | 83 | | 2016 | 2 |
| CWE-116 (encoding) | 63 | | 2017 | 47 |
| CWE-400 (resource DoS) | 50 | | 2018 | 69 |
| CWE-078 (OS command inj.) | 48 | | 2019 | 60 |
| CWE-094 (code injection) | 37 | | 2020 | 42 |
| CWE-730, CWE-022 | 29 each | | 2021 | 3 |

The CWEs add up to more than 223 because a CVE can carry several
(`CVE-2019-10744` has three). All 223 CVEs have `FILEPATH` and `FILELINE`
filled in, which gives location *ground truth* for scoring per line, not just
per file.

### 6. Three CVEs with multiple locations

The 223 CVEs add up to **233 *weaknesses***: 220 have exactly one, and three
have several.

| CVE | Locations | File | Generated `FILELINE` |
|---|---:|---|---|
| `CVE-2018-3725` | 5 | `bin/hekto.js` | `116\|138\|141\|152\|194` |
| `CVE-2021-23364` | 6 | `index.js` | `802\|827\|855\|890\|921\|925` |
| `CVE-2021-31712` | 2 | `src/decorators/Link/index.js` | `35\|59` |

In all three cases these are **multiple manifestation points of the same
vulnerability**, not distinct vulnerabilities: same file, byte-identical
`explanation` across the weaknesses, and a single CWE set. The benchmark schema
confirms it — `Weakness` has `additionalProperties: false` and only `location` +
`explanation`; the CWEs live at CVE level, described as *"the relevant CWEs for
the weaknesses"* (plural, shared).

That is why `FILELINE` is multi-valued while `FILEPATH` stays scalar.
`extract-urls.js` **validates** that all weaknesses of a CVE sit in the same
file and **aborts** if that ever stops holding, instead of silently discarding
the locations in the other files.

Impact on stage 3 metrics: the benchmark's own criterion
(`docs/benchmark-CVEs.md`) is *"the ideal analysis tool produces **at least one**
relevant alert on the prePatch commit"* — that is, it scores per CVE detected,
not per location covered. Preserving the 10 extra lines does not change the
primary metric; it changes a secondary location-precision metric, where a hit on
browserslist line 855 used to count as a false negative for not being line 802.

---

## Next stages

**Stage 2 — images and analysis scripts.** A `Dockerfile` and a runner script
per tool under `ic-security-lab-{codeql,semgrep,snyk-code}/`, consuming the
lists in `datasets/listas/`. Points of attention already mapped out: shallow
clone at the exact commit (`fetch --depth 1 origin <sha>`), directory and
database named by CVE, raw output at `results/<tool>/raw/<CVE>.<ext>`, and a
`logs/execution-log-*.csv` carrying CVE, tool, duration, exit code and version.

**Stage 3 — post-processing and metrics.** Normalization of SARIF/JSON into the
common schema under `results/*/treated/`, cross-referencing with the *ground
truth* (`FILEPATH`/`FILELINE`), and computing the metrics per tool and per CWE —
excluding `CVE-2018-1000096` from the per-CWE aggregations.
