# IC Security Project — SAST vs. DAST on JavaScript/TypeScript

Static analysis (SAST) pipeline over the **OpenSSF CVE Benchmark**, built to be
compared against dynamic analysis (DAST) results in an undergraduate research
project.

Each of the benchmark's **223 CVEs** is analyzed at its *vulnerable commit* by
three tools — **CodeQL**, **Semgrep** and **Snyk Code** — and the findings are
normalized into a common schema so detection metrics can be computed (true
positives, false negatives, coverage per CWE).

> **Status:** Stage 1 complete (project structure + input lists).
> Stage 2 (Docker images, analysis scripts and the normalizer) is **decided but
> not implemented** — the tool configuration is locked and documented under
> [Tool configuration](#tool-configuration--stage-2-decisions). Stage 3
> (workflows, execution and metrics) has not started.

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
├── docs/
│   └── metodologia-V7.md          # experimental protocol (VERSIONED)
├── tools/
│   ├── extract-urls.js            # benchmark JSON → cve-metadata.{csv,json}
│   ├── generate-lists.js          # cve-metadata.csv → listas/
│   ├── normalize.py               # raw → common schema      (stage 2, pending)
│   └── semgrep-packs/             # vendored p/default snapshot (stage 2)
├── .claude/
│   └── agents/
│       └── revisor-pipeline.md    # review subagent (VERSIONED)
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
| `tools/semgrep-packs/**` | ✅ | the exact ruleset that ran — pinned by sha256 |
| `.claude/agents/**` | ✅ | the review checklist is part of the method |
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

## Tool configuration — stage 2 decisions

Every choice below was measured against the **previous campaign's archived
results** (37 CodeQL SARIF, 185 Semgrep JSON, 182 Snyk SARIF) rather than picked
from documentation. Two initial hypotheses were tested and dropped; both are
recorded here, because the reason they failed is itself a finding.

> **Nothing in this section is implemented yet.** It is the contract stage 2 has
> to satisfy.

### Architecture: normalization runs outside the containers

The containers produce **raw output only**. Converting SARIF/JSON into the common
schema is a separate step — a single `tools/normalize.py`, run locally over the
raw files downloaded from the CI artifacts.

Normalization is the code most likely to need fixing (three formats, CWE
extraction, path normalization). Kept separate, a bug costs seconds of local
re-parsing; embedded in the images, it would cost re-running every clone and
every analysis. Consequences: the normalizer is **not** in any image; the
analysis loop's idempotence check looks for the **raw** file; `normalize.py` has
its own idempotence plus an `--overwrite` flag.

### CodeQL

**Suite: `javascript-security-extended.qls`** — the previous campaign used
`javascript-security-and-quality.qls`, and **908 of its 1 969 findings (46.1 %)**
came from rules carrying no CWE at all: `js/unused-local-variable` (534),
`js/use-before-declaration` (259), `js/regex/duplicate-in-character-class` (35).
Those are not vulnerability claims. Counting them as false positives would
measure the choice of suite, not the tool's precision. The switch is clean
subtraction — `security-and-quality` runs everything `security-extended` runs
plus maintainability queries, so no security query is lost.

Three format facts that the normalizer has to honour:

- **Severity is absent from the finding.** `level` appears on **0 of 1 969**
  results; it only exists on the rule, at `defaultConfiguration.level`. The rule
  is resolved **by `ruleId`, not by `ruleIndex`** — index resolution happens to
  work here (0 invalid indices, 0 `rule.toolComponent` references, extensions
  carry no rules) but breaks the moment a query pack ships rules in an extension.
  The normalizer reports how many findings ended with no severity resolved.
- **`security-severity` is present iff the rule is tagged `security`** — verified:
  all **100** security-tagged rules carry it, and the 18 rules that have a CWE
  tag but no score (`js/useless-assignment-to-local`, `js/trivial-conditional`, …)
  have no `security` tag. Under `security-extended` its coverage is therefore
  complete. It is **not** the base for `severity_normalized` — it is a CVSS-style
  *impact* score, on a different axis from `level` (the same 7.5 shows up as
  `warning` 48× and as `error` 13×), and neither of the other two tools has a
  counterpart. It is captured as a separate CodeQL-only nullable numeric field,
  parsed as float: the raw value is a string with inconsistent decimals (`5` and
  `5.0` both occur).
- **`endLine` is absent from 96.7 %** of findings (present on 65 of 1 969), so
  `line_end` must accept null.

### Semgrep

**Config: `p/default`, vendored and pinned by sha256, mounted at the container's
filesystem root.**

The previous campaign used `--config=auto`. Measurement shows `auto` resolved to
exactly `p/default` — it accounts for **145 of 145** distinct rules and **19 174
of 19 174** findings. The reason to abandon `auto` is reproducibility alone: it
is unpinnable and cannot even be described in the monograph.

The intuitive alternative, `p/javascript` + `p/security-audit`, was measured and
**rejected**:

| Config | Rules matched | Findings covered | CVE×CWE pairs |
|---|---|---|---|
| `p/javascript` (= `p/typescript`) | 24 / 54 | 228 / 4 062 (5.6 %) | 218 / 486 (45 %) |
| `p/javascript` + `p/security-audit` | 28 / 54 | 322 / 4 062 (7.9 %) | 281 / 486 (58 %) |
| `p/owasp-top-ten` | 22 / 54 | 198 / 4 062 (4.9 %) | — |
| **`p/default`** | **54 / 54** | **4 062 / 4 062 (100 %)** | **354 / 486 (73 %)** |

`p/javascript` is organised by *framework*, not by language: of its 74 rules, 31
are `javascript.express.*` and only **3** are `javascript.lang.security.*`
(`p/default` has 24). It therefore misses the highest-volume rules in the
benchmark's own CWE families — `path-join-resolve-traversal` (1 847 findings),
`detect-non-literal-regexp` (737), `prototype-pollution-loop` (310),
`unsafe-formatstring` (268). And `p/security-audit` is barely JavaScript at all:
83 Python, 52 Java, 28 Go rules against 17 JS + 3 TS.

Adding `p/javascript` to the union was measured too, and also rejected:
`p/javascript` is a **subset of `p/default` minus a single rule** —
`typescript.react.security.audit.react-unsanitized-property`, which declares
CWE-079 (already covered by 35 other rules) and produced **zero findings** in
19 174. In the other direction `p/default` has 91 JS/TS rules `p/javascript`
lacks.

**No `--exclude-rule`.** A single HTML rule,
`html.security.audit.missing-integrity`, produced **10 826 findings — 56.5 % of
the whole campaign**, and `html.*` as a family accounts for 67.5 % against 20.7 %
for `javascript.*`/`typescript.*`. That imbalance is *a result of the study* —
direct material for the discussion of precision and triage effort — so it is
measured, not discarded at collection time. The `html.*`/`yaml.*` noise is
handled in stage 3.

Execution flags and their reasons:

- **`--metrics=off`** — the default is `auto`, which per `--help` sends telemetry
  whenever `--config` pulls from the server.
- **`--time`** — records the inventory of rules actually applied at
  `.time.rules[]`, in-band, per CVE. The count goes into the normalized file's
  `metadata`.
- The registry needs **network but not authentication**: every `p/*` returns HTTP
  200 anonymously, and a scan with the vendored pack ran under `--network=none`.
  The `fingerprint` and `lines` fields come back as the literal string
  `"requires login"` regardless of where the config came from — that depends on
  being logged in, not on the config source, and it touches nothing the
  normalizer consumes.
- Snapshot identity: the registry's **ETag is the exact sha1 of the body**, so
  the vendored YAML is pinned by hash and dated for citation.

> **Trap — the vendored pack must be mounted at `/`.** Semgrep prefixes every
> `check_id` with the name of the directory holding the YAML:
> `--config=/packs/default.yaml` yields `packs.javascript.lang.security…`, and
> `--config=/rulesdir/js.yaml` yields `rulesdir.javascript…`. Only a config at the
> filesystem root leaves the IDs identical to the registry's. Get this wrong and
> the rule identifiers drift silently, with no error.

### Snyk Code

**Pinned by versioned URL:** `https://static.snyk.io/cli/v<VERSION>/snyk-linux`.
The previous image pulled `cli/latest`, which has already moved since that
campaign.

The `1.1306.1` reported in the archived SARIF is the **CLI version**, not a
separate SnykCode engine version — `static.snyk.io/cli/v1.1306.1/version` returns
exactly `1.1306.1`, and that pinned binary answers `1.1306.1` to `--version`. The
driver is *named* `SnykCode` but carries the CLI version; **no engine version is
recorded anywhere in the SARIF**, so it must be captured another way if the
monograph needs it.

- **Only `--sarif-file-output`.** The previous script also passed
  `--json-file-output`; the two files are **byte-identical**. There is no native
  Snyk JSON to parse.
- **`runs[0].properties.coverage[]` goes into the normalized `metadata`** — file
  counts per extension are what distinguishes *"analyzed and found nothing"* from
  *"there was nothing analyzable"*, a confusion that occurred in the previous
  campaign.
- **`automationDetails.id`** (`Snyk/Code/<ISO timestamp>`) is the source of
  `analysis_date`, being internal to the report.
- CWEs live on the rule, at `properties.cwe[]`, and Snyk's own vocabulary is
  inconsistent — both `CWE-74` and `CWE-074` occur — which is exactly why the
  3-digit normalization is applied to all three tools.

### Common schema: severity

Two fields. `severity_original` carries the raw value with no transformation;
`severity_normalized` carries the comparable axis.

| `severity_original` | `severity_normalized` |
|---|---|
| CodeQL `error` · Semgrep `ERROR` · Snyk `error` | `high` |
| CodeQL `warning` · Semgrep `WARNING` and `MEDIUM` · Snyk `warning` | `medium` |
| CodeQL `note` · Semgrep `INFO` · Snyk `note` | `low` |
| CodeQL rule with no level | `unknown` |

Any value outside this table **aborts** the normalization, naming the value and
the CVE. No silent default: normalization is cheap to re-run, so failing loudly
costs seconds and a wrong mapping would corrupt the metrics invisibly.

Two notes on the edges of that table:

- **Semgrep's vocabulary is frozen by the pin.** `p/default` declares exactly
  `WARNING` (722), `ERROR` (310), `INFO` (31) and `MEDIUM` (12) — no `HIGH`,
  `LOW` or `CRITICAL`. The `MEDIUM` rules are a recent supply-chain family (11
  `package_managers.*` + 1 `generic.secrets.*`) filling the same `severity:` field
  from a CVSS-style vocabulary; their profile is impact `HIGH` × likelihood
  `LOW`, which sits mid-scale alongside `WARNING`'s centre of gravity. In the
  archived campaign all **137** `MEDIUM` findings were `package_managers.*` —
  entirely inside the noise band stage 3 discards.
- **`unknown` should never fire.** The 74 rules with a null level produced no
  findings: 1 969 of 1 969 resolved. The row stays because the suite change alters
  which rules load — if `unknown` appears, it is a signal to investigate, not an
  expected outcome.

### Pinned versions

| Tool | Pinned | Latest at time of writing |
|---|---|---|
| CodeQL bundle | `codeql-bundle-v2.25.4` | `codeql-bundle-v2.26.4` |
| Semgrep | `1.171.0` (PyPI, and the matching Docker tag) | `1.175.0` |
| Snyk CLI | `1.1306.1` via versioned URL | `1.1307.0` (`latest`/`stable`) |

Pinning is deliberate: the point is that the numbers can be reproduced, not that
the newest tool is used.

---

## Review subagent

`.claude/agents/revisor-pipeline.md` defines a review agent invoked before
committing any shell script, Dockerfile, normalizer or workflow. Its checklist is
derived from the **defects that actually invalidated the previous campaign** —
analysing HEAD instead of the vulnerable commit, `|| true` masking build
failures, `git clone` stderr sent to `/dev/null`, outputs named by repository,
`while read` without the `|| [ -n "$VAR" ]` guard dropping the last line of a
file with no trailing newline.

It is read-only by construction: it reports defects, risks and observations, and
never edits code. It is versioned because the checklist is part of the method,
not a local convenience.

---

## Next stages

**Stage 2 — images, analysis scripts and the normalizer.** A `Dockerfile` and a
runner script per tool under `ic-security-lab-{codeql,semgrep,snyk-code}/`,
consuming the lists in `datasets/listas/`, plus `tools/normalize.py` outside the
images. The tool configuration is settled above; what remains is implementation.
Points of attention already mapped out: shallow clone at the exact commit
(`fetch --depth 1 origin <sha>`), directory and database named by CVE, raw output
at `results/<tool>/raw/<CVE>.<ext>`, and a `logs/execution-log-*.csv` carrying
CVE, tool, duration, exit code and version.

**Stage 3 — workflows, execution and metrics.** GitHub Actions workflows per
tool and per batch, the campaign itself, and then cross-referencing the
normalized results in `results/*/treated/` against the *ground truth*
(`FILEPATH`/`FILELINE`), computing metrics per tool and per CWE — excluding
`CVE-2018-1000096` from the per-CWE aggregations.

Two analysis decisions are already queued for that stage:

- **CWE families.** The benchmark labels path traversal across `CWE-022`,
  `CWE-023`, `CWE-036`, `CWE-073` and `CWE-099`, while Semgrep tags its
  path-traversal rules with only `022`/`073` and CodeQL's `js/path-injection`
  carries all five at once. Scoring per literal CWE would under-count real
  detections; the grouping has to be explicit.
- **Noise segmentation.** The `html.*`/`yaml.*`/`package_managers.*` bands are
  reported separately from `javascript.*`/`typescript.*` rather than deleted, so
  the triage-effort figure survives into the discussion.
