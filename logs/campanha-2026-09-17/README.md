# Campanha SAST de 16–17/09/2026 — registro de execução

Dois agregados e os 24 logs de execução por lote.

## Os 24 logs de execução

`cves-sast-batch-<lote>/execution-log-<ferramenta>.csv` é cópia **byte a
byte** do `logs/execution-log-<ferramenta>.csv` do artifact da execução do
lote, baixado com `gh run download` em 18/09/2026 e conferido com
`cmp`. O formato é o de todo log do projeto,
`cve,repo,commit,status,mensagem,duracao_segundos`.

Versionados em 18/09/2026, depois do cruzamento ter sido escrito e antes de
ele rodar: o `tools/cruza-deteccao.py` deriva deles o status de cada
(CVE, ferramenta), e sem eles um terceiro não reproduziria o cruzamento a
partir do repositório. Os artifacts expiram em 15/12/2026 (`aa`, `ab`) e
16/12/2026 (`ac` a `ah`).

| Lote | Ferramenta | Execução | Artifact | CVEs | sha256 |
|---|---|---|---|---:|---|
| `cves-sast-batch-aa` | codeql | `35106944490` | `lote-cves-sast-batch-aa-codeql-35106944490-1` | 30 | `0acf25f6b1640f93927c9b5eb3f954d94acc26886a77121347ed8769c0d43c7b` |
| `cves-sast-batch-aa` | semgrep | `35106944490` | `lote-cves-sast-batch-aa-semgrep-35106944490-1` | 30 | `622926132072b352fd1ea7443bcfd1b9fcc665e1af6aa8e481b8f98cf5c5ed60` |
| `cves-sast-batch-aa` | snyk-code | `35106944490` | `lote-cves-sast-batch-aa-snyk-code-35106944490-1` | 30 | `227802f2250809c6288880e10059da33e8b9aeaec5aef5b324833ed2d1c26839` |
| `cves-sast-batch-ab` | codeql | `35135927579` | `lote-cves-sast-batch-ab-codeql-35135927579-1` | 30 | `e3fb1848ca432d82a9cf9b857accb017b59bc8acff953bcac052c1fad8e275ce` |
| `cves-sast-batch-ab` | semgrep | `35135927579` | `lote-cves-sast-batch-ab-semgrep-35135927579-1` | 30 | `2b67bcb6adb96effa92cba4c80a3f1a732d7e8e2cc39ba88331680289bfed666` |
| `cves-sast-batch-ab` | snyk-code | `35135927579` | `lote-cves-sast-batch-ab-snyk-code-35135927579-1` | 30 | `dc89f839afd9e42be14e09659317627257de95891c504074ddaede68092d1961` |
| `cves-sast-batch-ac` | codeql | `35169202777` | `lote-cves-sast-batch-ac-codeql-35169202777-1` | 30 | `6cc9bef6430df99c89da08076f8a7374c9299ada0b3295838676b112043e217e` |
| `cves-sast-batch-ac` | semgrep | `35169202777` | `lote-cves-sast-batch-ac-semgrep-35169202777-1` | 30 | `62a087dccbf6502088f15b0c363a2d695272a294d4e1a7410a3612d521b7b87f` |
| `cves-sast-batch-ac` | snyk-code | `35169202777` | `lote-cves-sast-batch-ac-snyk-code-35169202777-1` | 30 | `5ec7d9af32b4afc9171b52778b8d6aad1f98b35ae84931dc2dbe3445829012e4` |
| `cves-sast-batch-ad` | codeql | `35169205115` | `lote-cves-sast-batch-ad-codeql-35169205115-1` | 30 | `9dfee24a5f35d1e585cfa422925cb4ebb5b224e0afed5a2b877687c55520fa3e` |
| `cves-sast-batch-ad` | semgrep | `35169205115` | `lote-cves-sast-batch-ad-semgrep-35169205115-1` | 30 | `c7950a37356092b4b573ab9dd3afdeedfc32acfa24a4af3099b5caf3d1e9697c` |
| `cves-sast-batch-ad` | snyk-code | `35169205115` | `lote-cves-sast-batch-ad-snyk-code-35169205115-1` | 30 | `2619210c3d214178bfecfa6fe0c91a8c9ec669f75823c0eb48b36866fef29f25` |
| `cves-sast-batch-ae` | codeql | `35169207030` | `lote-cves-sast-batch-ae-codeql-35169207030-1` | 30 | `80f03b54a0c4dc140899d11781dbb8f70a6f93196f1c09d073e3de04be32a932` |
| `cves-sast-batch-ae` | semgrep | `35169207030` | `lote-cves-sast-batch-ae-semgrep-35169207030-1` | 30 | `7c41c894756068ab608409eaaa0df2efb4a08dce202b98269f092c368fc21bba` |
| `cves-sast-batch-ae` | snyk-code | `35169207030` | `lote-cves-sast-batch-ae-snyk-code-35169207030-1` | 30 | `b03f24344840e73e30868dd78bca61d02cdb7aabde6767360640258efab650f9` |
| `cves-sast-batch-af` | codeql | `35169209525` | `lote-cves-sast-batch-af-codeql-35169209525-1` | 30 | `1a85c5e734899cd6f0f5168808bb7311353bfdb5a75c15faf03e18f1d7ab3472` |
| `cves-sast-batch-af` | semgrep | `35169209525` | `lote-cves-sast-batch-af-semgrep-35169209525-1` | 30 | `c6c658bda5aa0b79cb2c84a62f03935d5217d0cd19421175212740c930914803` |
| `cves-sast-batch-af` | snyk-code | `35169209525` | `lote-cves-sast-batch-af-snyk-code-35169209525-1` | 30 | `f16a92d5b9adf64213aeda827c9ff84d21a61e19e072deb85de1071a95f583b9` |
| `cves-sast-batch-ag` | codeql | `35169211662` | `lote-cves-sast-batch-ag-codeql-35169211662-1` | 30 | `bf5f52748c0aad8ed86d3de22a3208b57daa7ec8631ebaec6bfff1312dba8f27` |
| `cves-sast-batch-ag` | semgrep | `35169211662` | `lote-cves-sast-batch-ag-semgrep-35169211662-1` | 30 | `f3c495df7ce5bdc1071962e56f0c362abf188accb91a156169d2b96234ed2613` |
| `cves-sast-batch-ag` | snyk-code | `35169211662` | `lote-cves-sast-batch-ag-snyk-code-35169211662-1` | 30 | `f552dae79f023b67fabcbbba41f182ee63838747ccbb74c61dea745e0430e625` |
| `cves-sast-batch-ah` | codeql | `35169213227` | `lote-cves-sast-batch-ah-codeql-35169213227-1` | 13 | `ed9846b75cf60463d61e84ccbfa7251df8a537c79bfb5c83ea34debda4eb93e7` |
| `cves-sast-batch-ah` | semgrep | `35169213227` | `lote-cves-sast-batch-ah-semgrep-35169213227-1` | 13 | `2c3e1fe529c494c9b2d2f3d7bb26168ae7d4b3fef6c6a0f60a6e150c935dd990` |
| `cves-sast-batch-ah` | snyk-code | `35169213227` | `lote-cves-sast-batch-ah-snyk-code-35169213227-1` | 13 | `af1c160442f7fa9d957a980ecc86dc7c01d1228df811ee556f344d267e6a95b6` |

## Os dois agregados

`campanha-223.json` e `campanha-aa-ab.json` foram gerados na campanha por
script que **não está versionado**. O `por_cve` do `campanha-223.json` é
reconstituível destes 24 logs: deduplicando pela última linha de cada CVE,
como o `check-log.py`, status e duração batem nos 223 × 3 pares, com **zero
divergências** (conferido em 18/09/2026). Nenhum script do repositório lê
mais os agregados como entrada.
