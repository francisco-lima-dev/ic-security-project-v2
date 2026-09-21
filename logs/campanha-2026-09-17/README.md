# Campanha SAST de 16–17/09/2026 — registro de execução

Dois agregados, os 24 logs de execução e os 24 relatórios de normalização
por lote.

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

## Os 24 relatórios de normalização

`cves-sast-batch-<lote>/normalize-report-<ferramenta>.json` é cópia **byte a
byte** do `logs/normalize-report-<ferramenta>.json` do artifact da mesma
execução, gerado pelo `tools/normalize.py` dentro do job do lote. Baixado com
`gh run download` em 21/09/2026 e conferido com `cmp`. Os artifacts são os
mesmos da tabela acima: os 24 `execution-log-*.csv` do download de 21/09 batem
byte a byte com os versionados em 18/09.

Até 21/09/2026 nenhum destes estava no repositório. Os três
`logs/normalize-report-*.json` da raiz são do ensaio **local** da Fase E, e os
de `logs/ensaio-fumaca-2026-09-16/` são do ensaio de fumaça.

Os 24 trazem `schema_version` `1.3`. Somados: processados 221 / 221 / 216
(CodeQL / Semgrep / Snyk Code), `pulados_por_idempotencia` 0, `com_falha` 0,
`raws_ilegiveis` 0 e órfãos 0. Os 658 tratados dos artifacts são idênticos
byte a byte aos versionados em `results/*/treated/`.

Os campos `lista`, `raw_dir` e `treated_dir` guardam caminhos absolutos **do
runner** (`/home/runner/work/…`). São o que a execução gravou, e nenhum deles
é caminho da máquina do operador.

| Lote | Ferramenta | Execução | Processados | Duração (s) | Colisões | sha256 |
|---|---|---|---:|---:|---:|---|
| `cves-sast-batch-aa` | codeql | `35106944490` | 29 | 0.0793 | 0 | `6cbfe532cea58eaea6b96620b3b95d70fc4bd950a501d352d6adf8b289a59d43` |
| `cves-sast-batch-aa` | semgrep | `35106944490` | 29 | 0.5575 | 0 | `b7cd945ef37bbce3e15ce150f61122bd5d833723026dbd21f2ff4ea3aec1e805` |
| `cves-sast-batch-aa` | snyk-code | `35106944490` | 29 | 0.02 | 0 | `bfcaf0cf2bebb3e3579129390137b95a99887455b9b0f15014031b9bdf94f52c` |
| `cves-sast-batch-ab` | codeql | `35135927579` | 30 | 0.0748 | 0 | `392d82d1bb2c179535002292b38116c43cdd494c8747d5c98312e4a1dc510b60` |
| `cves-sast-batch-ab` | semgrep | `35135927579` | 30 | 2.2639 | 0 | `c9953eceda4ddc9555e59b3e52878b4c4104be41e6209384a002cf3042689810` |
| `cves-sast-batch-ab` | snyk-code | `35135927579` | 30 | 0.0221 | 0 | `032ba59992117864ccac0c2ee7b94b2a11bc2ae1b796bd7b8b7d4513b3f21adf` |
| `cves-sast-batch-ac` | codeql | `35169202777` | 30 | 0.1618 | 0 | `d6028d56bffa5d4165a6df63af97f40a9b9add1c3c527fc678cc2fcc5bacde2b` |
| `cves-sast-batch-ac` | semgrep | `35169202777` | 30 | 11.2237 | 0 | `1258b1563b6093bb59d6f5f84028f6e8714decd232b6b148794e42f8a2932a69` |
| `cves-sast-batch-ac` | snyk-code | `35169202777` | 28 | 0.0266 | 0 | `0ff5e51151188db4158497a0aae4a324a5b8642d8bedf2e85ef5f669be9f73df` |
| `cves-sast-batch-ad` | codeql | `35169205115` | 29 | 0.1506 | 0 | `5c21f98a2ddcb09a5d77fb495c7646687d07fc40732f8fa7e41e38fc98b7acf9` |
| `cves-sast-batch-ad` | semgrep | `35169205115` | 29 | 4.5518 | 0 | `2c8c2583e80ad3331c0518a9c2b3ac2326fb952b65eb1a8e491cc9b1b2b443c7` |
| `cves-sast-batch-ad` | snyk-code | `35169205115` | 27 | 0.1103 | 0 | `c8a3cdaee3cd888e05dfb96285a2b1520d99c292277a9a99f32fba29c60b2846` |
| `cves-sast-batch-ae` | codeql | `35169207030` | 30 | 0.1769 | 0 | `f5327f76bf5221973765f44bc64b196cf5e4387bb170f9c26c672e73dd111e4d` |
| `cves-sast-batch-ae` | semgrep | `35169207030` | 30 | 1.4236 | 0 | `7da62c79e3ec968888d82b72c2d7a6755dfbf65516f58d425ea4dfbaf3921770` |
| `cves-sast-batch-ae` | snyk-code | `35169207030` | 30 | 0.0456 | 0 | `9eff78544fe8487e037a14b331ecb36a70e211c64c30eb4ce5ca6f92bf6c21a9` |
| `cves-sast-batch-af` | codeql | `35169209525` | 30 | 0.094 | 0 | `0a147c3895710a6aca2d1450643877045b485a5e13c519586071ababaef18bbc` |
| `cves-sast-batch-af` | semgrep | `35169209525` | 30 | 0.7082 | 0 | `1e1504913ad13a041a5229531135efd8e1c9c74b9ceeceb3606d9c084409d867` |
| `cves-sast-batch-af` | snyk-code | `35169209525` | 29 | 0.025 | 0 | `de02ffee2cbf375916f363322345ec54be24d9f6ec4fa638058955195916db94` |
| `cves-sast-batch-ag` | codeql | `35169211662` | 30 | 0.1539 | 0 | `098d8c4f1645700f4a8b7ffbf787911c9e5e7fd8cf16d8e57f4e9f4073c1a7f8` |
| `cves-sast-batch-ag` | semgrep | `35169211662` | 30 | 4.1063 | 0 | `942ada4052727590ddcd697a2b7fdf198e9b90ab6318703bff6d9298753d4dec` |
| `cves-sast-batch-ag` | snyk-code | `35169211662` | 30 | 0.0416 | 0 | `17661a695c4ae7ab32a1b196cef18c1e02f699a97ac2af47b127684cdd948230` |
| `cves-sast-batch-ah` | codeql | `35169213227` | 13 | 0.0638 | 0 | `2953d89397b5acc931a49b3d78919fe7daba119d34a447afe5c881c4b693f3f2` |
| `cves-sast-batch-ah` | semgrep | `35169213227` | 13 | 0.8188 | 0 | `5ce1b5c1795c4e98e29d0f61b1666c7039be2a1a04186b3fcdf1a5c5c1e8830e` |
| `cves-sast-batch-ah` | snyk-code | `35169213227` | 13 | 0.0162 | 0 | `5b6bb1241ec952fbf1f0a9c2a2be9816409df2364ab31ce5bc117141de5f1872` |

Duração e colisões são os campos `duracao_segundos.total` e
`colisoes_chave_ordenacao.total` de cada relatório. A duração cobre o laço
sobre os raws — leitura, conversão e escrita do tratado —, e não a carga do
ground truth nem a da tabela de primário. Os totais somados estão no
`CLAUDE.md`, em "Campanha SAST — resultados".

## Os dois agregados

`campanha-223.json` e `campanha-aa-ab.json` foram gerados na campanha por
script que **não está versionado**. O `por_cve` do `campanha-223.json` é
reconstituível destes 24 logs: deduplicando pela última linha de cada CVE,
como o `check-log.py`, status e duração batem nos 223 × 3 pares, com **zero
divergências** (conferido em 18/09/2026). Nenhum script do repositório lê
mais os agregados como entrada.
