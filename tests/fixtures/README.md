# Fixtures sintéticas do normalizador

20 raws sintéticos mais uma lista sintética, em 9 diretórios.

Escritas à mão na Fase D, quando `results/*/raw/` estava **vazio**: o
normalizador foi escrito antes de existir qualquer saída real de ferramenta,
e esta é a única verificação possível nesse estado.

Vivem **fora** de `results/*/raw/` de propósito — aquele diretório é ignorado
pelo git, e os nomes ali dentro casariam com os globs do normalizador.

```
python3 tests/run-fixtures.py     # 130 asserções, saída não nula se alguma falhar
```

O corredor usa `--raw-dir`, `--treated-dir`, `--report-path` e `--lista`
apontando para diretório temporário. Nada é escrito em `results/` nem em
`logs/`.

## O que cada fixture cobre

### `codeql/` — casos normais, saída 0

| Arquivo | Cobre |
|---|---|
| `CVE-2018-14040.sarif` | o caso rico: CWE por `external/cwe/`, regra **sem** `defaultConfiguration.level` (→ `unknown`), `ruleId` **ausente** de `driver.rules[]` (→ `unresolved`), regra resolvida por `tool.extensions[].rules[]`, `security-severity` como `"6.1"` e como `5`, `line_end` nulo, caminho com `./` e com `file://` + prefixo do WORKDIR, achado duplicado (colisão de chave), ordem de entrada fora da ordem da chave total, `toolExecutionNotifications` mencionando o `gt_file_path` |
| `CVE-2018-1000096.sarif` | CVE **sem CWE** no ground truth; `results: []`; sem `invocations` → `analysis_date` por mtime e `tool_diagnostics` todo nulo → `gt_file_affected: null` |
| `CVE-2018-16472.sarif` | conjunto `CWE-250\|CWE-400`, **presente na tabela com primário vazio** → `gt_cwe_primary: null`; `toolExecutionNotifications: []` → `0`, distinto de `null` |
| `CVE-2017-16011.sarif` | conjunto **unitário** → primário é o próprio, sem consultar a tabela |
| `CVE-2018-16480.sarif` | `gt_file_path` **sem extensão** (`bin/public`) |

### `codeql-erros/` — saída não nula, nenhum tratado escrito

| Arquivo | Cobre |
|---|---|
| `CVE-2018-14041.sarif` | raw **truncado no meio** (D.8) |
| `CVE-2099-12345.sarif` | **raw órfão**: CVE fora de `cves-sast.txt` → falha ruidosa |
| `CVE-2016-10735.sarif` | SARIF com `runs[]` e **sem a chave `results`** → raw ilegível, simétrico ao Semgrep. Sem isso viraria `findings: []` com saída 0 |

### `semgrep/` — casos normais, saída 0

| Arquivo | Cobre |
|---|---|
| `CVE-2018-14040.json` | `extra.metadata.cwe` como **lista** e como **cadeia nua**; achado sem `cwe`; `ERROR`/`WARNING`/`MEDIUM`/`INFO`; `paths.scanned` contendo o `gt_file_path` (→ `true`), com `./` a normalizar; `paths.skipped` mencionando-o (→ `gt_file_affected`); `.time.rules` com **370** entradas — o valor real medido na Fase E sobre `twbs/bootstrap` |
| `CVE-2018-16480.json` | `gt_file_path` **ausente** de `paths.scanned` → `gt_file_scanned: false`; `.time.rules` com 12 entradas, subconjunto legítimo de `rules_total` → **nenhuma** anomalia; `errors[].type` nas **duas formas** que a saída real emite: cadeia nua e união etiquetada `["PartialParsing", [...]]` |
| `CVE-2018-1000096.json` | bloco `paths` ausente → `gt_file_scanned: null` **com motivo declarado**; `errors` ausente → `null`, nunca falha; `.time.rules` com **1075** entradas → `rules_applied > rules_total`, única anomalia possível depois que a Fase E mostrou que o campo conta regras *aplicadas* |

### `semgrep-erros/` — saída não nula

| Arquivo | Cobre |
|---|---|
| `CVE-2017-16011.json` | **sem `.time`** → falha, não `rules_applied: null` |
| `CVE-2018-16472.json` | severidade `CRITICAL`, **fora da tabela** → falha nomeando valor e CVE |

### `conjunto-ausente/` + `listas/lista-conjunto-ausente.txt`

Conjunto de CWE **ausente** da tabela de primário → falha ruidosa, em campo
próprio do relatório, distinta de "presente com primário vazio". Exige lista
sintética: nenhum dos 223 CVEs reais tem conjunto fora dos 17 mapeados.

### `snyk-code/` — casos normais, saída 0

| Arquivo | Cobre |
|---|---|
| `CVE-2018-14040.sarif` | `properties.cwe` como lista (`"CWE-79"` → `CWE-079`) e como cadeia nua; `results[].level`; `ruleId` ausente de `driver.rules[]`; `automationDetails.id` com carimbo ISO → `analysis_date_source: "tool"`; **`coverage` agregada por linguagem** → `gt_file_scanned: null` com motivo; `toolExecutionNotifications` ausente → `null` |
| `CVE-2018-16480.sarif` | `coverage` com **inventário de caminhos** → `gt_file_scanned: true`; sem `automationDetails` → mtime; `toolExecutionNotifications` presente e mencionando o `gt_file_path` |

### `gt-barra-inicial/` — defeito do ground truth

`CVE-2019-12041.json` (Semgrep). O benchmark declara `FilePath` = `/index.js`,
com barra inicial — o único dos 223. Cobre a remoção da barra, a preservação
do valor original em `gt_file_path_original`, e que `gt_file_scanned` passe a
casar com `paths.scanned` (antes da correção dava `false` contra um caminho
que ferramenta alguma emite).

### `codeql-absoluto/` — caminho absoluto sob prefixo não previsto

`CVE-2016-10735.sarif`, com achado em `/home/runner/work/x/x/js/src/util.js`.
Cobre que o caminho é **preservado** (normalização agressiva que come um
diretório real é pior que o problema que evita) **e** que a nota do relatório
e o resumo do console o denunciem, em vez de afirmar "nenhuma transformação,
tudo limpo".

### `snyk-code-erros/` — saída não nula

| Arquivo | Cobre |
|---|---|
| `CVE-2017-16011.sarif` | SARIF **vazio** (`{}`): parseia como JSON e não tem `runs[]`. É o caso que **só aqui** é pego |
| `CVE-2018-16472.sarif` | SARIF truncado no meio |

## As duas formas de `coverage` do Snyk

`CVE-2018-14040.sarif` e `CVE-2018-16480.sarif` trazem `coverage` em formatos
**diferentes** de propósito, porque o formato real não foi inspecionado — não
há raw do Snyk no repositório.

- **agregada por linguagem** (`{"files": 12, "lang": "JavaScript"}`) — é o que
  a documentação do projeto descreve, e **não permite decidir sobre um
  arquivo**. O normalizador grava `null` com motivo. Inferir `true` de uma
  contagem agregada fabricaria justamente o falso negativo silencioso que D.7
  existe para pegar
- **com inventário de caminhos** (`{"files": ["bin/public", …]}`) — forma
  hipotética, que permitiria a decisão

A Fase E dirá qual das duas o Snyk emite. Se for a agregada, `gt_file_scanned`
do Snyk será `null` nos 223, e o tri-estado terá **duas** ferramentas em
`null` em vez de uma.

## O que ficou SEM cobertura

Só a Fase E alcança:

- **a forma real das saídas.** Toda fixture aqui foi construída a partir da
  tabela "Formato das saídas das ferramentas" do `CLAUDE.md`, não de
  inspeção. Se um caminho de campo estiver errado na documentação, a fixture
  reproduz o erro e a asserção passa
- **`coverage` do Snyk** — ver acima
- **`toolExecutionNotifications` do Snyk**: o SARIF admite o campo, admitir
  não é emitir. A fixture exercita presença e ausência; qual ocorre, não se sabe
- **volume**: o maior raw aqui tem 6 achados. A duração medida pelo relatório
  não é extrapolável para os 223 CVEs
- **`paths.skipped` do Semgrep**: a fixture assume `[{path, reason}]`. Em
  1.171.0 o campo pode só aparecer sob `--verbose`; a ausência já é tratada
  como `null`, nunca como falha
- **`security-severity` ilegível** e **`extra.metadata.cwe` de tipo
  inesperado** (nem lista nem cadeia): há contador e caminho de código, sem
  fixture. São defesas contra o que não se espera ver
- **encoding**: todas as fixtures são ASCII. Raw com UTF-8 inválido cairia no
  `UnicodeDecodeError` já tratado como raw ilegível, mas não foi exercitado
