# Fixtures sintéticas do normalizador

20 raws sintéticos mais uma lista sintética, em 9 diretórios.

Escritas à mão na Fase D, quando `results/*/raw/` estava **vazio**: o
normalizador foi escrito antes de existir qualquer saída real de ferramenta,
e esta é a única verificação possível nesse estado.

Vivem **fora** de `results/*/raw/` de propósito — aquele diretório é ignorado
pelo git, e os nomes ali dentro casariam com os globs do normalizador.

```
python3 tests/run-fixtures.py     # saída não nula se alguma asserção falhar
```

O corredor usa `--raw-dir`, `--treated-dir`, `--report-path` e `--lista`
apontando para diretório temporário. Nada é escrito em `results/` nem em
`logs/`.

## O que cada fixture cobre

### `codeql/` — casos normais, saída 0

| Arquivo | Cobre |
|---|---|
| `CVE-2018-14040.sarif` | o caso rico: CWE por `external/cwe/`, regra **sem** `defaultConfiguration.level` (→ `unknown`), `ruleId` **ausente** de `driver.rules[]` (→ `unresolved`), regra resolvida por `tool.extensions[].rules[]`, `security-severity` como `"6.1"` e como `5`, `line_end` nulo, caminho com `./` e com `file://` + prefixo do WORKDIR, achado duplicado (colisão de chave), ordem de entrada fora da ordem da chave total, `toolExecutionNotifications` na **forma real medida na Fase E** — `level: "none"`, `message.text` vazia, `descriptor.id` `js/diagnostics/successfully-extracted-files` e o caminho só em `locations[0]`. Antes modelava uma **falha** de extração, que a saída real contradiz |
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
| `CVE-2018-14040.sarif` | `properties.cwe` como lista (`"CWE-79"` → `CWE-079`) e como cadeia nua; `results[].level`; `ruleId` ausente de `driver.rules[]`; `automationDetails.id` com carimbo ISO → `analysis_date_source: "tool"`; **`coverage` agregada por linguagem na forma real** (`lang` = extensão, `files` = contagem) → `gt_file_scanned: null` com motivo; duas entradas **`FAILED_PARSING`** → `tool_diagnostics.errors: 8`; `toolExecutionNotifications` ausente → `null` |
| `CVE-2018-16480.sarif` | `coverage` com **inventário de caminhos** → `gt_file_scanned: true` — forma **não observada** na saída real, mantida como ramo defensivo; mais uma entrada `FAILED_PARSING` **com caminho**, para assegurar que caminho sob entrada não suportada não conta como varrido; sem `automationDetails` → mtime; `toolExecutionNotifications` presente e mencionando o `gt_file_path` |

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

## `cruzamento/` — fixtures do `tools/cruza-deteccao.py`

Um arquivo só, `casos.json`, com 23 casos. Não são tratados prontos: cada caso
declara os achados de um (ferramenta, CVE) e o resultado esperado em cada
nível e variante, e o corredor monta os tratados em diretório temporário.

**O universo tem a forma do conjunto real.** As constantes do script — 223
CVEs, 220 pares, as três exclusões nominadas — não são sobrescrevíveis, então
a fixture usa a **lista real** e gera um tratado sem achados para todo
(ferramenta, CVE) sem caso; nenhum tratado para as duas baixas por código
indisponível nem para os cinco `SEM_ARQUIVO_ANALISAVEL` do Snyk Code; e um
log de execução sintético por (lote, ferramenta), nos oito lotes reais de
`datasets/listas/`, coerente com isso. O `gt_assumido` de cada caso
é conferido contra o gt derivado da lista: se a lista mudar, o caso falha em
vez de passar sobre premissa velha. **Nada lê `results/*/treated/`.**

`+` é caso positivo daquele nível ou variante; `−` é negativo.

| Caso | Ferramenta, CVE | Exercita |
|---|---|---|
| C01 | codeql `CVE-2017-16011` | nível 0 − (tratado sem achado) |
| C02 | codeql `CVE-2016-10735` | nível 0 +, nível 1 − (linha e CWE certos, outro arquivo) |
| C03 | codeql `CVE-2018-14040` | nível 1 +; nível 2 generosa − e estrita − (CWE fora do conjunto); nível 3 − |
| C04 | codeql `CVE-2017-16042` | nível 2 − nas duas variantes: arquivo certo num achado, CWE certo **noutro** |
| C05 | codeql `CVE-2018-16472` | estrita **não se aplica** (primário nulo), com acerto generoso completo |
| C06 | semgrep `CVE-2016-10735` | nível 2 generosa +, estrita − (CWE do conjunto que não é o primário) |
| C07 | semgrep `CVE-2018-14040` | nível 2 estrita +; nível 4 − nas duas (linha longe) |
| C08 | semgrep `CVE-2017-16042` | nível 3 + por `line_end` nulo tratado como ponto; nível 4 − (CWE errado) |
| C09 | semgrep `CVE-2017-16011` | nível 3 −: `line_end` nulo é ponto, não intervalo aberto |
| C10 | semgrep `CVE-2017-1000219` | nível 3 + por intervalo que contém a linha sem começar nela |
| C11 | semgrep `CVE-2017-16029` | nível 3 −: sem banda, intervalos a uma linha de distância dos dois lados |
| C12 | semgrep `CVE-2017-16028` | nível 3 e 4 + na borda inicial (`line_start` = linha) |
| C13 | snyk-code `CVE-2017-16028` | nível 3 e 4 + na borda final (`line_end` = linha) |
| C14 | snyk-code `CVE-2016-10735` | nível 4 − nas duas: linha num achado, CWE primário **noutro**, ambos no arquivo |
| C15 | snyk-code `CVE-2018-14040` | nível 4 generosa +, estrita − |
| C16 | snyk-code `CVE-2017-16042` | nível 4 estrita + |
| C17 | codeql `CVE-2021-23364` | `gt_file_lines` multivalorado: acerto na terceira linha, não na primeira |
| C18 | codeql `CVE-2019-12041` | `gt_file_path` normalizado (`/index.js` no benchmark) casa no nível 1 |
| C19 | codeql `CVE-2017-1000219` | nível 1 − por igualdade exata: mesmo basename, outro diretório; `gt_file_scanned: false`, e o CVE **permanece** no denominador |
| C20 | codeql `CVE-2017-16029` | nível 3 −: achado sem `line_start` |
| C21 | codeql `CVE-2018-3725` | nível 3 −: intervalo entre duas linhas do gt sem conter nenhuma |
| C22 | snyk-code `CVE-2017-15010` | estrita −, com o primário resolvido pela chave canônica (ordem declarada 730\|400) |
| C23 | snyk-code `CVE-2018-16479` | sem tratado no denominador: não-detecção em todos os níveis |

Cobertura por nível e variante, positivo / negativo:

| | positivo | negativo |
|---|---|---|
| nível 0 | C02 e todos com achado | C01, C23 |
| nível 1 | C03, C18 | C02, C19 |
| nível 2 generosa | C06, C07, C14 | C03, C04, C08 |
| nível 2 estrita | C07, C09, C14 | C04, C06, C22 |
| nível 3 | C08, C10, C12, C13, C17 | C03, C09, C11, C20, C21 |
| nível 4 generosa | C12, C13, C15, C22 | C07, C08, C14 |
| nível 4 estrita | C16, C17, C18 | C14, C15, C22 |
| estrita não se aplica | C05 (e o mesmo CVE, sem achado, nas outras duas) | — |

Além dos casos, o corredor exercita **41 mutantes** do universo — tratado de
CVE excluído, baixa com o status do outro motivo, `gt_cwes` não vazio no CVE
sem CWE, CVE sem CWE sem tratado, lista com 222 CVEs, ausência de tratado sem
causa admitida, log de lote sem um CVE, sem cabeçalho ou ausente, CVE em dois
lotes, CVE repetido no log, `OK` com tratado sem achado e `SEM_ACHADOS` com
tratado com achado, tratado órfão, schema, tipos, caminho absoluto, `finding_id`
repetido, parada sobre saída pré-existente, entre outros — exigindo de cada um `PARADO`, código 2 e
nenhuma saída escrita ou alterada. E confere determinismo (CSV byte-idêntico
entre execuções) e a interface (só opções de caminho).

O script tem ainda **duas camadas embutidas**, que rodam a cada execução antes
de qualquer número: autoteste com 34 mutantes (25 do validador de tratado, 7
das regras de presença × registro × denominador, 2 de status × achados), cada
um exigido pela guarda
**pretendida** e não por outra qualquer; e controle positivo da apuração, um
conjunto sintético de resposta conhecida em que todo contador tem valor
esperado não nulo. O corredor confere que ambas passaram.

**Verificado por mutação do próprio script, em 18/09/2026, não versionado:**
sete defeitos plantados no `cruza-deteccao.py` — intervalo aberto para
`line_end` nulo, banda de ±1, nível 1 por basename, estrita não aplicável
virando `false`, nível 4 por CVE e não por achado, ausência de tratado
admitida fora do Snyk, baixa com tratado não conferida — foram todos acusados
pela suíte. Seis deles as camadas embutidas já paravam; com elas desligadas,
os casos e os mutantes do corredor os acusaram sozinhos — esses seis são
pegos por duas camadas independentes. O sétimo, nível 1 por basename, as
camadas embutidas **não** veem (a apuração fica coerente consigo mesma): só o
caso C19 o pega.
