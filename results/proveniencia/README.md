# Saídas do cotejo de proveniência

Saídas de `tools/ground-truth/`, versionadas pela mesma razão que
`results/cruzamento/`: são o que sustenta o argumento, não perícia. Sem elas,
verificar os números do cotejo exige obter os catálogos externos e reexecutar;
com elas, o repositório se basta.

**Geradas em 20/09/2026**, do commit `d9b3c6a`.

## Como foram produzidas

Da raiz do repositório, com os catálogos obtidos em `catalogos/`, que é
ignorado:

```bash
tools/ground-truth/obter-catalogos.sh catalogos

G=tools/ground-truth; C=catalogos; O=results/proveniencia
COMUM="--csv datasets/cve-metadata.csv --clone ossf-cve-benchmark/CVEs"

python3 $G/cruza-codeql.py $C/codeql-2020/javascript/ql/src       $COMUM --rotulo ref   --json $O/cotejo-ref.json   > $O/cotejo-ref.txt
python3 $G/cruza-codeql.py $C/codeql-2020-12-11/javascript/ql/src $COMUM --rotulo sens  --json $O/cotejo-sens.json  > $O/cotejo-sens.txt
python3 $G/cruza-codeql.py $C/codeql-atual/javascript/ql/src      $COMUM --rotulo atual --json $O/cotejo-atual.json > $O/cotejo-atual.txt

python3 $G/cruza-codeql.py $C/codeql-2020/javascript/ql/src       --gt-json $C/benchmark-release/CVEs --rotulo release-ref  --json $O/cotejo-release-ref.json  > $O/cotejo-release-ref.txt
python3 $G/cruza-codeql.py $C/codeql-2020-12-11/javascript/ql/src --gt-json $C/benchmark-release/CVEs --rotulo release-sens --json $O/cotejo-release-sens.json > $O/cotejo-release-sens.txt
python3 $G/cruza-codeql.py $C/codeql-2020/javascript/ql/src       --gt-json $C/benchmark-previo/CVEs  --rotulo previo-ref   --json $O/cotejo-previo-ref.json   > $O/cotejo-previo-ref.txt
python3 $G/cruza-codeql.py $C/codeql-2020-12-02/javascript/ql/src --gt-json $C/benchmark-previo/CVEs  --rotulo previo-0212  --json $O/cotejo-previo-0212.json  > $O/cotejo-previo-0212.txt

python3 $G/compara-relatorios.py $O/cotejo-ref.json         $O/cotejo-sens.json        > $O/compara-ref-x-sens.txt
python3 $G/compara-relatorios.py $O/cotejo-release-ref.json $O/cotejo-ref.json         > $O/compara-release-x-csv.txt
python3 $G/compara-relatorios.py $O/cotejo-previo-ref.json  $O/cotejo-release-ref.json > $O/compara-previo-x-release.txt
python3 $G/compara-relatorios.py $O/cotejo-previo-0212.json $O/cotejo-previo-ref.json  > $O/compara-previo-0212-x-ref.txt
python3 $G/compara-relatorios.py $O/cotejo-ref.json         $O/cotejo-atual.json       > $O/compara-ref-x-atual.txt

(cd $G && npm ci)
node $G/cruza-semgrep.js datasets/cve-metadata.csv $C/semgrep-rules > $O/controle-semgrep.txt
```

**Os caminhos são relativos de propósito, e não é cosmético.** O
`cruza-codeql.py` grava em `consultas_dir` e `fonte_ground_truth` o caminho
que recebeu. Com caminho absoluto, o diretório da máquina do operador iria
para dentro de arquivo versionado — a mesma regra que o `cruza-deteccao.py`
aplica com guarda explícita. Daí `catalogos/` ficar dentro da árvore, e
ignorado: fora dela não há caminho relativo a dar.

O `--csv` e o `--clone` são passados explicitamente **porque o default é
absoluto** (`RAIZ / …`), e cairia no mesmo defeito.

## Determinismo

Reexecutar sobre os mesmos catálogos reproduz os mesmos bytes. Conferido em
três execuções com `PYTHONHASHSEED` distinto, para JSON e texto, com controle
positivo de que o teste acusa diferença real. Nenhuma saída leva carimbo de
execução, e `git diff --exit-code results/proveniencia/` depois de reexecutar
denuncia saída desatualizada.

## O que cada arquivo é

| Arquivo | Estado do CodeQL | Ground truth |
|---|---|---|
| `cotejo-ref.*` | `ec573b51` — **a referência** | CSV versionado |
| `cotejo-sens.*` | `9ff6d68a` — sensibilidade | CSV versionado |
| `cotejo-atual.*` | `f7caf559` — catálogo atual | CSV versionado |
| `cotejo-release-ref.*` | `ec573b51` | benchmark no commit do release |
| `cotejo-release-sens.*` | `9ff6d68a` | benchmark no commit do release |
| `cotejo-previo-ref.*` | `ec573b51` | benchmark anterior ao release |
| `cotejo-previo-0212.*` | `04bacf43` | benchmark anterior ao release |

Os `compara-*.txt` são as cinco diferenças **nominais** entre pares de
relatórios; `controle-semgrep.txt` é o controle contra o catálogo do Semgrep.

O `.json` é a saída de máquina, e é dele que o
`tools/circularidade-proveniencia.py` consome a partição. O `.txt` é a mesma
apuração em forma legível, com as listas nominais.

## Os números, para conferência rápida

| Cotejo | casados (normalizado) | idênticos |
|---|---|---|
| `ref` | **163 de 223 (73,1%)** | 163 de 163 |
| `sens` | 185 de 223 (83,0%) | 185 de 185 |
| `atual` | 185 de 223 (83,0%) | 108 idênticos, 74 subconjunto, 3 divergentes |
| `release-ref` | 163 de 219 (74,4%) | 163 de 163 |
| `release-sens` | 185 de 219 (84,5%) | 185 de 185 |
| `previo-ref` | 181 de 214 (84,6%) | 181 de 181 |
| `previo-0212` | 181 de 214 (84,6%) | 181 de 181 |

Controle do Semgrep: 2.228 regras de 2.162 YAML (16 com erro de parse);
T1 **0 (0,0%)**, T2 1 (0,4%), T3 37 (16,6%), união 38 (17,0%).

A diferença entre `ref` e `sens` é **22 CVEs**, todos por
`Security/CWE-915/PrototypePollutingFunction.ql`, nomeados em
`compara-ref-x-sens.txt`.

## Limite declarado

Os catálogos **não** são versionados, e nem o `cruza-codeql.py` nem estas
saídas gravam hash do conteúdo deles. A garantia de que o catálogo é o estado
certo vem do `obter-catalogos.sh`, que assevera o HEAD contra o commit do
`proveniencia.meta.json`. Catálogo trocado nesse caminho produziria saída
contra outro estado, e o repositório não tem como denunciá-lo.
