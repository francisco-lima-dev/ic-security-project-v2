# Cruzamento da versão corrigida

Saídas do `tools/cruza-corrigida.py`, que **aplica a §11** do
`docs/criterios-cruzamento.md` — fixada em 28/09/2026, antes da campanha da
versão corrigida — sobre os tratados dessa campanha
(`results/corrigida/<ferramenta>/treated/`, commits `7d6e935` e `4e8926c`).
Números sem leitura.

```
python3 tools/cruza-corrigida.py
```

Sem argumentos grava aqui; `--saida-dir DIR` grava noutro lugar. Gravar aqui
exige que todas as entradas estejam dentro do repositório.

## Entradas

| Entrada | Para quê |
|---|---|
| `results/cruzamento/matriz-deteccao.csv` (sha256 `f80158b7…452825`) | lado vulnerável, VP e FN, **lido, nunca recomputado**; conferido contra o sha256 registrado e contra o `csv_da_mesma_execucao` dos três `cruzamento-<ferramenta>.json` |
| `results/cruzamento/cruzamento-<ferramenta>.json` | agregados publicados, para reconstruir as células dos níveis 3, 4g e 4e |
| `results/pares/pares.csv` (sha256 `fd8fc5da…4dbc4`) | `gt_tipo_ponto`, `gt_ponto_post` e `post`; conferido contra o sha256 gravado no `pares.txt` |
| `datasets/listas/cves-sast.txt`, `datasets/cwe-primario.csv` | ground truth, pelo `carregar_gt` do `cruza-deteccao.py` |
| `datasets/listas/cves-sast-corrigida.txt` | universo e `PostPatchCommit`, conferidos contra o `pares.csv` |
| `logs/campanha-corrigida-2026-09-29/` | status final por (CVE, ferramenta), em ordem cronológica: os oito lotes e o redisparo |
| `results/corrigida/<ferramenta>/treated/` | lado corrigido; cada tratado validado pelo `validar_tratado` do `cruza-deteccao.py`, com o commit esperado igual ao `post` |
| `logs/campanha-2026-09-17/`, `results/<ferramenta>/treated/` | só a leitura secundária, que conta alertas por regra nos dois lados |

Os sha256 de todas as entradas e dos quatro scripts que moldam o resultado —
este, `cruza-deteccao.py`, `normalize.py` e `check-log.py` — estão em `fontes`
de cada JSON.

## Saídas

| Arquivo | Conteúdo |
|---|---|
| `matriz-corrigida.csv` | uma linha por (CVE, ferramenta, nível), nos 220 × 3 × 3: tipo e ponto corrigido, `na_principal` (falso nos 8 `so_remocao`), lado vulnerável (`VP`/`FN`/`nao_se_aplica`), status e presença do tratado corrigido, lado corrigido (`FP`/`VN`/`sem_analise`/`nao_se_aplica`) |
| `cruzamento-corrigida-<ferramenta>.json` | agregados da principal (212) e da sensibilidade (220), recall sobre os 220 publicado, decomposição por grupo, sem análise, contagens da leitura secundária, achados casados no ponto corrigido, fontes e controle positivo |
| `leitura-benchmark.csv` | por (CVE, ferramenta), nos 220: status nas duas campanhas, detecção pelo critério do benchmark, resultado, regras e alertas de cada regra nos dois lados |
| `cruzamento-corrigida.txt` | as tabelas, sem comentário |

Nos 8 `so_remocao`, a coluna do lado corrigido da matriz traz o resultado da
**sensibilidade**, no ponto `del:N`; eles não entram na principal.

## O que foi conferido — qualquer falha para o script sem gravar

1. proveniência: sha256 da matriz e do `pares.csv`; tratados corrigidos em
   contagem fixa, 220 / 220 / 215 — 214 só se o redisparo do `CVE-2019-15479`
   tivesse falhado —, iguais aos CVEs com status `OK` ou `SEM_ACHADOS`; o
   `metadata.commit` de cada tratado **e a coluna `commit` de cada log de
   execução** iguais ao `post`; o arquivo do ground truth `presente` no `post`
   nos 220; o log do Snyk Code do redisparo obrigatório;
2. universo: 212 na principal e 220 na sensibilidade; os 8 `so_remocao` iguais
   aos nominados na §11; nenhum dos três fora do denominador;
3. VP e FN nos 212, somados aos dos 8, reproduzem as células publicadas dos
   níveis 3, 4g e 4e, nas três ferramentas;
4. FP + VN + sem análise (+ n.s.a. na estrita) = 212 em cada célula;
5. sem análise: exatamente os cinco `SEM_ARQUIVO_ANALISAVEL` no Snyk Code —
   mais o `CVE-2019-15479` só se o redisparo tivesse falhado; qualquer outro
   erro é parada —, e nenhum no CodeQL e no Semgrep. O redisparo saiu `OK`;
6. a sensibilidade difere da principal só pelos 8;
7. a leitura secundária fecha em 220 por ferramenta, e os detectados pelo
   critério exato são subconjunto dos que acertam o nível 3;
8. os CSV e os JSON relidos do disco reproduzem o gerado, antes da promoção;
9. controle positivo de 1 a 8: 12 mutantes, ao menos um por conferência,
   todos acusados — no `conferencias.controle_positivo` de cada JSON;
10. determinismo: quatro `PYTHONHASHSEED` distintos, saídas idênticas byte a
    byte.

Conferido também por recontagem independente, sem as funções importadas: FP e
VN do nível 3 e as quatro categorias da leitura secundária batem nas três
ferramentas.

**Divergência declarada da §11, fechada:** se algum dos 8 `so_remocao` ficar
sem análise em alguma ferramenta, a §11 manda reportar a sensibilidade sem
ele, e o pedido desta apuração, mantê-lo como sem análise. O script **para**
nesse caso, em vez de escolher. Não ocorre: nenhum dos 8 está sem análise.

## A leitura secundária e o código do benchmark

Conferida contra `contrib/reports/explore-server/src` no commit `91c59fd`
(`isOnTarget`, `buildRulesOnATargetMap`, `getRelevantRuleAlertCounts`,
`getRelevantRuleAlertCountsConclusion`). A ordem das conclusões é a do código:
**ausente antes de não computável** — ferramenta que não analisou um dos lados
sai ausente, com ou sem detecção. Uma divergência declarada: o benchmark
compara o arquivo da weakness **como veio**, e aqui a comparação é contra o
`gt_file_path` normalizado; só o `CVE-2019-12041` (`/index.js`) é afetado.

**Interpretação declarada:** "a ferramenta analisou o lado" é ter tratado com
status `OK` ou `SEM_ACHADOS`. Os cinco `SEM_ARQUIVO_ANALISAVEL` do Snyk Code
(exit 3, sem raw, nas duas campanhas) saem por isso **ausentes**. Se o harness
do benchmark registrasse como execução uma saída com exit 3, eles seriam não
computáveis; o código lido não mostra como ele trata esse caso.

## O que as saídas não contêm

- leitura dos números, e comparação entre ferramentas;
- precisão sobre todos os alertas: alerta fora do ponto corrigido continua não
  classificável (§1, emenda de 21/09/2026). A precisão aqui é VP / (VP + FP)
  **no ponto da falha**;
- os níveis 0, 1 e 2 na versão corrigida (§11, "Os níveis");
- teste estatístico.
