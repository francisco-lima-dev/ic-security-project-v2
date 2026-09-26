# Capacidade empírica e delimitação por linguagem

Saídas da §10 de `docs/criterios-cruzamento.md`, em duas fases:

- **Tabela regra → linguagens** (25/09/2026): base do critério "pela
  linguagem da regra", fixada antes de qualquer contagem de achado.
- **Contagens** (26/09/2026): capacidade por CWE do achado e delimitação por
  linguagem, que aplicam a §10 sem alterá-la. Ver a segunda parte deste
  arquivo.

Descritivo: o que as ferramentas **reportam**, e não o que acertam. Nada
aqui cruza com o ground truth.

# Parte 1 — tabela regra → linguagens

**Gerada em 25/09/2026.**

## Como foi produzida

```bash
python3 tools/regras-linguagens-semgrep.py
```

Exige Docker e a imagem do Semgrep da campanha, pelo digest vigente
(`CLAUDE.md`, "Imagens da campanha — digests publicados"):

```bash
docker pull ghcr.io/francisco-lima-dev/ic-security-lab-semgrep@sha256:de71bdfbdf81d495781a4c80052c5f7d128ec9b76eba2304978e08b88ba5d000
```

## Parser

`ruamel.yaml` 0.19.1, Python 3.12.14, **dentro da imagem da campanha**, sem
rede, sob `--user`, com o pack montado só para leitura. O container só faz o
parse e devolve `id` e `languages` de cada regra, com o tipo preservado; toda
conferência roda no hospedeiro. É o mesmo parser da contagem de severidades
registrada no `CLAUDE.md`. O ambiente local não tem parser YAML, e contar o
pack com `grep` já produziu dois números errados.

A linguagem **nunca** é tirada do prefixo do `check_id`: prefixo é convenção
de nome, não declaração. O próprio pack tem regras `generic` com prefixo
`javascript.` e `java.`.

## Fonte lida

| Fonte | Para quê |
|---|---|
| `ic-security-lab-semgrep/rules/semgrep-default.yaml` | as regras |
| `ic-security-lab-semgrep/rules/semgrep-default.meta.json` | sha256 do arquivo e `rules_id_sha256`, conferidos |

## O que contém

- `regras-linguagens.csv` — uma linha por regra, ordenada por `check_id`:
  `check_id`, `languages` (minúsculas, ordenado, separado por `|`) e `js_ts`
  (`sim` se `languages` intersecta `javascript`, `js`, `typescript`, `ts`).
- `regras-linguagens.txt` — sha256 do pack e do CSV, `rules_id_sha256`
  recalculado, parser e versão, conferências e controle positivo, a
  composição JS/TS e a distribuição de regras por `languages`, com `generic`
  e `regex` destacadas.

## O que NÃO contém

**Contagem de achado alguma.** O `regras-linguagens-semgrep.py` não lê
tratado. A contagem de achados por CWE e por linguagem está na parte 2.

## Conferências

1. 1074 regras, 1074 `check_id` distintos.
2. `javascript` 152, `js` 1, `typescript` 150, `ts` 5, união 163.
3. sha256 do pack e `rules_id_sha256` iguais aos do descritor.
4. Toda regra tem `languages`, em lista.
5. O CSV é gravado com nome temporário e relido antes da promoção.
6. Controle positivo com mutante por conferência, inclusive `languages` como
   cadeia nua e elemento que não é cadeia. Além disso, um YAML mutante mínimo
   passa pelo **container de verdade**: o extrator tem de classificar lista,
   cadeia nua, elemento nulo e `languages` ausente, e chave duplicada tem de
   falhar (o `ruamel.yaml` levanta `DuplicateKeyError`).

Caminho de pack com `:` ou `,` é recusado antes de invocar o docker, porque o
`-v origem:destino:ro` não o monta. A coluna `languages` do CSV é normalizada
(minúsculas, sem repetição, ordenada), não o texto literal do pack.

**Não verificado:** que o parser interno do Semgrep 1.171.0 leia as regras
como o `ruamel.yaml` as lê. Os números batem com o descritor, mas o descritor
foi contado com o mesmo parser, na mesma imagem.

## Determinismo

Mesmos bytes com `PYTHONHASHSEED` 0, 1, 7 e 12345, para o CSV, o texto e o
stdout. O script recusa gravar dentro do repositório se alguma entrada
estiver fora dele.

# Parte 2 — capacidade por CWE e delimitação por linguagem

**Gerada em 26/09/2026.**

```bash
python3 tools/capacidade-empirica.py
```

Sem Docker e sem rede: só lê arquivos versionados. Sem argumentos, lê e grava
nos caminhos padrão; `--saida-dir` grava noutro lugar.

## Fontes lidas

| Fonte | Para quê |
|---|---|
| `results/<ferramenta>/treated/*.json` | de cada achado, `cwe`, `file_path` e `rule_id` (`has_cwe` só para conferir forma); do `metadata`, `cve_id`, `tool` e, no Snyk Code, `coverage`. **Nenhum campo `gt_*`** |
| `results/capacidade/regras-linguagens.csv` | linguagem da regra do Semgrep; sha256 fixado no script (`83b7fe5f…`, commit `ec1a351`) |
| `logs/campanha-2026-09-17/cves-sast-batch-*/normalize-report-<ferramenta>.json` | **só** para conferir os totais (`achados.total`, `achados.sem_cwe`) |

A linguagem da regra vem **só** da junção com o CSV, nunca do prefixo do
`check_id`.

## Definições aplicadas

- **Extensão:** o sufixo depois do último ponto do **nome** do arquivo (o que
  vem depois da última `/`), em minúsculas; sem ponto no nome, ou com o ponto
  no fim, não há extensão. `x.d.ts` → `ts`; `.eslintrc.js` → `js`;
  `bin/public` → sem extensão; `.npmrc` → `npmrc`.
- **JS/TS pela extensão:** `js jsx mjs cjs ts tsx mts cts`.
- **JS/TS pela regra** (só Semgrep): `languages` contém um de `javascript`,
  `js`, `typescript`, `ts`.
- **Categoria:** o CWE do achado; achado com mais de um CWE conta em cada um;
  achado sem CWE vai para `SEM_CWE`.
- **Universo:** todos os CVEs com tratado, 221 / 221 / 216.

## O que contém

- `capacidade-por-cwe.csv` — formato longo, uma linha por (ferramenta,
  versão, categoria): `universo_cves`, `cves_com_achado`, `achados`,
  `maior_cve` e `achados_maior_cve` (empate pelo identificador). Versões
  `js_ts_extensao` (a principal) e `todos`. Cada ferramenta traz, **nas duas
  versões**, toda categoria que ocorre em alguma delas, e `SEM_CWE` sempre:
  zero é explícito, e categoria com zero na versão principal é a que só
  ocorre fora de JS/TS. `maior_cve` vazio quando `achados` é 0.
- `delimitacao-linguagem.csv` — por (ferramenta, critério, célula):
  critério `extensao` nas três (`js_ts`, `fora`) e `regra_x_extensao` só no
  Semgrep (as quatro células da 2 × 2), com `achados`, `cves_com_achado` e as
  proporções da §10 sobre o total de achados e sobre o universo de CVEs.
- `capacidade.txt` — fontes e sha256, definições, conferências com o controle
  positivo, a tabela da versão principal, a delimitação e a 2 × 2 em achados
  e em CVEs, as extensões dos achados fora de JS/TS, a concentração do
  Semgrep por CVE e por regra, e a corroboração pelo `coverage` do Snyk Code.
  Só números e limitações declaradas.

## Conferências

Qualquer falha para o script sem gravar.

1. sha256 do `regras-linguagens.csv`; 221, 221 e 216 tratados, e o
   conjunto, não só a contagem: nenhuma das duas baixas por código
   indisponível, CodeQL e Semgrep com os mesmos CVEs, e o Snyk Code com eles
   menos os cinco `SEM_ARQUIVO_ANALISAVEL`.
2. Total de achados e de `SEM_CWE` dos tratados igual à soma dos oito
   relatórios de normalização de cada ferramenta e ao valor publicado.
3. Todo CWE na forma canônica — três dígitos com zero à esquerda, ou quatro
   ou mais sem ele (`CWE-0079` é recusado) —, sem repetição no achado e
   coerente com `has_cwe`; todo `file_path` é relativo e não vazio; `coverage` do Snyk na
   forma medida (quatro chaves, `files` inteiro, `lang` começando por ponto).
   Roda **antes** da apuração, que supõe a forma: achado fora dela para na 3,
   nomeado, e não em traceback.
4. Todo `rule_id` do Semgrep resolve no CSV de regras.
5. Partição: `js_ts + fora = total`; a 2 × 2 soma o total; cada margem da
   2 × 2 é igual ao critério correspondente sozinho.
6. Multi-CWE: soma das categorias menos o total igual a Σ(nº de CWEs − 1),
   nas duas versões.
7. 5.850 achados do Semgrep no `CVE-2018-20801`, número de documento.
8. Segundo caminho: `cves_com_achado` das células `extensao` e das dez
   maiores categorias da versão principal, por travessia independente (por
   CVE, o conjunto de caminhos; extensão por expressão regular).
9. Os dois CSV são gravados com nome temporário e relidos antes da promoção.
10. Controle positivo: mutante por conferência, inclusive `rule_id` com
    prefixo de diretório (`packs.javascript…`), e achados injetados em
    `x.d.ts` e `bin/public`, que caem em `js_ts` e em `fora` pelo laço
    inteiro. Os CSV adulterados do mutante da 9 são gravados em diretório
    temporário do sistema, nunca em `results/capacidade/`.

## Limitações

- **Pontos cegos da §10:** arquivo JavaScript sem extensão sai fora de JS/TS;
  regra `generic` ou `regex` disparando em arquivo JS sai fora pelo critério
  da regra.
- **Categorias não somam o total de achados**, porque achado multi-CWE conta
  em cada uma.
- **Achados são dominados por poucos CVEs**; por isso toda linha traz o
  maior CVE da categoria.
- **`coverage` do Snyk Code é agregada e não enumera caminhos.** O campo
  `lang` traz uma extensão (`.js`, `.html`), e não um nome de linguagem. A
  corroboração é por CVE, nunca por arquivo.
- **O critério pela regra não se aplica ao CodeQL nem ao Snyk Code** (§10).

## Determinismo

Mesmos bytes com `PYTHONHASHSEED` 0, 1, 7 e 12345, para os dois CSV, o texto
e o stdout. O script recusa gravar dentro do repositório se alguma entrada
estiver fora dele.
