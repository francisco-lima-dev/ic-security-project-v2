# Capacidade empírica — tabela regra → linguagens

Base do critério "pela linguagem da regra" da §10 de
`docs/criterios-cruzamento.md`. Versionada ao lado de `results/por-cwe/`, e
pela mesma razão: fixa, antes de qualquer contagem de achado, a tabela de que
o critério depende.

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

**Contagem de achado alguma.** Nenhum tratado é lido. A contagem de achados
por CWE e por linguagem é a fase seguinte, e o critério dela está na §10,
fixado antes.

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
