# Snyk Code — container de análise SAST

## Configuração avaliada

Padrão da ferramenta. Não há conjunto de regras declarável: o bloco `ruleset`
do schema comum é **nulo inteiro** para esta ferramenta, e `rules_applied`
também.

Somente `--sarif-file-output`. O `--json-file-output` produz arquivo
byte-idêntico ao SARIF; passar os dois duplica dados sem ganho.

## Build

```bash
cd ic-security-lab-snyk-code
docker build -t ic-security-lab-snyk-code \
    --build-arg SNYK_CLI_VERSION="$(jq -r .version snyk-cli.meta.json)" \
    --build-arg SNYK_CLI_SHA256="$(jq -r .sha256 snyk-cli.meta.json)" .
```

**Os dois `--build-arg` são obrigatórios.** Desde a Fase G-2b os `ARG` não
têm default e o build falha sem eles, por desenho: com default, um
`--build-arg` errado ou esquecido passava em silêncio.

CLI baixado de URL versionada (`https://static.snyk.io/cli/v<versão>/snyk-linux`),
fixada em `v1.1306.1`. Nunca `latest` nem `stable`: ambos já se moveram desde
a campanha anterior.

O `sha256` vem de `snyk-cli.meta.json`, versionado, e é conferido **antes**
de o binário virar executável; a comparação é fatal. O descritor declara a
limitação: o checksum publicado pela Snyk vem do **mesmo host** que serve o
binário, então a conferência protege contra corrupção em trânsito e troca
acidental de versão, não contra substituição na origem. É o valor
vendorizado no repositório que move a confiança do host para cá.

`jq` não é conveniência, é dependência de validação. Sem ele o Snyk seria a
única das três cujo raw não é conferido, e SARIF malformado ou vazio viraria
`OK`/`SEM_ACHADOS` gravado, preservado pela idempotência.

## Para que serve a guarda — e o que cada metade pega

O sha256 do artefato é conferido em **dois** momentos, e cada um pega um modo
de falha que o outro não alcança.

**Primeira, no build.** O Dockerfile confere o download contra o
`--build-arg`, antes de usá-lo, e o `ARG` não tem default: build sem ele
falha. Pega download corrompido, asset trocado na origem e `--build-arg`
esquecido.

**Segunda, em runtime** (desde a Fase G-2c). O script compara o
`ENV SNYK_CLI_SHA256` gravado na imagem contra o campo `sha256` de
`snyk-cli.meta.json`, versionado. Pega o caso que a primeira **não**
alcança: o descritor mudou no repositório e ninguém reconstruiu a imagem —
`ARG` e `ENV` congelam no mesmo build e sempre batem entre si.

Divergência é **fatal**. Repositório não montado emite **aviso** no stderr e a
execução **segue**: abortar quebraria execução legítima em contexto sem o
volume. É a mesma disciplina da comparação (2) do pack do Semgrep.

**Alcance, declarado.** A comparação (2) do Semgrep termina em *bytes* dos dois
lados. Esta compara **dois valores declarados**, e não estabelece que `/usr/local/bin/snyk`
ainda corresponde ao hash. Aqui, ao contrário do CodeQL, a comparação em bytes **está disponível e apenas não
foi feita**: o binário conferido no build continua na imagem, e `sha256sum` sobre
ele reproduz o `ENV`. Custaria hashear 178 MiB uma vez por lote e pegaria
bind-mount sobre o CLI em runtime — modo de falha que hoje não tem guarda. É
pendência registrada, não impossibilidade.

## Execução

Exige autenticação. O script espera `SNYK_TOKEN` no ambiente, falha com
mensagem clara se ausente, e nunca o grava em log nem o expõe via `set -x`.

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e XDG_CACHE_HOME=/tmp \
    -e SNYK_TOKEN \
    -v "$PWD":/workspace \
    ic-security-lab-snyk-code datasets/listas/cves-sast-batch-aa
```

Saída bruta em `results/snyk-code/raw/<CVE>.sarif`, log em
`logs/execution-log-snyk-code.csv`.

### Por que `--user` e `HOME` — aqui o `HOME` é obrigatório

Sem `--user`, os artefatos saem com dono root no volume montado. Mas o
`--user` **sozinho** quebra esta imagem: `debian:bookworm-slim` não tem
usuário de uid 1000, `HOME` vira `/`, e o Snyk falha ao gravar configuração.
Medido em 08/09/2026:

```
$ docker run --rm --user 1000:1000 --entrypoint snyk <img> config set foo=bar
 ERROR   Unspecified Error (SNYK-CLI-0000)

$ docker run --rm --user 1000:1000 -e HOME=/tmp --entrypoint snyk <img> config set foo=bar
foo updated
```

Com `HOME=/tmp` o CLI grava em `/tmp/.config/configstore/snyk.json` e em
`/tmp/.cache/snyk/`, ambos fora do volume montado.

**`snyk --version` passa nos dois casos** — é sonda fraca justamente para a
ferramenta que grava estado de usuário. Sondar com um comando que escreva.

## `SEM_ARQUIVO_ANALISAVEL` — exit 3 é resultado, não falha

O exit 3 do Snyk é "nenhum projeto suportado". A análise não quebrou; não há
o que analisar. Registrar como `ERRO_ANALISE` faria a reexecução tentar
indefinidamente e sumiria da leitura de cobertura — o defeito acessório que a
campanha anterior cometeu.

Consequência assumida: a idempotência **não** pula esse CVE, porque não há
raw cuja existência o sinalizasse. Fabricar um SARIF que a ferramenta não
emitiu seria pior. O `tools/check-log.py` conta esses casos como esperados,
não como incoerência.

## Formato da saída

SARIF 2.1.0, como o CodeQL, com diferenças que importam:

- o CWE está em `tool.driver.rules[].properties.cwe[]`, com padding
  inconsistente (`"CWE-94"`), e a resolução é por `ruleId`, nunca por
  `ruleIndex`
- a severidade está no **resultado** (`results[].level`), não só na regra
- `startLine` e `endLine` vêm **sempre ambos**
- `runs[0].properties.coverage[]` permite distinguir "analisou e não achou"
  de "não havia arquivo analisável", e vai íntegro para o `metadata` do
  tratado
- `automationDetails.id` serve como fonte do `analysis_date`

**Não verificado:** se `coverage[]` traz inventário de caminhos ou só
agregado por linguagem, e se `toolExecutionNotifications` é preenchido — o
SARIF admite o campo, admitir não é emitir. O normalizador trata as duas
formas de `coverage` e nunca falha por ausência de notificações; a Fase E
dirá qual ocorre.
