# Semgrep — container de análise SAST

## Pack vendorizado

O conjunto de regras é o `p/default` do registry, **vendorizado**: o YAML
resolvido foi baixado uma vez, versionado aqui e apontado por caminho local.
Nunca `--config=auto` — `auto` é impinável e não é descritível na monografia.

```
rules/semgrep-default.yaml       # o pack, 2 423 491 bytes, 1074 regras
rules/semgrep-default.meta.json  # procedência: sha256, data, contagens
```

O `meta.json` é a fonte do `--build-arg`. Não edite o YAML à mão: qualquer
alteração invalida o sha256 e a guarda de arranque derruba a execução.

### Duas identidades, e por que são duas

| campo | o que identifica |
|---|---|
| `sha256` | o **arquivo** |
| `rules_id_sha256` | o **conjunto de regras**, invariante à ordem |

O endpoint do registry serve o YAML com ordem de regras não determinística:
duas obtenções em 2026-09-06, separadas por 43 minutos, deram bytes
distintos com o mesmo conjunto de 1074 `check_id`. O `sha256` sozinho não
permite verificar, no futuro, se o pack vendorizado corresponde ao que o
registry serve; o `rules_id_sha256` permite.

### Contagem de regras exige parser YAML

`rules_total` é **1074**. Um `grep -c '^- id: '` conta 1073, porque a regra
`terraform.aws.security.aws-provisioner-exec.aws-provisioner-exec` declara
`patterns` antes de `id`. Nunca conte regras com grep.

## Build

O `PACK_SHA256` é **obrigatório** e vem do `meta.json`:

```bash
cd ic-security-lab-semgrep
docker build -t ic-security-lab-semgrep \
    --build-arg PACK_SHA256="$(jq -r .sha256 rules/semgrep-default.meta.json)" .
```

O build context é este diretório, sem `-f`. O `COPY` só alcança o context —
é por isso que o pack mora aqui dentro, e não em `rules/` na raiz do
repositório.

### Para que serve a guarda — e o que cada metade pega

O pack existe em dois lugares: versionado no repositório e assado na imagem
pelo `COPY`. O `run_semgrep.sh` faz **duas** comparações no arranque, e são
duas porque uma sozinha não basta.

**Primeira: `/default.yaml` contra `$PACK_SHA256`.** Pega `--build-arg`
errado, `meta.json` dessincronizado do YAML no momento do build, e
bind-mount sobre `/default.yaml` em runtime.

Ela **não** pega o arquivo do repositório mudar sem rebuild. Os dois lados
congelam no mesmo build — o `COPY` e o `ARG`/`ENV` — então a imagem antiga
continua com o arquivo antigo *e* com o hash antigo, os dois batem, e a
guarda passa enquanto a execução usa regras que o `meta.json` do repositório
já não descreve. Uma versão anterior deste README afirmava o contrário.

**Segunda: `/default.yaml` contra o pack do repositório montado**, em
`$WORKSPACE/ic-security-lab-semgrep/rules/semgrep-default.yaml`. É esta que
detecta imagem obsoleta, e ela existe porque a primeira não conseguia.

Se o workspace não estiver montado nesse caminho, a segunda comparação é
pulada com aviso no stderr, em vez de falhar.

## Execução

```bash
docker run --rm -v "$PWD":/workspace ic-security-lab-semgrep \
    datasets/listas/cves-sast-batch-aa
```

O argumento é o lote, relativo ao workspace montado. Sem argumento, roda a
lista completa (`datasets/listas/cves-sast.txt`).

Saída bruta em `results/semgrep/raw/<CVE>.json`, log em
`logs/execution-log-semgrep.csv`. O laço é idempotente: CVE cujo raw já
existe é registrado como `PULADO`.

Não exige autenticação nem rede — com o pack local não há requisição ao
registry. Verificável com `--network=none`.

## Armadilha do prefixo — o pack vai na raiz

O Semgrep prefixa o `check_id` com o nome do diretório que contém o YAML:

```
--config=/packs/default.yaml  →  packs.javascript.lang.security…
--config=/default.yaml        →  javascript.lang.security…        ← correto
```

Medido com o Semgrep 1.171.0; registrado em `prefix_verification` no
`meta.json`. Por isso o `COPY` leva o pack para `/default.yaml`, na raiz do
sistema de arquivos do container. Montado em subdiretório, os
identificadores divergiriam dos do registry e da campanha anterior, e a
comparação quebraria **em silêncio**.
