#!/usr/bin/env bash
#
# obter-catalogos.sh — materializa, em estado FIXADO, os catálogos de que a
# apuração de proveniência depende. Sem isto, o cotejo não é reproduzível
# por terceiro: dependeria de clones que só existem na máquina de quem
# apurou.
#
# Uso:
#   tools/ground-truth/obter-catalogos.sh <diretorio-destino>
#
# Grava:
#   <destino>/codeql-2020/javascript/ql/src        consultas JS em commit_2020
#   <destino>/codeql-2020-12-11/javascript/ql/src  consultas JS no main após o PR #4778
#   <destino>/codeql-atual/javascript/ql/src       consultas JS no commit "atual"
#   <destino>/semgrep-rules                        catálogo do Semgrep
#
# O segundo estado NÃO é âncora alternativa escolhida: é o que mede a
# sensibilidade do resultado à data de corte dentro de dezembro de 2020.
# Ver README.md e proveniencia.meta.json.
#
# Os commits estão em proveniencia.meta.json, versionado, e são os mesmos que
# o README cita. Não há valor digitado duas vezes.
#
# MÉTODO: fetch raso por SHA, com sparse-checkout e `--filter=blob:none`.
# É a mesma técnica que os scripts de análise usam, e pelo mesmo motivo:
# o GitHub aceita fetch raso por SHA arbitrário, e o clone completo do
# github/codeql seria de vários GB para ler algumas centenas de arquivos.
# Medido em 12/09/2026: o fetch do commit de 2020 leva ~1 s.
#
# Sem `set -e`: falha em um catálogo deve ser reportada com nome, não
# derrubar a obtenção dos outros em silêncio.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESCRITOR="$RAIZ/tools/ground-truth/proveniencia.meta.json"

DESTINO="${1:-}"
if [ -z "$DESTINO" ]; then
    echo "Uso: $0 <diretorio-destino>" >&2
    exit 1
fi
if [ ! -f "$DESCRITOR" ]; then
    echo "ERRO: descritor ausente: $DESCRITOR" >&2
    exit 1
fi
# Destino resolvido para absoluto UMA vez, antes de qualquer obtenção. Com
# caminho relativo e `cd` dentro de obter(), o segundo catálogo ia parar
# dentro do primeiro, e o `rm -rf` incidia lá.
if ! mkdir -p "$DESTINO" || ! DESTINO="$(cd "$DESTINO" && pwd)"; then
    echo "ERRO: nao foi possivel criar ou resolver o destino $1" >&2
    exit 1
fi

ler() {  # ler <caminho.de.chaves>
    python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2].split("."):
    d = d[k]
print(d)' "$DESCRITOR" "$1"
}

FALHAS=0

obter() {  # obter <rotulo> <url> <sha> <subcaminho> <destino-absoluto>
    local rotulo="$1" url="$2" sha="$3" sub="$4" dir="$5"
    echo "--- $rotulo: $sha"
    # Valor vazio vem de chave ausente no descritor; o traceback do python
    # já foi ao stderr, e seguir faria um fetch de SHA vazio.
    if [ -z "$url" ] || [ -z "$sha" ] || [ -z "$sub" ]; then
        echo "ERRO: url, commit ou subcaminho vazio para $rotulo" >&2
        FALHAS=$((FALHAS + 1)); return 1
    fi
    rm -rf "$dir"
    # `git -C`, nunca `cd`: o diretório corrente do script não muda, nem no
    # caminho de erro. Cada passo é conferido: com `git init` falho e destino
    # dentro de outro repositório, `remote add` e `config` cairiam no
    # repositório envolvente.
    if ! mkdir -p "$dir" \
            || ! git -C "$dir" init -q . \
            || ! git -C "$dir" remote add origin "$url" \
            || ! git -C "$dir" config core.sparseCheckout true \
            || ! printf '%s\n' "$sub" > "$dir/.git/info/sparse-checkout"; then
        echo "ERRO: preparacao do repositorio falhou em $dir" >&2
        FALHAS=$((FALHAS + 1)); return 1
    fi
    # stderr do git NUNCA vai para /dev/null: descartaria a razão da falha.
    if ! GIT_TERMINAL_PROMPT=0 timeout 900 git -C "$dir" fetch -q --depth 1 \
            --filter=blob:none origin "$sha" < /dev/null; then
        echo "ERRO: fetch raso de $sha em $url falhou" >&2
        FALHAS=$((FALHAS + 1)); return 1
    fi
    # O checkout também é rede: com `--filter=blob:none` os blobs do
    # sparse-checkout são buscados sob demanda. Mesmo limite de tempo e mesma
    # proteção contra prompt que o fetch.
    if ! GIT_TERMINAL_PROMPT=0 timeout 900 git -C "$dir" checkout -q FETCH_HEAD \
            < /dev/null; then
        echo "ERRO: checkout de FETCH_HEAD falhou em $dir" >&2
        FALHAS=$((FALHAS + 1)); return 1
    fi
    # Asserção do commit, pelo mesmo motivo que os scripts de análise a
    # fazem: boa formação de SHA não garante que o objeto seja um commit,
    # e um objeto de tag anotada atravessaria fetch e checkout em silêncio.
    local head_real
    head_real="$(git -C "$dir" rev-parse HEAD)"
    if [ "$head_real" != "$sha" ]; then
        echo "ERRO: HEAD $head_real nao e o commit pedido $sha" >&2
        FALHAS=$((FALHAS + 1)); return 1
    fi
    echo "    HEAD conferido | commit de $(git -C "$dir" log -1 --format=%cI)"
    return 0
}

obter "CodeQL commit_2020" \
    "$(ler codeql.url)" "$(ler codeql.commit_2020)" \
    "$(ler codeql.subcaminho)" "$DESTINO/codeql-2020"
obter "CodeQL main 11/12/2020 (PR #4778)" \
    "$(ler codeql.url)" "$(ler codeql.commit_2020_12_11)" \
    "$(ler codeql.subcaminho)" "$DESTINO/codeql-2020-12-11"
obter "CodeQL atual" \
    "$(ler codeql.url)" "$(ler codeql.commit_atual)" \
    "$(ler codeql.subcaminho)" "$DESTINO/codeql-atual"
obter "semgrep-rules" \
    "$(ler semgrep.url)" "$(ler semgrep.commit)" \
    "$(ler semgrep.subcaminho)" "$DESTINO/semgrep-rules"

if [ "$FALHAS" -gt 0 ]; then
    echo "ERRO: $FALHAS catalogo(s) nao foram obtidos." >&2
    exit 1
fi
echo "OK: catalogos em $DESTINO"
