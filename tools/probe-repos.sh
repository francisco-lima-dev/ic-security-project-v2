#!/usr/bin/env bash
#
# probe-repos.sh — sonda a acessibilidade dos repositórios distintos do
# conjunto SAST e grava a observação, datada, em datasets/sondagens/.
#
# Uso:
#   tools/probe-repos.sh [--lista ARQ] [--saida ARQ] [--jobs N]
#                        [--timeout SEG] [--force]
#
# A metodologia (Seção 4.3) promete sondagem datada IMEDIATAMENTE ANTES de
# cada campanha, e a Seção 9.2 a trata como evidência versionada das
# exclusões por indisponibilidade. Este script é o procedimento; o arquivo
# que ele grava é a observação.
#
# ESCOPO ESTRITO. Sonda, registra e conta por status. Não decide o que
# fazer com repositório inacessível, não cruza com o ground truth, não
# recomenda exclusão: isso é leitura de resultado, e leitura de resultado
# envelhece — a sondagem, não.
#
# O que é sondado: `git ls-remote --exit-code <url> HEAD`, exatamente a
# operação de que o pipeline depende (leitura anônima do remoto). Sondar
# com HTTP HEAD na página do projeto responderia outra pergunta: repositório
# pode existir na web e recusar clone anônimo, e o inverso vale para
# redirecionamento de organização renomeada.
#
# ANONIMATO — NÃO É DETALHE.
# A sondagem roda com GIT_CONFIG_GLOBAL e GIT_CONFIG_SYSTEM apontando para
# /dev/null, e com `-c credential.helper=` explícito. Sem isso o git do
# hospedeiro usa o credential helper configurado — nesta máquina
# `!/usr/bin/gh auth git-credential`, que é NÃO-INTERATIVO e portanto não é
# barrado por GIT_TERMINAL_PROMPT=0. Um repositório privado, ou visível
# apenas à conta do operador, sairia ACESSIVEL aqui e daria ERRO_FETCH na
# campanha: precisamente a divergência que a sondagem existe para
# antecipar. O mesmo vale para `url.<base>.insteadOf`, que reescreveria a
# URL em silêncio. O ambiente sondado passa a ser o do container, que não
# herda config do hospedeiro.
# Custo assumido: proxy declarado no gitconfig do hospedeiro também se
# perde. É o preço de medir o que a campanha vai encontrar.
#
# NÃO é sondada a existência do PrePatchCommit de cada CVE. Isso exigiria
# fetch por SHA em 223 commits, é o que a campanha faz de todo modo, e o
# resultado apareceria no log de execução como ERRO_FETCH. Aqui a unidade é
# o repositório, e são 186.
#
# Status gravados:
#   ACESSIVEL     ls-remote respondeu e HEAD existe; detalhe traz o sha
#   SEM_HEAD      remoto respondeu, mas sem ref HEAD (repositório vazio)
#   TIMEOUT       excedeu o limite por repositório, nas duas tentativas
#   INACESSIVEL   git falhou; detalhe traz a linha de erro do stderr
#
# DUAS TENTATIVAS para tudo que não seja 0 ou 2. São 186 conexões anônimas
# em paralelo: reset de TCP, hiccup de DNS ou throttling do servidor cairiam
# no mesmo status de repositório removido, e este arquivo é o que sustenta a
# queda de denominador (222 → 221). A coluna `tentativas` diz quantas foram
# gastas, para que falha persistente e falha transitória não se confundam na
# leitura.
#
# DIFFABILIDADE — o que é e o que não é.
# As linhas saem ordenadas por URL, com LC_ALL=C, para que duas sondagens
# sejam comparáveis. Mas três das seis colunas mudam a cada execução por
# construção: `sondado_em`, `duracao_segundos` e o `HEAD=<sha>` dentro de
# `detalhe`, que avança sempre que o branch padrão avança. Um `diff` cru
# entre duas sondagens marca todas as linhas. O par estável é
# (repo_url, status), e o diff útil é:
#
#   diff <(cut -d, -f2,3 sondagem-A.csv) <(cut -d, -f2,3 sondagem-B.csv)
#
# Sem `set -e`: repositório que falha é o resultado que se quer medir, não
# acidente que deva derrubar a sondagem.
set -uo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LISTA="$RAIZ/datasets/listas/cves-sast.txt"
SAIDA=""
JOBS=8
TIMEOUT_REPO=60
FORCE=0

DATA_ARQUIVO="$(date -u '+%Y-%m-%d')"
SONDADO_EM="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

exigir_valor() {
    if [ "$2" -lt 2 ]; then
        echo "ERRO: $1 exige um valor." >&2
        exit 2
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --lista)   exigir_valor "$1" $#; LISTA="$2"; shift 2 ;;
        --saida)   exigir_valor "$1" $#; SAIDA="$2"; shift 2 ;;
        --jobs)    exigir_valor "$1" $#; JOBS="$2"; shift 2 ;;
        --timeout) exigir_valor "$1" $#; TIMEOUT_REPO="$2"; shift 2 ;;
        --force)   FORCE=1; shift ;;
        -h|--help)
            # Imprime o cabeçalho até a primeira linha que não é comentário,
            # em vez de uma faixa fixa que envelhece a cada edição.
            sed -n '2,/^[^#]/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo "ERRO: argumento desconhecido: $1" >&2
            exit 2 ;;
    esac
done

[ -n "$SAIDA" ] || SAIDA="$RAIZ/datasets/sondagens/sondagem-repos-$DATA_ARQUIVO.csv"

for n in "$JOBS" "$TIMEOUT_REPO"; do
    if ! [[ "$n" =~ ^[1-9][0-9]*$ ]]; then
        echo "ERRO: --jobs e --timeout exigem inteiro positivo; recebido: $n" >&2
        exit 2
    fi
done

# Dependência ausente produziria 186 INACESSIVEL — evidência plausível,
# completa e falsa, que passaria pela guarda de contagem e seria gravada.
for dep in git timeout mktemp xargs; do
    if ! command -v "$dep" > /dev/null 2>&1; then
        echo "ERRO: dependencia ausente no PATH: $dep" >&2
        exit 1
    fi
done

if [ ! -f "$LISTA" ]; then
    echo "ERRO: lista nao encontrada: $LISTA" >&2
    exit 1
fi

# Sondagem do mesmo dia não é sobrescrita em silêncio: o arquivo é evidência
# datada, e a segunda execução do dia pode ter sido acidente.
if [ -e "$SAIDA" ] && [ "$FORCE" -ne 1 ]; then
    echo "ERRO: $SAIDA ja existe. Use --force para regravar." >&2
    exit 1
fi

mkdir -p "$(dirname "$SAIDA")" || exit 1

# Resíduo de execução morta por SIGKILL vive no diretório de saída, que o
# .gitignore desprotege (`!datasets/**`): ficaria untracked e commitável por
# acidente. Mesma regra dos scripts de análise — remoção incondicional antes
# de produzir o artefato desta execução.
rm -f "${SAIDA}".emprogresso.* 2> /dev/null

# --- repositórios distintos ----------------------------------------------
# Campo 2 da lista de seis campos. A invariante "nenhum campo contém
# vírgula" é o que torna o cut suficiente; o filtro de esquema pega o resto,
# porque linha malformada produziria valor truncado que seria sondado e
# contado como INACESSIVEL, indistinguível de indisponibilidade real.
TODAS="$(cut -d',' -f2 "$LISTA" | sed '/^[[:space:]]*$/d' | LC_ALL=C sort -u)"
URLS="$(printf '%s\n' "$TODAS" | grep -E '^(https?://|git@)' )"
DESCARTADAS="$(printf '%s\n' "$TODAS" | grep -cvE '^(https?://|git@)')"

if [ -z "$URLS" ]; then
    echo "ERRO: nenhuma URL valida extraida de $LISTA (campo 2 vazio ou malformado?)" >&2
    exit 1
fi
if [ "$DESCARTADAS" -gt 0 ]; then
    echo "AVISO: $DESCARTADAS valor(es) do campo 2 sem esquema de URL; descartados." >&2
    printf '%s\n' "$TODAS" | grep -vE '^(https?://|git@)' | sed 's/^/  /' >&2
fi

TOTAL="$(printf '%s\n' "$URLS" | wc -l)"
echo "Lista:          $LISTA" >&2
echo "Repositorios:   $TOTAL distintos" >&2
echo "Paralelismo:    $JOBS   Timeout: ${TIMEOUT_REPO}s por repositorio" >&2
echo "Sondado em:     $SONDADO_EM" >&2
echo "Ambiente git:   anonimo (GIT_CONFIG_GLOBAL/SYSTEM=/dev/null; credential.helper vazio)" >&2

# --- sonda de um repositório ---------------------------------------------
# Exportada porque roda sob xargs, em subshell próprio.
sondar_um() {
    local url="$1"
    local inicio dur rc saida_git err sha status detalhe tentativa ferr redirecionou

    inicio=$SECONDS
    redirecionou=""
    rc=0
    saida_git=""
    err=""

    for tentativa in 1 2; do
        ferr="$(mktemp)" || { echo "ERRO: mktemp falhou" >&2; return 1; }

        # stderr é capturado, nunca descartado: é a razão da falha, e vai
        # para a coluna detalhe.
        #
        # GIT_CONFIG_GLOBAL/SYSTEM=/dev/null e credential.helper vazio: ver
        # a nota de ANONIMATO no cabeçalho. Sem isso a sondagem mede o
        # acesso DO OPERADOR, não o acesso anônimo que a campanha terá.
        saida_git="$(GIT_TERMINAL_PROMPT=0 \
            GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
            timeout "$TIMEOUT_REPO" \
            git -c credential.helper= ls-remote --exit-code "$url" HEAD 2>"$ferr")"
        rc=$?

        # A primeira linha do stderr costuma ser ruído — tipicamente
        # `warning: redirecting to …`, que é justamente o caso de
        # organização renomeada. Preferir a linha que diz a causa, e só
        # cair na primeira quando não houver nenhuma.
        err="$(grep -m1 -E '^(fatal|error|remote):' "$ferr")"
        [ -n "$err" ] || err="$(head -n 1 "$ferr")"
        # Redirecionamento em resposta BEM-SUCEDIDA é informação material: o
        # repositório respondeu, mas mudou de dono ou de nome.
        if grep -qi 'redirecting to' "$ferr"; then
            redirecionou="$(grep -m1 -i 'redirecting to' "$ferr")"
        fi
        rm -f "$ferr"

        # 0 e 2 são vereditos do servidor, não acidentes: não se repetem.
        case "$rc" in 0|2) break ;; esac
        [ "$tentativa" -eq 2 ] && break
        sleep 2
    done

    dur=$((SECONDS - inicio))

    case "$rc" in
        0)
            status="ACESSIVEL"
            sha="$(printf '%s' "$saida_git" | head -n 1 | cut -f1)"
            detalhe="HEAD=$sha"
            [ -n "$redirecionou" ] && detalhe="$detalhe; $redirecionou"
            ;;
        2)
            # --exit-code: 2 = respondeu, nenhuma ref casou com HEAD.
            status="SEM_HEAD"
            detalhe="remoto respondeu sem ref HEAD"
            ;;
        124)
            status="TIMEOUT"
            detalhe="excedeu ${TIMEOUT_REPO}s"
            ;;
        *)
            status="INACESSIVEL"
            detalhe="git rc=$rc: ${err:-sem stderr}"
            ;;
    esac

    # Nenhum campo pode conter vírgula: o arquivo é CSV lido com cut/read,
    # como as listas de entrada. Quebras de linha idem.
    detalhe="${detalhe//,/;}"
    detalhe="${detalhe//$'\n'/ }"
    detalhe="${detalhe//$'\r'/ }"

    printf '%s,%s,%s,%s,%s,%s\n' \
        "$SONDADO_EM" "$url" "$status" "$detalhe" "$tentativa" "$dur"
}
export -f sondar_um
export SONDADO_EM TIMEOUT_REPO

# --- execução -------------------------------------------------------------
# Escrita atômica: o arquivo definitivo só aparece completo. Sondagem
# interrompida no meio não deixa evidência truncada com cara de completa.
PARCIAL="$(mktemp "${SAIDA}.emprogresso.XXXXXX")" || {
    echo "ERRO: mktemp falhou em $(dirname "$SAIDA")" >&2
    exit 1
}
trap 'rm -f "$PARCIAL"' EXIT

{
    echo "sondado_em,repo_url,status,detalhe,tentativas,duracao_segundos"
    # LC_ALL=C: a ordenação existe para o arquivo ser comparável contra a
    # sondagem anterior, e sob outro LC_COLLATE a pontuação é ponderada de
    # outro jeito — duas sondagens em ambientes distintos difeririam por
    # reordenação inteira, sem que nada tenha mudado.
    printf '%s\n' "$URLS" \
        | xargs -r -P "$JOBS" -I{} bash -c 'sondar_um "$@"' _ {} \
        | LC_ALL=C sort -t',' -k2,2
} > "$PARCIAL"

LINHAS="$(($(wc -l < "$PARCIAL") - 1))"
if [ "$LINHAS" -ne "$TOTAL" ]; then
    # Preservado sob nome de incompleto, não removido: 185 sondagens boas
    # jogadas fora por um fork que não vingou não deixariam material de
    # diagnóstico. O sufixo não casa com *.csv nem com os globs do
    # normalizador.
    INCOMPLETO="${SAIDA}.incompleto"
    mv -f "$PARCIAL" "$INCOMPLETO"
    trap - EXIT
    echo "ERRO: sondou $LINHAS de $TOTAL repositorios; saida NAO gravada." >&2
    echo "  parcial preservado em $INCOMPLETO" >&2
    exit 1
fi

mv -f "$PARCIAL" "$SAIDA" || exit 1
trap - EXIT
# mktemp cria 0600; o resto de datasets/ é 0644. O git não versiona o modo,
# mas o arquivo é lido no hospedeiro.
chmod 644 "$SAIDA"

# --- contagem por status --------------------------------------------------
# Contagem, não leitura: quem sonda precisa ver na hora se algo mudou.
echo >&2
echo "Gravado: $SAIDA" >&2
tail -n +2 "$SAIDA" | cut -d',' -f3 | LC_ALL=C sort | uniq -c | sort -rn >&2
REPETIDOS="$(tail -n +2 "$SAIDA" | awk -F',' '$5 != "1"' | wc -l)"
echo "  repositorios que exigiram segunda tentativa: $REPETIDOS" >&2
echo >&2
NAO_ACESSIVEIS="$(tail -n +2 "$SAIDA" | awk -F',' '$3 != "ACESSIVEL"')"
if [ -n "$NAO_ACESSIVEIS" ]; then
    echo "Nao acessiveis:" >&2
    printf '%s\n' "$NAO_ACESSIVEIS" | awk -F',' '{printf "  %-58s %s  %s (tentativas: %s)\n", $2, $3, $4, $5}' >&2
fi
