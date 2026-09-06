#!/usr/bin/env bash
#
# run_semgrep.sh — roda o Semgrep sobre os CVEs de um lote do OpenSSF CVE
# Benchmark, produzindo APENAS a saída bruta. A normalização para o schema
# comum é um passo separado, fora do container.
#
# Uso, dentro do container:
#   run_semgrep.sh [caminho-da-lista]
# O caminho é relativo ao workspace montado, ou absoluto. Sem argumento,
# usa a lista completa.
#
# Log estruturado em logs/execution-log-<ferramenta>.csv, uma linha por CVE:
#   cve,repo,commit,status,mensagem,duracao_segundos
# Nenhum campo pode conter vírgula.
#
# A coluna `commit` é o PrePatchCommit da lista, e o script ASSERTA que o
# HEAD analisado é esse commit antes de rodar a ferramenta. A mensagem
# registra "HEAD conferido" para que o log seja evidência por si só, sem
# depender de quem o lê saber qual versão deste script produziu a linha.
#
# Reexecução acrescenta uma linha PULADO por CVE já feito. O log não tem
# timestamp nem id de execução: quem o consumir deve deduplicar por CVE
# mantendo a última linha.
#
# Status que este script emite:
#   OK             analisou e reportou pelo menos um achado
#   SEM_ACHADOS    analisou e não reportou nada. O raw fica gravado com a
#                  lista de achados vazia, para distinguir de "não analisou"
#   PULADO         o raw já existia; a idempotência avançou sem reanalisar
#   ERRO_LINHA     linha malformada na lista de entrada
#   ERRO_FETCH     não obteve o código no commit do ground truth
#   ERRO_CHECKOUT  obteve o código mas não fixou o commit, ou o HEAD
#                  resultante não é o PrePatchCommit
#   ERRO_ANALISE   a ferramenta falhou, estourou o tempo ou produziu saída
#                  ilegível. O raw parcial é removido para que a reexecução
#                  tente de novo
#
# Sem `set -e`: o laço tem de sobreviver a CVE que falha, e códigos de
# saída não-zero das ferramentas são dado, não acidente.
set -uo pipefail

FERRAMENTA="semgrep"
WORKSPACE="${WORKSPACE:-/workspace}"
PACK="/default.yaml"
PACK_REPO="$WORKSPACE/ic-security-lab-semgrep/rules/semgrep-default.yaml"

# PROVISÓRIO. Sem dado de duração — que só a Fase E produz — qualquer limite
# é chute, e um valor curto demais transformaria análise legítima de
# repositório grande em ERRO_ANALISE sistemático. Generoso de propósito.
# Revisar depois de medir.
TIMEOUT_ANALISE=1800

LISTA_ARG="${1:-datasets/listas/cves-sast.txt}"
case "$LISTA_ARG" in
    /*) LISTA="$LISTA_ARG" ;;
    *)  LISTA="$WORKSPACE/$LISTA_ARG" ;;
esac

RAW_DIR="$WORKSPACE/results/$FERRAMENTA/raw"
LOG_DIR="$WORKSPACE/logs"
LOG="$LOG_DIR/execution-log-$FERRAMENTA.csv"

WORKDIR=""

limpar() {
    cd /tmp
    if [ -n "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
        WORKDIR=""
    fi
}

# O handler tem de SAIR. `trap limpar INT TERM` apenas rodaria limpar e o
# bash retomaria no comando seguinte: o laço continuaria, e o log ganharia
# linhas de erro para CVEs jamais tentados.
limpar_e_sair() {
    echo "AVISO: sinal recebido; encerrando o lote apos limpar." >&2
    limpar
    exit 130
}
trap limpar EXIT
trap limpar_e_sair INT TERM

# --- guarda do pack vendorizado ------------------------------------------
if [ -z "${PACK_SHA256:-}" ]; then
    echo "ERRO: PACK_SHA256 nao definido." >&2
    echo "  Construa a imagem com --build-arg PACK_SHA256=<hash do pack>" >&2
    exit 1
fi
if [ ! -f "$PACK" ]; then
    echo "ERRO: pack vendorizado ausente em $PACK" >&2
    exit 1
fi
PACK_ATUAL=$(sha256sum "$PACK" | cut -d' ' -f1)

# Primeira comparação: o pack da imagem contra o hash do build. Pega
# --build-arg errado e bind-mount sobre /default.yaml em runtime.
if [ "$PACK_ATUAL" != "$PACK_SHA256" ]; then
    echo "ERRO: pack em $PACK nao corresponde ao PACK_SHA256 do build" >&2
    echo "  esperado: $PACK_SHA256" >&2
    echo "  obtido:   $PACK_ATUAL" >&2
    exit 1
fi

# Segunda comparação: o pack da imagem contra o pack do repositório montado.
# Esta é a que pega imagem obsoleta — o arquivo versionado mudou e ninguém
# reconstruiu. As duas primeiras grandezas congelam no mesmo build e sempre
# batem entre si, logo a primeira comparação sozinha NÃO detecta esse caso.
if [ -f "$PACK_REPO" ]; then
    PACK_REPO_SHA=$(sha256sum "$PACK_REPO" | cut -d' ' -f1)
    if [ "$PACK_REPO_SHA" != "$PACK_ATUAL" ]; then
        echo "ERRO: a imagem esta obsoleta em relacao ao pack do repositorio" >&2
        echo "  na imagem:      $PACK_ATUAL" >&2
        echo "  no repositorio: $PACK_REPO_SHA" >&2
        echo "  Reconstrua a imagem com --build-arg PACK_SHA256=\$(jq -r .sha256 rules/semgrep-default.meta.json)" >&2
        exit 1
    fi
else
    echo "AVISO: $PACK_REPO ausente; nao foi possivel conferir a imagem" >&2
    echo "  contra o pack do repositorio. O workspace esta montado?" >&2
fi

# --- pré-condições --------------------------------------------------------
if [ ! -f "$LISTA" ]; then
    echo "ERRO: lista nao encontrada: $LISTA" >&2
    exit 1
fi
mkdir -p "$RAW_DIR" "$LOG_DIR" || exit 1
if [ ! -s "$LOG" ]; then
    echo "cve,repo,commit,status,mensagem,duracao_segundos" > "$LOG"
fi

VERSAO_SEMGREP=$(semgrep --version | tail -n 1)
if [ -z "$VERSAO_SEMGREP" ]; then
    # Não aborta, mas grita: falha ao capturar a versão em imagem
    # recém-construída indica binário quebrado, e quem acompanha a
    # execução tem de ver na hora.
    VERSAO_SEMGREP="VERSAO_NAO_CAPTURADA"
    echo "AVISO: nao foi possivel capturar a versao do semgrep" >&2
fi
VERSAO_PENDENTE="semgrep $VERSAO_SEMGREP; pack sha256 $PACK_ATUAL"

# --- log estruturado ------------------------------------------------------
registrar() {
    local cve="$1" repo="$2" commit="$3" status="$4" msg="$5" dur="$6"
    cve="${cve//,/;}";  repo="${repo//,/;}";  commit="${commit//,/;}"
    msg="${msg//,/;}";  msg="${msg//$'\n'/ }"; msg="${msg//$'\r'/ }"
    if [ -n "$VERSAO_PENDENTE" ]; then
        msg="$VERSAO_PENDENTE${msg:+; $msg}"
        VERSAO_PENDENTE=""
    fi
    printf '%s,%s,%s,%s,%s,%s\n' \
        "$cve" "$repo" "$commit" "$status" "$msg" "$dur" >> "$LOG"
}

# --- laço -----------------------------------------------------------------
NUM_LINHA=0
# A lista é lida no fd 3, não no stdin: em `done < "$LISTA"` toda ferramenta
# e todo git herdam a lista no fd 0, e um filho que leia stdin engoliria
# linhas do lote — CVEs sumindo sem linha nenhuma no log.
#
# O `|| [ -n "$CVE_ID" ]` cobre arquivo sem quebra de linha final: sem ele
# a última linha do lote seria descartada em silêncio.
while IFS=',' read -r CVE_ID REPO_URL COMMIT CWES FILEPATH FILELINE <&3 || [ -n "${CVE_ID:-}" ]; do
    NUM_LINHA=$((NUM_LINHA + 1))
    CVE_ID="${CVE_ID%$'\r'}"
    [ -z "${CVE_ID// /}" ] && continue
    case "$CVE_ID" in \#*) continue ;; esac

    # Defesa em profundidade contra linha malformada. A invariante "nenhum
    # campo contém vírgula" é garantida pelo gerador; isto pega o resto.
    if ! [[ "$CVE_ID" =~ ^CVE-[0-9]{4}-[0-9]+$ ]]; then
        registrar "$CVE_ID" "${REPO_URL:-}" "${COMMIT:-}" "ERRO_LINHA" \
            "identificador de CVE invalido na linha $NUM_LINHA" 0
        continue
    fi
    if ! [[ "${COMMIT:-}" =~ ^[0-9a-fA-F]{40}$ ]]; then
        registrar "$CVE_ID" "${REPO_URL:-}" "${COMMIT:-}" "ERRO_LINHA" \
            "commit sem 40 hex na linha $NUM_LINHA" 0
        continue
    fi

    SAIDA="$RAW_DIR/$CVE_ID.json"
    # Nome do temporário, deliberado em duas frentes: ponto inicial, que
    # esconde de glob `*` em bash e no glob do Python; e sufixo .tmp, que
    # não casa com `*.json` nem `*.sarif`. Órfão deste arquivo nunca pode
    # ser confundido com raw pelo normalizador.
    PARCIAL="$RAW_DIR/.em-progresso-$CVE_ID.tmp"

    # Órfão de execução morta por SIGKILL vive no volume montado, onde o
    # handler não alcançou. Remoção incondicional aqui dá comportamento
    # definido para ele, antes de qualquer decisão sobre este CVE.
    rm -f "$PARCIAL"

    # Idempotência: verifica o RAW, não o normalizado.
    if [ -f "$SAIDA" ]; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "PULADO" \
            "saida bruta ja existe" 0
        continue
    fi

    INICIO=$SECONDS
    MENSAGEM=""

    # --- obtenção do código no commit vulnerável --------------------------
    # PrePatchCommit, nunca HEAD nem PostPatchCommit: no HEAD o CVE já está
    # corrigido e a comparação com o ground truth se invalida.
    # Diretório de trabalho FORA do volume montado.
    WORKDIR="/tmp/src-$CVE_ID"
    rm -rf "$WORKDIR"
    if ! mkdir -p "$WORKDIR" || ! cd "$WORKDIR"; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
            "nao foi possivel criar $WORKDIR" $((SECONDS - INICIO))
        limpar
        continue
    fi

    if ! git init -q .; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
            "git init falhou em $WORKDIR" $((SECONDS - INICIO))
        limpar
        continue
    fi
    if ! git remote add origin "$REPO_URL"; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
            "git remote add falhou" $((SECONDS - INICIO))
        limpar
        continue
    fi

    # stderr do git NUNCA vai para /dev/null: descartaria a razão da falha.
    if GIT_TERMINAL_PROMPT=0 timeout 300 git fetch -q --depth 1 origin "$COMMIT" < /dev/null; then
        REF="FETCH_HEAD"
    else
        echo "[$CVE_ID] fetch raso falhou; tentando clone completo" >&2
        MENSAGEM="fallback de clone completo"
        if ! cd /tmp; then
            registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
                "nao foi possivel voltar para /tmp" $((SECONDS - INICIO))
            limpar
            continue
        fi
        rm -rf "$WORKDIR"
        # --no-single-branch explícito: é o default em clone não-raso, mas a
        # config clone.defaultSingleBranch o inverteria, e commit em branch
        # não-padrão ocorre neste dataset (quatro CVEs do bootstrap vivem só
        # em v3-dev). Sem isto, falha parcial e silenciosa.
        if ! GIT_TERMINAL_PROMPT=0 timeout 900 git clone -q --no-single-branch "$REPO_URL" "$WORKDIR" < /dev/null; then
            registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
                "fetch raso e clone completo falharam" $((SECONDS - INICIO))
            limpar
            continue
        fi
        if ! cd "$WORKDIR"; then
            registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
                "clone completo nao produziu $WORKDIR" $((SECONDS - INICIO))
            limpar
            continue
        fi
        REF="$COMMIT"
    fi

    if ! git checkout -q "$REF"; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_CHECKOUT" \
            "checkout de $REF falhou${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi

    # Asserção do PrePatchCommit. Esta é a invariante cuja violação
    # invalidou a campanha anterior inteira, e até aqui a garantia dependia
    # da semântica do FETCH_HEAD, não de evidência.
    HEAD_REAL=$(git rev-parse HEAD)
    if [ "$HEAD_REAL" != "$COMMIT" ]; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_CHECKOUT" \
            "HEAD $HEAD_REAL nao e o PrePatchCommit${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi
    MENSAGEM="HEAD conferido${MENSAGEM:+; $MENSAGEM}"

    # --- análise ----------------------------------------------------------
    # Config local, nunca --config=auto. Sem filtro de severidade e sem
    # exclusão de caminho.
    #
    # Escreve no temporário e só promove ao nome final depois de validar:
    # raw truncado gravado direto no nome final sobreviveria a SIGKILL e a
    # idempotência o leria como análise concluída, para sempre.
    timeout "$TIMEOUT_ANALISE" semgrep scan \
        --config="$PACK" \
        --json \
        --time \
        --metrics=off \
        --output="$PARCIAL" \
        . < /dev/null
    RC=$?

    if [ "$RC" -eq 124 ]; then
        rm -f "$PARCIAL"
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "semgrep excedeu ${TIMEOUT_ANALISE}s${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi
    if [ "$RC" -ge 2 ] || [ ! -f "$PARCIAL" ]; then
        rm -f "$PARCIAL"
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "semgrep saiu com $RC${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi

    ACHADOS=$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(len(json.load(f).get("results", [])))
except Exception:
    print(-1)
' "$PARCIAL" 2>/dev/null)
    # Valor não numérico é tratado como saída ilegível, nunca gravado no
    # log: `[ "$ACHADOS" -lt 0 ]` erraria com string crua, a execução cairia
    # no else e registraria OK com lixo na coluna de contagem — corrupção
    # silenciosa exatamente no campo que explica ausências no conjunto de
    # resultados.
    if ! [[ "$ACHADOS" =~ ^-?[0-9]+$ ]]; then
        ACHADOS=-1
    fi

    if [ "$ACHADOS" -lt 0 ]; then
        rm -f "$PARCIAL"
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "saida do semgrep ilegivel como JSON${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi

    # mv no mesmo diretório é atômico: ou o raw existe íntegro, ou não existe.
    if ! mv -f "$PARCIAL" "$SAIDA"; then
        rm -f "$PARCIAL"
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "falha ao promover a saida para $SAIDA${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi

    if [ "$ACHADOS" -eq 0 ]; then
        # Arquivo preservado com "results": [] — distingue "analisou e nao
        # achou" de "nao analisou".
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "SEM_ACHADOS" \
            "0 achados${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
    else
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "OK" \
            "$ACHADOS achados${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
    fi

    limpar
done 3< "$LISTA"

echo "Lote concluido: $LISTA"
