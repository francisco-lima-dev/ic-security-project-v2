#!/usr/bin/env bash
#
# run_codeql.sh — roda o CodeQL sobre os CVEs de um lote do OpenSSF CVE
# Benchmark, produzindo APENAS a saída bruta (SARIF). A normalização para o
# schema comum é um passo separado, fora do container.
#
# Uso, dentro do container:
#   run_codeql.sh [caminho-da-lista]
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

FERRAMENTA="codeql"
WORKSPACE="${WORKSPACE:-/workspace}"

# security-extended, não security-and-quality: consultas de qualidade não
# são alegação de vulnerabilidade, e computá-las como falso positivo
# mediria a escolha de suíte, não a precisão da ferramenta.
SUITE="codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"

# PROVISÓRIO. Sem dado de duração — que só a Fase E produz — qualquer limite
# é chute, e um valor curto demais transformaria análise legítima de
# repositório grande em ERRO_ANALISE sistemático. Generoso de propósito.
# Revisar depois de medir.
TIMEOUT_CREATE=3600
TIMEOUT_ANALYZE=3600

# Limites da OBTENÇÃO do código. Os valores são exatamente os que já
# vigoravam, em literal, nas duas invocações do laço: 300 s no fetch raso e
# 900 s no clone de contingência. Nada muda de comportamento — o que muda é
# que o valor passa a ter nome, e a mensagem do log pode citá-lo sem
# duplicar o literal. Duplicá-lo faria a mensagem mentir no dia em que
# alguém editasse só um dos dois lugares.
TIMEOUT_FETCH=300
TIMEOUT_CLONE=900

LISTA_ARG="${1:-datasets/listas/cves-sast.txt}"
case "$LISTA_ARG" in
    /*) LISTA="$LISTA_ARG" ;;
    *)  LISTA="$WORKSPACE/$LISTA_ARG" ;;
esac

RAW_DIR="$WORKSPACE/results/$FERRAMENTA/raw"
LOG_DIR="$WORKSPACE/logs"
LOG="$LOG_DIR/execution-log-$FERRAMENTA.csv"

WORKDIR=""
DBDIR=""

limpar() {
    cd /tmp
    if [ -n "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
        WORKDIR=""
    fi
    # O database do CodeQL é grande; deixá-lo para trás enche o disco no
    # meio do lote.
    if [ -n "$DBDIR" ]; then
        rm -rf "$DBDIR"
        DBDIR=""
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

# --- guarda de integridade do bundle do CodeQL ---------------------------
# SEGUNDA comparação, análoga à do pack vendorizado do Semgrep. A PRIMEIRA
# vive no build: o Dockerfile confere o sha256 do tarball baixado contra o
# `--build-arg`, antes de desempacotar, e falha se divergir.
#
# Esta pega o modo de falha que a primeira NÃO alcança: o descritor
# versionado mudou no repositório e ninguém reconstruiu a imagem. O `ARG` e
# o `ENV` congelam no mesmo build e sempre batem entre si, logo a
# comparação do build sozinha não detecta esse caso.
#
# ASSIMETRIA DECLARADA, e ela é estrutural. A comparação (2) do Semgrep
# termina em BYTES dos dois lados: confere o `/default.yaml` da imagem
# contra o YAML do repositório montado. Esta compara DOIS VALORES
# DECLARADOS — o `ENV` assado no build contra o campo do descritor hoje.
# Ela NÃO estabelece que /opt/codeql ainda corresponde ao hash. AQUI a
# comparação em bytes é estruturalmente IMPOSSÍVEL: o valor declarado é o
# do TARBALL, que o Dockerfile remove depois de desempacotar, e /opt/codeql
# é a árvore extraída — rehashá-la não reproduziria o valor, e é guardar os
# 808 MB do tarball na imagem que seria proibitivo.
#
# No Snyk a situação é OUTRA, e está registrada lá: o binário conferido no
# build continua na imagem, então a comparação em bytes está disponível e
# apenas não foi feita. Não repita esta justificativa lá.
#
# Quem chega aqui com a expectativa formada pelo Semgrep tem de ler esta
# ressalva; ela está também no campo `why_no_second_comparison` do
# descritor.
#
# Repositório não montado emite AVISO no stderr e a execução SEGUE:
# abortar quebraria execução legítima em contexto sem o volume. Mesma
# disciplina da comparação (2) do Semgrep.
DESCRITOR="$WORKSPACE/ic-security-lab-codeql/codeql-bundle.meta.json"
if [ -z "${CODEQL_BUNDLE_SHA256:-}" ]; then
    echo "ERRO: CODEQL_BUNDLE_SHA256 nao definido na imagem." >&2
    echo "  Reconstrua com --build-arg CODEQL_BUNDLE_SHA256=<sha256 do bundle do CodeQL>" >&2
    exit 1
fi
if [ -f "$DESCRITOR" ]; then
    # Parser do formato, nunca regex sobre o JSON.
    if ! SHA_DESCRITOR=$(node -e '
const fs = require("fs");
const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
process.stdout.write(typeof d.sha256 === "string" ? d.sha256 : "");
' "$DESCRITOR"); then
        echo "ERRO: nao foi possivel ler o sha256 de $DESCRITOR" >&2
        exit 1
    fi
    # Campo ausente devolve string vazia, que compararia contra o ENV e
    # divergiria — mas com mensagem errada. A validacao de forma separa
    # "descritor malformado" de "imagem obsoleta".
    if ! [[ "$SHA_DESCRITOR" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERRO: campo sha256 ausente ou malformado em $DESCRITOR" >&2
        echo "  obtido: '$SHA_DESCRITOR'" >&2
        exit 1
    fi
    # O lado do ENV também é validado quanto à forma. Sem isso, um
    # --build-arg com hex maiúsculo ou espaço em volta sairia como "imagem
    # obsoleta", nomeando a causa errada — que é o defeito que a validação
    # existe para evitar do outro lado.
    if ! [[ "$CODEQL_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
        echo "ERRO: CODEQL_BUNDLE_SHA256 da imagem nao e um sha256 canonico" >&2
        echo "  obtido: '$CODEQL_BUNDLE_SHA256'" >&2
        exit 1
    fi
    if [ "$SHA_DESCRITOR" != "$CODEQL_BUNDLE_SHA256" ]; then
        echo "ERRO: a imagem esta obsoleta em relacao ao descritor do repositorio" >&2
        echo "  na imagem:      $CODEQL_BUNDLE_SHA256" >&2
        echo "  no descritor:   $SHA_DESCRITOR" >&2
        echo "  Reconstrua a imagem com --build-arg CODEQL_BUNDLE_SHA256=<sha256 do descritor>" >&2
        exit 1
    fi
else
    echo "AVISO: $DESCRITOR ausente; nao foi possivel conferir a imagem" >&2
    echo "  contra o descritor do repositorio. O workspace esta montado?" >&2
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

VERSAO_CODEQL=$(codeql version --format=terse)
if [ -z "$VERSAO_CODEQL" ]; then
    # Não aborta, mas grita: falha ao capturar a versão em imagem
    # recém-construída indica binário quebrado, e quem acompanha a
    # execução tem de ver na hora.
    VERSAO_CODEQL="VERSAO_NAO_CAPTURADA"
    echo "AVISO: nao foi possivel capturar a versao do codeql" >&2
fi
VERSAO_PENDENTE="codeql $VERSAO_CODEQL; suite $SUITE"

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

    SAIDA="$RAW_DIR/$CVE_ID.sarif"
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
    DBDIR="/tmp/db-$CVE_ID"
    rm -rf "$WORKDIR" "$DBDIR"
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
    #
    # O código de retorno é capturado em VARIÁVEL antes de decidir o ramo, e
    # não consumido pela condição do `if`. Sem isso, estouro do limite
    # (rc 124, do `timeout`) e recusa do servidor (`upload-pack: not our
    # ref`, rc 128) caem no mesmo ramo de contingência e produzem a MESMA
    # linha de log — causas opostas, lentidão nossa ou do servidor contra
    # ausência do objeto, contadas no mesmo balde. A contagem de fallback é
    # métrica de vigilância do protocolo, e só serve se as distinguir.
    # É a disciplina que as invocações de análise deste script já seguem, e
    # que faltava só na obtenção.
    #
    # O 124 é o estouro do `timeout` do GNU coreutils, que é o que as três
    # imagens têm por serem todas de base Debian. Sob outra implementação o
    # número seria outro e um estouro sairia como "saiu com N" — leitura
    # falsa e silenciosa. Fica amarrado à base, que é fixada por digest.
    GIT_TERMINAL_PROMPT=0 timeout "$TIMEOUT_FETCH" git fetch -q --depth 1 origin "$COMMIT" < /dev/null
    RC_FETCH=$?
    if [ "$RC_FETCH" -eq 0 ]; then
        REF="FETCH_HEAD"
    else
        # Nenhuma vírgula nestas mensagens. O `registrar` já troca vírgula
        # por ponto-e-vírgula; escrever sem ela é a primeira linha, não a
        # única. O log é CSV de seis campos, e quem o lê — o
        # tools/check-log.py — separa por vírgula.
        if [ "$RC_FETCH" -eq 124 ]; then
            MOTIVO_FETCH="fetch raso excedeu ${TIMEOUT_FETCH}s"
        else
            MOTIVO_FETCH="fetch raso saiu com $RC_FETCH"
        fi
        echo "[$CVE_ID] $MOTIVO_FETCH; tentando clone completo" >&2
        MENSAGEM="fallback de clone completo; $MOTIVO_FETCH"
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
        GIT_TERMINAL_PROMPT=0 timeout "$TIMEOUT_CLONE" git clone -q --no-single-branch "$REPO_URL" "$WORKDIR" < /dev/null
        RC_CLONE=$?
        if [ "$RC_CLONE" -ne 0 ]; then
            # Mesma disciplina do fetch: estouro do limite não é falha do
            # servidor, e o ERRO_FETCH tem de dizer qual dos dois foi.
            if [ "$RC_CLONE" -eq 124 ]; then
                MOTIVO_CLONE="clone completo excedeu ${TIMEOUT_CLONE}s"
            else
                MOTIVO_CLONE="clone completo saiu com $RC_CLONE"
            fi
            registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_FETCH" \
                "$MOTIVO_CLONE; $MOTIVO_FETCH" $((SECONDS - INICIO))
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
    # Sem filtro de severidade e sem exclusão de caminho.
    #
    # Escreve no temporário e só promove ao nome final depois de validar:
    # raw truncado gravado direto no nome final sobreviveria a SIGKILL e a
    # idempotência o leria como análise concluída, para sempre.
    timeout "$TIMEOUT_CREATE" codeql database create "$DBDIR" \
        --language=javascript \
        --source-root=. \
        --build-mode=none < /dev/null
    RC_CREATE=$?

    # Exit code do create é verificado: falhou, não roda o analyze.
    if [ "$RC_CREATE" -eq 124 ]; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "database create excedeu ${TIMEOUT_CREATE}s${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi
    if [ "$RC_CREATE" -ne 0 ]; then
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "database create saiu com $RC_CREATE${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi

    timeout "$TIMEOUT_ANALYZE" codeql database analyze "$DBDIR" \
        "$SUITE" \
        --ram=4096 \
        --format=sarif-latest \
        --output="$PARCIAL" < /dev/null
    RC_ANALYZE=$?

    if [ "$RC_ANALYZE" -eq 124 ]; then
        rm -f "$PARCIAL"
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "database analyze excedeu ${TIMEOUT_ANALYZE}s${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi
    if [ "$RC_ANALYZE" -ne 0 ] || [ ! -f "$PARCIAL" ]; then
        rm -f "$PARCIAL"
        registrar "$CVE_ID" "$REPO_URL" "$COMMIT" "ERRO_ANALISE" \
            "database analyze saiu com $RC_ANALYZE${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
        limpar
        continue
    fi

    ACHADOS=$(node -e '
const fs = require("fs");
try {
  const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  let n = 0;
  for (const r of (d.runs || [])) n += (r.results || []).length;
  console.log(n);
} catch (e) {
  console.log(-1);
}
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
            "SARIF ilegivel${MENSAGEM:+; $MENSAGEM}" $((SECONDS - INICIO))
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
        # Arquivo preservado com results vazio — distingue "analisou e nao
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
