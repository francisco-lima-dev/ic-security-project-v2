# Snyk Code — análise SAST do OpenSSF CVE Benchmark.
#
# Build context: este diretório (ic-security-lab-snyk-code/), sem -f.
# Os dois --build-arg são OBRIGATÓRIOS: os ARG não têm default e o build
# falha sem eles, por desenho. Os valores vivem em snyk-cli.meta.json.
#   docker build -t ic-security-lab-snyk-code \
#       --build-arg SNYK_CLI_VERSION="$(python3 -c 'import json;print(json.load(open("snyk-cli.meta.json"))["version"])')" \
#       --build-arg SNYK_CLI_SHA256="$(python3 -c 'import json;print(json.load(open("snyk-cli.meta.json"))["sha256"])')" .
#
# Execução (exige SNYK_TOKEN no ambiente):
#   docker run --rm -v "$PWD":/workspace -e SNYK_TOKEN ic-security-lab-snyk-code \
#       datasets/listas/cves-sast-batch-aa
# Base fixada por DIGEST DO ÍNDICE multi-arquitetura, não por tag. A tag
# fica ao lado porque documenta o que o digest é, sem afrouxar a fixação.
# Índice cobre 5 plataformas. Reconfirmado em 2026-09-12 pela API do
# registro, distinguindo índice de plataforma pelo mediaType.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# URL versionada. Nem "latest" nem "stable": ambos já se moveram desde a
# campanha anterior e apontam hoje para 1.1307.0.
# SEM DEFAULT nos dois ARG: com default, um --build-arg errado ou
# esquecido passa em silêncio. Valores em snyk-cli.meta.json, versionado.
ARG SNYK_CLI_VERSION
ARG SNYK_CLI_SHA256
# Gravado na imagem para tornar possível a SEGUNDA comparação — imagem
# contra o descritor do repositório, em runtime. Ela ainda NÃO existe:
# viveria no script de análise, fora do escopo da fase que criou este ENV.
ENV SNYK_CLI_SHA256=${SNYK_CLI_SHA256}

# jq não é conveniência: é dependência de validação. Sem ele o Snyk seria a
# única das três ferramentas cujo raw não é conferido, e SARIF malformado ou
# vazio viraria OK/SEM_ACHADOS gravado, preservado pela idempotência.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        jq \
    && rm -rf /var/lib/apt/lists/*

# Verificação FATAL antes de tornar executável: um binário de 178 MiB
# vindo da rede não entra na imagem sem conferência. O `test -n` aborta
# quando o --build-arg nao veio, em vez de comparar contra string vazia.
RUN test -n "$SNYK_CLI_VERSION" \
    && test -n "$SNYK_CLI_SHA256" \
    && curl -fsSL -o /usr/local/bin/snyk \
        "https://static.snyk.io/cli/${SNYK_CLI_VERSION}/snyk-linux" \
    && echo "${SNYK_CLI_SHA256}  /usr/local/bin/snyk" | sha256sum -c - \
    && chmod +x /usr/local/bin/snyk \
    && snyk --version \
    && jq --version

# INVENTÁRIO DO QUE NÃO SE FIXA. 119 .deb, nenhum pinado.
# O `test -s` após cada arquivo: `RUN` roda em `sh -c` sem pipefail, e o
# status de `dpkg-query | sort` é o do `sort`. Sem ele, produtor que falha
# deixa arquivo vazio e o build passa publicando inventário vazio.
RUN mkdir -p /inventario \
    && dpkg-query -f '${binary:Package}=${Version}\n' -W | sort > /inventario/deb.txt \
    && test -s /inventario/deb.txt \
    && snyk --version > /inventario/snyk-version.txt \
    && test -s /inventario/snyk-version.txt \
    && printf '%s\n' "$SNYK_CLI_SHA256" > /inventario/snyk-cli.sha256

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_snyk-code.sh"]
