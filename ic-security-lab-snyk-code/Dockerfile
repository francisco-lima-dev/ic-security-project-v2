# Snyk Code — análise SAST do OpenSSF CVE Benchmark.
#
# Build context: este diretório (ic-security-lab-snyk-code/), sem -f.
#   docker build -t ic-security-lab-snyk-code .
#
# Execução (exige SNYK_TOKEN no ambiente):
#   docker run --rm -v "$PWD":/workspace -e SNYK_TOKEN ic-security-lab-snyk-code \
#       datasets/listas/cves-sast-batch-aa
FROM debian:bookworm-slim

# URL versionada. Nem "latest" nem "stable": ambos já se moveram desde a
# campanha anterior e apontam hoje para 1.1307.0.
ARG SNYK_CLI_VERSION=v1.1306.1

# jq não é conveniência: é dependência de validação. Sem ele o Snyk seria a
# única das três ferramentas cujo raw não é conferido, e SARIF malformado ou
# vazio viraria OK/SEM_ACHADOS gravado, preservado pela idempotência.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
        jq \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/snyk \
        "https://static.snyk.io/cli/${SNYK_CLI_VERSION}/snyk-linux" \
    && chmod +x /usr/local/bin/snyk \
    && snyk --version \
    && jq --version

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_snyk-code.sh"]
