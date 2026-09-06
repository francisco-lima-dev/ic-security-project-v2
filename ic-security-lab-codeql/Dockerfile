# CodeQL — análise SAST do OpenSSF CVE Benchmark.
#
# Build context: este diretório (ic-security-lab-codeql/), sem -f.
#   docker build -t ic-security-lab-codeql .
#
# Execução (o workspace montado é a raiz do repositório):
#   docker run --rm -v "$PWD":/workspace ic-security-lab-codeql \
#       datasets/listas/cves-sast-batch-aa
FROM node:24-bookworm

# Versão do bundle fixada. Nunca "latest": o bundle carrega as consultas,
# e trocá-lo silenciosamente troca o conjunto avaliado.
ARG CODEQL_BUNDLE_VERSION=v2.25.4
ENV CODEQL_BUNDLE_VERSION=${CODEQL_BUNDLE_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/codeql-bundle.tar.gz \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-${CODEQL_BUNDLE_VERSION}/codeql-bundle-linux64.tar.gz" \
    && tar -xzf /tmp/codeql-bundle.tar.gz -C /opt \
    && rm -f /tmp/codeql-bundle.tar.gz

ENV PATH="/opt/codeql:${PATH}"

# Falha o build se o bundle não desempacotou onde se espera.
RUN codeql version --format=terse

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_codeql.sh"]
