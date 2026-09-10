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

# O tarball preserva dono e modo de quem o empacotou: os 3.151 .qlx
# precompilados saem com dono uid 1001, e 462 deles com modo 600. Sob
# `--user` com qualquer outro uid o CodeQL nao consegue le-los, cai em
# AccessDeniedException por consulta e RECOMPILA o plano — medido em
# ~1min20s por consulta (Fase E, 10/09/2026, uid 1000: 7 de 104 consultas em
# 9 minutos; com este chmod, 104 de 104 em ~40s).
#
# Nao e otimizacao: o custo de recompilacao cai INTEIRO dentro do `analyze`
# do PRIMEIRO CVE do lote — os seguintes reusam o compile-cache em
# $HOME/.codeql, que vive no /tmp do container e dura o `docker run` — e pode
# encostar no TIMEOUT_ANALYZE de 3600s. O desfecho seria um unico
# ERRO_ANALISE, sem causa aparente, exatamente a falha que nao se explica
# sozinha.
#
# O uid 1001 do runner do GitHub Actions bate com o dono dos arquivos, entao
# la o defeito provavelmente nao apareceria. E a mesma coincidencia de uid do
# HOME, com o sinal invertido — la o 1000 daqui salva e o 1001 quebraria;
# aqui o 1001 salva e o 1000 quebra. Depender da coincidencia e o que este
# projeto decidiu nao fazer.
RUN chmod -R a+rX /opt/codeql

ENV PATH="/opt/codeql:${PATH}"

# Falha o build se o bundle não desempacotou onde se espera.
RUN codeql version --format=terse

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_codeql.sh"]
