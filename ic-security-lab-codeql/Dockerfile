# CodeQL — análise SAST do OpenSSF CVE Benchmark.
#
# Build context: este diretório (ic-security-lab-codeql/), sem -f.
# Os dois --build-arg são OBRIGATÓRIOS: os ARG não têm default e o build
# falha sem eles, por desenho. Os valores vivem em codeql-bundle.meta.json.
#   docker build -t ic-security-lab-codeql \
#       --build-arg CODEQL_BUNDLE_VERSION="$(python3 -c 'import json;print(json.load(open("codeql-bundle.meta.json"))["bundle"].removeprefix("codeql-bundle-"))')" \
#       --build-arg CODEQL_BUNDLE_SHA256="$(python3 -c 'import json;print(json.load(open("codeql-bundle.meta.json"))["sha256"])')" .
#
# Execução (o workspace montado é a raiz do repositório):
#   docker run --rm -v "$PWD":/workspace ic-security-lab-codeql \
#       datasets/listas/cves-sast-batch-aa
# Base fixada por DIGEST DO ÍNDICE multi-arquitetura, não por tag. A tag
# fica ao lado porque documenta o que o digest é, sem afrouxar a fixação.
# O digest de UMA plataforma quebraria o build em runner de arquitetura
# diferente; este índice cobre 3 (linux/amd64, arm64/v8, ppc64le).
# Reconfirmado em 2026-09-12 pela API do registro, distinguindo índice de
# plataforma pelo mediaType e recalculando o sha256 do corpo recebido.
FROM node:24-bookworm@sha256:6dac556d980b7f0e5498d08f08cee0ca67798b4ad6c23964a9214920e67758d0

# Versão e sha256 do bundle. SEM DEFAULT, nos dois: com default, um
# --build-arg errado ou esquecido passa em silêncio e a imagem sai com
# conteúdo diferente do que o descritor declara. É a disciplina que o
# PACK_SHA256 do Semgrep já tinha e que faltava aqui.
# Os valores vivem em codeql-bundle.meta.json, versionado.
ARG CODEQL_BUNDLE_VERSION
ARG CODEQL_BUNDLE_SHA256
ENV CODEQL_BUNDLE_VERSION=${CODEQL_BUNDLE_VERSION}
# Gravado na imagem para tornar possível a SEGUNDA comparação — imagem
# contra o descritor do repositório, em runtime —, que pega o descritor
# alterado sem rebuild. Ela ainda NÃO existe: viveria no script de
# análise, fora do escopo da fase que criou este ENV.
ENV CODEQL_BUNDLE_SHA256=${CODEQL_BUNDLE_SHA256}

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Verificação FATAL antes de desempacotar: 808 MB vindos da rede não
# entram na imagem sem conferência. O `test -n` aborta o build quando o
# --build-arg não veio, em vez de deixar o sha256sum comparar contra
# string vazia.
RUN test -n "$CODEQL_BUNDLE_VERSION" \
    && test -n "$CODEQL_BUNDLE_SHA256" \
    && curl -fsSL -o /tmp/codeql-bundle.tar.gz \
        "https://github.com/github/codeql-action/releases/download/codeql-bundle-${CODEQL_BUNDLE_VERSION}/codeql-bundle-linux64.tar.gz" \
    && echo "${CODEQL_BUNDLE_SHA256}  /tmp/codeql-bundle.tar.gz" | sha256sum -c - \
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

# INVENTÁRIO DO QUE NÃO SE FIXA.
# Fixar a base por digest congela o substrato e deixa os pacotes soltos:
# são 413 .deb nesta imagem, nenhum com versão pinada. Chamar o resultado
# de "build reproduzível" seria falso. O que torna a garantia honesta é
# registrar o que flutuou — e as versões são recuperáveis mesmo depois do
# `rm -rf /var/lib/apt/lists/*`, porque o dpkg-query não depende delas.
#
# O `test -s` após cada arquivo NÃO é zelo: `RUN` roda em `sh -c` sem
# pipefail, e o status de `dpkg-query | sort` é o do `sort`. Sem a
# conferência, um produtor que falhasse deixaria o arquivo vazio, a cadeia
# `&&` seguiria e o build passaria — publicando inventário vazio que passa
# por inventário. É o resultado falso plausível da regra geral de contagem.
RUN mkdir -p /inventario \
    && dpkg-query -f '${binary:Package}=${Version}\n' -W | sort > /inventario/deb.txt \
    && test -s /inventario/deb.txt \
    && codeql version --format=terse > /inventario/codeql-version.txt \
    && test -s /inventario/codeql-version.txt \
    && printf '%s\n' "$CODEQL_BUNDLE_SHA256" > /inventario/codeql-bundle.sha256

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_codeql.sh"]
