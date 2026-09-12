# Semgrep — análise SAST do OpenSSF CVE Benchmark.
#
# Build context: este diretório (ic-security-lab-semgrep/), sem -f.
# O PACK_SHA256 é obrigatório e vem de rules/semgrep-default.meta.json:
#   docker build -t ic-security-lab-semgrep \
#       --build-arg PACK_SHA256="$(jq -r .sha256 rules/semgrep-default.meta.json)" .
#
# Execução:
#   docker run --rm -v "$PWD":/workspace ic-security-lab-semgrep \
#       datasets/listas/cves-sast-batch-aa
# Base fixada por DIGEST DO ÍNDICE multi-arquitetura, não por tag. A tag
# fica ao lado porque documenta o que o digest é, sem afrouxar a fixação.
# Índice cobre 8 plataformas. Reconfirmado em 2026-09-12 pela API do
# registro, distinguindo índice de plataforma pelo mediaType.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

# sha256 esperado do pack vendorizado. O script confere no arranque:
# o pack existe em dois lugares (repositório e imagem) e sem a guarda um
# rebuild esquecido faria os resultados declararem um hash que não
# corresponde às regras que rodaram.
ARG PACK_SHA256
ENV PACK_SHA256=${PACK_SHA256}

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir semgrep==1.171.0

# O pack vendorizado vai na RAIZ do sistema de arquivos, não em
# subdiretório: o Semgrep prefixa o check_id com o nome do diretório que
# contém o YAML, e em subdiretório os identificadores divergiriam dos do
# registry e da campanha anterior, quebrando a comparação em silêncio.
COPY rules/semgrep-default.yaml /default.yaml

# Valida no BUILD, não no primeiro lote: imagem construída sem --build-arg,
# ou com hash dessincronizado do YAML, só seria descoberta quando alguém
# disparasse uma campanha.
RUN semgrep --version \
    && test -n "$PACK_SHA256" \
    && echo "${PACK_SHA256}  /default.yaml" | sha256sum -c -

# INVENTÁRIO DO QUE NÃO SE FIXA.
# 118 .deb e 67 pacotes pip, dos quais o `semgrep==1.171.0` pina UM: as
# 66 dependências transitivas resolvem no build. Fixar a base não fecha
# a reprodutibilidade; registrar o resolvido é o que torna a garantia
# honesta em vez de aparente.
# O `test -s` após cada arquivo: `RUN` roda em `sh -c` sem pipefail, e o
# status de `dpkg-query | sort` e de `pip3 list | sort` é o do `sort`. Sem
# ele, produtor que falha deixa arquivo vazio e o build passa publicando
# inventário vazio — que é justamente o que sustenta a afirmação de que
# isto NÃO é build reproduzível.
RUN mkdir -p /inventario \
    && dpkg-query -f '${binary:Package}=${Version}\n' -W | sort > /inventario/deb.txt \
    && test -s /inventario/deb.txt \
    && pip3 list --format=freeze | sort > /inventario/pip.txt \
    && test -s /inventario/pip.txt \
    && semgrep --version > /inventario/semgrep-version.txt \
    && test -s /inventario/semgrep-version.txt \
    && printf '%s\n' "$PACK_SHA256" > /inventario/pack.sha256

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_semgrep.sh"]
