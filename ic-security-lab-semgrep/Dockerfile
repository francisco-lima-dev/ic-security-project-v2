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
FROM python:3.12-slim

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

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

WORKDIR /workspace
ENTRYPOINT ["/scripts/run_semgrep.sh"]
