Artefato do lote cves-sast-batch-ae — ferramenta snyk-code
====================================================================

AVISO DE PROTOCOLO — ler antes de usar qualquer coisa deste artifact

  * Regra do ensaio de fumaca (cves-sast-fumaca): os resultados de
    DETECCAO de ensaio sao descartados; preservam-se so o log de
    execucao e o normalize-report. Este lote nao e o de ensaio.
  * NUNCA descompactar este artifact dentro de results/*/raw/ de uma
    arvore de trabalho que depois va rodar lote. No runner a idempotencia
    e inerte, porque o ambiente nasce limpo; localmente ela PULARIA os
    CVEs cujo raw ja existe, e o lote sairia incompleto sem erro visivel.
  * Lote sem raw algum FALHA o job. Mas o job verde NAO significa lote
    inteiro analisado: lote com parte dos CVEs em ERRO_* termina verde.
    Ler a contagem de status abaixo.

lote: cves-sast-batch-ae
ferramenta: snyk-code
imagem_pedida: ghcr.io/<dono>/ic-security-lab-snyk-code@sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
preparado_em: 2026-09-17T01:05:54Z
workflow_run_id: 35169207030
workflow_run_attempt: 1
commit: 579f383195251daa8ff1858322652e9c0bcb4c39
runner_image_os: ubuntu24
runner_image_version: 20260907.300.1
uid_do_runner: 1001
gid_do_runner: 1001
lista: datasets/listas/cves-sast-batch-ae
registros_na_lista: 30
linhas_fisicas_na_lista: 30
quebra_de_linha_final: presente

estado herdado do checkout, movido para fora do workspace:
  logs/execution-log-snyk-code.csv (6 linhas)
  logs/normalize-report-snyk-code.json (102 linhas)
  results/snyk-code/treated/*.json: 0 arquivo(s)
  results/snyk-code/raw no inicio: ausente (nao versionado), 0 entradas

portao previo (tests/run-fixtures.py): rc=0 | 250 verificacoes, 0 falha(s)
imagem_usada: ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
repodigest_conferido: ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
image_id: sha256:318db7224c1cbecb65cfa1967bd43a4e1196c61fec60c6fbb6404cb5f254ad55
controle do HOME: DEFEITO MEDIDO — sem -e HOME=/tmp falha (rc=1); com -e HOME=/tmp opera
pre-voo da imagem: OK (linha de limites conferida; parada em "ERRO: lista nao encontrada: /workspace/datasets/listas/.prevoo-inexistente")
normalize.py: rc=0
check-log.py: rc=0
portao de lote sem raw: OK — 30 de 30 CVEs do lote com raw

====================================================================
DESFECHO DOS PASSOS
====================================================================
preparar: success
portao previo (fixtures): success
imagem por digest: success
controle do HOME (nao fatal): success
lote: success
normalize.py: success
check-log.py: success
portao de lote sem raw: success
rede do Semgrep (nao fatal, so no Semgrep): skipped
resultados e logs copiados para o artifact: sim

--- container
inicio: 2026-09-17T01:06:10Z
fim: 2026-09-17T01:20:53Z
duracao_segundos: 883
rc_container: 0
limite_do_lote_segundos: 5400 (teto 5400; decorrido no job ao iniciar 16; disponivel 6074)
estouro_do_limite_do_lote: nao
laco_chegou_ao_fim: sim
limites_pedidos: -e TIMEOUT_ANALISE=900
limites_esperados: limites efetivos em segundos: TIMEOUT_ANALISE=900; TIMEOUT_FETCH=300; TIMEOUT_CLONE=900
limites_efetivos: limites efetivos em segundos: TIMEOUT_ANALISE=900; TIMEOUT_FETCH=300; TIMEOUT_CLONE=900
limites_conferidos: sim

--- contagens
raws (CVE-*): 30
tratados (*.json): 30
linhas no log de execucao (com cabecalho): 31

--- portoes (linhas emitidas pelos proprios scripts)
[tests/run-fixtures.py]
250 verificacoes, 0 falha(s)
[tools/normalize.py]
  processados: 30 | pulados: 0 | com falha: 0
  linhas da lista sem raw: 193 | raws sem linha na lista: 0
  achados: 730 (sem CWE: 0)
[tools/check-log.py]
  linhas no log: 30 | CVEs distintos apos deduplicacao: 30 | raws: 30
  ultimo status por CVE: {'OK': 17, 'SEM_ACHADOS': 13}
  (1) raw existe e o ultimo status e de erro: 0
  (2) status OK/SEM_ACHADOS e nao existe raw: 0
  (3) SEM_ARQUIVO_ANALISAVEL sem raw: 0  (ESPERADO — resultado, nao falha)
  (4) CVE do lote sem raw e sem linha de log: 0 de 30
      fallback de clone completo: 0
