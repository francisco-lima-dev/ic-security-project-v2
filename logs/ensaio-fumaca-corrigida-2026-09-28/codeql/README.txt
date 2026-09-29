Artefato do lote cves-sast-corrigida-fumaca — ferramenta codeql
====================================================================

AVISO DE PROTOCOLO — ler antes de usar qualquer coisa deste artifact

  * ESTE LOTE E DE ENSAIO. Os resultados de DETECCAO dele sao
    DESCARTADOS, como foram os do ensaio local: CVEs deste lote integram
    lotes da campanha. Preservam-se o LOG de execucao e o
    normalize-report; os achados, nao.
  * NUNCA descompactar este artifact dentro de results/*/raw/ de uma
    arvore de trabalho que depois va rodar lote. No runner a idempotencia
    e inerte, porque o ambiente nasce limpo; localmente ela PULARIA os
    CVEs cujo raw ja existe, e o lote sairia incompleto sem erro visivel.
  * Lote sem raw algum FALHA o job. Mas o job verde NAO significa lote
    inteiro analisado: lote com parte dos CVEs em ERRO_* termina verde.
    Ler a contagem de status abaixo.

campanha: corrigida
commit_analisado: PostPatchCommit (versao corrigida)
lista_completa_do_normalize: datasets/listas/cves-sast-corrigida.txt
lote: cves-sast-corrigida-fumaca
ferramenta: codeql
imagem_pedida: ghcr.io/<dono>/ic-security-lab-codeql@sha256:39950e7ac03b7d7b7a724c742e1c48e9475ed998d58a4734d653188d31afcbec
preparado_em: 2026-09-28T18:42:57Z
workflow_run_id: 36467129181
workflow_run_attempt: 1
commit: 52b3076158e843fb7392eae54e4f93edd65f0a49
runner_image_os: ubuntu24
runner_image_version: 20260920.314.1
uid_do_runner: 1001
gid_do_runner: 1001
lista: datasets/listas/cves-sast-corrigida-fumaca
registros_na_lista: 7
linhas_fisicas_na_lista: 7
quebra_de_linha_final: presente

estado herdado do checkout, movido para fora do workspace:
  logs/execution-log-codeql.csv (6 linhas)
  logs/normalize-report-codeql.json (131 linhas)
  results/codeql/treated/*.json: 221 arquivo(s)
  results/codeql/raw no inicio: ausente (nao versionado), 0 entradas

portao previo (tests/run-fixtures.py): rc=0 | 1463 verificacoes, 0 falha(s)
imagem_usada: ghcr.io/francisco-lima-dev/ic-security-lab-codeql@sha256:39950e7ac03b7d7b7a724c742e1c48e9475ed998d58a4734d653188d31afcbec
repodigest_conferido: ghcr.io/francisco-lima-dev/ic-security-lab-codeql@sha256:39950e7ac03b7d7b7a724c742e1c48e9475ed998d58a4734d653188d31afcbec
image_id: sha256:61d5ab857af5b85b362c247a06dce837c94487a670eb0a0b3fb021f8efda6bef
controle do HOME: DEFEITO MEDIDO — sem -e HOME=/tmp falha (rc=1); com -e HOME=/tmp opera
pre-voo da imagem: OK (linha de limites conferida; parada em "ERRO: lista nao encontrada: /workspace/datasets/listas/.prevoo-inexistente")
normalize.py: rc=0 (--lista datasets/listas/cves-sast-corrigida.txt)
check-log.py: rc=0
portao de lote sem raw: OK — 7 de 7 CVEs do lote com raw

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
inicio: 2026-09-28T18:43:58Z
fim: 2026-09-28T18:49:58Z
duracao_segundos: 360
rc_container: 0
limite_do_lote_segundos: 9000 (teto 9000; decorrido no job ao iniciar 61; disponivel 9629)
estouro_do_limite_do_lote: nao
laco_chegou_ao_fim: sim
limites_pedidos: -e TIMEOUT_CREATE=900 -e TIMEOUT_ANALYZE=900
limites_esperados: limites efetivos em segundos: TIMEOUT_CREATE=900; TIMEOUT_ANALYZE=900; TIMEOUT_FETCH=300; TIMEOUT_CLONE=900
limites_efetivos: limites efetivos em segundos: TIMEOUT_CREATE=900; TIMEOUT_ANALYZE=900; TIMEOUT_FETCH=300; TIMEOUT_CLONE=900
limites_conferidos: sim

--- contagens
raws (CVE-*): 7
tratados (*.json): 7
linhas no log de execucao (com cabecalho): 8

--- portoes (linhas emitidas pelos proprios scripts)
[tests/run-fixtures.py]
1463 verificacoes, 0 falha(s)
[tools/normalize.py]
  processados: 7 | pulados: 0 | com falha: 0
  linhas da lista sem raw: 213 | raws sem linha na lista: 0
  achados: 26 (sem CWE: 0)
[tools/check-log.py]
  linhas no log: 7 | CVEs distintos apos deduplicacao: 7 | raws: 7
  ultimo status por CVE: {'OK': 4, 'SEM_ACHADOS': 3}
  (1) raw existe e o ultimo status e de erro: 0
  (2) status OK/SEM_ACHADOS e nao existe raw: 0
  (3) SEM_ARQUIVO_ANALISAVEL sem raw: 0  (ESPERADO — resultado, nao falha)
  (4) CVE do lote sem raw e sem linha de log: 0 de 7
      fallback de clone completo: 0
