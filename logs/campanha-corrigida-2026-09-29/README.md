# Campanha SAST da versão corrigida, 29/09/2026 — registro de execução

Os 24 artifacts das oito execuções do `analise-lote.yml` com
`campanha=corrigida`, sobre o `PostPatchCommit` dos 220 CVEs do denominador
(listas `cves-sast-corrigida-batch-aa` a `ah`), fora os raws. Critérios da
versão corrigida na §11 do `docs/criterios-cruzamento.md`; convenções da
campanha no `CLAUDE.md`, "Campanha da versão corrigida — convenções".

Todas as execuções no commit `91ed31a`, com os três limites de análise em
900 s. Os 24 jobs saíram `success`.

| Lote | Execução | Início (UTC) | Artifacts expiram em |
|---|---|---|---|
| `aa` | `36509298178` | 2026-09-29 01:44 | 28/12/2026 |
| `ab` | `36540758244` | 2026-09-29 08:07 | 28/12/2026 |
| `ac` | `36540761783` | 2026-09-29 08:07 | 28/12/2026 |
| `ad` | `36540764816` | 2026-09-29 08:07 | 28/12/2026 |
| `ae` | `36540768455` | 2026-09-29 08:07 | 28/12/2026 |
| `af` | `36540772285` | 2026-09-29 08:07 | 28/12/2026 |
| `ag` | `36540775631` | 2026-09-29 08:07 | 28/12/2026 |
| `ah` | `36540779107` | 2026-09-29 08:07 | 28/12/2026 |

Nome de cada artifact: `lote-corrigida-cves-sast-corrigida-batch-<lote>-<ferramenta>-<execução>-1`.
Baixados com `gh run download` em 29/09/2026. A campanha não atravessou a
meia-noite UTC: as oito execuções são de 29/09/2026.

## O que está aqui, e de onde veio

| Origem no artifact | Destino no repositório | Arquivos | Como |
|---|---|---:|---|
| `results/<ferramenta>/treated/CVE-*.json` | `results/corrigida/<ferramenta>/treated/` | 654 | `tools/importa-artifacts.py` |
| `logs/execution-log-<ferramenta>.csv`, `logs/normalize-report-<ferramenta>.json` | `cves-sast-corrigida-batch-<lote>/` | 48 | `tools/importa-artifacts.py` |
| `README.txt` | `cves-sast-corrigida-batch-<lote>/<ferramenta>/` | 24 | `tools/importa-artifacts.py` |
| `disco.txt`, `container/{lote,prevoo,resumo}.txt`, `portoes/{run-fixtures,normalize,check-log}.txt` | `cves-sast-corrigida-batch-<lote>/<ferramenta>/` | 168 | cópia byte a byte, conferida |
| `rede-semgrep/scan.json` (só nos jobs do Semgrep) | `cves-sast-corrigida-batch-<lote>/semgrep/rede-semgrep/` | 8 | idem |
| `datasets/sondagens/sondagem-<x>-runner-<data>.txt` | `datasets/sondagens/sondagem-<x>-runner-<lote>-<data>.txt` | 32 | idem, com o lote no nome |

A importação foi feita primeiro em `--dry-run` (24 de 24 aprovados) e depois
real. O importador confere que o `metadata.commit` de cada tratado e a coluna
`commit` do log de execução são o `PostPatchCommit` da lista do lote, e recusa
destino da outra campanha e sobrescrita. Depois dela,
`git diff --exit-code` sobre `results/{codeql,semgrep,snyk-code}/treated` e
sobre `results/cruzamento` saiu 0: nada da campanha de detecção foi tocado.

As sondagens mudam de nome pelo mesmo motivo da campanha 1: o nome no artifact
não traz o lote, e os oito lotes produzem o mesmo nome.

**sha256 dos 280 arquivos** — os de `logs/` deste diretório e as 32
sondagens; os tratados não entram — em `SHA256SUMS-artifacts.txt`, com
caminhos relativos à raiz do repositório:

```
sha256sum -c logs/campanha-corrigida-2026-09-29/SHA256SUMS-artifacts.txt
```

Conferido 280 de 280; a mutação de um dígito numa linha é acusada.

## Varredura de segredo antes de versionar, em 29/09/2026

O job do Snyk Code tem `SNYK_TOKEN` no ambiente do passo do lote, e o
`container/lote.txt` dele é o stdout e o stderr do container. A varredura
cobriu os 280 arquivos acima, ainda no artifact, antes da cópia, com os
padrões nomeados da campanha 1 — UUID, `snyk_*`, tokens do GitHub, AWS,
Slack, chave privada, JWT, `Bearer`, URL com credencial, atribuição a nome
sensível, e-mail — e cadeias de alta entropia. **Nenhum segredo.** O que ela
levantou:

- **3.803 ocorrências de UUID**, todas em dois contextos: 3.657 `Finding ID:`,
  3.511 distintos, todos presentes no raw SARIF do Snyk do mesmo artifact; e
  146 `urn:snyk:interaction:`, identificadores de erro do catálogo do Snyk,
  todos distintos. Nenhum UUID fora desses dois contextos
- **dois e-mails**, ambos nome de diretório de fixture do repositório do
  `CVE-2019-10775` (`test/public/…`), no `lote.txt` do CodeQL do lote `ae`
- **três cadeias de alta entropia**, as três o caminho
  `com/SLMNBJ/selectize-plugin-a11y` da URL de um repositório, nos três logs
  de execução do lote `af`
- a linha `Organization:` do resumo do Snyk sai vazia nos 214 resumos de teste (220 menos os cinco exit 3 e o
  `ERRO_ANALISE`, que não chegam ao resumo); o token
  fictício do pré-voo, `prevoo-ficticio-nao-e-segredo`, não aparece

**Controle positivo:** um arquivo sintético com uma forma falsa de cada um dos
14 padrões teve as 14 acusadas, mais a de alta entropia; e um UUID falso
enxertado no meio de uma linha de um `lote.txt` real do Snyk (lote `ad`) foi
acusado e classificado fora dos dois contextos. **Alcance declarado:** a
varredura acha segredo nas formas procuradas; o valor real do token não é
conhecido aqui, e não foi procurado literalmente.

## Os raws

Não versionados. Cópia externa, fora da árvore do projeto, um `tar` por
ferramenta com `zstd`, com `<lote>/<artifact>/results/<ferramenta>/raw/`
dentro:

| Arquivo | bytes | raws | sha256 |
|---|---:|---:|---|
| `raws-codeql-2026-09-29.tar.zst` | 1.776.490 | 220 | `525b68a8130fdac9709ad708acebe6734d49c19278b0e0bbd9f6b76c132bfe31` |
| `raws-semgrep-2026-09-29.tar.zst` | 8.000.143 | 220 | `62e9c02ef472580848010a5b27fbd862dbea032d283726e8bbbf99a56a717d7a` |
| `raws-snyk-code-2026-09-29.tar.zst` | 747.900 | 214 | `27720a9b3ab3fea3256269447724404dc7eea1d959f2ff4e1537155a5aa0face` |

Os três passam em `zstd -t`, e os 654 raws contidos são idênticos, por sha256,
aos dos artifacts: nenhum falta, nenhum sobra, e a contagem por lote bate.
Descomprimidos, somam 621,5 MiB (CodeQL 57,3, Semgrep 547,9, Snyk Code 16,3).
