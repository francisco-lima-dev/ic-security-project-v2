# CLAUDE.md

Contexto e regras do projeto. Contém apenas informação estável — regras,
convenções, invariantes e defeitos conhecidos. Progresso de execução e
pendências ficam fora deste arquivo, por envelhecerem rápido.

## Contexto do projeto

Iniciação Científica comparando ferramentas SAST (CodeQL, Semgrep, Snyk
Code) e DAST (OWASP ZAP) na detecção de vulnerabilidades em aplicações
JavaScript/TypeScript.

- Benchmark SAST: OpenSSF CVE Benchmark — 223 CVEs, 186 repositórios
  distintos, 38 CWEs distintos após normalização
- Benchmark DAST: OWASP Juice Shop e OWASP NodeGoat

## Regra crítica — checkout do commit vulnerável

Toda análise SAST **deve** fazer checkout do `PrePatchCommit`, o commit
anterior à correção.

Analisar o HEAD do branch padrão invalida a comparação com o ground truth:
os CVEs do benchmark já foram corrigidos, então o código no HEAD é a versão
corrigida. Uma campanha anterior foi inteiramente invalidada por esse erro.

Nunca analisar HEAD nem `PostPatchCommit`.

## Critério oficial de acerto do benchmark

Segundo `docs/benchmark-CVEs.md` do OpenSSF, a ferramenta ideal produz ao
menos um alerta relevante no commit `prePatch` e nenhum no `postPatch`.

O benchmark pontua por **CVE detectado**, não por localização coberta.
Acertar qualquer uma das localizações de um CVE conta como detecção.

## Unidade de análise

A unidade é o **CVE**, não o repositório. O mesmo repositório aparece com
commits diferentes em vários CVEs (bootstrap 7×, lodash 5×, jquery 4×,
rendertron 4×).

Todos os arquivos de saída são nomeados pelo ID do CVE, nunca pelo nome do
repositório. Nomear por repositório causa sobrescrita entre CVEs do mesmo
repositório e colisão entre repositórios homônimos
(`linxiaowu66/swagger-ui` vs `swagger-api/swagger-ui`).

## Formato das listas de entrada

Seis campos, sem cabeçalho:

```
CVE,URL,PrePatchCommit,CWEs,FilePath,FileLine
```

- **CWEs** — um ou mais, separados por `|`, normalizados para três dígitos
  com zero à esquerda (`CWE-079`, nunca `CWE-79`)
- **FilePath** — escalar, caminho do arquivo vulnerável segundo o ground
  truth
- **FileLine** — uma ou mais linhas separadas por `|`, ou vazio

Todo arquivo termina com quebra de linha final. A ausência dela fez o
pipeline anterior descartar silenciosamente a última linha de vários lotes.

### Invariante — nenhum campo pode conter vírgula

O formato é separado por vírgula e lido com `read` no bash, que joga o
excedente na última variável. `Repository` e `FilePath` são validados
contra vírgula no gerador; `CWEs` e `FileLine` usam `|` internamente por
esse motivo.

### Invariante — FilePath escalar

Todas as weaknesses de um mesmo CVE apontam para o mesmo arquivo. Vale para
os 223, e o `extract-urls.js` aborta caso deixe de valer, em vez de
descartar em silêncio as localizações dos demais arquivos.

### FileLine multivalorado

Os 223 CVEs somam 233 localizações. Três têm mais de uma:

| CVE | Localizações | Arquivo |
|---|---:|---|
| `CVE-2018-3725` | 5 | `bin/hekto.js` |
| `CVE-2021-23364` | 6 | `index.js` |
| `CVE-2021-31712` | 2 | `src/decorators/Link/index.js` |

São múltiplos pontos da mesma vulnerabilidade, não vulnerabilidades
distintas: mesmo arquivo, `explanation` byte-idêntica e um único conjunto de
CWEs. O schema do benchmark confirma — `Weakness` tem
`additionalProperties: false` e apenas `location` e `explanation`; os CWEs
ficam no nível do CVE.

Preservar todas as linhas evita contar como erro de localização um acerto
legítimo em linha diferente da primeira.

## Regra de processo — não regerar listas em execução

Depois que a execução dos lotes começar, **não regerar as listas**.
Conteúdo novo (Juice Shop, NodeGoat) vai em lista separada, nunca refazendo
as existentes. Regerar invalida a correspondência entre nomes de lote e os
artifacts e logs já produzidos.

O gerador exige a flag `--force` para remover lotes existentes.

## Política de versionamento

**Versionados:** `datasets/`, `tools/`, `results/*/treated/`, `logs/`,
Dockerfiles, scripts, workflows.

**Ignorados:** `results/*/raw/`, clones temporários (`src-CVE-*`),
databases do CodeQL, `node_modules/`, o clone `ossf-cve-benchmark/`.

Motivo: o repositório precisa permitir verificar os números do estudo sem
depender de artifacts do GitHub Actions, que expiram em 30 dias.

## Convenções de execução

- Cada ferramenta roda em container Docker próprio, iterando sobre os CVEs
  de um lote
- O laço é **idempotente**: pula CVE cuja saída já existe, permitindo
  retomar um lote interrompido sem reprocessar
- Todo CVE analisado gera arquivo de saída, mesmo sem achados
  (`"findings": []`), para distinguir "analisou e não achou" de "não
  analisou"
- Todo script produz log estruturado por CVE:
  `cve,repo,commit,status,mensagem,duracao_segundos`
- Limpeza do código obtido — e do database, no CodeQL — ao final de cada
  iteração, inclusive nos caminhos de erro

## Defeitos conhecidos do conjunto de dados

- `CVE-2018-1000096` não tem CWE atribuído. É analisado normalmente, mas
  fica fora das contagens da matriz de confusão
- `CVE-2017-18352` e `CVE-2018-11093` têm `PostPatchCommit` malformado no
  benchmark original da OpenSSF — truncado e abreviado, respectivamente.
  Não afeta o pipeline SAST, que usa apenas `PrePatchCommit`
- Sete CVEs de "Zip Slip" contêm aspas no campo `Explanation`. O
  `cve-metadata.csv` é RFC 4180 válido: aspas internas são escapadas por
  duplicação

## Arquitetura — normalização fora dos containers

Os containers produzem **apenas** a saída bruta, em `results/<tool>/raw/`.
A normalização para o schema comum é um passo separado, em
`tools/normalize.py`, executado fora das imagens Docker.

Motivo: a normalização é o código com maior chance de precisar de correção
(três formatos distintos, extração de CWE, mapeamento de severidade).
Separada, um bug se conserta reexecutando segundos de parsing local;
embutida no container, exigiria reexecutar clones e análises inteiras.

Por isso a idempotência do laço de análise verifica a existência do **raw**,
não do arquivo normalizado.

## Configuração das ferramentas

### CodeQL
Suíte `javascript-security-extended.qls`. A campanha anterior usou
`security-and-quality`, que acrescenta consultas de qualidade
(`js/unused-local-variable` e afins) responsáveis por 46% dos achados sem
CWE. Regra de qualidade não é alegação de vulnerabilidade: computá-la como
falso positivo mediria a escolha de suíte, não a precisão da ferramenta.

A troca é subtração limpa — `security-and-quality` contém tudo de
`security-extended` mais as consultas de qualidade.

### Semgrep
Nunca `--config=auto`. O conjunto de regras é vendorizado: o YAML resolvido
é baixado uma vez, versionado no repositório com sha256 e data, e apontado
por caminho local. Isso permite execução offline (`--network=none`,
verificado) e torna o conjunto descritível na monografia.

Flags: `--time` (grava o inventário de regras aplicadas em `.time.rules[]`
dentro do próprio JSON, por CVE) e `--metrics=off` (com config local o
Semgrep não envia telemetria, mas a flag torna isso explícito).

**Armadilha do prefixo no `check_id`.** O Semgrep prefixa o `check_id` com
o nome do diretório que contém o YAML:

```
--config=/packs/default.yaml  →  packs.javascript.lang.security...
--config=/default.yaml        →  javascript.lang.security...   ← correto
```

O pack vendorizado **deve** ser montado na raiz do sistema de arquivos do
container. Caso contrário os identificadores de regra divergem dos do
registry e da campanha anterior, quebrando a comparação em silêncio.

**Pack: `p/default`, sozinho.** Foi o que o `--config=auto` resolvia na
campanha anterior (145/145 regras, cobertura total dos achados). Cobre 73%
dos pares CVE×CWE do benchmark, contra 45% de `p/javascript` e 58% da
combinação `p/javascript` + `p/security-audit`.

`p/javascript` é orientado a framework, não a linguagem: é subconjunto de
`p/default` a menos de uma única regra, e não contém as regras genéricas
mais produtivas (path traversal, prototype pollution). `p/security-audit`
tem apenas 20 regras JS/TS de 225.

A união com `p/javascript` foi medida e descartada: acrescentaria uma
regra, de CWE-079 já coberto por outras 35, com zero achados na amostra, ao
custo de um segundo snapshot para versionar.

Os packs `p/*` do registry respondem sem autenticação — exigem apenas rede.

### Snyk Code
Somente `--sarif-file-output`. O `--json-file-output` produz arquivo
byte-idêntico ao SARIF; passar os dois duplica dados sem ganho.

CLI baixado de URL versionada (`https://static.snyk.io/cli/v<versão>/snyk-linux`),
nunca `latest` nem `stable` — ambos já mudaram desde a campanha anterior.

Exige autenticação: o script espera `SNYK_TOKEN` no ambiente, falha com
mensagem clara se ausente, e nunca o grava em log nem o expõe via `set -x`.

## Formato das saídas das ferramentas

Referência apurada sobre os resultados reais. Todas emitem caminho de
arquivo **relativo e limpo**, sem prefixo de diretório de trabalho.

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| Formato | SARIF 2.1.0 | JSON próprio | SARIF 2.1.0 |
| CWE | `tool.driver.rules[].properties.tags[]`, prefixo `external/cwe/` | `results[].extra.metadata.cwe` | `tool.driver.rules[].properties.cwe[]` |
| Formato do CWE | `external/cwe/cwe-079`, minúsculo | `"CWE-829: descrição"` | `"CWE-94"`, padding inconsistente |
| Caminho | `results[].locations[0].physicalLocation.artifactLocation.uri` | `results[].path` | igual ao CodeQL |
| Linhas | `region.startLine`; `endLine` ausente em 96,7% | `start.line` / `end.line`, sempre ambos | `region.startLine` / `endLine`, sempre ambos |
| Severidade | apenas na regra (`defaultConfiguration.level`) — exige join | `results[].extra.severity` | `results[].level` |
| Valores | `error` / `warning` / `note` | `ERROR` / `WARNING` / `INFO` / `MEDIUM` | `error` / `warning` / `note` |
| Regra | `results[].ruleId` | `results[].check_id` | `results[].ruleId` |
| Versão | `tool.driver.semanticVersion` | `.version` no topo | `tool.driver.semanticVersion` |

Pontos de atenção do normalizador:

- **`extra.metadata.cwe` do Semgrep muda de tipo** — array na maioria dos
  casos, string nua numa minoria. Iterar uma string nua percorre
  caracteres.
- **Resolver a regra por `ruleId`**, não por `ruleIndex`, no CodeQL e no
  Snyk. Custa o mesmo e é robusto a reordenação.
- **`line_end` aceita nulo** — ausente na quase totalidade dos achados do
  CodeQL.
- **A severidade do CodeQL exige join com a tabela de regras** — é a única
  das três assim, e o dado que mais facilmente vira nulo silencioso. Contar
  e reportar quantos achados ficaram sem severidade resolvida.
- **`fingerprint` e `lines` do Semgrep trazem a string literal
  `"requires login"`** quando a ferramenta roda sem autenticação. Depende de
  login, não da origem do config, e não afeta `check_id`, caminho, linhas,
  severidade nem `metadata.cwe` — que é tudo o que o normalizador consome.
- No Snyk, `runs[0].properties.coverage[]` permite distinguir "analisou e
  não achou" de "não havia arquivo analisável", e `automationDetails.id`
  serve como fonte do `analysis_date`.
- **`security-severity` do CodeQL** é campo à parte, exclusivo dessa
  ferramenta, capturado no schema como numérico anulável. Não serve de base
  para `severity_normalized`: mede impacto no estilo CVSS, enquanto o
  `level` (derivado de `problem.severity`) mede confiança na alegação — o
  mesmo valor 7.5 aparece tanto como `warning` quanto como `error`.
  Presente em toda regra com tag `security`, logo cobertura de 100% sob
  `security-extended`. Formato inconsistente (`5` e `5.0`): parsear como
  float, nunca comparar como texto.

## Características do conjunto de dados relevantes ao cruzamento

- **Famílias de CWE.** CWE-023, 036, 073 e 099 são variantes de path
  traversal. O benchmark usa a família inteira; as ferramentas costumam
  rotular suas regras apenas com 022 ou 073. Comparar por identificador
  exato subestima a detecção — o agrupamento por família é decisão a
  resolver na etapa de cruzamento.

## O que NÃO fazer

- Não analisar HEAD nem `PostPatchCommit`
- Não nomear saídas pelo nome do repositório
- Não usar `|| true` em builds ou execuções de workflow — mascara falhas e
  faz o job passar como bem-sucedido com o container quebrado
- Não redirecionar o stderr de `git clone`/`fetch` para `/dev/null` —
  descarta a razão da falha
- Não regerar listas com execução em andamento
- Não gravar campo com vírgula nas listas de entrada
- Não usar `--config=auto` no Semgrep
- Não montar o pack vendorizado do Semgrep em subdiretório
- Não passar `--json-file-output` ao Snyk
- Não usar `latest` ou `stable` para o CLI do Snyk