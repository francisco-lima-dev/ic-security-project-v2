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

Esse critério é o que fundamenta a modalidade de **correspondência por
conjunto** descrita adiante.

## Unidade de análise

A unidade é o **CVE**, não o repositório. O mesmo repositório aparece com
commits diferentes em vários CVEs (bootstrap 7×, lodash 5×, jquery 4×,
rendertron 4×).

Todos os arquivos de saída são nomeados pelo ID do CVE, nunca pelo nome do
repositório. Nomear por repositório causa sobrescrita entre CVEs do mesmo
repositório e colisão entre repositórios homônimos
(`linxiaowu66/swagger-ui` vs `swagger-api/swagger-ui`).

## Proveniência do ground truth — CodeQL

**Medido em setembro de 2026. Condiciona todo o cruzamento.**

Os rótulos do ground truth não resultam de classificação independente dos
CVEs: em 83% do conjunto, `explanation` e `CWEs` foram herdados da consulta
do CodeQL que identificou o caso.

| Verificação | Resultado |
|---|---|
| `explanation` idêntica ao `@name` de consulta do pacote JS do CodeQL | 185 de 223 (83,0%) |
| Destas, com `CWEs` idêntico às tags `external/cwe/` da consulta (estado de dez/2020) | 185 de 185 (100%) |
| Divergências não explicadas | 0 |
| Controle: `explanation` idêntica a mensagem de regra do Semgrep (2.228 regras) | 0 (0,0%) |

O cotejo contra o CodeQL **atual** dá 108 idênticos, 75 subconjuntos e 2
divergentes; as três situações se resolvem pela evolução posterior do
catálogo. Usar sempre o estado de **9 de dezembro de 2020**, data do anúncio
do benchmark.

Os 38 sem correspondência têm `explanation` em prosa, escrita à mão — outra
camada de proveniência.

### Consequência prática

**O campo `CWEs` não é classificação do defeito.** É o conjunto de tags da
consulta que originou o registro, e descreve uma família (path traversal:
022+023+036+073+099) ou um conjunto de impactos potenciais (prototype
pollution: 078+079+094+400+915).

Isso invalida qualquer tratamento que assuma um CWE por defeito.

### Reprodução

Scripts versionados em `tools/ground-truth/`. O CWE pretendido pelo
benchmark para qualquer CVE do núcleo é recuperável consultando as tags da
consulta correspondente no CodeQL em dez/2020.

## Caracterização estrutural do ground truth

| Característica | Valor |
|---|---:|
| CVEs no conjunto | 223 |
| CVEs que apontam exatamente um arquivo | 223 (a totalidade) |
| Weaknesses (localizações) no conjunto | 233 |
| CVEs com mais de uma weakness | 3 |
| CVEs com um único CWE | 57 |
| CVEs com mais de um CWE | 165 (74,0%) |
| CVEs sem CWE | 1 |
| Pares (CWE, arquivo) efetivamente afirmados | 222 |
| Pares que a expansão cartesiana geraria | 534 (+140,5%) |
| CVEs com CWE sem zero à esquerda no próprio benchmark | 14 |

**A dimensão de arquivo é degenerada:** (CWE, arquivo) ≡ (CWE, CVE). O
arquivo é função do CVE e não acrescenta poder discriminante.

**165 CVEs têm mais de um CWE para um defeito único**, em um único arquivo.
Os 165 se distribuem em apenas **17 conjuntos distintos**; os cinco maiores
cobrem 136 deles (82,4%).

## Tratamento do ground truth — dupla apuração

**Nunca expandir um CVE multivalorado em uma linha por CWE.** Os 222 pares
reais virariam 534, e as ~312 linhas acrescidas seriam combinações que
ferramenta alguma pode reportar — todas contadas como falso negativo, por
artefato do protocolo.

As métricas são apuradas em duas modalidades sobre o mesmo conjunto de
resultados:

| Modalidade | TP quando | Unidade |
|---|---|---|
| Correspondência por conjunto | a ferramenta reporta **qualquer um** dos CWEs do CVE, no arquivo do ground truth | (CVE, arquivo) — 222 |
| Correspondência por CWE primário | a ferramenta reporta **o** CWE que descreve o defeito | (CWE, arquivo) — 222 |

Denominadores idênticos, apurações diretamente comparáveis. A diferença
entre elas é resultado em si: mede acerto de família versus acerto de
classificação específica.

### Regra de fechamento do CWE primário

**O primário tem que pertencer ao conjunto declarado pelo benchmark para
aquele CVE.** Atribuir identificador de fora — ainda que taxonomicamente
mais preciso — é editar o ground truth, não interpretá-lo, e torna o alvo
inatingível para qualquer ferramenta.

Evidência, em ordem de precedência: o campo `explanation`; na sua
insuficiência, o diff entre `prePatch` e `postPatch`.

A tabela de mapeamento dos 17 conjuntos é versionada em
`datasets/cwe-primario.csv`, uma linha por conjunto, com a evidência de cada
decisão. Sua aplicação é automática.

**Exceção documentada:** `CVE-2017-16023` e `CVE-2018-7560` descrevem
injeção de expressão regular, não ReDoS como os outros 23 do conjunto
`CWE-400 + CWE-730`. O identificador adequado (CWE-624) não está no
conjunto; pela regra de fechamento, recebem o primário do grupo.

### Sem agrupamento por família de CWE

Decisão fechada. O agrupamento em família é propriedade do **ground truth**,
não convenção de rotulagem das ferramentas: os cinco identificadores de path
traversal comparecem juntos porque são as tags da consulta `js/path-injection`.
O problema é tratado na origem, pela seleção do CWE primário, e não por
critério de agrupamento na comparação.

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

O gerador emite **aviso não bloqueante** para as anomalias que são do
próprio benchmark e cujo tratamento cabe à normalização: `PostPatchCommit`
malformado e `FilePath` fora de forma canônica. A lista sai byte-idêntica —
o aviso torna a anomalia visível na geração, e não três etapas adiante.

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
legítimo em linha diferente da primeira. Na métrica de precisão de
localização, a faixa é atribuída pela **menor** divergência entre a linha
reportada e qualquer uma das linhas do ground truth.

## Regra de processo — não regerar listas em execução

Depois que a execução dos lotes começar, **não regerar as listas**.
Conteúdo novo (Juice Shop, NodeGoat) vai em lista separada, nunca refazendo
as existentes. Regerar invalida a correspondência entre nomes de lote e os
artifacts e logs já produzidos.

O gerador exige a flag `--force` para remover lotes existentes.

## Política de versionamento

**Versionados:** `datasets/` (incluindo `cwe-primario.csv` e
`v1-checkids.txt`), `tools/`, `tests/fixtures/` e `tests/run-fixtures.py`,
`results/*/treated/`, `results/zap/`, `logs/` (incluindo
`normalize-report-<ferramenta>.json`), o pack vendorizado do Semgrep e seu
descritor, Dockerfiles, scripts, workflows.

**Ignorados:** `results/*/raw/`, clones temporários (`src-CVE-*`),
databases do CodeQL, `node_modules/`, o clone `ossf-cve-benchmark/`.

`results/zap/` guarda os oito relatórios da campanha DAST de julho de 2026
(JSON e HTML por aplicação e modo) mais o plano de automação. São os
**únicos dados de detecção válidos do estudo** — a campanha SAST anterior
foi invalidada. Existiam em cópia única fora de controle de versão.

Os relatórios não trazem campo de modo de varredura. A correspondência
está no README do diretório, estabelecida por contagem de alertas
(10/14/23/29) e não por nomenclatura: `juice-shop-report.json` é o
baseline, apesar do nome não dizer. **Não renomear** — os nomes são o
artefato produzido pela execução.

Ainda **não** trazidos para o repositório: os scripts de proveniência do
ground truth (previstos em `tools/ground-truth/`) e o script de sondagem
de disponibilidade dos repositórios.

Motivo: o repositório precisa permitir verificar os números do estudo sem
depender de artifacts do GitHub Actions, que expiram em 30 dias.

**Verificar versionabilidade com `git add --dry-run`, nunca com
`git check-ignore -v`.** O `-v` reporta *casamento de padrão*, não veredito,
e devolve 0 tanto para padrão de ignore quanto para negação: para
`logs/normalize-report-semgrep.json` ele imprime `!logs/**` e sai 0, e para
`results/semgrep/raw/*.json` imprime `results/*/raw/` e também sai 0. Só o
`add --dry-run` distingue os dois casos.

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
- **Escrita atômica da saída bruta**: escrever em nome temporário e
  renomear para o definitivo só após validar. A idempotência olha o nome
  definitivo, então interrupção abrupta (SIGKILL, OOM, limite de job) não
  deixa arquivo truncado que a execução seguinte leia como análise
  concluída. O nome temporário não pode casar com os globs do normalizador
  (`*.json`, `*.sarif`, `CVE-*`), e resíduo de execução anterior é removido
  antes de processar cada CVE
- **Remover saída parcial antes de registrar erro.** Sem isso, um raw
  truncado deixado por análise que falhou faz a idempotência pular aquele
  CVE para sempre
- **Assertar o commit analisado**: comparar `git rev-parse HEAD` com o
  `PrePatchCommit` e gravar o valor efetivo no log. Sem a asserção, a
  garantia repousa na semântica do `FETCH_HEAD` e nenhum artefato registra
  qual commit foi submetido às ferramentas
- Sinal de interrupção deve **encerrar** o script, não só limpar. Um
  `trap ... INT TERM` que apenas chama a função de limpeza retorna e o
  bash retoma no comando seguinte: o laço continua e o log ganha linhas de
  erro para CVEs jamais tentados

### Conjunto de status do log

`OK`, `SEM_ACHADOS`, `PULADO`, `ERRO_LINHA`, `ERRO_FETCH`,
`ERRO_CHECKOUT`, `ERRO_ANALISE`, mais `SEM_ARQUIVO_ANALISAVEL` **só no
Snyk Code**.

`SEM_ARQUIVO_ANALISAVEL` corresponde ao exit 3 do Snyk, "nenhum projeto
suportado". É **resultado, não falha**: a análise não quebrou, e não há o
que analisar. Registrar como `ERRO_ANALISE` faria a reexecução tentar
indefinidamente e sumiria da leitura de cobertura — o defeito acessório
que a campanha anterior cometeu. Consequência assumida: a idempotência não
pula esse CVE, porque não há raw cuja existência o sinalizasse, e fabricar
um SARIF que a ferramenta não emitiu seria pior.

### Permissões dos artefatos produzidos em container

Os três containers rodam como root; sem intervenção, `results/*/raw/` e
`logs/*.csv` saem com dono root no volume montado e o usuário do hospedeiro
não os reescreve.

**Decisão, por medição (08/09/2026): `--user` com `HOME` explícito.**

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e XDG_CACHE_HOME=/tmp \
    -v "$PWD":/workspace \
    ic-security-lab-<x> datasets/listas/cves-sast-batch-aa
```

Resolve na origem, em vez de `chown` pós-lote, que só desfaz o atrito depois
de criado. O `-e HOME=/tmp` **não é opcional**: sob uid ausente do
`/etc/passwd` da imagem, `HOME` fica `/`, que não é gravável.

| Imagem | `--user` só | `--user` + `HOME=/tmp` |
|---|---|---|
| `semgrep` (python:3.12-slim) | **quebra**: `PermissionError: '/.semgrep'` | OK |
| `snyk-code` (debian:bookworm-slim) | `--version` passa, **`config set` falha** (`SNYK-CLI-0000`) | OK — grava em `/tmp/.config/configstore/` |
| `codeql` (node:24-bookworm) | passa | OK |

O CodeQL passar **é coincidência do uid deste hospedeiro**: `node:24-bookworm`
já tem um usuário 1000 (`node`), e `HOME` resolve para `/home/node`. Sob uid
1001 — o do runner do GitHub Actions — `HOME` vira `/` como nas outras. Por
isso a invocação é a mesma nas três, e não condicionada à ferramenta.

Verificado ainda, sob `--user` nas três imagens: `/tmp` continua gravável
(onde vivem `WORKDIR` e `DBDIR`), o volume montado recebe escrita, e os
arquivos saem com o uid/gid do hospedeiro.

O `--version` é sonda fraca para as ferramentas que gravam estado de usuário:
o Snyk passa nele e falha ao escrever configuração. Sondar com um comando que
**escreva**.

### Revisão antes da execução

Todo script, Dockerfile ou normalizador passa pelo subagente
`revisor-pipeline` antes de commit. O checklist dele deriva dos defeitos
reais que invalidaram a campanha anterior. Revisão sem apontamentos é
resultado válido.

**Limitação declarada, não corrigida.** A revisão incide sobre a versão
*anterior* às correções que ela mesma motiva. As verificações mecânicas são
refeitas sobre a versão final — na Fase D, a suíte de fixtures passou de 113
para 143 asserções, cobrindo cada correção —, mas **não há segunda revisão
completa**. Vale para a Fase C (declarado na Seção 8.5 da metodologia) e
reaparece na Fase D pelo mesmo motivo: uma segunda revisão motivaria novas
correções, e a recursão não tem ponto de parada natural.

## Obtenção do código — comportamento medido

Fetch raso por SHA, com fallback para clone completo. Medições de
setembro de 2026:

- O GitHub **aceita** fetch raso por SHA arbitrário, inclusive de commit
  fora do branch padrão. O fallback deve disparar raramente
- O clone de fallback usa `--no-single-branch` **explícito**. É redundante
  ante o default do Git, mas a config `clone.defaultSingleBranch` o
  inverteria em silêncio
- Isso não é precaução abstrata: **4 dos 7 CVEs do bootstrap**
  (`CVE-2018-14040`, `CVE-2018-14042`, `CVE-2018-20676`, `CVE-2018-20677`)
  têm o commit alcançável apenas por `origin/v3-dev`, não pelo branch
  padrão. Sob clone single-branch, os quatro dariam `ERRO_CHECKOUT`
  dispersos entre lotes, sem causa comum aparente
- Fora do alcance de ambos: commit só em `refs/pull/*`, em fork, ou em
  branch removido — e são os mesmos casos em que o fetch raso também
  falha, então ali o fallback paga o timeout sem resolver
- **Contar** quantos CVEs usaram fallback, como métrica própria e não só
  na coluna mensagem. O valor esperado é baixo; elevação súbita indica
  mudança no servidor ou degradação do conjunto

Sondar a disponibilidade dos 186 repositórios **imediatamente antes de
cada campanha**, com saída datada e versionada. Sondagem é observação;
script é procedimento.

## Defeitos conhecidos do conjunto de dados

- `CVE-2018-1000096` não tem CWE atribuído. É analisado normalmente, mas
  fica fora das contagens da matriz de confusão
- `CVE-2017-18352` e `CVE-2018-11093` têm `PostPatchCommit` malformado no
  benchmark original da OpenSSF — truncado e abreviado, respectivamente.
  Não afeta o pipeline SAST, que usa apenas `PrePatchCommit`
- Sete CVEs de "Zip Slip" contêm aspas no campo `Explanation`. O
  `cve-metadata.csv` é RFC 4180 válido: aspas internas são escapadas por
  duplicação
- **`CVE-2019-12041` declara `FilePath` absoluto**: `/index.js`, com barra
  inicial, no próprio benchmark da OpenSSF (conferido em
  `datasets/cve-metadata.csv`, não é defeito do gerador). É o único dos 223.
  O arquivo é `index.js` na raiz do repositório. O normalizador remove a
  barra, preserva o valor original em `gt_file_path_original` e avisa no
  stderr. Sem isso, `gt_file_scanned` daria `false` por comparação contra um
  caminho que ferramenta alguma emite, e o CVE viraria falso negativo
  garantido no cruzamento — sem erro visível.
  A remoção vale **só para o ground truth**: caminho do benchmark é relativo
  ao repositório por definição, ao passo que caminho absoluto vindo de uma
  **ferramenta** sinaliza que a premissa do WORKDIR quebrou, e é preservado
  e reportado, nunca comido em silêncio
- **14 CVEs trazem CWE sem zero à esquerda** (`CWE-79`) no próprio ground
  truth. A normalização de três dígitos aplica-se ao ground truth **e** às
  saídas das ferramentas, não só a estas

  Este e o `/index.js` acima são **o mesmo tipo de defeito**: o benchmark
  grava um valor fora de forma canônica, e comparar sem normalizar produz
  divergência silenciosa. Logo a regra é geral — **o ground truth é
  normalizado antes de qualquer comparação, em CWE e em caminho.** Ambos são
  detectados na geração (aviso não-bloqueante do `generate-lists.js`) e
  corrigidos na normalização, nunca editados na lista
- `CVE-2017-16114` e `CVE-2017-17461` incidem sobre o mesmo repositório e
  arquivo, em linhas adjacentes (459 e 460). Sem colisão na execução, já que
  cada um roda em seu commit; relevante apenas se resultados forem agregados
  entre CVEs na métrica de localização
- `docs/benchmark-CVEs.md` exemplifica `CVE-2020-8203` com `CWE-471` e
  descrição em prosa; o arquivo distribuído para o mesmo CVE traz cinco CWEs
  e o nome de consulta do CodeQL. A especificação e a instância divergem, e
  ambas entraram no mesmo release
- O repositório do benchmark é importação achatada: 88 commits, o mais
  antigo sendo o release 1.0.0 de 22/09/2020. O processo de construção do
  dataset não é recuperável a partir dele
- **`linxiaowu66/swagger-ui` não existe mais.** Sondagem de 06/09/2026:
  185 dos 186 repositórios alcançáveis, um inacessível. Atinge
  `CVE-2016-1000229`, que está no lote de teste e no `batch-aa` — a
  primeira coisa que a Fase E roda contém um `ERRO_FETCH` **esperado**, em
  1 dos 5. Não é defeito do script.
  Não é falso negativo: nenhuma ferramenta foi confrontada com o código,
  porque não houve código. Categoria própria, fora da matriz —
  **denominador cai de 222 para 221 pares**, em ambas as modalidades.
  Reconferir na hora da campanha: repositório pode voltar, outro pode cair.
  Ironia registrada: é justamente um dos dois homônimos que motivaram a
  regra de nomear saídas pelo CVE

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

Corolário prático: **a tabela de CWE primário não bloqueia a campanha**. O
campo `gt_cwe_primary` é preenchido na normalização, que roda depois e é
barata de refazer.

`tools/normalize.py` **não lê, não importa e não invoca o log de execução**.
A separação entre coleta e normalização existe para que a etapa barata não
herde as dependências da cara: log ausente ou parcial não pode derrubar a
normalização. As conferências que precisam do log vivem em
`tools/check-log.py`, script próprio, e os dois não se referenciam.

Pelo mesmo motivo o `metadata.commit` vem **da lista de entrada**, não do log.
A asserção do commit é fatal no script de análise — divergência entre
`git rev-parse HEAD` e o `PrePatchCommit` dá `ERRO_CHECKOUT` e o CVE não é
analisado —, logo, para todo CVE que tem raw, o commit pretendido e o efetivo
coincidem por construção. A evidência está no log, que é versionado, e não se
replica no tratado.

O relatório de cada execução vai para `logs/normalize-report-<ferramenta>.json`,
versionado, irmão do `execution-log-*.csv`. As fixtures sintéticas ficam em
`tests/fixtures/`, **fora** de `results/*/raw/` — aquele diretório é ignorado
e os nomes casariam com os globs do normalizador.

**Raw ilegível é falha, nunca `findings: []`.** JSON ou SARIF que não
parseia, ou sem a estrutura mínima (`runs[]`, `runs[0]` objeto, `results[]`
lista), interrompe aquele CVE com erro e **não** grava tratado. O critério é
**tipo de exceção**, jamais casamento de texto de mensagem — mensagem de
parser muda com a versão da biblioteca, e a contagem de raws ilegíveis é
dado da monografia. O laço segue para o próximo CVE e a execução termina com
código não nulo se houve ao menos um.

É o que pega SARIF vazio ou malformado do Snyk, a única das três cujo raw o
laço de análise não valida.

**Fronteira a resolver no smoke test:** `results` é opcional no SARIF. Se o
Snyk **omitir** a chave em varredura sem achados, toda análise limpa vira
falha dura. Nesse caso a regra passa a ser "ausência de `results` com
`coverage[]` presente = zero achados". É o item de maior risco de bloqueio
da Fase E.

### `tools/check-log.py` — conferências do registro

```
python3 tools/check-log.py --tool <ferramenta> [--lista-lote <arquivo>]
```

Deduplica por CVE mantendo a **última** linha: reexecução acrescenta uma
linha `PULADO` por CVE já feito, e o log não tem timestamp nem id de
execução.

| Conferência | Significado |
|---|---|
| status de erro **com** raw | incoerência — houve saída para item registrado como falho |
| `OK`/`SEM_ACHADOS` **sem** raw | incoerência — a saída sumiu ou nunca foi promovida |
| `PULADO` **sem** raw | incoerência — a idempotência se apoiou em arquivo inexistente |
| `SEM_ARQUIVO_ANALISAVEL` sem raw | **esperado**, só contado |

A quarta, opcional, exige `--lista-lote`: CVE sem raw **e** sem linha de log
é a assinatura observável do defeito do fd 0, que não produz erro visível.

**`--lista-lote` recebe a lista do lote, nunca a completa** — contra a
completa, todo CVE de lote ainda não rodado apareceria como sumido. O script
avisa se a lista passada exceder o tamanho de lote.
Atenção ao nome: o `normalize.py` tem `--lista`, que é a lista **completa**.
Semânticas opostas, por isso nomes distintos.

## Schema comum de saída

Bloco `metadata` por CVE, lista `findings`. Campos de ground truth
prefixados por `gt_`, no bloco de metadados, não repetidos por achado:

- `gt_cwes` — conjunto declarado pelo benchmark, normalizado
- `gt_cwe_primary` — CWE selecionado pela tabela de mapeamento; nulo nos
  CVEs sem CWE e naquele cujo conjunto segue sem primário definido
- `gt_file_path` — escalar
- `gt_file_lines` — lista, podendo ter mais de um elemento em três CVEs

- `gt_file_scanned` — tri-estado: a ferramenta considerou o arquivo do
  ground truth? `true`/`false` no Semgrep (`paths.scanned`) e no Snyk
  (`coverage[]`); **`null` no CodeQL**, cujo SARIF não traz inventário de
  arquivos varridos. O `null` é assimetria declarada, não omissão —
  acompanha sempre `gt_file_scanned_reason`.
  Aplicado aos 223, não só aos cinco CVEs cujo arquivo não tem extensão
  (`bin/public`: CVE-2018-16480, CVE-2018-3731, CVE-2018-3747;
  `bin/http-live`: CVE-2018-16479, CVE-2019-5423). Custa o mesmo e dá o
  denominador de arquivos varridos por ferramenta.
  **`false` não exclui de denominador algum** — ver "O que NÃO fazer"

- `tool_diagnostics` — o que a ferramenta reporta sobre a própria execução:
  `errors` e `skipped_paths` (Semgrep), `notifications`
  (`invocations[].toolExecutionNotifications`, CodeQL e Snyk),
  `gt_file_affected` e `details`. Captura **condicional**: campo ausente
  grava `null` e segue; ausência nunca é falha, porque a emissão não está
  assegurada — no Snyk, o SARIF admite `toolExecutionNotifications` mas não
  se verificou que emite.
  Motivo de existir: arquivo cuja análise falhou não produz achado, e o
  resultado é indistinguível de análise limpa. Mesmo modo de falha que o
  `gt_file_scanned` pega, por outro caminho.
  `gt_file_affected` é **heurística por subcadeia sobre texto truncado**, e
  o próprio tratado declara isso em `gt_file_affected_method`. Não entra em
  contagem alguma da matriz

- `schema_version` — literal. Tratado com versão divergente da corrente
  **não** é pulado pela idempotência: reprocessa, ou falha se faltar
  `--overwrite`. Sem isso, evolução do schema produz conjunto heterogêneo
  sem sinal

- `analysis_date_source` — `tool` ou `file_mtime`. CodeQL usa
  `invocations[0].endTimeUtc`; Snyk, `automationDetails.id`; o Semgrep **não
  tem carimbo de tempo no JSON**, e cai no mtime do raw.
  O campo existe porque o mtime é proveniência mais fraca: não sobrevive a
  download de artifact nem a `git clone` — e o tratado é versionado, então o
  mtime de qualquer cópia obtida do repositório é o do checkout. Declarar a
  origem é melhor que uniformizar por aparência

**Identificadores do schema JSON em inglês.** Nomes de arquivo, valores de
status do log e tabelas auxiliares (`cwe-primario.csv`) mantêm o
português já adotado. `gt_cwe_primary`, nunca `gt_cwe_primario`.

**`ruleset` é estrutura, não string em prosa** — o campo sustenta a
reprodutibilidade e precisa ser comparável programaticamente:

```json
"ruleset": {
  "name": "p/default",
  "sha256": "…",
  "rules_id_sha256": "…",
  "obtained_at": "…",
  "rules_total": 1074
},
"rules_loaded": 1074
```

Preenchimento por ferramenta:

- **Semgrep** — completo; `rules_loaded` vem de `.time.rules[]`. A
  comparação `rules_loaded` × `rules_total` detecta pack obsoleto.
  `rules_id_sha256` vem do descritor e é **obrigatório**: o `sha256`
  identifica o *arquivo*, e só ele não permite a um terceiro verificar
  identidade de *conjunto*, porque o registry serve o YAML em ordem não
  determinística. Sem o campo no tratado, quem lê um treated isolado teria de
  ir ao descritor
- **CodeQL** — `name` = referência da suíte, `sha256`, `rules_id_sha256` e
  `obtained_at` nulos, `rules_total` 104, `rules_loaded` **nulo**: o `driver.rules[]` do
  SARIF registra o que apareceu, não o que foi carregado
- **Snyk Code** — `ruleset` nulo inteiro, `rules_id_sha256` incluso; não há
  conjunto declarável

**`severity_normalized` tem cinco valores, não quatro.** Além de `high`,
`medium`, `low` e `unknown`, existe `unresolved`: regra que o `ruleId` **não
resolveu** na tabela de regras do SARIF. É defeito de junção do normalizador,
e colapsá-lo em `unknown` — que é ausência legítima de nível numa regra
resolvida — esconderia um bug atrás de uma categoria prevista. Os dois vão
separados ao relatório. Ocorrência de qualquer um dos dois é sinal a
investigar: nenhum achado da campanha anterior caiu neles.

**`gt_file_path_original`** aparece só quando o `gt_file_path` do benchmark
precisou ser normalizado — hoje um único CVE, `CVE-2019-12041`, que declara
`/index.js` com barra inicial. Guarda o valor como veio, para que o tratado
seja cotejável com o benchmark sem consultar o relatório.

**`gt_file_scanned_reason`** acompanha o `gt_file_scanned` quando ele é
`null`, dizendo por quê. O `null` tem mais de uma causa — o SARIF do CodeQL
não traz inventário de arquivos varridos; o Semgrep pode vir sem
`paths.scanned`; a `coverage` do Snyk pode vir agregada por linguagem, sem
caminhos — e sem o motivo as três viram a mesma coisa na leitura.

**Chave canônica na busca da tabela de primário.** Normalizar para três
dígitos, ordenar, juntar. Nunca casar por string crua contra a grafia em
prosa. Conjunto **ausente** da tabela → falha ruidosa. Conjunto
**presente com primário vazio** (`CWE-250|CWE-400`) → grava nulo, conta,
reporta. São erros diferentes.

## Configuração das ferramentas

### CodeQL
Suíte `javascript-security-extended.qls`. A campanha anterior usou
`security-and-quality`, que acrescenta consultas de qualidade
(`js/unused-local-variable` e afins) responsáveis por 46% dos achados sem
CWE. Regra de qualidade não é alegação de vulnerabilidade: computá-la como
falso positivo mediria a escolha de suíte, não a precisão da ferramenta.

A troca é subtração limpa — `security-and-quality` contém tudo de
`security-extended` mais as consultas de qualidade.

Caminho de suíte verificado no bundle 2.25.4:
`codeql/javascript-queries:codeql-suites/javascript-security-extended.qls`
— resolve, 104 consultas, 100 com CWE.

**`--build-mode=none` com `--language=javascript` verificado ponta a
ponta** (set/2026), em CodeQL 2.26.4, não na 2.25.4 fixada. Confirmou
quatro propriedades:

- o modo é aceito e o database é criado
- o caminho no SARIF sai **relativo e limpo** (`app.js`), sem prefixo do
  diretório de trabalho — a propriedade de que todo o cruzamento depende,
  e que vem de invocar a ferramenta com `--source-root=.` de dentro do
  WORKDIR
- 101 de 103 regras com CWE e as **mesmas** 101 com `security-severity`;
  as duas sem CWE são consultas de Summary, que não produzem achado
- `database analyze` sai **0 mesmo com achados**, então checar
  `RC != 0` não rebaixa análise bem-sucedida

Fica por verificar na imagem real: se `node:24` é runtime suportado pelo
extrator TypeScript e se o asset do bundle existe na tag. Smoke test com
`cves-sast-teste` antes do primeiro lote.

O `--format=sarif-latest` é flutuante por definição; só está pinado porque
o bundle está.

### Semgrep
Nunca `--config=auto`. O conjunto de regras é vendorizado: o YAML resolvido
é baixado uma vez, versionado no repositório com sha256 e data, e apontado
por caminho local. Isso permite execução offline (`--network=none`,
verificado) e torna o conjunto descritível na monografia.

**Onde vive e como entra na imagem.** Arquivo em
`ic-security-lab-semgrep/rules/semgrep-default.yaml`, com o descritor
irmão `semgrep-default.meta.json`. Entra na imagem por **`COPY` para
`/default.yaml`**, não por mount em `docker run`.

O `COPY` não é o que resolve a armadilha do prefixo — um mount na raiz
resolveria igual. O que ele faz é mover a garantia da invariante para
dentro da imagem, onde ninguém a altera sem rebuild, e tornar a imagem
autocontida. Custo nulo: o workflow reconstrói a imagem a cada execução.

O caminho é dentro do diretório da ferramenta porque o build context é
`ic-security-lab-<x>/` (verificado nos workflows da campanha anterior:
todos fazem `cd` e depois `docker build .`, sem `-f`). Um `rules/` na raiz
não seria alcançável pelo `COPY`.

**Obtenção:** `curl -sS https://semgrep.dev/c/p/default`, do host. O
Semgrep 1.171.0 não oferece mecanismo de dump — `show dump-config` produz
AST OCaml de 94 MB e não há cache de regras em disco. O corpo servido é
idêntico byte a byte dentro e fora do container, com ou sem o header
`Accept: application/json` que o cliente envia.

**Guarda de sha256 — duas comparações, ambas fatais.** O pack existe em
dois lugares, repositório e imagem, e cada comparação pega um modo de
falha distinto. Nenhuma cobre a outra.

1. `/default.yaml` contra o `$PACK_SHA256` do `--build-arg`. Pega
   `--build-arg` errado ou esquecido no build, e bind-mount sobre
   `/default.yaml` em runtime. O script exige antes que `PACK_SHA256`
   esteja presente e não vazio, e aborta se não estiver.
2. `/default.yaml` contra
   `$WORKSPACE/ic-security-lab-semgrep/rules/semgrep-default.yaml`, que
   está montado. Pega o arquivo do repositório mudado sem rebuild — o caso
   que a comparação (1) **não** alcança, porque `ARG` e `COPY` congelam no
   mesmo build e os dois lados mudam juntos.

Se o repositório não estiver montado, a comparação (2) emite aviso no
stderr e a execução segue: abortar quebraria execução legítima em contexto
sem o volume, e a comparação (1) continua valendo.

**O endpoint serve o YAML com ordem não determinística.** Duas obtenções
com uma hora de intervalo deram bytes distintos e conjunto de regras
idêntico — zero removidas, zero acrescentadas, um bloco deslocado. O
sha256 identifica o **arquivo**, não o **conjunto**. Por isso o descritor
grava também `rules_id_sha256`: o sha256 da lista de `check_id` ordenada,
um por linha, invariante à reordenação.

**Contagem: 1074 regras, 163 JS/TS.** Contar com **parser YAML**, nunca
`grep -c '^- id: '` — ao menos uma regra declara `patterns` antes de `id`,
e o grep devolve 1073. Foi a origem da divergência 1073 vs 1074; o pack
não cresceu, o método de contagem é que estava errado.
O filtro de linguagem precisa cobrir grafias duplicadas: `javascript`
(152) e `js` (1), `typescript` (150) e `ts` (5).

**Continuidade com a v1.** Os 145 `check_id` que produziram achado na
campanha anterior estão em `datasets/v1-checkids.txt`, e o descritor
registra a interseção contra o snapshot vendorizado. Estabelece
continuidade por identificador e afasta remoção de regra produtiva; **não**
estabelece identidade de pack — regras acrescentadas e regras que não
dispararam não deixam vestígio no cotejo.

**Item do smoke test da Fase E, com consequência definida.** Verificar se
`.time.rules[]` lista as **1074 regras carregadas** ou apenas as **aplicadas
às linguagens presentes** no repositório. Se for por linguagem, renomear o
campo do schema para `rules_applied`: campo chamado `rules_loaded` que
significa outra coisa é pior que campo ausente.

O risco é de segunda ordem — a integridade do pack dentro do container já
está garantida pelas duas comparações de sha256, que são fatais. A comparação
`rules_loaded` × `rules_total` é segunda linha de defesa, não a primeira.

**Vocabulário de severidade: quatro valores, fechado.** Contado com parser
YAML (`ruamel.yaml`, dentro da própria imagem) sobre o pack vendorizado:
`WARNING` 722, `ERROR` 310, `INFO` 31, `MEDIUM` 11 — soma **1074**, uma por
regra, nenhuma regra sem `severity` no topo.

Um `grep` por `severity:` conta **1075**. A regra a mais é
`generic.secrets.security.google-maps-apikeyleak.google-maps-apikeyleak`, que
declara `severity: WARNING` no topo **e** `metadata.severity: MEDIUM` — o
regex conta as duas. O normalizador lê `results[].extra.severity`, que vem do
topo; o `metadata.severity` não é lido. É o mesmo tipo de erro de método que
produziu o episódio 1073 × 1074: **contar com parser, nunca com grep.**

Flags: `--time` (grava o inventário de regras aplicadas em `.time.rules[]`
dentro do próprio JSON, por CVE) e `--metrics=off` (com config local o
Semgrep não envia telemetria, mas a flag torna isso explícito).

**Armadilha do prefixo no `check_id`.** O Semgrep prefixa o `check_id` com
o nome do diretório que contém o YAML:

```
--config=/packs/default.yaml  →  packs.javascript.lang.security...
--config=/default.yaml        →  javascript.lang.security...   ← correto
```

O pack vendorizado **deve** ficar na raiz do sistema de arquivos do
container. Caso contrário os identificadores de regra divergem dos do
registry e da campanha anterior, quebrando a comparação em silêncio.
Medido em Docker com a 1.171.0, nos três casos:
`/packs/default.yaml` → prefixo `packs.`; `/rulesdir/js.yaml` →
`rulesdir.`; `/default.yaml` → sem prefixo. O registro dessa medição está
no descritor do pack, em `prefix_verification`.

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

#### Regra geral de contagem

Três episódios do projeto têm a mesma estrutura — objeto medido certo,
método de medição errado:

| Episódio | Método falho | Causa |
|---|---|---|
| 1073 em vez de 1074 regras | `grep -c '^- id: '` | uma regra declara `patterns` antes de `id` |
| 1075 em vez de 1074 severidades | `grep -c 'severity:'` | uma regra declara `severity` no topo **e** em `metadata` |
| "versionável" lido errado | `git check-ignore -v` | reporta casamento de padrão, não veredito |

A verificação por regex sobre formato estruturado falha por causas
**independentes** — ordem de campos e profundidade de aninhamento —, então
descartar uma não garante a ausência da outra.

Daí: **toda contagem que vá para a monografia sai de parser do formato**, e
**divergência entre dois métodos é reconciliada antes de qualquer dos
números ser aceito**, ainda que a conclusão sobreviva à reconciliação — como
sobreviveu nos três casos.

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

## Ameaças à validade que o pipeline não resolve

Declaradas na monografia, não corrigíveis por código:

- **Assimetria de comparabilidade.** O CodeQL é avaliado contra um gabarito
  derivado da sua própria taxonomia; Semgrep e Snyk Code não. Vantagem do
  CodeQL nas métricas admite explicação alternativa à de superioridade
  técnica. A modalidade por conjunto atenua, não elimina.
- **Viés de seleção.** Se o núcleo do dataset veio de casos que o CodeQL
  detecta, vulnerabilidades que ele não detecta estão sub-representadas. O
  recall absoluto incide sobre universo já filtrado.
- **Alcance do controle com o Semgrep.** Cotejo feito contra o catálogo
  atual, não o de 2020. O viés é conservador: catálogo menor daria
  correspondência ainda menor que a nula medida.
- **A seleção do CWE primário herda a proveniência.** A evidência de
  primeira ordem para escolher o primário é o `explanation`, que é o
  `@name` de consulta do CodeQL em 83% dos casos. A modalidade por
  primário acrescenta uma segunda camada da mesma proveniência; a
  modalidade por conjunto não depende da escolha e serve de contraprova.
- **Ordem não determinística do pack.** O sha256 não permite a terceiro
  verificar se o pack vendorizado corresponde ao que o registry serve
  noutro momento. Mitigado por `rules_id_sha256`; resta que o conjunto é
  verificável por identidade de regras, não de arquivo.
- **Verificação do CodeQL em versão adjacente.** O ensaio ponta a ponta
  rodou na 2.26.4, não na 2.25.4 empregada.
- **O schema de normalização foi construído contra a documentação das
  saídas, não contra saída real.** As 18 fixtures sintéticas derivam da
  tabela "Formato das saídas das ferramentas" acima, que por sua vez vem da
  documentação e das saídas da campanha preliminar. Erro nessa tabela é
  reproduzido pela fixture, e a asserção passa. A suíte prova conformidade
  ao formato **suposto**, não que o suposto corresponda ao emitido. Só o
  smoke test resolve, e é por isso que ele antecede o primeiro lote

## O que NÃO fazer

- Não analisar HEAD nem `PostPatchCommit`
- Não nomear saídas pelo nome do repositório
- **Não expandir CVE multivalorado em uma linha por CWE**
- **Não tratar o campo `CWEs` como classificação do defeito** — é conjunto
  de tags de consulta
- **Não atribuir CWE primário fora do conjunto declarado pelo benchmark**
- Não usar `|| true` em builds ou execuções de workflow — mascara falhas e
  faz o job passar como bem-sucedido com o container quebrado
- **Não descartar stderr de comando algum** (não só do git) — descarta a
  razão da falha. Vale para as capturas de versão das ferramentas: falha
  ali indica imagem quebrada, e deve aparecer no stderr além do log
- Não regerar listas com execução em andamento
- Não gravar campo com vírgula nas listas de entrada
- Não usar `--config=auto` no Semgrep
- Não deixar o pack vendorizado do Semgrep fora da raiz do container
- **Não contar regras do pack com `grep`** — exige parser YAML
- **Não tratar o exit 3 do Snyk como `ERRO_ANALISE`** — é
  `SEM_ARQUIVO_ANALISAVEL`
- **Não deixar a lista de entrada no fd 0 do laço** (`done < "$LISTA"`):
  toda ferramenta e todo git herdam a lista em stdin, e um filho que leia
  stdin engole linhas do lote — CVEs somem sem linha de log. Usar fd
  alternativo, ou `< /dev/null` nas chamadas
- **Não usar `set -e`** nos scripts de análise: falha em um CVE deve pular
  aquele item, não derrubar o laço. Conferir exit codes explicitamente
- Não passar `--json-file-output` ao Snyk
- Não usar `latest` ou `stable` para o CLI do Snyk
- **Não rodar os containers sem `--user` e sem `-e HOME=/tmp`** — sem o
  primeiro os artefatos saem com dono root; sem o segundo, Semgrep e Snyk
  quebram sob uid ausente do `/etc/passwd` da imagem
- **Não sondar tolerância a `--user` com `--version`** — o Snyk passa nele e
  falha ao gravar configuração. Sondar com comando que escreva
- **Não acoplar `normalize.py` ao log de execução** — nem importar, nem ler,
  nem invocar
- **Não produzir `findings: []` a partir de raw ilegível**
- **Não colapsar "regra não resolvida" em `unknown`**
- **Não consultar a tabela de primário para conjunto vazio ou unitário**
- **Não excluir CVE de denominador por `gt_file_scanned: false`** — a causa
  ali é interna à ferramenta, ao contrário do repositório que não existe
- Não gravar fixtures em `results/*/raw/`
