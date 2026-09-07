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
`v1-checkids.txt`), `tools/`, `results/*/treated/`, `results/zap/`,
`logs/`, o pack vendorizado do Semgrep e seu descritor, Dockerfiles,
scripts, workflows.

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

### Revisão antes da execução

Todo script, Dockerfile ou normalizador passa pelo subagente
`revisor-pipeline` antes de commit. O checklist dele deriva dos defeitos
reais que invalidaram a campanha anterior. Revisão sem apontamentos é
resultado válido.

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
- **14 CVEs trazem CWE sem zero à esquerda** (`CWE-79`) no próprio ground
  truth. A normalização de três dígitos aplica-se ao ground truth **e** às
  saídas das ferramentas, não só a estas
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

## Schema comum de saída

Bloco `metadata` por CVE, lista `findings`. Campos de ground truth
prefixados por `gt_`, no bloco de metadados, não repetidos por achado:

- `gt_cwes` — conjunto declarado pelo benchmark, normalizado
- `gt_cwe_primary` — CWE selecionado pela tabela de mapeamento; nulo nos
  CVEs sem CWE e naquele cujo conjunto segue sem primário definido
- `gt_file_path` — escalar
- `gt_file_lines` — lista, podendo ter mais de um elemento em três CVEs

**Identificadores do schema JSON em inglês.** Nomes de arquivo, valores de
status do log e tabelas auxiliares (`cwe-primario.csv`) mantêm o
português já adotado. `gt_cwe_primary`, nunca `gt_cwe_primario`.

**`ruleset` é estrutura, não string em prosa** — o campo sustenta a
reprodutibilidade e precisa ser comparável programaticamente:

```json
"ruleset": {
  "name": "p/default",
  "sha256": "…",
  "obtained_at": "…",
  "rules_total": 1074
},
"rules_loaded": 1074
```

Preenchimento por ferramenta:

- **Semgrep** — completo; `rules_loaded` vem de `.time.rules[]`. A
  comparação `rules_loaded` × `rules_total` detecta pack obsoleto
- **CodeQL** — `name` = referência da suíte, `sha256` e `obtained_at`
  nulos, `rules_total` 104, `rules_loaded` **nulo**: o `driver.rules[]` do
  SARIF registra o que apareceu, não o que foi carregado
- **Snyk Code** — `ruleset` nulo inteiro; não há conjunto declarável

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