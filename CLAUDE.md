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

**As aplicações da campanha DAST não são submetidas às ferramentas SAST.**
Decisão do orientador, e a razão não é de escopo e sim de ausência de
gabarito: Juice Shop e NodeGoat não declaram, por vulnerabilidade, arquivo,
linha, identificador de CWE e commit anterior à correção — os quatro
elementos de que a apuração depende. Achados produzidos ali não seriam
classificáveis em verdadeiro e falso positivo, e a contagem resultante
mediria volume de alerta, não detecção.

A consequência é que as duas famílias não compartilham alvo algum: a
comparação entre SAST e DAST neste trabalho se dá entre o que cada uma
alcança em seus próprios termos, e não entre detecções sobre a mesma
aplicação.

Decidido também manter o OWASP NodeGoat no estudo. Os quatro relatórios de
`results/zap/` são, portanto, o conjunto DAST definitivo.

## Regra crítica — checkout do commit vulnerável

Toda análise SAST da **campanha de detecção** **deve** fazer checkout do
`PrePatchCommit`, o commit anterior à correção.

Analisar o HEAD do branch padrão invalida a comparação com o ground truth:
os CVEs do benchmark já foram corrigidos, então o código no HEAD é a versão
corrigida. Uma campanha anterior foi inteiramente invalidada por esse erro.

**HEAD, nunca**, em campanha alguma: foi o que invalidou a campanha
preliminar. Tampouco serve de versão corrigida — ver "Falso positivo na versão
corrigida".

**`PostPatchCommit`, só na segunda campanha**, a de reconhecimento da correção,
e **nunca na campanha de detecção**.

Até 22/09/2026 a regra dizia "Nunca analisar HEAD nem `PostPatchCommit`", sem
distinguir campanha. A decisão de 21/09/2026 pela segunda campanha a tornou
contraditória, e ela foi reescrita.

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
CVEs: em **73,1%** do conjunto, `explanation` e `CWEs` foram herdados da
consulta do CodeQL que identificou o caso.

**Âncora: `ec573b51` (08/12/2020). Decidido em 20/09/2026.**

| Verificação | Resultado |
|---|---|
| `explanation` idêntica ao `@name` de consulta do pacote JS do CodeQL | **163 de 223 (73,1%)** |
| Destas, com `CWEs` idêntico às tags `external/cwe/` da consulta | 163 de 163 (100%) |
| Divergências não explicadas | 0 |
| Controle: `explanation` idêntica a mensagem de regra do Semgrep (2.228 regras) | 0 (0,0%) |

**Por que `ec573b51`, e não `9ff6d68a`.** `ec573b51` é o último merge do main
anterior ao commit do release do benchmark (`2020-12-09T13:27:12Z`).
`9ff6d68a` é de `2020-12-11T21:58:09Z`, **posterior** — e um estado do CodeQL
que veio depois do benchmark não pode ser a fonte das etiquetas dele. A tese é
herança, e herança exige que a consulta exista antes do rótulo; a contagem é
conservadora por construção, porque não credita como herança o rótulo que
corresponde a código ainda não integrado ao main.

**Os 185 de 223 (83,0%) ficam como medida de sensibilidade**, contra
`9ff6d68a`, com 185 de 185 idênticos. **A diferença é inteira e exatamente os
22 CVEs de prototype pollution**, todos por
`Security/CWE-915/PrototypePollutingFunction.ql`, nomeados em
`results/proveniencia/compara-ref-x-sens.txt`: `CVE-2018-16487`,
`CVE-2018-16489`, `CVE-2018-16490`, `CVE-2018-16491`, `CVE-2018-16492`,
`CVE-2018-3719`, `CVE-2018-3721`, `CVE-2018-3722`, `CVE-2018-3728`,
`CVE-2018-3750`, `CVE-2018-3752`, `CVE-2019-10746`, `CVE-2019-10747`,
`CVE-2019-10750`, `CVE-2019-11358`, `CVE-2020-15256`, `CVE-2020-5258`,
`CVE-2020-7638`, `CVE-2020-7699`, `CVE-2020-7720`, `CVE-2020-8116`,
`CVE-2020-8203`. Zero casados só na referência, e os 163 comuns não mudam de
consulta nem de relação.

Isso **não** afirma que a correspondência com `9ff6d68a` seja coincidência: o
achado temporal do `tools/ground-truth/README.md` documenta que, no commit do
release, o estado de consulta que esses 22 rótulos reproduzem já era público
num PR aberto e não integrado. A âncora deixa esses casos fora da contagem;
não os nega.

O cotejo contra o CodeQL **atual** dá 185 casados, com 108 idênticos, 74
subconjuntos e 3 divergentes; as três situações se resolvem pela evolução
posterior do catálogo, e ele não serve de âncora por ser seis anos posterior
ao benchmark.

Os 60 sem correspondência contra a âncora têm `explanation` em prosa, escrita
à mão — outra camada de proveniência. Contra `9ff6d68a` são 38.

### Consequência prática

**O campo `CWEs` não é classificação do defeito.** É o conjunto de tags da
consulta que originou o registro, e descreve uma família (path traversal:
022+023+036+073+099) ou um conjunto de impactos potenciais (prototype
pollution: 078+079+094+400+915).

Isso invalida qualquer tratamento que assuma um CWE por defeito.

### Reprodução

**Os scripts de proveniência estão versionados em `tools/ground-truth/`**
desde a Fase P (`db26b4c`, 13/09/2026), com o estado de referência fixado na
Fase P-2 (`1a7d3a3`, 14/09/2026). O `README.md` do diretório traz os comandos
que reproduzem o cotejo a partir de um clone limpo, e o achado deixou de ser o
único do estudo que um terceiro não reproduz. Até 18/09/2026 este parágrafo
afirmava o contrário, com conferência de 10/09 — anterior aos dois commits.

**A divergência que este parágrafo registrava está resolvida.** Até
20/09/2026 a tabela acima afirmava 185 de 223 (83,0%) e mandava usar o estado
de 9 de dezembro, enquanto o README do diretório fixava `ec573b51`; os dois
números conviviam sem que se dissesse qual ia ao texto. **Vai o 163 de 223
(73,1%), contra `ec573b51`**, pela razão de precedência temporal registrada
acima. A tabela foi corrigida, e os 185 passaram a medida de sensibilidade.

**As saídas do cotejo estão versionadas em `results/proveniencia/`** desde
20/09/2026 — os sete relatórios, as cinco comparações nominais e o controle do
Semgrep, com o `README.md` do diretório trazendo os comandos exatos. Até então
só os scripts estavam no repositório, e conferir qualquer número do cotejo
exigia obter os catálogos externos e reexecutar. Os catálogos seguem fora do
versionamento, obtidos por `obter-catalogos.sh` em `catalogos/`, ignorado; os
caminhos gravados nos relatórios são relativos ao repositório de propósito,
para que o diretório da máquina do operador não entre em arquivo versionado.

O procedimento: o CWE pretendido pelo benchmark para qualquer CVE do núcleo é
recuperável consultando as tags `external/cwe/` da consulta correspondente no
CodeQL em **`ec573b51`**.

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

## Critérios do cruzamento — o documento

`docs/criterios-cruzamento.md`, escrito em 18/09/2026, **antes de qualquer
código de cruzamento e de qualquer número de detecção**. É a fonte; isto é
ponteiro, não cópia — duplicar o conteúdo criaria duas versões para divergirem.

Fixa os **cinco níveis de acerto** (0 repositório, 1 arquivo, 2 arquivo + CWE,
3 arquivo + linha, 4 os três), com o mesmo achado satisfazendo todas as
condições do nível; o **casamento de linha por sobreposição** de
`[line_start, line_end]` com alguma `gt_file_lines`, sem banda de tolerância,
`line_end` nulo valendo `[line_start, line_start]`; as **duas variantes de
CWE**, generosa (intersecta `gt_cwes`) e estrita (contém `gt_cwe_primary`); e o
**denominador de 220 pares**, o mesmo para as três ferramentas.

Registrava também que **não haveria métrica de precisão nem de falso
positivo** — **superado pela emenda de 21/09/2026 à §1 do documento**: o
negativo existe na versão corrigida, no ponto da falha. Achado fora desse ponto
continua não classificável, e volume de alerta continua caracterização
descritiva, nunca medida de qualidade.

**A decomposição da detecção por categoria de CWE está na §9 do documento**
(25/09/2026): categoria, limiar e tratamento do grupo "outros" são de lá.
**A capacidade empírica e a delimitação por linguagem estão na §10**
(25/09/2026): eixo, universo, unidades e os dois critérios de JS/TS.

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
`results/*/treated/`, `results/cruzamento/`, `results/proveniencia/`,
`results/circularidade/`, `results/por-cwe/`, `results/capacidade/`, `results/zap/`, `logs/`
(incluindo `normalize-report-<ferramenta>.json`), o pack vendorizado do
Semgrep e seu descritor, Dockerfiles, scripts, workflows.

**`results/cruzamento/` entra no repositório ao lado de `results/*/treated/`,
e pela mesma razão:** é o que sustenta o argumento, não perícia. São as
saídas do `tools/cruza-deteccao.py` — a matriz por (CVE, ferramenta) e um
JSON por ferramenta —, decidido em 18/09/2026. São pequenas (cerca de
720 KiB) e determinísticas: não gravam carimbo de execução. Cada JSON traz o
sha256 do CSV, o de cada entrada e o dos três scripts que moldam o resultado
(`cruza-deteccao.py`, `normalize.py`, `check-log.py`). Reexecutar sobre as
mesmas entradas e o mesmo código reproduz os mesmos bytes, então diferença no
diff é mudança de entrada ou de código, nunca de relógio; e
`git diff --exit-code results/cruzamento/` depois de reexecutar denuncia saída
desatualizada. O script recusa gravar ali se alguma entrada estiver fora do
repositório, porque o caminho da máquina do operador iria para os JSON.

**`results/proveniencia/` e `results/circularidade/` entram pela mesma razão,
em 20/09/2026.** São as saídas de `tools/ground-truth/` — sete relatórios do
cotejo, cinco comparações nominais e o controle do Semgrep — e as da apuração
de circularidade. Até então só os scripts estavam versionados, e conferir
qualquer número do cotejo exigia obter os catálogos externos e reexecutar.
Somam cerca de 800 KiB, são determinísticas e não gravam carimbo de execução:
conferido em três execuções com `PYTHONHASHSEED` distinto, para JSON e texto,
com controle positivo de que o teste acusa diferença real. Cada `README.md` de
diretório traz os comandos exatos e a procedência.

**Caminho relativo não é cosmética nessas duas.** O `cruza-codeql.py` grava em
`consultas_dir` e `fonte_ground_truth` o caminho que recebeu, e os defaults
dele são absolutos: invocar sem `--csv` e `--clone` explícitos levaria o
diretório da máquina do operador para dentro de arquivo versionado. Por isso
os catálogos são obtidos em `catalogos/`, **dentro da árvore e ignorado** — de
fora dela não há caminho relativo a dar. O
`tools/circularidade-proveniencia.py` fecha o mesmo buraco com guarda
explícita, na forma do `cruza-deteccao.py`: recusa gravar em
`results/circularidade/` se alguma entrada estiver fora do repositório.

**`results/por-cwe/` entra pela mesma razão, em 25/09/2026.** Guarda a
distribuição de `gt_cwe_primary` nos 220 pares do denominador — propriedade do
ground truth, e não resultado de detecção —, produzida por
`tools/distribuicao-cwe-primario.py`, que toma o denominador do
`cruza-deteccao.py` e o primário das funções do `normalize.py`, sem
reimplementar nenhum dos dois. É determinística e não grava carimbo de
execução: conferido com quatro `PYTHONHASHSEED` distintos. O CSV gravado é
relido antes de ocupar o nome definitivo, e o script recusa gravar dentro do
repositório se alguma entrada estiver fora dele. O `README.md` do diretório traz o
comando e a procedência.

**`results/capacidade/` entra pela mesma razão, em 25/09/2026.** Guarda a
tabela regra → linguagens do pack vendorizado do Semgrep, produzida por
`tools/regras-linguagens-semgrep.py`, que lê o YAML com `ruamel.yaml` dentro
da imagem do Semgrep da campanha, referenciada pelo digest vigente, e nunca
pelo prefixo do `check_id`. É determinística e não grava carimbo de execução:
conferido com quatro `PYTHONHASHSEED` distintos. O CSV gravado é relido antes
de ocupar o nome definitivo, e o script recusa gravar dentro do repositório se
alguma entrada estiver fora dele. Nesta fase não contém contagem de achado
alguma. O `README.md` do diretório traz o comando e a procedência.

**Ignorados:** `results/*/raw/`, clones temporários (`src-CVE-*`),
databases do CodeQL, `node_modules/`, o clone `ossf-cve-benchmark/`, os
catálogos externos do cotejo (`catalogos/`).

`results/zap/` guarda os oito relatórios da campanha DAST de julho de 2026
(JSON e HTML por aplicação e modo) mais o plano de automação. São os
**únicos dados de detecção válidos do estudo** — a campanha SAST anterior
foi invalidada. Existiam em cópia única fora de controle de versão.

Os relatórios não trazem campo de modo de varredura.

A correspondência entre relatório, aplicação e modo de varredura está em
`results/zap/README.md`, escrito na Fase F-1. Até então a remissão apontava
para documento inexistente: nenhum commit do repositório continha esse
README, e a correspondência não era recuperável de fonte alguma — ver o
quinto episódio da regra geral de contagem.

O README a estabelece por contagem sobre os próprios relatórios, em duas
unidades — tipos de alerta (`site[].alerts[]`) e instâncias (soma de
`instances[]`) —, e **as duas discriminam igualmente** os quatro arquivos,
de modo que a atribuição não depende da unidade escolhida. A série citada
neste arquivo (10/14/23/29) é a de **tipos**.

O modo é ainda confirmado por evidência **independente da contagem**: os
dois relatórios `full` trazem alertas de regra de varredura ativa
(`pluginid` 4xxxx), e os dois `baseline` trazem zero. A aplicação sai de
`site[0].@name`. Cada HTML é pareado ao JSON irmão pelo conjunto de nomes
de alerta, não por semelhança de nome de arquivo.

`juice-shop-report.json` é o baseline, apesar do nome não dizer. **Não
renomear** — os nomes são o artefato produzido pela execução.

O script de sondagem de disponibilidade **foi trazido na Fase E**:
`tools/probe-repos.sh`, com a saída datada em
`datasets/sondagens/sondagem-repos-<AAAA-MM-DD>.csv`.

Os scripts de proveniência do ground truth **foram trazidos na Fase P**
(`db26b4c`), em `tools/ground-truth/`; ver "Reprodução", na seção de
proveniência.

Motivo: o repositório precisa permitir verificar os números do estudo sem
depender de artifacts do GitHub Actions, cuja retenção padrão é de **90
dias**, configurável de 1 a 90 em repositório público. O argumento que ela
sustenta — versionar treated e logs, tratar o raw como perícia descartável —
fica intacto e é reforçado.

**Verificar versionabilidade com `git add --dry-run`, nunca com
`git check-ignore -v`.** O `-v` reporta *casamento de padrão*, não veredito,
e devolve 0 tanto para padrão de ignore quanto para negação: para
`logs/normalize-report-semgrep.json` ele imprime `!logs/**` e sai 0, e para
`results/semgrep/raw/*.json` imprime `results/*/raw/` e também sai 0. Só o
`add --dry-run` distingue os dois casos.

## Convenções de execução

- Cada ferramenta roda em container Docker próprio, iterando sobre os CVEs
  de um lote
- O laço é **idempotente**: pula CVE cuja saída bruta já existe. A
  propriedade governa a retomada **local** de um lote interrompido.

  **No ambiente da campanha ela é inerte.** As saídas brutas não são
  versionadas e cada execução parte de ambiente limpo, de modo que
  reexecutar um lote no GitHub Actions o **reprocessa integralmente** — o
  custo de uma reexecução é o lote inteiro, não o seu remanescente.
  Consequência para o `check-log.py`: o status `PULADO` não ocorre ali, e a
  conferência "`PULADO` sem raw" não dispara no ambiente da campanha.
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

**A asserção foi exercitada com divergência real (Fase E, 10/09/2026), e o
caso que a fez disparar é mais amplo que o defeito que a motivou.**

SHA bem formado porém inexistente no repositório **não** chega à asserção: o
fetch raso é recusado (`upload-pack: not our ref`), o `git checkout` falha
(`unable to read tree`) e sai `ERRO_CHECKOUT`. A guarda anterior basta.

**SHA de tag anotada chega.** O objeto de tag atravessa o fetch e o checkout
sem erro algum e o `FETCH_HEAD` resolve para o commit que a tag aponta —
árvore distinta da esperada, análise deslocada em silêncio, nenhum erro
registrado. Medido com o objeto de tag `4da165fd…` do `node-growl`, que
descasca para o commit `68ec24dd…`; o log saiu
`ERRO_CHECKOUT,HEAD 68ec24dd… nao e o PrePatchCommit`.

O caso não é artificial. O benchmark declara 223 SHA-1 completos e bem
formados (ver defeitos do conjunto), e **boa formação não distingue objeto de
commit de objeto de tag**. A asserção é o único ponto do protocolo que
intercepta essa condição.

**Exit 137 não estabelece esgotamento de memória.** É `SIGKILL`, e o
`docker stop` o envia ao fim do prazo de graça — assinatura idêntica à do
OOM-killer, causa oposta. Ocorreu na Fase E ao interromper deliberadamente
uma execução prolongada, em máquina de 8 GB, onde o esgotamento era
plausível: aceitar a assinatura teria produzido registro falso.

Some-se que o `trap ... INT TERM` **não** interrompe ferramenta em primeiro
plano — o bash só roda o handler quando o comando retorna —, de modo que a
interrupção externa chega como código de encerramento do container, não como
sinal tratado pelo script.

Atribuir causa a interrupção exige evidência independente da assinatura.
Registre o exit code bruto e o contexto; não nomeie memória sem outra prova.

### `TIMEOUT_ANALYZE` provisório, e o teto de 6 h já observado

**`TIMEOUT_ANALYZE` = 3600 s é provisório.** Foi fixado contra os máximos
observados no ensaio local (146 s no CodeQL), que é critério distinto e mais
frouxo do que o que de fato governa a campanha.

**O limite é por CVE; o teto de 6 h é por job.** As duas grandezas não são
comensuráveis por inspeção, e a folga de uma não implica a da outra.

**O teto não é restrição hipotética: já interrompeu execuções deste
projeto.** Em julho de 2026, na série exploratória do repositório anterior
(`pipeline-security-analysis`), o CodeQL atingiu o teto primeiro sobre o
conjunto inteiro e, depois, **ainda em regime de lotes**, em dois lotes da
mesma partição — `aa` e `ab` — enquanto `ac`, `ad` e `ae` terminaram em
1h09, 1h04 e 52 min.

**O degrau é o dado.** Três lotes da mesma partição terminando com mais de
quatro horas de folga, e dois consumindo o teto inteiro, não é perfil de
custo agregado excessivo: é perfil de **item individual que não termina**.
Reduzir o lote pela metade apenas dividiria o mesmo travamento em dois jobs;
o que intercepta esse modo de falha é o limite de tempo **por invocação**.

No lote `ab` o travamento está identificado: a execução não passou do
**clone completo do primeiro repositório** (`zeit/next.js`), sem profundidade
e sem limite de tempo. No lote `aa` a causa **não foi determinada** — o
primeiro repositório era pequeno (`isaacs/st`), e não se apurou em que ponto
o job parou de progredir.

Uma dessas execuções correu seis horas e **não produziu arquivo algum**. O
script já escrevia a saída por item diretamente no diretório final, de modo
que a ausência de saída não decorre de promoção tardia. A perda
apresentou-se no step de upload como **aviso de caminho não encontrado**,
entre avisos de dependência deprecada, e não como erro.

Daí três exigências do protocolo atual, que aquela série não tinha: obtenção
do código por fetch raso, limite de tempo por invocação, e registro
estruturado por item, que tornaria o travamento visível em minutos em vez de
seis horas.

**Fronteira do que essa evidência estabelece.** A série de julho era
exploratória, tinha o **repositório** por unidade, usava a suíte
`security-and-quality` e analisava o HEAD. Estabelece que o teto interrompe
e que a perda pode apresentar-se como aviso. **Não** estabelece duração por
CVE, tamanho de lote seguro, nem razão runner/local.

A condição que torna a garantia aritmética, e não dependente de
comportamento, é que o produto entre tamanho de lote e limite por invocação
caiba no teto do job. O valor corrente não a satisfaz. Sua revisão depende
de duas grandezas ainda não medidas: a razão entre as durações do runner e
as do hospedeiro local, apurada no ensaio de fumaça, e a manutenção do
tamanho de lote corrente. Não havendo valor confortável, o parâmetro a
revisar é o **tamanho do lote**, não o limite.

Até lá, 3600 s permanece, com `timeout-minutes` explícito abaixo de 360 no
job e `if: always()` no upload como guarda independente.

**Decidido em H4, 16/09/2026: 900 s** nos três limites de análise, por medição
no runner — ver "Ensaio de fumaça — leitura (Fase H, 16/09/2026)", que traz a
folga declarada e o critério. O default do código **continua 3600/1800**: os
900 entram como entrada do `workflow_dispatch` a cada disparo de lote, nunca no
script. `TIMEOUT_FETCH` e `TIMEOUT_CLONE` seguem sem mudança, por não haver
dado.

#### Limites sobrescrevíveis por ambiente (Fase H, H0b, 14/09/2026)

Os três `run_*.sh` leem os limites com `${VAR-default}`. **Ausente**, vale o
default do script, que é o valor que vigorava. **Definida**, vale o ambiente:
`-e TIMEOUT_ANALYZE=1800` no `docker run` ajusta o limite sem rebuild e sem
digest novo. O número no código deixou de provar o que rodou; o que prova é o
valor efetivo registrado, adiante.

**Os nomes não são uniformes, e não se renomeiam.** Renomear é mudança de
interface, e nome trocado no workflow é ignorado em silêncio — o script roda
com o default.

| Script | Análise | Obtenção |
|---|---|---|
| `run_codeql.sh` | `TIMEOUT_CREATE` 3600 **e** `TIMEOUT_ANALYZE` 3600 | `TIMEOUT_FETCH` 300, `TIMEOUT_CLONE` 900 |
| `run_semgrep.sh` | `TIMEOUT_ANALISE` 1800 | idem |
| `run_snyk-code.sh` | `TIMEOUT_ANALISE` 1800 | idem |

No CodeQL a análise de um CVE pode consumir a **soma** dos dois, 7200 s; com a
obtenção em fallback, 8400 s. É a soma, e não o `TIMEOUT_ANALYZE` sozinho, que
entra no produto lote × limite contra o teto de 6 h.

**Sem dois-pontos, de propósito.** Com `${VAR:-default}`, variável definida e
vazia — `env:` de workflow cuja expressão resolveu vazio — cairia no default
em silêncio. Com `${VAR-default}` ela chega à guarda e aborta. Consequência
para o workflow de lote: passar o `-e` só quando houver valor.

**Guarda fatal antes de qualquer trabalho:** cada limite casa
`^[1-9][0-9]*$`, ou o script sai 1 nomeando variável e valor. Medido no GNU
`timeout` (9.11 no hospedeiro, 9.7 na base das imagens):

| Valor | `timeout` | Sem a guarda |
|---|---|---|
| `1800s` | **aceito**, roda normal | o log gravaria `excedeu 1800ss` |
| vazio, `-5`, `abc` | rc 125 | todo CVE do lote em `ERRO_FETCH`/`ERRO_ANALISE` |
| `0` | **desliga o limite**, rc 0 | nada falha — é o caso perigoso |

A guarda barra todos pela forma, o `0` inclusive, pelo `^[1-9]`. Dos casos da
tabela, o `0` é o que mais importa barrar, porque sem a guarda não produziria
sinal algum; a suíte o exercita por execução, variável a variável, nos três
scripts.

**Valor efetivo registrado em duas frentes:** a linha
`limites efetivos em segundos: NOME=valor; …` no stderr, e os mesmos segmentos
`NOME=valor` na primeira linha do log de cada execução, via
`VERSAO_PENDENTE`. A redação evita as marcas do `_parece_obtencao()` do
`check-log.py`. Conferido com controle positivo: o segmento
`fetch raso limite 300s` sai `NAO RECONHECIDO`; `TIMEOUT_FETCH=300` não sai.

**Verificado por controle positivo, não só por sintaxe** (14/09/2026,
`CVE-2017-16042`):

| Execução | Desfecho |
|---|---|
| Semgrep, imagem reconstruída, `-e TIMEOUT_ANALISE=1` | `ERRO_ANALISE`, `semgrep excedeu 1s` |
| Semgrep, mesma imagem, sem a variável | `OK` em 13 s, `TIMEOUT_ANALISE=1800` no log |
| CodeQL, script novo montado sobre imagem existente, `-e TIMEOUT_CREATE=1` | `ERRO_ANALISE`, `database create excedeu 1s` |
| CodeQL, idem, `-e TIMEOUT_ANALYZE=1` | `ERRO_ANALISE`, `database analyze excedeu 1s` |

O Snyk **não** foi exercitado em container: exige `SNYK_TOKEN`. Dele se
verificou, no hospedeiro, a guarda e a linha de stderr — que saem antes da
checagem do token —, e por leitura a propagação ao `timeout`.

**Verificação que constava como pendente — fechada, e já satisfeita quando foi
escrita.** O parágrafo, da Fase F-2 (`53fcfad`, 11/09/2026), pedia conferir se
os scripts limitavam também o **fetch e o fallback de clone**, e não só a
análise, porque o travamento de julho ocorreu antes de qualquer análise, onde o
`TIMEOUT_ANALYZE` não alcança.

Limitavam, e desde antes do parágrafo: `timeout 300` no fetch raso e
`timeout 900` no clone de contingência estão nos três scripts desde a primeira
versão deles (`46ab9e5`, 06/09/2026), e seguiam lá no próprio `53fcfad`. A
Fase G-1b (`6ed071a`) deu nome aos valores — `TIMEOUT_FETCH`, `TIMEOUT_CLONE` —
e separou estouro de recusa no log; H0b os tornou sobrescrevíveis. O modo de
falha do lote `ab` de julho — clone completo sem limite — fica alcançado por
eles. O registro do estouro de ambos é exercitado em `tests/run-fixtures.py`
por execução do script do CodeQL com o `timeout` substituído por stub que
devolve 124 — não por estouro real —, e os outros dois scripts entram pela
identidade byte a byte do bloco de obtenção.

Fora do alcance, declarado: `git init`, `git remote add`, `git checkout` e
`git rev-parse` não estão sob `timeout`.

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

**Denominador quando `SEM_ARQUIVO_ANALISAVEL` ocorre.** Exit 3 é causa
**interna à ferramenta**, como o `gt_file_scanned: false` e ao contrário do
repositório que não existe. O CVE **permanece no denominador** (220/222) nas
duas modalidades e conta como não-detecção do Snyk Code. Nunca se cria
denominador por ferramenta.

O 220 são os 222 pares afirmados menos as **duas** baixas por código
indisponível, nominadas nos defeitos conhecidos: `CVE-2016-1000229`
(repositório inexistente), medida no lote `aa` em 16/09/2026, e
`CVE-2018-8035` (commit inexistente no repositório), medida no lote `ad` em
17/09/2026. Até a campanha o valor era 221, com uma baixa só.

**SUPERADO PELA CAMPANHA (17/09/2026), e o original fica abaixo intacto.** O
estado ocorreu **5 vezes nos 223**, o que cai no terceiro ramo previsto: deixa
de ser borda e vira resultado de cobertura do Snyk Code, com sentença própria
na comparação. Duas frases do texto original deixam de valer: a de que o ramo
"segue coberto apenas por stub" — ele foi exercitado por execução real — e a
dúvida sobre correlação com os cinco arquivos sem extensão, que a campanha
resolve: **a correlação é exata, 5 de 5**. Os CVEs são `CVE-2018-16479`,
`CVE-2018-16480`, `CVE-2018-3731`, `CVE-2018-3747` e `CVE-2019-5423`, cujos
arquivos de ground truth são `bin/http-live` e `bin/public`. O denominador não
se move, como o próprio ramo previa. Ver "Campanha SAST — resultados".

Escrito **antes** da campanha, deliberadamente, para que a escolha não pareça
posterior aos números. Três ramos previstos:

- **0 de 223** — a ameaça sobre o conjunto se fecha ("o estado não ocorre
  neste benchmark"), afirmação distinta de "o ramo de código foi exercitado
  por execução real": este segue coberto apenas por stub. Ambas as frases vão
  ao texto.
- **1 ou 2** — reportados nominalmente, com o `coverage[]` do CVE anexado.
  Denominador não se move.
- **3 ou mais** — deixa de ser borda e vira resultado de cobertura do Snyk
  Code, com sentença própria na comparação; vale checar correlação com os
  cinco arquivos sem extensão e com TypeScript. Denominador não se move.

**Forma de verificação do tratamento.** O conjunto é JS/TS por construção, e
a condição de não haver projeto suportado, embora possível, não é dele
esperada; caçar um CVE que a produza não se justifica pelo custo. O ramo é
exercitado por execução controlada — o exit 3 é reproduzido por stub, fora do
laço da campanha — e essa forma é declarada. A ocorrência real, se houver, é
apurada pela própria campanha, cujo `coverage[]` responde sobre os 223: a
verificação empírica é resultado do estudo, não pré-requisito da execução.

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

#### O `--user` também alcança o que a imagem só LÊ (Fase E, 10/09/2026)

A tabela acima mede escrita. Há um segundo efeito, medido só ao rodar um lote
inteiro: o bundle do CodeQL 2.25.4 traz **3.151 arquivos `.qlx` precompilados,
todos com dono uid 1001**, e **462 deles com modo `600`**. Sob `--user` com
uid diferente de 1001 o CodeQL não consegue lê-los, cai em
`AccessDeniedException` por consulta e **recompila o plano de consulta**, a
cerca de 1 min 20 s cada.

Medido nesta máquina (uid 1000), mesma imagem, mesmo lote, só variando a
legibilidade do bundle:

| | AccessDenied | consultas recompiladas | progresso em ~9 min |
|---|---:|---:|---|
| imagem como está | 8 | 7 | 7 de 104 |
| `+ chmod -R a+rX /opt/codeql` | 0 | 0 | 104 de 104 em ~40 s |

**É a mesma classe de defeito do `HOME`, com o sinal invertido.** No `HOME` o
uid 1000 deste hospedeiro é que salvava o CodeQL, e o uid 1001 do runner é que
quebraria; aqui o uid 1001 do runner é que salva, e o 1000 é que quebra. Nos
dois casos o comportamento depende de uma coincidência de uid, que é
exatamente o que não se deve deixar de pé.

Nada disso **falha**: o resultado é idêntico, só mais lento. Mas o custo cai
inteiro dentro do `analyze` do **primeiro** CVE do lote — os seguintes reusam
`$HOME/.codeql/compile-cache`, que vive no `/tmp` do container e dura o
`docker run` — e pode encostar no `TIMEOUT_ANALYZE` de 3600 s, virando
`ERRO_ANALISE` sem causa aparente.

**Correção adotada:** `RUN chmod -R a+rX /opt/codeql` no Dockerfile do CodeQL,
logo após desempacotar o bundle. Verificada na imagem da campanha
reconstruída, sob `--user` com o uid 1000 deste hospedeiro: os 3.151 `.qlx`
passam a modo 644, `AccessDeniedException` cai a **zero**, **nenhuma** consulta
é recompilada e as 104 carregam do precompilado.

Com ela, a medição de duração do CodeQL passou a sair da **imagem da
campanha**, não de uma imagem de diagnóstico — era a maior fragilidade da
medição da Fase E.

Sob `--user`, um processo cujo uid é o **dono** dos `.qlx` os lê mesmo em
modo 600. Onde o uid de execução coincide com o dono do bundle (1001), o
defeito não se manifesta — com ou sem o `chmod` na imagem. A execução no
runner, portanto, **não distingue** imagem corrigida de não corrigida nesse
eixo: ela mede o defeito do `HOME`, que só se manifesta sob uid ausente do
`/etc/passwd` da imagem. Os dois defeitos ficam cobertos pela **união** de
duas medições — `.qlx` em uid 1000, local, Fase E; `HOME` em uid 1001, no
runner —, nunca por uma execução única.

**Premissa não medida:** que o uid do runner seja 1001. Vem da documentação e
de relatos públicos, não de medição própria. Confirmada no job de diagnóstico
da Fase G, que registra uid **e gid em separado** — nada no pipeline pode
supor `uid == gid`. Vindo diferente de 1001, o defeito dos `.qlx` volta a se
manifestar no runner e o parágrafo acima se inverte quanto a *onde* cada
defeito aparece; a primeira frase, sobre o dono ler arquivo modo 600, vale em
qualquer uid.

### Revisão antes da execução

Todo script, Dockerfile ou normalizador passa pelo subagente
`revisor-pipeline` antes de commit. O checklist dele deriva dos defeitos
reais que invalidaram a campanha anterior. Revisão sem apontamentos é
resultado válido.

**Um caso em que a revisão não foi sequer prévia (Fase E).** O
`tools/normalize.py` foi commitado em **10/09/2026** sem revisão: o subagente
morreu no limite de sessão da API antes de produzir apontamento, e a
alteração não era cosmética — mudança de schema, função nova de despacho por
tipo, inversão de uma guarda e três avisos de console. A revisão rodou
**depois**, em 10/09/2026, sobre o diff já commitado, e apontou seis itens,
todos corrigidos em commit próprio. Fica no registro: ali a revisão deixou de
ser prévia, o que é uma perda a mais do que a limitação estrutural descrita
no parágrafo seguinte.

**Limitação declarada, não corrigida.** A revisão incide sobre a versão
*anterior* às correções que ela mesma motiva. As verificações mecânicas são
refeitas sobre a versão final: a suíte de fixtures cresce a cada correção que
uma revisão motiva, e **cada correção ganha asserção própria** — foi assim na
Fase D e de novo em cada rodada da Fase E. O número corrente sai de
`python3 tests/run-fixtures.py`, não daqui, justamente para não envelhecer a
cada acréscimo.

Mas **não há segunda revisão completa**. Vale para a Fase C (declarado na §8.5 da metodologia, numeração da V10) e
reaparece na Fase D pelo mesmo motivo: uma segunda revisão motivaria novas
correções, e a recursão não tem ponto de parada natural.

## Ensaio de fumaça — leitura (Fase H, 16/09/2026)

Execução `35101790912` do `analise-lote.yml`, commit `3af154a`, lote
`cves-sast-fumaca` (7 CVEs), com os três campos de limite **vazios**: o ensaio
mede os defaults. Runner `ubuntu24` / `20260907.300.1`, uid:gid **1001:1001**.
Os três jobs saíram `success` — CodeQL 7m45s, Semgrep 5m14s, Snyk Code 3m03s.
Seis CVEs analisados; o `CVE-2016-1000229` saiu `ERRO_FETCH`, como previsto.

**Resultados de detecção descartados**, pela regra do ensaio: raw e tratado não
entram no repositório. **Preservados em `logs/ensaio-fumaca-2026-09-16/`**: os
três `execution-log-*.csv` e os três `normalize-report-*.json`, byte-idênticos
aos do artifact. Os arquivos homônimos na raiz de `logs/` continuam sendo os do
ensaio **local** da Fase E e não foram tocados. As sondagens datadas estão em
`datasets/sondagens/`.

### 1. Razão runner ÷ local no CodeQL ≈ 0,70

| CVE | local (Fase E) | runner | razão |
|---|---:|---:|---:|
| `CVE-2017-16042` | 63 s | 44 s | 0,70 |
| `CVE-2018-14041` | 78 s | 59 s | 0,76 |
| `CVE-2018-14040` | 127 s | 82 s | 0,65 |
| `CVE-2019-10744` | 146 s | 103 s | 0,71 |

**Ressalva:** são quatro pontos, de repositórios pequenos a médios, medidos num
único par de máquinas. Não transfere para repositório grande, para outro runner
nem para as outras duas ferramentas.

### 2. Porte do repositório não prediz custo de análise — correção de premissa

Arquivos extraídos pelo CodeQL × duração, no runner:

| arquivos extraídos | duração |
|---:|---:|
| 3 | 44 s |
| 58 | 103 s |
| 126 | 59 s |
| 174 | 82 s |
| 14 | 51 s |
| 704 | 77 s |

O caso de 58 arquivos custou mais que o de 704. A premissa de que repositório
grande implica análise longa — que sustentava o dimensionamento por tamanho de
repositório — **não se sustenta nesta faixa**, e fica registrada como corrigida.

### 3. Os valores de `T` decididos

`TIMEOUT_CREATE` = `TIMEOUT_ANALYZE` = `TIMEOUT_ANALISE` = **900 s**.
`TIMEOUT_FETCH` (300) e `TIMEOUT_CLONE` (900) **sem mudança, por não haver
dado**: o único fallback do ensaio saiu por rc 128 do git, não por estouro.

**A assimetria da falha é o critério.** Limite curto demais falha um CVE, é
nomeado no log (`excedeu ${T}s`), fica localizado e é reexecutável por CVE.
Limite longo demais deixa o item travado consumir o teto do job, mata o lote
inteiro e a reexecução recomeça do zero — o modo de falha de julho de 2026.

**Folga declarada:** ~9× sobre o máximo observado no CodeQL (103 s), ~15× nos
outros dois (58 s no Semgrep, 60 s no Snyk Code).

### 4. Lote de 30 confirmado no escopo restrito

69 s por CVE analisado no CodeQL, projeção de ~35 min contra 150 de teto.

**Escrito assim de propósito, e não "o ensaio confirmou o lote de 30":** o
perfil de item que não termina — o que interrompeu os lotes `aa` e `ab` em
julho de 2026 — **não foi amostrado** por sete CVEs.

### 5. Inventário do CodeQL: notificação × `artifacts[]` depurado

Batem **6 de 6**, até **704 arquivos**, incluindo o caso multilíngue
(`CVE-2018-14380`: 506 `.jsx`, 158 `.js`, 21 `.ts` extraídos; o Semgrep viu
ainda 1165 `.java` no mesmo repositório). **Nenhum teto na faixa medida.**

### 6. O Snyk Code não decide `gt_file_scanned`

`null` em **6 de 6**, com o motivo "coverage[] agregada, sem inventário de
caminhos: nao decide sobre um arquivo". **Resolve por observação** a suposição
que o `normalize.py` carregava. Consequência: cobertura por arquivo disponível
em **duas das três** ferramentas.

### 7. `gt_file_scanned: true` no `.yaml` do `CVE-2018-20164`

Significa que o arquivo **entrou no inventário** — presente na notificação de
extraídos do CodeQL e em `paths.scanned` do Semgrep —, **não que foi analisado
como YAML**: as duas ferramentas deram `SEM_ACHADOS`. **O ramo `false` segue
sem exercício no laço.**

### 8. Braço 3 da sonda de rede: 112 s no runner contra ~13 s de um lote com rede

O Semgrep **opera** sem rede, mas tentando alcançá-la e esperando o timeout, o
que é distinto de "não usa a rede". Reproduzido: 109 s e 113 s no hospedeiro
local, 112 s no runner — **não é artefato local**.

### Como os valores de `T` se aplicam

**Não estão no código, e não devem entrar nele.** Os `run_*.sh` mantêm os
defaults (3600/3600/1800/300/900), e os 900 entram como **entrada do
`workflow_dispatch`**, a cada disparo de lote:

```
gh workflow run analise-lote.yml --ref master \
    -f lote=cves-sast-batch-aa \
    -f timeout_create=900 -f timeout_analyze=900 -f timeout_analise=900
```

Cada job usa só os campos da sua ferramenta; campo vazio vale o default do
script. É o que H0b comprou: mudar o limite não exige rebuild nem digest novo.
O valor efetivo de cada lote fica na primeira linha do log e no README do
artifact, e o passo do lote o confere contra o pedido.

## Campanha SAST — resultados (17/09/2026)

Oito lotes, os 223 CVEs do benchmark, commit `579f383` em todos, três limites
em **900 s** conferidos pela linha que o **container** imprime em **24 de 24
jobs**. Nenhum lote precisou ser refeito.

| Lote | Execução | | Lote | Execução |
|---|---|---|---|---|
| `aa` | `35106944490` | | `ae` | `35169207030` |
| `ab` | `35135927579` | | `af` | `35169209525` |
| `ac` | `35169202777` | | `ag` | `35169211662` |
| `ad` | `35169205115` | | `ah` | `35169213227` |

`aa` e `ab` correram em série, com leitura entre eles, porque carregavam risco
desconhecido — o `aa` congelava o tamanho de lote e o `ab` tinha o
`zeit/next.js`. Os seis restantes correram em paralelo: **34 minutos de relógio
para 163 CVEs**. Custo total da campanha: cerca de **1 h 30** de relógio.

**A campanha atravessou a meia-noite UTC, e as datas diferem entre lotes.** Não
é inconsistência do registro: `aa` e `ab` rodaram em **16/09/2026** (14:12 e
18:41 UTC), e `ac` a `ah` em **17/09/2026** (01:05 a 01:39 UTC), disparados
juntos. O ensaio de fumaça, anterior a tudo, é de 16/09 às 13:25 UTC. Por isso
o `CVE-2016-1000229` sai datado de 16/09 (lote `aa`) e o `CVE-2018-8035` de
17/09 (lote `ad`), e por isso os cinco `SEM_ARQUIVO_ANALISAVEL`, vindos de
`ac`, `ad` e `af`, são de 17/09.

### As quatro grandezas, que não são a mesma

Confundi-las é fácil, e já ocorreu na redação deste registro. Elas são
distintas e todas necessárias:

| Grandeza | Valor |
|---|---:|
| CVEs no conjunto | **223** |
| Pares (CWE, arquivo) afirmados | **222** |
| Pares no denominador, após as duas baixas | **220** |
| CVEs com raw no CodeQL e no Semgrep | **221** |
| CVEs com raw no Snyk Code | **216** |

**222 e não 223 porque o `CVE-2018-1000096` não tem CWE** e já estava fora da
matriz antes de qualquer execução — ele rodou normalmente na campanha, com raw
nas três ferramentas. **220 e não 221** porque as baixas por código
indisponível são duas, e cada uma tira um par. **221 é contagem de CVE com
raw**, não de pares: 223 menos as duas baixas.

### Cobertura

As duas baixas, ambas fora do denominador e **nenhuma delas falso negativo**:

| CVE | Repositório | Causa |
|---|---|---|
| `CVE-2016-1000229` | `linxiaowu66/swagger-ui` | repositório inexistente; fetch e clone com rc 128 |
| `CVE-2018-8035` | `apache/uima-ducc` | commit inexistente; `upload-pack: not our ref`, depois `reference is not a tree` |

O Snyk Code tem cinco CVEs a menos porque saiu com `SEM_ARQUIVO_ANALISAVEL`
(exit 3) em `CVE-2018-16479`, `CVE-2018-16480`, `CVE-2018-3731`,
`CVE-2018-3747` e `CVE-2019-5423`. **São exatamente os cinco cujo arquivo de
ground truth não tem extensão** — `bin/http-live` e `bin/public` —, o que o
documento já registrava como peculiaridade do conjunto. Correlação **5 de 5**.
O ramo saiu do stub e tem ocorrência real; os CVEs **permanecem no
denominador**, e o estado conta como não-detecção do Snyk Code.

### Duração

| Ferramenta | mediana | média | máximo | q1–q3 | soma |
|---|---:|---:|---:|---|---:|
| CodeQL | 47 s | 58,6 s | 304 s | 43–60 s | 3,63 h |
| Semgrep | 18 s | 21,9 s | 202 s | 14–21 s | 1,36 h |
| Snyk Code | 13 s | 18,5 s | 135 s | 10–19 s | 1,14 h |

**Convenção: as 223 linhas do registro**, incluídas as duas de falha de
obtenção. **A média do CodeQL constou como 58,8 s até 22/09/2026**, valor que
corresponde a 222 linhas; sobre as 223 é 58,6 s. As demais células e as médias
das outras duas ferramentas sempre seguiram a convenção das 223. A V10 **herdou
daqui** o 58,8, e a conferência de `tools/confere-numeros-v10.py` o pegou nos
dois documentos; os dois foram corrigidos na mesma rodada.

**Os 900 s nunca foram exercidos:** o máximo dos 223 é 304 s, um terço do
limite, e nenhum log traz `excedeu`. O que se pode dizer é que a decisão de H4
**não foi posta à prova** — não que ela estava certa.

### Porte × custo no CodeQL, 221 pontos

| arquivos extraídos | n | mediana | mín | máx |
|---|---:|---:|---:|---:|
| 0–10 | 72 | 43 s | 35 s | 49 s |
| 11–50 | 57 | 45 s | 34 s | 58 s |
| 51–100 | 27 | 54 s | 39 s | 105 s |
| 101–200 | 26 | 61 s | 44 s | 83 s |
| 201–500 | 19 | 69 s | 49 s | 120 s |
| 501–1000 | 10 | 92 s | 59 s | 220 s |
| >1000 | 10 | 158 s | 60 s | 304 s |

Há um **piso de ~43 s** que domina até cerca de 50 arquivos, e a curva sobe de
forma monótona depois. O **joelho está entre 500 e 1000 arquivos**, onde a
mediana dobra em relação ao piso; acima de 1000 ela triplica. A relação entre
porte e custo **existe**, mas fica escondida sob o custo fixo de invocação na
faixa em que está a maior parte do conjunto — **129 dos 221 CVEs têm 50
arquivos ou menos**. O maior caso, **5693 arquivos**, custou 296 s.

**Isto REFINA, e não apaga, a formulação de 16/09/2026** ("porte do repositório
não prediz custo de análise"), registrada na leitura do ensaio de fumaça com 6
pontos e depois com 59. Aquela redação valia para a amostra que se tinha: nas
faixas então observadas o piso realmente domina, e foi o que se viu. Com 221
pontos a relação aparece — o que a amostra pequena não continha eram os casos
acima de 500 arquivos.

### Fallback de obtenção

**2 em 223**, ambos por **rc 128 do git**, **zero por estouro de limite**: um
no `aa`, um no `ad`, zero nos outros seis lotes. São os mesmos dois CVEs de
código indisponível. A taxa é **estável ao longo dos oito lotes**, sem a
elevação súbita que a métrica de vigilância existe para detectar.

### `gt_file_scanned`

CodeQL **221 `true`**, Semgrep **221 `true`**, Snyk Code **216 `null`**.

**Nenhum `false` nos 223.** O ramo continua sem exercício no laço depois da
campanha inteira, coberto só por fixture — limitação que sobreviveu ao conjunto
completo. O `null` do Snyk é o já registrado (`coverage[]` agregada, sem
inventário de caminhos), e a consequência para a análise é que **cobertura por
arquivo está disponível em duas das três ferramentas**.

### Inventário do CodeQL

**211 batem de 221.** Maior extração observada: **5693 arquivos**.

Dez divergentes: `CVE-2018-18282`, `CVE-2018-3738`, `CVE-2019-13127`,
`CVE-2019-15532`, `CVE-2019-15657`, `CVE-2019-18350`, `CVE-2019-18818`,
`CVE-2020-27666`, `CVE-2020-7638`, `CVE-2021-31712`.

**A divergência é sempre no mesmo sentido:** o `artifacts[]` depurado tem de 1
a 4 arquivos **a mais** que a notificação, e a notificação **nunca** tem nada
que o `artifacts[]` não tenha. Os 22 extras somados são todos JS/TS — 19 `.js`,
2 `.mjs`, 1 `.ts` — concentrados em `docs/.vuepress/`, `.storybook/`,
`examples/` e `tests/`.

**Isto não é teto de enumeração**, e a razão é a direção: teto faria a
*notificação* perder arquivos, e ela não perde nenhum. A escolha de usar a
notificação como fonte única — feita antes de existir raw real, contra a opção
mais óbvia do `artifacts[]` — **nunca superestimou cobertura** nos 221 casos.

**Hipótese, declarada como hipótese:** os extras são arquivos que o extrator
conheceu mas não extraiu — configuração de ferramenta de documentação e
exemplos. Confirmá-la exige cruzar com `js/diagnostics/extraction-errors` e
`js/parse-error`, que aparecem nos ids de notificação de dois desses SARIFs.
**Verificação disponível, não feita.**

### Achados brutos — volume reportado, NÃO detecção

CodeQL **3230**, Semgrep **11768**, Snyk Code **3666**. **Nada foi cruzado com
o ground truth**, e a comparação entre ferramentas **não se faz por este
número**: ele mede quantos alertas cada uma emitiu, não quantos CVEs cada uma
detectou.

O volume do Semgrep é **concentrado**: nos seis últimos lotes, 10 CVEs somam
**77%** do total, e só o **`CVE-2018-20801` responde por 5850 achados** — perfil
de regra disparando em massa num repositório, e não de detecção densa. O
cruzamento precisa saber disso antes de calcular precisão, sob pena de um único
CVE dominar a métrica da ferramenta.

### Portões

Nos 24 jobs: conferências (1), (2) e (4) do `check-log.py` em **zero**; a (3)
igual ao número de `SEM_ARQUIVO_ANALISAVEL` de cada lote, como previsto;
`normalize.py` com **zero** falhas, **zero** órfãos e **zero** raws ilegíveis;
portão de lote sem raw OK em todos; **zero** `ANOMALO`, `INCOERENTE` ou `NAO
RECONHECIDO`; nenhum `excedeu`; `df -h` inalterado antes e depois; sonda de
`HOME` com `DEFEITO MEDIDO` e rede do Semgrep `OPERA SEM REDE` em todos os
lotes.

Sobrecarga do laço — container menos a soma das durações por CVE: **1 a 4 s por
lote**, nas três ferramentas.

### Normalização — os 24 relatórios (apurado em 21/09/2026)

**Versionados desde 21/09/2026** em
`logs/campanha-2026-09-17/cves-sast-batch-<lote>/normalize-report-<ferramenta>.json`,
cópia byte a byte dos artifacts, com procedência e sha256 no `README.md` do
diretório. Até então **nenhum** estava no repositório: os três
`logs/normalize-report-*.json` da raiz são do ensaio local da Fase E, e os de
`logs/ensaio-fumaca-2026-09-16/` são do ensaio de fumaça.

Todos no schema `1.3`, com processados 221 / 221 / 216,
`pulados_por_idempotencia` **0** e falhas **0** — a duração somada cobre o
conjunto inteiro, e não um remanescente.

**Duração, somada sobre os oito lotes** — `duracao_segundos.total`, que mede o
laço sobre os raws (leitura, conversão, escrita do tratado), no runner:

| Ferramenta | normalização | análise (soma por CVE) | fração |
|---|---:|---:|---:|
| CodeQL | 0,96 s | 3,63 h | 0,007% |
| Semgrep | 25,65 s | 1,36 h | 0,52% |
| Snyk Code | 0,31 s | 1,14 h | 0,007% |

**A premissa da §5.1 da metodologia (V10) se sustenta em volume real:** cerca de 27 s
de normalização para as três ferramentas, contra cerca de 6 h de análise. O
Semgrep concentra o custo pelo mesmo motivo que concentra o volume: o maior
CVE, `CVE-2018-20801` (raw de 144,1 MiB), leva **8,72 s**, um terço do total da
ferramenta, e o lote `ac` que o contém leva 11,2 dos 25,7 s.

**Colisões da chave de ordenação: zero nas três**, sobre 18.664 achados. Isso
reconfere em escala a propriedade que a §9.1 limitava aos 4 CVEs do ensaio
local. O zero foi conferido por dois caminhos, porque zero sozinho não
distingue "não há" de "não perguntei":

- **recontagem independente** sobre os 658 tratados versionados, com a chave
  completa: zero de novo
- **controle positivo** com a chave **sem as colunas**, que é a do schema 1.1:
  **60 / 624 / 4** colisões em **27 / 60 / 2** CVEs (CodeQL / Semgrep / Snyk
  Code). O método acusa colisão quando ela existe, e são as colunas que a
  levam a zero. Na Fase E, com 4 CVEs, eram 11

**`rules_applied` do Semgrep, nos 221:** mínimo **144**
(`CVE-2018-20164`), máximo **910** (`CVE-2018-11798`), mediana **296**, que é
também a moda (79 CVEs). Quartis 296 e 302, com 39 valores distintos.
`rules_total` é 1074 em todos, `semgrep_rules_applied_anomalo` vazio nos oito
lotes, e os 221 valores batem com o `metadata.rules_applied` dos tratados.

### Volume dos resultados, e o que fica fora do git

Medido sobre os artifacts dos oito lotes, descomprimido:

| Ferramenta | raws | total | médio | tratados | total |
|---|---:|---:|---:|---:|---:|
| CodeQL | 221 | 59,1 MiB | 274 KiB | 221 | 2,3 MiB |
| Semgrep | 221 | 547,7 MiB | 2,5 MiB | 221 | 10,7 MiB |
| Snyk Code | 216 | 16,4 MiB | 78 KiB | 216 | 2,4 MiB |
| **Total** | **658** | **623,1 MiB** | | **658** | **15,5 MiB** |

**O Semgrep responde por 88% do volume bruto** — 547,7 dos 623,1 MiB —, e o
raw médio dele é **9× o do CodeQL e 32× o do Snyk Code**. Os **oito maiores
raws do conjunto são todos do Semgrep** e somam cerca de **341 MiB**, mais da
metade de tudo. O maior é o `CVE-2018-20801`, com **144,1 MiB** — o **mesmo CVE
dos 5850 achados** registrado acima. Volume de arquivo e volume de alerta não
são dois fatos: são o mesmo fato medido por dois instrumentos, a regra
disparando em massa num repositório.

**Os 24 logs de execução dos lotes estão versionados desde 18/09/2026**, em
`logs/campanha-2026-09-17/cves-sast-batch-<lote>/`, como cópia byte a byte dos
artifacts, com procedência e sha256 no `README.md` do diretório. Até então só
os dois agregados estavam no repositório, e o script que os gerou não está. O
`por_cve` do `campanha-223.json` é reconstituível dos 24 logs com **zero
divergências**, em status e duração, nos 223 × 3 pares. O
`tools/cruza-deteccao.py` lê os logs, e não o agregado.

**Os tratados somam 15,5 MiB, 40× menos que os raws**, com a mesma cobertura de
CVE. É o que a política de versionamento comprou: o tratado sustenta o
argumento, o raw é perícia.

**Os raws não são versionados, e não é só política.** `results/*/raw/` está
ignorado desde o início, mas o `CVE-2018-20801.json` de 144,1 MiB seria recusado
no push ainda que não estivesse — excede o limite de 100 MB por arquivo do
GitHub. **LFS foi decidido contra**: acrescentaria dependência de infraestrutura
e cota para guardar exatamente aquilo que a política classifica como
descartável.

**Onde os raws estão, e até quando.** Nos artifacts das oito execuções, com
retenção de 90 dias contados do **início da execução**, não da publicação do
artifact:

| Lotes | Execuções de | Artifacts expiram em |
|---|---|---|
| `aa`, `ab` | 16/09/2026 | **15/12/2026** |
| `ac` a `ah` | 17/09/2026 | **16/12/2026** |

Depois dessas datas, **reproduzir qualquer coisa a partir do raw depende de
cópia externa** — ao repositório e ao GitHub. Refazer a campanha não recupera o
raw antigo: reprocessa tudo, já que a idempotência é inerte no ambiente do
Actions. A cópia existe, comprimida por ferramenta e fora da árvore do projeto;
o caminho dela não vai a este arquivo, porque diretório na máquina do operador
não é registro reproduzível. Comprimida com `zstd`, ela cabe em **6,4 MiB** —
**1,0%** dos 623,1 MiB (CodeQL 54×, Semgrep 114×, Snyk Code 35×), o que por si
já diz da natureza do volume: JSON de achado repetido é quase todo redundância.

Feita em 17/09/2026. Um `tar` por ferramenta, com `zstd`:

| Arquivo | bytes | sha256 |
|---|---:|---|
| `raws-codeql-2026-09-17.tar.zst` | 1.139.137 | `1d33ab928ddfa4214cc801bf369e15a2f280b4fcb8e593a8c5b32570dddf8162` |
| `raws-semgrep-2026-09-17.tar.zst` | 5.033.822 | `fd2b118b8399547cdb059831a34906808b4b53dde747d6f247d5f2ba2221a822` |
| `raws-snyk-code-2026-09-17.tar.zst` | 485.769 | `a3e68bd40bb3408a20a05e037846189a8148888b209be8ed5b46eab319702eaf` |

**Conferida contra os artifacts em 21/09/2026.** Os três passam em `zstd -t`,
e os **658 raws** contidos (221 / 221 / 216) são idênticos por sha256 aos dos
artifacts. Nenhum falta, nenhum sobra, nenhum aparece em duplicata, e a
contagem por lote bate. **A cópia contém só os raws.** O restante de cada
artifact — `portoes/`, `container/`, `README.txt`, `disco.txt`,
`rede-semgrep/scan.json` e as 32 sondagens de `HOME` e de rede — está
**versionado desde 21/09/2026**, 232 arquivos byte a byte. Os primeiros cinco
estão em `logs/campanha-2026-09-17/cves-sast-batch-<lote>/<ferramenta>/`. As
sondagens estão em `datasets/sondagens/`, com o lote no nome: o do artifact
não o traz e colidiria entre lotes e com as quatro
`sondagem-*-runner-2026-09-16.txt` do ensaio de fumaça, das quais diferem. A
procedência, o manifesto de sha256 e a varredura de segredo que precedeu o
commit estão no `README.md` daquele diretório. Com isso, **tudo o que os 24
artifacts continham está no repositório ou na cópia externa**.

**Observação dos `container/lote.txt` do Snyk Code, não investigada:** todo
teste com achados termina com `ERROR Forbidden (SNYK-CLI-0000)`, `403`,
impresso **depois** do resumo do teste. São 133 de 133 testes com status `OK`,
e nenhum dos 83 `SEM_ACHADOS`. O raw foi gravado e normalizado nos 133. O que
a CLI tenta fazer quando recebe o 403, e se isso afeta algo além da
mensagem, não foi apurado. **Investigação adiada** até a renovação da cota de
testes do Snyk, esgotada em 21/09/2026; ver o item do Snyk Code em "Falso
positivo na versão corrigida".

## Cruzamento SAST — resultados (18/09/2026)

Números sem leitura. Os critérios — o que cada nível exige, as duas variantes
de CWE, o casamento de linha, o denominador — estão em
`docs/criterios-cruzamento.md`, que é a fonte; aqui só os números.

Produzidos por `tools/cruza-deteccao.py` sobre os 658 tratados, com as saídas
em `results/cruzamento/`: `matriz-deteccao.csv` (uma linha por (CVE,
ferramenta), 223 × 3) e `cruzamento-<ferramenta>.json` (agregados, achados
casados por `finding_id`, ressalvas). O CSV desta execução tem sha256

```
f80158b730794c3135701a8631e551d89610775562577322b806fcc180452825
```

gravado também em cada JSON (`csv_da_mesma_execucao`), ao lado do sha256
dos três scripts que o produziram (`fontes.codigo`). As saídas são
determinísticas — duas execuções dão os mesmos bytes — e não levam carimbo de
execução.

**Validação: nenhuma parada.** 0 anomalias em 658 tratados; autoteste
embutido com 34 de 34 mutantes acusados pela guarda pretendida; controle
positivo sem divergência; conferência CSV × JSON em 669 linhas, 0
divergências.

**Denominador: 220 pares**, o mesmo nas três ferramentas. Fora:
`CVE-2016-1000229` e `CVE-2018-8035` (código indisponível) e
`CVE-2018-1000096` (sem CWE).

### Matriz — acertos / não-acertos / não se aplica

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| nível 0 | 190 / 30 | 183 / 37 | 132 / 88 |
| nível 1 | 140 / 80 | 98 / 122 | 45 / 175 |
| nível 2 generosa | 126 / 94 | 48 / 172 | 16 / 204 |
| nível 2 estrita | 124 / 95 / 1 | 46 / 173 / 1 | 9 / 210 / 1 |
| nível 3 | 101 / 119 | 25 / 195 | 22 / 198 |
| nível 4 generosa | 95 / 125 | 20 / 200 | 10 / 210 |
| nível 4 estrita | 94 / 125 / 1 | 20 / 199 / 1 | 6 / 213 / 1 |

A terceira parcela só existe nas variantes estritas.

### Nível 1 × nível 3

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| CVEs no nível 1 | 140 | 98 | 45 |
| destes, no nível 3 | 101 | 25 | 22 |
| destes, sem nível 3 | 39 | 73 | 23 |

### Contagens à parte

**Estrita não se aplica:** `CVE-2018-16472` (`CWE-250|CWE-400`, primário
indefinido na tabela), nas três ferramentas — contado em `não se aplica`,
nunca como não-acerto.

**Sem tratado no denominador, contados como não-detecção:** CodeQL 0,
Semgrep 0, Snyk Code 5 — `CVE-2018-16479`, `CVE-2018-16480`,
`CVE-2018-3731`, `CVE-2018-3747` e `CVE-2019-5423`, todos
`SEM_ARQUIVO_ANALISAVEL` nos logs da campanha.

**`gt_file_scanned` nos 220 pares:**

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| `true` | 220 | 220 | 0 |
| `false` | 0 | 0 | 0 |
| `null` | 0 | 0 | 215 |
| `sem_tratado` | 0 | 0 | 5 |

**Achados no arquivo do ground truth sem fim ou sem início de linha:**

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| achados no arquivo do gt com `line_end` nulo | 661 | 0 | 0 |
| achados no arquivo do gt com `line_start` nulo | 0 | 0 | 0 |

## Circularidade da proveniência — apuração (20/09/2026)

Números sem leitura, como no cruzamento. Produzidos por
`tools/circularidade-proveniencia.py` sobre a matriz de
`results/cruzamento/` e os relatórios de `results/proveniencia/`; saídas em
`results/circularidade/`. O script consome `por_relacao` e `sem_casar` do
cotejo e **não reimplementa** critério algum.

**O que se mede.** Os níveis 2 e 4 dependem de casamento de CWE, e o CodeQL é
medido contra etiquetas herdadas dele próprio em 163 dos 223. A apuração parte
o denominador de 220 pela proveniência da etiqueta e compara as três
ferramentas nos sete níveis, para que se veja se a vantagem do CodeQL varia
com a proveniência ou com o conjunto.

**Partição, contra a âncora `ec573b51`:** herdado **161**, não herdado **59**,
soma 220. Fora do denominador: `CVE-2016-1000229` e `CVE-2018-1000096`
(herdados) e `CVE-2018-8035` (não herdado).

**Controle da partição:** a soma dos dois grupos reconstrói a matriz de
detecção publicada acima em **21 células × 2 partições, zero divergências**.

### Ressalva do método — a partição é por `explanation`

**O grupo não é definido pela etiqueta de CWE, e sim pela `explanation`.** O
cotejo casa `explanation` ≡ `@name` da consulta; a relação entre os conjuntos
de CWE é consequência reportada, não critério. Na âncora as duas coincidem —
163 casados, 163 `identico` —, **mas a recíproca não vale**: CVE de
`explanation` em prosa pode carregar conjunto de CWEs igual ao de uma consulta,
e cai em "não herdado" mesmo assim.

**Medido.** No grupo não herdado, **6 de 59** têm conjunto de 2+ CWEs idêntico
ao de alguma consulta do catálogo: `CVE-2019-10765`, `CVE-2020-11022`,
`CVE-2020-11059`, `CVE-2020-26256`, `CVE-2020-27666`, `CVE-2020-7752`.
Conjuntos unitários — 8 de 59 — são contados à parte, porque `CWE-079` sozinho
coincide com muitas consultas por banalidade e não por herança.

**O caso exemplar é `CVE-2019-10745`:** conjunto `CWE-078|079|094|400|915`,
idêntico ao dos 22 de prototype pollution, e `explanation` em prosa. É não
herdado nas **duas** referências, e é o 23º CVE com `gt_cwe_primary` CWE-915.

Registro de origem: o enunciado desta apuração definiu o grupo herdado como
"CVEs cuja etiqueta de CWE casa com a consulta". **Está errado**, e a correção
é esta seção. O número não muda — as duas afirmações coincidem em 163 de 163
na âncora —, mas as afirmações são distintas, e os 6 casos acima são a prova
de que a coincidência não é identidade.

### Tabela — grupo herdado (161) × não herdado (59)

`acertos/base`; a base das variantes estritas desconta o `CVE-2018-16472`,
cujo primário é indefinido.

| nível | CodeQL herd. | CodeQL n.herd. | Semgrep herd. | Semgrep n.herd. | Snyk herd. | Snyk n.herd. |
|---|---|---|---|---|---|---|
| 0 | 144/161 (89,4%) | 46/59 (78,0%) | 134/161 (83,2%) | 49/59 (83,1%) | 100/161 (62,1%) | 32/59 (54,2%) |
| 1 | 110/161 (68,3%) | 30/59 (50,8%) | 77/161 (47,8%) | 21/59 (35,6%) | 39/161 (24,2%) | 6/59 (10,2%) |
| 2 generosa | 101/161 (62,7%) | 25/59 (42,4%) | 35/161 (21,7%) | 13/59 (22,0%) | 15/161 (9,3%) | 1/59 (1,7%) |
| 2 estrita | 100/160 (62,5%) | 24/59 (40,7%) | 33/160 (20,6%) | 13/59 (22,0%) | 9/160 (5,6%) | 0/59 (0,0%) |
| 3 | 80/161 (49,7%) | 21/59 (35,6%) | 22/161 (13,7%) | 3/59 (5,1%) | 21/161 (13,0%) | 1/59 (1,7%) |
| 4 generosa | 76/161 (47,2%) | 19/59 (32,2%) | 17/161 (10,6%) | 3/59 (5,1%) | 10/161 (6,2%) | 0/59 (0,0%) |
| 4 estrita | 76/160 (47,5%) | 18/59 (30,5%) | 17/160 (10,6%) | 3/59 (5,1%) | 6/160 (3,8%) | 0/59 (0,0%) |

**Numerador e denominador vão sempre juntos, e não há teste estatístico.** Os
grupos são de tamanhos muito desiguais — 161 contra 59 —, e diferença de
poucos pontos percentuais no grupo menor não significa nada.

**Os três zeros são do Snyk Code, no grupo não herdado.** O controle é que o
mesmo caminho de contagem dá 9, 10 e 6 nas células herdadas dos mesmos níveis,
e que o autoteste do script exercita mutação de zero para um antes de tocar o
conjunto real.

### Deltas (herdado − não herdado, em pontos percentuais)

**Os níveis 1 e 3 não usam CWE e são o controle interno.** Diferença que
apareça neles não pode ser circularidade de etiqueta.

| nível | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| 0 | +11,5 | +0,2 | +7,9 |
| **1 (sem CWE)** | **+17,5** | **+12,2** | **+14,1** |
| 2 generosa | +20,4 | −0,3 | +7,6 |
| 2 estrita | +21,8 | −1,4 | +5,6 |
| **3 (sem CWE)** | **+14,1** | **+8,6** | **+11,3** |
| 4 generosa | +15,0 | +5,5 | +6,2 |
| 4 estrita | +17,0 | +5,5 | +3,8 |

### Composição de CWE dos dois grupos — os grupos não são comparáveis

`gt_cwe_primary`, dez categorias — **não** as maiores do denominador: fora
delas ficam CWE-020 (6) e CWE-089 (4). As dez coincidem com a união das sete
maiores de cada grupo, e com nenhum outro corte de 3 a 9. **Se foi esse o
critério usado ao criar a tabela não está registrado** no commit que a criou
(`4a9241b`), onde o rótulo era "os oito maiores". A distribuição completa,
sem partição, está em `results/por-cwe/distribuicao-primario.csv`:

| CWE primário | herdado | não herdado |
|---|---:|---:|
| **CWE-915** | **0** | **23** |
| CWE-079 | 39 | 8 |
| CWE-022 | 27 | 2 |
| CWE-078 | 24 | 1 |
| CWE-400 | 24 | 2 |
| CWE-094 | 8 | 6 |
| CWE-116 | 8 | 1 |
| CWE-770 | 0 | 4 |
| CWE-730 | 0 | 3 |
| CWE-601 | 7 | 0 |

Conjunto `gt_cwes` completo, os maiores:

| conjunto | herdado | não herdado |
|---|---:|---:|
| `CWE-078\|CWE-079\|CWE-094\|CWE-400\|CWE-915` | **0** | **23** |
| `CWE-079\|CWE-116` | 38 | 2 |
| `CWE-078\|CWE-088` | 24 | 1 |
| `CWE-730\|CWE-400` | 24 | 1 |
| `CWE-022\|CWE-023\|CWE-036\|CWE-073\|CWE-099` | 20 | 1 |
| `CWE-094\|CWE-079\|CWE-116` | 8 | 0 |
| `CWE-022` | 7 | 1 |
| `CWE-116\|CWE-020` | 7 | 0 |
| `CWE-079` | 0 | 6 |

**39% do grupo não herdado é prototype pollution**, ausente por completo do
herdado. Enquanto for assim, proveniência da etiqueta e tipo de vulnerabilidade
variam juntos, e nenhuma das duas explica a diferença sozinha. É a confusão
que a apuração torna visível, e que ela **não** resolve.

### Os 22 de prototype pollution

Todos com `gt_cwe_primary` CWE-915, todos com o mesmo conjunto `gt_cwes`,
todos no denominador. **Não herdados sob `ec573b51`, herdados sob `9ff6d68a`.**

No cruzamento, sobre os 22:

| nível | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| 1 | 17 | 12 | 1 |
| 2 estrita | 16 | 11 | 0 |
| 3 | 14 | 1 | 0 |
| 4 estrita | **13** | 1 | 0 |

**Excluindo-os dos dois grupos, as duas partições passam a ser o mesmo
conjunto** — 161 e 37, conferido por igualdade de conjuntos — e as tabelas
ficam idênticas. Os deltas do CodeQL viram +33,2 / +40,9 / +30,8 / +34,0 nos
níveis 1 / 2 estrita / 3 / 4 estrita.

**Consequência para a escolha da âncora:** ela não é crítica para esta
análise. A diferença inteira entre as duas leituras são os 22, e fora deles as
duas referências dizem a mesma coisa. Sob `9ff6d68a` (183 contra 37) os deltas
do CodeQL são +34,3 / +42,1 / +32,4 / +35,4 nos mesmos níveis.

### Composição dos grupos por ferramenta

| | herdado | não herdado |
|---|---|---|
| CodeQL | 161/161 | 59/59 |
| Semgrep | 161/161 | 59/59 |
| Snyk Code | **156/161** | 59/59 |

Os cinco `SEM_ARQUIVO_ANALISAVEL` do Snyk Code caem **todos no grupo
herdado**, nas duas referências. Permanecem no denominador e contam como
não-detecção, pela regra fixada antes da campanha.

## Falso positivo na versão corrigida — descoberta e decisão (21/09/2026)

**O README do benchmark define o falso positivo sobre a versão corrigida.**
Por CVE, ele pergunta se a ferramenta detecta a vulnerabilidade ou produz falso
negativo e se, rodando sobre o código corrigido, reconhece a correção ou produz
falso positivo. O negativo existe: é a versão corrigida, no ponto da falha,
onde o benchmark garante (`docs/benchmark-CVEs.md`) que a vulnerabilidade foi
removida. Lido em 21/09/2026, no commit `91c59fd` do benchmark; o trecho está
no README desde o release 1.0.0.

**O critério já estava neste arquivo, e o erro foi não ligá-lo.** O critério
da versão corrigida está na seção "Critério oficial de acerto do benchmark"
desde 28/08/2026 (`342194b`). A §1 do `docs/criterios-cruzamento.md` foi escrita
em 18/09/2026 sem ligá-lo ao falso positivo, e o README, que o nomeia assim, não
tinha sido lido. A §1 recebeu **emenda datada de 21/09/2026**, que marca como
superado o trecho errado e o preserva. Alerta **fora** do ponto da falha
continua não classificável.

- **A primeira campanha rodou só antes da correção** e dá a metade VP/FN da
  matriz. Essa metade **não muda**: os cinco níveis, as duas variantes, o
  denominador de 220 e a apuração da circularidade ficam como estão.
- **Decidido: haverá uma segunda campanha, sobre o `PostPatchCommit`**, com as
  mesmas imagens e o mesmo pipeline da primeira. É a campanha de reconhecimento
  da correção, e a regra crítica foi reescrita para admiti-la, e só a ela.
- **O critério de casamento na versão corrigida ainda não está fixado.** Será
  definido no documento de critérios antes de qualquer resultado. A primeira
  decisão é entre a matriz de quatro células e a leitura condicional que a
  ferramenta de relatório do benchmark implementa; as duas estão descritas na
  §8 do documento.
- **A campanha de julho de 2026, que rodou no HEAD, não substitui a segunda.**
  O HEAD difere do código vulnerável por anos de mudanças, e não só pela
  correção, o que desfaz a comparação controlada que o benchmark propõe.
- **Snyk Code.** A cota de testes da conta usada na campanha **esgotou em
  21/09/2026**, e a investigação do 403 (ver "Observação dos
  `container/lote.txt` do Snyk Code") fica **adiada até a renovação**. Cada
  execução do Snyk Code consome um teste. A investigação gasta de 4 a 6; a
  segunda campanha soma outros 216, se repetir a cobertura da primeira; no pior
  caso, com a primeira campanha do Snyk refeita, as duas somam **432**. Se a
  cota for resolvida com outra conta, **as duas campanhas do Snyk precisam
  rodar na mesma conta**, ou o 403 precisa ser investigado antes, para saber se
  depende da conta.
- Os dois `PostPatchCommit` malformados do benchmark passam a afetar a segunda
  campanha; ver os defeitos conhecidos do conjunto.

## Metodologia V10 — natureza e pendências (21/09/2026)

**A versão vigente é a `docs/metodologia-V10.md`, de 22/09/2026, e ela é
parcial.** Documento de método **e resultados**, cobrindo as campanhas SAST e
DAST; revoga a frase da V9 de que "nenhum resultado de detecção é apresentado
aqui". As seções **9.8** (resultados da versão corrigida), **9.9** (detecção por
CWE), **10** (resultados DAST) e **11** (análise comparativa) estão **a
preencher**, e a versão só fecha com as quatro.

**Numeração nova:** as seções 9, 10 e 11 da V9 passaram a **12** (ameaças), **13**
(decisões) e **14** (pendências), para que os resultados venham depois do método.
Remissão a "Seção 9" da V9 hoje aponta para os resultados, não para as ameaças.

**A V9 permanece versionada**, como registro do que estava decidido antes da
campanha, e a V10 remete a ela. **A pauta da V10 foi removida** no commit que
versionou a V10, por ter cumprido a função; está no histórico, versionada em
`f6bd601`, e recuperável por
`git show f6bd601:docs/pauta-metodologia-V10.md`.

**Três promessas da V9 ainda não cumpridas, a fazer antes de fechar a V10:**

- a **detecção por CWE, por ferramenta** (§7.7). O cruzamento apurou por
  ferramenta; a decomposição por CWE não existe;
- a **tabela de capacidade empírica** por ferramenta (§7.6);
- a **proporção dos achados do Semgrep fora de JavaScript/TypeScript**,
  declarada (§7.6).

**Registrado noutras seções, e não repetido aqui:**

- **A sondagem de disponibilidade antes da campanha** está em "Obtenção do
  código". A última registrada é a de 10/09/2026, seis dias antes da
  campanha, e o denominador saiu da medição da própria campanha.
- **A cota do Snyk Code e o adiamento da investigação do 403** estão no item
  do Snyk Code em "Falso positivo na versão corrigida".

### Conferência dos números da metodologia (22/09/2026)

**`tools/confere-numeros-v10.py` confere o documento contra as fontes
versionadas**, tratando-o como texto de entrada e nunca como verdade. Na
primeira rodada foram **447 afirmações**, com controle positivo de **10 de 10**
células adulteradas acusadas, uma por família de verificação. Extração que não
case exatamente uma vez é falha declarada, nunca silêncio.

```
python3 tools/confere-numeros-v10.py --controle-positivo
```

**O que a conferência pegou:** a média do CodeQL em 58,8 s, que vinha deste
arquivo, e a faixa de duração do lote mais lento, que não batia com a medição
versionada. Ambas corrigidas nos dois documentos em 22/09/2026.

**O que NÃO é conferível a partir do repositório, e por quê.** A lista poupa a
próxima conferência de redescobri-la; nenhum destes números sai de arquivo
versionado, e todos são declarados como medição própria:

| Afirmação | Por que não se confere |
|---|---|
| Severidades do pack do Semgrep (722/310/31/11) | exige parser YAML, e o ambiente local não tem um; contar com `grep` é proibido pela regra geral de contagem. `rules_total` 1074 e 163 JS/TS conferem contra o descritor versionado |
| Volume bruto (623 / 548 / 144 MiB) e cópia externa (6,35 MiB) | `results/*/raw/` não é versionado; a fonte é este arquivo |
| 1 h 30 de relógio da campanha, e os 34 min dos seis lotes em paralelo | duração de **job** no GitHub Actions, que inclui pull da imagem e upload de artifact; não versionada. O que se confere é a duração do **container**, no `README.txt` de cada lote |
| Suítes do CodeQL (88 / 104 / 202 consultas) | o bundle não é versionado |
| Sondagem de 06/09/2026 (185 de 186) | não deixou saída versionada; só a de 10/09/2026 tem arquivo |

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

**Na campanha de 16 e 17/09/2026 a regra não foi cumprida à letra** (conferido
em 22/09/2026). Há duas sondagens de repositório registradas: a de 06/09/2026,
citada nos defeitos conhecidos e sem saída versionada, e a de **10/09/2026**,
em `datasets/sondagens/sondagem-repos-2026-09-10.csv` (`4d22aa5`): 185
`ACESSIVEL` e um `INACESSIVEL`, o `linxiaowu66/swagger-ui`. **Nenhuma
registrada entre 10/09 e a campanha**: a última precedeu o lote `aa` em seis
dias, e nenhum workflow invoca o `tools/probe-repos.sh`. A pauta da V10 dava a de 06/09 como a
última registrada, mas a de 10/09 é posterior.

- **O denominador saiu da medição da própria campanha, CVE a CVE**, e não da
  sondagem: `ERRO_FETCH` no `CVE-2016-1000229`, `ERRO_CHECKOUT` no
  `CVE-2018-8035`. A sondagem de 10/09 daria uma baixa só.
- **Uma sondagem de repositório não teria detectado o `CVE-2018-8035`**, por
  mais próxima da campanha que fosse: é commit inexistente em repositório
  existente, e o script pergunta só pelo `HEAD` (`git ls-remote --exit-code
  <url> HEAD`). O `apache/uima-ducc` saiu `ACESSIVEL` em 10/09.

A V9 (§4.3 e §7.4) afirma que o denominador é o apurado na sondagem que
antecede a execução. Isso não descreve o que ocorreu, e a V10 precisa dizer
como o protocolo foi de fato cumprido; está na §4.3 da
`docs/metodologia-V10.md`.

**A sondagem deve ser anônima.** O `git ls-remote` usa, por padrão, o
credential helper configurado no hospedeiro — com o `gh` autenticado, a
sondagem mede o acesso **do operador**, não o acesso anônimo que a campanha
terá. Repositório privado sairia `ACESSIVEL` na sondagem e `ERRO_FETCH` na
execução, que é exatamente a divergência que a sondagem existe para
antecipar. O script neutraliza a configuração global e o helper antes de
sondar.

## Defeitos conhecidos do conjunto de dados

- `CVE-2018-1000096` não tem CWE atribuído. É analisado normalmente, mas
  fica fora das contagens da matriz de confusão
- `CVE-2017-18352` e `CVE-2018-11093` têm `PostPatchCommit` malformado no
  benchmark original da OpenSSF — truncado e abreviado, respectivamente
  (38 e 7 caracteres hex). Não afetou a campanha de detecção, que usa apenas
  `PrePatchCommit`. **Passam a afetar a segunda campanha**, que roda sobre o
  `PostPatchCommit` (ver "Falso positivo na versão corrigida"). O pipeline
  pressupõe SHA completo — o fetch raso é por SHA, e a asserção compara
  `git rev-parse HEAD` com o valor da lista —, e hoje o gerador nem emite o
  `PostPatchCommit`, só avisa da forma dele. A resolução — expandir o SHA
  abreviado pelo próprio repositório, se o prefixo for único, ou excluir com
  motivo declarado — fica para o desenho da segunda campanha, e não está
  tomada.
  Os 223 `PrePatchCommit`, esses, são SHA-1 completos e bem formados — e o
  gerador valida 40 hex. **Boa formação não implica que o objeto referido
  seja um commit:** um objeto de tag anotada tem a mesma forma, atravessa
  fetch e checkout sem erro e desloca a árvore analisada em silêncio. Só a
  asserção de `git rev-parse HEAD` intercepta; ver as convenções de execução
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
  porque não houve código. Categoria própria, fora da matriz.
  Reconferir na hora da campanha: repositório pode voltar, outro pode cair.
  Reconferido em 10/09/2026, com o mesmo resultado, e não na hora da
  campanha; ver "Obtenção do código".
  Ironia registrada: é justamente um dos dois homônimos que motivaram a
  regra de nomear saídas pelo CVE
- **`CVE-2018-8035` — commit inexistente no repositório.** Medido na campanha
  em 17/09/2026, lote `ad`, nas três ferramentas: em `apache/uima-ducc`, o
  fetch raso saiu 128 com `upload-pack: not our ref`, o clone completo veio, e
  o `git checkout` falhou com `reference is not a tree` — o commit
  `4c20c4fc00d5605ba40fac235df3ccf7dc38cb52` que o benchmark declara não existe
  ali. Status `ERRO_CHECKOUT`, sem raw.
  É a **segunda** baixa por indisponibilidade de código, da mesma categoria da
  anterior: nenhuma ferramenta foi confrontada com o código, logo não é falso
  negativo. Note que o SHA é bem formado — 40 hex — e que aqui nem a boa
  formação nem a asserção de HEAD estão em causa: o objeto simplesmente não
  está no repositório
- **Denominador da campanha, consolidado em 17/09/2026.** As duas baixas acima
  tiram um par cada: **222 pares afirmados → 220 no denominador**, em ambas as
  modalidades. Até a campanha o documento registrava 221, com uma baixa só.
  **Não confundir com a contagem em CVEs:** 223 CVEs no conjunto, 221 com raw
  no CodeQL e no Semgrep. Os dois números não coincidem porque o
  `CVE-2018-1000096` não tem CWE e já estava fora da matriz antes de qualquer
  execução — é ele que faz 222 e não 223

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

**Fronteira fechada no smoke test da Fase E (10/09/2026).** `results` é
opcional no SARIF, e o risco era o Snyk **omitir** a chave em varredura sem
achados, transformando toda análise limpa em falha dura. Medido em varredura
real sem achados (`CVE-2017-16042`, `snyk exit 0`): a chave **está presente,
como lista vazia**, e o `runs[0]` traz `automationDetails`, `properties`,
`results` e `tool`. A guarda fica como está, e a regra alternativa
("ausência de `results` com `coverage[]` presente = zero achados") **não** é
necessária.

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

**Versão corrente: `1.3`.** O valor vive em `SCHEMA_VERSION`, no
`tools/normalize.py`, e é gravado em `metadata.schema_version` de todo
tratado e no cabeçalho de todo relatório de normalização. Tratado com versão
divergente da corrente **não** é pulado pela idempotência: reprocessa, ou
falha pedindo `--overwrite`. Sem isso, evolução do schema produziria conjunto
heterogêneo sem sinal.

Bloco `metadata` por CVE, lista `findings`. Campos de ground truth
prefixados por `gt_`, no bloco de metadados, não repetidos por achado:

- `gt_cwes` — conjunto declarado pelo benchmark, normalizado
- `gt_cwe_primary` — CWE selecionado pela tabela de mapeamento; nulo nos
  CVEs sem CWE e naquele cujo conjunto segue sem primário definido
- `gt_file_path` — escalar
- `gt_file_lines` — lista, podendo ter mais de um elemento em três CVEs

**Colunas nos achados, desde o schema 1.2.** `column_start` e `column_end`,
anuláveis, com a mesma disciplina do `line_end`. As três ferramentas as
emitem em 100% dos achados (`region.startColumn`/`endColumn` no SARIF,
`start.col`/`end.col` no Semgrep) — no CodeQL a coluna vem **mesmo quando o
`endLine` não vem**.

Entraram por medição, não por completude: na Fase E, **11 achados do Semgrep
empataram** em (arquivo, linha, regra, mensagem) e diferiam **só na coluna** —
duas chamadas a `path.join` na mesma linha, em `lib/fp/build-modules.js:122`,
colunas 24-30 e 32-40. Sem a coluna a chave de ordenação não era total contra
saída real, e um empate deixava de ser informação: passava a significar
"idênticos em tudo que o schema grava" quando os achados eram distintos no
raw. Também inflava qualquer contagem de precisão sobre `findings`, contando
o mesmo par (regra, linha) mais de uma vez sem deixar rastro por achado.
Com as colunas na chave, as 11 colisões foram a **zero** nos mesmos raws.

A ordem da chave é: `file_path`, `line_start`, `line_end`, `column_start`,
`column_end`, `rule_id`, `message`, e o índice de entrada só como desempate
final.

- `gt_file_scanned` — tri-estado: a ferramenta considerou o arquivo do
  ground truth? **`true`/`false` no Semgrep e no CodeQL; `null` no Snyk.**
  O `gt_file_scanned_reason` acompanha os **três** estados desde o schema 1.3.

  **A assimetria inverteu na Fase E.** Até o 1.2 o `null` era do CodeQL e se
  dizia declarado; a medição mostrou que o SARIF **traz** inventário, e o
  `null` passou a ser só do Snyk, onde é impossibilidade real —
  `coverage[]` agregada por linguagem, `files` sempre contagem.

  **Fonte no CodeQL: a notificação `js/diagnostics/successfully-extracted-files`,
  e só ela.** Enumera um caminho por arquivo extraído, inclui arquivos sem
  achado, e o caminho vive só em `locations[0]` — `message.text` é vazia.

  **`runs[0].artifacts[]` está descartado como fonte.** É a escolha óbvia e é
  a errada: superconjunto contaminado por outras linguagens. No
  `CVE-2018-14040` traz 176 entradas contra 174 da notificação, e as duas a
  mais — `docs/_plugins/bridge.rb` e `docs/_plugins/bugify.rb` — entram por
  notificação de Ruby. Usá-lo reportaria como varrido o que o extrator de
  JavaScript não tocou, o que é **pior que `null`**: afirma o contrário do
  verdadeiro. `js/baseline/expected-extracted-files` também não serve — é
  amostra de baseline (45 contra 174 no mesmo CVE), não inventário.

  **Ausência da notificação → `null`, nunca `false`.** Ausência de inventário
  e ausência do arquivo no inventário são coisas distintas, pelo mesmo
  princípio que separa `unknown` de `unresolved` na severidade.

  **`false` não quer dizer o mesmo nas duas ferramentas**, e é por isso que o
  motivo passou a acompanhar todos os estados:

  | Ferramenta | `false` significa |
  |---|---|
  | Semgrep | o arquivo ficou fora da varredura (`paths.scanned`) |
  | CodeQL | o arquivo não foi extraído para o banco de dados |
  | Snyk Code | não ocorre: o estado é `null`, indeterminado |

  Os dois universos respondem à pergunta que o campo faz — o arquivo foi
  olhado, ou a ausência de achado é artefato? Mas respondem **por aproximação
  declarada, não por equivalência**. O `false` do CodeQL é mais ruidoso: parte
  dos arquivos não extraídos simplesmente **não é da linguagem analisada**, e
  não ter sido extraído nada diz sobre cobertura. Não afeta o uso, porque o
  `gt_file_path` é JS/TS por construção do benchmark — mas a distinção não é
  decorativa, e é o que impede simplificar o `gt_file_scanned_reason` adiante.
  O que não se pode é deixar um booleano fingir uniformidade que não existe.

  **Conferência do teto, sem compensação.** Não se sabe se a notificação
  enumera *todos* os arquivos extraídos ou até um limite. O relatório grava,
  por CVE, a contagem da notificação e a de `artifacts[]` **depurado** das
  URIs que só aparecem por notificação de outra linguagem; divergência num CVE
  grande é o sinal. Nenhuma heurística compensa teto: conta-se e reporta-se, e
  a campanha decide com 223 CVEs em vez de 4. O modo de falha é **assimétrico**
  e conservador — havendo teto, o arquivo acima dele sai `false`, nunca
  `true`, e `false` não fabrica varredura que não houve.
  Medido nos 4 CVEs da Fase E: **bateu em 4 de 4** (3, 174, 126 e 58).

  **Motivação original do campo**, que é assunto distinto da conferência
  acima: ele é apurado nos 223, e não só nos cinco CVEs cujo arquivo do
  ground truth não tem extensão (`bin/public`: CVE-2018-16480, CVE-2018-3731,
  CVE-2018-3747; `bin/http-live`: CVE-2018-16479, CVE-2019-5423) — aqueles em
  que a dúvida "a ferramenta olhou este arquivo?" salta à vista. Custa o mesmo
  apurar em todos, e dá o denominador de arquivos considerados por ferramenta.
  **`false` não exclui de denominador algum** — ver "O que NÃO fazer"

- `tool_diagnostics` — o que a ferramenta reporta sobre a própria execução:
  `errors` (Semgrep, de `errors[]`; Snyk, da contagem de `FAILED_PARSING` da
  `coverage[]`), `skipped_paths` (Semgrep), `notifications`
  (`invocations[].toolExecutionNotifications`, **só o CodeQL**) e `details`.
  Captura **condicional**: campo ausente grava `null` e segue; ausência nunca
  é falha, porque a emissão não está assegurada.
  **Medido na Fase E:** o Snyk **não emite** `toolExecutionNotifications` —
  `invocations` está ausente por inteiro do SARIF dele —, e o Semgrep não
  emite `paths.skipped` sem `--verbose`. Nos dois casos o `null` é o
  comportamento previsto para campo ausente, e foi o observado.
  Motivo de existir: arquivo cuja análise falhou não produz achado, e o
  resultado é indistinguível de análise limpa. Mesmo modo de falha que o
  `gt_file_scanned` pega, por outro caminho.
  **`gt_file_affected` foi removido no schema 1.2**, e o motivo é
  instrutivo: a polaridade do campo **invertia entre ferramentas**. No
  Semgrep os detalhes vinham de `errors[]` e `paths.skipped[]` — problemas —,
  então `true` queria dizer "houve problema com o arquivo"; no CodeQL vinham
  das `toolExecutionNotifications`, que são quase todas de extração
  **bem-sucedida** (174 de 176 num CVE), então `true` queria dizer o oposto.
  Pior: o booleano era calculado sobre a lista inteira, enquanto `details`
  guarda só as 20 primeiras entradas — num CVE com 224 notificações o campo
  saía `true` por causa de uma entrada que o tratado não grava, e quem lê não
  tinha como conferir nem refutar. Campo cujo sentido depende da ferramenta,
  e cuja evidência não está no registro, é pior que campo ausente.
  No CodeQL a pergunta verdadeira — "a ferramenta considerou este arquivo" —
  é a do `gt_file_scanned`, que desde o schema 1.3 a responde pelo inventário
  do próprio SARIF, em vez de por subcadeia sobre texto truncado

- `schema_version` — literal. Tratado com versão divergente da corrente
  **não** é pulado pela idempotência: reprocessa, ou falha se faltar
  `--overwrite`. Sem isso, evolução do schema produz conjunto heterogêneo
  sem sinal

- `analysis_date_source` — `tool` ou `file_mtime`. **Só o Snyk Code usa
  carimbo da ferramenta**, de `automationDetails.id`. CodeQL e Semgrep caem
  no mtime do raw, por motivos diferentes: o Semgrep **não emite carimbo
  algum** no JSON; o CodeQL emite bloco de invocação **sem data de
  conclusão** — `invocations[0].endTimeUtc` não existe na 2.25.4, e os quatro
  CVEs da Fase E caíram no mtime. Ver "Divergências encontradas na
  confrontação da Fase E".
  O ramo `analysis_date_source: "tool"` do CodeQL ficou, portanto,
  **inalcançável** na versão fixada. O tratamento permanece como salvaguarda
  e descreve forma não observada.
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
"rules_applied": 297
```

Preenchimento por ferramenta:

- **Semgrep** — completo; `rules_applied` vem de `.time.rules[]`, que conta
  as regras **aplicadas às linguagens presentes**, não as 1074 carregadas
  (medido na Fase E; ver a subseção do Semgrep). A relação verdadeira é
  `rules_applied` ≤ `rules_total`, e só a **violação** desse limite é
  anomalia — desigualdade estrita é o caso comum.
  `rules_id_sha256` vem do descritor e é **obrigatório**: o `sha256`
  identifica o *arquivo*, e só ele não permite a um terceiro verificar
  identidade de *conjunto*, porque o registry serve o YAML em ordem não
  determinística. Sem o campo no tratado, quem lê um treated isolado teria de
  ir ao descritor
- **CodeQL** — `name` = referência da suíte, `sha256`, `rules_id_sha256` e
  `obtained_at` nulos, `rules_total` 104, `rules_applied` **nulo**: o `driver.rules[]` do
  SARIF registra o que apareceu no resultado, não o que foi aplicado
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

**`gt_file_scanned_reason`** acompanha o `gt_file_scanned` nos **três**
estados desde o schema 1.3, não só no `null`. Enquanto uma única ferramenta
decidia, o motivo só era necessário para explicar a abstenção; com duas
decidindo por **mecanismos distintos** — varridos no Semgrep, extraídos no
CodeQL —, o booleano sozinho passaria a esconder de que universo veio.

O `null` restante é do Snyk, e ali é impossibilidade real: `coverage[]`
agregada por linguagem, `files` sempre contagem. No Semgrep o `null` só
ocorreria se o JSON viesse sem `paths.scanned`, o que não aconteceu na Fase E;
no CodeQL, se o SARIF vier sem a notificação de extraídos.

**Chave canônica na busca da tabela de primário.** Normalizar para três
dígitos, ordenar, juntar. Nunca casar por string crua contra a grafia em
prosa. Conjunto **ausente** da tabela → falha ruidosa. Conjunto
**presente com primário vazio** (`CWE-250|CWE-400`) → grava nulo, conta,
reporta. São erros diferentes.

## Imagens da campanha — digests publicados

O digest é o contrato: os jobs de lote referenciam a imagem por ele, e a tag
`campanha` se move a cada build. Todo rebuild produz digests novos por
definição, e cada conjunto publicado fica registrado aqui, datado e com o run
id do `build-imagens.yml`, que é quem os produz. O inventário completo de cada
build está no consolidado `datasets/sondagens/sondagem-imagens-runner-<data>.txt`;
o artifact expira em 90 dias.

### Vigentes — rebuild de H0c, 15/09/2026

Execução `34961746566`, construída em `2026-09-15T11:09:37Z` sobre o commit
`a08c559` (H0b), runner `ubuntu24` / `20260907.300.1`, uid:gid `1001:1001`.
Consolidado: `datasets/sondagens/sondagem-imagens-runner-2026-09-15.txt`.

```
ghcr.io/francisco-lima-dev/ic-security-lab-codeql@sha256:39950e7ac03b7d7b7a724c742e1c48e9475ed998d58a4734d653188d31afcbec
ghcr.io/francisco-lima-dev/ic-security-lab-semgrep@sha256:de71bdfbdf81d495781a4c80052c5f7d128ec9b76eba2304978e08b88ba5d000
ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
```

**Por que existem.** H0b tornou os limites de tempo sobrescrevíveis por
ambiente, e os scripts entram na imagem por `COPY scripts/ /scripts/`: sem
rebuild, as imagens publicadas rodariam os scripts anteriores, que ignoram o
ambiente. O rebuild precede o ensaio de fumaça para que o ensaio meça as
imagens que a campanha usa — medição numa imagem aplicada a outra não é
evidência.

**Valores pinados, conferidos contra os descritores versionados:** bundle do
CodeQL `v2.25.4` (sha256 `5a68ac6f…`), pack do Semgrep (sha256 `1ddc9b0b…`),
`semgrep==1.171.0`, CLI do Snyk `1.1306.1` (sha256 `3b25e606…`). Idênticos aos
de 12/09; nenhum descritor, Dockerfile ou o próprio workflow mudou entre
`49282a8` e `a08c559`.

**Deriva contra o consolidado de 12/09 — a medida do que ficou solto.**

| Imagem | `.deb` com versão mudada | pip com versão mudada | acrescentados / removidos |
|---|---:|---:|---:|
| codeql | 0 de 413 | — | 0 / 0 |
| semgrep | 0 de 118 | 1 de 67: `uvicorn` 0.52.4 → 0.53.0 | 0 / 0 |
| snyk-code | 0 de 119 | — | 0 / 0 |

Um dos 716 artefatos soltos derivou em 2,5 dias, sem mudança de versão maior.
Base, runner, kernel e Docker idênticos aos de 12/09. O `image_id` mudou nas
três, como esperado: mudaram a camada de scripts e o label de revisão.

Apurado por parser da forma do consolidado, com a contagem declarada de cada
seção conferida contra as linhas lidas, e com controle positivo por mutação
sintética. O parser não está versionado; a deriva é reproduzível por `diff`
simples dos dois consolidados, que têm a mesma forma — fora cabeçalho, digests
e `image_id`, a única linha divergente é a do `uvicorn`.

### Histórico — substituídos pelo rebuild de H0c

Substituídos em 15/09/2026 porque trazem os scripts anteriores a H0b, com os
limites de tempo fixos no código. Nenhuma imagem foi apagada do GHCR nesta
fase: são o registro do que a Fase G produziu.

**12/09/2026, 22:11 UTC — execução `34722049993`, commit `49282a8` (G-2c).**
Vigentes até H0c. Consolidado:
`datasets/sondagens/sondagem-imagens-runner-2026-09-12.txt`.

```
ghcr.io/francisco-lima-dev/ic-security-lab-codeql@sha256:80c647fb2b5ff2bd17915d88f7d26af8962a2298c51d38d2e1950b142d22536a
ghcr.io/francisco-lima-dev/ic-security-lab-semgrep@sha256:27ef60ddb50ee7eaa2f482ddd9b3db55a32147f7f01e8ef4369309d1fda20eaf
ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:51d2d36b9174f90d3d6721caf4f7d990b921336a1dfa7e67ecb09a0c16b6fba8
```

**12/09/2026, 17:48 UTC — execução `34709333865`, commit `ae7c490`.** Build
anterior do mesmo dia, superado pelo das 22:11 antes de existir workflow de
lote que o usasse. Nenhum consolidado dele foi versionado; os digests abaixo
vêm do `digests.txt` do artifact, lido em 15/09/2026.

```
ghcr.io/francisco-lima-dev/ic-security-lab-codeql@sha256:8b6dd9c11d02c16b5007710ef2d12e93c46288b1ebb829dc0f866dd096b345eb
ghcr.io/francisco-lima-dev/ic-security-lab-semgrep@sha256:f27c2a37632d6b93452b2d038d7bb69b5d9ee34fd84a0055938d21a0ec320ab4
ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:5a0458faff9b10dc1edb4abee2f1e7b423be0909135b690702eb318052291d31
```

**12/09/2026, 17:34 UTC — execução `34708622703`, commit `a15b810` (G-2b).**
Falhou no passo de construção e publicação, mas **depois** de publicar duas das
três imagens: o `digests.txt` do artifact, lido em 15/09/2026, registra CodeQL e
Semgrep, e não traz digest nem inventário do Snyk. Imagem publicada por execução
que falhou continua no registro — é o caso que a emissão antecipada do output e
o `if: always()` do upload existem para não perder.

```
ghcr.io/francisco-lima-dev/ic-security-lab-codeql@sha256:b72cd8b47b6d56d5acbb6ba65fdcd9174d731781b43e20f107a529e1b0faddf8
ghcr.io/francisco-lima-dev/ic-security-lab-semgrep@sha256:dc8f7f7fdd668d7c49305593ca05e164f8725be2f96742c75210ed3bad86ed04
```

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
ponta.** O primeiro ensaio (set/2026) rodou na 2.26.4; a **Fase E
(10/09/2026) repetiu na 2.25.4 fixada**, sobre o lote `cves-sast-teste`, e
confirmou as mesmas propriedades: `database create` e `database analyze`
saíram 0 nos quatro CVEs, o `tool.driver.semanticVersion` do SARIF é
`2.25.4`, e os 104 achados vieram com caminho relativo e limpo. As quatro
propriedades originalmente confirmadas eram:

- o modo é aceito e o database é criado
- o caminho no SARIF sai **relativo e limpo** (`app.js`), sem prefixo do
  diretório de trabalho — a propriedade de que todo o cruzamento depende,
  e que vem de invocar a ferramenta com `--source-root=.` de dentro do
  WORKDIR
- 101 de 103 regras com CWE e as **mesmas** 101 com `security-severity`;
  as duas sem CWE são consultas de Summary, que não produzem achado
- `database analyze` sai **0 mesmo com achados**, então checar
  `RC != 0` não rebaixa análise bem-sucedida

Verificado na Fase E (10/09/2026): o asset do bundle existe na tag, a imagem
constrói, a suíte resolve 104 consultas e o lote `cves-sast-teste` rodou
ponta a ponta. O extrator de TypeScript aceita `.ts` sob `--build-mode=none`
em `node:24` — `database create` extraiu e saiu 0.

**O que resta é mais específico:** o extrator de TypeScript **atravessando o
laço**, sobre CVE de TypeScript real, no ambiente da campanha. A verificação
acima foi **sondagem dedicada, fora do laço**, e estabelece que o extrator
funciona — não que o laço o exercite. Os 4 CVEs do lote de teste são todos
JavaScript. Item do ensaio de fumaça no Actions; ver também as ameaças à
validade.

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
autocontida.

**O custo deixou de ser nulo-por-frequência na Etapa 3.** A campanha
constrói a imagem **uma vez** e a referencia **por digest** nos jobs de lote,
em vez de reconstruí-la a cada execução. O propósito do `COPY` fica mais
forte — o pack congela num digest citável —, mas a premissa de custo cai:
alterar o pack no repositório passa a exigir rebuild e republicação
explícitos.

Consequência para as guardas de sha256: com rebuild por execução, repositório
e imagem se moviam juntos e a comparação (2) quase não tinha como divergir.
Com build único, a derivação entre os dois passa a ser o modo de falha
esperado da nova forma de execução, e a comparação (2) **deixa de ser cinto
redundante e passa a ser a guarda em que a decisão do build único repousa**.
Ela é fatal e continua como está.

Cada job de lote registra o **digest da imagem efetivamente usada**, e o
relatório da campanha o reproduz.

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

**Resolvido no smoke test da Fase E (10/09/2026): `.time.rules[]` conta as
regras APLICADAS, não as carregadas.** Nos quatro CVEs analisados deu 256
(`tj/node-growl`, 5 arquivos), 297 (`twbs/bootstrap` 4.1 e `lodash`) e 370
(`twbs/bootstrap` 3), e as 256 do menor são **subconjunto próprio** das 370
do maior — varia com os tipos de arquivo presentes, que é a definição de
"aplicadas".

O número de carregadas existe, mas **só como texto de console**
(`Scanning N files tracked by git with 1074 Code rules`); o JSON não o traz.
Logo o schema não tem como gravar `rules_loaded`, e o campo passou a chamar-se
`rules_applied` — a consequência já estava definida antes da medição.

O campo continua sendo segunda linha de defesa, agora com outra pergunta:
`rules_applied` ≤ `rules_total` é a relação verdadeira, e **só a violação do
limite** é sinal — significaria que o config em uso não é o pack vendorizado.
Desigualdade estrita é o caso comum e não se reporta, sob pena de afogar o
relatório. A integridade do pack dentro do container continua garantida pelas
duas comparações de sha256, que são fatais e são a primeira linha.

Consequência para o `.time.rules[]` ausente: continua sendo **falha** do CVE,
não `rules_applied` nulo. Sem o campo não há sequer o limite superior.

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
| exit 137 lido como memória | código de encerramento tomado por assinatura de OOM | `docker stop` envia `SIGKILL`; a assinatura é compatível com a causa, mas não a estabelece |
| ρ ≈ 0,2 entre arquivos extraídos e duração do CodeQL | duas séries pareadas **por ordem de aparição** em documento que não declarava a correspondência | o pareamento correto, computado das fontes versionadas, é outro; o valor calculado era sobre pares errados |

A verificação por regex sobre formato estruturado falha por causas
**independentes** — ordem de campos e profundidade de aninhamento —, então
descartar uma não garante a ausência da outra.

Daí: **toda contagem que vá para a monografia sai de parser do formato**, e
**divergência entre dois métodos é reconciliada antes de qualquer dos
números ser aceito**, ainda que a conclusão sobreviva à reconciliação — como
sobreviveu nos três primeiros casos.

O quarto é de natureza distinta: não é contagem, é **atribuição de causa**.
Nos três primeiros o método correto é o parser do formato, ou o comando que
realiza de fato a operação em vez do que apenas casa padrão. No quarto não há
parser que sirva — o método correto é **corroborar por evidência independente
antes de atribuir**, porque a assinatura é compatível com a causa e não a
estabelece.

O quinto é de terceira natureza: não é contagem nem atribuição de causa, é
**cruzamento**. O objeto estava certo e os dados eram reais, mas a
correspondência entre duas séries foi **inferida pela ordem de aparição** em
vez de lida da fonte. O erro é invisível dentro do cálculo — produz um número
plausível — e só aparece ao reconstruir o pareamento por outro caminho.

**O agravante, e a prova.** A correspondência estava disponível, chaveada por
CVE, em duas fontes versionadas do próprio repositório:
`logs/execution-log-codeql.csv`, com `duracao_segundos` por CVE, e o campo
`codeql_inventario` de `logs/normalize-report-codeql.json`, com
`{cve, notificacao, artifacts_depurado, bate}`. Não foram consultadas. O
defeito não foi de indisponibilidade do dado, e sim de não ter procurado a
fonte que o declara.

Computado dessas fontes, o pareamento correto dos quatro CVEs da Fase E é:

| CVE | duração | arquivos extraídos |
|---|---:|---:|
| `CVE-2017-16042` | 63 s | 3 |
| `CVE-2018-14041` | 78 s | 126 |
| `CVE-2018-14040` | 127 s | 174 |
| `CVE-2019-10744` | 146 s | 58 |

A ordem das duas séries difere porque o log inclui o `CVE-2016-1000229`, que
saiu `ERRO_FETCH` com duração 0 e não gera inventário. Parear por posição
desloca tudo a partir daí e troca os dois CVEs do bootstrap entre si — que foi
exatamente o erro cometido.

**Nenhum coeficiente de correlação é calculado sobre esses quatro pontos.**
Quatro pontos não permitem prever; o registro existe para tornar a
correspondência explícita, não para relacionar as grandezas.

O padrão reincidiu sob outra forma, entre documentos: presumiu-se que certa
passagem constasse dos três documentos do projeto por figurar em dois, sem
conferir a terceira ocorrência. E uma terceira vez, sobre a campanha DAST:
este arquivo remetia a correspondência entre relatório e modo de varredura a
um README que **nunca existiu em commit algum** — a lacuna foi fechada na Fase
F-1, com o README escrito a partir de contagem sobre os próprios relatórios.

Daí, geral e simétrico: **correspondência não declarada é conferida antes de
ser usada, trate-se de séries, de listas ou de documentos.** Não estando
explícita, o primeiro passo é torná-la explícita na fonte, nunca estimá-la
pela ordem. Todo relatório que produza duas séries sobre os mesmos itens deve
**chavear ambas pelo identificador do item** — aqui, o CVE. E remissão a
documento é conferida quanto à existência do documento.

**Generalização dos episódios, e não um episódio a mais.** Resultado vazio ou
nulo exige distinguir **"não há"** de **"não perguntei"**. Verificação que
retorna zero é aceita apenas quando o método foi exercido contra caso
conhecidamente positivo, ou quando o stderr foi lido. Padrão que não casa,
pathspec inválido e argumento tomado por opção produzem zero indistinguível
de ausência.

Quatro ocorrências registradas, todas com resultado falso plausível:
`git ls-files 'results/*/treated/'`, cujo curinga com barra final não casa
nada, sugerindo ausência de arquivos que existiam; teste de padrão cujo
argumento começava com `-`, lido como opção, com o stderr suprimido; a
divergência de contagem de regras já registrada acima; e a varredura de
segredo da Fase F, que não cobria webhook do Slack e cuja ausência de achado
só era afirmável **nas formas procuradas** — o scanner do GitHub, com outro
repertório, detectou uma forma que ela não procurava.

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

**Confrontada campo a campo contra saída real em 10/09/2026** (Fase E, lote
`cves-sast-teste`, 4 CVEs por ferramenta, 285 achados). As linhas abaixo
marcadas com ✓ foram confirmadas; as divergências encontradas estão logo
após a tabela. Antes disso a tabela vinha da documentação e da campanha
preliminar, e era a origem das fixtures — ver a ameaça à validade
correspondente.

Confirmado sem ressalva: **os 285 achados das três ferramentas saíram com
caminho relativo e limpo; nenhum exigiu transformação.** É a propriedade de
que todo o cruzamento depende.

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| Formato | SARIF 2.1.0 | JSON próprio | SARIF 2.1.0 |
| CWE | `tool.driver.rules[].properties.tags[]`, prefixo `external/cwe/` | `results[].extra.metadata.cwe` | `tool.driver.rules[].properties.cwe[]` |
| Formato do CWE | `external/cwe/cwe-079`, minúsculo | `"CWE-829: descrição"` | `"CWE-94"`, padding inconsistente |
| Caminho | `results[].locations[0].physicalLocation.artifactLocation.uri` | `results[].path` | igual ao CodeQL |
| Linhas | `region.startLine`; `endLine` ausente em 96,7% (100% na amostra da Fase E) ✓ | `start.line` / `end.line`, sempre ambos ✓ | `region.startLine` / `endLine`, sempre ambos ✓ |
| Severidade | apenas na regra (`defaultConfiguration.level`) — exige join ✓ (`level` ausente em **104 de 104** achados) | `results[].extra.severity` ✓ | `results[].level` ✓ |
| Valores | `error` / `warning` / `note` ✓ | `ERROR` / `WARNING` / `INFO` / `MEDIUM` ✓ | `error` / `warning` / `note` ✓ |
| Regra | `results[].ruleId` ✓ | `results[].check_id` ✓, **sem prefixo** de diretório | `results[].ruleId` ✓ |
| Versão | `tool.driver.semanticVersion` ✓ | `.version` no topo ✓ | `tool.driver.semanticVersion` ✓ |
| Data da análise | **`invocations[0].endTimeUtc` NÃO existe** → cai no mtime | não tem carimbo ✓ → mtime | `automationDetails.id` ✓ |
| Inventário de arquivos | **existe**: `runs[0].artifacts[]` e `toolExecutionNotifications` | `paths.scanned[]` ✓ | `coverage[]` **agregada por linguagem**, sem caminhos |
| Notificações | `toolExecutionNotifications` presente, sempre `level: "none"` | não emite ✓ | **não emite** (`invocations` ausente) |

### Divergências encontradas na confrontação da Fase E

**CodeQL — `invocations[0].endTimeUtc` não existe.** O `invocations[0]` real
traz **apenas** `executionSuccessful` e `toolExecutionNotifications`. Os
quatro CVEs caíram em `analysis_date_source: "file_mtime"`, e o relatório os
listou em `analysis_date_fallback_mtime` — o campo existe justamente para
que isso apareça em vez de passar por carimbo da ferramenta.

**CodeQL — o SARIF TRAZ inventário de arquivos varridos.** Em duas formas:
`runs[0].artifacts[]`, com `uri` relativo e `uriBaseId` `%SRCROOT%`; e
`toolExecutionNotifications` com descritor
`js/diagnostics/successfully-extracted-files`, uma entrada por arquivo
extraído. A afirmação contrária, que sustentava `gt_file_scanned: null` no
CodeQL, é **falsa como fato**.
**Encaminhado:** desde o schema 1.3 o CodeQL **decide**, pela notificação
`js/diagnostics/successfully-extracted-files`; `artifacts[]` ficou descartado
como fonte. Ver o campo `gt_file_scanned` na seção do schema.

**CodeQL — `versionControlProvenance` ausente.** Não há registro do commit
analisado dentro do próprio raw; o log de execução segue sendo a única
evidência, e por isso é versionado.

**Snyk — `coverage[]` é agregada por linguagem**, na forma
`{files, isSupported, lang, type}` — exatamente quatro chaves, e `files` é
**sempre contagem**, nunca lista de caminhos (11 entradas em 4 raws, todas
numéricas). Não decide sobre um arquivo, e `gt_file_scanned` fica `null` nos
223.

Traz, porém, entradas `type: "FAILED_PARSING"` com a contagem de arquivos que
a ferramenta não conseguiu ler. **Desde o schema 1.2 elas são promovidas a
`tool_diagnostics.errors`**, e o `details` declara que a contagem *não
discrimina caminhos* — sem essa declaração, quem lê `errors: 8` suporia saber
quais arquivos. Arquivo cuja análise falhou não produz achado, e o resultado é
indistinguível de análise limpa: é o sinal que o `tool_diagnostics` existe
para capturar, e deixá-lo só em `metadata.coverage` era preservá-lo onde
ninguém procura.

Corolário defensivo: ao procurar inventário de caminhos na `coverage[]`, o
normalizador **ignora entradas não suportadas**. Hoje o ramo é inalcançável,
porque `files` é contagem; se o Snyk passar a enumerar caminhos, um arquivo
listado sob `FAILED_PARSING` seria contado como varrido e `gt_file_scanned`
sairia `true` para arquivo que a ferramenta não conseguiu ler.

**Snyk — varredura sem achados emite `"results": []`**, chave presente e
lista vazia. Era a fronteira aberta de maior risco da fase; está fechada, e
a guarda de raw ilegível fica como está.

**Semgrep — `paths.skipped` não existe** sem `--verbose`: `.paths` traz
somente `scanned`. `tool_diagnostics.skipped_paths` sai `null`, que é o
comportamento previsto para campo ausente.

**Semgrep — `errors[].type` muda de tipo**, pela mesma razão que
`extra.metadata.cwe`: cadeia nua numa minoria (`"Other syntax error"`) e
**união etiquetada** na maioria — `["PartialParsing", [{path, start, end}]]`.
Só a etiqueta interessa ao diagnóstico.

**Todas — `level: "none"` nunca aparece em `results[]`.** Aparece só nas
`toolExecutionNotifications` do CodeQL, que não são achados. A tabela de
severidade não é afetada.

Pontos de atenção do normalizador:

- **`errors[].type` do Semgrep também muda de tipo** — cadeia nua ou união
  etiquetada `[etiqueta, carga]`. Mesma armadilha do `cwe` abaixo, em outro
  campo: os dois exigem despacho por tipo, nunca acesso direto.
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
  `@name` de consulta do CodeQL em **73,1%** dos casos. A modalidade por
  primário acrescenta uma segunda camada da mesma proveniência; a
  modalidade por conjunto não depende da escolha e serve de contraprova.
- **Circularidade da etiqueta, MEDIDA e não só declarada.** A ameaça de
  assimetria acima deixou de ser apenas argumentada: a partição do
  denominador pela proveniência da etiqueta está apurada e registrada na
  seção "Circularidade da proveniência". O que a apuração **não** resolve é
  a confusão com o tipo de vulnerabilidade, porque os grupos diferem em
  composição de CWE; e o controle interno dos níveis 1 e 3 é o que permite
  separar as duas coisas. A leitura fica ao texto.
- **Ordem não determinística do pack.** O sha256 não permite a terceiro
  verificar se o pack vendorizado corresponde ao que o registry serve
  noutro momento. Mitigado por `rules_id_sha256`; resta que o conjunto é
  verificável por identidade de regras, não de arquivo.
- ~~**Verificação do CodeQL em versão adjacente.**~~ **Fechada na Fase E:**
  o ensaio original rodou na 2.26.4, mas o lote de teste rodou na **2.25.4
  empregada**, com `semanticVersion` `2.25.4` no próprio SARIF. Deixou de ser
  ameaça.
- **O schema de normalização foi construído contra a documentação das
  saídas, não contra saída real.** As fixtures sintéticas derivam da tabela
  "Formato das saídas das ferramentas" acima, que por sua vez vinha da
  documentação e das saídas da campanha preliminar. Erro nessa tabela é
  reproduzido pela fixture, e a asserção passa: a suíte prova conformidade
  ao formato **suposto**, não que o suposto corresponda ao emitido.
  **Atenuado, não eliminado, pela Fase E (10/09/2026):** a tabela foi
  confrontada campo a campo contra saída real e seis divergências
  apareceram, todas registradas acima; as fixtures divergentes foram
  corrigidas contra o real, incluindo a do CodeQL, que modelava a
  notificação como **falha** de extração quando a saída real é de extração
  bem-sucedida.
- **A decisão do `gt_file_scanned` do CodeQL repousa em 4 CVEs.** O
  inventário por notificação foi validado contra saída real em quatro casos,
  incluindo o que motiva o campo — `js/collapse.js` extraído e sem achado. Não
  se sabe se a notificação tem teto em repositório grande; a conferência
  notificação × `artifacts[]` depurado bateu em 4 de 4, e vai no relatório de
  cada campanha para que 223 CVEs digam mais do que 4.
- **A amostra da confrontação são 4 CVEs e 4 repositórios, todos
  JavaScript.** Nenhum TypeScript no laço, nenhum monorepo, e nenhum
  `SEM_ARQUIVO_ANALISAVEL` — o único status do log que a Fase E não
  exercitou. O extrator de TypeScript foi fechado por **sondagem dedicada**,
  fora do laço (`database create --build-mode=none` sobre um `.ts`, extração
  e exit 0 em `node:24`), o que é evidência de que o extrator funciona, não
  de que o laço o atravessa. Forma que não ocorreu nesses quatro continua
  descrita por suposição, e é o que o ensaio de fumaça no Actions precisa
  cobrir

## O que NÃO fazer

- Não analisar HEAD, em campanha alguma. `PostPatchCommit` só na segunda
  campanha, de reconhecimento da correção — nunca na campanha de detecção
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
  ali é interna à ferramenta, ao contrário do repositório que não existe. Vale
  igualmente para o `false` do CodeQL, que significa "não extraído para o
  banco de dados", e não para o `null` do Snyk
- **Não usar `runs[0].artifacts[]` como inventário de arquivos varridos do
  CodeQL** — é superconjunto contaminado por outras linguagens, e afirmaria
  varredura que não houve. A fonte é a notificação
  `js/diagnostics/successfully-extracted-files`
- **Não tratar ausência da notificação de extraídos como `false`** — é `null`,
  pelo mesmo princípio que separa `unknown` de `unresolved`
- **Não sondar disponibilidade de repositório com credencial do hospedeiro** —
  mede o acesso do operador, não o anônimo que a campanha terá
- Não gravar fixtures em `results/*/raw/`
- **Não usar tag flutuante de imagem base nos Dockerfiles** — `FROM
  python:3.12-slim` e congêneres admitem conteúdo distinto entre construções.
  Fixar por digest (`FROM <imagem>@sha256:…`), pelo mesmo motivo que o CLI do
  Snyk vem de URL versionada. O build único da campanha garante que os oito
  lotes usem a mesma imagem; a fixação das bases é o que permite reconstruí-la
  depois
- **Não encadear com `&&` uma guarda que CONTA antes de um comando que
  ESCREVE** — `grep -c` sai 1 com zero casamentos, que é justamente o resultado
  desejado numa guarda, e a cadeia quebra **antes** do comando seguinte.
  Ocorrido em H4 (16/09/2026): a guarda "nenhum raw no índice" imprimiu `0`, o
  `git commit` encadeado depois dela **nunca rodou**, e o `echo "$?"` da linha
  seguinte reportou o código da cadeia quebrada, não o de um commit.
  Sintoma observável: o push responde `Everything up-to-date` e o `HEAD` não se
  move. Contar com `awk` ou `wc -l`, que não falham sem casamento, e conferir
  **explicitamente** o código do comando que importa, em vez de confiar na
  cadeia. É a regra geral de contagem — zero indistinguível de falha — num
  contexto novo: guarda antes de escrita
