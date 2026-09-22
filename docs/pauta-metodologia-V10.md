# Pauta da metodologia V10 — o que muda em relação à V9

Levantamento feito em 21/09/2026, com a V9 aberta ao lado e seção a seção.
Tudo o que está aqui foi medido ou decidido entre 14 e 20/09/2026, e está
registrado no `CLAUDE.md` e nas saídas versionadas do repositório. Nada
aqui é hipótese sobre o que a V10 deveria dizer: é o que os dados passaram a
sustentar.

A V10 será **documento de método e resultados**, cobrindo as campanhas SAST e
DAST (ver a seção seguinte). Ela **não pode ser fechada agora**: falta a
modalidade DAST inteira, que reescreve as seções 6 e 7, produz a seção de
resultados DAST e habilita a análise comparativa. Esta pauta serve para que
nada da modalidade estática se perca até lá.

**Convenção:** cada item traz a seção da V9 afetada e a natureza da mudança —
**ALTERAR** (o texto da V9 fica incorreto), **ACRESCENTAR** (conteúdo novo),
**REMOVER** (pendência resolvida ou afirmação superada) ou **MANTER** (parece
que muda, mas não muda — registrado para evitar edição indevida).

---

## Natureza da V10: documento de método e resultados — DECIDIDO

**Decidido em 21/09/2026.** A V10 deixa de ser apenas documento de método e
passa a ser **documento de método e resultados**. Ela registra o protocolo,
como as versões anteriores, e acrescenta os **resultados das campanhas SAST e
DAST**.

É a mudança de maior alcance desta versão, porque altera a natureza do
documento e não só o seu conteúdo. A V9 afirma, na nota de abertura, que
"nenhum resultado de detecção é apresentado aqui. Este é um documento de
método" — frase que a V10 **revoga expressamente**.

### O que muda em consequência

**A "Nota sobre o estado deste documento" é reescrita.** Ela deve dizer:

- que a V10 é documento de método **e** de resultados, e que isso a distingue
  de todas as versões anteriores;
- que a campanha SAST foi executada em 16 e 17/09/2026, precedida do ensaio de
  fumaça de 16/09, sobre os 223 CVEs, nas três ferramentas;
- que a campanha DAST foi executada em 24/07/2026, como a V9 já registra, e
  que seus resultados passam a ser apresentados;
- que os resultados de detecção dos dois ensaios — o local e o de fumaça —
  **continuam descartados**, e que os resultados apresentados são os da
  campanha;
- que todo número de resultado sai de artefato versionado e é reproduzível a
  partir do repositório.

**A estrutura do documento ganha seções de resultados.** Proposta:

| Seção | Conteúdo |
|---|---|
| 1 a 9 | método, como na V9, com as alterações desta pauta |
| **Resultados SAST** | nova — o que está nas seções 4 e 5 desta pauta |
| **Resultados DAST** | nova — a preencher quando o pipeline DAST existir |
| **Análise comparativa** | nova — SAST × DAST pela taxonomia comum da §7.1 |
| Ameaças à validade | a §9 da V9, deslocada para depois dos resultados, porque passa a qualificar números e não só o desenho |
| Registro de decisões e pendências | as §10 e §11 da V9 |

Deslocar as ameaças à validade para depois dos resultados é sugestão, não
obrigação — mas é a ordem convencional num texto que apresenta números, e a
§9 da V9 já contém ameaças que só fazem sentido diante dos resultados (a
circularidade, por exemplo).

**A separação entre método e resultado continua sendo exigência, agora dentro
do mesmo documento.** A V9 extrai boa parte da sua credibilidade de fixar
critérios antes de haver números. Na V10 isso precisa ficar visível: as
seções de método descrevem o que foi decidido e quando, as de resultado
apresentam o que foi medido, e nenhuma seção de método é reescrita à luz do
resultado sem registro da alteração. O documento de critérios do cruzamento,
datado e versionado antes do primeiro número, é a evidência dessa ordem e deve
ser citado.

**Consequência de prazo.** A V10 só fica completa depois do pipeline DAST, dos
seus resultados e da análise comparativa. A parte SAST pode ser redigida
antes, mas a versão não se fecha sem as três seções de resultado.

## 0. Antes de tudo: o que a V9 já tinha certo

Três pontos que pareciam desatualizados e **não estão**. Não editar.

- **§2.2.2 — proveniência em 73,1%.** A V9 já fixa a âncora no último estado
  do catálogo anterior ao release (`ec573b51`) e já registra os 185 do estado
  posterior como sensibilidade. O número errado (83%) estava no `CLAUDE.md`, e
  foi corrigido lá. **MANTER.**
- **§7.1 — CWE como pivô único entre as fontes.** A unidade comum entre SAST e
  DAST já está decidida na V9. **MANTER.**
- **§1.3 e §9.4 — benchmarks distintos e alvos disjuntos.** A justificativa de
  usar conjuntos diferentes, e a declaração de que as duas famílias não
  compartilham alvo, já estão escritas. **MANTER.**

> O relatório de andamento em PDF foi descartado e não será usado.

---

## 1. A mudança central: a matriz de confusão completa

**Esta seção foi reescrita em 21/09/2026.** A versão anterior desta pauta
afirmava que FP e VN eram incomputáveis com este benchmark e que a V10
retiraria precisão e F1. **Estava errada.** O documento de critérios recebe
emenda datada com a mesma correção.

**Como o erro aconteceu — e não foi falta de informação.** O critério da versão
corrigida **já estava registrado** no `CLAUDE.md` desde 28/08/2026 (commit
`342194b`), citando o `docs/benchmark-CVEs.md` do benchmark: a ferramenta ideal
produz ao menos um alerta relevante no commit anterior à correção e nenhum no
posterior. A §1 dos critérios, escrita em 18/09, **não relacionou esse critério
ao falso positivo**. O README do benchmark, que dá a ele o nome de taxa de
falso positivo, não tinha sido lido. O erro de método é esse: a informação
estava no repositório e não foi ligada à decisão.

### O que o benchmark diz, e o que o estudo constrói a partir disso

Para cada CVE, o README do benchmark faz duas perguntas: se a ferramenta detecta
a vulnerabilidade ou produz um falso negativo; e se, rodando sobre o código
corrigido, reconhece a correção ou produz um falso positivo. O
`docs/benchmark-CVEs.md` garante que a versão corrigida não contém a
vulnerabilidade.

**A tabela abaixo é construção do estudo, não o que o benchmark calcula.** É a
leitura que o estudo faz das duas perguntas e daquela garantia: o rótulo
negativo é a versão corrigida, **no ponto da falha**.

| Versão analisada | No ponto da falha | Alerta ali | Resultado |
|---|---|---|---|
| antes da correção | a falha existe | sim | VP |
| antes da correção | a falha existe | não | FN |
| depois da correção | a falha foi removida | sim | **FP** |
| depois da correção | a falha foi removida | não | **VN** |

Universo definido: um ponto vulnerável e um ponto corrigido por CVE.

### Como a ferramenta de relatório do próprio benchmark calcula — é diferente

Lido no código de relatório do benchmark em 21/09/2026:

- **só entram as regras que, na versão vulnerável, alertaram exatamente no
  (arquivo, linha) da falha** — por igualdade, não por sobreposição;
- a correção conta como **reconhecida** quando ao menos uma dessas regras tem
  **menos alertas no repositório inteiro** na versão corrigida — o benchmark não
  tenta localizar "o mesmo ponto";
- **se nenhuma regra acertou na versão vulnerável, o resultado é *não
  computável*.** O benchmark não atribui FP nem VN a um CVE que a ferramenta não
  detectou, e **não monta a matriz de quatro células**.

A diferença é de desenho, não de detalhe. O benchmark avalia o reconhecimento da
correção **condicionado à detecção**; a tabela do estudo atribui FP ou VN a
**todos** os CVEs. **A escolha entre as duas leituras — ou apurar as duas, como
foi feito com os níveis — é a primeira decisão do desenho da segunda
campanha**, e fica registrada como tal, sem ser fixada aqui.

Um ponto a favor da leitura do estudo sobre o restante do código: o relatório em
arquivo do benchmark classifica alerta fora da falha como **desconhecido**, não
como falso positivo.

### §7.3 Definições operacionais — ALTERAR

A V9 define os quatro quadrantes, mas com uma definição de FP que **não é a do
benchmark**: "a ferramenta reporta um CWE em um arquivo em que o ground truth
não o registra". Essa definição trata como erro qualquer alerta fora do
gabarito, e isso **não se sustenta** — o benchmark não afirma que o resto do
código está limpo, e um alerta ali pode ser vulnerabilidade real não
catalogada.

A V10 substitui pela **definição adotada pelo estudo, a partir das duas
perguntas do README e da garantia do `docs/benchmark-CVEs.md`**: FP e VN medidos
na versão corrigida. Se a medida é no ponto da falha, como na tabela acima, ou
condicionada à detecção, como na ferramenta do benchmark, é a decisão em aberto
da segunda campanha.

**O que continua não classificável:** alerta fora do ponto da falha, noutro
arquivo ou noutro trecho do mesmo arquivo, nas duas versões. De 77,8% a 96,9%
dos alertas caem fora do arquivo do ground truth, e esses seguem sem
classificação.

### §7.7 Métricas — ALTERAR

A V9 diz: "Apuram-se precisão, recall e F1-score, por ferramenta e por CWE".

**As três ficam**, mas com escopo declarado: são calculadas sobre o universo
do benchmark — um ponto vulnerável e um corrigido por CVE —, e **não** sobre
todos os alertas da ferramenta. Acrescenta-se a **especificidade**, que o VN
torna calculável. A redação precisa dizer isso explicitamente, porque
"precisão" sem qualificação sugere a leitura mais ampla.

Mantém-se a caracterização de **volume de alertas** como descritiva, nunca
como medida de qualidade: 3.230 no CodeQL, 11.768 no Semgrep, 3.666 no Snyk
Code, com a concentração do Semgrep (dez CVEs somam 77% nos seis últimos
lotes; o `CVE-2018-20801` sozinho soma 5.850).

### §11 "Universo de referência do verdadeiro negativo" — RESOLVIDA

A pendência se resolve pela versão corrigida: **o universo do VN é a versão
corrigida de cada CVE**, um por CVE — no ponto da falha, na leitura do estudo,
ou restrito aos CVEs detectados, na leitura do benchmark. Mover para as pendências
resolvidas, com a razão.

### A segunda campanha — ACRESCENTAR, e é a maior mudança desta versão

A primeira campanha rodou **só antes da correção**. Ela dá a metade VP/FN da
matriz, e esses resultados **não mudam**. FP e VN exigem uma **segunda
campanha**, sobre o commit da correção (`PostPatchCommit`), com as mesmas
imagens e o mesmo pipeline.

Decisões a fixar **antes** dos resultados dela, como na primeira:

- **Primeira e mais importante: matriz de quatro células ou reconhecimento
  condicionado à detecção** (ver acima), ou as duas.
- **Como localizar o ponto da falha depois da correção.** A correção muda o
  arquivo, e a linha pode mudar de número. Consultar antes como a ferramenta
  de relatório do próprio benchmark faz esse casamento.
- **Quais níveis se aplicam.** O nível 1 (arquivo certo) tende a disparar na
  versão corrigida por causa de outros alertas no mesmo arquivo; o FP útil
  deve vir dos níveis que usam a linha.
- **Quantos `PostPatchCommit` são utilizáveis.** Dois vêm mal formados, e o
  gerador os rejeitaria: `CVE-2017-18352` (truncado) e `CVE-2018-11093`
  (abreviado). O `CLAUDE.md` os registrava como inofensivos porque o pipeline
  usava só o commit anterior; passam a importar. Resolver — expandindo o SHA pelo
  próprio repositório, se o prefixo for único, ou excluindo com motivo
  declarado — no desenho da segunda campanha. Conferir também se os demais
  existem nos repositórios.
- **O denominador da versão corrigida**, que pode diferir de 220.

**A regra crítica do `CLAUDE.md` muda.** Ela dizia "nunca analisar HEAD nem
`PostPatchCommit`". Passa a ser: **HEAD, nunca** — foi o que invalidou a
campanha preliminar —; **`PostPatchCommit`, só na segunda campanha**, de
reconhecimento da correção, e nunca na de detecção.

**A campanha de julho de 2026, que rodou no HEAD, não substitui esta.** O HEAD
vem depois da correção, mas difere do código vulnerável por anos de mudanças,
e não só pelo conserto — o que desfaz a comparação controlada que o benchmark
propõe. Além disso, aquela campanha foi invalidada por defeitos de coleta.

**Snyk Code:** a segunda campanha soma 216 testes à investigação do 403 (seção
7c). Ver ali a questão da cota e a da conta.

## 2. Os níveis de acerto

### §7.2 Unidade da matriz de confusão — ALTERAR

A V9 justifica **não descer ao nível da linha** com dois argumentos: a
definição do TN (que muda de natureza: deixa de ser o universo de todas as linhas, que a V9 rejeitava com razão, e passa a ser um ponto por CVE, na versão corrigida) e a divergência de convenção de reporte
entre ferramentas (que foi medida e é pequena).

A V10 adota **cinco níveis de acerto**, todos apurados na mesma passada:

| Nível | Critério |
|---|---|
| 0 | achado em qualquer lugar da árvore analisada |
| 1 | achado no arquivo do ground truth |
| 2 | nível 1 e o CWE casa |
| 3 | nível 1 e a linha casa |
| 4 | nível 3 e o CWE casa |

Nos níveis 2, 3 e 4, **o mesmo achado** tem de satisfazer todas as
condições.

A unidade (CWE, arquivo) permanece — continua degenerada e equivalente a
(CWE, CVE), como a V9 já registra. O que muda é que a linha deixa de ser
métrica auxiliar e passa a definir dois níveis.

O argumento de convenção de reporte **não se perde, muda de função**: ele
motiva o critério de sobreposição (item seguinte) em vez de motivar a recusa
da linha.

Registrar que os critérios foram fixados em documento versionado
(`docs/criterios-cruzamento.md`) **antes** de qualquer número de detecção, e
que o histórico do repositório comprova a ordem.

### §7.7 Precisão de localização (as faixas) — ALTERAR

A V9 prevê faixas descritivas: exata, próxima (até 5), aproximada (até 10),
apenas arquivo.

A V10 substitui por **sobreposição do intervalo do achado com alguma linha do
ground truth, sem banda de tolerância**. `line_end` nulo vale como
`[line_start, line_start]`.

A decisão foi tomada por medição: o ganho da sobreposição sobre o casamento
exato é de **5, 1 e 13 achados** (CodeQL, Semgrep, Snyk Code), sobre 717, 360
e 199 achados no arquivo do ground truth. Dezesseis dos 19 ganhos vêm de
regras de limitação de taxa (`js/missing-rate-limiting` no CodeQL,
`NoRateLimitingForExpensiveWebOperation` no Snyk Code), que reportam a função
inteira.

**Decisão a tomar na redação:** manter as faixas da V9 como caracterização
descritiva da distância, ao lado do critério de acerto? Os dados existem — a
distância mediana ao ground truth, dentro do arquivo certo, é de 71, 113 e 64
linhas, e mais de 35% dos achados estão a mais de 100 linhas. É informação
útil, mas não pode ser confundida com critério de acerto.

A regra da V9 para CVEs com várias linhas de referência — menor divergência
contra qualquer delas — **se mantém** e está implementada.

### §7.4 Dupla apuração — ALTERAR (nomenclatura)

As duas modalidades da V9 sobrevivem, com nome novo:

| V9 | V10 |
|---|---|
| Correspondência por conjunto | variante **generosa** — o CWE do achado intersecta `gt_cwes` |
| Correspondência por CWE primário | variante **estrita** — o achado contém `gt_cwe_primary` |

Elas passam a qualificar os níveis 2 e 4, em vez de serem as duas únicas
apurações.

**Achado a registrar:** as duas variantes quase não divergem — 126/124 no
CodeQL, 48/46 no Semgrep; só o Snyk Code mostra diferença (16/9). A V9
apresenta a diferença entre elas como "resultado de interesse próprio"; ela
existe, mas é pequena.

---

## 3. O denominador

### §7.4 "CVEs cujo repositório não está disponível" — ALTERAR

A V9 registra o denominador como **221**, com uma baixa. São **duas**, e o
denominador é **220**.

| Grandeza | Valor |
|---|---:|
| CVEs no conjunto | 223 |
| Pares (CWE, arquivo) afirmados | 222 |
| **Pares no denominador** | **220** |
| CVEs com saída bruta no CodeQL e no Semgrep | 221 |
| CVEs com saída bruta no Snyk Code | 216 |

As duas baixas por indisponibilidade de código:

- `CVE-2016-1000229` — repositório `linxiaowu66/swagger-ui` inexistente,
  medido no lote `aa` em 16/09/2026;
- `CVE-2018-8035` — **novo**: o commit `4c20c4fc…` que o benchmark declara
  não existe em `apache/uima-ducc`. Fetch raso recusado
  (`upload-pack: not our ref`), clone completo bem-sucedido, checkout
  recusado (`reference is not a tree`). Medido no lote `ad` em 17/09/2026.

Nota de redação: a V9 trata a indisponibilidade como **de repositório**. A
segunda baixa é de **commit** num repositório que existe. A categoria precisa
ser generalizada para "indisponibilidade de código".

### §4.3 / §7.4 Sondagem de disponibilidade antes da campanha — VERIFICAR

**Ponto sério.** A V9 exige que a sondagem de disponibilidade dos
repositórios seja **refeita imediatamente antes da campanha** (§7.4, §9.2), e
que o denominador empregado seja o apurado nela. A última sondagem registrada
é de **06/09/2026**; a campanha rodou em 16–17/09.

Conferir se houve sondagem entre essas datas. Se não houve, a V10 precisa
declarar que o protocolo foi cumprido de outra forma — a própria campanha
mediu a disponibilidade, CVE a CVE, e é dela que sai o denominador de 220 —
em vez de afirmar uma sondagem que não ocorreu.

Nota: a sondagem de repositório **não teria detectado** o `CVE-2018-8035`, que
é commit inexistente em repositório existente. Isso fortalece o argumento de
que a medição da própria campanha é a fonte correta do denominador.

### §2.2.3 Defeitos conhecidos — ACRESCENTAR

O `CVE-2018-8035` entra ao lado do `CVE-2016-1000229`.

### §9.2 Disponibilidade dos repositórios e dos commits — ALTERAR

A V9 diz que a sondagem obteve 185 de 186 repositórios acessíveis. Continua
certo para repositórios. Acrescentar que a disponibilidade de **commit**
também degenerou, e que isso **não é detectável por sondagem de
repositório** — só se manifesta no checkout.

### §5.2 / §7.4 Os cinco `SEM_ARQUIVO_ANALISAVEL` — ACRESCENTAR

O ramo previsto na V9 (exit 3 do Snyk Code) **ocorreu**, cinco vezes, e a
correlação com os arquivos sem extensão é exata:

`CVE-2018-16479`, `CVE-2018-16480`, `CVE-2018-3731`, `CVE-2018-3747`,
`CVE-2019-5423` — arquivos `bin/http-live` e `bin/public`.

Permanecem no denominador e contam como não-detecção do Snyk Code, pela regra
que a V9 já fixa. O que muda é que deixa de ser previsão e vira ocorrência.

---

## 4. Resultado — seção nova

A V9 não tem resultados. A V10 precisa de uma seção de resultados da
modalidade estática, com a matriz dos sete níveis:

| Nível | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| 0 | 190 | 183 | 132 |
| 1 | 140 | 98 | 45 |
| 2 generosa | 126 | 48 | 16 |
| 2 estrita | 124 | 46 | 9 |
| 3 | 101 | 25 | 22 |
| 4 generosa | 95 | 20 | 10 |
| 4 estrita | 94 | 20 | 6 |

Sobre 220 (219 nas estritas, descontado o `CVE-2018-16472` de primário
indefinido).

**Esta tabela é a metade VP/FN da matriz.** A metade FP/VN vem da segunda
campanha (seção 1). A seção de resultados da V10 precisa apresentar as duas
juntas.

Pontos que o texto precisa cobrir:

- **A ordenação é a mesma nos sete níveis.** A conclusão não depende do
  critério escolhido.
- **Os níveis não formam hierarquia linear.** O Snyk Code tem nível 3 (22)
  maior que nível 2 generosa (16).
- **Nível 1 → nível 3**, perda por ferramenta: CodeQL 39 de 140 (28%),
  Semgrep 73 de 98 (74%), Snyk Code 23 de 45 (51%).
- **Nível 1 → nível 2 generosa**: o CodeQL mantém 90%, o Semgrep menos da
  metade, o Snyk Code um terço.
- A leitura de mecanismo (fluxo de dados contra casamento de padrão) é
  **interpretação e não medição**, e precisa ser declarada assim.

A V9 promete métricas **por CWE** (§7.7). **Não foram computadas.** Ver seção
8 desta pauta.

Duração por CVE na campanha, a incluir nos resultados:

| Ferramenta | mediana | máximo | q1–q3 | soma |
|---|---:|---:|---|---:|
| CodeQL | 47 s | 304 s | 43–60 s | 3,63 h |
| Semgrep | 18 s | 202 s | 14–21 s | 1,36 h |
| Snyk Code | 13 s | 135 s | 10–19 s | 1,14 h |

### §1.2 Perguntas de pesquisa — AJUSTAR

A segunda pergunta fala em "desempenho de cada ferramenta quando confrontada
com um conjunto de vulnerabilidades conhecidas". Com a segunda campanha,
**desempenho passa a ser medido pela matriz completa** no universo do
benchmark. A pergunta deve deixar claro o escopo: desempenho sobre os pontos
vulneráveis e corrigidos, não sobre todos os alertas das ferramentas.

---

## 5. Circularidade — ameaça medida

### §9.2 Proveniência e assimetria de comparabilidade — ALTERAR

A V9 declara a ameaça e diz que eventual vantagem do CodeQL "admite, por
construção, explicação alternativa à de superioridade técnica, e assim deve
ser reportada".

A V10 pode dizer mais, porque a ameaça **foi medida**. Partição do
denominador pela proveniência da etiqueta: **161 herdados, 59 não
herdados**. Níveis 1 e 3, que não usam CWE, como controle interno.

Diferença herdado − não herdado, em pontos percentuais:

| Nível | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| 1 (sem CWE) | +17,5 | +12,2 | +14,1 |
| 2 estrita | +21,8 | −1,4 | +5,6 |
| 3 (sem CWE) | +14,1 | +8,6 | +11,3 |
| 4 estrita | +17,0 | +5,5 | +3,8 |

As duas leituras que o texto precisa manter juntas:

1. **A maior parte da diferença entre grupos não é circularidade.** Nos níveis
   sem CWE, o grupo herdado favorece as três ferramentas, inclusive as que não
   geraram etiqueta.
2. **Há sinal de circularidade na diferença das diferenças.** Exigir o CWE
   aumenta a vantagem do CodeQL no grupo herdado e diminui a das outras duas.
   Magnitude de 3 a 4 pontos percentuais.

**O recorte livre de circularidade:** grupo não herdado, nível 3 — CodeQL 21
de 59, Semgrep 3, Snyk Code 1. A vantagem sobrevive onde a circularidade não
opera.

**Limites da apuração, a declarar:**

- composição de CWE quase disjunta entre os grupos (CWE-915 é 23/59 do não
  herdado e zero do herdado; CWE-022 27/2; CWE-078 24/1) — proveniência e tipo
  de vulnerabilidade variam juntos;
- tamanhos desiguais (161/59), sem teste estatístico;
- a partição é pela **`explanation`**, não pela etiqueta de CWE — coincidem em
  163/163 na âncora, mas 6 CVEs do grupo não herdado têm conjunto de 2+ CWEs
  idêntico ao de alguma consulta.

**Os 22 de prototype pollution:** excluídos dos dois grupos, as partições
contra `ec573b51` e `9ff6d68a` produzem tabelas idênticas. **A escolha da
âncora não altera esta análise.** Sobre os 22, o CodeQL acerta o nível 4
estrita em 13, o Semgrep em 1, o Snyk Code em 0.

### §9.2 Viés de seleção do conjunto — MANTER

A apuração de circularidade trata **circularidade de etiqueta**, não **viés de
seleção**. Que vulnerabilidades não detectadas pelo CodeQL estejam
sub-representadas continua sendo limitação declarada e não medida. Não
confundir as duas no texto.

---

## 6. Execução — infraestrutura e protocolo

### §3.1 SAST — GitHub Actions — ALTERAR

A V9 diz: "Cada workflow constrói a imagem Docker da respectiva ferramenta e
executa o container."

**Não é mais assim.** As imagens são construídas **uma vez** por
`build-imagens.yml`, publicadas no GHCR e referenciadas por **digest**. O
workflow de lote (`analise-lote.yml`) só puxa e executa. É isso que garante
que os oito lotes usaram bytes idênticos.

Digests vigentes, do rebuild de 15/09/2026 (execução `34961746566`):

```
ic-security-lab-codeql    @sha256:39950e7ac03b7d7b7a724c742e1c48e9475ed998d58a4734d653188d31afcbec
ic-security-lab-semgrep   @sha256:de71bdfbdf81d495781a4c80052c5f7d128ec9b76eba2304978e08b88ba5d000
ic-security-lab-snyk-code @sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
```

### §4.4 Modelo de execução — ALTERAR

Três trechos ficam superados:

1. **"O limite de análise permanece provisório."** Decidido: **900 s** em
   `TIMEOUT_CREATE`, `TIMEOUT_ANALYZE` e `TIMEOUT_ANALISE`; `TIMEOUT_FETCH`
   300 e `TIMEOUT_CLONE` 900 sem mudança, por falta de dado.

   **A justificativa não é folga sobre o observado, é assimetria da falha.**
   Limite curto demais falha um CVE, nomeado no log, reexecutável por CVE.
   Limite longo demais deixa um item travado consumir o teto do job, mata o
   lote, e a reexecução recomeça do zero.

   Os 900 **nunca foram exercidos**: máximo de 304 s em 223 CVEs. Dizer isso
   é diferente de dizer que a decisão estava certa.

2. **"A projeção de aproximadamente seis horas para oito lotes é piso
   frouxo."** A campanha levou **cerca de 1 h 30** de relógio, com os dois
   primeiros lotes em série e os seis restantes em paralelo.

3. **"será revisto a partir da razão entre as durações dos dois ambientes."**
   A razão foi medida: **o runner é cerca de 30% mais rápido** que o
   hospedeiro local (0,65 a 0,76 em quatro CVEs pareados). A premissa
   implícita da V9 — runner mais lento — estava errada na direção.

Acrescentar:

- os limites passaram a ser **sobrescrevíveis por ambiente**
  (`${VAR-default}`, sem dois-pontos, para que variável vazia pare na guarda
  em vez de cair no default), com guarda fatal `^[1-9][0-9]*$` — o `0`
  desligaria o limite no GNU `timeout` sem erro algum;
- o valor efetivo de cada lote fica registrado na primeira linha do log e é
  conferido contra o pedido;
- a decisão do lote de 30 é **confirmada no escopo restrito**: a projeção
  agregada cabe com folga; o perfil de item que não termina **não foi
  amostrado**.

### §4.6 Conferências do workflow de lote — ACRESCENTAR

Duas conferências novas, que são protocolo e não detalhe de implementação:

- **Pré-voo da imagem.** Antes do lote, o container roda sobre uma lista
  inexistente. Os scripts imprimem os limites efetivos, passam pelas guardas
  de integridade e só então param. Imagem com script errado, imagem obsoleta
  em relação ao descritor, limite inválido e volume não montado viram falha
  em segundos, e não depois do lote inteiro.
- **Portão de lote sem raw.** Lote que não produziu saída bruta alguma falha o
  job, porque nesse caso container, normalizador e conferidor do registro
  saem todos com sucesso. O portão nomeia a condição e **não atribui causa** —
  ele também dispararia num lote todo em `SEM_ARQUIVO_ANALISAVEL`, que é
  resultado e não falha.

### §4.4 O travamento de julho — ACRESCENTAR

O `zeit/next.js`, repositório que consumiu o teto de 6 h em julho de 2026,
foi analisado em **55 s** no CodeQL, com 377 arquivos extraídos, sem
fallback. O modo de falha identificado na V9 — clone completo sem limite —
está fechado.

Ressalva: é o mesmo nome de lote (`ab`) por coincidência da partição, não o
mesmo lote. A comparação é entre execuções de conjuntos diferentes.

### §4.3 A classe prevista pela V9 ocorreu — ACRESCENTAR

A V9 (§4.3) prevê duas coisas que a campanha confirmou, e vale dizê-lo:

- que ficam fora do alcance dos dois mecanismos de obtenção **os commits que
  existam só em referências de pull request, em fork ou em branch removido**;
- que **identificador bem formado porém inexistente** é recusado antes da
  asserção, porque o checkout falha.

O `CVE-2018-8035` é exatamente esse caso: SHA de 40 hexadecimais, bem formado,
ausente do repositório. Fetch raso recusado, clone completo bem-sucedido,
checkout recusado, `ERRO_CHECKOUT`, nenhuma saída bruta. O protocolo tratou o
caso como desenhado.

E a V9 afirma que o servidor aceita fetch raso por SHA fora do branch padrão,
"de modo que o fallback deve ser acionado raramente". Confirmado: os quatro
CVEs do bootstrap cujo commit só é alcançável por `v3-dev` passaram pelo fetch
raso, **sem fallback**.

### §4.3 / §4.6 Fallback de obtenção — ACRESCENTAR

A métrica de vigilância que a V9 institui produziu seu primeiro dado: **2 em
223**, ambos por rc 128 do git, **zero por estouro de limite**. Taxa estável
ao longo dos oito lotes. Os dois casos são as duas baixas por indisponibilidade
de código.

### §4.7 Tabela do diretório pessoal, linha do CodeQL — ALTERAR

A tabela da V9 registra o CodeQL como "Correto" mesmo sem `-e HOME=/tmp`, e
explica que isso é coincidência do identificador do hospedeiro de teste — e
que sob o identificador do runner "a condição se iguala à das outras duas".

**Confirmado no runner**: a escrita genérica em `$HOME` falha na imagem do
CodeQL sem `-e HOME=/tmp`. O comando da própria ferramenta **não foi sondado**
— não se identificou comando do CodeQL que grave em `$HOME` e custe segundos,
e `codeql resolve languages` não discrimina. A linha da tabela precisa dizer
as duas coisas.

**Segundo defeito, das consultas precompiladas.** A V9 registra que ele é
corrigido na construção da imagem e que não se manifesta no runner quando o
identificador coincide com o proprietário dos arquivos. **Não foi medido na
campanha.** A mediana de 47 s por CVE no CodeQL é compatível com ausência de
recompilação integral, mas isso é inferência, não medida — dizer assim.

### §4.7 / §9.1 Defeito do diretório pessoal — ALTERAR

A V9 lista como pendente de verificação no ambiente da campanha. **Medido com
controle nas três imagens**, sob uid 1001:1001: sem `-e HOME=/tmp`, `$HOME`
cai em `/` e a escrita falha; com ele, opera. `whoami` retorna rc 1 nas três —
o uid não está no `/etc/passwd` de nenhuma.

### §9.1 Dependência de serviço externo, frase sobre o Semgrep — ALTERAR

A V9 diz que o Semgrep opera "sem necessidade de rede". Correto, mas
incompleto. Medido com controle positivo: sob `--network=none`, o Semgrep
**completa**, mas leva **~110 s** num arquivo, contra ~13 s de um lote inteiro
com rede. Reproduzido no hospedeiro local (109 s, 113 s) e no runner (112 s).

A afirmação correta é: **opera sem rede, tentando alcançá-la e esperando o
tempo esgotar.** Isso é diferente de "não usa a rede".

### §8 — ACRESCENTAR subseção do ensaio de fumaça

A V9 termina a seção 8 no ensaio local (§8.6). Acrescentar o ensaio de fumaça
no runner (execução `35101790912`, 16/09/2026): composição do lote (sete
CVEs, com as razões de cada item), o que fechou, o que caiu, e o que
continuou aberto. A leitura está em `CLAUDE.md`, seção "Ensaio de fumaça —
leitura".

Acrescentar também uma subseção da **campanha**: oito lotes, ids de execução,
datas (a campanha atravessou a meia-noite UTC — `aa` e `ab` em 16/09, `ac` a
`ah` em 17/09).

---

## 7. Caracterização do conjunto

### §2.2.1 Distribuição de extensões — ACRESCENTAR

Apurada por programa sobre os 223:

| Extensão | CVEs |
|---|---:|
| `.js` | 202 |
| `.ts` | 12 |
| sem extensão | 5 |
| `.jsx` | 2 |
| `.mjs` | 1 |
| `.yaml` | 1 |

Os 12 de TypeScript atravessam o laço (verificado no ensaio de fumaça, com o
`graylog2-server`). O `.yaml` (`CVE-2018-20164`) foi incluído no inventário
das duas ferramentas que decidem — mas estar no inventário não significa ter
sido analisado como YAML.

### §9.5 O quinto caso — ALTERAR

A V9 registra que a relação entre número de arquivos extraídos e duração foi
computada sobre séries desalinhadas, e o coeficiente descartado. **Agora há a
relação real, com 221 pontos**:

| arquivos extraídos | n | mediana |
|---|---:|---:|
| 0–10 | 72 | 43 s |
| 11–50 | 57 | 45 s |
| 51–100 | 27 | 54 s |
| 101–200 | 26 | 61 s |
| 201–500 | 19 | 69 s |
| 501–1000 | 10 | 92 s |
| >1000 | 10 | 158 s |

Piso de ~43 s até cerca de 50 arquivos; joelho entre 500 e 1000; o maior caso,
5.693 arquivos, custou 296 s.

Registrar a trajetória, que é ela mesma um caso de §9.5: com 6 pontos a
leitura foi "porte não prediz custo"; com 59, "há um piso que domina"; com
221, "a relação existe, escondida sob o custo fixo de invocação na faixa em
que está a maior parte do conjunto". **Conclusão tirada de amostra pequena
foi refinada, não confirmada.**

### §9.5 — ACRESCENTAR casos novos

A regra geral da V9 ("resultado nulo exige distinguir ausência do objeto de
pergunta mal formulada") reincidiu em formas novas nesta fase. Candidatos a
registro:

- guarda de contagem encadeada com `&&` antes de um `git commit`: o `grep -c`
  saiu 1 com zero casamentos, a cadeia quebrou, o commit não rodou, e o `$?`
  seguinte reportou a cadeia;
- sonda que casou o **eco** do comando em vez da saída dele, reportando
  "0 de 2" onde o correto era inconclusivo;
- apuração do inventário que **reimplementou** o critério de depuração em vez
  de lê-lo da fonte, produzindo números que contradiziam o relatório do
  próprio script;
- leitura de tabela pela coluna errada, que produziu "17 conjuntos sem
  primário" onde havia um;
- contagem visual que deu 11 onde o dado dizia 13 — pega por verificador
  automático com controle positivo;
- dicionário alimentado por iteração de conjunto, que tornou uma saída
  versionada não determinística entre processos.

Não é preciso registrar todos. O padrão comum — **método que produz número
plausível sem ser o método correto** — é o que interessa, e ele se repetiu.

---

## 7a. Normalização e verificação dos programas

### §5.6 Lacunas residuais — ALTERAR

A V9 lista três:

- **volume** — a maior fixture tinha poucos achados. **Resolvida**: a
  normalização rodou sobre 18.664 achados reais, 658 tratados, zero falhas,
  zero saídas ilegíveis;
- **codificação fora do ASCII** — **conferir**: não se apurou se algum achado
  real trouxe texto fora do repertório ASCII;
- **dois avisos sem fixture** — **permanece**.

### §5.1 / §5.6 Duração da normalização — RESOLVIDO (21/09/2026)

A V9 condiciona a arquitetura da §5.1 a uma premissa: a normalização tem de
ter custo desprezível em volume real. **Se sustenta.** Somada sobre os oito
lotes, no runner:

| Ferramenta | normalização | análise | fração |
|---|---:|---:|---:|
| CodeQL | 0,96 s | 3,63 h | 0,007% |
| Semgrep | 25,65 s | 1,36 h | 0,52% |
| Snyk Code | 0,31 s | 1,14 h | 0,007% |

Cerca de 27 s de normalização contra cerca de 6 h de análise. Um terço do
tempo do Semgrep vem de um único CVE, o `CVE-2018-20801` (8,72 s, raw de
144 MiB). A medida cobre o laço sobre os raws, não a carga do ground truth.

Os 24 `normalize-report` da campanha estão versionados desde 21/09/2026, em
`logs/campanha-2026-09-17/cves-sast-batch-<lote>/`. A pendência da §11 fecha.

### §9.1 Suficiência da chave de ordenação em escala — RESOLVIDO (21/09/2026)

A V9 limita a propriedade aos quatro CVEs do ensaio local e diz que a
campanha a reconfere. **Reconferida: zero colisões nas três ferramentas**,
sobre 18.664 achados.

O zero tem controle positivo: com a chave **sem as colunas** — a do schema
1.1 —, o mesmo método acusa **60 / 624 / 4** colisões (CodeQL / Semgrep / Snyk
Code). São as colunas que levam a contagem a zero, o que confirma a decisão da
V9 de acrescentá-las. Na Fase E, com quatro CVEs, eram 11.

### Verificação dos programas de cruzamento — ACRESCENTAR

A V9 descreve a verificação da normalização (§5.6). Os dois programas novos
precisam de descrição equivalente:

- **`cruza-deteccao.py`**: 23 casos sintéticos sobre o ground truth real, com
  positivo e negativo em cada nível e variante; 41 mutantes externos e 34
  embutidos, cada um exigido pela guarda pretendida; sete defeitos plantados no
  próprio programa, todos acusados — seis por duas camadas independentes, e um
  (casamento por nome de arquivo) só pelo caso C19;
- **`circularidade-proveniencia.py`**: a soma dos dois grupos reconstrói a
  matriz publicada em 21 células × 2 partições, zero divergências; saída
  determinística conferida sob três `PYTHONHASHSEED`.

O detalhe de que um defeito plantado é pego por **uma só camada** é o tipo de
precisão que a §5.6 da V9 cultiva, e merece constar.

## 7b. Limitações a acrescentar em §9

Quatro limitações medidas que a pauta ainda não cobria:

**Assimetria de granularidade de linha.** 94,1% dos achados do CodeQL (3.040
de 3.230) não trazem `line_end`, contra zero nas outras duas. Na prática o
CodeQL é avaliado por critério de ponto e as outras por critério de
intervalo. Não distorce o resultado, porque o ganho do intervalo é de cerca de
1% — mas é assimetria estrutural entre as ferramentas, e vai declarada como
tal.

**Limitação investigada e ausente — CWE nos achados.** Havia o risco de os
níveis 2 e 4 não serem comparáveis, se alguma ferramenta emitisse muitos
achados sem CWE. Medido: **zero** em 18.664 achados, e zero CVEs em que o
arquivo certo foi achado só por alertas sem CWE. O zero se explica: o campo de
CWE do Semgrep muda de tipo, e o tratamento explícito dos dois tipos, decidido
antes de existir dado real, recuperou 126 achados que sairiam sem CWE. Vale
registrar como "investigado e ausente", que é informação — não omitir por não
ter se confirmado.

**Cobertura por arquivo no Snyk Code — confirmada.** A V9 (§9.2) já declara
que o Snyk Code não decide sobre arquivo determinado. A campanha confirmou:
`null` em 216 de 216. Consequência para a análise, a dizer com todas as
letras: no Snyk Code **não se distingue "olhou e não viu" de "não olhou"**.

**`rules_applied` do Semgrep em escala.** A V9 (§4.5) reporta 256, 297, 297 e
370 regras aplicadas, de quatro CVEs do ensaio local. **Nos 221 da campanha:
mínimo 144 (`CVE-2018-20164`), máximo 910 (`CVE-2018-11798`), mediana e moda
296.** De 1.074 regras carregadas. Trocar os quatro pontos pela faixa.

**Deriva das imagens entre rebuilds.** O rebuild de 15/09 foi comparado com o
de 12/09 pelo inventário de pacotes: 1 de 716 artefatos soltos mudou de versão
(`uvicorn`, na imagem do Semgrep). Os valores fixados por descritor — bundle
do CodeQL, pack do Semgrep, CLI do Snyk — ficaram idênticos. Registrar em §9.1
como medida do que a fixação de base deixa solto.

## 7c. Observação sobre o Snyk Code — INVESTIGAR ANTES DA V10

**Todo teste do Snyk Code com achados termina com `ERROR Forbidden
(SNYK-CLI-0000)`, HTTP 403, impresso depois do resumo do teste.** São 133 de
133 testes com status `OK`, e **nenhum** dos 83 `SEM_ACHADOS`. O raw foi
gravado e normalizado nos 133.

Não se sabe o que a CLI tenta fazer quando recebe o 403. Hipótese, não
verificada: depois de encontrar achados, a CLI tenta uma operação no nível da
organização — enviar o resultado à plataforma, ou consultar políticas — que a
conta usada não permite.

**Por que isto importa mais do que parece.** O Snyk Code é a ferramenta com a
menor detecção do estudo, em todos os sete níveis. Se o 403 interrompe algo que
altera os achados — aplicação de política, enriquecimento, paginação —, o
resultado dele estaria subestimado por falha de execução, e não por capacidade.
Isso inflaria a diferença entre as ferramentas na direção em que ela já é
grande. **Um viés silencioso contra a ferramenta mais fraca é o tipo de defeito
que mais distorce uma comparação.**

A evidência de que não afeta — raw gravado, contagem de achados coerente com o
log — é boa mas não é decisiva: mostra que o que foi gravado está íntegro, não
que nada deixou de ser gravado. Verificar antes de publicar os números do Snyk
Code.

**Estado em 21/09/2026: investigação adiada pela cota de testes.** A conta do
Snyk usada na campanha esgotou o limite de testes do período. Cada execução do
Snyk Code consome um teste, e a investigação não pode rodar até a renovação.
O prompt está pronto; ela gasta de 4 a 6 testes — dois CVEs, duas execuções
cada — e cabe com folga no ciclo seguinte.

**A segunda campanha soma mais 216 testes.** No pior caso — 403 afetando os
achados, e a primeira campanha do Snyk precisando ser refeita — são 432 testes.

**Troca de conta, se for o caminho.** Se a cota for resolvida com uma conta
nova, as duas campanhas do Snyk precisam rodar **na mesma conta**, ou o 403
precisa ser investigado antes, para saber se depende da conta. Senão, a
diferença entre a versão vulnerável e a corrigida deixa de ser atribuível só à
correção. Conferir também os termos de uso do Snyk quanto a contas múltiplas.

**A cota também condiciona o pior caso.** Se a investigação mostrar que o 403
afeta os achados, refazer o Snyk Code custa 216 testes. Conferir na conta o
limite do plano: se for menor que isso, refazer ocupa mais de um ciclo de
renovação, e o prazo da V10 precisa contemplar.

**Se a investigação não for feita**, o texto declara como limitação, com os
fatos: os 133 testes com achados terminaram em 403, os 83 sem achados não; o
SARIF foi gravado íntegro; não se apurou se algo deixou de ser gravado. O que
não pode é publicar o número do Snyk Code sem nenhuma das duas coisas.

## 8. Promessas da V9 ainda não cumpridas

Itens que a V9 declara e que **não foram feitos**. Precisam ser feitos antes
da V10 ou retirados do texto com razão declarada.

- **§7.7 — métricas por CWE.** A V9 promete apuração por ferramenta **e por
  CWE**. O cruzamento computou por ferramenta. A decomposição por CWE não
  existe.
- **§7.6 — delimitação por linguagem do Semgrep.** A V9 diz que "parte
  substancial" dos achados do Semgrep recai fora de JS/TS, que a delimitação é
  aplicada na análise, e que "a proporção descartada é declarada". Não foi
  feito. O Semgrep varreu 1.165 `.java` só no `graylog2-server`.
- **§7.6 — tabela de capacidade empírica por ferramenta.** Categorias
  efetivamente reportadas, a partir dos achados brutos. Não existe.
- **§11 — CWE primário do conjunto `CWE-250 + CWE-400`.** Continua indefinido
  (`CVE-2018-16472`). A variante estrita não se aplica a ele e o caso é
  contado à parte. Pendência mantida.

---

## 9. Política de versionamento — §5.5 ALTERAR

Acrescentar à tabela:

| Categoria | Situação |
|---|---|
| Resultados do cruzamento (`results/cruzamento/`) | Versionados |
| Saídas do cotejo de proveniência (`results/proveniencia/`) | Versionadas |
| Apuração de circularidade (`results/circularidade/`) | Versionada |
| Logs de execução da campanha, por lote | Versionados |
| Documento de critérios do cruzamento | Versionado |

Registrar que as saídas dessas três categorias são **determinísticas** — sem
carimbo de execução, conferidas em três `PYTHONHASHSEED` distintos — e trazem
o sha256 das entradas e do código que as produziu.

Registrar o volume que justifica manter os brutos fora: **623 MiB** de saída
bruta, dos quais o Semgrep responde por 548 MiB (88%); o maior arquivo, 144 MiB,
seria recusado no push sem LFS. Os tratados somam 15,5 MiB.

Registrar que os brutos **expiram em 15 e 16/12/2026** nos artifacts do GitHub,
e onde fica a cópia externa, quando existir.

### Cópia externa dos brutos — CONFERIDA (21/09/2026)

Feita em 17/09/2026: um `tar.zst` por ferramenta, **6,35 MiB** no total contra
623 MiB descomprimidos. Os três passam em `zstd -t`, e os 658 raws contidos
são idênticos por sha256 aos dos artifacts. Tamanhos e sha256 registrados no
`CLAUDE.md`; o caminho, não, por política.

**Ressalva:** a cópia está na mesma máquina do repositório. Não protege contra
perda do disco. A V10 precisa nomear um local fora da máquina.

**Restante dos artifacts — versionado em 21/09/2026.** Portões, saídas do
container, README e disco de cada job, os oito `scan.json` da sonda de rede e
as 32 sondagens dos lotes: 232 arquivos, byte a byte, com manifesto de sha256
conferível por `sha256sum -c`. Antes, varredura de segredo com controle
positivo — nenhum segredo. **Tudo o que os 24 artifacts continham está no
repositório ou na cópia externa**, e a expiração de dezembro deixa de ser
risco.

### Imagens no GHCR ainda privadas — DECIDIR

**Ponto sério.** Os três pacotes de imagem nasceram privados e continuam
privados, com a decisão de torná-los públicos pendente da leitura das
licenças do pack do Semgrep e do bundle do CodeQL.

Enquanto forem privados, a afirmação de reprodutibilidade tem alcance menor
do que parece: um terceiro **não consegue** puxar as imagens pelos digests
registrados. Consegue reconstruí-las a partir dos Dockerfiles versionados, mas
obtém bytes diferentes — 716 pacotes são resolvidos no momento do build, e a
comparação entre os rebuilds de 12 e 15/09 já mostrou um deles mudando de
versão em dois dias e meio.

A V10 precisa, portanto, ou registrar as imagens como públicas, ou declarar
que a reprodução exata depende de acesso concedido e que a reconstrução
independente é aproximada.

---

## 10. §11 Decisões e verificações pendentes — REESCREVER

A seção inteira da V9 fica quase toda resolvida:

| Pendência da V9 | Destino |
|---|---|
| Universo de referência do TN | **resolvida pelo desenho do benchmark**: o ponto da falha na versão corrigida |
| CWE primário de `CWE-250 + CWE-400` | **permanece** |
| Limite de tempo das análises | decidido, 900 s |
| Dois avisos de execução sem fixture | conferir se continua |
| Uid efetivo e defeito do diretório pessoal | medido |
| Duração do CodeQL no ambiente da campanha | medida |
| TypeScript atravessando o laço | verificado |
| Execução sem rede do Semgrep | verificada, com a ressalva dos ~110 s |
| Completude do inventário do CodeQL | **211 de 221 batem, até 5.693 arquivos**; os 10 divergentes vão todos no mesmo sentido (`artifacts[]` com 1 a 4 a mais), o que não é teto de enumeração |
| Duração da normalização | **medida** — 27 s contra 6 h; premissa da §5.1 sustentada |

Pendências **novas** para a V10:

- **a segunda campanha, sobre a versão corrigida**, e o critério de casamento
  nela, fixado antes dos resultados;
- o ramo `gt_file_scanned: false` nunca ocorreu em 223 CVEs — continua sem
  exercício sobre dado real;
- a hipótese sobre os 10 divergentes do inventário (arquivos que o extrator
  conheceu e não extraiu) é verificável com `js/diagnostics/extraction-errors`
  e não foi verificada;
- as três promessas da seção 8 desta pauta;
- o 403 do Snyk Code (seção 7c) — investigar antes de publicar os números da
  ferramenta; **adiado até a renovação da cota de testes do Snyk**;
- a modalidade DAST inteira.

---

## 10b. §10 Registro de decisões — ACRESCENTAR

O registro da V9 termina na decisão 72. Decisões desta fase, a numerar a
partir de 73:

| Decisão | Seção |
|---|---|
| Limites de tempo sobrescrevíveis por ambiente, sem reconstrução de imagem | 4.4 |
| Reconstrução das imagens antes do ensaio de fumaça, para que o ensaio meça as imagens da campanha | 3.1, 8 |
| Workflow de lote único para ensaio e campanha, com matriz por ferramenta | 3.1 |
| Pré-voo da imagem antes de cada lote | 4.6 |
| Portão de lote sem saída bruta, que nomeia a condição e não atribui causa | 4.6 |
| Limite de análise em 900 s, justificado pela assimetria da falha | 4.4 |
| Tamanho de lote de 30 confirmado no escopo restrito | 4.4 |
| Dois lotes em série e seis em paralelo | 8 |
| FP e VN definidos na versão corrigida, a partir do README e do `benchmark-CVEs.md`; definição de FP da V9 abandonada | 7.3, 7.7 |
| Segunda campanha, sobre o commit da correção | 4, 8 |
| Cinco níveis de acerto, apurados na mesma passada | 7.2 |
| Casamento de linha por sobreposição, sem banda de tolerância | 7.7 |
| Critérios de cruzamento fixados em documento antes de qualquer resultado | 7 |
| Denominador de 220, com a segunda baixa por commit inexistente | 7.4 |
| Versionamento dos tratados, do cruzamento, da proveniência, da circularidade e dos logs por lote; brutos fora | 5.5 |
| Saídas de análise determinísticas, sem carimbo de execução, com resumo do código que as produziu | 5.5 |
| Apuração da circularidade com os níveis sem CWE como controle interno | 9.2 |

## 11. Registro de alterações — ACRESCENTAR entrada "Versão 10"

Resumo para o topo do documento, na forma das entradas anteriores:

- **natureza do documento: passa de método a método e resultados**, com
  seções de resultados SAST, DAST e da análise comparativa;
- **matriz de confusão completa**, com FP e VN medidos na versão corrigida, a
  partir da definição do benchmark; a definição de FP da V9 é abandonada;
- **segunda campanha**, sobre o commit da correção;
- cinco níveis de acerto, com critério de linha por sobreposição, substituem a
  dupla apuração isolada e as faixas de localização;
- denominador de 221 para 220, com a segunda baixa por indisponibilidade de
  commit;
- resultados da modalidade estática;
- circularidade da proveniência medida, com controle interno;
- limite de tempo decidido e justificado pela assimetria da falha;
- infraestrutura com imagens por digest e build único;
- caracterização porte × custo com 221 pontos;
- resultados da campanha DAST — a preencher;
- análise comparativa SAST × DAST — a preencher.
