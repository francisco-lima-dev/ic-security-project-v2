# Critérios do cruzamento SAST

Documento de método. Fixa **o que conta como acerto** no confronto entre os
achados normalizados e o ground truth do OpenSSF CVE Benchmark, antes de
qualquer código de cruzamento existir.

Escrito em 18/09/2026, depois da campanha dos 223 CVEs e da caracterização dos
658 tratados, e **antes** de qualquer número de detecção ter sido computado.
A ordem importa: critério escolhido depois de ver o resultado é critério
ajustado ao resultado.

---

## 1. O que este estudo NÃO vai reportar, e por quê

### Emenda de 21/09/2026 — o falso positivo existe

**A afirmação central desta seção está errada.** O texto original, preservado
abaixo, diz que não existe rótulo negativo em lugar algum do conjunto, e conclui
que não haverá métrica de precisão nem de falso positivo. O rótulo negativo
existe: é a **versão corrigida** do mesmo código, no ponto da falha. Ali o
benchmark garante que a vulnerabilidade foi removida.

**Como foi descoberto.** Lendo o README do próprio benchmark, em 21/09/2026:
<https://github.com/ossf-cve-benchmark/ossf-cve-benchmark/blob/main/README.md>,
consultado nessa data, no commit `91c59fd`, que era o HEAD do repositório. O
trecho está lá, palavra por palavra, desde o release 1.0.0 (`4e90564`,
09/12/2020):

> Second, by also analyzing the patched versions of the same codebases, false
> positive rates of these tools can be measured more accurately and based on
> real validated fixes.
>
> For each CVE in the in the dataset (200+ CVEs so far), the CVE Benchmark
> determines:
>
> 1. Is the security tool able to detect the vulnerability, or does it produce
>    a false negative?
> 2. When run against the patched codebase, does it recognize the validated
>    patch, or does it produce a false positive?

A duplicação "in the in the" é do original.

**O erro não foi só de leitura.** O critério da versão corrigida estava no
`CLAUDE.md` desde 28/08/2026 (`342194b`), citando o `docs/benchmark-CVEs.md` do
benchmark: a ferramenta ideal produz ao menos um alerta relevante no `prePatch`
e nenhum no `postPatch`. Esta seção foi escrita em 18/09/2026 sem ligar esse
critério ao falso positivo, e o README, que o nomeia assim, não tinha sido lido.
A inexistência do negativo era inferência, apresentada como propriedade do
conjunto.

**Definição adotada pelo estudo, a partir das duas perguntas do README e da
garantia do `benchmark-CVEs.md`.** A garantia é a de que, num CVE completo, o
`postPatch` "contains zero relevant weaknesses, meaning that the vulnerability
has been fixed properly".

| Versão analisada | O que o benchmark garante no ponto da falha | Alerta ali | Resultado |
|---|---|---|---|
| antes da correção | a falha existe | sim | verdadeiro positivo |
| antes da correção | a falha existe | não | falso negativo |
| depois da correção | a falha foi removida | sim | **falso positivo** |
| depois da correção | a falha foi removida | não | **verdadeiro negativo** |

Isso dá a matriz de confusão completa, num universo definido: um ponto
vulnerável e um ponto corrigido por CVE. Precisão, especificidade e F1 passam a
ser computáveis **nesse sentido** — que não é a precisão sobre todos os alertas
da ferramenta.

A tabela é construção do estudo, não o cálculo que a ferramenta de relatório do
benchmark implementa: aquela lê a segunda pergunta de forma condicional à
detecção no `prePatch`, sem localizar o ponto na versão corrigida. As duas
leituras estão descritas na §8, e a escolha entre elas não está feita.

**O que continua valendo.** Alerta fora do ponto da falha — noutro arquivo, ou
noutro trecho do mesmo arquivo — continua não classificável: o benchmark não
afirma que o resto do repositório esteja limpo, nem na versão vulnerável nem na
corrigida. A fração de 77,8% a 96,9% dos alertas fora do arquivo do ground truth
(§6) segue sem classificação possível, e a precisão sobre todos os alertas segue
incomputável. O que cai é só a conclusão de que não há negativo nenhum. Há um,
por CVE, e é ele que torna o falso positivo computável.

**O que muda no plano do estudo.** Falso positivo e verdadeiro negativo exigem
uma **segunda campanha**, sobre o commit da correção (`PostPatchCommit`), que a
primeira não rodou. Até ela existir, a matriz tem só a metade positiva.

**O que não muda.** Os resultados da primeira campanha — os cinco níveis, as
duas variantes de CWE, o denominador de 220, a apuração da circularidade — são a
metade VP/FN da matriz e não são afetados por esta emenda.

**O critério de casamento na versão corrigida não está fixado.** Localizar "o
mesmo ponto" depois da correção e decidir quais níveis se aplicam são decisões a
fixar neste documento antes de qualquer resultado da segunda campanha; ver §8.

**Por que emenda, e não reescrita.** Este documento vale por ter sido fixado
antes de qualquer número de detecção, com o histórico do repositório provando a
ordem. Reescrever a seção em silêncio apagaria essa evidência e esconderia um
erro de método que precisa ficar registrado.

**SUPERADO POR ESTA EMENDA (21/09/2026), e o original fica abaixo intacto.**
Deixam de valer:

- "Não haverá métrica de precisão, nem de falso positivo" — haverá, no sentido
  da tabela acima, com a segunda campanha;
- "Não existe rótulo negativo em lugar algum do conjunto" — existe, na versão
  corrigida, no ponto da falha;
- o "no lugar" de "O que se reporta no lugar" — detecção e volume continuam
  sendo o que a primeira campanha reporta, mas não mais em lugar do falso
  positivo;
- na alternativa descartada, "construindo o negativo que falta" — no ponto da
  falha, o negativo não falta. A rotulagem manual continua sendo o único
  caminho para a precisão sobre **todos os alertas**, e nesse sentido a frase
  "o que tornaria a precisão computável" segue certa.

Continuam valendo, no sentido restrito de alertas fora do ponto da falha: que o
ground truth não afirma que o resto do código é limpo; que nada no dado permite
classificar achado fora do arquivo do CVE; e que o volume do `CVE-2018-20801` só
distorceria uma precisão sobre todos os alertas.

### Texto original, de 18/09/2026

**Não haverá métrica de precisão, nem de falso positivo.**

O ground truth afirma **uma** vulnerabilidade por CVE: um par (CWE,
arquivo), com as linhas. Ele **não afirma que o resto do código é limpo**. Não
existe rótulo negativo em lugar algum do conjunto.

A consequência é direta e não tem contorno dentro deste benchmark: um achado
fora do arquivo do CVE pode ser vulnerabilidade real não catalogada, código
morto, falso positivo, ou outra CVE que o benchmark não cobre. **Nada no dado
permite distinguir esses casos.** Calcular "achados que casam o ground truth ÷
total de achados" e chamar isso de precisão afirmaria mais do que o conjunto
sustenta.

O que se reporta no lugar:

- **Detecção** (recall), que é bem fundada: para cada CVE afirmado, a
  ferramenta o encontrou ou não.
- **Volume de alertas**, como caracterização descritiva, nomeado como tal e
  nunca apresentado como medida de qualidade.

Uma consequência secundária, e boa: isto dissolve o problema do
`CVE-2018-20801`, que responde por 5850 dos 11768 achados do Semgrep. Aquele
volume só distorceria uma métrica de precisão. Para detecção, o CVE acerta ou
não acerta, e conta uma vez como qualquer outro.

**A alternativa que existe e foi descartada:** rotular à mão uma amostra de
achados, construindo o negativo que falta. Custa semanas, é subjetivo, e sairia
do escopo de uma iniciação científica. Registrado como o que tornaria a
precisão computável, não como lacuna do desenho.

---

## 2. Os cinco níveis de acerto

Nenhum critério único é escolhido. **Os cinco são apurados na mesma passada**,
e o texto discute o que os números mostrarem.

| Nível | Critério | O que estabelece |
|---|---|---|
| **0** | a ferramenta produziu ao menos um achado na árvore analisada | limite superior; quase sem valor isolado |
| **1** | ao menos um achado com `file_path` = `gt_file_path` | a ferramenta olhou o arquivo certo |
| **2** | nível 1 **e** o CWE casa | arquivo certo, natureza certa |
| **3** | nível 1 **e** a linha casa | arquivo certo, ponto certo |
| **4** | nível 3 **e** o CWE casa | o estrito: arquivo, ponto e natureza |

Um CVE conta para um nível se **ao menos um** achado satisfaz o critério. Os
níveis 2, 3 e 4 exigem que **o mesmo achado** satisfaça todas as condições —
não vale um achado acertar o arquivo e outro acertar o CWE.

**O intervalo entre níveis é resultado, não ruído.** A diferença entre o nível
1 e o 3 mede quanto a ferramenta erra o ponto dentro do arquivo certo; entre o
1 e o 2, quanto erra a natureza. Nenhum número isolado diz isso.

Apurar também, explicitamente: **dos CVEs que acertam no nível 1, quantos
acertam no 3**. É o que separa "encontrou a vulnerabilidade" de "encontrou
alguma coisa naquele arquivo".

---

## 3. Casamento de linha — sobreposição

**Critério:** o intervalo `[line_start, line_end]` do achado contém alguma das
`gt_file_lines`.

**`line_end` nulo é tratado como `[line_start, line_start]`** — sem fim
declarado, o intervalo é o ponto. Isto não é escolha entre opções: é a única
leitura possível do dado.

**Sem banda de tolerância.** Nada de ±5 ou ±10 linhas.

### Por que sobreposição, e por que sem banda

A escolha foi decidida por medição sobre os 658 tratados, não por argumento.
O temor inicial era que a sobreposição favorecesse ferramentas que reportam
intervalos longos: quanto mais linhas um achado cobre, maior a chance de tocar
a linha do ground truth por acaso.

**O ganho da sobreposição sobre o casamento exato é de 5, 1 e 13 achados** —
CodeQL, Semgrep e Snyk Code. Sobre 717, 360 e 199 achados no arquivo do ground
truth. Qualquer uma das duas opções produz praticamente o mesmo resultado, e é
isso que torna a decisão segura: ela quase não importa.

**Dezesseis dos 19 ganhos vêm de regras de limitação de taxa**, que reportam a
função inteira em vez de uma linha: `NoRateLimitingForExpensiveWebOperation` no
Snyk Code (12 dos 13 ganhos dele) e `js/missing-rate-limiting` no CodeQL (4 dos
5 ganhos dele). As três exceções são `js/polynomial-redos`, `raw-html-concat` e
`javascript/DOMXSS`.

**A simetria entre as três ferramentas não existe, e não se força.** O ganho
está no Snyk Code (13) e no CodeQL (5); o Semgrep tem **um**, e ele é o
`raw-html-concat`, que não é regra de limitação de taxa. É comportamento de
regra específica, não propriedade da ferramenta, e não justifica um desenho
mais complicado.

A banda de tolerância foi descartada por não haver o que ela resolveria: com
ganho de 1%, ampliar a janela não muda a conclusão e introduz um parâmetro
arbitrário a defender no texto.

### Assimetria a declarar no texto

**94,1% dos achados do CodeQL não trazem `line_end`** (3040 de 3230), contra
zero nas outras duas. Na prática, o CodeQL é avaliado por critério de ponto e
as outras duas por critério de intervalo.

Como o ganho do intervalo é de ~1%, a assimetria **não distorce o resultado** —
mas é assimetria estrutural entre as ferramentas, e vai declarada como tal, não
apresentada como defeito do dado nem escondida.

### O que a caracterização mostrou, e que muda a expectativa

A distância mediana entre o achado e a linha do ground truth mais próxima,
**restrita aos achados no arquivo certo**, é de **71, 113 e 64 linhas**. Mais
de 35% dos achados no arquivo certo estão a **mais de 100 linhas** do ground
truth, nas três ferramentas.

Isto não é problema do critério: é caracterização do que as ferramentas
reportam. Registrado aqui porque antecipa que o nível 3 será substancialmente
menor que o nível 1, e porque essa diferença é um dos resultados a discutir —
não uma anomalia a corrigir.

---

## 4. Casamento de CWE — duas variantes

Ambas apuradas, para todos os níveis que dependem de CWE:

- **Generosa:** o conjunto `cwe` do achado **intersecta** `gt_cwes`.
- **Estrita:** o conjunto `cwe` do achado **contém** `gt_cwe_primary`.

A variante estrita usa o `gt_cwe_primary`, construído deliberadamente para
este fim, com tabela versionada cobrindo os 17 conjuntos multivalorados do
benchmark. Quando `gt_cwe_primary` é nulo — conjunto vazio ou primário
indefinido na tabela —, a variante estrita **não se aplica** a esse CVE, e o
caso é contado à parte em vez de tratado como não-acerto.

Toda comparação usa a **forma normalizada** de três dígitos (`CWE-079`), que o
`normalize.py` aplica de ponta a ponta. Nunca comparar cadeia crua.

### O que foi descartado

**Casamento por família** — aceitar um CWE pai ou filho na hierarquia do MITRE
como acerto. Introduz dependência de taxonomia externa, uma cascata de
julgamentos sobre quais relações valem, e não há critério objetivo para parar.
Custo alto, ganho duvidoso.

### A limitação que foi investigada e NÃO existe

Havia o risco de os níveis 2 e 4 não serem comparáveis entre ferramentas: se
uma delas emitisse muitos achados sem CWE, seria penalizada por ausência de
metadado e não por erro de natureza.

Medido: **zero achados sem CWE nas três ferramentas**, em 18.664 achados. E
**zero CVEs** em que a ferramenta acertou o arquivo mas todos os achados ali
estão sem CWE. Corroborado por três fontes independentes, uma delas os
contadores do `normalize.py` gravados no momento da campanha.

Um dado explica o zero e merece registro: o contador `semgrep_cadeia_nua` é
**126**. O campo `extra.metadata.cwe` do Semgrep muda de tipo — lista na
maioria, cadeia nua numa minoria —, e sem o tratamento explícito dos dois tipos
esses 126 achados sairiam com `has_cwe: false`, indistinguíveis de ausência
legítima. A decisão de tratar os dois tipos, tomada antes de existir raw real,
é o que torna os níveis 2 e 4 comparáveis hoje.

---

## 5. O denominador

**220 pares (CWE, arquivo)**, em ambas as modalidades.

| Grandeza | Valor |
|---|---:|
| CVEs no conjunto | 223 |
| Pares afirmados pelo benchmark | 222 |
| Pares no denominador | **220** |

**222 e não 223** porque o `CVE-2018-1000096` não declara CWE e está fora da
matriz desde antes de qualquer execução.

**220 e não 222** porque duas baixas por indisponibilidade de código saem do
denominador, cada uma tirando um par:

| CVE | Causa |
|---|---|
| `CVE-2016-1000229` | repositório `linxiaowu66/swagger-ui` inexistente |
| `CVE-2018-8035` | commit declarado não existe em `apache/uima-ducc` |

Nas duas, **nenhuma ferramenta foi confrontada com o código**. Não são falsos
negativos, e mantê-las no denominador atribuiria às ferramentas uma falha que
é do conjunto.

**O denominador é o mesmo para as três ferramentas.** Nunca se cria
denominador por ferramenta — é o que permite que os números sejam comparados
entre si.

### Os cinco do Snyk Code permanecem no denominador

O Snyk Code saiu com `SEM_ARQUIVO_ANALISAVEL` (exit 3) em `CVE-2018-16479`,
`CVE-2018-16480`, `CVE-2018-3731`, `CVE-2018-3747` e `CVE-2019-5423` —
exatamente os cinco CVEs cujo arquivo do ground truth **não tem extensão**
(`bin/http-live`, `bin/public`). Correlação de 5 em 5.

Exit 3 é causa **interna à ferramenta**, ao contrário do repositório que não
existe: o código estava lá e a ferramenta não o analisou. Os cinco permanecem
no denominador e contam como **não-detecção do Snyk Code**, pela regra fixada
no `CLAUDE.md` antes da campanha.

---

## 6. Limitações a declarar no texto

Todas medidas, nenhuma hipotética:

**Cobertura por arquivo indisponível no Snyk Code.** `gt_file_scanned` é
`null` em 216 de 216, porque a `coverage[]` do SARIF traz contagem por
linguagem e não inventário de caminhos. Para o CodeQL e o Semgrep sabe-se se o
arquivo do ground truth foi visto (221 `true` em ambos); para o Snyk, **não se
pode distinguir "olhou e não viu" de "não olhou"**.

**Nenhum `false` em `gt_file_scanned` nos 223.** O ramo continua sem exercício
no laço depois da campanha completa, coberto só por fixture. Limitação que
sobreviveu ao conjunto inteiro.

**Assimetria de `line_end`**, descrita na seção 3.

**Volume de alertas não é medida de qualidade**, pela razão da seção 1. O
volume do Semgrep é além disso **concentrado**: 10 CVEs somam 77% do total nos
seis últimos lotes, e o `CVE-2018-20801` sozinho responde por 5850 achados.
Qualquer número agregado de volume precisa vir acompanhado da distribuição.

**Fração de achados fora do arquivo do ground truth:** 77,8% no CodeQL, 96,9%
no Semgrep, 94,6% no Snyk Code. É o que o nível 0 captura e o nível 1 descarta.
Pelo argumento da seção 1, **esses achados não são classificáveis** como
corretos ou incorretos com este conjunto.

*Nota de 21/09/2026.* Os dois parágrafos acima que remetem à seção 1 — volume
de alertas e fração fora do arquivo do ground truth — continuam valendo. Tratam
de alertas fora do ponto da falha, que a emenda da §1 não alcança: ela
estabelece o negativo na versão corrigida, no ponto da falha, e só ali.

---

## 7. Como o cruzamento deve ser implementado

**O script computa todas as combinações e não decide nada.** Cinco níveis, duas
variantes de CWE, emitindo matriz por (CVE, ferramenta). Qual recorte discutir
é decisão do texto, tomada depois de ver os números — e o script não pode
embutir uma preferência que torne o recorte alternativo indisponível.

A razão é concreta, e vem desta própria fase: das duas previsões que fiz antes
de medir — viés de extensão de intervalo, e limitação de CWE —, **as duas
estavam erradas**. E a distância mediana de 71 a 113 linhas, que é o achado
mais consequente da caracterização, não foi antecipada por ninguém. Previsão
sobre o resultado do cruzamento vale pouco; o script não deve carregar
nenhuma.

Requisitos de implementação, na disciplina que o projeto já aplica:

- **Fixtures antes do conjunto real**, como no `normalize.py`. Cada nível e
  cada variante de CWE precisa de caso positivo e caso negativo sintéticos.
- **Validação estrutural fatal** antes de emitir número algum: schema 1.3,
  chaves esperadas, tipos. Zero anomalia só vale como resultado se o validador
  foi exercido contra positivo.
- **Zero exige controle.** Qualquer contagem que dê zero precisa de
  demonstração de que o caminho de contagem funciona — a regra geral do
  projeto: zero indistinguível de falha não é resultado.
- **Parser do formato, nunca regex sobre prosa.** Os campos do schema são lidos
  pelo que são.
- O script lê `results/*/treated/`, versionados, e **não depende de artifact**:
  um terceiro reproduz os números a partir do repositório sozinho.
- **O script lê também o registro de status da campanha**, para que a
  ausência de um tratado nunca seja interpretada sem causa registrada. O
  registro sai dos 24 logs de execução dos lotes, versionados em
  `logs/campanha-2026-09-17/cves-sast-batch-<lote>/` como cópia byte a byte
  dos artifacts. A leitura é a do `check-log.py`, em que vale a última linha
  de cada CVE. Nenhum arquivo intermediário entra: o `campanha-223.json` é
  reconstituível desses logs, com zero divergências, e não é lido.

  O registro **não define o denominador**, que vem da lista menos as três
  exclusões nominadas. Serve de conferência: CVE do denominador sem tratado
  só é admitido com `SEM_ARQUIVO_ANALISAVEL` do Snyk Code no log, e as duas
  baixas têm de trazer `ERRO_FETCH` e `ERRO_CHECKOUT`, cada uma o status do
  seu motivo. Qualquer outra combinação para o script.

  **Limite, declarado:** se o próprio log trouxer um `SEM_ARQUIVO_ANALISAVEL`
  indevido, a ausência é aceita como não-detecção. Não há, no repositório,
  segunda fonte da causa contra a qual conferi-lo.

---

## 8. O que este documento não fixa

**Nada sobre a modalidade DAST.** O ground truth do benchmark dá arquivo e
linha; o OWASP ZAP reporta URL, parâmetro e alerta. Não há mapeamento direto, e
a unidade comum entre as duas famílias — provavelmente CWE — é decisão de
método ainda em aberto, a tomar quando o pipeline DAST existir.

**Nada sobre a comparação entre SAST e DAST.** Os dois conjuntos são de
natureza diferente: 223 CVEs de repositórios reais de um lado, duas aplicações
deliberadamente vulneráveis do outro. A comparação direta entre os números vai
precisar de justificativa explícita, e ela não está escrita.

**O critério de casamento na versão corrigida.** Acrescentado em 21/09/2026, pela
emenda da §1. Localizar "o mesmo ponto" depois da correção — cuja linha pode
mudar de número, ou deixar de existir — e decidir quais dos cinco níveis se
aplicam à versão corrigida são decisões **a fixar neste documento antes de
qualquer resultado da segunda campanha**, como foi feito na primeira.

**A primeira decisão do desenho da segunda campanha é a escolha entre duas
leituras:** a matriz de quatro células da emenda da §1, que trata cada CVE como
um ponto vulnerável e um ponto corrigido, independentes; e a leitura condicional
que a ferramenta de relatório do próprio benchmark implementa. Esta fica
registrada aqui como ponto de partida, **sem fixar**.

Como a ferramenta do benchmark calcula o reconhecimento da correção, lido no
código do commit `91c59fd`, em `contrib/reports/explore-server/src/`:

- **Condicional à detecção no `prePatch`.** Só se avalia a versão corrigida de
  CVE que a ferramenta detectou na vulnerável. Detecção, ali, é o critério do
  próprio benchmark, descrito nos dois itens seguintes; o mais próximo dele entre
  os cinco níveis da §2 é o nível 3.
- **Por regra.** Entram só as regras que, no `prePatch`, produziram alerta num
  alvo (`buildRulesOnATargetMap`, em `server/index.ts`).
- **Por igualdade de (arquivo, linha).** Alvo é o par exato de uma weakness, sem
  sobreposição de intervalo (`isOnTarget`, no mesmo arquivo).
- **Contando alertas no repositório inteiro no `postPatch`.** Para cada regra que
  entrou, compara-se o total de alertas dela no `prePatch` e no `postPatch`, sem
  localizar ponto algum (`getRelevantRuleAlertCounts`, em `client/util.tsx`). A
  correção conta como reconhecida (`Negative`, exibido como "good") se ao menos
  uma dessas regras tem menos alertas no `postPatch`; do contrário, o resultado é
  `NeutralOrPositive` ("bad").
- **`Uncomputable` quando não houve detecção** (`getRelevantRuleAlertCountsConclusion`,
  no mesmo arquivo), e `Missing` quando a ferramenta não rodou nos dois commits.
  O benchmark não atribui falso positivo nem verdadeiro negativo ao CVE que a
  ferramenta não detectou, e não monta a matriz de quatro células.

---

## 9. Decomposição da detecção por categoria de CWE

Fixado em 25/09/2026, a partir da distribuição de `gt_cwe_primary` no
denominador (`results/por-cwe/distribuicao-primario.csv`), **antes** de
qualquer número de detecção por categoria. A distribuição é propriedade do
ground truth, e não resultado. Única detecção por categoria já conhecida: a
do CWE-915, publicada na apuração da circularidade. Com n = 23, ele fica
acima de qualquer limiar considerado.

### A categoria

**A categoria de um CVE é o seu `gt_cwe_primary`. Sempre a do CVE, nunca a
do achado.** Um CVE de primário CWE-079 acertado na variante generosa por
achado etiquetado CWE-116 conta em CWE-079. O CWE do achado pertence à
tabela de capacidade empírica (§7.6 da metodologia), que é outro eixo.

Cada CVE cai em exatamente uma categoria, e o agrupamento é uma
**partição** do denominador de 220. Controle obrigatório da apuração: a
soma das categorias reconstrói a matriz de detecção publicada, em todas as
células, nas três ferramentas, com zero divergências.

O `CVE-2018-16472`, de primário indefinido, forma a categoria
`SEM_PRIMARIO`. Entra nos níveis 0, 1 e 3 e nas variantes generosas; nas
estritas não se aplica, como já ocorre na matriz.

### O limiar

**k = 10. A categoria com n ≥ 10 tem taxa apurada e discutida no texto.**

Distribuição: 47, 29, 26, 25, 23, 14 | 9, 7, 6 | 4, 4, 3, 3, 3, 2, 2, 2
e dez categorias com 1. Nenhuma categoria tem n entre 10 e 13, de modo que
qualquer limiar de 10 a 14 produz o mesmo corte; ele coincide com o salto
de 14 para 9.

Acima do limiar ficam seis categorias — CWE-079 (47), CWE-022 (29),
CWE-400 (26), CWE-078 (25), CWE-915 (23) e CWE-094 (14) —, com 164 dos 220
CVEs do denominador.

Alternativas examinadas e descartadas:

- **k = 20** retiraria o CWE-094, categoria distinta e com n suficiente para
  leitura.
- **k = 6** acrescentaria CWE-116 (9), CWE-601 (7) e CWE-020 (6), com n
  pequeno demais para que uma taxa diga algo.

### Abaixo do limiar

**Nada é omitido.** A apuração publica todas as categorias, com acertos e
n, em `results/por-cwe/`. O limiar governa o que o texto discute, não o que
se publica.

Abaixo do limiar, o texto apresenta só contagens (acertos/n), sem
percentual. As categorias abaixo do limiar formam o grupo "outros", com 56
CVEs (55 com primário e o `CVE-2018-16472`), em 22 categorias. **O grupo não
recebe taxa agregada**: é heterogêneo, e uma taxa conjunta não descreveria
tipo de vulnerabilidade algum.

"Outros" é agrupamento de apresentação, não critério de casamento, e não
contraria a vedação de agrupamento por família (Decisão 39 da metodologia).
Pelo mesmo motivo, as categorias de negação de serviço por expressão
regular não se fundem: estão em CWE-400 (26, das quais `CVE-2017-16023` e
`CVE-2018-7560` são as exceções documentadas de injeção de expressão
regular), CWE-730 (3) e CWE-404 (1). No texto, o desempenho em ReDoS
corresponde essencialmente ao CWE-400, e isso é declarado.

### Incerteza

Para as seis categorias acima do limiar, cada taxa é acompanhada do
intervalo de Wilson de 95%, sem correção de continuidade, com z = 1,96,
como **descrição** da incerteza devida ao tamanho da categoria. Não é teste
de hipótese, e nenhuma comparação entre ferramentas ou categorias é
declarada significativa a partir dele. Abaixo do limiar não se calcula
intervalo.

### Expectativa declarada antes do número

Os conjuntos de CWE-079, CWE-116 e CWE-094 se sobrepõem, e os 8 CVEs do
conjunto `CWE-079|CWE-094|CWE-116` têm primário CWE-094. Espera-se que a
diferença entre as variantes generosa e estrita se concentre nessas
categorias. É expectativa registrada para ser confrontada, e não critério:
nenhuma regra da apuração depende dela.

### Composição e circularidade

A decomposição por categoria não resolve a confusão entre proveniência da
etiqueta e tipo de vulnerabilidade apontada na apuração da circularidade.
Na partição pela âncora `ec573b51`, entre as seis categorias acima do
limiar, o cruzamento categoria × herança tem as duas células populadas em
cinco, mas em três delas o grupo não herdado tem 1 ou 2 CVEs — CWE-022
(27/2), CWE-400 (24/2) e CWE-078 (24/1). Só CWE-079 (39/8) e CWE-094 (8/6)
têm mais de 2 CVEs em cada grupo, e mesmo ali o cruzamento serve no máximo
como ilustração. O CWE-915 é 0/23 na âncora e 22/1 na referência de
sensibilidade (`9ff6d68a`): é o maior recorte livre de etiqueta herdada sob
a âncora, e a propriedade depende dela.

---

## Registro de alterações

| Data | Commit | Seção | Alteração |
|---|---|---|---|
| 18/09/2026 | `9a91332` | todas | versão original |
| 18/09/2026 | `a1c9cfa` | §2 | o nível 0 passa a falar da árvore analisada, não do repositório |
| 18/09/2026 | `beac0b2` | §7 | o script lê o status nos 24 logs de lote versionados |
| 21/09/2026 | o desta entrada | §1, §6, §8 | emenda: o falso positivo existe, na versão corrigida e no ponto da falha. O trecho da §1 que afirmava a inexistência do negativo fica marcado como superado e preservado. §6 ganha nota de que os parágrafos sobre alertas fora do ponto continuam valendo. §8 registra o critério da versão corrigida como não fixado e as duas leituras possíveis. Datada do dia da descoberta; redigida e commitada em 22/09/2026 |
| 25/09/2026 | o desta entrada | §9 | seção nova: decomposição da detecção por categoria de CWE. Categoria é o `gt_cwe_primary` do CVE; limiar k = 10, fixado pela distribuição em `results/por-cwe/`, antes de qualquer número de detecção por categoria; grupo "outros" sem taxa agregada; intervalo de Wilson de 95% nas seis categorias acima do limiar |
