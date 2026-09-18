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
