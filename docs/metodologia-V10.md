# Metodologia e resultados — V10

**Comparação de abordagens SAST e DAST na detecção de vulnerabilidades em aplicações JavaScript/TypeScript**

Francisco Sales de Lima Junior

22 de setembro de 2026 — versão parcial: resultados SAST da campanha de detecção; campanha da versão corrigida, DAST e análise comparativa a preencher

---

## Nota sobre o estado deste documento

**A partir desta versão, o documento é de método e de resultados.** As versões
anteriores registravam apenas o protocolo experimental, e a nota de abertura da
Versão 9 afirmava que nenhum resultado de detecção era apresentado. Esta versão
revoga essa afirmação: além do protocolo, das decisões e de suas justificativas,
passa a apresentar os resultados das campanhas.

O estado de cada parte do estudo, nesta versão:

- **Campanha SAST de detecção — executada.** Rodou em 16 e 17 de setembro de
  2026, sobre os 223 CVEs do benchmark, nas três ferramentas, precedida do
  ensaio de fumaça de 16 de setembro (Seção 8). Seus resultados constam da
  Seção 9.
- **Campanha SAST da versão corrigida — a executar.** Mede o falso positivo e o
  verdadeiro negativo, na forma definida na Seção 7.3, e completa a matriz de
  confusão. Até ela existir, os resultados SAST são a metade positiva da matriz.
- **Campanha DAST — executada** em 24 de julho de 2026, com dados disponíveis e
  análise a fazer (Seções 6 e 10).
- **Análise comparativa entre as duas abordagens — a fazer** (Seção 11).

As seções marcadas como **a preencher** trazem a estrutura já fixada e o
conteúdo pendente. A versão só se fecha com as quatro partes concluídas.

**Método e resultado continuam separados, agora dentro do mesmo documento.**
Os critérios de cruzamento da campanha de detecção foram fixados em documento
versionado (`docs/criterios-cruzamento.md`) **antes** de qualquer número de
detecção existir, e o histórico do repositório comprova a ordem. As seções de
método descrevem o que foi decidido e quando; as de resultado, o que foi medido.
Nenhuma seção de método foi reescrita à luz do resultado sem registro da
alteração.

Os resultados de detecção dos dois ensaios — o local (Seção 8.6) e o de fumaça
(Seção 8.7) — **continuam descartados**. Os resultados apresentados são os da
campanha.

Todo número de resultado sai de artefato versionado e é reproduzível a partir
do repositório do estudo, que é público (Seção 5.5). Os procedimentos que
apuram a proveniência do ground truth integram o repositório desde setembro de
2026, sob `tools/ground-truth/`, com as saídas versionadas em
`results/proveniencia/`.

---

## Registro de alterações

### Versão 10

Esta versão muda a natureza do documento, que passa de método a **método e
resultados**, e incorpora a execução da campanha SAST de detecção, o ensaio de
fumaça que a precedeu, o cruzamento com o ground truth e a apuração da
circularidade da proveniência. Duas correções de método de alcance amplo: a
**matriz de confusão completa**, com falso positivo e verdadeiro negativo
definidos sobre a versão corrigida do código, o que exige uma segunda campanha;
e o **denominador de 220**, com a segunda baixa por commit inexistente.

**Numeração.** As seções 9, 10 e 11 da Versão 9 passam a 12, 13 e 14, para que
os resultados (novas Seções 9, 10 e 11) venham depois do método e as ameaças à
validade depois dos resultados. As remissões do corpo do texto foram
atualizadas. As dos registros das versões anteriores, abaixo, referem-se à
numeração da época e ficam como estavam.

| Seção | Tipo | Alteração |
|---|---|---|
| Nota | **Correção** | O documento passa a ser de método e resultados; revogada a afirmação de que nenhum resultado de detecção é apresentado. |
| 1.2 | Correção | "Desempenho" passa a significar a matriz completa no universo do benchmark, com o escopo declarado. |
| 2.2.1 | Acréscimo | Distribuição de extensões dos arquivos do ground truth. |
| 2.2.3, 7.4 | **Correção** | Segunda baixa por indisponibilidade de código, `CVE-2018-8035`, de commit inexistente; denominador de 221 para 220. |
| 3.1 | Correção | Imagens construídas uma vez e referenciadas por digest; o workflow de lote só as executa. |
| 4.3 | Acréscimo | A classe de commit fora de alcance prevista ocorreu; o fallback foi raro como previsto; a sondagem de 10/09 não precedeu imediatamente a campanha, e o denominador saiu da medição da própria campanha. |
| 4.4 | **Correção** | Limite de análise decidido em 900 s, pela assimetria da falha; limites sobrescrevíveis por ambiente; razão entre ambientes medida; tamanho de lote confirmado no escopo restrito. |
| 4.6 | Acréscimo | Pré-voo da imagem e portão de lote sem saída bruta. |
| 4.7 | Correção | Defeito do diretório pessoal medido com controle nas três imagens. |
| 5.5 | Acréscimo | Versionamento do cruzamento, da proveniência, da circularidade e dos artefatos da campanha; saídas determinísticas; cópia externa dos brutos. |
| 5.6 | Acréscimo | Premissa de custo da normalização medida; verificação dos programas de cruzamento. |
| 7.2, 7.4, 7.7 | **Correção** | Cinco níveis de acerto; casamento de linha por sobreposição; variantes generosa e estrita. |
| 7.3, 7.7 | **Correção** | Falso positivo e verdadeiro negativo definidos na versão corrigida; a definição de falso positivo da Versão 9 é abandonada. |
| 8.7, 8.8 | Acréscimo | Ensaio de fumaça e campanha de detecção. |
| 9 | Acréscimo | Resultados SAST da campanha de detecção e apuração da circularidade. |
| 10, 11 | Acréscimo | Estrutura das seções de resultados DAST e da análise comparativa, a preencher. |
| 12 | Acréscimo | Circularidade medida; limitações medidas na campanha; casos novos de método de medição. |
| 13 | Acréscimo | Decisões 73 a 90. |
| 14 | Correção | Pendências reescritas: resolvidas as verificações do ensaio de fumaça; novas pendências da versão corrigida, do Snyk Code e das promessas não cumpridas. |

### Versão 9

Esta versão incorpora a reconstrução, o versionamento e a reexecução do procedimento que apura a proveniência do ground truth. A reexecução, com o estado do catálogo fixado por commit em lugar de por data, **corrige o número de manchete do achado**: 163 de 223, e não 185. A hipótese sobrevive intacta e ganha evidência de ordem cronológica que a versão anterior não tinha.

| Seção | Tipo | Alteração |
|---|---|---|
| Nota, 2.2.2 | Acréscimo | Os procedimentos de proveniência passam a integrar o repositório; a condição de achado não reproduzível deixa de subsistir. |
| 2.2.2 | **Correção** | O cotejo contra o estado de referência dá **163 de 223 (73,1%)**, com 163 de 163 de identidade de conjunto. Os 185 registrados correspondem ao estado do catálogo dois dias posterior ao commit do release do benchmark. |
| 2.2.2 | Acréscimo | Estado de referência fixado por commit, com o critério declarado; sensibilidade do resultado à data de corte; achado de ordem cronológica e reescrita de rótulos pelo benchmark. |
| 2.2.2 | Correção | A divergência entre a documentação e a instância do benchmark, antes registrada como contemporânea e não explicada, é explicada pela reescrita de rótulos. |
| 4.4 | Acréscimo | Os limites de obtenção do código, isoladamente, não satisfazem a condição aritmética contra o teto do job; a decisão de manter o tamanho de lote passa a apoiar-se em comportamento medido, com sinal de vigilância próprio. |
| 4.6 | Acréscimo | O registro de execução passa a distinguir estouro de limite de recusa do servidor, e a contagem de recurso ao clone de contingência passa a existir como conferência. |
| 4.7 | Correção | O identificador de usuário do ambiente da campanha deixa de ser premissa e passa a medição datada. |
| 8.5 | Acréscimo | Os fluxos de trabalho passam a submeter-se à revisão prévia, por decisão fundada em defeito real. |
| 9.2 | Correção | Proporção da proveniência corrigida de 83% para 73,1% nas duas ocorrências. |
| 9.5 | Acréscimo | Registro da explicação refutada e da reincidência do padrão na própria revisão. |
| 10 | Acréscimo | Decisões 69 a 72. |
| 11 | Correção | Pendência do alcance do limite de tempo sobre a obtenção resolvida por inspeção e retirada. |

### Versão 8

Esta versão incorpora o exame de execuções anteriores no serviço de integração contínua, realizadas em julho de 2026 em série exploratória anterior à reconstrução do pipeline, e registra três decisões tomadas com o orientador. O teto de tempo por job, até aqui tratado como restrição prospectiva, passa a constar como restrição já observada, com o modo de falha que a produziu identificado. A correspondência entre séries pendente na versão anterior é computada a partir das fontes versionadas.

| Seção | Tipo | Alteração |
|---|---|---|
| Nota, 5.5, 11 | Correção | O repositório do estudo foi publicado em acesso público; a limitação de cópia local única deixa de subsistir. |
| 4.4 | Acréscimo | O teto agregado do job já interrompeu execuções deste estudo; modo de falha identificado como item individual que não termina, e fronteira do que a observação estabelece. |
| 5.5 | Precisão | Retenção dos artefatos temporários do serviço de integração contínua. |
| 6.1, 9.3 | Correção | A correspondência entre relatório e modo da campanha DAST passa a constar de documento próprio, estabelecida em duas unidades de contagem e confirmada por evidência independente da contagem. |
| 8.6 | Correção | A correspondência entre as duas séries do ensaio local é computada a partir das fontes versionadas; os quatro pares ficam determinados. |
| 9.4 | Correção | A mitigação por alvo comum é descartada por ausência de gabarito nas aplicações da campanha DAST; a limitação permanece declarada e não mitigada. |
| 9.5 | Acréscimo | Registro de nova reincidência do padrão entre documentos, e generalização: resultado vazio exige distinguir ausência de pergunta mal formulada. |
| 10 | Acréscimo | Decisões 65 a 68. |
| 11 | Correção | Três pendências resolvidas e retiradas: manutenção do NodeGoat, execução de SAST sobre as aplicações DAST e espelhamento do repositório. Acrescida a verificação do alcance do limite de tempo sobre a obtenção do código. |

### Versão 7

Esta versão incorpora o ensaio local do pipeline reconstruído, executado em setembro de 2026 sobre o lote de teste de cinco CVEs (Seção 8.6). Duas decisões da versão 6 são revertidas por medição — a indeterminação da varredura de arquivo no CodeQL e o indicador heurístico de menção ao arquivo do ground truth —, e a assimetria entre ferramentas declarada na versão anterior inverte-se. As demais alterações são acréscimos e precisões.

| Seção | Tipo | Alteração |
|---|---|---|
| 2.2.3 | Precisão | Boa formação do identificador de commit não implica que o objeto referido seja um commit. |
| 4.3 | Acréscimo | Asserção do commit exercitada com divergência real, e o caso que a motiva independentemente do defeito da campanha preliminar. |
| 4.4 | Correção | Idempotência declarada inerte no ambiente da campanha, onde a saída bruta não persiste entre execuções. |
| 4.4 | Correção | Dimensionamento de lote reformulado: a projeção de duração é piso frouxo, não previsão, e a concordância com a campanha preliminar não é tomada como corroboração. |
| 4.4 | Acréscimo | Relação entre o limite de tempo por invocação e o teto agregado do job; o valor corrente do limite declarado provisório. |
| 4.5 | Acréscimo | Legibilidade das consultas precompiladas do bundle do CodeQL sob identificador de usuário do hospedeiro; orçamento de memória próprio do extrator; verificação do extrator de TypeScript. |
| 4.5 | Correção | O inventário de regras do Semgrep enumera regras **aplicadas**, não carregadas; campo do schema renomeado em consequência. Execução sem rede confirmada. |
| 4.5 | Correção | Custo da incorporação do conjunto de regras sob construção única da imagem, e novo papel da segunda comparação de resumo. |
| 4.6 | Acréscimo | Efeito da ausência de material analisável sobre o denominador, com os três resultados possíveis declarados antes da execução, e forma de verificação do tratamento. |
| 4.5 | Acréscimo | Forma da saída do Snyk Code em análise sem achados e do seu inventário de cobertura, medidas. |
| 4.7 | Acréscimo | Segundo defeito de permissão, de sinal invertido em relação ao primeiro. |
| 5.2 | Correção | Varredura do arquivo do ground truth passa a ser decidida também no CodeQL; a indeterminação remanescente é do Snyk Code. Motivo do estado declarado nos três estados. Eliminado o indicador heurístico de menção. Coordenada de coluna acrescida aos achados e à chave de ordenação. Campo de inventário de regras renomeado. |
| 5.3 | Correção | Chave de ordenação total, com a coordenada de coluna. |
| 5.6 | Correção | Parte das fixtures passa a derivar de saída real, reduzindo a lacuna declarada. |
| 8.5 | Acréscimo | Terceira rodada de revisão, e um caso em que a revisão incidiu sobre código já commitado. |
| 8.6 | Acréscimo | Nova seção: ensaio local do pipeline, com a confrontação dos formatos declarados contra saída real. |
| 9.1 | Correção | A ameaça relativa à origem documental das fixtures é reduzida, não eliminada. Acrescida a ameaça de ambiente do ensaio local. |
| 9.1 | Correção | Duas ameaças resolvidas: verificação do CodeQL em versão adjacente e variação das imagens base entre reconstruções. |
| 9.2 | Acréscimo | Denominadores de arquivo considerado não são comparáveis entre as ferramentas. |
| 9.5 | Acréscimo | Quarto e quinto episódios: assinatura de encerramento de processo lida como causa que não estabelece; análise de correspondência entre duas listas cuja ordem foi inferida, não declarada. Registro da reincidência do padrão entre documentos. |
| 10 | Acréscimo | Decisões 58 a 64. |
| 11 | Correção | Seis verificações do ensaio de fumaça resolvidas pelo ensaio local e retiradas; acrescidas as que o ensaio local não pode responder. Retirada a verificação de ausência de material analisável, remetida à Seção 4.6; pendência de limite de tempo reformulada. |

### Versão 6

Esta versão incorpora o que a construção e a revisão da etapa de normalização estabeleceram por medição, em setembro de 2026. Nenhuma decisão metodológica da versão 5 foi revertida; as alterações são acréscimos, precisões e a correção de duas inconsistências internas do documento.

| Seção | Tipo | Alteração |
|---|---|---|
| 2.2.1 | Acréscimo | Registro do caminho de arquivo fora de forma canônica na caracterização estrutural. |
| 2.2.3 | Acréscimo | `CVE-2019-12041` declara caminho de arquivo absoluto no próprio benchmark. Vínculo explícito com os catorze identificadores de CWE sem zero à esquerda: são o mesmo tipo de defeito, e a regra de normalização do ground truth passa a ser geral. |
| 4.5 | Correção | Forma de incorporação do conjunto de regras do Semgrep à imagem: cópia no momento da construção, não montagem em tempo de execução — alinhando a prosa à Decisão 41, que a versão anterior contrariava. |
| 4.5 | Acréscimo | Reconciliação do vocabulário de severidade do conjunto vendorizado, com a causa da divergência entre contagem por analisador e contagem por expressão regular. Item do ensaio de fumaça quanto ao inventário de regras carregadas, com consequência declarada. |
| 4.6 | Acréscimo | Quarta conferência do registro de execução, contra a lista do lote executado. |
| 4.7 | Acréscimo | Nova subseção: execução dos containers sob o identificador de usuário do hospedeiro, com diretório pessoal explícito. Decisão por medição. |
| 5.1 | Acréscimo | Independência do programa de normalização em relação ao registro de execução, declarada como propriedade do protocolo e não como detalhe de implementação. Conferidor do registro em programa próprio. |
| 5.2 | Correção | O exemplo do schema passa a exibir o campo de conjunto de regras como estrutura, corrigindo divergência entre o exemplo e a prosa na versão anterior. |
| 5.2 | Acréscimo | Campos acrescidos ao schema: versão do schema, origem da data de análise, varredura do arquivo do ground truth e seu motivo, valor original do caminho do ground truth, diagnósticos da ferramenta, e identidade secundária do conjunto de regras. |
| 5.3 | Correção | A normalização do ground truth deixa de valer apenas para identificadores de CWE e passa a valer também para caminhos de arquivo. Falha alta em saída bruta ilegível. |
| 5.4 | Correção | Estado próprio para severidade não resolvida por junção, distinto da ausência legítima de nível. |
| 5.5 | Acréscimo | Fixtures sintéticas, relatório de normalização e programa de conferência incorporados à política de versionamento. |
| 5.6 | Acréscimo | Nova subseção: verificação da normalização por fixtures sintéticas, com declaração das lacunas de cobertura. |
| 8.5 | Acréscimo | Segunda rodada de revisão, sobre a etapa de normalização: resultado, defeito de maior consequência e limitação reiterada. |
| 9.1 | Acréscimo | Nova ameaça: o schema de normalização foi construído contra a documentação das saídas, não contra saída real. |
| 9.5 | Acréscimo | Nova subseção: confiabilidade dos métodos de contagem e verificação empregados no próprio estudo. |
| 10 | Acréscimo | Decisões 48 a 57. |
| 11 | Correção | Pendências atualizadas; acrescentadas as verificações do ensaio de fumaça, com consequência declarada para cada uma. |

### Versão 5

Esta versão incorpora o que a construção e a revisão do pipeline SAST estabeleceram por medição, em setembro de 2026. Nenhuma decisão metodológica da versão 4 foi revertida; as alterações são acréscimos e precisões.

| Seção | Tipo | Alteração |
|---|---|---|
| 2.2.3 | Acréscimo | Indisponibilidade do repositório de um CVE, verificada por sondagem dos 186 repositórios. |
| 4.3 | Acréscimo | Comportamento medido do fetch raso e do clone de fallback; asserção do commit analisado; sondagem prévia de disponibilidade. |
| 4.5 | Correção | Contagem de regras do `p/default` corrigida de 1.073 para 1.074, com a causa da divergência. Registro da ordem não determinística do arquivo servido pelo registry e da identidade secundária adotada. Verificação empírica do modo de construção do banco de dados do CodeQL. |
| 4.6 | Acréscimo | Conjunto completo de estados do registro de execução, incluindo o estado de ausência de material analisável. Escrita atômica da saída bruta. |
| 5.2 | Correção | Campo de CWE primário renomeado para `gt_cwe_primary`. Campo de conjunto de regras passa de cadeia descritiva a estrutura, com preenchimento declarado por ferramenta. |
| 6.1 | Acréscimo | Relatórios do ZAP versionados no repositório; contagens reproduzidas a partir deles e correspondência entre arquivo e modo estabelecida por contagem, não por nomenclatura. |
| 7.4 | Correção | Denominador da matriz de confusão passa de 222 para 221 registros. |
| 8.5 | Acréscimo | Nova subseção: revisão do pipeline por checklist derivado dos defeitos da campanha invalidada. |
| 9.1 | Acréscimo | Duas ameaças à reprodutibilidade: ordem não determinística do arquivo de regras e verificação do CodeQL feita em versão adjacente à empregada. |
| 9.2 | Correção | Disponibilidade dos commits deixa de ser risco enunciado e passa a ocorrência medida. Subjetividade do mapeamento de CWE primário ganha a observação de que sua evidência principal herda a proveniência do CodeQL. |
| 10 | Acréscimo | Decisões 41 a 47. |

### Versão 4

Esta versão incorpora a caracterização do ground truth do OpenSSF CVE Benchmark realizada em setembro de 2026.

| Seção | Tipo | Alteração |
|---|---|---|
| 2.2 | Correção | A descrição das características do ground truth foi refeita. A afirmação de que o campo CWEs é multivalorado permanece, mas sua interpretação muda: os múltiplos CWEs não descrevem defeitos distintos. |
| 2.2.1 | Acréscimo | Nova subseção com a caracterização estrutural medida. |
| 2.2.2 | Acréscimo | Nova subseção sobre a proveniência do ground truth. |
| 7.1 | Correção | A discussão sobre famílias de identificadores foi reescrita: não é convenção de rotulagem das ferramentas, é herança das tags da consulta que originou o registro. |
| 7.2 | Correção | Registrada a constatação de que a dimensão de arquivo é degenerada no conjunto. |
| 7.4 | Correção | Substituída a decisão de expandir CVEs multivalorados em n registros independentes. Adota-se dupla apuração. |
| 9.2 | Acréscimo | Duas ameaças à validade decorrentes da proveniência do ground truth. |
| 10 | Correção | Decisão 32 substituída. Acrescentadas as decisões 37 a 40. |
| 11 | Correção | Removida a pendência relativa ao critério de agrupamento por família de CWE, agora resolvida. |

---

## 1. Desenho do estudo

### 1.1 Objetivo

Comparar abordagens de análise estática (SAST) e análise dinâmica (DAST) na detecção de vulnerabilidades em aplicações JavaScript e TypeScript, discutindo capacidades, limitações e complementaridade de cada uma.

### 1.2 Perguntas de pesquisa

- Que categorias de vulnerabilidade cada abordagem é capaz de detectar na prática?
- Qual o desempenho de cada ferramenta quando confrontada com um conjunto de vulnerabilidades conhecidas (ground truth)?
- Em que medida as duas abordagens se sobrepõem, e em que medida se complementam?

**Escopo de "desempenho" na segunda pergunta.** Desempenho é medido pela matriz de confusão no universo que o benchmark define — um ponto vulnerável e um ponto corrigido por CVE (Seção 7.3). Não é o desempenho sobre todos os alertas que cada ferramenta emite, que o conjunto não permite classificar (Seção 7.3). Até a campanha da versão corrigida, a resposta cobre a metade positiva da matriz: a detecção.

### 1.3 Justificativa do uso de benchmarks distintos

O estudo emprega conjuntos de dados diferentes para cada abordagem. Essa escolha não é arbitrária: decorre de uma restrição estrutural verificada empiricamente.

O OpenSSF CVE Benchmark reúne 223 CVEs reais de JavaScript e TypeScript, com CWE e localização de arquivo mapeados por CVE. É, portanto, adequado para avaliar ferramentas SAST, que operam sobre código-fonte estático.

A análise DAST, contudo, exige uma aplicação em execução, acessível por URL. Investigou-se a viabilidade de usar o OpenSSF também para o lado dinâmico, por meio de um processo de cherry picking com validação via Docker. O resultado foi conclusivo: apenas 2 dos 223 repositórios são aplicações web efetivamente implantáveis. Os demais são majoritariamente pacotes npm — bibliotecas utilitárias sem interface HTTP.

Esse achado, além de justificar a adoção de benchmarks especializados, é tratado como contribuição metodológica do trabalho: evidencia empiricamente que o OpenSSF CVE Benchmark foi concebido para avaliação estática e não é transponível para avaliação dinâmica. A caracterização apresentada na Seção 2.2.2 converge para a mesma conclusão por outro caminho.

Para o lado DAST adotaram-se, portanto, aplicações intencionalmente vulneráveis mantidas pela OWASP: o OWASP Juice Shop e o OWASP NodeGoat.

---

## 2. Materiais

### 2.1 Ferramentas sob avaliação

| Ferramenta | Abordagem | Modelo de execução |
|---|---|---|
| CodeQL | SAST | Local, em container |
| Semgrep | SAST | Local, em container |
| Snyk Code | SAST | Local, com envio ao serviço da Snyk |
| OWASP ZAP | DAST | Local, contra aplicação em execução |

Registra-se que o Snyk Code transmite o código analisado ao backend da Snyk, diferentemente do CodeQL e do Semgrep, que operam integralmente na máquina de execução. Essa diferença tem implicações de dependência externa e de disponibilidade de serviço, declaradas na Seção 12.

O escopo do estudo restringe-se a SAST e DAST. Não foi realizada análise de composição de software (SCA); o Snyk Code é empregado exclusivamente em sua capacidade SAST.

### 2.2 Ground truth SAST — OpenSSF CVE Benchmark

Fonte: `github.com/ossf-cve-benchmark/ossf-cve-benchmark`

O ground truth não é um arquivo único. Distribui-se em um arquivo JSON por CVE, no diretório `CVEs/` da raiz do repositório. Cada arquivo declara o identificador do CVE, o repositório, o commit anterior e o posterior à correção, uma lista de weaknesses — cada qual com arquivo, linha e uma descrição textual — e uma lista de CWEs atribuídos ao CVE.

Os metadados foram consolidados em um arquivo tabular com a seguinte estrutura:

| Campo | Descrição |
|---|---|
| CVE | Identificador do CVE |
| Repository | URL do repositório |
| PrePatchCommit | Commit anterior à correção (código vulnerável) |
| PostPatchCommit | Commit imediatamente posterior à correção |
| CWEs | Um ou mais CWEs atribuídos ao CVE |
| Explanation | Descrição textual da vulnerabilidade |
| FilePath | Caminho do arquivo vulnerável |
| FileLine | Linha da vulnerabilidade no arquivo |

O conjunto compreende 223 CVEs, distribuídos por 186 repositórios distintos e 38 CWEs distintos após normalização.

Registra-se uma distinção que a estrutura do arquivo torna necessária: a lista de CWEs é declarada no nível do CVE, ao passo que a localização é declarada no nível da weakness. Os dois níveis não são ligados entre si. A Seção 2.2.1 examina a consequência dessa separação, e a Seção 2.2.2 identifica sua origem.

#### 2.2.1 Caracterização estrutural

Procedeu-se, em setembro de 2026, à medição direta da estrutura do conjunto, sobre os 223 arquivos JSON. Os resultados condicionam o protocolo de análise comparativa.

| Característica medida | Resultado |
|---|---|
| CVEs no conjunto | 223 |
| CVEs que apontam exatamente um arquivo | 223 (a totalidade) |
| Weaknesses (localizações) no conjunto | 233 |
| CVEs com mais de uma weakness | 3 (todas no mesmo arquivo) |
| CVEs com um único CWE atribuído | 57 |
| CVEs com mais de um CWE atribuído | 165 (74,0%) |
| CVEs sem CWE atribuído | 1 |
| Pares (CWE, arquivo) efetivamente afirmados | 222 |
| Pares gerados por expansão cartesiana | 534 (+140,5%) |
| CVEs com identificador de CWE sem zero à esquerda | 14 |
| CVEs com caminho de arquivo fora de forma canônica | 1 |

**A dimensão de arquivo é degenerada.** Cada CVE do conjunto mapeia exatamente um arquivo. Três CVEs — `CVE-2018-3725`, `CVE-2021-23364` e `CVE-2021-31712` — registram mais de uma weakness, mas todas apontam para o mesmo arquivo, com descrição idêntica e um único conjunto de CWEs: são múltiplos pontos da mesma vulnerabilidade, e não vulnerabilidades distintas. Em consequência, o par (CWE, arquivo) equivale ao par (CWE, CVE): o arquivo é função do CVE e não acrescenta poder discriminante. A escolha da unidade da matriz de confusão, discutida na Seção 7.2, permanece justificada pelos motivos ali expostos, mas não implica perda de granularidade em relação ao par (CWE, CVE).

**A multiplicidade de CWEs não corresponde a multiplicidade de defeitos.** Em 165 dos 223 casos há mais de um CWE atribuído a um defeito único, localizado em um único ponto de um único arquivo. O `CVE-2020-8203`, do lodash, exemplifica a situação: registra uma weakness — uma função sujeita a poluição de protótipo, na linha 2559 de `lodash.js` — e cinco CWEs, dos quais apenas o CWE-915 descreve o defeito presente no código. Os demais correspondem a consequências potenciais da exploração, não a construções identificáveis naquele ponto.

**Os conjuntos de CWE se repetem literalmente entre CVEs distintos.** Os 165 casos multivalorados distribuem-se em apenas 17 conjuntos distintos, dos quais os cinco maiores cobrem 136 CVEs (82,4%). A repetição exata de conjuntos entre CVEs sem relação entre si indica atribuição por procedimento uniforme, e não por exame individual de cada caso — o que a Seção 2.2.2 confirma.

**A inconsistência de formatação está no próprio ground truth.** Quatorze CVEs registram identificadores sem zero à esquerda (`CWE-79` em lugar de `CWE-079`) e um registra caminho de arquivo em forma absoluta (Seção 2.2.3). A normalização prevista na Seção 5.3 aplica-se, portanto, também ao ground truth, e não apenas às saídas das ferramentas — em identificadores **e** em caminhos.

**Os 223 CVEs vêm de 186 repositórios.** A maioria dos repositórios contribui com um CVE; alguns com vários — o Bootstrap com 7, o Lodash com 5, o jQuery e o Rendertron com 4, o Next.js com 3. Os quatro CVEs do Rendertron apontam para o mesmo commit.

**Distribuição de extensões do arquivo do ground truth**, apurada por programa sobre os 223 registros em setembro de 2026 (`tools/extensoes.py`):

| Extensão | CVEs |
|---|---:|
| `.js` | 202 |
| `.ts` | 12 |
| sem extensão | 5 |
| `.jsx` | 2 |
| `.mjs` | 1 |
| `.yaml` | 1 |

Os cinco arquivos sem extensão são `bin/public` (`CVE-2018-16480`, `CVE-2018-3731`, `CVE-2018-3747`) e `bin/http-live` (`CVE-2018-16479`, `CVE-2019-5423`). Nenhum dos 12 arquivos TypeScript é arquivo de declaração (`.d.ts`). O único `.yaml` é o `regexes.yaml` do `CVE-2018-20164`, cuja vulnerabilidade é uma expressão regular sujeita a negação de serviço.

#### 2.2.2 Proveniência do ground truth

A repetição literal de conjuntos de CWE descrita na subseção anterior motivou a investigação de sua origem. A hipótese examinada foi a de que os rótulos do ground truth derivassem do catálogo de consultas de uma das ferramentas integradas ao benchmark, e não de classificação independente de cada CVE.

**Método.** O campo de descrição textual de cada weakness foi cotejado, após normalização tipográfica, com o campo `@name` das consultas do pacote JavaScript do CodeQL. Para os casos correspondentes, comparou-se o conjunto de CWEs do ground truth com as tags `external/cwe/` declaradas no cabeçalho da própria consulta. O critério de correspondência é de **igualdade**, exata ou normalizada, nunca de subcadeia: subcadeia mede vocabulário compartilhado, e não herança de rótulo. Identificadores de CWE são normalizados para três dígitos **dos dois lados**.

**O procedimento integra o repositório desde setembro de 2026**, sob `tools/ground-truth/`, e obtém cada catálogo em estado fixado por commit, sem depender de cópia local de quem apurou. Um descritor versionado registra cada commit, sua data e o critério pelo qual foi escolhido; nenhum valor é digitado duas vezes, e toda contagem aqui reproduzida provém da saída dos programas.

**Estado de referência.** O cotejo é apurado contra o **último estado do catálogo integrado ao ramo principal anterior ao commit do release do benchmark**. O critério decorre da própria hipótese: para que o rótulo tenha sido herdado, a consulta que o origina precisa existir antes dele. A referência é, por construção, contagem conservadora — não credita como herança rótulo que corresponda a código ainda não integrado.

A reexecução do procedimento sobre esse estado **corrigiu o resultado registrado nas versões anteriores deste documento**, que não distinguia estados do catálogo dentro do mesmo mês.

| Verificação | Resultado |
|---|---|
| Descrições idênticas ao campo `@name` de consulta do CodeQL, no estado de referência | **163 de 223 (73,1%)** |
| Destas, com conjunto de CWEs idêntico às tags da consulta | **163 de 163 (100%)** |
| Divergências não explicadas | 0 |

**Sensibilidade à data de corte.** O número depende do estado do catálogo, e a dependência é inteiramente atribuível a um conjunto nomeado de casos:

| Estado do catálogo | Correspondências | Identidade de conjunto |
|---|---|---|
| Referência — último estado integrado antes do commit do release | 163 de 223 | 163 de 163 |
| Estado integrado dois dias depois do commit do release | 185 de 223 | 185 de 185 |
| Estado atual do catálogo | 185 de 223 | 108 idênticos, 74 subconjuntos, 3 divergentes |

A diferença entre as duas primeiras linhas são **22 CVEs de poluição de protótipo**, e nenhum outro: os 163 restantes correspondem às mesmas consultas nos dois estados, sem alteração de relação. O estado intermediário é o primeiro do ramo principal a conter a consulta sob o nome e as tags que o ground truth registra — nome e tags que a consulta preexistente adquiriu por renomeação, e não por criação (a identidade interna da consulta é a mesma nos dois estados).

**A tabela registrada nas versões anteriores deste documento corresponde ao estado intermediário**, linha a linha, inclusive no número de registros sem correspondência. A correção consiste em adotar o estado que satisfaz o critério de anterioridade, e em reportar o outro como medida de sensibilidade.

O cotejo contra o estado atual do repositório de consultas produz 108 correspondências exatas, 74 casos em que o conjunto do ground truth é subconjunto próprio das tags atuais e 3 divergências. As três situações resolvem-se pela evolução posterior do catálogo: a consulta `js/clear-text-logging`, por exemplo, declarava as tags `cwe-312`, `cwe-315` e `cwe-359` em dezembro de 2020 — exatamente o conjunto registrado no ground truth — e declara hoje `cwe-312`, `cwe-359` e `cwe-532`.

A divisão entre subconjuntos e divergências depende de uma convenção declarada: conjunto **vazio** confrontado com consulta que declara tags é computado como divergência, e não como subconjunto, embora o vazio seja subconjunto de todo conjunto — ausência de rótulo não é concordância parcial. Sob a convenção oposta os mesmos dados dariam 108, 75 e 2, que é a leitura registrada nas versões anteriores. O programa imprime as duas contagens.

**Controle.** O mesmo cotejo foi aplicado ao catálogo de regras do Semgrep, com o propósito de verificar se as descrições constituiriam vocabulário corrente da área em lugar de nomenclatura de uma ferramenta específica. Contra 2.228 regras, a correspondência exata é nula. Um critério deliberadamente frouxo — presença da descrição como subcadeia em alguma mensagem de regra — produz 17,0%, valor que o exame dos casos atribui à ocorrência de termos genéricos como injeção de código e cross-site scripting no interior de descrições relativas a outros defeitos, e não a coincidência de rótulo.

**Interpretação.** O ground truth do OpenSSF CVE Benchmark não foi construído por classificação independente dos CVEs. Em 73,1% do conjunto, a descrição e os CWEs foram herdados da consulta do CodeQL que identificou o caso, e a identidade de conjunto é total nos casos correspondentes: não há um só em que a descrição coincida com o nome de uma consulta e o conjunto de CWEs difira das tags daquela consulta. Os registros restantes dividem-se entre descrições em prosa, específicas do caso e redigidas manualmente, e os 22 casos de poluição de protótipo tratados adiante — o que indica mais de uma camada de proveniência no conjunto.

#### 2.2.2.1 Ordem cronológica e reescrita de rótulos

A apuração do estado de referência tornou possível examinar a **ordem** entre a existência da consulta e o registro do rótulo, e não apenas a coincidência entre os dois. O exame incidiu sobre os 22 casos de poluição de protótipo, que são exatamente aqueles em que os dois estados do catálogo divergem.

**Primeiro elemento — o estado do catálogo que os rótulos reproduzem não estava integrado ao ramo principal no momento do commit do release.** A consulta correspondente encontrava-se, então, em proposta de alteração **aberta e pública**, originada de bifurcação igualmente pública, submetida cinco dias antes do commit do release e integrada dois dias depois dele. O conjunto completo de tags que o ground truth registra passou a constar daquela proposta em janela cujo limite superior é estabelecido por objeto criado pelo próprio servidor da plataforma, e portanto independente do relógio de quem submeteu — poucas horas antes do commit do release.

**Segundo elemento — o benchmark reescreveu os rótulos.** Recuperou-se o estado do conjunto anterior ao commit do release, alcançável pelo histórico que a importação achatada não preserva mas que permanece acessível por identificador. Naquele estado, os mesmos CVEs de poluição de protótipo registram a descrição e as tags da consulta **como ela constava do ramo principal**; no commit do release, registram as da mesma consulta **como ela constava da proposta**. Em um dos casos a descrição em prosa permanece idêntica e apenas o conjunto de CWEs se altera, do conjunto antigo para o novo.

Cotejado contra o estado do ramo principal que o antecede, o estado anterior do benchmark apresenta a mesma identidade total de conjunto: 181 correspondências, 181 idênticas.

**Leitura.** Em ambos os momentos, o estado da consulta precede o rótulo. A direção é, portanto, a de herança, e não a de coincidência de nomenclatura: o conjunto acompanhou a evolução da consulta durante a semana que antecedeu sua publicação.

**O que não se estabelece.** De onde os autores do conjunto obtiveram o estado da proposta — da proposta pública ou de cópia própria; se o estado anterior do conjunto era público; e a hora de **publicação** do release, da qual se conhece apenas a data do commit, gravada pelo cliente.

**Consequência sobre a divergência documental.** A discrepância entre a especificação do benchmark e o arquivo de dados distribuído, registrada adiante e descrita nas versões anteriores como contemporânea e não explicada, passa a ter explicação: a especificação registra a descrição e o identificador da consulta **no estado anterior**, e o arquivo de dados, os do estado da proposta. Os dois arquivos entraram no mesmo release porque a reescrita alcançou o arquivo de dados e não alcançou a documentação.

**Evidência documental corroborante.** O arquivo `docs/benchmark-CVEs.md`, que especifica o formato dos registros, emprega o `CVE-2020-8203` como exemplo canônico. A instância ali apresentada difere da efetivamente distribuída no diretório `CVEs/`, para o mesmo CVE, no mesmo commit e na mesma linha: a documentação registra a descrição em prosa "Prototype pollution in utility function" e um único identificador, CWE-471; o arquivo de dados registra a descrição "Prototype-polluting function" — nome de consulta do CodeQL — e cinco identificadores, entre os quais o CWE-471 não figura. A discrepância entre a especificação e a instância é contemporânea: ambos os arquivos foram introduzidos no mesmo release.

Registra-se que a documentação do benchmark não declara, em nenhum ponto, a origem dos valores do campo CWEs. O CodeQL é ali apresentado como uma das três ferramentas cuja avaliação o benchmark suporta, em paridade com ESLint e NodeJSScan.

**Limitação de rastreabilidade.** O repositório do benchmark contém 88 commits, o mais antigo dos quais é o release 1.0.0, de 22 de setembro de 2020. Trata-se de importação achatada: o histórico anterior à publicação não está disponível, e o arquivo de dados do CVE examinado não sofreu alteração posterior. Em consequência, o processo de construção do conjunto não pode ser reconstituído a partir do repositório, e a inferência sobre proveniência apoia-se no cruzamento sistemático descrito acima, não em evidência cronológica.

Não se localizou, na literatura consultada, registro dessa característica. Trabalhos que estendem o benchmark observaram limitações vizinhas — a omissão, no relatório, de CWEs não detectados por nenhuma das ferramentas selecionadas, e a inadequação da granularidade de linha a analisadores que reportam em nível de método ou bloco —, mas sem identificar a origem dos rótulos.

Essa constatação não desqualifica o benchmark, cuja utilidade para avaliação de ferramentas estáticas permanece. Ela delimita o que a comparação mede, e por isso é declarada entre as ameaças à validade (Seção 12.2) e incorporada ao protocolo de análise (Seções 7.1 e 7.4).

Registra-se, como subproduto de interesse para reprodutibilidade, que o procedimento fornece meio de recuperar o CWE pretendido pelo benchmark para qualquer CVE do núcleo: basta consultar as tags da respectiva consulta no estado de referência fixado pelo descritor.

**Limitação de reprodução, declarada.** Não está estabelecido, e não há como estabelecer, qual estado do catálogo a apuração **original** empregou: ela não deixou programa em arquivo nem registro do commit consultado. Os programas auxiliares encontrados junto ao conjunto de dados foram lidos integralmente e não são o cotejo — leem apenas os arquivos do benchmark e não consultam catálogo algum. O procedimento ora versionado é reprodução do método descrito, com o estado fixado pelo critério declarado acima, e não reconstituição do que se fez então.

#### 2.2.3 Defeitos conhecidos do conjunto de dados

Registram-se as inconsistências identificadas durante a preparação:

- **`CVE-2018-1000096` não possui CWE atribuído.** O CVE é analisado normalmente, mas fica fora das contagens da matriz de confusão (Seção 7.4).

- **`CVE-2017-18352` e `CVE-2018-11093` possuem `PostPatchCommit` malformado** no benchmark original da OpenSSF — respectivamente truncado em 38 caracteres e registrado em forma abreviada de 7 caracteres. O defeito é do benchmark, não da extração. A campanha de detecção emprega apenas o `PrePatchCommit` e não foi afetada; o gerador de listas emite aviso não bloqueante sobre a ocorrência e não emite o campo.

  **O defeito passa a afetar a campanha da versão corrigida** (Seção 7.3), que roda sobre o `PostPatchCommit`. O pipeline pressupõe identificador completo: a obtenção rasa é por SHA, e a asserção compara o `HEAD` com o valor da lista. A resolução — expandir o identificador abreviado pelo próprio repositório, se o prefixo for único, ou excluir o CVE com motivo declarado — integra o desenho daquela campanha e não está tomada.

- **`CVE-2019-12041` declara caminho de arquivo em forma absoluta.** O campo `FilePath` registra `/index.js`, com barra inicial, no próprio benchmark da OpenSSF; o arquivo é `index.js` na raiz do repositório. É o único caso entre os 223, verificado contra dezoito critérios de anomalia — barra inicial, prefixo relativo, referência a diretório anterior, barra invertida, esquema de protocolo, caminho vazio ou composto apenas de espaços, espaços em posição inicial, final ou interna, barra dupla, barra final, segmento isolado, expansão de diretório pessoal, letra de unidade, caractere de controle, caractere fora de ASCII e vírgula.

  O tratamento é dado na normalização (Seção 5.3): a barra é removida do valor do ground truth, o valor original é preservado em campo próprio e a ocorrência é registrada. Sem isso, a verificação de varredura do arquivo (Seção 5.2) compararia o caminho do ground truth contra um valor que ferramenta alguma emite, e o CVE seria computado como falso negativo sem que erro algum se manifestasse.

  A remoção vale **apenas para o ground truth**. Caminho absoluto emitido por uma **ferramenta** tem significado oposto: sinaliza que a premissa de invocação a partir do diretório de trabalho não se sustentou, e é preservado e reportado, nunca corrigido em silêncio.

  Este defeito e o dos catorze identificadores sem zero à esquerda são **o mesmo tipo de ocorrência**: o benchmark grava um valor fora de forma canônica, e a comparação sem normalização prévia produz divergência silenciosa. A regra decorrente é geral e consta da Seção 5.3 — o ground truth é normalizado antes de qualquer comparação, em identificadores e em caminhos. Ambos são detectados na geração das listas, por aviso não bloqueante, e corrigidos na normalização; em nenhum caso a lista de entrada é editada.

- **Sete CVEs de "Zip Slip" contêm aspas no campo `Explanation`.** O arquivo tabular consolidado é RFC 4180 válido: aspas internas são escapadas por duplicação.

- **`CVE-2017-16114` e `CVE-2017-17461`** incidem sobre o mesmo repositório e o mesmo arquivo, em linhas adjacentes (459 e 460). Como cada CVE é analisado em seu próprio commit, não há colisão na execução. A proximidade seria relevante apenas se os resultados fossem agregados entre CVEs; o cruzamento os apura um a um, pelo critério de linha da Seção 7.7.

- **O repositório `linxiaowu66/swagger-ui`, associado ao `CVE-2016-1000229`, não está mais disponível.** A sondagem dos 186 repositórios do conjunto, realizada em 6 de setembro de 2026, obteve 185 alcançáveis e um inacessível, com resposta de repositório inexistente. O defeito não é do benchmark nem da extração: o repositório existia quando o conjunto foi construído. A sondagem de 10 de setembro de 2026 e a campanha de detecção confirmaram a inacessibilidade. O tratamento está na Seção 7.4 e a limitação, na Seção 12.2.

  Registra-se a coincidência: o repositório desaparecido é justamente um dos dois homônimos — `linxiaowu66/swagger-ui` e `swagger-api/swagger-ui` — cuja existência motivou a regra de nomear as saídas pelo identificador do CVE (Seção 4.1). O par que fundamentou a regra reduziu-se a um elemento, sem que isso a torne dispensável: a sobrescrita entre CVEs do mesmo repositório permanece, e é o motivo principal.

- **O commit declarado pelo `CVE-2018-8035` não existe no repositório.** Medido na campanha de detecção, em 17 de setembro de 2026, nas três ferramentas: em `apache/uima-ducc`, a obtenção rasa foi recusada pelo servidor (`upload-pack: not our ref`), o clone completo foi bem-sucedido, e o checkout falhou com `reference is not a tree` — o commit `4c20c4fc…` que o benchmark declara não está no repositório. O identificador é SHA-1 completo e bem formado; o objeto é que está ausente.

  É a segunda baixa por indisponibilidade de código, e difere da primeira: o repositório existe, e a sondagem de repositório o dá como acessível (Seção 4.3). A classe corresponde à prevista na Seção 4.3 — commit fora do alcance dos dois mecanismos de obtenção. O tratamento está na Seção 7.4.

Verificou-se que os 223 valores de `PrePatchCommit` são hashes SHA-1 completos e bem formados. Registra-se que boa formação não implica que o objeto referido seja um commit: um identificador de objeto anotado de marcação, por exemplo, é igualmente bem formado e conduz a árvore distinta. A Seção 4.3 trata da verificação que cobre esse caso.

### 2.3 Ground truth DAST — OWASP Juice Shop

O ground truth do Juice Shop é o arquivo `data/static/challenges.yml`, descrito pelo projeto como fonte única de verdade dos desafios, utilizado na inicialização da aplicação para popular a tabela `Challenges`.

Cada entrada possui os campos `name`, `category`, `description`, `difficulty`, `hints`, `mitigationUrl`, `key` e, opcionalmente, `tags`, `disabledEnv` e `tutorial`.

Três ausências condicionam o protocolo de análise:

- Não há campo de CWE.
- Não há campo de OWASP Top 10.
- Não há localização — nenhum endpoint, rota ou URL. A localização é apenas descritiva, embutida no texto dos campos `description` e `hints`.

As categorias constituem taxonomia própria do projeto: XSS, Injection, Broken Access Control, Sensitive Data Exposure, Improper Input Validation, Security Misconfiguration, Broken Authentication, Cryptographic Issues, Vulnerable Components, Observability Failures, Broken Anti Automation, Security through Obscurity, Unvalidated Redirects, XXE, Insecure Deserialization e Miscellaneous.

Registra-se ainda que o `challenges.yml` cataloga desafios de hacking, não vulnerabilidades detectáveis por varredura automatizada. Parte substancial dos desafios é, por natureza, indetectável por um scanner — tarefas de OSINT, esteganografia, leitura de política de privacidade, interação com contratos inteligentes e injeção de prompt em chatbot.

### 2.4 Ground truth DAST — OWASP NodeGoat

O NodeGoat não dispõe de arquivo de ground truth estruturado. O mapeamento para o OWASP Top 10 existe sob a forma de uma página de tutorial embutida na aplicação, acessível em `/tutorial` durante a execução, implementada como templates HTML em `app/views/tutorial/` (`a1.html` a `a10.html`). O conteúdo é prosa em HTML, sem menção a CWE.

Características relevantes:

- **Granularidade inferior à categoria.** Cada categoria subdivide-se em vulnerabilidades específicas; `a1.html`, por exemplo, contém A1-1 Server Side JS Injection, A1-2 SQL and NoSQL Injection e A1-3 Log Injection.
- **Localização em nível de código.** Cada subitem traz seção Source Code Example indicando arquivo e função.
- **Dependência de ambiente.** O tutorial informa que as vulnerabilidades de injeção NoSQL não estão presentes em determinadas configurações de banco de dados.
- **Edição antiga do OWASP Top 10.** A organização em A1–A10, com A1 correspondendo a Injection, indica edição anterior à de 2021.

---

## 3. Infraestrutura de execução

### 3.1 SAST — GitHub Actions

As análises estáticas executam em workflows do GitHub Actions, disparados manualmente via `workflow_dispatch`, em runners `ubuntu-latest`.

**As imagens são construídas uma única vez**, pelo workflow `build-imagens.yml`, publicadas no GitHub Container Registry e referenciadas por **digest**, e não por etiqueta. O workflow de lote, `analise-lote.yml`, não constrói imagem: puxa cada uma pelo digest, confere o digest efetivamente obtido e executa o container. É isso que garante que todos os lotes da campanha rodem sobre bytes idênticos.

Digests vigentes, do rebuild de 15 de setembro de 2026 (execução `34961746566`, commit `a08c559`):

```
ic-security-lab-codeql    @sha256:39950e7ac03b7d7b7a724c742e1c48e9475ed998d58a4734d653188d31afcbec
ic-security-lab-semgrep   @sha256:de71bdfbdf81d495781a4c80052c5f7d128ec9b76eba2304978e08b88ba5d000
ic-security-lab-snyk-code @sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
```

O workflow de lote recebe o nome do lote como entrada e executa as três ferramentas numa matriz, uma por job, para que cada uma disponha do teto de tempo do job inteiro. Normaliza os resultados no próprio runner, aplica as conferências da Seção 4.6 e publica como artifacts os resultados brutos, os normalizados, os registros de execução e as saídas das conferências.

O limite de 6 horas por job impõe a divisão da carga em lotes (batches), detalhada na Seção 4.4.

### 3.2 DAST — AWS EC2

As análises dinâmicas executam em instância `m7i-flex.large` (2 vCPU, 8 GB de RAM) com Ubuntu Server 24.04 LTS. As aplicações-alvo e o ZAP são executados em containers Docker na própria instância. O acesso se dá por SSH com par de chaves, e a instância é interrompida quando não está em uso.

---

## 4. Protocolo SAST

### 4.1 Unidade de análise

A unidade de análise é o **CVE**, não o repositório.

Essa definição decorre de uma característica do dataset: o mesmo repositório aparece associado a múltiplos CVEs, cada um em um commit distinto. O repositório bootstrap, por exemplo, comparece sete vezes; lodash, cinco; jquery e rendertron, quatro cada.

Tratar o repositório como unidade produziria dois defeitos:

- **Sobrescrita de resultados.** Análises distintas do mesmo repositório em commits diferentes gerariam arquivos de saída homônimos.
- **Colisão de nomes.** Os repositórios `linxiaowu66/swagger-ui` e `swagger-api/swagger-ui` produzem o mesmo nome-base.

Com o CVE como unidade, o denominador do estudo é 223, coincidindo com o ground truth.

### 4.2 Preparação das listas de entrada

Um script gerador lê os metadados consolidados e produz listas de execução no formato de seis campos:

```
CVE,URL,PrePatchCommit,CWEs,FilePath,FileLine
```

O campo CWEs usa `|` como separador interno (`CWE-079|CWE-116`), evitando conflito com o delimitador de campo, e os identificadores já são gravados normalizados.

As listas são autocontidas: cada linha carrega tanto os parâmetros de execução quanto o ground truth correspondente. Isso permite que a etapa de normalização preencha os campos de referência do schema de saída sem consulta a fontes externas, e facilita a depuração de divergências.

Todos os arquivos gerados terminam com quebra de linha final. A ausência dessa quebra causou, na campanha preliminar, o descarte silencioso da última linha de vários lotes (Seção 8).

O gerador aplica validações bloqueantes — número de registros, integridade dos hashes, ausência de duplicatas, formato dos CWEs — e aborta sem escrever qualquer arquivo caso alguma seja violada. Aplica ainda avisos **não bloqueantes** para as anomalias que são do próprio benchmark e cujo tratamento cabe à normalização: `PostPatchCommit` malformado e caminho de arquivo fora de forma canônica (Seção 2.2.3). O aviso torna a anomalia visível na geração, e não apenas três etapas adiante.

A partir da lista completa são derivados oito lotes de até 30 CVEs, além de um lote de teste com cinco CVEs selecionados para exercitar condições específicas: dois CVEs do mesmo repositório em commits distintos, um repositório extenso, um repositório de pequeno porte e um dos dois repositórios homônimos.

**Regra de processo.** Uma vez iniciada a execução dos lotes, as listas não são regeradas. Conteúdo adicional é incorporado em lista separada. A regeração alteraria a correspondência entre nomes de lote e os artefatos e registros já produzidos.

### 4.3 Obtenção do código-fonte

Este é o ponto mais crítico do protocolo. Cada análise da **campanha de detecção** deve incidir sobre o código no estado vulnerável, ou seja, no commit anterior à correção (`PrePatchCommit`), registrado no ground truth.

A **campanha da versão corrigida** (Seção 7.3) incide sobre o commit da correção (`PostPatchCommit`), e só ela. O HEAD do branch padrão **nunca** é analisado, em campanha alguma: foi o que invalidou a campanha preliminar (Seção 8), e ele tampouco serve de versão corrigida, porque difere do código vulnerável por todo o histórico posterior à correção, e não só por ela.

O procedimento, para cada CVE:

```bash
git init .
git remote add origin "$REPO_URL"
timeout 300 git fetch --depth 1 origin "$COMMIT"
git checkout FETCH_HEAD
```

Justificativas de cada elemento:

- O fetch raso do commit específico reduz substancialmente o volume transferido em repositórios extensos, o que é relevante diante do limite de tempo por job.
- O timeout protege contra conexões travadas. A variável `GIT_TERMINAL_PROMPT=0`, empregada adicionalmente, impede apenas o bloqueio em solicitação de credenciais.
- Nem todos os servidores Git permitem fetch de SHA arbitrário. Em caso de falha, aplica-se fallback para clone completo seguido de checkout, e o uso do fallback é registrado no log.
- Falhas de obtenção interrompem apenas o item corrente; o laço prossegue para o próximo CVE.

**Alcance do fallback, medido.** O clone de fallback é executado sem `--depth` e com `--no-single-branch` explícito, de modo a trazer a totalidade das referências remotas. A opção é redundante ante o comportamento padrão do Git, mas é declarada para tornar o resultado independente de configuração de ambiente, que pode invertê-lo.

A medida não é precaução abstrata. Quatro dos sete CVEs do repositório bootstrap — `CVE-2018-14040`, `CVE-2018-14042`, `CVE-2018-20676` e `CVE-2018-20677` — têm o commit do ground truth alcançável apenas pelo branch `v3-dev`, e não pelo branch padrão. Sob clone restrito a um único branch, os quatro produziriam falha de checkout, dispersa entre os lotes e sem causa comum aparente.

Verificou-se igualmente que o servidor do GitHub aceita o fetch raso por SHA arbitrário, inclusive de commit fora do branch padrão, de modo que o fallback deve ser acionado raramente. Restam fora do alcance de ambos os mecanismos os commits que existam apenas em referências de pull request, em fork ou em branch removido. A frequência de acionamento do fallback é contabilizada como métrica própria, e não apenas registrada em texto livre no log, precisamente porque o valor esperado é baixo: elevação súbita indicaria mudança de comportamento do servidor ou degradação do conjunto.

**Confirmado na campanha de detecção.** O fallback foi acionado em **2 dos 223 CVEs**, ambos por recusa do servidor (código de saída 128 do Git) e **nenhum por estouro de limite**: um no lote `aa`, um no `ad`, zero nos outros seis — taxa estável ao longo dos oito lotes. Os dois são as duas baixas por indisponibilidade de código (Seção 7.4). Os quatro CVEs do bootstrap cujo commit só é alcançável pelo branch `v3-dev` passaram pelo fetch raso, **sem fallback**, como a verificação anterior previa.

**A classe fora de alcance também ocorreu.** O `CVE-2018-8035` (Seção 2.2.3) declara commit ausente do repositório: o fetch raso foi recusado, o clone completo foi bem-sucedido, e o checkout falhou. O caso foi tratado como desenhado — registro de falha de checkout, nenhuma saída bruta —, e é o que o parágrafo seguinte descreve para identificador bem formado porém inexistente.

**Asserção do commit analisado.** Após o checkout, o script compara o HEAD resolvido com o commit registrado no ground truth e registra o valor efetivo no log. A verificação custa uma linha e responde à natureza do defeito que invalidou a campanha preliminar: sem ela, a garantia de que o código analisado é o vulnerável repousa sobre a semântica do `FETCH_HEAD`, e nenhum artefato do estudo registra qual commit foi de fato submetido às ferramentas.

A asserção é **fatal**: divergência interrompe o processamento daquele CVE e o registra como falha de checkout, de modo que nenhuma saída bruta é produzida a partir de código não conferido. Essa propriedade é o que autoriza a decisão registrada na Seção 5.1 quanto à origem do campo de commit no resultado normalizado.

**A asserção foi exercitada com divergência real** no ensaio local (Seção 8.6), e o caso que a fez disparar amplia o alcance da verificação para além do defeito que a motivou. Identificador bem formado porém inexistente no repositório é recusado antes: o fetch raso não o encontra e o checkout falha, de modo que a guarda anterior basta. Já um identificador de objeto anotado de marcação atravessa o fetch e o checkout sem erro, e resolve para o commit ao qual a marcação aponta — árvore distinta da esperada, análise silenciosamente deslocada, nenhum erro registrado.

A asserção é o único ponto do protocolo que intercepta essa condição. Ela não decorre de hipótese: o ground truth declara identificadores bem formados (Seção 2.2.3), e boa formação não distingue objeto de commit de objeto de marcação.

**Sondagem prévia de disponibilidade.** Antes de cada campanha, verifica-se a acessibilidade dos 186 repositórios, com registro datado do resultado. A verificação converte em procedimento o que, de outro modo, seria observação pontual (Seções 2.2.3 e 12.2).

**Como a regra foi cumprida na campanha de detecção — e a sua revisão.** A Versão 9 exigia a sondagem **imediatamente** antes da campanha, e o denominador apurado nela. **Não foi cumprida à letra.** A última sondagem registrada é de **10 de setembro de 2026**, versionada em `datasets/sondagens/sondagem-repos-2026-09-10.csv` — 185 repositórios acessíveis e um inacessível, o `linxiaowu66/swagger-ui` —, seis dias antes do primeiro lote, sem outra registrada entre as datas.

O denominador da campanha **saiu da medição da própria campanha, CVE a CVE**, e não da sondagem: falha de obtenção no `CVE-2016-1000229` e falha de checkout no `CVE-2018-8035`. A sondagem de 10 de setembro daria uma baixa só, e **nenhuma sondagem de repositório teria detectado a segunda**, por mais próxima da campanha que fosse: é commit inexistente em repositório existente, e a sondagem pergunta apenas pelo `HEAD` de cada repositório.

A regra passa, por isso, a ter esta forma: **a sondagem antecipa as baixas de repositório; a campanha as confirma, e é a única que alcança as de commit. O denominador é o que a campanha mede.** Para a campanha da versão corrigida, a sondagem, se feita, precisa rodar antes do primeiro lote e sem credenciais do operador — com o cliente do GitHub autenticado no hospedeiro, ela mede o acesso do operador, e não o acesso anônimo que a campanha emprega.

### 4.4 Modelo de execução

Cada ferramenta executa em um container Docker próprio, que itera sobre os CVEs de um lote. Ao final de cada iteração, o código-fonte obtido é removido; no caso do CodeQL, remove-se também o banco de dados gerado. A remoção é feita por caminho nominal, derivado do identificador do CVE já validado, e nunca por expansão de padrão sobre o diretório temporário — restrição de que depende a decisão da Seção 4.7.

O laço é idempotente: antes de processar um CVE, o script verifica a existência do arquivo de saída correspondente e, havendo-o, avança. A propriedade governa a **retomada local** de um lote interrompido.

**No ambiente da campanha ela é inerte.** As saídas brutas não são versionadas (Seção 5.5) e cada execução parte de ambiente limpo, de modo que a reexecução de um lote reprocessa-o integralmente. A consequência é assumida: o custo de uma reexecução é o lote inteiro, e não o seu remanescente. Em contrapartida, o estado de registro que sinaliza CVE ignorado por idempotência não ocorre ali, o que simplifica a conferência descrita na Seção 4.6.

Adotou-se o tamanho de 30 CVEs por lote. O ensaio local (Seção 8.6) mediu durações por CVE sobre quatro casos escolhidos por contraste, e não por amostragem, de modo que não estimam a duração dos 223: a projeção de aproximadamente seis horas para oito lotes é **piso frouxo, não previsão**. O que o dimensionamento exige não é a mediana e sim o pior lote plausível, apurado a partir do máximo observado.

**Medido na campanha:** cerca de **1 h 30 de relógio** para os oito lotes, com os dois primeiros em série e os seis restantes em paralelo — 34 minutos para os seis. **Essas duas durações são de job no serviço de integração contínua e não estão versionadas**: incluem a obtenção da imagem e a publicação dos artefatos, que o registro do container não cobre.

O que o repositório registra é a duração do **container** por lote. O lote mais lento é sempre o do CodeQL, e consumiu **de 26 a 33 minutos** nos sete lotes de 30 CVEs, e 15 minutos no lote de 13, contra um teto de seis horas por job.

A concordância com a duração da campanha preliminar não é tomada como corroboração: aquela campanha analisou outros commits sob suíte mais ampla, e a coincidência de ordem de grandeza não decorre de propriedade comum às duas.

**Limite por invocação e teto do job não são comensuráveis.** O limite de tempo é por invocação; o teto de seis horas é por job. A folga de um não implica a do outro: um pequeno número de CVEs que atinjam o limite consome, somado, parcela substancial do teto antes de qualquer trabalho regular do lote. O job encerrado pelo teto é interrompido **sem executar a etapa de preservação de resultados**, de modo que se perdem o registro de execução e as saídas brutas já promovidas — precisamente a evidência de que o ocorrido foi esgotamento de tempo, e não falha das ferramentas.

**O teto não é restrição prospectiva: já interrompeu execuções deste estudo.** Em julho de 2026, em série exploratória anterior à reconstrução do pipeline, a análise pelo CodeQL atingiu o teto primeiro sobre o conjunto inteiro e, depois, **ainda em regime de lotes**, em dois lotes de uma mesma partição de cinco — enquanto os três restantes concluíram entre 52 minutos e 1 hora e 9 minutos.

**O degrau é o dado.** Três lotes da mesma partição concluindo com mais de quatro horas de folga, e dois consumindo o teto integral, não constitui perfil de custo agregado excessivo: constitui perfil de **item individual que não termina**. Reduzir o lote à metade apenas dividiria o mesmo travamento entre dois jobs; o que intercepta esse modo de falha é o limite de tempo por invocação.

Em um dos dois lotes o travamento está identificado: a execução não ultrapassou a obtenção do código-fonte do primeiro repositório, feita por clone completo, sem profundidade e sem limite de tempo, sobre repositório de histórico extenso. No outro a causa **não foi determinada** — o primeiro repositório era de pequeno porte, e não se apurou em que ponto a execução deixou de progredir.

Uma dessas execuções transcorreu seis horas e **não produziu arquivo algum**. O script já promovia a saída por item diretamente ao diretório definitivo, de modo que a ausência de resultado não decorre de promoção tardia. A perda apresentou-se, na etapa de preservação de resultados, como aviso de caminho inexistente, entre avisos de dependência obsoleta — e não como erro.

Daí três exigências do protocolo atual, ausentes daquela série: obtenção do código por fetch raso (Seção 4.3), limite de tempo por invocação, e registro estruturado por item (Seção 4.6), que tornaria o travamento visível em minutos em lugar de seis horas.

**Fronteira do que essa observação estabelece.** A série de julho era exploratória, tinha o repositório por unidade de iteração, empregava suíte mais ampla e analisava o HEAD. Estabelece que o teto interrompe, e que a perda pode apresentar-se como aviso. **Não** estabelece duração por CVE, tamanho de lote seguro, nem a razão entre as durações dos dois ambientes.

A condição que torna a garantia aritmética, e não dependente de comportamento, é que o produto entre o tamanho do lote e o limite por invocação caiba no teto do job. O valor corrente do limite não satisfaz essa condição: foi fixado contra os máximos observados no ensaio local, que é critério distinto e mais frouxo.

**A condição não é satisfazível com os limites adotados, e a apuração que o estabeleceu é de setembro de 2026.** Inspecionaram-se os programas de análise quanto a quais invocações estão sob limite de tempo. Verificou-se que a obtenção do código-fonte está sob limite — tanto a obtenção rasa quanto o clone de contingência —, o que resolve a pendência que a versão anterior deste documento registrava. Mas a soma dos dois limites, multiplicada pelo tamanho de lote corrente, **já excede o teto do job antes de qualquer análise**. Nenhum valor do limite de análise torna a condição satisfazível, e reduzir o lote ao ponto de satisfazê-la o levaria a uma ordem de grandeza incompatível com a campanha.

**Decisão, registrada com sua razão.** Mantém-se o tamanho de lote corrente, e a decisão passa a apoiar-se em **comportamento medido** — obtenção rasa da ordem de segundos, recurso ao clone de contingência raro por medição (Seção 4.3) — e não no limite de pior caso. Para que o lote excedesse o teto seria preciso que cerca de metade dos seus itens atingisse simultaneamente o pior caso completo de obtenção, o que não constitui variação, e sim falha sistêmica do serviço de hospedagem ou da rede do ambiente.

A garantia é, portanto, **probabilística e declarada**, e não aritmética. Isso obriga a que exista sinal de vigilância, e é o que a Seção 4.6 estabelece: a contagem de recurso ao clone de contingência, discriminada por causa. Sem ela a decisão não teria instrumento, e a alternativa — orçamento de tempo por lote, com estado próprio de registro — foi examinada e descartada por acrescentar estado ao vocabulário do registro sem economizar execução, já que a idempotência é inerte no ambiente da campanha.

**O limite de análise, decidido em setembro de 2026: 900 segundos.** Aplica-se às três ferramentas — no CodeQL, separadamente à criação do banco e à análise; no Semgrep e no Snyk Code, à análise. Os limites da obtenção do código (300 segundos no fetch raso, 900 no clone de contingência) não mudaram, por falta de dado que o justificasse: nenhum foi atingido.

**A justificativa não é a folga sobre o observado, e sim a assimetria da falha.** Limite curto demais falha um CVE, o registro nomeia a causa (`excedeu 900s`), a falha fica localizada e o CVE é reexecutável isoladamente. Limite longo demais deixa um item que não termina consumir o teto do job, interromper o lote inteiro e perder a evidência — o modo de falha de julho de 2026. Como nenhum valor torna a garantia aritmética (acima), o limite só pode ser escolhido pela falha que se prefere sofrer, e a primeira é recuperável.

**Os 900 segundos nunca foram exercidos.** O máximo observado nos 223 CVEs foi de 304 segundos, no CodeQL. Isso estabelece que a decisão não foi posta à prova — não que estava certa.

**Os limites são sobrescrevíveis por ambiente**, sem reconstrução de imagem nem digest novo: os scripts os leem de variável de ambiente, com o valor anterior como padrão, e o workflow de lote os recebe como entrada. Variável definida e vazia não cai no padrão: interrompe a execução numa guarda de forma, que exige inteiro positivo de segundos. A guarda existe sobretudo por causa do zero, que para o `timeout` do GNU desliga o limite sem erro algum. O valor efetivo de cada lote fica registrado na primeira linha do log de execução e é conferido contra o pedido.

**A razão entre os ambientes foi medida no ensaio de fumaça** (Seção 8.7): o runner da campanha é **cerca de 30% mais rápido** que o hospedeiro do ensaio local, com razões entre 0,65 e 0,76 em quatro CVEs pareados. A premissa implícita das versões anteriores — runner mais lento — estava errada na direção.

**O tamanho de lote de 30 fica confirmado, no escopo restrito.** A projeção agregada cabe com folga de quatro a seis vezes contra o teto. O perfil de **item que não termina**, que interrompeu os lotes de julho, **não foi amostrado** nem pelo ensaio nem pela campanha, que não o produziu. A garantia continua probabilística e declarada.

**O repositório que travou a série de julho foi analisado em 55 segundos.** O `zeit/next.js`, cujo clone completo sem limite consumiu o teto de seis horas em julho, foi analisado pelo CodeQL em 55 segundos na campanha, com 377 arquivos extraídos e sem fallback: o fetch raso resolveu. A coincidência de nome entre os lotes (`ab` nas duas séries) é da partição, e não indica o mesmo conjunto de CVEs.

A relação entre o porte do repositório e o custo de análise, medida nos 221 CVEs analisados, está na Seção 9.

Registra-se que este modelo — um container por lote, com laço interno — é uniforme entre as três ferramentas.

### 4.5 Configuração das ferramentas

#### CodeQL

```
codeql database create --language=javascript \
    --source-root=. --build-mode=none

codeql database analyze <db> \
    codeql/javascript-queries:codeql-suites/javascript-security-extended.qls \
    --ram=4096 --format=sarif-latest --output=<saida>
```

A linguagem `javascript` abrange JavaScript e TypeScript no CodeQL. Versão fixada: bundle `codeql-bundle-v2.25.4`.

**Suíte.** Emprega-se `security-extended`. A campanha preliminar utilizou `security-and-quality`, que acrescenta consultas de qualidade voltadas a estrutura e manutenibilidade — `js/unused-local-variable`, `js/useless-assignment-to-local`, `js/trivial-conditional` e afins.

A mudança tem fundamento metodológico. Consultas de qualidade não constituem alegação de vulnerabilidade; computá-las como falso positivo na matriz de confusão mediria a escolha de suíte, não a precisão da ferramenta. Na campanha preliminar, tais consultas responderam por 46% dos achados sem CWE atribuído.

A substituição não implica perda de cobertura de segurança. A relação de contenção entre as suítes foi verificada diretamente no bundle empregado:

| Suíte | Consultas | Consultas com CWE declarado |
|---|---|---|
| code-scanning | 88 | 84 (95,5%) |
| security-extended | 104 | 100 (96,2%) |
| security-and-quality | 202 | 140 (69,3%) |

O conjunto `security-extended` menos `security-and-quality` é vazio, ao passo que o inverso contém 98 consultas — de modo que a substituição constitui subtração estrita, sem perda de qualquer consulta de segurança.

Das quatro consultas de `security-extended` sem CWE declarado, todas são de diagnóstico ou de sumário e não produzem entrada no conjunto de resultados. Em execução de verificação sobre alvo controlado, a totalidade dos achados apresentou CWE e escore de severidade de segurança. Registra-se que os percentuais acima referem-se a consultas, ao passo que o valor de 46% mencionado anteriormente refere-se a achados; as grandezas não são diretamente comparáveis, ainda que apontem no mesmo sentido.

**Verificação empírica do modo de construção.** A combinação `--build-mode=none` com `--language=javascript` foi exercitada ponta a ponta sobre alvo controlado, com criação de banco de dados, análise pela suíte e emissão de SARIF. O ensaio confirmou quatro propriedades das quais o restante do protocolo depende: o modo de construção é aceito; o caminho de arquivo emitido é relativo e limpo, sem prefixo do diretório de trabalho, o que sustenta o cotejo com o campo de caminho do ground truth; a cobertura de CWE e de escore de severidade abrange a totalidade das consultas com marcação de segurança, restando sem CWE apenas as consultas de sumário, que não produzem entrada no conjunto de resultados; e o código de saída da análise é nulo mesmo na presença de achados, de modo que a verificação de erro do script não rebaixa análise bem-sucedida.

Registra-se que o ensaio descrito acima foi executado na versão 2.26.4 do CodeQL, e não na 2.25.4 fixada para o estudo. A diferença de uma consulta entre as duas versões — 105 na 2.26.4, 104 na fixada — ilustra a evolução independente do catálogo e reforça o motivo da fixação.

A limitação daí decorrente **não subsiste**: o ensaio local (Seção 8.6) repetiu a verificação na versão fixada, sobre a imagem efetivamente construída, com as quatro propriedades reproduzidas. O registro consta da Seção 12.1.

O ensaio local (Seção 8.6) fechou as verificações que restavam: a suíte resolve 104 consultas na imagem construída, a análise emite caminho relativo e limpo em todos os achados, e o extrator de TypeScript opera sobre o runtime da imagem — este último aferido por sondagem dedicada, uma vez que nenhum dos CVEs do lote de teste contém arquivo TypeScript. Sondagem dedicada estabelece que o extrator funciona, não que o laço o atravesse; a distinção consta da Seção 12.1.

**Legibilidade das consultas precompiladas.** O bundle distribui 3.151 consultas em forma precompilada, das quais 462 com permissão de leitura restrita ao proprietário, atribuídas a um identificador de usuário fixo. Sob a execução descrita na Seção 4.7 — com o identificador do usuário do hospedeiro —, o processo não as lê, registra recusa de acesso e **recompila cada consulta a partir do código-fonte**, ao custo aproximado de um minuto e vinte segundos por consulta.

A medição isolou a variável, sobre a mesma imagem e o mesmo lote, alterando apenas a legibilidade:

| | Recusas de acesso | Consultas recompiladas | Progresso em nove minutos |
|---|---|---|---|
| Imagem sem correção | 8 | 7 | 7 de 104 |
| Com leitura liberada na construção | 0 | 0 | 104 de 104, em cerca de 40 s |

A correção — liberação de leitura no momento da construção da imagem — é adotada. O motivo não é desempenho apenas: o custo de recompilação recai integralmente sobre a primeira análise do lote e pode alcançar o limite de tempo por invocação, produzindo falha de análise em um único CVE, sem causa aparente e sem relação com o código analisado. É a categoria de defeito que o protocolo persegue desde a Seção 8.

Registra-se que a condição **depende de coincidência de identificadores**: o defeito manifesta-se quando o identificador do usuário do hospedeiro difere do proprietário dos arquivos na imagem, e não se manifesta quando coincidem. A Seção 4.7 registra um segundo defeito de permissão cujo sinal é exatamente o inverso. Em ambos, a correção elimina a dependência da coincidência em vez de confiar nela.

**Orçamento de memória.** A opção que fixa a memória da análise não governa a totalidade do consumo: o extrator anuncia e reserva orçamento próprio, adicional. A distinção é relevante para o dimensionamento do ambiente de execução e para a atribuição de causa em interrupções abruptas (Seção 12.5).

**Forma de referência à suíte.** Emprega-se a referência por pacote, e não o caminho absoluto do arquivo. Ambas resolvem para o mesmo conjunto de consultas, mas o caminho absoluto embute a versão do pacote de consultas, que evolui independentemente da versão do bundle — uma atualização de bundle invalidaria o caminho sem sinalização.

Não se aplicam filtros de severidade nem exclusões de caminho. O exit code de `database create` é verificado; sua falha impede a etapa de análise e é registrada no log.

#### Semgrep

```
semgrep scan --config=/default.yaml --json --time --metrics=off \
    --output=<saida>
```

Versão fixada: 1.171.0.

**Conjunto de regras.** A campanha preliminar utilizou `--config=auto`, que resolve as regras junto ao Semgrep Registry em tempo de execução. Verificou-se, por cotejo dos identificadores de regra produzidos, que o `auto` resolvia exatamente para o conjunto `p/default` — 145 de 145 regras distintas e a totalidade dos achados. Ainda assim, essa correspondência não é garantida ao longo do tempo: o conteúdo do `auto` varia com o registry, e o método não é descritível em termos verificáveis.

Adota-se, portanto, o conjunto `p/default` vendorizado: o arquivo de regras resolvido é obtido uma única vez, versionado no repositório do estudo com registro de sha256 e data de obtenção, e referenciado por caminho local. A execução prescinde de rede, o que foi verificado experimentalmente, e o conjunto torna-se descritível e auditável.

**Justificativa da escolha do conjunto.** Mediu-se a cobertura de cada alternativa contra os pares CVE×CWE do benchmark:

| Conjunto | Cobertura |
|---|---|
| `p/javascript` | 45% |
| `p/javascript` + `p/security-audit` | 58% |
| `p/default` | 73% |

O resultado é contraintuitivo e merece registro. O conjunto `p/javascript` organiza-se por framework, não por linguagem: das suas 74 regras, 31 são específicas de Express e apenas três pertencem à família `javascript.lang.security`. As regras genéricas mais produtivas — path traversal e prototype pollution, famílias centrais do benchmark — não o integram. Já `p/security-audit` reúne 225 regras, das quais apenas 20 são JavaScript ou TypeScript.

A união de `p/default` com `p/javascript` foi avaliada e descartada: a interseção é de 73 das 74 regras, e a única regra exclusiva declara CWE-079, já contemplado por outras 35 regras do `p/default`, sem ter produzido qualquer achado na amostra examinada.

**Forma de incorporação à imagem.** O arquivo vendorizado é **copiado para a raiz do sistema de arquivos da imagem** no momento de sua construção, e não montado em tempo de execução. A escolha desacopla a execução da forma de invocação do container, torna a imagem autocontida e move para dentro dela a garantia da invariante de prefixo descrita adiante. O custo é que a substituição do conjunto exige reconstrução da imagem. Na campanha esse custo deixa de ser nominal: a imagem é construída uma vez e referenciada por identidade de conteúdo nos jobs de lote, e não reconstruída a cada execução, de modo que alterar o conjunto no repositório sem reconstruir e republicar a imagem torna-se caminho praticável.

A consequência recai sobre a **segunda** das duas comparações de resumo descritas adiante. Sob reconstrução por execução, os dois lados que ela coteja moviam-se juntos e a divergência era improvável na prática, ainda que possível em princípio; sob construção única, a derivação entre o conjunto versionado e o conjunto embutido passa a ser o modo de falha esperado da nova forma de execução. A comparação não muda; muda o seu papel, que deixa de ser verificação de contorno e passa a ser a garantia sobre a qual a construção única repousa.

A integridade do arquivo dentro da imagem é conferida por duas comparações de resumo criptográfico, ambas fatais e nenhuma redundante em relação à outra: a primeira contra o valor declarado no momento da construção, que detecta construção mal parametrizada e substituição do arquivo em tempo de execução; a segunda contra o arquivo versionado no repositório, quando este está acessível, que detecta alteração do repositório sem reconstrução da imagem — caso que a primeira não alcança, por congelarem-se ambos os lados no mesmo momento de construção.

**Contagem do conjunto.** O `p/default` reúne **1.074 regras** multilinguagem, das quais 163 declaram JavaScript ou TypeScript. A contagem exige processamento do arquivo por analisador YAML: a contagem por expressão regular sobre o início de linha resulta em 1.073, porque ao menos uma regra declara o campo de padrões antes do campo de identificador. Registra-se também que o arquivo emprega grafias distintas para a mesma linguagem — `javascript` e `js`, `typescript` e `ts` —, de modo que qualquer filtro por linguagem deve contemplar ambas.

**Vocabulário de severidade do conjunto.** A contagem por analisador YAML, sobre o arquivo vendorizado, atribui a cada uma das 1.074 regras exatamente um valor de severidade no nível superior da declaração: `WARNING` 722, `ERROR` 310, `INFO` 31, `MEDIUM` 11. Nenhuma regra deixa de declará-lo. O vocabulário é, portanto, fechado e integralmente coberto pela correspondência da Seção 5.4.

A contagem por expressão regular sobre a ocorrência do campo produz 1.075. A divergência tem causa única e identificada: uma regra — `generic.secrets.security.google-maps-apikeyleak.google-maps-apikeyleak`, declarada para linguagem genérica — registra o campo em dois níveis, no topo e no bloco de metadados, com valores distintos. A expressão regular conta as duas ocorrências. A normalização consome o valor do nível superior, que é o exposto no campo de severidade de cada achado; o valor aninhado não é lido.

O episódio reproduz, por causa distinta, o da contagem de regras: em ambos, o objeto medido estava correto e o método de medição, errado (Seção 12.5).

**Registro do conjunto aplicado.** A opção `--time` grava, no próprio arquivo de saída, o inventário das regras efetivamente empregadas em cada execução. A opção `--metrics=off` suprime o envio de telemetria.

**O inventário enumera regras aplicadas, não carregadas.** A versão anterior deste documento registrava a dúvida e declarava a consequência de antemão; o ensaio local mediu: quatro execuções sobre repositórios distintos produziram inventários de 256, 297, 297 e 370 regras, e o menor é subconjunto próprio do maior. As 1.074 regras carregadas comparecem apenas no texto de console, que não é artefato preservado.

Em consequência, e conforme a decisão já registrada, o campo correspondente do schema passa a chamar-se **`rules_applied`** (Seção 5.2). Campo cujo nome afirma grandeza diversa da registrada é pior que campo ausente, e a renomeação preserva a possibilidade de comparação sem induzir leitura falsa.

A perda é de uma verificação de segunda ordem: a comparação entre regras declaradas e regras aplicadas deixa de detectar conjunto obsoleto, porque a diferença passa a ser esperada e variável. A integridade do conjunto dentro do container permanece assegurada pelas duas comparações de resumo, que são fatais e independentes desta. Resta útil o extremo inferior: inventário vazio significa que nenhuma regra se aplicou, condição que produziria conjunto vazio de achados indistinguível de análise sem achados, e que é registrada como anomalia própria.

**Execução sem rede.** A ausência de dependência de rede foi confirmada em execução com a interface desabilitada: o conjunto local é carregado integralmente e os achados são produzidos.

**Registro de erros parciais.** O campo que enumera erros de análise emprega representação variável: cadeia simples em parte dos casos e união etiquetada na maioria. Iteração que não despache por tipo produz detalhe sem identificar o erro, sem que isso se manifeste como falha — os demais campos do registro permanecem preenchidos. O tratamento é análogo ao exigido pelo campo de CWE, e a ocorrência de tipo não previsto é contabilizada em separado.

**Ordem não determinística do arquivo servido.** O registry entrega o conjunto resolvido com ordenação variável entre requisições: duas obtenções separadas por cerca de uma hora produziram arquivos de mesmo tamanho e conjunto de regras idêntico — nenhuma acrescida, nenhuma removida — mas com um bloco de regras deslocado, e portanto com resumos criptográficos distintos. Verificou-se ainda que o corpo servido é idêntico dentro e fora do container, independentemente do cabeçalho de aceitação enviado pelo cliente, de modo que a obtenção prescinde da própria ferramenta.

A consequência é que o resumo do arquivo identifica o arquivo, e não o conjunto de regras. Adota-se, por isso, uma identidade secundária: o resumo da lista de identificadores de regra ordenada, invariante à reordenação. O arquivo descritor que acompanha o conjunto vendorizado registra ambos, além do tamanho, da contagem total, da contagem de regras JavaScript e TypeScript, e da data e do endereço de obtenção. Conforme a Seção 5.2, a identidade secundária é reproduzida também no resultado normalizado, de modo que a verificação de identidade de conjunto não dependa de consulta ao descritor.

**Continuidade com a campanha preliminar.** O mesmo descritor registra a verificação de que os 145 identificadores de regra produtores de achado na campanha preliminar estão presentes no conjunto vendorizado, e a lista desses identificadores é versionada junto ao estudo. A verificação estabelece continuidade no nível do identificador e afasta a hipótese de remoção de regras produtivas; não estabelece identidade entre o conjunto que o modo automático resolvia e o conjunto vendorizado, uma vez que regras acrescentadas ao conjunto e regras executadas sem resultado não deixam vestígio no cotejo.

O arquivo de regras vendorizado, acompanhado de seus dois resumos e da data de obtenção, e o inventário de regras registrado em cada execução compõem o apêndice de reprodutibilidade do estudo. Ao contrário do registro por identificadores de regra empregado na campanha preliminar, que contemplava apenas as regras produtoras de achado, o conjunto assim documentado abrange igualmente as regras executadas sem resultado.

**Prefixo dos identificadores de regra.** O Semgrep antepõe ao `check_id` o nome do diretório que contém o arquivo de regras. O arquivo vendorizado reside, por isso, na raiz do sistema de arquivos da imagem: em subdiretório, os identificadores divergiriam dos do registry, comprometendo silenciosamente qualquer comparação. A propriedade foi medida em três configurações distintas e o registro da medição acompanha o descritor do conjunto.

**Composição dos achados.** Na campanha preliminar, apenas 20,7% dos achados eram de JavaScript ou TypeScript; 67,5% provinham de regras de HTML, e uma única regra — verificação de atributo de integridade em elementos script — respondeu por 56,5% do total. Optou-se por não excluir tais regras na coleta: a exclusão embutiria decisão de análise no procedimento de captura, e a distribuição observada constitui, em si, resultado relevante para a discussão sobre esforço de triagem. O tratamento ocorre na etapa de análise comparativa.

Não se aplicam filtros de severidade nem exclusões de caminho.

#### Snyk Code

```
snyk code test --sarif-file-output=<saida.sarif>
```

Versão fixada: CLI 1.1306.1, obtido por URL versionada (`static.snyk.io/cli/v1.1306.1/snyk-linux`). A campanha preliminar utilizou o endereço `latest`, que já aponta para versão distinta — circunstância que motivou a fixação.

Emprega-se apenas a saída SARIF. Verificou-se que a saída JSON produzida simultaneamente é byte-idêntica à SARIF, de modo que a segunda opção duplicava dados sem acréscimo de informação.

Não se aplicam filtros de severidade nem exclusões de caminho. O comando retorna código de saída não nulo quando encontra problemas, o que exige tratamento específico para não interromper o laço.

Distingue-se explicitamente, no registro de execução, a condição análise concluída sem achados da condição falha de análise — distinção que a mera ausência de arquivo de saída não permite estabelecer.

**Forma da saída, medida.** O ensaio local (Seção 8.6) estabeleceu três propriedades da saída que condicionam a normalização:

- Em análise concluída sem achados, a ferramenta emite a lista de resultados **presente e vazia**, e não omite a chave. A distinção importa porque a omissão seria tratada como saída estruturalmente incompleta, convertendo toda análise limpa em falha declarada.
- O inventário de cobertura é **agregado por extensão de arquivo**, com contagem, indicação de suporte e estado de processamento, sem enumeração de caminhos. Não decide, portanto, sobre um arquivo determinado (Seção 5.2).
- O bloco de invocação não é emitido, de modo que não há notificações de execução a capturar.

Registra-se que o inventário de cobertura distingue um estado de **falha de processamento** por extensão, que é justamente o sinal de arquivo cuja análise não se completou. Por ser contagem agregada, é promovido aos diagnósticos do resultado normalizado com a limitação declarada no próprio registro.

### 4.6 Registro de execução

Cada ferramenta produz um log estruturado, com uma linha por CVE:

```
cve,repo,commit,status,mensagem,duracao_segundos
```

O campo `status` assume os valores `OK`, `SEM_ACHADOS`, `PULADO`, `ERRO_LINHA`, `ERRO_FETCH`, `ERRO_CHECKOUT` e `ERRO_ANALISE`, acrescidos de `SEM_ARQUIVO_ANALISAVEL` no caso do Snyk Code.

Este último merece justificativa. A ferramenta distingue, por código de saída próprio, a condição de não haver material analisável da condição de falha. Registrá-la como erro seria incorreto em dois sentidos: a análise não falhou, e a reexecução voltaria a tentar indefinidamente um caso que nunca produzirá saída. Registrá-la como ausência de achados também seria incorreto, por confundir as duas condições que o protocolo se propõe a separar desde a Seção 5.3. Adota-se, portanto, estado próprio, com a consequência assumida de que a verificação de idempotência não o reconhece — não há saída bruta cuja existência pudesse sinalizá-lo, e fabricar um arquivo que a ferramenta não emitiu seria pior que repetir a tentativa.

**Efeito sobre o denominador.** A ausência de material analisável é causa **interna à ferramenta** — decorre da sua definição de projeto suportado, que integra o objeto da avaliação —, e não externa ao estudo, como a indisponibilidade de repositório tratada na Seção 7.4. Aplica-se-lhe, portanto, a mesma disciplina do arquivo não considerado (Seção 5.2): o CVE permanece no denominador das duas modalidades de apuração e é computado como ausência de detecção da ferramenta afetada. Em nenhuma hipótese se constitui denominador próprio por ferramenta, sob pena de destruir a comparabilidade direta entre apurações que a Seção 7.4 estabelece.

A regra é declarada antes da execução, deliberadamente, para que a decisão não se apresente como posterior aos números. Três resultados são possíveis, e cada um produz afirmação distinta:

- **Nenhuma ocorrência entre os 223.** Fecha-se a ameaça relativa ao conjunto: o estado não ocorre neste benchmark. A afirmação não se confunde com a de que o tratamento correspondente foi exercitado por execução real, que permanece sustentada apenas por verificação isolada; ambas são reportadas.
- **Uma ou duas ocorrências.** Reportadas nominalmente, acompanhadas do inventário de cobertura do CVE, sem efeito sobre o denominador.
- **Três ou mais.** Deixa de ser condição de borda e constitui resultado de cobertura da ferramenta, com tratamento próprio na análise comparativa; examina-se então a correlação com os arquivos sem extensão referidos na Seção 5.2 e com a presença de TypeScript. O denominador permanece inalterado.

**Ocorreu o terceiro caso.** Na campanha, o Snyk Code encerrou com ausência de material analisável em **cinco** CVEs: `CVE-2018-16479`, `CVE-2018-16480`, `CVE-2018-3731`, `CVE-2018-3747` e `CVE-2019-5423`. **São exatamente os cinco cujo arquivo do ground truth não tem extensão** — `bin/http-live` e `bin/public` (Seção 2.2.1): correlação de cinco em cinco, e nenhuma com TypeScript. O estado passa de condição de borda a resultado de cobertura da ferramenta. Os cinco permanecem no denominador e contam como ausência de detecção do Snyk Code, pela regra fixada acima antes da campanha. O ramo deixou de estar coberto apenas por execução controlada: foi exercitado por execução real.

**Forma de verificação do tratamento.** O conjunto de 223 CVEs é constituído por aplicações JavaScript e TypeScript, de modo que a condição de não haver projeto suportado, embora possível, não é dele esperada; a busca dirigida por um CVE que a produza não é justificável pelo custo. O tratamento é exercitado por execução controlada, em que o código de saída da ferramenta é reproduzido fora do laço da campanha, e essa forma é declarada. A ocorrência real, se houver, é apurada pela própria campanha, cujo inventário de cobertura responde sobre os 223 — a verificação empírica é, portanto, resultado do estudo, e não pré-requisito de sua execução.

**Estouro de limite distinguido de recusa do servidor.** As invocações de obtenção do código passaram, em setembro de 2026, a registrar o código de retorno em variável antes de decidir o ramo, e a declarar na mensagem quando houve **estouro do limite de tempo**. Antes disso o código era consumido pela condição do desvio e se perdia: estouro de limite e recusa do servidor — causas opostas, uma de lentidão e outra de ausência do objeto referido — produziam linha de registro byte a byte idêntica. A disciplina era a que as invocações de análise já seguiam, e faltava apenas na obtenção.

A correção é pré-requisito da decisão registrada na Seção 4.4: a contagem de recurso ao clone de contingência é o sinal de vigilância que sustenta a manutenção do tamanho de lote, e um sinal que soma dois eventos de causas opostas não serve ao fim que motiva sua existência.

**Contagem do recurso ao clone de contingência.** O programa de conferência do registro passou a apurá-la, como métrica e não como incoerência: não faz a conferência falhar, conta e reporta. Discrimina a causa da obtenção rasa — estouro de limite, outro código de retorno, ou indeterminada — e reporta em separado os casos em que o próprio clone de contingência falhou.

Duas propriedades da contagem são declaradas. **O corpus de registros tem dois vocabulários** para a mesma condição: os registros anteriores a setembro de 2026, versionados, empregam a redação que não discrimina causa, e não são editados; a contagem reconhece as duas formas, reporta quantas linhas casaram cada uma, e computa como indeterminada a causa que a forma antiga não permite apurar. E **a contagem é piso, não valor exato**, sempre que houver reexecução: a conferência considera a última linha de cada CVE, e a reexecução substitui a linha do CVE que recorreu ao clone pela linha da reexecução. A saída declara essa condição quando ela ocorre.

**Escrita atômica da saída bruta.** A saída de cada ferramenta é escrita em nome temporário e renomeada para o nome definitivo apenas após validação. A verificação de idempotência incide sobre o nome definitivo, de modo que interrupção abrupta — sinal não capturável, esgotamento de memória ou de disco, limite de tempo do job — não deixa arquivo truncado que a execução seguinte leia como análise concluída. O caso é o mesmo que a Seção 5.3 procura evitar: falso negativo indistinguível de ausência legítima de achados, sem erro visível. O nome temporário é escolhido de modo a não corresponder aos padrões de busca empregados pela normalização, e resíduo de execução anterior é removido antes do processamento de cada CVE.

**Conferência do registro.** O registro é conferido por programa próprio, independente da normalização (Seção 5.1), que confronta os estados registrados com a existência das saídas brutas correspondentes. Como a reexecução de um lote acrescenta uma linha por CVE já concluído, a conferência considera, para cada CVE, a última linha registrada.

Quatro condições são apuradas:

| Condição | Interpretação |
|---|---|
| Estado de erro com saída bruta presente | Incoerência: houve produção de saída para item registrado como falho |
| Estado de conclusão sem saída bruta | Incoerência: a saída desapareceu ou nunca foi promovida ao nome definitivo |
| Estado de item já concluído, sem saída bruta | Incoerência: a idempotência apoiou-se em arquivo que não existe mais |
| Ausência de material analisável sem saída bruta | **Esperada**, apenas contabilizada — é a consequência assumida do estado próprio descrito acima |

A quarta conferência, acrescida nesta versão, é opcional e exige que se informe a lista do lote executado: confronta as linhas da lista com o conjunto de saídas brutas e de linhas do registro, de modo a identificar CVEs que não produziram saída **nem** linha de registro. Essa combinação é a assinatura observável de um defeito documentado da campanha preliminar, em que processos filhos consumiam a lista de entrada mantida na entrada padrão do laço e itens desapareciam sem deixar rastro. Exige-se a lista do lote, e não a lista completa, porque contra esta todo CVE de lote ainda não executado apareceria como ausente; o programa emite aviso quando a lista informada excede o tamanho de lote adotado.

**Pré-voo da imagem.** Antes de cada lote, o workflow executa o container sobre uma lista inexistente. Os scripts imprimem os limites de tempo efetivos, passam pelas guardas de integridade — do conjunto de regras vendorizado, do bundle do CodeQL, do binário do Snyk Code — e só então se interrompem por não encontrar a lista, sem criar registro nem saída. Imagem com script anterior ao esperado, imagem obsoleta em relação ao descritor versionado, limite de tempo inválido e volume não montado tornam-se falha em segundos, e não depois do lote inteiro. No Snyk Code, que exige credencial antes das guardas, o pré-voo usa credencial fictícia; a real não entra nessa etapa.

**Portão de lote sem saída bruta.** Lote que não produziu saída bruta alguma faz o job falhar. A condição é acrescentada pelo workflow e não altera o critério de saída dos programas de normalização e de conferência, porque neles, nesse caso, tudo termina com sucesso: sem saída para ler, não há incoerência a apontar. As causas prováveis são de infraestrutura — credencial revogada, rede de saída bloqueada no container, limite de tempo por item curto demais. **O portão nomeia a condição e não atribui causa**: ele também dispara num lote em que todos os CVEs resultem em ausência de material analisável, que é resultado e não falha. A causa é estabelecida pela contagem de estados da conferência do registro, que a mensagem manda ler.

Esse registro é publicado junto aos artifacts e versionado. Sua existência é condição para que ausências no conjunto de resultados possam ser explicadas — e não meramente constatadas. Os 24 registros de execução da campanha, um por lote e ferramenta, estão versionados como cópia exata dos artifacts (Seção 5.5).

### 4.7 Execução dos containers e propriedade dos artefatos

As imagens executam, por padrão, sob o usuário administrativo do container. Sem intervenção, as saídas brutas e os registros de execução são gravados no volume montado com propriedade desse usuário, e o usuário do hospedeiro — que executa a normalização e o controle de versão — não consegue reescrevê-los.

Adota-se a execução sob o identificador de usuário e de grupo do hospedeiro, com diretório pessoal e diretório de cache declarados explicitamente:

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e XDG_CACHE_HOME=/tmp \
    -v "$PWD":/workspace \
    <imagem> <lista-do-lote>
```

A alternativa — corrigir a propriedade dos arquivos após cada lote — foi descartada por resolver o atrito depois de criá-lo, e por depender de passo adicional que pode ser omitido.

**A declaração do diretório pessoal não é acessória.** Sob identificador de usuário ausente do cadastro interno da imagem, o diretório pessoal resolve para a raiz do sistema de arquivos, que não é gravável. A medição, sobre as três imagens efetivamente construídas:

| Imagem | Apenas com identificador de usuário | Com identificador e diretório pessoal |
|---|---|---|
| Semgrep | Falha ao criar diretório de estado | Correto |
| Snyk Code | Executa comandos de consulta, falha ao gravar configuração | Correto |
| CodeQL | Correto no hospedeiro de teste; **falha de escrita no ambiente da campanha** | Correto |

O êxito do CodeQL no hospedeiro de teste é **coincidência do identificador ali empregado**: a imagem base declara um usuário com o mesmo identificador, cujo diretório pessoal existe. Sob o identificador empregado pelos runners do serviço de integração contínua, a condição se iguala à das outras duas — o que o ensaio de fumaça confirmou, adiante. Por isso a forma de invocação é uniforme entre as três ferramentas, e não condicionada à ferramenta.

Verificou-se ainda, sob essa invocação, que o diretório temporário do container permanece gravável — nele residem o código obtido e o banco de dados do CodeQL —, que o volume montado recebe escrita, e que os arquivos resultantes têm a propriedade do usuário do hospedeiro.

**Registra-se uma armadilha de método.** A sondagem por comando de consulta de versão é insuficiente para as ferramentas que gravam estado de usuário: o Snyk Code responde corretamente a ela e falha ao gravar sua configuração. A verificação exige comando que escreva.

A escolha impõe uma restrição às rotinas de limpeza descritas na Seção 4.4, verificada nos três scripts: a remoção deve incidir sobre caminhos nominais, pois o diretório temporário passa a abrigar também o estado de usuário das ferramentas, e uma limpeza por expansão de padrão destruiria a autenticação no meio de um lote.

**Um segundo defeito de permissão, de sinal invertido.** O ensaio local revelou que a mesma decisão expõe o CodeQL a uma falha oposta: consultas precompiladas do bundle, com leitura restrita ao proprietário, tornam-se ilegíveis sob o identificador do hospedeiro e forçam recompilação integral (Seção 4.5).

Os dois defeitos são simétricos e igualmente dependentes de coincidência. O primeiro manifesta-se quando o identificador do usuário não consta do cadastro da imagem — condição do ambiente da campanha, e não do hospedeiro onde a decisão foi medida. O segundo manifesta-se quando o identificador difere do proprietário dos arquivos do bundle — condição do hospedeiro, e não do ambiente da campanha, onde os dois provavelmente coincidem.

Nenhum dos dois foi observado nos dois ambientes: cada um apareceu onde o outro não aparece. Ambos são corrigidos na construção da imagem, de modo que o comportamento deixe de depender de qual identificador executa.

**O primeiro defeito foi medido no ambiente da campanha, com controle, nas três imagens.** Em cada lote, o workflow executa cada imagem sob o identificador do runner em dois braços, variando só a declaração do diretório pessoal. Sem ela, o diretório pessoal resolve para a raiz e a escrita falha; com ela, opera. A consulta ao nome do usuário falha nas três imagens, o que confirma que o identificador do runner não consta do cadastro de nenhuma delas. No Semgrep e no Snyk Code, também o comando da própria ferramenta falha sem a declaração. **No CodeQL, o comando da ferramenta não foi sondado**: não se identificou comando dele que grave estado de usuário e custe segundos, e o de consulta de linguagens opera nos dois braços, sem discriminar. O resultado se repetiu nos oito lotes.

**O segundo não se manifesta ali** quando o identificador do ambiente coincide com o proprietário dos arquivos do bundle: um processo lê arquivo de que é proprietário ainda que a permissão restrinja os demais. A cobertura dos dois resulta, portanto, da união de duas medições em ambientes distintos, e não de uma medição única. O identificador efetivo do ambiente da campanha **deixou de ser premissa**. Sondagem executada no próprio ambiente em 12 de setembro de 2026 registrou identificador de usuário e de grupo, versão da imagem do ambiente, número de núcleos, memória e espaço disponíveis, e o resultado da escrita sob identificador explícito; a saída é datada e integra o repositório. O identificador coincide com o proprietário dos arquivos do bundle, de modo que o segundo defeito, como previsto, **não se manifesta ali** — e a cobertura dos dois permanece resultante da união das duas medições.

**O segundo defeito não foi medido na campanha.** A mediana de 47 segundos por CVE no CodeQL é compatível com a ausência de recompilação integral das consultas, mas isso é inferência a partir da duração, e não medida.

Registra-se que a sondagem consigna identificador de usuário e de grupo **em campos separados**, ainda que coincidam neste ambiente: a coincidência é propriedade do ambiente observado, não do protocolo, e nenhum ponto deste pode supô-la.

A mesma sondagem verificou, com controle, que o isolamento de rede opera no ambiente da campanha — o controle com rede alcançou o destino, e a sonda isolada, executada e respondida, não alcançou. A verificação distingue a ausência de alcance da ausência de execução, que a saída de um contêiner que não roda tornaria indistinguíveis.

---

## 5. Normalização dos resultados

### 5.1 Arquitetura da normalização

A normalização constitui etapa separada da execução das ferramentas. Os containers produzem exclusivamente a saída bruta; a conversão para o schema comum é realizada por um único programa, externo às imagens Docker, aplicado posteriormente sobre esses arquivos.

A separação decorre de assimetria de custo. A execução das ferramentas é onerosa — envolve obtenção de código, construção de bancos de dados e comunicação com serviços externos. A normalização é operação de leitura e reescrita, de custo desprezível. Como o código de normalização é o que mais provavelmente exigirá correção, ao lidar com três formatos heterogêneos, mantê-lo fora do container permite reprocessar apenas a normalização, sem repetir a coleta.

Em consequência, a verificação de idempotência do laço de análise incide sobre a saída bruta, não sobre o arquivo normalizado.

**Independência em relação ao registro de execução.** O programa de normalização não lê, não importa e não invoca o registro de execução. A propriedade é deliberada e integra o protocolo, não a implementação: a etapa barata não deve herdar as dependências da etapa cara, e registro ausente, parcial ou corrompido não pode impedir o reprocessamento da normalização. As conferências que necessariamente dependem do registro residem no programa próprio descrito na Seção 4.6, e os dois programas não se referenciam.

Daí decorre a origem do campo de commit no resultado normalizado: ele provém da lista de entrada, e não do registro. A asserção descrita na Seção 4.3 é fatal, de modo que, para todo CVE que possua saída bruta, o commit pretendido e o efetivamente analisado coincidem por construção. A evidência da verificação reside no registro de execução, que é versionado, e não se replica no resultado normalizado — que registra apenas o que foi conferido, não alegação não verificada.

**Preservação do que não é derivável.** As saídas brutas não são versionadas (Seção 5.5), de modo que a normalização é a última etapa em que a informação que elas contêm ainda existe. O que o schema não capturar deixa de existir no estudo quando as saídas brutas forem descartadas. Essa consideração fundamenta a inclusão, no schema, dos campos de diagnóstico e de cobertura descritos na Seção 5.2, que não são consumidos pela matriz de confusão mas sem os quais certas ausências de detecção se tornam inexplicáveis.

### 5.2 Schema comum

As três ferramentas SAST produzem saídas em formatos distintos. Os resultados são convertidos para um schema único, organizado em bloco de metadados por CVE e lista de achados:

```json
{
  "metadata": {
    "schema_version": "1.3",
    "cve_id": "CVE-2018-14040",
    "repository": "https://github.com/twbs/bootstrap.git",
    "commit": "13bf8aeae3db71e28af69782328c22215795c169",
    "tool": "semgrep",
    "tool_version": "1.171.0",
    "ruleset": {
      "name": "p/default",
      "sha256": "…",
      "rules_id_sha256": "…",
      "obtained_at": "2026-09-06T…",
      "rules_total": 1074
    },
    "rules_applied": 370,
    "analysis_date": "2026-09-10T14:32:11Z",
    "analysis_date_source": "file_mtime",
    "gt_cwes": ["CWE-079", "CWE-116"],
    "gt_cwe_primary": "CWE-079",
    "gt_file_path": "js/collapse.js",
    "gt_file_lines": [140],
    "gt_file_scanned": true,
    "gt_file_scanned_reason": "inventário de arquivos varridos, de paths.scanned",
    "tool_diagnostics": {
      "errors": 0,
      "skipped_paths": null,
      "notifications": null,
      "details": []
    }
  },
  "findings": [
    {
      "finding_id": "semgrep:CVE-2018-14040:0001",
      "rule_id": "javascript.lang.security.audit.xss",
      "cwe": ["CWE-079"],
      "has_cwe": true,
      "severity_original": "WARNING",
      "severity_normalized": "medium",
      "security_severity": null,
      "file_path": "js/collapse.js",
      "line_start": 142,
      "line_end": 145,
      "column_start": 24,
      "column_end": 30,
      "message": "..."
    }
  ]
}
```

Os campos prefixados por `gt_` reproduzem o ground truth do CVE analisado, permitindo que a comparação prescinda de junção com fonte externa. Por valerem para o CVE inteiro, situam-se no bloco de metadados e não são repetidos em cada achado.

O campo `gt_cwe_primary` registra o CWE selecionado conforme a Seção 7.4. Admite valor nulo nos CVEs sem CWE atribuído e naquele cujo conjunto permanece sem primário definido. Os identificadores do schema são grafados em inglês, por uniformidade; nomes de arquivo, estados do registro de execução e tabelas auxiliares conservam a grafia em português já adotada no repositório.

**Versão do schema.** O campo `schema_version` é literal e comparado na verificação de idempotência: resultado normalizado cuja versão divirja da corrente não é preservado silenciosamente. Sem ele, a evolução do schema produziria conjunto de resultados heterogêneo sem sinalização.

**Conjunto de regras.** O campo `ruleset` é estrutura, e não cadeia descritiva, de modo a permitir conferência automática. Reúne o nome do conjunto, seus dois resumos, a data de obtenção e a contagem total de regras; o campo `rules_applied`, à parte, registra quantas regras a execução efetivamente aplicou ao repositório analisado.

O nome do campo corrige o da versão anterior. A medição descrita na Seção 4.5 estabeleceu que o inventário disponível enumera regras aplicadas, e não carregadas, de modo que o valor varia com o conteúdo do repositório e é legitimamente inferior ao total declarado. A comparação entre os dois deixa, por isso, de servir como detector de conjunto obsoleto; permanece como verificação do extremo inferior, em que inventário vazio sinaliza que nenhuma regra se aplicou.

A inclusão do resumo da lista ordenada de identificadores — a identidade secundária descrita na Seção 4.5 — é obrigatória no Semgrep. Sem ela, quem examinasse um resultado normalizado isolado disporia apenas do resumo do arquivo, que não permite verificar identidade de conjunto, dada a ordenação variável com que o registry o serve.

O preenchimento difere por ferramenta: completo no Semgrep, cuja opção de temporização registra o inventário carregado; parcial no CodeQL, onde o nome corresponde à referência da suíte e o inventário de regras carregadas não é recuperável da saída, que registra apenas as regras comparecentes; e ausente no Snyk Code, que não expõe conjunto de regras declarável.

**Origem da data de análise.** O campo `analysis_date_source` declara de onde a data provém: da própria saída da ferramenta, quando esta a registra, ou do carimbo de tempo do arquivo de saída bruta, quando não registra. A distinção é necessária porque a segunda origem é proveniência mais fraca — não sobrevive à transferência do arquivo nem à obtenção do repositório por clone, caso em que o carimbo passa a ser o do momento da obtenção. Declarar a origem é preferível a uniformizar por aparência um campo cuja confiabilidade difere entre ferramentas.

**Varredura do arquivo do ground truth.** O campo `gt_file_scanned` registra se o arquivo apontado pelo ground truth foi efetivamente considerado pela ferramenta, em três estados: verdadeiro, falso e indeterminado. O terceiro estado é acompanhado do campo `gt_file_scanned_reason`, que declara a causa da indeterminação, uma vez que ela admite mais de uma — a saída do CodeQL não registra inventário de arquivos considerados; a do Semgrep pode não registrá-lo; e a do Snyk Code pode registrá-lo agregado por linguagem, sem discriminação de caminhos. Sem o motivo, as três situações se tornam indistinguíveis na leitura.

A motivação é concreta. Cinco CVEs do conjunto apontam arquivos sem extensão — `bin/public` e `bin/http-live` —, e ferramentas que selecionam alvos por extensão os ignorariam internamente, sem produzir erro. O efeito emergiria como ausência de detecção indistinguível de limitação legítima da ferramenta. A verificação é aplicada aos 223, e não apenas a esses cinco: o custo é o mesmo e o resultado fornece o denominador de arquivos efetivamente considerados por ferramenta.

**O valor falso não exclui o CVE de denominador algum.** A causa, neste caso, é interna à ferramenta — decorre de sua configuração predefinida, que é justamente o objeto da avaliação —, ao contrário da indisponibilidade de repositório tratada na Seção 7.4, cuja causa é externa. Excluir ocultaria aquilo que o estudo se propõe a medir, e reproduziria, na etapa de captura, a decisão de análise que a Seção 4.5 recusa quanto às regras do Semgrep. O campo é registrado e contabilizado; o denominador é decisão da etapa de análise comparativa, onde a dupla apuração já fornece o instrumento adequado.

**Valor original do caminho do ground truth.** O campo `gt_file_path_original` comparece apenas quando o caminho declarado pelo benchmark exigiu normalização — hoje um único CVE (Seção 2.2.3). Preserva o valor como distribuído, de modo que o resultado normalizado permaneça cotejável com a fonte sem consulta ao relatório da normalização.

**Diagnósticos da ferramenta.** O bloco `tool_diagnostics` reúne o que cada ferramenta reporta sobre a própria execução: erros parciais, caminhos descartados e notificações de execução. A motivação é a mesma da verificação de varredura: um arquivo cuja análise falhou não produz achado, e o resultado é indistinguível de análise limpa. Os campos são capturados quando presentes e registrados como indeterminados quando ausentes; a ausência nunca constitui falha, uma vez que a emissão desses campos não está assegurada em todas as ferramentas.

O indicador de afetação do arquivo do ground truth é **heurístico** — apoia-se na ocorrência do caminho no texto dos diagnósticos, que pode estar truncado — e o schema declara essa condição em campo próprio, para que não seja lido como afirmação. Não integra contagem alguma da matriz de confusão.

O campo `line_end` admite valor nulo: encontra-se ausente na quase totalidade dos achados do CodeQL. O campo `security_severity` é exclusivo do CodeQL e discutido na Seção 5.4.

**Estrutura das saídas de origem.** Registra-se, para fins de reprodutibilidade da etapa de normalização, a localização dos campos relevantes em cada formato de origem:

| | CodeQL | Semgrep | Snyk Code |
|---|---|---|---|
| Formato | SARIF 2.1.0 | JSON próprio | SARIF 2.1.0 |
| CWE | `driver.rules[].properties.tags[]`, prefixo `external/cwe/` | `extra.metadata.cwe` | `driver.rules[].properties.cwe[]` |
| Caminho | `locations[0].physicalLocation.artifactLocation.uri` | `path` | como CodeQL |
| Linhas | `region.startLine`; `endLine` raro | `start.line` / `end.line` | `region.startLine` / `endLine` |
| Severidade | apenas na regra (exige junção) | `extra.severity` | `level` |
| Identificador | `ruleId` | `check_id` | `ruleId` |

Três particularidades exigem tratamento específico. O campo de CWE do Semgrep alterna entre lista e cadeia de caracteres simples conforme a regra, de modo que iteração ingênua percorreria caracteres individuais. A severidade do CodeQL não consta do achado, existindo apenas na tabela de regras, o que exige junção — a única das três nessa condição, e a mais sujeita a produzir valor nulo sem sinalização. E a associação entre achado e regra é realizada pelo identificador textual, não pelo índice posicional.

Registra-se que esta tabela deriva da documentação das ferramentas e da inspeção das saídas da campanha preliminar, e não de saída produzida pelo pipeline reconstruído. A limitação decorrente consta da Seção 12.1.

### 5.3 Regras de normalização

**Identificadores CWE.** Todos os identificadores são normalizados para o formato de três dígitos com zero à esquerda (`CWE-079`), em todas as fontes — ground truth e saídas das ferramentas. Sem essa normalização, `CWE-79` e `CWE-079` seriam tratados como categorias distintas, corrompendo silenciosamente toda a análise. Conforme a Seção 2.2.1, quatorze registros do próprio ground truth exigem essa conversão. A conversão é realizada por uma única implementação, aplicada a todos os pontos em que identificadores são comparados, inclusive na construção da chave de busca da tabela de CWE primário.

**Caminhos de arquivo.** Cada ferramenta pode reportar caminhos com prefixos decorrentes do diretório de execução no container. Todos são normalizados para caminho relativo à raiz do repositório, condição necessária para o cotejo com o campo de caminho do ground truth. A verificação empírica descrita na Seção 4.5 indica que as três emitem caminho já relativo; a normalização permanece como salvaguarda, e o número de casos em que efetivamente transformou algum valor é contabilizado e declarado, distinguindo-se a contagem de achados transformados da contagem de transformações aplicadas, uma vez que um mesmo achado pode exigir mais de uma.

Caminho absoluto emitido por ferramenta e não reconhecido pela normalização é **preservado e reportado com destaque**, jamais convertido por conjectura: sua ocorrência significa que a premissa de invocação a partir do diretório de trabalho não se sustentou, e essa é informação de primeira ordem para o estudo. O relatório da normalização não afirma a invariante quando ela falhou.

No ensaio local (Seção 8.6), nenhum dos 285 achados produzidos pelas três ferramentas exigiu transformação, e o mesmo se verificou nos caminhos dos inventários de varredura. A única transformação de caminho registrada no estudo incide sobre o ground truth, no caso descrito na Seção 2.2.3.

**Ordenação dos achados.** Os achados de cada CVE são ordenados por chave determinística antes da atribuição do identificador sequencial, de modo que o artefato versionado não varie com a ordem de emissão. A chave compreende caminho, linha inicial, linha final, coordenadas de coluna, identificador de regra e mensagem, com o índice de emissão como desempate final.

A inclusão das coordenadas de coluna, nesta versão, torna a chave total no conjunto observado. Antes dela, o ensaio local registrou onze coincidências, correspondentes a ocorrências distintas do mesmo padrão na mesma linha, indistinguíveis no artefato ainda que distintas na saída de origem. Com a coordenada, as coincidências desaparecem, e empate remanescente passa a significar o que o protocolo afirma: achados idênticos em todo campo que o schema preserva.

**Normalização do ground truth.** Aplica-se ao ground truth a mesma disciplina, em identificadores **e** em caminhos: a barra inicial do caso descrito na Seção 2.2.3 é removida antes de qualquer comparação, o valor original é preservado e a ocorrência é registrada. A assimetria com o parágrafo anterior é deliberada e tem fundamento: o caminho do benchmark é, por definição, relativo à raiz do repositório, ao passo que o caminho emitido por ferramenta carrega informação sobre a execução.

**Achados sem CWE.** Regras sem CWE mapeado produzem lista de identificadores vazia e indicador negativo. Tais achados integram a análise de capacidade, mas não as métricas por CWE.

**Severidade.** Tratada na Seção 5.4.

**Análises sem achados.** Todo CVE analisado produz arquivo de saída, ainda que com lista de achados vazia. A distinção entre analisado sem achados e não analisado é assim preservada no próprio conjunto de resultados. No caso do Snyk Code, registra-se adicionalmente o inventário de arquivos considerados, que permite distinguir ausência de achados de ausência de material analisável.

**Saída bruta ilegível.** Arquivo que não seja processável, ou que não apresente a estrutura mínima esperada, interrompe o tratamento daquele CVE com erro explícito, sem produção de resultado normalizado, e a ocorrência é contabilizada. Em nenhuma circunstância a falha de leitura produz lista de achados vazia: isso converteria defeito de leitura em ausência legítima de detecção, que é precisamente a confusão que o protocolo se propõe a evitar desde a escrita atômica da Seção 4.6. A condição não interrompe o processamento dos demais CVEs, e a execução termina com código de saída não nulo quando houve ao menos uma ocorrência.

### 5.4 Severidade

As três ferramentas empregam vocabulários próprios. Preserva-se o valor de origem e acrescenta-se o valor normalizado, conforme a correspondência:

| Origem | Normalizado |
|---|---|
| CodeQL `error` · Semgrep `ERROR` · Snyk `error` | `high` |
| CodeQL `warning` · Semgrep `WARNING` e `MEDIUM` · Snyk `warning` | `medium` |
| CodeQL `note` · Semgrep `INFO` · Snyk `note` | `low` |
| Regra resolvida sem nível declarado | `unknown` |
| Regra não resolvida pelo identificador | `unresolved` |

Valor não previsto na tabela interrompe a normalização com identificação do valor e do CVE, em lugar de receber atribuição implícita.

**Os dois últimos estados são distintos e não se colapsam.** O primeiro corresponde a ausência legítima: a regra foi localizada na tabela de regras da saída e não declara nível. O segundo corresponde a falha de junção: o identificador do achado não foi localizado. Registrar ambos sob o mesmo rótulo ocultaria um defeito do próprio programa de normalização atrás de uma categoria prevista pelo protocolo. Os dois são contabilizados em separado e declarados. Nenhum dos dois ocorreu na campanha preliminar; a ocorrência de qualquer um deles é sinal a investigar, e não condição esperada.

Duas observações delimitam o alcance da correspondência.

O vocabulário do Semgrep comporta o valor `MEDIUM`, oriundo de escala qualitativa distinta da clássica `ERROR`/`WARNING`/`INFO`, empregada por regras recentes de cadeia de suprimentos. O exame dos eixos auxiliares de impacto e probabilidade situa tais regras na mesma faixa composta que `WARNING`, o que sustenta a correspondência adotada. Registra-se, contudo, que a equivalência vale no composto e não no impacto isolado. Na prática a questão é inconsequente para o estudo: a totalidade dos achados assim classificados na campanha preliminar pertencia a famílias fora do escopo de JavaScript e TypeScript. A contagem do conjunto vendorizado (Seção 4.5) confirma que o vocabulário é fechado nesses quatro valores.

O CodeQL fornece, além do nível textual, um escore numérico de severidade de segurança. Não se adota esse escore como base da normalização. Os dois campos medem grandezas distintas: o nível textual deriva da severidade declarada do problema e expressa confiança na alegação, ao passo que o escore numérico exprime impacto na escala CVSS. A relação entre ambos não é monotônica — um mesmo escore comparece tanto em regras de nível `warning` quanto `error` —, de modo que a substituição não refinaria a escala, e sim alteraria a grandeza medida. Acresce que nenhuma das outras duas ferramentas fornece grandeza equivalente, o que tornaria o campo comparável apenas consigo mesmo.

O escore é, ainda assim, preservado em campo próprio, numérico e anulável, disponível para análises internas ao CodeQL. Seu formato admite representações distintas para o mesmo valor, exigindo conversão numérica antes de qualquer comparação.

**Severidade não resolvida.** O número de achados do CodeQL cuja severidade não pôde ser obtida por junção com a tabela de regras é contabilizado e declarado, em separado da ausência legítima de nível.

### 5.5 Política de versionamento

O repositório do estudo adota a seguinte política, de modo que a verificação dos resultados não dependa de artefatos temporários:

| Categoria | Situação |
|---|---|
| Metadados, listas e scripts geradores | Versionados |
| Dockerfiles, scripts de análise, workflows | Versionados |
| Programa de normalização e conferidor do registro | Versionados |
| Fixtures sintéticas de verificação da normalização | Versionadas |
| Resultados normalizados | Versionados |
| Registros de execução e relatórios de normalização | Versionados |
| Tabela de mapeamento de CWE primário | Versionada |
| Scripts de caracterização do ground truth | Versionados |
| Documento de critérios do cruzamento | Versionado |
| Programas de cruzamento e de apuração da circularidade, com suas fixtures | Versionados |
| Resultados do cruzamento (`results/cruzamento/`) | Versionados |
| Saídas do cotejo de proveniência (`results/proveniencia/`) | Versionadas |
| Apuração da circularidade (`results/circularidade/`) | Versionada |
| Registros de execução, relatórios de normalização e demais conteúdos dos artifacts da campanha, por lote | Versionados |
| Sondagens datadas do ambiente e das imagens | Versionadas |
| Saídas brutas das ferramentas | Não versionadas; cópia externa |
| Clones temporários e bancos de dados do CodeQL | Não versionados |

A decisão de versionar os resultados normalizados e os registros de execução responde a uma limitação da campanha preliminar, na qual todos os resultados residiam exclusivamente em artefatos do GitHub Actions, sujeitos a expiração — cuja retenção padrão é de noventa dias, configurável entre um e noventa em repositório público —, o que impedia a verificação posterior dos números apresentados.

As saídas brutas permanecem fora do controle de versão por serem volumosas e integralmente deriváveis: os resultados normalizados são gerados a partir delas, e a reexecução as reproduz. Essa decisão é o que confere caráter terminativo à normalização, conforme a Seção 5.1.

**O volume que justifica a decisão, medido na campanha:** 623 MiB de saída bruta, dos quais o Semgrep responde por 548 MiB (88%); o maior arquivo isolado, de 144 MiB — o Semgrep sobre o `CVE-2018-20801`, o mesmo CVE que responde por 5.850 achados —, seria recusado pelo serviço de hospedagem sem extensão de armazenamento de arquivos grandes. Os resultados normalizados somam 15,5 MiB.

**Cópia externa.** Como os artifacts expiram noventa dias após a execução — em 15 e 16 de dezembro de 2026, para os lotes da campanha —, as saídas brutas foram preservadas em cópia comprimida, um arquivo por ferramenta, somando 6,35 MiB, com sha256 registrado no repositório. Os 658 arquivos contidos foram conferidos por sha256 contra os artifacts. **A cópia fica fora do repositório**, e a reprodução exata a partir das saídas brutas depende dela.

**O restante dos artifacts da campanha está versionado** — registros de execução, relatórios de normalização, saídas das conferências, saídas do container e as sondagens executadas em cada lote —, como cópia exata, com manifesto de sha256. Antes do versionamento, esse conteúdo passou por varredura de segredos com controle positivo, porque o job do Snyk Code carrega credencial no ambiente; nenhuma foi encontrada. Com isso, tudo o que os artifacts continham está no repositório ou na cópia externa.

**Saídas de análise determinísticas.** Os resultados do cruzamento, as saídas do cotejo de proveniência e a apuração da circularidade não gravam carimbo de execução: mesmas entradas e mesmo código produzem os mesmos bytes, conferido sob variação da semente de dispersão do interpretador. Cada saída registra o sha256 das entradas e dos programas que a produziram. Diferença no controle de versão, após reexecução, é mudança de entrada ou de código, nunca de relógio. Os programas recusam gravar nas saídas versionadas se alguma entrada estiver fora do repositório, porque o caminho da máquina do operador iria para elas.

**Imagens privadas no registro.** As três imagens publicadas no GitHub Container Registry permanecem **privadas**, com a decisão de torná-las públicas pendente da leitura das licenças do conjunto de regras do Semgrep e do bundle do CodeQL. Enquanto forem privadas, um terceiro não obtém as imagens pelos digests registrados: pode reconstruí-las a partir dos Dockerfiles versionados, mas obtém bytes diferentes, porque centenas de pacotes são resolvidos no momento da construção. Pendência registrada na Seção 14.

Os scripts de caracterização do ground truth referidos nas Seções 2.2.1 e 2.2.2 são versionados junto ao estudo, de modo que os números ali declarados possam ser reproduzidos por terceiros a partir do repositório do benchmark.

Documenta-se ainda, em arquivo próprio na raiz do repositório, o conjunto de regras e convenções do projeto — unidade de análise, formato das listas, obrigatoriedade do checkout do commit vulnerável, política de versionamento e defeitos conhecidos do conjunto de dados.

O repositório do estudo foi publicado em acesso público em setembro de 2026, resolvendo a limitação operacional registrada nas versões anteriores deste documento — até então mantinha-se em cópia local única, sem espelhamento remoto, condição que a política acima não podia cumprir, pela mesma razão que o versionamento dos relatórios da campanha DAST veio corrigir (Seção 6.1). A publicação é decisão metodológica antes de operacional: o protocolo descrito aqui existe para ser reexecutado por terceiro, e o repositório integra o resultado tanto quanto os números que ele sustenta.

### 5.6 Verificação da normalização

O programa de normalização foi construído antes da existência de qualquer saída real do pipeline reconstruído. Sua verificação apoia-se, por isso, em **fixtures sintéticas** — arquivos de entrada escritos à mão, versionados junto ao estudo, acompanhados de uma suíte de asserções sobre os resultados esperados.

As fixtures exercitam as condições que o protocolo declara relevantes e que, por sua natureza, não produzem erro visível: campo de CWE em ambos os tipos admitidos pelo Semgrep; regra sem nível de severidade declarado; identificador de achado ausente da tabela de regras; saída sem achados; saída truncada; saída estruturalmente incompleta; caminho de arquivo do ground truth sem extensão e em forma absoluta; caminho emitido com prefixo relativo, com esquema de protocolo e em forma absoluta não reconhecida; CVE sem CWE, com CWE único, com conjunto presente na tabela de primário, com primário indefinido e com conjunto ausente da tabela; inventário de arquivos considerados em ambas as formas previstas; notificações de execução presentes, vazias e ausentes; colisão sob a chave de ordenação; e ordem de entrada invertida.

**A origem das fixtures determina o alcance da verificação.** Na construção inicial, todas derivavam da documentação das saídas, não de saída real: um erro nessa referência seria reproduzido pela fixture, e a asserção correspondente passaria. A verificação estabelecia que o programa faz o que o protocolo determina *dado o formato que o protocolo supõe*, sem estabelecer que esse formato corresponde ao emitido.

O ensaio local (Seção 8.6) reduziu essa lacuna, sem eliminá-la. Onde a confrontação revelou divergência, a fixture foi corrigida contra a saída real e a suíte reexecutada — de modo que parte das fixtures passa a derivar de observação, e não de documentação. Um caso é ilustrativo: a fixture do CodeQL modelava determinada notificação como indício de falha de extração, e a medição estabeleceu que ela indica extração bem-sucedida. A suíte passava afirmando a polaridade inversa da real.

A lacuna residual é de amostra, não mais de origem, e consta da Seção 12.1.

Lacunas residuais registradas na versão anterior: volume, codificação de caracteres fora do repertório ASCII, e dois avisos de execução para os quais há tratamento no código sem fixture que os dispare. **A primeira foi resolvida pela campanha**: a normalização rodou sobre 18.664 achados reais, em 658 resultados, com zero falhas e zero saídas brutas ilegíveis. As outras duas permanecem: não se apurou se algum achado real trouxe texto fora do repertório ASCII, e os dois avisos continuam sem fixture.

O relatório produzido a cada execução da normalização é versionado (Seção 5.5) e registra as contagens que a monografia declara: resultados produzidos, omitidos e falhos; transformações de caminho, com valores anterior e posterior; distribuição das severidades normalizadas e os dois contadores da Seção 5.4; ocorrências de campo de CWE em forma não canônica; estados do CWE primário; estados da varredura do arquivo do ground truth, agregados por motivo; a conferência de completude do inventário do CodeQL; diagnósticos das ferramentas; colisões sob a chave de ordenação; saídas brutas ilegíveis; e a duração da operação.

Anomalia registrada apenas no arquivo de relatório é anomalia que depende de leitura posterior para ser notada. As que exigem atenção imediata são também emitidas no fluxo de erro da execução.

A duração é registrada por decorrer dela a premissa que sustenta a arquitetura da Seção 5.1: se a normalização não for de custo desprezível em volume real, a separação entre coleta e normalização deixa de ter a justificativa que lhe foi dada, e a premissa deve ser revista à luz da medição.

**A premissa se sustenta.** Somada sobre os oito lotes da campanha, no ambiente de execução:

| Ferramenta | Normalização | Análise (soma por CVE) | Fração |
|---|---:|---:|---:|
| CodeQL | 0,96 s | 3,63 h | 0,007% |
| Semgrep | 25,65 s | 1,36 h | 0,52% |
| Snyk Code | 0,31 s | 1,14 h | 0,007% |

Cerca de 27 segundos de normalização contra cerca de seis horas de análise. Um terço do tempo do Semgrep vem de um único CVE, o `CVE-2018-20801`, cuja saída bruta tem 144 MiB. A medida cobre o laço sobre as saídas brutas, e não a carga do ground truth.

**A chave de ordenação é suficiente em escala.** Zero colisões nas três ferramentas, sobre os 18.664 achados. O zero tem controle positivo: com a chave sem as colunas, na forma anterior do schema, o mesmo método acusa 60, 624 e 4 colisões (CodeQL, Semgrep, Snyk Code). São as colunas que levam a contagem a zero, o que confirma a decisão de acrescentá-las.

**Verificação dos programas de cruzamento.** Os dois programas acrescentados depois da campanha seguem a mesma disciplina.

O programa de cruzamento (`tools/cruza-deteccao.py`) é verificado por 23 casos sintéticos escritos sobre o ground truth real, com caso positivo e negativo em cada nível e variante da Seção 7.2, e por mutantes: 41 externos, que alteram o conjunto de entrada, e 34 embutidos, que rodam a cada execução e exigem que cada guarda dispare pelo motivo pretendido. Sete defeitos plantados no próprio programa foram todos acusados: seis por duas camadas independentes, e um — o casamento de caminho pelo nome do arquivo, em vez do caminho completo — por um único caso sintético.

O programa de apuração da circularidade (`tools/circularidade-proveniencia.py`) tem como controle principal a reconstrução da matriz publicada: a soma dos dois grupos da partição reproduz os acertos de cada ferramenta em cada nível, em 21 células e duas partições, sem divergência.

---

## 6. Protocolo DAST

### 6.1 Execução

O OWASP ZAP foi executado em 24 de julho de 2026 contra as duas aplicações alvo, em dois modos:

- **Baseline** — análise passiva, sem ataques ativos.
- **Full scan** — análise passiva acrescida de ataques ativos.

Os relatórios foram gerados em JSON e HTML por aplicação e modo, com a versão 2.17.0 do ZAP.

As contagens de alertas, extraídas diretamente dos relatórios JSON, são:

| Aplicação | Modo | Alto | Médio | Baixo | Informativo | Total |
|---|---|---|---|---|---|---|
| Juice Shop | Baseline | 0 | 2 | 5 | 3 | 10 |
| Juice Shop | Full | 0 | 5 | 5 | 4 | 14 |
| NodeGoat | Baseline | 1 | 5 | 9 | 8 | 23 |
| NodeGoat | Full | 3 | 7 | 9 | 10 | 29 |

Registra-se que documentação preliminar do projeto apresentava contagens inferiores (8, 9, 19 e 17), correspondentes ao resumo de console do ZAP, que exclui os alertas de nível informativo. Os valores acima, obtidos dos relatórios em JSON, são os adotados.

**Versionamento dos relatórios.** Os oito relatórios — JSON e HTML por aplicação e modo — e o plano de automação empregado integram o repositório do estudo. A campanha DAST produziu os únicos dados de detecção válidos até o momento, e existiam em cópia única fora de controle de versão. As quatro contagens da tabela acima são, em consequência, reproduzíveis a partir dos arquivos versionados, e não apenas afirmadas.

**Correspondência entre arquivo e modo.** Os relatórios em JSON não registram o modo de execução, e a associação apoiava-se na nomenclatura dos arquivos — insuficiente em um dos quatro casos, cujo nome não distingue o modo. A associação foi estabelecida por contagem: o arquivo em questão apresenta dez alertas, correspondentes ao modo baseline do Juice Shop, e os demais reproduzem exatamente os valores da tabela. Os nomes originais foram preservados, por serem o artefato efetivamente produzido pela execução.

A correspondência é registrada em documento próprio junto aos relatórios, criado em setembro de 2026. Até então as versões anteriores deste documento afirmavam que ela ali constava, e o documento não existia — ocorrência registrada na Seção 12.5. A associação foi, na ocasião, reestabelecida e ampliada:

- **Em duas unidades de contagem.** Além dos tipos de alerta, que produzem os valores da tabela acima, contou-se a soma de instâncias por alerta. As duas séries discriminam igualmente os quatro arquivos, de modo que a atribuição não depende da unidade escolhida; declara-se qual delas corresponde aos números aqui apresentados.
- **Por evidência independente da contagem.** Os dois relatórios de full scan registram alertas oriundos de regras de varredura ativa, e os dois de baseline não registram nenhum — critério que decide o modo sem recurso a contagem de totais. A aplicação-alvo é obtida do próprio relatório, e cada relatório em HTML é pareado ao seu JSON pelo conjunto de nomes de alerta, e não por semelhança de nome de arquivo.

Observa-se que os únicos alertas de risco alto do estudo provêm do full scan do NodeGoat — Cross Site Scripting refletido e baseado em DOM (CWE-079) e SQL Injection (CWE-089) —, circunstância coerente com a exclusão documentada na Seção 6.2, que afeta o Juice Shop.

### 6.2 Delimitação do ground truth do Juice Shop

Duas exclusões são aplicadas ao `challenges.yml` antes de qualquer comparação.

**Exclusão por ambiente de execução.** O campo `disabledEnv` indica ambientes nos quais o desafio permanece desativado. Diversos desafios listam Docker nesse campo, incluindo a maioria dos desafios de XSS, além de XXE, RCE, SSTi, LFR e NoSQL DoS.

Como a aplicação foi executada em Docker, esses desafios são excluídos do ground truth: as vulnerabilidades correspondentes não estavam ativas na instância submetida à varredura, e computá-las como falsos negativos mediria um alvo inexistente.

Esta exclusão tem consequência interpretativa direta: a ausência de detecção de XSS pelo ZAP no Juice Shop não constitui falha da ferramenta.

**Exclusão por detectabilidade.** Aplica-se filtro pelas tags oficiais do projeto, adotadas como critério objetivo de indetectabilidade por varredura automatizada:

| Tag | Motivo da exclusão |
|---|---|
| OSINT | Requer pesquisa externa à aplicação |
| Web3 | Requer interação com contrato inteligente |
| AI/LLM | Injeção de prompt em chatbot |
| Shenanigans | Conteúdo lúdico sem correspondente técnico |
| Code Analysis | Requer inspeção do código-fonte |

Ao filtro objetivo segue-se revisão manual do subconjunto remanescente, com critério registrado em apêndice.

O emprego da metadata oficial do projeto, em lugar de classificação subjetiva item a item, torna o critério auditável.

Observa-se que a tag Code Analysis identifica precisamente os desafios que exigem inspeção de código-fonte — domínio da análise estática. A constatação é aproveitada na discussão de complementaridade entre as abordagens.

### 6.3 Dupla apuração

As métricas DAST são apuradas duas vezes: contra o ground truth integral e contra o subconjunto filtrado.

O procedimento tem duplo propósito. Primeiro, previne a objeção de que o filtro tenha sido ajustado até produzir resultados favoráveis. Segundo, a diferença entre as duas apurações constitui, em si, um resultado: quantifica o grau de inadequação do benchmark para avaliação de ferramentas dinâmicas.

---

## 7. Protocolo de análise comparativa

### 7.1 Taxonomia comum

O CWE é adotado como pivô único de tradução entre as fontes:

- O OpenSSF fornece CWE diretamente.
- Cada alerta do ZAP registra um campo `cweid`.
- As categorias do Juice Shop são mapeadas manualmente para CWE.
- A correspondência CWE → OWASP Top 10 2021 emprega a lista oficial publicada pela OWASP.

Optou-se por convergir todas as fontes a um único ponto de tradução, em vez de estabelecer correspondências diretas entre taxonomias heterogêneas.

**Famílias de identificadores.** Certos CWEs do benchmark constituem variantes de uma mesma classe — CWE-023, CWE-036, CWE-073 e CWE-099 são especializações ou vizinhos de travessia de caminho, e comparecem sempre em conjunto com o CWE-022.

A versão 3 deste documento registrava a hipótese de que a comparação por identificador exato subestimaria a detecção, uma vez que as ferramentas tendem a rotular suas regras apenas com os identificadores mais gerais da família. A caracterização descrita na Seção 2.2.2 explica e dispensa essa hipótese.

O agrupamento em família não é convenção de rotulagem das ferramentas: é propriedade do ground truth, que herdou o conjunto de tags da consulta que originou cada registro. Os cinco identificadores de travessia de caminho comparecem juntos nos 21 CVEs correspondentes porque são as tags declaradas pela consulta `js/path-injection`, e não porque cinco defeitos distintos coexistam naquele arquivo. O mesmo se verifica nos demais conjuntos.

Em consequência, não se adota critério de agrupamento por família na comparação. O problema que tal critério pretenderia resolver é tratado na origem, pela seleção do CWE primário descrita na Seção 7.4, que opera sobre o ground truth e não sobre a saída das ferramentas.

### 7.2 Unidade da matriz de confusão

As granularidades disponíveis diferem entre as abordagens, o que impõe matrizes de confusão separadas:

| Abordagem | Unidade | Fundamento |
|---|---|---|
| SAST | (CWE, arquivo) | Ver justificativa abaixo |
| DAST | (categoria, aplicação) | Ausência de localização no `challenges.yml` |

Registra-se, conforme a Seção 2.2.1, que a dimensão de arquivo é degenerada neste conjunto: cada CVE mapeia exatamente um arquivo, de modo que o par (CWE, arquivo) equivale ao par (CWE, CVE). A unidade adotada não é, portanto, mais grosseira do que a alternativa de tomar o CVE como referência — as duas coincidem. A escolha permanece expressa em termos de arquivo por ser essa a forma em que as ferramentas reportam seus achados.

**Da unidade de arquivo aos cinco níveis de acerto.** A Versão 9 adotava o arquivo como unidade e aproveitava a linha apenas como métrica auxiliar de localização, com dois motivos: a definição do verdadeiro negativo e a convenção de reporte das ferramentas. **Esta versão substitui esse arranjo** por cinco níveis de acerto, todos apurados na mesma passada, fixados em documento versionado antes de qualquer número de detecção (`docs/criterios-cruzamento.md`).

| Nível | Critério | O que estabelece |
|---|---|---|
| 0 | ao menos um achado na árvore analisada | limite superior; quase sem valor isolado |
| 1 | ao menos um achado no arquivo do ground truth | a ferramenta considerou o lugar certo |
| 2 | nível 1 **e** o CWE casa | lugar certo, natureza certa |
| 3 | nível 1 **e** a linha casa | lugar certo, ponto certo |
| 4 | nível 3 **e** o CWE casa | o estrito: arquivo, ponto e natureza |

Um CVE conta para um nível se ao menos um achado satisfaz o critério; nos níveis 2, 3 e 4, **o mesmo achado** tem de satisfazer todas as condições. Um achado acertar o arquivo e outro acertar o CWE não constitui acerto de nível 2.

**Os níveis 2 e 3 não formam escada.** Um exige o CWE, o outro a linha; uma ferramenta pode acertar mais no nível 3 que no 2.

**Nenhum critério único é escolhido.** Escolher um seria arbitrar; computar vários e reportar a diferença entre eles é resultado. O intervalo entre o nível 1 e o 3 mede quanto a ferramenta erra o ponto dentro do arquivo certo; entre o 1 e o 2, quanto erra a natureza.

**Os dois motivos da Versão 9 não se perdem; mudam de função.** A convenção de reporte das ferramentas — umas indicam o ponto de entrada do dado não confiável, outras o ponto de uso — é a razão para manter os níveis 1 e 2, que avaliam no arquivo e não dependem da linha: a ferramenta que acerta o arquivo com convenção de reporte distante da linha registrada não é computada como ausência de detecção em todos os níveis. A definição do verdadeiro negativo continua proibindo a linha como universo de negativos, que seria arbitrariamente grande; o verdadeiro negativo adotado nesta versão é outro, um ponto por CVE, na versão corrigida (Seção 7.3).

**O critério de linha é descrito na Seção 7.7**, e o de CWE, com as duas variantes, na Seção 7.4.

### 7.3 Definições operacionais

**Esta seção foi reescrita nesta versão.** A Versão 9 definia os quatro quadrantes da matriz de confusão com uma definição de falso positivo — "a ferramenta reporta um CWE em um arquivo em que o ground truth não o registra" — que **não é a do benchmark e não se sustenta**, e que o documento de critérios, na sua primeira redação, levou a abandonar em sentido oposto, afirmando que falso positivo e verdadeiro negativo eram incomputáveis. As duas posições estavam erradas.

**O que o benchmark diz.** O README do OpenSSF CVE Benchmark declara que, ao analisar também as versões corrigidas dos mesmos códigos, mede a taxa de falsos positivos com base em correções reais e validadas, e formula duas perguntas por CVE: se a ferramenta detecta a vulnerabilidade ou produz um falso negativo; e se, rodando sobre o código corrigido, reconhece a correção ou produz um falso positivo. A documentação dos CVEs do benchmark garante que o commit posterior à correção não contém a vulnerabilidade.

**O rótulo negativo existe:** é a versão corrigida do código, no ponto da falha. Ali, o benchmark afirma que a vulnerabilidade foi removida.

**Definição adotada pelo estudo, a partir das duas perguntas do README e daquela garantia:**

| Versão analisada | O que o benchmark garante no ponto da falha | Alerta ali | Resultado |
|---|---|---|---|
| antes da correção (`PrePatchCommit`) | a falha existe | sim | verdadeiro positivo (VP) |
| antes da correção | a falha existe | não | falso negativo (FN) |
| depois da correção (`PostPatchCommit`) | a falha foi removida | sim | **falso positivo (FP)** |
| depois da correção | a falha foi removida | não | **verdadeiro negativo (VN)** |

Na versão anterior à correção, "alerta ali" é o nível de acerto da Seção 7.2. Na versão corrigida, o critério de casamento é o que a campanha da versão corrigida precisa fixar (adiante).

Isso dá a matriz de confusão completa, num universo definido: um ponto vulnerável e um ponto corrigido por CVE. Precisão, especificidade e F1 passam a ser computáveis **nesse sentido** — que não é a precisão sobre todos os alertas da ferramenta.

**O que continua não classificável.** Alerta fora do ponto da falha — noutro arquivo, ou noutro trecho do mesmo arquivo —, em qualquer das duas versões. O benchmark afirma uma vulnerabilidade por CVE e não afirma que o resto do código esteja limpo. Um alerta ali pode ser erro da ferramenta ou vulnerabilidade real não catalogada, e nada no dado permite distinguir. O próprio conjunto desmente a hipótese de completude: os quatro CVEs do Rendertron apontam para o mesmo commit, de modo que, na análise de um deles, as três outras falhas estão presentes no código e seriam computadas como falso positivo de uma ferramenta que as encontrasse. De 77,8% a 96,9% dos alertas das três ferramentas caem fora do arquivo do ground truth (Seção 9) e seguem sem classificação. A precisão sobre **todos** os alertas continua incomputável; o único caminho para ela seria a rotulagem manual de uma amostra de alertas.

**A tabela é construção do estudo, não o cálculo da ferramenta de relatório do benchmark.** Lida no código do benchmark (commit `91c59fd`), aquela ferramenta calcula o reconhecimento da correção de modo diferente:

- só avalia a versão corrigida dos CVEs que a ferramenta **detectou** na versão vulnerável — detecção por igualdade exata de arquivo e linha;
- entram apenas as regras que produziram esse alerta;
- a correção conta como reconhecida quando ao menos uma dessas regras produz **menos alertas no repositório inteiro** na versão corrigida — sem localizar ponto algum;
- se não houve detecção, o resultado é *não computável*, e não falso positivo nem verdadeiro negativo.

A diferença é de desenho. A leitura do benchmark é **condicionada à detecção**; a tabela do estudo atribui falso positivo ou verdadeiro negativo a **todos** os CVEs. A leitura condicionada cria, por construção, um denominador distinto por ferramenta — o que a regra da Seção 7.4 veda, por destruir a comparabilidade direta entre elas. A escolha entre as duas leituras, ou a apuração das duas, é **a primeira decisão do desenho da campanha da versão corrigida**, e não está tomada. Registra-se, em favor da leitura do estudo quanto ao restante do código, que o relatório em arquivo do benchmark classifica alerta fora da falha como desconhecido, e não como falso positivo.

**Como o erro ocorreu, e não foi falta de informação.** O critério da versão corrigida estava registrado no documento de regras do projeto desde 28 de agosto de 2026, citando a documentação do benchmark: a ferramenta ideal produz ao menos um alerta relevante no commit anterior à correção e nenhum no posterior (Seção 7.4). O documento de critérios, redigido em 18 de setembro, não relacionou esse critério ao falso positivo, e o README, que lhe dá esse nome, não tinha sido lido. O documento de critérios recebeu **emenda datada de 21 de setembro de 2026**, que marca como superado o trecho errado e o preserva. O caso integra os da Seção 12.5.

**A campanha da versão corrigida.** A campanha de detecção rodou apenas antes da correção e fornece a metade VP/FN da matriz, cujos resultados (Seção 9) não são afetados pela correção desta seção. Falso positivo e verdadeiro negativo exigem uma segunda campanha, sobre o `PostPatchCommit`, com as mesmas imagens e o mesmo pipeline. Decisões a fixar no documento de critérios **antes** de qualquer resultado dela, como na primeira:

- **a leitura: matriz de quatro células ou reconhecimento condicionado à detecção**, ou as duas;
- **como localizar o ponto da falha depois da correção**, cuja linha pode mudar de número ou deixar de existir;
- **quais níveis se aplicam** à versão corrigida — o nível 1 tende a disparar nela por causa de outros alertas no mesmo arquivo, e o falso positivo útil deve vir dos níveis que usam a linha;
- **quantos `PostPatchCommit` são utilizáveis**: dois vêm malformados (Seção 2.2.3), e os demais precisam ser conferidos quanto à existência nos repositórios;
- **o denominador da versão corrigida**, que pode diferir do da detecção.

A série de julho de 2026, que analisou o HEAD, **não substitui** esta campanha: o HEAD difere do código vulnerável por todo o histórico posterior à correção, e não só por ela, o que desfaz a comparação controlada que o benchmark propõe; além disso, aquela série foi invalidada por defeitos de coleta (Seção 8).

### 7.4 Tratamento do ground truth

Esta seção substitui a decisão registrada na versão 3, segundo a qual um CVE com n CWEs originaria n registros independentes de ground truth. A caracterização apresentada na Seção 2.2 tornou essa decisão insustentável.

**Por que a expansão foi abandonada.** A expansão pressupunha que os múltiplos CWEs de um CVE correspondessem a defeitos distintos, cada qual passível de detecção independente. A medição mostrou que essa premissa não se verifica: o conjunto de CWEs é herdado das tags da consulta que originou o registro e descreve uma família ou um conjunto de impactos potenciais, não defeitos coexistentes.

Mantida a expansão, os 222 pares efetivamente afirmados pelo ground truth passariam a 534, e as 312 linhas acrescidas corresponderiam a combinações que ferramenta alguma poderia reportar — porque o defeito ali não está. Todas seriam computadas como falso negativo, deprimindo o recall das três ferramentas de modo uniforme e por artefato do protocolo. A métrica resultante não mediria capacidade de detecção.

**Dupla apuração — as variantes generosa e estrita.** Adota-se, em substituição, a apuração em duas modalidades, aplicadas ao mesmo conjunto de resultados. A partir desta versão elas qualificam os níveis de acerto que dependem de CWE (níveis 2 e 4, Seção 7.2), com os nomes de **variante generosa** (correspondência por conjunto: o CWE do achado intersecta os CWEs do CVE) e **variante estrita** (correspondência por CWE primário: o achado contém o CWE primário):

| Modalidade | Critério de verdadeiro positivo | Unidade |
|---|---|---|
| Correspondência por conjunto | A ferramenta reporta qualquer um dos CWEs atribuídos ao CVE, no arquivo registrado | (CVE, arquivo) — 222 registros |
| Correspondência por CWE primário | A ferramenta reporta o CWE que descreve o defeito, no arquivo registrado | (CWE, arquivo) — 222 registros |

A primeira modalidade é permissiva e corresponde ao critério declarado pela documentação do próprio benchmark, que define como completo o CVE para o qual a ferramenta de análise ideal produz ao menos um alerta relevante no commit anterior à correção e nenhum no posterior. É, portanto, a modalidade que permite comparação com resultados publicados por terceiros. A segunda é mais rigorosa e sustenta as métricas por CWE, que constituem objetivo declarado do estudo.

Ambas operam sobre o mesmo denominador, de modo que as duas apurações são diretamente comparáveis. A diferença entre elas quantifica em que medida as ferramentas acertam a família da vulnerabilidade mas divergem quanto à sua classificação específica. **Medida na campanha, a diferença é pequena** — 126 contra 124 acertos no nível 2 do CodeQL, 48 contra 46 no do Semgrep —, e só no Snyk Code é apreciável (16 contra 9; Seção 9).

**Seleção do CWE primário.** O CWE primário de cada CVE é determinado por tabela de mapeamento aplicada aos 17 conjuntos multivalorados identificados na Seção 2.2.1. Os 57 CVEs de CWE único dispensam mapeamento, e o CVE sem CWE não é submetido à tabela — a distinção entre os três casos é operacionalizada na normalização, de modo que conjunto ausente da tabela produza falha explícita em vez de confundir-se com ausência prevista.

**Regra de fechamento.** O CWE primário deve necessariamente pertencer ao conjunto declarado pelo benchmark para aquele CVE. Atribuir identificador externo ao conjunto — ainda que taxonomicamente mais preciso — constituiria edição do ground truth e não sua interpretação, e tornaria o alvo inatingível para qualquer ferramenta, uma vez que a avaliação se faz contra o que o benchmark declarou.

**Evidência empregada, em ordem de precedência.** A descrição textual da weakness, que na maioria dos casos nomeia o defeito; na sua insuficiência, o diff entre os commits anterior e posterior à correção, que revela o que foi efetivamente corrigido.

A tabela resultante:

| Conjunto declarado | CVEs | Primário | Base da decisão |
|---|---|---|---|
| CWE-079 + CWE-116 | 42 | CWE-079 | Descrições referem-se a cross-site scripting; CWE-116 designa o mecanismo |
| CWE-078 + CWE-088 | 25 | CWE-078 | As quatro descrições do grupo referem-se a injeção de comando |
| CWE-400 + CWE-730 | 25 | CWE-400 | Negação de serviço por expressão regular |
| CWE-078 + 079 + 094 + 400 + 915 | 23 | CWE-915 | Poluição de protótipo; os demais são impactos potenciais |
| CWE-022 + 023 + 036 + 073 + 099 | 21 | CWE-022 | Travessia de caminho; os demais são especializações |
| CWE-079 + CWE-094 + CWE-116 | 8 | CWE-094 | Descrições referem-se a injeção de código |
| CWE-020 + CWE-116 | 7 | CWE-116 | Escape ou codificação incompletos |
| CWE-079 + CWE-116 + CWE-601 | 3 | CWE-601 | Redirecionamento não validado |
| CWE-312 + CWE-315 + CWE-359 | 3 | CWE-312 | Registro em claro de informação sensível |
| CWE-020 + CWE-079 + CWE-116 | 1 | CWE-079 | Sanitização incompleta de atributo HTML |
| CWE-020 + CWE-094 | 1 | CWE-094 | Execução arbitrária de código |
| CWE-074 + CWE-094 | 1 | CWE-094 | Execução arbitrária de código |
| CWE-404 + CWE-730 | 1 | CWE-404 | Fluxo não encerrado |
| CWE-125 + CWE-126 | 1 | CWE-125 | Leitura além do limite do buffer |
| CWE-290 + CWE-807 | 1 | CWE-807 | Contorno de verificação de segurança |
| CWE-020 + CWE-668 | 1 | CWE-020 | Validação de entrada imprópria |
| CWE-250 + CWE-400 | 1 | a definir | Descrição não corresponde a nenhum dos dois; pendente de exame do diff. É o `CVE-2018-16472`: a variante estrita não se aplica a ele, que é contado à parte, sem virar não-acerto — daí o denominador de 219 na variante estrita |

**Exceções registradas.** Dois CVEs do conjunto CWE-400 + CWE-730 — `CVE-2017-16023` e `CVE-2018-7560` — descrevem injeção de expressão regular, defeito distinto da negação de serviço que caracteriza os 23 demais do grupo. Neles o atacante controla a própria expressão, e não o texto por ela processado. O identificador que melhor os descreveria, CWE-624, não integra o conjunto declarado; pela regra de fechamento acima, recebem o primário do grupo e são registrados como exceção documentada.

**Auditabilidade.** A tabela de mapeamento é versionada junto ao estudo, em formato tabular, com uma linha por conjunto e a evidência que sustentou cada decisão. Sua aplicação é automática e reprodutível a partir do ground truth original. O conjunto ainda sem primário definido produz valor nulo declarado e contabilizado, e não interrompe o processamento.

**CVEs sem CWE.** Registros cujo campo CWEs está vazio permanecem no conjunto de dados, preservando rastreabilidade, mas não integram a matriz de confusão, por inexistir referência de comparação. A exclusão atinge um CVE, conforme a Seção 2.2.3, e é declarada.

**CVEs cujo código não está disponível.** Aplica-se exclusão de natureza distinta a dois CVEs cujo código não pôde ser obtido (Seção 2.2.3): o `CVE-2016-1000229`, cujo repositório não existe mais, e o `CVE-2018-8035`, cujo commit declarado não existe no repositório. A Versão 9 tratava a indisponibilidade como **de repositório**; o segundo caso é de **commit** num repositório existente, e a categoria passa a ser **indisponibilidade de código**. Em nenhum dos dois alguma ferramenta foi confrontada com o código: não são falsos negativos. Computá-los como ausência de detecção mediria a persistência do código público, e não capacidade de análise.

A exclusão é registrada em categoria própria, com contagem declarada, e os CVEs permanecem no conjunto de dados para preservar rastreabilidade. **O denominador de ambas as modalidades passa de 222 para 220 registros.** Os denominadores permanecem idênticos entre si e entre as três ferramentas.

As grandezas envolvidas não são a mesma, e confundi-las é fácil:

| Grandeza | Valor |
|---|---:|
| CVEs no conjunto | 223 |
| Pares (CWE, arquivo) afirmados | 222 |
| **Pares no denominador** | **220** |
| CVEs com saída bruta no CodeQL e no Semgrep | 221 |
| CVEs com saída bruta no Snyk Code | 216 |

São 222 e não 223 porque o `CVE-2018-1000096` não declara CWE — ele foi analisado normalmente e tem saída nas três ferramentas. São 220 e não 222 pelas duas baixas por indisponibilidade de código. O Snyk Code tem cinco saídas a menos pelos casos de ausência de material analisável (Seção 4.6), que **permanecem** no denominador.

**O denominador é o que a campanha mede** (Seção 4.3). A Versão 9 previa que o denominador fosse o apurado na sondagem que antecede a execução; a sondagem de repositório não alcança commit inexistente, e o denominador efetivamente empregado saiu da medição da própria campanha, CVE a CVE.

**Distinção quanto ao arquivo não varrido.** Registra-se que a condição descrita na Seção 5.2 — arquivo do ground truth não considerado pela ferramenta — **não** enseja exclusão análoga. A causa ali é interna à ferramenta e à sua configuração predefinida, que constituem o objeto da avaliação; aqui é externa ao estudo e às ferramentas. A primeira é resultado; a segunda, perda de oportunidade de medição.

### 7.5 Achados fora do escopo do ground truth

O ZAP produz alertas legítimos que não constam do `challenges.yml` — cabeçalhos de segurança ausentes, atributos de cookie, políticas de conteúdo.

Tais alertas não são computados como falsos positivos. Um falso positivo caracteriza afirmação falsa da ferramenta; um cabeçalho ausente está efetivamente ausente. Classificá-lo como erro mediria a incompletude do benchmark, não a precisão da ferramenta.

Adota-se categoria própria — achados válidos fora do escopo do ground truth — sob duas condições: a contagem é reportada explicitamente, e cada alerta é submetido a triagem manual que separa achado legítimo fora de escopo de falso positivo genuíno.

O volume de alertas dinâmicos permite auditoria manual integral, o que se registra como característica favorável do protocolo.

Observa-se que essa classe de achados — cabeçalhos, cookies, configuração de servidor — constitui categoria igualmente inacessível à análise estática, observação incorporada à discussão de complementaridade.

### 7.6 Capacidade das ferramentas

A tabela de capacidade por ferramenta reflete capacidade empírica — as categorias efetivamente reportadas neste estudo — e não a capacidade teórica derivada do catálogo de regras de cada ferramenta.

A tabela contabiliza achados brutos, sem filtragem prévia contra o ground truth. Mede-se ali abrangência; a acurácia é objeto da matriz de confusão. A separação torna as duas apurações independentes entre si.

Registra-se que o conjunto de regras do Semgrep abrange linguagens diversas, de modo que parte substancial de seus achados recai fora do escopo de JavaScript e TypeScript. A delimitação por linguagem é aplicada nesta etapa, e não na coleta, e a proporção descartada é declarada — constitui, ela própria, indicativo do esforço de triagem imposto pela ferramenta em sua configuração predefinida.

**Estado nesta versão: a tabela de capacidade e a delimitação por linguagem do Semgrep ainda não foram apuradas.** Os dados necessários estão nos resultados normalizados versionados, e as duas apurações são pendências registradas na Seção 14. Indício da magnitude: só no repositório do `CVE-2018-14380`, o Semgrep varreu 1.165 arquivos Java.

### 7.7 Métricas

**Métricas da matriz de confusão**, no universo definido pela Seção 7.3 — um ponto vulnerável e um ponto corrigido por CVE —, por ferramenta, nos cinco níveis de acerto e nas duas variantes de CWE:

| Métrica | Fórmula | Exige |
|---|---|---|
| **Recall** | VP ÷ (VP + FN) | só a campanha de detecção |
| Precisão | VP ÷ (VP + FP) | a campanha da versão corrigida |
| Especificidade | VN ÷ (VN + FP) | a campanha da versão corrigida |
| F1 | média harmônica de precisão e recall | a campanha da versão corrigida |

**Nesta versão, só o recall está apurado.** Precisão, especificidade e F1 dependem da campanha da versão corrigida. A redação dos resultados precisa declarar o escopo em toda ocorrência: "precisão" sem qualificação sugere a leitura sobre todos os alertas, que o conjunto não permite (Seção 7.3).

**A apuração por CWE**, objetivo declarado desde as versões anteriores, **ainda não foi feita**: o cruzamento apurou por ferramenta. É pendência registrada na Seção 14.

**Volume de alertas.** Caracteriza-se, descritivamente, o volume de alertas por ferramenta e sua distribuição entre CVEs. É declarado como caracterização, **nunca** como medida de qualidade: mede quanto a ferramenta reporta, não quanto acerta, e, pelo argumento da Seção 7.3, alertas fora do ponto da falha não são classificáveis.

**Critério de linha: sobreposição, sem banda de tolerância.** A linha casa quando o intervalo reportado pelo achado — da linha inicial à final — contém alguma das linhas registradas no ground truth. Achado sem linha final é tratado como o ponto da linha inicial. Nos três CVEs com mais de uma linha de referência (Seção 2.2.1), basta conter qualquer uma delas: exigir a primeira computaria como erro um acerto legítimo em outro ponto da mesma vulnerabilidade.

**Esta versão substitui as faixas de precisão de localização** da Versão 9 (exata, até 5 linhas, até 10, apenas arquivo). A decisão foi tomada por medição sobre os resultados da campanha, antes do cruzamento. O temor era que a sobreposição favorecesse ferramentas que reportam intervalos longos. Medido: o ganho da sobreposição sobre a coincidência exata da linha inicial é de **5, 1 e 13 achados** — CodeQL, Semgrep e Snyk Code —, sobre 717, 360 e 199 achados no arquivo do ground truth. As duas opções produzem praticamente o mesmo resultado, e é isso que torna a escolha segura. Dezesseis dos 19 ganhos vêm de regras de limitação de taxa (`js/missing-rate-limiting` no CodeQL, `NoRateLimitingForExpensiveWebOperation` no Snyk Code), que reportam a função inteira; o único ganho do Semgrep vem de regra de outra natureza. Banda de tolerância foi descartada por não haver o que resolver: com ganho de cerca de 1%, ampliar a janela introduziria um parâmetro arbitrário sem mudar a conclusão.

**Caracterização da distância, que não é critério de acerto.** Restrita aos achados no arquivo certo, a distância mediana até a linha do ground truth mais próxima é de 71, 113 e 64 linhas, e mais de 35% dos achados estão a mais de 100 linhas, nas três ferramentas. O dado antecipa que o nível 3 seria substancialmente menor que o nível 1, e integra os resultados como caracterização, não como faixa de acerto.

**Assimetria de granularidade, declarada.** 94,1% dos achados do CodeQL não trazem linha final, contra nenhum nas outras duas: na prática, o CodeQL é avaliado por critério de ponto e as outras por critério de intervalo. Como o ganho do intervalo é de cerca de 1%, a assimetria não distorce o resultado, mas é estrutural.

A apuração é feita por CVE, sem agregação entre CVEs, o que evita a sobreposição referida na Seção 2.2.3 quanto aos dois CVEs situados em linhas adjacentes do mesmo arquivo.

**Comparabilidade das variantes de CWE entre ferramentas — investigada, e a limitação não existe.** Os níveis 2 e 4 só seriam comparáveis entre as ferramentas se nenhuma delas emitisse muitos achados sem CWE, porque achado sem CWE nunca casa. Medido: **nenhum** achado sem CWE, em 18.664, e nenhum CVE em que o arquivo certo tenha sido encontrado só por achados sem CWE. O zero tem explicação: o campo de CWE do Semgrep muda de tipo, e o tratamento explícito dos dois tipos, decidido antes da existência de saída real (Seção 5.2), recuperou 126 achados que sairiam sem CWE.

---

## 8. Execuções: a preliminar invalidada, os ensaios e a campanha

Registra-se, por transparência metodológica, que uma primeira campanha SAST foi executada em julho de 2026 e posteriormente invalidada (Seções 8.1 a 8.4), e que o pipeline reconstruído foi revisado, ensaiado localmente, ensaiado no ambiente da campanha e, por fim, executado (Seções 8.5 a 8.8).

### 8.1 O defeito

Os scripts da primeira versão obtinham o código-fonte por meio de clone simples do repositório, sem checkout do commit registrado no ground truth. A análise incidia, portanto, sobre o estado corrente do branch padrão.

Como os CVEs do benchmark correspondem, por definição, a vulnerabilidades divulgadas e majoritariamente corrigidas, o código submetido às ferramentas era, na maior parte dos casos, a versão já corrigida.

### 8.2 Consequência

A comparação com o ground truth ficaria comprometida em ambas as direções: verdadeiros positivos tornar-se-iam improváveis por construção, e falsos negativos seriam inflados por defeito do protocolo, não por limitação das ferramentas. Qualquer métrica de precisão ou recall daí derivada seria inválida.

### 8.3 Defeitos acessórios identificados

O exame da campanha preliminar revelou, além do defeito principal, um conjunto de fragilidades cuja correção foi incorporada ao protocolo atual:

- **Descarte silencioso de registros.** Um dos scripts lia a lista de entrada sem proteção contra arquivo desprovido de quebra de linha final, descartando a última entrada de cada lote assim formado. O efeito foi confirmado sobre um caso específico.
- **Nomeação de saídas pelo repositório.** Produzia sobrescrita entre CVEs do mesmo repositório e colisão entre repositórios homônimos.
- **Supressão de falhas nos workflows.** O encadeamento de comandos que neutraliza o código de retorno fazia o job ser reportado como bem-sucedido ainda que a imagem não fosse construída ou o container encerrasse prematuramente.
- **Ausência de registros de execução.** Não sendo os logs preservados como artefato, tornou-se impossível determinar a causa das ausências observadas no conjunto de resultados.
- **Descarte da saída de erro.** Dois dos scripts redirecionavam a saída de erro das operações de clone, eliminando a informação sobre a razão das falhas.
- **Interpretação equivocada de cobertura.** No caso do Snyk Code, a ausência de arquivo de saída foi inicialmente lida como falha de análise, quando correspondia, na maior parte dos casos, a análise concluída sem achados.
- **Consumo da lista de entrada por processos filhos.** A lista mantida na entrada padrão do laço era herdada pelos processos invocados, de modo que itens podiam ser consumidos sem produzir registro. A conferência descrita na Seção 4.6 fornece a assinatura observável dessa condição.

### 8.4 Encaminhamento

Os dados da primeira campanha foram arquivados, não descartados. Preservam registro das versões efetivamente empregadas — Semgrep 1.171.0, Snyk Code 1.1306.1 e CodeQL 2.25.4 —, recuperáveis apenas a partir dos próprios arquivos de resultado, uma vez que apenas o CodeQL estava fixado em versão determinada.

Permitem ainda, se conveniente, comparação entre a análise sobre o estado corrente e a análise sobre o commit vulnerável — cotejo que quantificaria o efeito do defeito.

O protocolo foi reconstruído, incorporando o checkout do commit vulnerável e as demais correções descritas neste documento.

Considera-se que o registro deste episódio integra a contribuição do trabalho: a análise do estado corrente em lugar do commit vulnerável constitui armadilha recorrente em estudos de avaliação de ferramentas SAST sobre benchmarks de CVE.

### 8.5 Revisão do pipeline reconstruído

O episódio da Seção 8.3 forneceu um inventário de defeitos concretos, e não apenas uma lição geral. Esse inventário foi convertido em checklist de revisão, aplicado ao pipeline reconstruído por um revisor automatizado independente de quem escreveu o código, com acesso somente de leitura e instrução explícita de não propor alterações, apenas relatar.

O procedimento tem duplo propósito. Primeiro, verificar antes da execução as invariantes cuja violação não produz erro visível — o checkout do commit vulnerável, a normalização do caminho de arquivo, a distinção entre análise sem achados e falha. Segundo, registrar como resultado o que a revisão confirmou correto, e não apenas o que apontou: uma revisão sem apontamentos é informação, e o checklist exige que o revisor a declare como tal em vez de preencher o relatório com observações menores.

**Primeira rodada — imagens e scripts de análise.** Identificou um defeito de comportamento, dez riscos condicionais e oito observações. O defeito e nove dos riscos foram corrigidos antes da execução; os demais foram registrados como itens a verificar durante a normalização e o ensaio de fumaça. A revisão confirmou, por inspeção direta, o checkout do commit do ground truth nos três scripts e a invocação das ferramentas a partir do diretório de trabalho — condição de que depende a emissão de caminhos relativos à raiz do repositório, ponto identificado como o de maior consequência silenciosa do projeto.

**Segunda rodada — normalização e conferência do registro.** Identificou dois defeitos de comportamento, oito riscos condicionais e oito observações, e confirmou por inspeção as nove invariantes submetidas a exame, entre as quais o tratamento de ambos os tipos admitidos no campo de CWE do Semgrep, a junção por identificador textual, a impossibilidade de falha de leitura produzir lista de achados vazia, a separação entre os dois estados de severidade não atribuída e a independência entre normalização e registro de execução.

O defeito de maior consequência é registrado por seu valor ilustrativo: o caminho declarado pelo ground truth não era submetido a normalização alguma, de modo que o único CVE que o declara em forma absoluta (Seção 2.2.3) produziria comparação contra um valor inexistente nas saídas, e seria computado como falso negativo sem manifestação de erro. O segundo defeito é da mesma natureza, aplicado ao relatório: a nota que atesta a regularidade dos caminhos era emitida precisamente na condição em que a regularidade falhara.

Ambos pertencem à classe que motivou o procedimento — divergência silenciosa entre o que o protocolo supõe e o que os dados apresentam — e nenhum seria detectado pela execução, que teria transcorrido sem erro.

**Terceira rodada — alterações decorrentes do ensaio local.** Incidiu sobre as modificações que o ensaio local motivou no programa de normalização, e produziu seis apontamentos, todos corrigidos. Dois merecem registro por sua natureza.

O primeiro é de método: a guarda que compara regras declaradas e regras aplicadas fora convertida de igualdade para desigualdade unilateral, em razão do achado descrito na Seção 4.5 — e a conversão, correta quanto ao extremo superior, suprimiu silenciosamente o extremo inferior. Inventário vazio deixava de ser detectado, condição que produz conjunto vazio de achados indistinguível de análise sem achados. O limite inferior foi restabelecido como anomalia própria.

O segundo é o caso da fixture de polaridade invertida, descrito na Seção 5.6: a suíte passava afirmando o contrário do que a medição estabelece. Nenhuma execução o revelaria, porque o teste e o código concordavam entre si.

**Uma rodada incidiu sobre código já incorporado ao repositório.** Por interrupção do procedimento, as alterações do fechamento do ensaio local foram registradas antes da revisão correspondente, que se realizou em seguida. O fato é declarado no repositório junto ao registro da revisão. A ordem prevista — revisão antes do registro — não foi observada nesse caso, e a revisão posterior não tem o mesmo valor preventivo, ainda que tenha produzido os apontamentos acima.

**Extensão da disciplina aos fluxos de trabalho.** A regra, tal como redigida, alcançava programas, arquivos de construção de imagem e o normalizador, porque os fluxos de trabalho não existiam quando foi estabelecida. Passou a alcançá-los também, por decisão fundada em defeito real: a primeira revisão de fluxo de trabalho identificou guarda que operaria na primeira execução e ficaria **inerte a partir da segunda**, por depender de condição que a própria execução anterior tornava falsa. Guarda que funciona uma vez e deixa de funcionar é pior que guarda ausente, porque ninguém volta a examinar o que já passou. Fluxo de trabalho é artefato que governa execução e apresenta os mesmos modos de falha silenciosa dos demais.

**Limitação reiterada.** A revisão incide sobre a versão do código anterior às correções que ela mesma motiva. As verificações mecânicas são refeitas sobre a versão final — a suíte de asserções sobre fixtures passou de 113 para 143 casos ao fim da segunda rodada, e de 143 para 173 ao fim do ensaio local, cobrindo cada correção —, mas não se realiza revisão completa subsequente. A limitação é declarada e não corrigida: uma revisão adicional motivaria novas correções, e a recursão carece de ponto de parada natural.

---

### 8.6 Ensaio local do pipeline reconstruído

Antes de qualquer execução no ambiente da campanha, o pipeline foi exercitado integralmente sobre o lote de teste de cinco CVEs descrito na Seção 4.2, nas três ferramentas, seguido da normalização e da conferência do registro de execução.

O ensaio tem três propósitos, em ordem crescente de alcance: verificar que o pipeline executa; medir durações e volumes, de que dependem o dimensionamento de lote e os limites de tempo; e **confrontar os formatos de saída declarados na Seção 5.2 contra saída real**. O terceiro é o de maior consequência e o menos visível: as três ferramentas podem concluir sem erro algum e a descrição dos formatos permanecer incorreta, porque as fixtures que verificam a normalização derivam dela (Seção 5.6).

Os resultados de detecção do ensaio foram descartados ao fim, preservando-se os registros de execução e os relatórios de normalização. A razão é de protocolo: dois dos cinco CVEs integram também um lote da campanha, e saída bruta remanescente faria a verificação de idempotência saltá-los, com dados produzidos sob versão anterior do schema.

**Verificações de execução.** Confirmaram-se, nas três ferramentas: a produção de artefatos distintos para os dois CVEs que compartilham repositório em commits diferentes; a ausência de colisão entre os repositórios homônimos; e o tratamento do CVE cujo repositório não está disponível, que produziu falha de obtenção sem deixar saída parcial, com limpeza executada e prosseguimento do laço. Este último é o único exercício integral do caminho de erro antes da campanha.

Confirmaram-se ainda a ausência de prefixo de diretório nos identificadores de regra do Semgrep, a execução sem rede dessa ferramenta, e a inexistência de achados nos dois estados de severidade não atribuída da Seção 5.4.

**Confrontação dos formatos.** A descrição da Seção 5.2 mostrou-se correta quanto a formato, localização e forma dos identificadores de CWE, caminho de arquivo, linhas, severidade, identificador de regra e versão da ferramenta. Em particular, a totalidade dos 285 achados produzidos emitiu caminho relativo e limpo — propriedade de que depende todo o cotejo com o ground truth.

Seis divergências foram registradas:

| Ferramenta | Declarado | Observado |
|---|---|---|
| CodeQL | data de análise obtida do bloco de invocação | o bloco não registra data de conclusão; a data recai sobre o carimbo do arquivo, conforme previsto pelo campo de origem |
| CodeQL | a saída não registra inventário de arquivos considerados | registra, em duas formas; a consequência está na Seção 5.2 |
| CodeQL | registro de proveniência de controle de versão, se emitido, seria evidência independente do commit | não é emitido; o registro de execução permanece a única evidência, e é por isso versionado |
| Snyk Code | inventário de cobertura decide sobre arquivo determinado | é agregado por extensão, sem enumeração de caminhos |
| Snyk Code | emissão de notificações de execução não verificada | não emite; o bloco de invocação é ausente |
| Semgrep | registro de caminhos descartados disponível | não é emitido sem opção adicional de verbosidade |

Registraram-se ainda duas condições de maior risco que **não** se materializaram: a saída do Snyk Code em análise sem achados traz a lista de resultados presente e vazia, de modo que a guarda de saída estruturalmente incompleta não precisou ser alterada; e o valor de severidade não previsto na correspondência da Seção 5.4 não comparece em achado algum, aparecendo apenas em notificações de execução, que não são achados.

Uma divergência não prevista pela descrição emergiu do exame: o campo de erros do Semgrep emprega representação de tipo variável, tratada conforme a Seção 4.5.

**Exercício da asserção do commit.** Descrito na Seção 4.3. É a primeira ocorrência, no estudo, de disparo da asserção com divergência real.

**Medições.** Durações medianas por CVE de 24 s, 102 s e 31 s para Semgrep, CodeQL e Snyk Code, com máximos de 37 s, 146 s e 54 s. A normalização das três ferramentas consumiu, somada, fração de segundo — o que confirma a premissa de custo desprezível que fundamenta a arquitetura da Seção 5.1. O volume de saída bruta é de poucos megabytes por lote e o espaço em disco não constituiu restrição.

A medição do CodeQL foi refeita sobre a imagem corrigida conforme a Seção 4.5, de modo que não depende de imagem de diagnóstico. Permanece, contudo, a limitação de ambiente declarada na Seção 12.1.

**Correspondência entre séries.** O relatório do ensaio apresentava, em tabelas distintas, a duração por CVE e o número de arquivos extraídos por CVE, sem que a correspondência entre elas estivesse declarada — omissão que produziu o erro registrado na Seção 12.5.

A correspondência foi posteriormente computada, não do relatório e sim das fontes versionadas, ambas chaveadas pelo identificador do CVE: o registro de execução do CodeQL, que traz a duração por CVE, e o relatório de normalização da mesma ferramenta, cujo inventário associa a cada CVE a contagem de arquivos extraídos. Os quatro pares ficam determinados:

| CVE | Duração | Arquivos extraídos |
|---|---:|---:|
| `CVE-2017-16042` | 63 s | 3 |
| `CVE-2018-14041` | 78 s | 126 |
| `CVE-2018-14040` | 127 s | 174 |
| `CVE-2019-10744` | 146 s | 58 |

A ordem das duas séries difere porque o registro de execução inclui também o CVE cujo repositório não está disponível, que produziu falha de obtenção com duração nula e não gera inventário. O cotejo por posição desloca os pares a partir dali e troca entre si os dois CVEs que compartilham repositório — que foi exatamente o erro cometido.

**Nenhum coeficiente de correlação é computado sobre esses quatro pontos.** Quatro observações não permitem prever; o registro existe para tornar a correspondência explícita, não para relacionar as grandezas. A questão de que aquele exame partia permanece em aberto, conforme a Seção 12.5.

**Cobertura do ensaio.** Quatro CVEs efetivamente analisados, em quatro repositórios, todos de JavaScript. O lote não contém arquivo TypeScript, monorepo, nem caso de ausência de material analisável. O extrator de TypeScript foi verificado por sondagem dedicada, o que estabelece que ele opera sobre o runtime da imagem, não que o laço o atravesse.

### 8.7 Ensaio de fumaça no ambiente da campanha

Antes do primeiro lote, o workflow de lote foi executado sobre um lote dirigido de sete CVEs, no próprio ambiente da campanha (execução `35101790912`, 16 de setembro de 2026), com os limites de tempo nos valores padrão, para que o ensaio os medisse.

**Composição, e a razão de cada item.** Os cinco CVEs do ensaio local, para parear as durações entre os dois ambientes; o `CVE-2018-20164`, único do conjunto com arquivo `.yaml`, para exercitar sob o laço o ramo de arquivo não considerado; e, por último, o `CVE-2018-14380`, TypeScript real sob o laço, em repositório multilíngue e de grande porte — o caso em que as duas fontes do inventário do CodeQL (Seção 5.2) teriam motivo para divergir. O item de maior custo esperado foi posto por último, para que um estouro dele não comprometesse a medição dos anteriores.

**Antes do ensaio, as imagens foram reconstruídas.** Os limites de tempo passaram a ser sobrescrevíveis por ambiente (Seção 4.4), e os scripts integram as imagens. Sem reconstrução, o ensaio mediria imagens diferentes das que a campanha usaria, e o limite escolhido a partir dele não poderia ser citado. A comparação do inventário de pacotes entre as duas construções, com dois dias e meio de intervalo, mostrou um de 716 pacotes resolvidos no momento da construção mudando de versão; os valores fixados por descritor ficaram idênticos.

**O que fechou.**

- **TypeScript atravessa o laço**, nas três ferramentas: 21 arquivos `.ts` extraídos no `CVE-2018-14380`, incluído o do ground truth. Era a única verificação que bloqueava a campanha.
- **O defeito do diretório pessoal foi medido com controle** nas três imagens (Seção 4.7).
- **O isolamento de rede opera** no ambiente da campanha, e o Semgrep completa a varredura com o conjunto de regras vendorizado sob isolamento total — com a ressalva de duração da Seção 12.1.
- **As imagens publicadas carregam os scripts esperados**: a linha dos limites efetivos saiu no pré-voo e no lote das três.
- **O caminho de erro foi exercitado com causa discriminada**: o `CVE-2016-1000229` resultou em falha de obtenção, com recusa do servidor nas duas tentativas, e não estouro de limite.
- **O inventário do CodeQL bateu nas duas fontes em seis de seis CVEs**, inclusive no multilíngue, com 704 arquivos extraídos.

**O que se mostrou diferente do esperado.**

- **O runner é mais rápido, não mais lento**: razão de 0,65 a 0,76 sobre o hospedeiro local (Seção 4.4).
- **O item de grande porte não amostrou a cauda de duração.** O `CVE-2018-14380`, com 704 arquivos, custou 77 segundos no CodeQL, menos que um CVE de 58 arquivos (103 segundos). A premissa de que o porte prediz o custo não se sustentou na amostra; a campanha a refinou (Seção 9).
- **O `.yaml` foi considerado** pelas duas ferramentas que informam cobertura, e o ramo de arquivo não considerado continuou sem exercício sob o laço.

**Os resultados de detecção do ensaio foram descartados**, como os do ensaio local, porque seus CVEs integram lotes da campanha. Preservaram-se os registros de execução, os relatórios de normalização e as sondagens.

### 8.8 Campanha de detecção

A campanha de detecção rodou em oito lotes, sobre os 223 CVEs, no commit anterior à correção, com o commit do repositório do estudo `579f383` em todos, as imagens pelos digests da Seção 3.1 e os limites de análise em 900 segundos, conferidos pela linha que o próprio container imprime em 24 de 24 jobs.

| Lote | Execução | Data | | Lote | Execução | Data |
|---|---|---|---|---|---|---|
| `aa` | `35106944490` | 16/09/2026 | | `ae` | `35169207030` | 17/09/2026 |
| `ab` | `35135927579` | 16/09/2026 | | `af` | `35169209525` | 17/09/2026 |
| `ac` | `35169202777` | 17/09/2026 | | `ag` | `35169211662` | 17/09/2026 |
| `ad` | `35169205115` | 17/09/2026 | | `ah` | `35169213227` | 17/09/2026 |

**Os dois primeiros lotes rodaram em série, com leitura entre eles**, porque carregavam o risco desconhecido: o primeiro fixava definitivamente o tamanho de lote, e o segundo continha o repositório que travou a série de julho. Passaram sem falha de conferência, sem divergência de inventário, sem limite atingido. **Os seis restantes rodaram em paralelo**, em 34 minutos — duração de job no serviço de integração contínua, não versionada (Seção 4.4). A campanha atravessou a meia-noite UTC, o que explica as duas datas.

**Nenhum lote precisou ser refeito.** Nos 24 jobs: as conferências do registro sem incoerência; a normalização sem falhas, sem saídas brutas órfãs nem ilegíveis; o portão de lote sem saída bruta satisfeito; nenhum estouro de limite; o controle do diretório pessoal e a sonda de rede com o resultado do ensaio de fumaça em todos os lotes. A sobrecarga do laço — duração do container menos a soma das durações por CVE — ficou entre 1 e 4 segundos por lote.

**Observação não investigada, registrada.** Todo teste do Snyk Code com achados terminou com mensagem de acesso negado (HTTP 403), impressa **depois** do resumo do teste: 133 de 133 testes com achados, e nenhum dos 83 sem achados. A saída bruta foi gravada e normalizada nos 133. O que a ferramenta tenta fazer ao receber a recusa, e se isso afeta algo além da mensagem, não foi apurado (Seções 12.1 e 14).

Os resultados estão na Seção 9.

## 9. Resultados SAST — campanha de detecção

Resultados da campanha de 16 e 17 de setembro de 2026 (Seção 8.8), cruzados com o ground truth pelos critérios da Seção 7, fixados antes de qualquer número. Produzidos por `tools/cruza-deteccao.py` e `tools/circularidade-proveniencia.py`, com as saídas versionadas em `results/cruzamento/` e `results/circularidade/`.

**Estes resultados são a metade positiva da matriz de confusão** — verdadeiros positivos e falsos negativos, isto é, o recall. A metade negativa depende da campanha da versão corrigida (Seção 7.3) e constará da Seção 9.8.

As passagens de interpretação estão marcadas como tal; o restante é medida.

### 9.1 Cobertura

| | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| CVEs com saída bruta, de 223 | 221 | 221 | 216 |
| Pares no denominador | 220 | 220 | 220 |

Os dois CVEs sem saída em nenhuma ferramenta são as baixas por indisponibilidade de código (Seção 7.4). Os cinco a menos no Snyk Code são os de ausência de material analisável (Seção 4.6), que permanecem no denominador e contam como ausência de detecção. Nenhum lote foi refeito, e nenhuma saída bruta foi ilegível.

### 9.2 Matriz de detecção

Acertos sobre o denominador de 220 — 219 nas variantes estritas, que descontam o `CVE-2018-16472`, de primário indefinido (Seção 7.4):

| Nível | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| 0 — achado na árvore | 190 (86,4%) | 183 (83,2%) | 132 (60,0%) |
| 1 — arquivo | 140 (63,6%) | 98 (44,5%) | 45 (20,5%) |
| 2 generosa — arquivo e CWE | 126 (57,3%) | 48 (21,8%) | 16 (7,3%) |
| 2 estrita | 124 (56,6%) | 46 (21,0%) | 9 (4,1%) |
| 3 — arquivo e linha | 101 (45,9%) | 25 (11,4%) | 22 (10,0%) |
| 4 generosa — arquivo, linha e CWE | 95 (43,2%) | 20 (9,1%) | 10 (4,5%) |
| 4 estrita | 94 (42,9%) | 20 (9,1%) | 6 (2,7%) |

**A ordenação entre as ferramentas é a mesma nos sete níveis, sem cruzamento.** A conclusão sobre a ordem não depende do critério escolhido — é o que o desenho em camadas existia para estabelecer.

**Os níveis 2 e 3 não formam escada** (Seção 7.2): o Snyk Code tem mais acertos no nível 3 (22) que no nível 2 generosa (16).

**As variantes generosa e estrita quase não divergem**, salvo no Snyk Code.

### 9.3 Onde cada ferramenta perde

**Do arquivo certo para o ponto certo** (nível 1 para nível 3):

| | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| CVEs no nível 1 | 140 | 98 | 45 |
| destes, também no nível 3 | 101 | 25 | 22 |
| perdidos | 39 (28%) | 73 (74%) | 23 (51%) |

**Do arquivo certo para a natureza certa** (nível 1 para nível 2 generosa): o CodeQL mantém 90% dos acertos (140 para 126), o Semgrep menos da metade (98 para 48), o Snyk Code cerca de um terço (45 para 16).

**Interpretação.** Encontrar o arquivo e classificar a natureza da vulnerabilidade são capacidades distintas. O Semgrep encontra o arquivo com frequência razoável e perde tanto o ponto quanto a natureza, o que é compatível com correspondência sintática de padrões; o CodeQL mantém-se nos três eixos, o que é compatível com análise de fluxo de dados. **Essa leitura de mecanismo não é medida**: o estudo não mede a técnica interna das ferramentas.

**Caracterização da distância.** Dentro do arquivo certo, a distância mediana entre o achado e a linha do ground truth é de 71 linhas no CodeQL, 113 no Semgrep e 64 no Snyk Code, e mais de 35% dos achados estão a mais de 100 linhas, nas três (Seção 7.7).

### 9.4 Duração, e a relação entre porte e custo

| Ferramenta | Mediana | Média | Máximo | 1º–3º quartil | Soma |
|---|---:|---:|---:|---|---:|
| CodeQL | 47 s | 58,6 s | 304 s | 43–60 s | 3,63 h |
| Semgrep | 18 s | 21,9 s | 202 s | 14–21 s | 1,36 h |
| Snyk Code | 13 s | 18,5 s | 135 s | 10–19 s | 1,14 h |

A duração por CVE cobre obtenção do código e análise. Nenhum CVE se aproximou do limite de 900 segundos (Seção 4.4).

**Convenção da tabela, declarada.** As quatro estatísticas são apuradas sobre as **223 linhas do registro de execução** de cada ferramenta, incluídas as duas de falha de obtenção, cuja duração é próxima de zero (Seção 7.4). A média do CodeQL constou como 58,8 s nas primeiras versões destes números, valor que corresponde a 222 linhas; sobre as 223, é 58,6 s. As demais células, e as médias das outras duas ferramentas, sempre seguiram a convenção das 223.

**Porte do repositório e custo de análise no CodeQL**, sobre os 221 CVEs analisados:

| Arquivos extraídos | CVEs | Mediana |
|---|---:|---:|
| 0–10 | 72 | 43 s |
| 11–50 | 57 | 45 s |
| 51–100 | 27 | 54 s |
| 101–200 | 26 | 61 s |
| 201–500 | 19 | 69 s |
| 501–1000 | 10 | 92 s |
| mais de 1000 | 10 | 158 s |

Há um **piso de cerca de 43 segundos** que domina até cerca de 50 arquivos, e a curva sobe de forma monótona depois. O **joelho está entre 500 e 1000 arquivos**, onde a mediana dobra em relação ao piso; acima de 1000, ela triplica. O maior caso, com 5.693 arquivos extraídos, custou 296 segundos.

A relação entre porte e custo **existe**, mas fica encoberta pelo custo fixo de invocação na faixa em que está a maior parte do conjunto: 129 dos 221 CVEs têm 50 arquivos ou menos. Registra-se a trajetória, que é ela mesma um caso da Seção 12.5: com seis pontos, no ensaio de fumaça, a leitura foi a de que o porte não prediz o custo; com 59, a de que um piso domina; com 221, esta. **A conclusão da amostra pequena foi refinada, e não confirmada.**

### 9.5 Volume de alertas — caracterização, não medida de qualidade

| | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| Achados | 3.230 | 11.768 | 3.666 |
| Fração fora do arquivo do ground truth | 77,8% | 96,9% | 94,6% |

**Estes números medem quanto cada ferramenta reporta, e não quanto acerta** (Seções 7.3 e 7.7). Os alertas fora do arquivo do ground truth não são classificáveis como corretos ou incorretos com este conjunto.

**O volume do Semgrep é concentrado.** Nos seis últimos lotes, dez CVEs somam 77% dos achados da ferramenta, e um único — o `CVE-2018-20801` — responde por 5.850, com saída bruta de 144 MiB. É perfil de regra disparando em massa num repositório, e não de detecção densa. Qualquer número agregado de volume precisa vir acompanhado da distribuição.

### 9.6 Inventário do CodeQL

A conferência entre as duas fontes do inventário de arquivos extraídos (Seção 5.2) bateu em **211 dos 221 CVEs**. A maior extração observada foi de 5.693 arquivos.

Os dez divergentes — `CVE-2018-18282`, `CVE-2018-3738`, `CVE-2019-13127`, `CVE-2019-15532`, `CVE-2019-15657`, `CVE-2019-18350`, `CVE-2019-18818`, `CVE-2020-27666`, `CVE-2020-7638`, `CVE-2021-31712` — **divergem sempre no mesmo sentido**: a lista de artefatos depurada tem de 1 a 4 arquivos a mais que a notificação de arquivos extraídos, e a notificação nunca tem arquivo que a lista não tenha. Os 22 arquivos a mais somados são todos JavaScript ou TypeScript, concentrados em diretórios de documentação, de exemplos e de testes.

**Isto não é teto de enumeração**, e a razão é a direção: um teto faria a notificação perder arquivos, e ela não perde nenhum. A escolha da notificação como fonte única, feita antes de existir saída real e contra a opção mais óbvia, **nunca superestimou a cobertura** nos 221 casos.

**Hipótese, não medida:** os arquivos a mais são os que o extrator conheceu e não extraiu — configuração de ferramentas de documentação e exemplos. A verificação é possível, pelas notificações de erro de extração presentes em dois desses resultados, e não foi feita.

### 9.7 Cobertura por arquivo

| | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| Arquivo do ground truth considerado | 221 | 221 | não informa |
| Não considerado | 0 | 0 | não informa |

**Nenhum caso de arquivo não considerado nos 223 CVEs.** O ramo correspondente continua sem exercício sobre dado real, coberto apenas por fixture. No Snyk Code, que informa cobertura agregada por linguagem, sem inventário de caminhos, a condição é indeterminada nos 216: **não se distingue, nele, a análise que examinou o arquivo e não encontrou nada da que não o examinou**.

### 9.8 Resultados da campanha da versão corrigida — a preencher

Falso positivo e verdadeiro negativo, e com eles precisão, especificidade e F1, na forma que a Seção 7.3 vier a fixar.

### 9.9 Detecção por CWE — a preencher

Os acertos por categoria de vulnerabilidade, por ferramenta e por nível. Pendência da Seção 14: os dados estão na matriz versionada.

### 9.10 Circularidade da proveniência — apuração

A Seção 2.2.2 estabelece que, em **163 dos 223 CVEs (73,1%)**, a descrição e o conjunto de CWEs foram herdados da consulta do CodeQL que identificou o caso. Daí uma ameaça direta ao resultado da Seção 9.2: os níveis 2 e 4 dependem de casamento de CWE, e o CodeQL é medido, em grande parte, contra etiquetas derivadas dele próprio. Ao contrário da maioria das ameaças à validade, esta é mensurável com o dado existente.

**Partição.** O denominador de 220 foi partido pela proveniência da etiqueta, contra o estado de referência do catálogo (`ec573b51`, Seção 2.2.2): **161 CVEs com etiqueta herdada e 59 sem**. Os níveis 1 e 3, que não usam CWE, funcionam como **controle interno**. A soma dos dois grupos reconstrói a matriz da Seção 9.2 em 21 células, sem divergência.

Acertos por grupo (a base da variante estrita desconta o `CVE-2018-16472`):

| Nível | CodeQL herdado | CodeQL não herdado | Semgrep herdado | Semgrep não herdado | Snyk herdado | Snyk não herdado |
|---|---:|---:|---:|---:|---:|---:|
| 0 | 144/161 | 46/59 | 134/161 | 49/59 | 100/161 | 32/59 |
| 1 | 110/161 | 30/59 | 77/161 | 21/59 | 39/161 | 6/59 |
| 2 generosa | 101/161 | 25/59 | 35/161 | 13/59 | 15/161 | 1/59 |
| 2 estrita | 100/160 | 24/59 | 33/160 | 13/59 | 9/160 | 0/59 |
| 3 | 80/161 | 21/59 | 22/161 | 3/59 | 21/161 | 1/59 |
| 4 generosa | 76/161 | 19/59 | 17/161 | 3/59 | 10/161 | 0/59 |
| 4 estrita | 76/160 | 18/59 | 17/160 | 3/59 | 6/160 | 0/59 |

Diferença de taxa entre o grupo herdado e o não herdado, em pontos percentuais:

| Nível | CodeQL | Semgrep | Snyk Code |
|---|---:|---:|---:|
| 0 | +11,5 | +0,2 | +7,9 |
| 1 (sem CWE) | +17,5 | +12,2 | +14,1 |
| 2 generosa | +20,4 | −0,3 | +7,6 |
| 2 estrita | +21,8 | −1,4 | +5,6 |
| 3 (sem CWE) | +14,1 | +8,6 | +11,3 |
| 4 generosa | +15,0 | +5,5 | +6,2 |
| 4 estrita | +17,0 | +5,5 | +3,8 |

**Duas leituras, que precisam ser mantidas juntas.**

*A maior parte da diferença entre os grupos não é circularidade.* Nos níveis que não usam CWE, o grupo herdado é mais favorável para as três ferramentas — inclusive para as duas que não geraram etiqueta alguma. Se fosse circularidade de etiqueta, o efeito não apareceria onde a etiqueta não entra.

*Há sinal de circularidade, na diferença das diferenças.* Exigir o casamento de CWE **aumenta** a vantagem do CodeQL no grupo herdado — de +17,5 para +21,8, e de +14,1 para +17,0 — e **diminui** a das outras duas. A assimetria é a assinatura esperada da circularidade, e só o CodeQL a exibe. A magnitude é de **3 a 4 pontos percentuais**.

**O recorte livre de circularidade.** No grupo sem etiqueta herdada e no nível 3 — sem herança e sem CWE —, o CodeQL acerta **21 de 59**, o Semgrep **3** e o Snyk Code **1**. A ordenação e a ordem de grandeza da vantagem sobrevivem no recorte em que a circularidade não pode operar.

**Limites da apuração.**

- **Os grupos não são comparáveis em composição.** O CWE-915 (poluição de protótipo) é 23 dos 59 do grupo não herdado e nenhum do herdado; o CWE-022 é 27 contra 2; o CWE-078, 24 contra 1. Proveniência da etiqueta e tipo de vulnerabilidade variam juntos, e este dado não separa os dois efeitos.
- **Os tamanhos são desiguais** (161 contra 59). Nenhum teste estatístico foi aplicado, e toda taxa é reportada com numerador e denominador.
- **A partição é pela descrição, e não pela etiqueta de CWE.** O cotejo de proveniência casa a descrição do CVE com o nome da consulta; a identidade dos conjuntos de CWE é consequência, não critério. As duas coincidem nos 163 casados, mas a recíproca não vale: **seis** CVEs do grupo não herdado carregam conjunto de dois ou mais CWEs idêntico ao de alguma consulta, com descrição em prosa — o `CVE-2019-10745` é o caso exemplar.
- Os cinco CVEs de ausência de material analisável do Snyk Code estão todos no grupo herdado.

**Os 22 CVEs de poluição de protótipo e a escolha da âncora.** Os 22 CVEs que separam o estado de referência do catálogo do estado de sensibilidade (Seção 2.2.2) estão no grupo não herdado sob a âncora, e todos têm primário CWE-915. Sobre eles, o CodeQL acerta 17 no nível 1 e 13 no nível 4 estrita; o Semgrep, 12 e 1; o Snyk Code, 1 e 0. **Excluídos os 22 dos dois grupos, as partições pelas duas referências coincidem** — 161 e 37 CVEs —, e as tabelas ficam idênticas. **A escolha da âncora não altera a análise de circularidade**; a diferença entre 163 e 185 é exatamente esses 22.

---

## 10. Resultados DAST — a preencher

Resultados da campanha DAST de 24 de julho de 2026 (Seção 6.1), cruzados com o ground truth das duas aplicações (Seções 2.3, 2.4 e 6.2), pela unidade da Seção 7.2 e pela taxonomia comum da Seção 7.1.

Estrutura prevista:

- **10.1 Correspondência dos alertas às categorias do ground truth**, pelo mapeamento manual das categorias para CWE.
- **10.2 Dupla apuração**, integral e filtrada, conforme a Seção 6.3.
- **10.3 Triagem dos alertas fora do escopo**, conforme a Seção 7.5.
- **10.4 Matriz de confusão**, com o conjunto de quadrantes que a triagem tornar computável — decisão a tomar em coerência com a da Seção 7.3.

---

## 11. Análise comparativa SAST × DAST — a preencher

Comparação entre as duas abordagens pela cobertura de categorias de CWE, em agregado, nos termos das Seções 7.1 e 12.4: as duas famílias não compartilham alvo, e a comparação não é feita CVE a CVE.

Estrutura prevista:

- **11.1 Categorias cobertas por cada abordagem**, e a sobreposição entre elas.
- **11.2 Complementaridade**: categorias alcançadas por uma abordagem e não pela outra.
- **11.3 Alcance da comparação**, com as limitações da Seção 12.4.

---

## 12. Ameaças à validade e limitações

### 12.1 Reprodutibilidade das ferramentas

**Fixação de versões.** As três ferramentas são empregadas em versão determinada: CodeQL 2.25.4, Semgrep 1.171.0 e Snyk Code CLI 1.1306.1. O conjunto de regras do Semgrep é vendorizado e registrado por dois resumos. A campanha preliminar, em contraste, fixava apenas o CodeQL, e as demais versões só foram recuperáveis a partir dos próprios arquivos de resultado.

**Dependência de serviço externo.** O Snyk Code depende de disponibilidade, autenticação e limites de uso do serviço da Snyk, e transmite o código analisado a esse serviço. Falhas de disponibilidade durante a campanha afetariam a cobertura. CodeQL e Semgrep operam integralmente na máquina de execução — no caso do Semgrep, com o conjunto de regras local, sem necessidade de rede.

**O Semgrep opera sem rede, mas tenta alcançá-la.** Medido com controle positivo no ensaio de fumaça: sob isolamento total de rede, o Semgrep completa a varredura, mas leva cerca de **110 segundos** num único arquivo, contra cerca de 13 segundos de um lote inteiro com rede — reproduzido no hospedeiro local (109 e 113 segundos) e no ambiente da campanha (112 segundos). A afirmação correta é que ele **opera sem rede, tentando alcançá-la e esperando o tempo esgotar** — o que difere de não a usar.

**O Snyk Code tem duas condições abertas que dependem do serviço.** A primeira: todo teste com achados terminou com recusa de acesso (HTTP 403), impressa depois do resumo (Seção 8.8). A saída bruta foi gravada nos 133 casos, o que mostra que o gravado está íntegro, não que nada deixou de ser gravado. Como o Snyk Code é a ferramenta de menor detecção do estudo, um defeito silencioso contra ela inflaria a diferença entre as ferramentas na direção em que já é grande; a investigação está pendente (Seção 14). A segunda: **a análise ocorre no serviço, e o motor e as regras dele não são fixados pela imagem** — rodar o mesmo CVE em outra data pode dar outro resultado. A campanha da versão corrigida, se executada em data distinta da de detecção, precisa declarar essa condição, e as duas campanhas do Snyk Code devem rodar na mesma conta, para que a diferença entre elas não inclua mudança de permissão.

**Imagens base — resolvida.** A versão anterior deste documento registrava que as imagens Docker não eram fixadas por identidade de conteúdo, admitindo variação entre reconstruções — condição agravada pela reconstrução a cada execução, que multiplicava as oportunidades de variação ao longo de uma mesma campanha. A construção única com referência por identidade de conteúdo (Seção 4.5) fecha essa ameaça e torna citável, no relatório de cada lote, a imagem efetivamente empregada.

O que a decisão introduz em troca está declarado na Seção 4.5: a possibilidade de derivação entre o conjunto de regras versionado e o embutido na imagem, interceptada pela segunda comparação de resumo, que é fatal.

**Ordem não determinística do conjunto de regras servido.** Conforme a Seção 4.5, o registry do Semgrep entrega o conjunto resolvido com ordenação variável entre requisições. O resumo criptográfico do arquivo não permite, portanto, que terceiro verifique se o conjunto vendorizado corresponde ao que o registry serve em outro momento: arquivos de conteúdo idêntico produzem resumos distintos. A mitigação é a identidade secundária pela lista ordenada de identificadores, invariante à reordenação, reproduzida também no resultado normalizado; a limitação residual é que o conjunto de regras do estudo é verificável por identidade de regras, e não por identidade de arquivo.

**Verificação do CodeQL em versão adjacente — resolvida.** A versão anterior deste documento registrava que o ensaio ponta a ponta do modo de construção do banco de dados fora executado em versão posterior à fixada, restando a possibilidade, tida por remota, de divergência de comportamento entre as duas. O ensaio local (Seção 8.6) repetiu a verificação na versão fixada, sobre o lote de teste: a construção e a análise do banco de dados concluíram sem erro nos quatro CVEs, e a própria saída declara a versão empregada em seu campo de versão semântica, o que dispensa atestado externo. As quatro propriedades originalmente confirmadas — aceitação do modo, emissão de caminhos relativos à raiz do repositório, cobertura de identificadores de CWE entre as regras e código de saída nulo mesmo havendo achados — foram reproduzidas. A ameaça deixa de subsistir.

**Campos dependentes de autenticação.** Determinados campos auxiliares da saída do Semgrep permanecem não preenchidos quando a ferramenta opera sem autenticação. Verificou-se experimentalmente que a condição decorre da ausência de autenticação e não da origem do conjunto de regras, e que os campos afetados não integram os dados consumidos pela normalização.

**Origem das fixtures de verificação.** O programa de normalização e as fixtures que o verificam foram inicialmente derivados da documentação das saídas das ferramentas e da inspeção das saídas da campanha preliminar. A confrontação descrita na Seção 8.6 corrigiu as que divergiam da saída real, de modo que a lacuna está reduzida, não eliminada: as fixtures que não divergiram permanecem de origem documental, e uma delas comprovadamente afirmava a polaridade inversa da observada sem que asserção alguma o revelasse.

**Ambiente do ensaio local.** As medições de duração, volume e permissão da Seção 8.6 foram obtidas em hospedeiro distinto do ambiente da campanha, com identificador de usuário, disco e memória diferentes. Não transferem. O caso mais claro é o das permissões: dois defeitos simétricos foram identificados, cada um manifesto no ambiente em que o outro não se manifesta (Seção 4.7). O ensaio de fumaça mediu o primeiro no ambiente da campanha (Seção 4.7); o segundo permanece estabelecido pela medição local, e a cobertura dos dois resulta da união das duas, não de uma medição única. As medições de duração foram refeitas no ambiente da campanha pelo ensaio de fumaça e pela campanha (Seções 4.4 e 9.4).

**Amostra do ensaio local.** Quatro CVEs efetivamente analisados, em repositórios de uma única linguagem. Propriedades verificadas sobre essa amostra — inclusive a completude do inventário de arquivos do CodeQL e a suficiência da chave de ordenação — valiam para a faixa observada. **A campanha reconferiu as duas em escala**: o inventário bateu em 211 dos 221 CVEs, até 5.693 arquivos, com as divergências todas no sentido que exclui teto de enumeração (Seção 9.6); a chave de ordenação não teve colisão em 18.664 achados (Seção 5.6).

**Imagens privadas.** As imagens da campanha permanecem privadas no registro (Seção 5.5). A reprodução exata depende de acesso concedido; a reconstrução independente, a partir dos Dockerfiles versionados, é aproximada.

### 12.2 Delimitação do conjunto de dados

**Proveniência do ground truth e assimetria de comparabilidade.** Conforme a Seção 2.2.2, em 73,1% do conjunto a descrição e os CWEs do ground truth derivam do catálogo de consultas do CodeQL — uma das três ferramentas SAST sob avaliação. O CodeQL é, portanto, confrontado com uma referência construída a partir de sua própria taxonomia, condição que não se aplica ao Semgrep nem ao Snyk Code.

A consequência delimita a interpretação dos resultados: a comparação entre as três ferramentas não mede capacidade de detecção em abstrato, e sim grau de concordância com a nomenclatura e o recorte do CodeQL. Eventual vantagem do CodeQL nas métricas admite, por construção, explicação alternativa à de superioridade técnica, e assim deve ser reportada. Registra-se que a modalidade de correspondência por conjunto (Seção 7.4) atenua parcialmente o efeito, por não exigir coincidência de identificador específico, mas não o elimina.

**A ameaça foi medida, e está delimitada** (Seção 9.10). A maior parte da vantagem do CodeQL não se explica por circularidade: nos níveis sem CWE, o grupo de etiqueta herdada é mais favorável às três ferramentas. Há sinal de circularidade, de 3 a 4 pontos percentuais, na ampliação da vantagem do CodeQL quando o CWE é exigido. E no recorte em que a circularidade não opera — etiqueta não herdada, nível sem CWE —, o CodeQL acerta 21 de 59, contra 3 e 1. A explicação alternativa que esta seção exigia declarar existe, mas não sustenta a diferença observada.

**Viés de seleção do conjunto.** Se o núcleo do dataset foi constituído a partir de casos identificados pelo CodeQL, vulnerabilidades que a ferramenta não detecta tendem a estar sub-representadas. O recall apurado para as três ferramentas incide, portanto, sobre um universo previamente filtrado pela capacidade de uma delas. A limitação afeta a interpretação do recall em termos absolutos; a comparação relativa entre Semgrep e Snyk Code, que não participaram dessa construção, permanece menos afetada.

**A apuração da circularidade não trata este viés.** Ela mede a circularidade de **etiqueta**; o viés de **seleção** — quais vulnerabilidades entraram no conjunto — continua declarado e não medido.

**Disponibilidade dos repositórios e dos commits.** Parte dos CVEs remonta a 2016–2017, e repositórios removidos, renomeados ou submetidos a reescrita de histórico podem impedir a obtenção do commit registrado. A limitação deixou de ser enunciado e passou a ocorrência medida: as sondagens de 6 e de 10 de setembro de 2026 obtiveram 185 dos 186 repositórios acessíveis, com um inacessível, atingindo um CVE (Seções 2.2.3 e 7.4).

**A disponibilidade de commit também degenerou**, e isso não é detectável por sondagem de repositório: o `CVE-2018-8035` declara commit ausente de um repositório acessível, e só a campanha o revelou, no checkout (Seções 2.2.3 e 4.3).

A ocorrência é de natureza degenerativa: o conjunto perde elementos com o tempo, por causa externa ao estudo e às ferramentas. A perda é quantificada e declarada pela campanha, CVE a CVE, e não constatada apenas pela ausência de resultado.

**Cobertura do benchmark.** A capacidade empírica apurada é limitada ao que comparece no conjunto analisado. A ausência de determinado CWE nos resultados informa sobre o dataset, não necessariamente sobre as ferramentas.

**Denominadores de arquivo considerado não são comparáveis entre as ferramentas.** Conforme a Seção 5.2, o Semgrep informa arquivos varridos e o CodeQL informa arquivos extraídos para o banco de dados, ao passo que o Snyk Code não decide sobre arquivo determinado. Os três respondem à pergunta que o campo formula, mas sobre universos distintos, de modo que a proporção de arquivos considerados não constitui grandeza comparável entre ferramentas. O uso previsto do campo — distinguir ausência de detecção de ausência de exame, no arquivo apontado pelo ground truth — não depende dessa comparação.

Acresce que a fonte adotada no CodeQL enumera arquivos extraídos sem que se tenha estabelecido a inexistência de limite máximo de enumeração. A conferência descrita na Seção 5.2 detecta discordância entre as duas fontes disponíveis na mesma saída, mas duas fontes sujeitas ao mesmo limite concordariam de todo modo. A decisão foi validada sobre quatro CVEs e reconferida pela campanha, em repositórios de até 5.693 arquivos extraídos: as divergências observadas vão todas no sentido oposto ao de um teto (Seção 9.6). O Snyk Code não informa cobertura por arquivo em nenhum dos 216 CVEs analisados (Seção 9.7).

**Alcance do controle com o Semgrep.** O controle descrito na Seção 2.2.2 cotejou o ground truth com o catálogo de regras do Semgrep em seu estado atual, e não no estado vigente em 2020. O catálogo atual é mais extenso que o de então, de modo que o viés opera em sentido conservador: um catálogo menor produziria correspondência ainda inferior à nula ora medida.

**Subjetividade residual do mapeamento de CWE primário.** A tabela da Seção 7.4 resulta de julgamento sobre 17 conjuntos, ainda que apoiado em evidência documental e submetido a regra de fechamento explícita. A dupla apuração mitiga o risco: a modalidade de correspondência por conjunto independe inteiramente do mapeamento, de modo que divergência quanto a este pode ser avaliada por comparação entre as duas apurações.

Acresce uma observação que a proveniência do ground truth impõe. A evidência de primeira ordem para a seleção do primário é o campo de descrição da weakness, o mesmo campo que, em 73,1% do conjunto, é herdado do catálogo de consultas do CodeQL (Seção 2.2.2). A seleção do primário incorpora, portanto, uma segunda camada da mesma proveniência, e não apenas a primeira. A observação reforça, mais do que enfraquece, a razão de haver duas modalidades: a apuração por conjunto não depende da seleção e serve de contraprova à apuração por primário.

### 12.3 Delimitação da campanha DAST

**Aplicações-alvo.** O número reduzido de aplicações dinâmicas limita a generalização das conclusões sobre desempenho do ZAP.

**Versões das aplicações.** A correspondência exata entre a versão do `challenges.yml` empregada como ground truth e a imagem executada durante a varredura deve ser verificada. Não havendo fixação de tag na execução, a divergência é declarada como limitação.

**Parâmetros de varredura.** Limites de configuração do ZAP afetam as contagens reportadas. Verificou-se que um número expressivo de alertas registra exatamente cinco instâncias, e que o plano de automação disponível fixa limite de alertas por regra e duração máxima de rastreamento. As contagens de instâncias por alerta são, por isso, tratadas como possivelmente truncadas e não empregadas quantitativamente.

**Duração das varreduras.** Os registros de tempo dos relatórios indicam que a campanha dinâmica completa transcorreu em aproximadamente vinte minutos, com intervalo inferior a cinco minutos entre os dois full scans. Documentação preliminar do projeto indicava duração substancialmente superior por aplicação. A divergência sugere que a varredura ativa pode não ter percorrido integralmente as aplicações — circunstância agravada, no caso do Juice Shop, por tratar-se de aplicação de página única, cuja superfície é de difícil descoberta por rastreadores convencionais.

**Registro do modo de varredura.** Os relatórios em JSON não contêm campo que identifique o modo de execução. A associação entre relatório e modo foi estabelecida por contagem e, posteriormente, confirmada por evidência independente da contagem — a presença de alertas de regra de varredura ativa apenas nos relatórios de full scan (Seção 6.1). A limitação residual é que nenhuma das duas evidências provém do próprio campo que a ferramenta deixou de emitir.

### 12.4 Alvos disjuntos entre abordagens

As campanhas SAST e DAST incidem sobre conjuntos distintos de aplicações. Em consequência, a análise de sobreposição entre abordagens não pode ser estabelecida por medição direta sobre um alvo comum, restringindo-se à comparação de cobertura de categorias em agregado.

**A mitigação por alvo comum foi examinada e descartada.** Considerou-se executar também as ferramentas SAST sobre o código-fonte das aplicações empregadas na campanha DAST, obtendo-se ao menos um alvo submetido a ambas as abordagens. Decidiu-se não executá-las, e a razão não é de escopo e sim de ausência de gabarito: o Juice Shop e o NodeGoat não declaram, por vulnerabilidade, arquivo, linha, identificador de CWE e commit anterior à correção — os quatro elementos de que a apuração das Seções 7.3 e 7.4 depende. Achados produzidos ali não seriam classificáveis em verdadeiro e falso positivo, e a contagem resultante mediria volume de alerta, não detecção.

A limitação permanece, em consequência, **declarada e não mitigada**: as duas famílias não compartilham alvo algum, e a comparação entre elas se dá entre o que cada uma alcança em seus próprios termos, e não entre detecções sobre a mesma aplicação. Decidiu-se igualmente manter o OWASP NodeGoat no estudo, de modo que os quatro relatórios da Seção 6.1 constituem o conjunto DAST definitivo.

### 12.5 Confiabilidade dos métodos de medição empregados

Três ocorrências registradas ao longo da construção do pipeline compartilham a mesma estrutura, e sua repetição justifica registro próprio: em todas, o objeto medido estava correto e o método de medição, errado, produzindo divergência que somente a medição por método independente revelou.

| Ocorrência | Método falho | Causa |
|---|---|---|
| Contagem de regras do conjunto vendorizado (1.073 em lugar de 1.074) | Expressão regular sobre o início de linha | Ao menos uma regra declara os campos em ordem diversa da suposta |
| Contagem de severidades do conjunto vendorizado (1.075 em lugar de 1.074) | Expressão regular sobre a ocorrência do campo | Uma regra declara o campo em dois níveis de aninhamento |
| Verificação de exclusão de arquivos do controle de versão | Comando de consulta de padrões | O comando reporta correspondência de padrão, inclusive de negação, e não veredito de exclusão |
| Atribuição de causa a interrupção de processo | Código de encerramento tomado como assinatura de esgotamento de memória | O mesmo código resulta de encerramento deliberado por sinal; a assinatura é compatível com a causa, mas não a estabelece |
| Análise de relação entre duas grandezas medidas | Correspondência entre duas listas inferida pela ordem em que foram transcritas | As listas não estavam alinhadas; o coeficiente resultante foi computado sobre pares inexistentes |

Nos dois primeiros casos, o método correto é o processamento por analisador da linguagem em que o arquivo está escrito; no terceiro, o comando que efetivamente realiza a operação em modo simulado; no quarto, a corroboração por evidência independente antes da atribuição; no quinto, a exigência de que a correspondência entre séries esteja declarada na fonte, e não reconstituída pela ordem de transcrição.

O quinto caso merece registro adicional por sua consequência. Examinava-se a relação entre o número de arquivos extraídos por CVE e a duração da análise, com vista a estimar o custo da campanha a partir de atributo barato do conjunto. O cotejo apoiou-se na ordem em que as duas séries figuravam no relatório do ensaio local, que não é a mesma; o coeficiente daí resultante não descreve relação alguma. Uma vez identificado o erro, a correspondência foi computada a partir das fontes versionadas, e os quatro pares ficam determinados (Seção 8.6). A questão de que o exame partia — se o porte do repositório prediz a duração — permanece **em aberto**, não respondida negativamente como se chegou a supor: quatro observações não permitem prever, e nenhum coeficiente é computado sobre elas.

Registra-se que o padrão reincidiu na própria revisão que o identificou, sob outra forma: presumiu-se que determinada passagem constasse dos três documentos do projeto por figurar em dois deles, sem que a terceira ocorrência fosse conferida — presunção que se mostrou falsa em um caso e verdadeira em outro. A correspondência inferida não era, ali, entre séries de medidas, e sim entre documentos; o método falho é o mesmo. O padrão reincidiu ainda duas vezes, e as duas merecem registro por incidirem sobre o próprio material do estudo. A presunção acima veio a mostrar-se falsa também no terceiro documento: a passagem existia apenas no relatório do ensaio local, que não integra o repositório, e não em nenhum dos dois documentos versionados. E, sobre a campanha DAST, o conjunto de regras do projeto remetia a correspondência entre relatório e modo de varredura a documento que **não existia em versão alguma do repositório** — lacuna fechada em setembro de 2026 e registrada na Seção 6.1.

A regra que daí se extrai é geral e simétrica: **correspondência não declarada é conferida antes de ser usada**, trate-se de séries, de listas ou de documentos. Não estando declarada, o primeiro passo é torná-la explícita na fonte, nunca estimá-la pela ordem; e remissão a documento é conferida quanto à existência do documento.

**Uma explicação plausível, refutada.** Ao constatar-se que a reexecução do cotejo de proveniência produzia número diverso do registrado, propôs-se que o número registrado proviesse do estado **atual** do catálogo, e ofereceu-se aritmética que o explicava: certo número de casos a mais compensado por certo número a menos, com saldo exatamente igual à diferença observada. A aritmética é verdadeira e a atribuição, falsa — o estado atual não produz identidade total de conjunto, de modo que não pode ter originado o número registrado. As duas consultas invocadas como responsáveis pelos casos a mais sequer existiam no catálogo em dezembro de 2020. A explicação foi aceita, em primeira instância, porque os números fechavam.

Registra-se como caso próprio porque ilustra modo de falha distinto dos anteriores: não é método de medição errado, é **explicação que reproduz o resultado sem ser sua causa**. A exigência que dele decorre é de mesma ordem que as demais: hipótese que explique uma diferença por compensação entre parcelas deve ter cada parcela verificada quanto à existência, e não apenas quanto à soma.

**Generalização, e não um episódio adicional.** As ocorrências acima têm em comum que o resultado obtido era plausível. Decorre delas uma exigência sobre resultados vazios: **resultado nulo exige distinguir a ausência do objeto da formulação inadequada da pergunta.** Verificação que retorna zero só é aceita quando o método foi exercido contra caso reconhecidamente positivo, ou quando a saída de erro foi lida. Padrão que não corresponde, especificação de caminho inválida e argumento interpretado como opção produzem zero indistinguível de ausência — e assim ocorreu, no curso desta revisão, com uma consulta ao controle de versão cuja especificação de caminho não correspondia a arquivo algum, sugerindo ausência de arquivos existentes, e com uma busca por padrão cujo argumento foi interpretado como opção, com a saída de erro suprimida.

A exigência tem alcance que excede a verificação de método. A varredura de segredos do histórico do repositório, conduzida antes da publicação, não localizou ocorrência alguma — mas cobria um repertório de formas, e o mecanismo de proteção do serviço de hospedagem, com repertório diverso, detectou forma que ela não procurava, posteriormente confirmada como valor de exemplo de documentação e não credencial. A conclusão que a varredura autoriza é, por isso, a de que não há ocorrência **nas formas procuradas**, e não a de que não há segredo no histórico.

O quarto caso ocorreu no ensaio local e teria produzido registro incorreto se aceito: a interrupção deliberada de uma execução prolongada produziu o mesmo código que o esgotamento de memória produziria, em circunstância na qual o esgotamento era plausível pelas características do hospedeiro. A distinção decorreu do exame do mecanismo — o tratamento de sinal do script não interrompe ferramenta em primeiro plano —, e não da assinatura.

A observação tem alcance além deste estudo, e por isso é declarada em lugar de apenas corrigida: a verificação por expressão regular sobre formatos estruturados falha por causas independentes entre si — ordem de campos e profundidade de aninhamento —, de modo que a ausência de uma delas não assegura a ausência da outra. O procedimento adotado, em consequência, exige que toda contagem destinada a figurar como resultado seja produzida por analisador do formato, e que discrepância entre dois métodos seja reconciliada antes de qualquer das contagens ser aceita, ainda que a conclusão sobreviva à reconciliação — como sobreviveu nos três casos.


**Casos desta versão.** O padrão — método que produz número plausível sem ser o método correto — reincidiu durante a campanha e o cruzamento, sempre interceptado antes de chegar a resultado, e registra-se pela forma de cada ocorrência:

- **Guarda que não guardava.** Uma contagem encadeada antes de um commit terminou com código de saída diferente de zero ao contar zero ocorrências; a cadeia se interrompeu, o commit não rodou, e o código de retorno lido em seguida era o da cadeia, não o do commit. O sucesso aparente não correspondia a operação alguma.
- **Sonda que leu o próprio comando.** Uma verificação procurou uma expressão na saída e casou com o eco do comando que a continha, reportando resultado onde o correto era "inconclusivo".
- **Critério reimplementado em lugar de lido.** Uma apuração do inventário do CodeQL reescreveu o critério de depuração do programa de normalização, em vez de usar o do próprio programa, e produziu números que contradiziam o relatório dele.
- **Coluna errada.** A leitura da tabela de CWE primário pela coluna errada produziu "17 conjuntos sem primário" onde havia um.
- **Contagem visual.** Um número transcrito de tabela a olho (11) divergia do dado (13), e foi interceptado por verificador automático com controle positivo, que confronta cada número de texto com a saída versionada.
- **Ordem não determinística.** Uma saída versionada variava entre execuções porque um contador era alimentado pela iteração de um conjunto, cuja ordem muda entre processos; a versão em texto ordenava e escondia a variação.
- **Informação presente e não ligada.** O critério da versão corrigida estava registrado desde agosto e não foi relacionado ao falso positivo quando se decidiu que ele não existia (Seção 7.3). Não é método de medição errado, é conclusão tirada sem consultar o que o próprio projeto já sabia — e o resultado, "não há negativo", era plausível.

---

## 13. Registro de decisões

| # | Decisão | Seção |
|---|---|---|
| 1 | Benchmarks distintos para SAST e DAST | 1.3 |
| 2 | CVE como unidade de análise, não repositório | 4.1 |
| 3 | Listas de entrada autocontidas, com ground truth embutido | 4.2 |
| 4 | Listas em seis campos, com CWEs normalizados na origem | 4.2 |
| 5 | Validações bloqueantes no gerador de listas | 4.2 |
| 6 | Lotes de 30 CVEs, com lote de teste dirigido | 4.2, 4.4 |
| 7 | Não regerar listas com execução em andamento | 4.2 |
| 8 | Checkout obrigatório do commit vulnerável | 4.3 |
| 9 | Fetch raso com fallback para clone completo | 4.3 |
| 10 | Container por lote, com laço idempotente | 4.4 |
| 11 | CodeQL: suíte security-extended, não security-and-quality | 4.5 |
| 12 | Semgrep: `p/default` vendorizado, não `--config=auto` | 4.5 |
| 13 | Semgrep: sem exclusão de regras na coleta | 4.5 |
| 14 | Semgrep: arquivo de regras na raiz do sistema de arquivos do container | 4.5 |
| 15 | Snyk Code: apenas saída SARIF, CLI em versão fixada | 4.5 |
| 16 | Log estruturado de execução, versionado | 4.6 |
| 17 | Normalização executada fora dos containers | 5.1 |
| 18 | Schema com metadados por CVE e ground truth embutido | 5.2 |
| 19 | Normalização de CWE para três dígitos, também no ground truth | 5.3 |
| 20 | Normalização de caminhos à raiz do repositório | 5.3 |
| 21 | Registro explícito de análises sem achados | 5.3 |
| 22 | Severidade normalizada a partir do nível textual | 5.4 |
| 23 | Escore numérico do CodeQL preservado, mas não normalizado | 5.4 |
| 24 | Resultados normalizados e registros de execução versionados | 5.5 |
| 25 | Contagens DAST extraídas dos relatórios JSON | 6.1 |
| 26 | Exclusão de desafios desativados em Docker | 6.2 |
| 27 | Filtro de detectabilidade por tags oficiais | 6.2 |
| 28 | Dupla apuração das métricas DAST | 6.3 |
| 29 | CWE como pivô único de tradução | 7.1 |
| 30 | Matrizes de confusão separadas por abordagem | 7.2 |
| 31 | Unidade (CWE, arquivo) para SAST, não (CWE, arquivo, linha) | 7.2 |
| 32 | Dupla apuração SAST: por conjunto e por CWE primário | 7.4 |
| 33 | Exclusão de CVEs sem CWE das contagens | 7.4 |
| 34 | Categoria própria para achados fora de escopo | 7.5 |
| 35 | Capacidade empírica, com achados brutos | 7.6 |
| 36 | Linha como métrica auxiliar de precisão de localização | 7.7 |
| 37 | CWE primário restrito ao conjunto declarado pelo benchmark | 7.4 |
| 38 | Tabela de mapeamento de CWE primário versionada e auditável | 7.4 |
| 39 | Sem agrupamento por família de CWE na comparação | 7.1 |
| 40 | Proveniência do ground truth declarada como ameaça à validade | 12.2 |
| 41 | Conjunto de regras do Semgrep embutido na imagem, não montado em execução | 4.5 |
| 42 | Identidade secundária do conjunto de regras pela lista ordenada de identificadores | 4.5 |
| 43 | Asserção do commit analisado, com registro do valor efetivo no log | 4.3 |
| 44 | Escrita atômica da saída bruta, com validação antes da promoção do nome | 4.6 |
| 45 | Estado próprio para ausência de material analisável | 4.6 |
| 46 | Exclusão por indisponibilidade de repositório em categoria própria, fora da matriz | 7.4 |
| 47 | Revisão do pipeline por checklist derivado dos defeitos da campanha invalidada | 8.5 |
| 48 | Normalização independente do registro de execução, com commit proveniente da lista | 5.1 |
| 49 | Conferência do registro de execução em programa próprio, com quarta conferência contra a lista do lote | 4.6, 5.1 |
| 50 | Normalização do ground truth estendida a caminhos de arquivo, com preservação do valor original | 2.2.3, 5.3 |
| 51 | Estado próprio para severidade não resolvida por junção, distinto da ausência de nível | 5.4 |
| 52 | Registro tri-estado da varredura do arquivo do ground truth, sem efeito sobre denominador | 5.2, 7.4 |
| 53 | Diagnósticos da ferramenta preservados no resultado normalizado | 5.2 |
| 54 | Saída bruta ilegível como falha declarada, nunca como ausência de achados | 5.3 |
| 55 | Execução dos containers sob o identificador de usuário do hospedeiro, com diretório pessoal explícito | 4.7 |
| 56 | Verificação da normalização por fixtures sintéticas versionadas, com lacunas declaradas | 5.6 |
| 57 | Identidade secundária do conjunto de regras reproduzida no resultado normalizado | 5.2 |
| 58 | Ensaio local do pipeline, com confrontação dos formatos declarados contra saída real, antes do ensaio de fumaça | 8.6 |
| 59 | Campo de inventário de regras do Semgrep renomeado para regras aplicadas | 4.5, 5.2 |
| 60 | Coordenada de coluna acrescida aos achados e à chave de ordenação | 5.2, 5.3 |
| 61 | Varredura do arquivo do ground truth decidida no CodeQL pela notificação de extração bem-sucedida | 5.2 |
| 62 | Motivo do estado de varredura declarado nos três estados | 5.2 |
| 63 | Eliminação do indicador heurístico de menção ao arquivo do ground truth | 5.2 |
| 64 | Consultas precompiladas do bundle tornadas legíveis na construção da imagem | 4.5, 4.7 |
| 65 | Não executar as ferramentas SAST sobre as aplicações da campanha DAST, por ausência de gabarito | 12.4 |
| 66 | Manutenção do OWASP NodeGoat no estudo | 2.4, 12.4 |
| 67 | Publicação do repositório do estudo em acesso público | 5.5 |
| 68 | Correspondência entre relatório e modo da campanha DAST registrada em documento próprio, em duas unidades de contagem e por evidência independente | 6.1 |
| 69 | Procedimentos de apuração da proveniência do ground truth versionados, com estados dos catálogos fixados por commit em descritor próprio | 2.2.2 |
| 70 | Estado de referência do catálogo do CodeQL fixado como o último integrado ao ramo principal antes do commit do release do benchmark, por critério de anterioridade | 2.2.2 |
| 71 | Manutenção do tamanho de lote corrente, com a decisão apoiada em comportamento medido e não em limite de pior caso, e com sinal de vigilância próprio | 4.4, 4.6 |
| 72 | Fluxos de trabalho submetidos à revisão prévia, na mesma disciplina dos programas e das imagens | 8.5 |
| 73 | Limites de tempo sobrescrevíveis por ambiente, sem reconstrução de imagem, com guarda de forma que rejeita valor vazio e zero | 4.4 |
| 74 | Reconstrução das imagens antes do ensaio de fumaça, para que o ensaio meça as imagens da campanha | 3.1, 8.7 |
| 75 | Workflow de lote único para o ensaio e a campanha, com as três ferramentas em matriz, uma por job | 3.1 |
| 76 | Pré-voo da imagem antes de cada lote | 4.6 |
| 77 | Portão de lote sem saída bruta, que nomeia a condição e não atribui causa | 4.6 |
| 78 | Limite de análise em 900 segundos, justificado pela assimetria da falha e não pela folga sobre o observado | 4.4 |
| 79 | Tamanho de lote de 30 confirmado no escopo restrito, com o perfil de item que não termina declarado como não amostrado | 4.4 |
| 80 | Dois primeiros lotes em série, com leitura entre eles, e os seis restantes em paralelo | 8.8 |
| 81 | Cinco níveis de acerto, apurados na mesma passada, em lugar de critério único | 7.2 |
| 82 | Casamento de linha por sobreposição, sem banda de tolerância, decidido por medição, em substituição às faixas de localização | 7.7 |
| 83 | Critérios de cruzamento fixados em documento versionado antes de qualquer número de detecção | 7.2 |
| 84 | Indisponibilidade de código como categoria de exclusão, abrangendo repositório e commit; denominador de 220 | 7.4 |
| 85 | O denominador é o que a campanha mede; a sondagem prévia antecipa baixas de repositório e não alcança as de commit | 4.3, 7.4 |
| 86 | Falso positivo e verdadeiro negativo definidos na versão corrigida, a partir do README e da documentação do benchmark; definição de falso positivo da versão anterior abandonada; campanha da versão corrigida | 7.3 |
| 87 | Versionamento do cruzamento, da proveniência, da circularidade e de todo o conteúdo dos artifacts da campanha, salvo as saídas brutas, preservadas em cópia externa | 5.5 |
| 88 | Saídas de análise determinísticas, sem carimbo de execução, com o resumo das entradas e do código que as produziu | 5.5 |
| 89 | Apuração da circularidade da proveniência com os níveis sem CWE como controle interno | 9.10 |
| 90 | Documento de método e resultados | Nota |

---

## 14. Decisões e verificações pendentes

Registram-se as questões ainda em aberto no momento desta redação.

### Decisões

**Desenho da campanha da versão corrigida** (Seção 7.3). Em ordem: a leitura — matriz de quatro células, reconhecimento condicionado à detecção, ou as duas; o critério de localização do ponto da falha depois da correção; os níveis aplicáveis; o tratamento dos dois `PostPatchCommit` malformados (Seção 2.2.3) e a conferência dos demais; o denominador. Tudo fixado no documento de critérios antes de qualquer resultado.

**Snyk Code.** A investigação da recusa de acesso ao fim dos testes com achados (Seções 8.8 e 12.1) está adiada: a cota de testes da conta empregada esgotou-se em 21 de setembro de 2026. A investigação consome de quatro a seis testes; a campanha da versão corrigida, 216; no pior caso — recusa que afete os achados e obrigue a refazer a campanha de detecção da ferramenta —, 432. Se a cota for resolvida com outra conta, as duas campanhas do Snyk Code devem rodar na mesma conta, ou a recusa precisa ser investigada antes, para saber se depende da conta. Os números do Snyk Code não devem ser apresentados como definitivos sem a investigação ou sem a declaração explícita da limitação.

**Publicação das imagens.** As três imagens da campanha permanecem privadas no registro, com a decisão pendente da leitura das licenças do conjunto de regras do Semgrep e do bundle do CodeQL (Seção 5.5).

**CWE primário do conjunto CWE-250 + CWE-400.** Único conjunto da tabela da Seção 7.4 ainda sem definição. A descrição registrada não corresponde a nenhum dos dois identificadores declarados, o que exige exame do diff de correção. Afeta um CVE, o `CVE-2018-16472`, ao qual a variante estrita não se aplica.

### Apurações prometidas e ainda não feitas

Constam das versões anteriores e dependem apenas dos dados já versionados:

- **detecção por CWE**, por ferramenta e por nível (Seções 7.7 e 9.9);
- **tabela de capacidade empírica** por ferramenta (Seção 7.6);
- **proporção dos achados do Semgrep fora de JavaScript e TypeScript**, declarada (Seção 7.6).

### Verificações abertas

- **Ramo de arquivo não considerado.** Não ocorreu em 223 CVEs e continua exercitado só por fixture (Seção 9.7).
- **Divergências do inventário do CodeQL.** A hipótese sobre os dez casos (Seção 9.6) é verificável pelas notificações de erro de extração, e não foi verificada.
- **Texto fora do repertório ASCII** nos achados reais, e **dois avisos de execução sem fixture** (Seção 5.6). O campo que declara a origem da data de análise admite valor que a versão fixada do CodeQL não produz (Seção 8.6); o tratamento permanece como salvaguarda.
- **Segundo defeito de permissão** do CodeQL, não medido no ambiente da campanha (Seção 4.7).

### Trabalho restante para fechar esta versão

- a **campanha da versão corrigida** e seus resultados (Seções 7.3 e 9.8);
- os **resultados DAST** (Seção 10);
- a **análise comparativa** (Seção 11).

**Nota sobre pendências resolvidas nesta versão.** O universo de referência do verdadeiro negativo resolve-se pela versão corrigida (Seção 7.3). O limite de tempo das análises foi decidido (Seção 4.4). As verificações que a versão anterior remetia ao ambiente da campanha foram todas feitas: o identificador de usuário e o defeito do diretório pessoal (Seção 4.7); a duração do CodeQL no ambiente da campanha (Seções 4.4 e 9.4); o TypeScript atravessando o laço (Seção 8.7); a execução sem rede do Semgrep (Seção 12.1); a completude do inventário do CodeQL em repositórios de grande porte (Seção 9.6); e a duração da normalização sobre o conjunto completo (Seção 5.6).

**Nota.** A pendência relativa ao critério de agrupamento por família de CWE, registrada nesta seção na versão 3, foi resolvida e consta da Seção 7.1.
