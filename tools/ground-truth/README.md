# Proveniência do ground truth — procedimento

Reconstrói o cotejo que produziu o achado mais forte do estudo: que
`explanation` e `CWEs` do ground truth do OpenSSF CVE Benchmark foram
**herdados da consulta do CodeQL que identificou o caso**.

Até a Fase P, era o único achado do estudo que um terceiro não reproduzia —
os scripts nunca haviam sido versionados.

## Como rodar, de um clone limpo

```bash
G=tools/ground-truth
C=/tmp/catalogos
$G/obter-catalogos.sh $C

# ground truth do CSV versionado contra os três estados do CodeQL
python3 $G/cruza-codeql.py $C/codeql-2020/javascript/ql/src       --rotulo ref   --json /tmp/ref.json
python3 $G/cruza-codeql.py $C/codeql-2020-12-11/javascript/ql/src --rotulo sens  --json /tmp/sens.json
python3 $G/cruza-codeql.py $C/codeql-atual/javascript/ql/src      --rotulo atual --json /tmp/atual.json

# estados do benchmark lidos do JSON
python3 $G/cruza-codeql.py $C/codeql-2020/javascript/ql/src \
    --gt-json $C/benchmark-release/CVEs --rotulo release-ref --json /tmp/release-ref.json
python3 $G/cruza-codeql.py $C/codeql-2020-12-11/javascript/ql/src \
    --gt-json $C/benchmark-release/CVEs --rotulo release-sens --json /tmp/release-sens.json
python3 $G/cruza-codeql.py $C/codeql-2020/javascript/ql/src \
    --gt-json $C/benchmark-previo/CVEs --rotulo previo-ref --json /tmp/previo-ref.json
python3 $G/cruza-codeql.py $C/codeql-2020-12-02/javascript/ql/src \
    --gt-json $C/benchmark-previo/CVEs --rotulo previo-0212 --json /tmp/previo-0212.json

# diferenças nominais
python3 $G/compara-relatorios.py /tmp/ref.json         /tmp/sens.json
python3 $G/compara-relatorios.py /tmp/release-ref.json /tmp/ref.json
python3 $G/compara-relatorios.py /tmp/previo-ref.json  /tmp/release-ref.json
python3 $G/compara-relatorios.py /tmp/previo-0212.json /tmp/previo-ref.json
python3 $G/compara-relatorios.py /tmp/ref.json         /tmp/atual.json

(cd $G && npm ci)
node $G/cruza-semgrep.js datasets/cve-metadata.csv $C/semgrep-rules
```

Commits, datas e hashes vêm de `proveniencia.meta.json`. A obtenção é fetch
raso por SHA com `sparse-checkout`, a mesma técnica dos scripts de análise;
cada estado tem o HEAD **asseverado** contra o commit pedido, e o destino pode
ser relativo. `npm ci`, e não `npm install`: só o `ci` garante a árvore do
`package-lock.json`.

## O que cada peça faz

| Arquivo | Papel |
|---|---|
| `obter-catalogos.sh` | materializa quatro estados do CodeQL, o catálogo do Semgrep e dois estados do benchmark |
| `cruza-codeql.py` | o cotejo principal; lê o ground truth do CSV ou, com `--gt-json`, de uma pasta `CVEs/` |
| `compara-relatorios.py` | diferença **nominal** entre dois relatórios do cotejo |
| `cruza-semgrep.js` | o **controle** — Node, preservado como instrumento original |
| `proveniencia.meta.json` | entradas e fatos de proveniência, cada um com fonte e campo |
| `package.json` | fixa `js-yaml` em versão exata, sem `^` |

**Convenção dos números.** O descritor guarda entradas e fatos obtidos da API
do GitHub; não guarda contagem. Toda contagem deste README é saída de
`cruza-codeql.py`, `compara-relatorios.py` ou `cruza-semgrep.js`, pelos
comandos acima. Diferença entre estados nunca é subtração de totais: sai do
`compara-relatorios.py`, com os CVEs nomeados.

**Qual benchmark é o ground truth.** O CSV versionado é o benchmark no commit
do clone conferido (`ground_truth.clone_conferido`), **não** no commit do
release. O `compara-relatorios.py` entre o release e o CSV dá:

- **219** CVEs no release e **223** no CSV;
- **4 só no CSV:** `CVE-2020-26256`, `CVE-2021-23344`, `CVE-2021-23364` e
  `CVE-2021-31712`;
- **0** CVEs com rótulo diferente;
- os mesmos **163** casados contra a referência.

Os quatro CVEs acrescentados depois não casam em nenhum dos três estados do
CodeQL. Por isso nenhum número abaixo depende de o ground truth ser o CSV ou
o release.

## Estado de referência — a decisão

**Referência: `ec573b51`** (`codeql.commit_2020`), merge do PR #4759 no main
em `2020-12-08T15:38:36Z`: o último merge do main anterior ao commit do
release do benchmark (`2020-12-09T13:27:12Z`). Contra ele:

| Ground truth | `explanation` ≡ `@name` | `CWEs` idênticos às tags |
|---|---|---|
| CSV versionado | **163 de 223 (73,1%)** | **163 de 163** |
| commit do release | 163 de 219 (74,4%) | 163 de 163 |

**Razão.** A tese é herança, e para ser herança a consulta tem de existir
antes do rótulo. A referência é o CodeQL **integrado ao main** no momento do
commit do release. É contagem conservadora por construção: não credita como
herança o rótulo que corresponde a código ainda não integrado.

Isso **não** afirma que a correspondência com estado posterior seja
coincidência. Para os CVEs de prototype pollution, a herança de código
público não integrado está documentada adiante, no achado temporal. A
referência deixa esses casos fora da contagem; não os nega.

**A seleção usa uma data gravada pelo cliente**, a do commit do release. O
número não depende dela dentro da janela conferida. Os oito merges da cadeia
de primeiros pais de `ec573b51` a `af180d43` (`2020-12-11T20:42:11Z`) têm a
mesma árvore `javascript/ql/src`, `4d630cef002c4303b92e7c32193cba203dd16957`,
conferida por `git rev-parse` e pela API (`codeql.arvores_js_conferidas`).

**Por que não os commits anteriores.**

- A Fase P usou `a7451a12`, commit de **branch** do PR #4775 (C#), integrado
  ao main só em 17/12/2020.
- A primeira decisão da Fase P-2 foi `b649ccd8`, último merge do main em
  09/12/2020, mas ele é **posterior** ao commit do release.

As duas têm a mesma árvore JS de `ec573b51`. O número não muda, mas elas só
valiam por coincidência de árvore, e não por satisfazer o critério.

## Sensibilidade à data de corte

| Estado do CodeQL | Papel | casados (normalizado / exato) | idênticos / gt⊂consulta / divergentes | sem casar |
|---|---|---|---|---:|
| `ec573b51` (`2020-12-08T15:38:36Z`) | **referência** | 163 / 163 | 163 / 0 / 0 | 60 |
| `9ff6d68a` (`2020-12-11T21:58:09Z`) | medida de sensibilidade | 185 / 185 | 185 / 0 / 0 | 38 |
| `f7caf559` (atual, `2026-09-05T09:18:23Z`) | catálogo atual | 185 / 184 | 108 / 74 / 3 | 38 |

Ground truth: o CSV versionado. Com o commit do release como ground truth,
`9ff6d68a` dá 185 de 219, e 185 de 185 idênticos.

`9ff6d68a` é o merge do PR #4778 no main, o primeiro estado que contém
`Security/CWE-915/PrototypePollutingFunction.ql`. **É medida de
sensibilidade, não âncora alternativa.** A tabela registrada no `CLAUDE.md`,
atribuída lá a 09/12/2020, se reproduz neste estado.

A diferença, pelo `compara-relatorios.py` entre referência e `9ff6d68a`:

- **Ground truth igual** nos dois: 0 CVEs com rótulo diferente.
- **22 casados só em `9ff6d68a`**, todos por `PrototypePollutingFunction.ql`.
- **0 casados só na referência.**
- Os 163 casados nos dois: 0 com consulta diferente e 0 com relação diferente.

`PrototypePollutingFunction.ql` e a `PrototypePollutionUtility.ql` da
referência são **a mesma consulta**, `@id js/prototype-pollution-utility`,
renomeada e movida pelo PR (`codeql.consulta_prototype_pollution`).

## Achado temporal — forma (b)

**No commit do release, o estado de consulta que os rótulos dos CVEs de
prototype pollution reproduzem era público, num PR aberto, e não integrado
ao main.** Datas em `achado_temporal` e `benchmark` no descritor, com fonte
e campo:

| Fato | Data (UTC) | Fonte |
|---|---|---|
| PR #4778 aberto, de `asgerf/codeql` (fork) | `2020-12-04T13:02:02Z` | `pulls/4778` → `created_at`; sem evento de rascunho na timeline |
| `@name` "Prototype-polluting function" no head revisado, ainda sem a 079 | até `2020-12-07T09:56:24Z` | timeline, evento `reviewed`, `commit_id` `d0bb6315` |
| `fd293d07` (acrescenta `cwe-079`) no branch do PR | entre `2020-12-09T09:58:52Z` e `2020-12-09T09:59:55Z` | inferior: `committer.date`, **gravada pelo cliente**; superior: `ed729a19`, filho criado pelo **servidor** do GitHub (`web-flow`, assinatura verificada) |
| Commit "Release 1.0.0" do benchmark | `2020-12-09T13:27:12Z` | `commits/4e90564` → `committer.date`, **gravada pelo cliente**; **não há** objeto Release nem tag, e não se achou limite do lado do servidor |
| PR #4778 integrado ao main | `2020-12-11T21:58:10Z` | `pulls/4778` → `merged_at` |

**A ordem se sustenta por dois caminhos, e o segundo não depende de relógio.**

- **Pelas datas:** `09:59:55Z` (servidor) antecede `13:27:12Z`. Mas a segunda
  é do cliente do benchmark (`achado_temporal.ordem_por_data`).
- **Pelo conteúdo:** os rótulos do commit do release trazem o conjunto
  `CWE-078/079/094/400/915`. No histórico público do CodeQL esse conjunto
  aparece primeiro em `fd293d07`: nem o head revisado `d0bb6315` nem o main
  até `9ff6d68a` o têm. O conteúdo do release é posterior ou contemporâneo a
  esse estado, ou a um equivalente não publicado
  (`achado_temporal.ordem_por_conteudo`).

### A troca de rótulos

O descritor fixa dois estados do benchmark:

- **prévio:** `85411e55`, "preview release #4 for ossf", de
  `2020-12-02T22:37:58Z`, alcançável como base do PR #1 do benchmark;
- **release:** `4e90564`.

**O estado prévio já estava rotulado pelo main.** Cotejado contra o main
**anterior** a ele (`04bacf43`, `2020-12-02T21:08:22Z`), dá **181 de 214
casados e 181 de 181 idênticos**. Contra a referência dá o mesmo: o
`compara-relatorios.py` entre os dois cotejos mostra 0 diferenças.

O `compara-relatorios.py` entre o estado prévio e o release, ambos contra a
referência:

- **22 CVEs com rótulo diferente.**
  - Em 21, `"Prototype pollution in utility function"` com
    `CWE-400/471` passa a `"Prototype-polluting function"` com
    `CWE-078/079/094/400/915` — do `@name` e das tags da consulta como estava
    no main para os da mesma consulta renomeada no PR.
  - Em 1, `CVE-2019-10745`, a `explanation` em prosa fica igual e só os
    `CWEs` mudam, do mesmo modo.
- **21 casados só no estado prévio**, todos por
  `PrototypePollutionUtility.ql`.
- **3 casados só no release**, que são CVEs acrescentados no release.
- **160 casados nos dois**, com 0 mudanças de consulta e 0 de relação.
- **6 CVEs só no release.** Um deles é `CVE-2020-15256`, o 22º de prototype
  pollution.
- **1 CVE só no estado prévio:** `CVE-2019-14863`, gravado na forma antiga
  do schema (`patchBase`), que o `--gt-json` lê e lista.

**Leitura.** Antes do release, o benchmark estava rotulado por um main que o
antecede. No commit do release, os rótulos de prototype pollution foram
reescritos para o estado da mesma consulta no PR. Nos dois momentos, o estado
da consulta precede o rótulo: a direção é a de herança.

**O que não se estabelece.**

- De onde os autores do benchmark tiraram o estado do PR: do PR público ou de
  cópia própria.
- Se o estado prévio do benchmark era público. Existir PR em 03/12/2020 não
  prova visibilidade.
- A hora de **publicação** do release. Só a do commit é conhecida, e ela é
  gravada pelo cliente. O fork mais antigo listado pela API é de
  `2020-12-09T13:50:06Z`, mas seu conteúdo na criação não é recuperável
  (`benchmark.release_ressalva`).

## Explicação refutada

A versão da Fase P deste README, antes da revisão, atribuía os 185
registrados ao catálogo **atual**, com saldo "+22 = 29 − 7". **Refutada:**
o catálogo atual dá **108** idênticos, e não produz "185 de 185".

O `compara-relatorios.py` entre referência e atual mostra por que os totais
enganavam:

- **29 casados só no atual:** 22 por `PrototypePollutingFunction.ql`, 4 por
  `ResourceExhaustion.ql` e 3 por `ServerCrash.ql`.
- **7 casados só na referência**, todos por `ZipSlip.ql`. O `@name` dessa
  consulta mudou, no mesmo caminho.
- **3 casados mudam de consulta**, de `RequestForgery.ql` para
  `experimental/Security/CWE-918/SSRF.ql`.

`ResourceExhaustion.ql` e `ServerCrash.ql` **não existem** nos catálogos de
2020 obtidos pelo `obter-catalogos.sh`. O saldo coincide em número, mas não é
a causa.

## Controle — Semgrep

Contra o catálogo atual do Semgrep (`semgrep.commit`), com 2.228 regras de
2.162 YAML lidos (16 com erro de parse):

| Teste | Resultado |
|---|---|
| T1 — `explanation` igual à `message`, normalizada | **0 (0,0%)** |
| T2 — igual ao último segmento do `id` | 1 (0,4%) — `CVE-2018-16472` |
| T3 — contida em alguma `message` | 37 (16,6%) |
| União | 38 (17,0%) |

As `explanation` não são vocabulário comum da área: são nomes de consulta do
CodeQL. A subcadeia (T3) mede vocabulário compartilhado, não herança, e por
isso nunca é critério do cotejo.

## Declarações do cotejo que movem número

| Declaração | Efeito, pela saída do cotejo |
|---|---|
| Igualdade exata ou normalizada, nunca subcadeia; manchete é a normalizada | exato e normalizado coincidem em todos os estados de 2020; no atual, 185 normalizado e 184 exato |
| Escopo: todo `.ql` sob `javascript/ql/src`, **inclusive `experimental/`** | 0 casamentos via `experimental/` nos estados de 2020; 3 no atual |
| Só `external/cwe/cwe-NNN` entra no conjunto; outra grafia é listada | em 2020, `external/cwe-295` em `DisablingCertificateValidation.ql`; `CVE-2018-1000096` sai idêntico com os dois conjuntos vazios, 1 identidade vazia por estado |
| Vazio contra consulta com tags é `divergente`, não subconjunto | atual: 108/74/3; com vazio como subconjunto, 108/75/2 |
| CWE normalizado para três dígitos dos dois lados | — |
| Equivalência CSV × clone do benchmark conferida quando o clone existe | conferida em 223 CVEs (`ground_truth.clone_conferido`) |
| `--gt-json` lê `prePatch` ou, na falta, `patchBase`; CVE sem nenhuma das duas, repetido ou com nome divergente do arquivo aborta | estado prévio: 1 CVE na forma antiga, 0 sem explanation |

## Limitação declarada

**Como o estado de dez/2020 foi obtido na apuração original não está
estabelecido, e não há como estabelecer.** A apuração não deixou script nem
registro do commit usado. O clone local do CodeQL do operador tem reflog de
uma entrada só (`codeql.commit_2020_apuracao_original`).

Os três scripts não rastreados encontrados no clone do benchmark
(`agrupa-conjuntos-cwe.js`, `detalha-grupo.js`, `diagnostico-ground-truth.js`)
foram lidos por inteiro. **Não são o cotejo**: leem só os JSON do benchmark,
agrupam ou contam CWEs, `explanation` e localizações, e não tocam catálogo
algum. Com isso se encerra a busca pela pista
(`ground_truth.clone_scripts_nao_rastreados_leitura`).

## Limite do que isto estabelece

Estabelece que o cotejo é reproduzível e que a hipótese se sustenta no estado
de referência. Estabelece também que o número depende da data de corte, e
que a diferença é nominalmente os CVEs de prototype pollution, cujos rótulos
o benchmark reescreveu, antes do commit do release, do estado do main para o
do PR público.

Não estabelece que algum desses estados seja o da apuração original.
