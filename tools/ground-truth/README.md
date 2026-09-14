# Proveniência do ground truth — procedimento

Reconstrói o cotejo que produziu o achado mais forte do estudo: que
`explanation` e `CWEs` do ground truth do OpenSSF CVE Benchmark foram
**herdados da consulta do CodeQL que identificou o caso**.

Até esta fase, era o único achado do estudo que um terceiro não reproduzia —
os scripts nunca haviam sido versionados.

## Como rodar, de um clone limpo

```bash
tools/ground-truth/obter-catalogos.sh /tmp/catalogos

python3 tools/ground-truth/cruza-codeql.py \
    /tmp/catalogos/codeql-2020/javascript/ql/src       --rotulo "commit_2020"
python3 tools/ground-truth/cruza-codeql.py \
    /tmp/catalogos/codeql-2020-12-11/javascript/ql/src --rotulo "main 11/12/2020"
python3 tools/ground-truth/cruza-codeql.py \
    /tmp/catalogos/codeql-atual/javascript/ql/src      --rotulo "atual"

(cd tools/ground-truth && npm ci)
node tools/ground-truth/cruza-semgrep.js \
    datasets/cve-metadata.csv /tmp/catalogos/semgrep-rules
```

Os commits vêm de `proveniencia.meta.json`, versionado. Nenhum valor é
digitado duas vezes, e nada depende de clone preexistente em máquina alguma.
A obtenção leva ~10 s: é fetch raso por SHA com `sparse-checkout`, a mesma
técnica dos scripts de análise, e cada catálogo tem o HEAD **asseverado**
contra o commit pedido. O destino pode ser relativo; é resolvido para
absoluto antes da primeira obtenção.

`npm ci`, e não `npm install`: só o `ci` garante a árvore do
`package-lock.json`.

## O que cada peça faz

| Arquivo | Papel |
|---|---|
| `obter-catalogos.sh` | materializa os quatro catálogos em estado fixado |
| `cruza-codeql.py` | o cotejo principal — Python, sem dependência externa |
| `cruza-semgrep.js` | o **controle** — Node, preservado como instrumento original |
| `proveniencia.meta.json` | commits, datas, origens e as ressalvas |
| `package.json` | fixa `js-yaml` em versão exata, sem `^` |

Os dois scripts de cotejo conferem, quando o clone do benchmark está
presente, que o CSV versionado equivale aos JSON do benchmark, e abortam se
divergir. O `cruza-codeql.py` confere `explanation` de todas as weaknesses e
o conjunto canônico de CWEs; o `cruza-semgrep.js`, só `explanation`. Clone
ausente gera aviso — a equivalência fica **não conferida**, e o relatório
diz isso.

## Critério de casamento

Igualdade **exata** ou **normalizada**, nunca subcadeia. As duas são
reportadas lado a lado; a normalizada é a de manchete. A normalização do
controle é equivalente à do cotejo sobre este ground truth, que é todo ASCII
— não idêntica em geral; ver o docstring do `cruza-codeql.py`.

Subcadeia mede vocabulário compartilhado, não herança: no controle do
Semgrep ela devolve 17%, e esses 17% são termos genéricos — "cross site
scripting" — dentro de descrições sobre outra coisa.

CWE é normalizado para três dígitos **dos dois lados**: o ground truth tem
14 CVEs com CWE sem zero à esquerda e o CodeQL grava a tag em minúsculas.
Nenhum desses 14 está entre os casados idênticos em estado algum, então a
normalização não move número aqui — mas sem ela moveria em outro conjunto.

### Declarações que movem número

| Declaração | Efeito medido |
|---|---|
| Escopo: todo `.ql` sob `javascript/ql/src`, **inclusive `experimental/`** | no catálogo atual, 3 casamentos vêm de `experimental/Security/CWE-918/SSRF.ql`; sem eles o atual daria 182. Nos estados de dez/2020, 0 |
| Só `external/cwe/cwe-NNN` entra no conjunto; outra grafia é **listada** | em dez/2020 há uma, `external/cwe-295`, em `DisablingCertificateValidation.ql` — a consulta que casa o `CVE-2018-1000096`, único do benchmark sem CWE. Ele sai `identico` com **os dois conjuntos vazios** |
| Vazio contra consulta com tags é `divergente`, não subconjunto | no catálogo atual dá 108/74/3; com vazio como subconjunto, 108/75/2. O relatório imprime as duas |
| Manchete é a medida normalizada | nos estados de dez/2020, exato = normalizado. No atual, 185 normalizado e 184 exato: `CVE-2018-1000620` termina em ponto e o `@name` não |

## Resultado obtido em 12–13/09/2026

| Estado do catálogo CodeQL | casados (normalizado / exato) | idênticos / gt⊂consulta / divergentes | sem casar |
|---|---|---|---:|
| `commit_2020` `a7451a12` | **163 / 163** | **163** / 0 / 0 | 60 |
| main após o PR #4778, `9ff6d68a` (11/12/2020 21:58Z) | **185 / 185** | **185** / 0 / 0 | 38 |
| atual `f7caf559` (05/09/2026) | 185 / 184 | 108 / 74 / 3 | 38 |

Medido também, fora do `obter-catalogos.sh`: o último merge do main em
dezembro de 2020 (`2bb96369f15d23651f0cd1f10f2d80a6064e4b5d`, 22/12) dá
185/185.

Em cada estado de dezembro, uma das identidades é a vazia do
`CVE-2018-1000096`: identidades **não vazias** são 162 de 162 e 184 de 184.

Controle, Semgrep (`40b8c63f`): 2.228 regras de 2.162 YAML lidos (16 erros
de parse, todos arquivos de teste `.test.yaml`/`.test.yml` com vários
documentos e nenhuma regra). T1 — `explanation` igual à
`message`, **normalizada** — **0 de 223**. T2 — igual ao último segmento do
id — 1 (`CVE-2018-16472`, `remote-property-injection`). T3 — subcadeia — 37;
união, 38 (17,0%).

**A hipótese sobrevive em todos os estados de dezembro de 2020 medidos**:
todo CVE cuja `explanation` casa o `@name` de uma consulta tem também o
conjunto `CWEs` idêntico às tags daquela consulta, sem exceção. E o controle
devolve zero: as `explanation` não são vocabulário comum da área, são nomes
de consulta do CodeQL.

## Sensibilidade à data de corte — a divergência com o CLAUDE.md

O `CLAUDE.md` e a metodologia registram **185 de 223** e **185 de 185** no
estado de dez/2020. Contra `commit_2020` o procedimento obtém **163** e
**163 de 163**. Contra o main de **dois dias depois** obtém **185, 185 de 185
e 38 sem casar** — a tabela registrada, linha a linha.

A diferença inteira são os **22 CVEs de `Prototype-polluting function`**:

- a consulta `Security/CWE-915/PrototypePollutingFunction.ql` entrou no main
  com o merge do PR #4778, em 11/12/2020 21:58Z; a predecessora em
  `a7451a12` é `PrototypePollutionUtility.ql`, com outro `@name` e tags
  `400/471`;
- o `@name` e as tags do ground truth (`078/079/094/400/915`) estão no branch
  do PR desde `fd293d07`, de 09/12/2020 09:58Z — **antes** do commit do
  release 1.0.0 do benchmark (09/12/2020 13:27Z). Os rótulos vieram de um
  estado que não era o main público do dia 9;
- entre `a7451a12` e `9ff6d68a` os 163 casados continuam casando com as
  mesmas consultas, e os únicos acréscimos são os 22.

`commit_2020` não é commit de main: é de branch do PR #4775 (C#), integrado
em 17/12/2020. Sua árvore `javascript/ql/src` é, porém, idêntica à do main em
`b649ccd8` (09/12/2020 19:55Z) e em `af180d43` (11/12/2020 20:42Z). O 163 vale
para o main nessa janela e só nela.

**Explicação anterior, refutada.** A versão revisada deste README atribuía os
185 registrados ao catálogo **atual**, com saldo 29 − 7 = +22. Não se
sustenta: o catálogo atual dá 108 idênticos, e não produz "185 de 185". O
29 − 7 é aritmética verdadeira no atual, mas a atribuição é coincidência:
`ResourceExhaustion.ql` (4) e `ServerCrash.ql` (3) **não estão** no main em
dezembro de 2020 — foram reintroduzidas em janeiro de 2021, PRs #4942 e
#4951 — e compensam por acaso os 7 CVEs de Zip Slip, que deixam de casar no
atual porque o `@name` de `Security/CWE-022/ZipSlip.ql` mudou, no mesmo
caminho.

**Qual estado representa "dez/2020" é decisão do operador**, não deste
README. Este procedimento torna os dois reproduzíveis.

## Limite do que isto estabelece

Estabelece que **o cotejo é reproduzível**, que **a hipótese se sustenta**
em todos os estados de dezembro de 2020 medidos e que **o número depende da
data de corte**: 163 até 11/12/2020 20:42Z, 185 a partir do merge seguinte.

Não estabelece que algum desses seja o estado da apuração original, que não
deixou script em arquivo nem registro do commit usado.
