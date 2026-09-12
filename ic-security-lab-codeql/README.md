# CodeQL — container de análise SAST

## Configuração avaliada

Suíte `javascript-security-extended.qls`, **não** `security-and-quality`.
A campanha anterior usou a segunda, que acrescenta consultas de qualidade
(`js/unused-local-variable` e afins) responsáveis por 46% dos achados sem
CWE. Regra de qualidade não é alegação de vulnerabilidade: computá-la como
falso positivo mediria a escolha de suíte, não a precisão da ferramenta.

```
codeql/javascript-queries:codeql-suites/javascript-security-extended.qls
```

**104 consultas** no bundle `v2.25.4`, que é o da imagem. Verificado na
imagem construída, com `codeql resolve queries` sobre a referência acima.

O ensaio ponta a ponta do `--build-mode=none` rodou na 2.26.4 e viu 105 — é
evolução do catálogo entre versões, não discrepância. O valor gravado no
tratado é o da versão empregada.

## Build

```bash
cd ic-security-lab-codeql
docker build -t ic-security-lab-codeql \
    --build-arg CODEQL_BUNDLE_VERSION="$(jq -r '.bundle | sub("^codeql-bundle-";"")' codeql-bundle.meta.json)" \
    --build-arg CODEQL_BUNDLE_SHA256="$(jq -r .sha256 codeql-bundle.meta.json)" .
```

Build context é este diretório, sem `-f`.

**Os dois `--build-arg` são obrigatórios.** Desde a Fase G-2b os `ARG` não
têm default e o build falha sem eles, por desenho: com default, um
`--build-arg` errado ou esquecido passava em silêncio e a imagem saía com
conteúdo diferente do que o descritor declara. É a disciplina que o
`PACK_SHA256` do Semgrep já tinha.

A fonte dos dois valores é `codeql-bundle.meta.json`, versionado. É essa
leitura que move a confiança do host de origem para o repositório: o build
compara contra o que está versionado aqui, não contra o que a release
disser no dia. O `sha256` é conferido **antes** de desempacotar os 808 MB, e
a comparação é fatal.

Nunca `latest`: o bundle carrega as consultas, e trocá-lo em silêncio troca
o conjunto avaliado.

## Execução

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e XDG_CACHE_HOME=/tmp \
    -v "$PWD":/workspace \
    ic-security-lab-codeql datasets/listas/cves-sast-batch-aa
```

O argumento é o lote, relativo ao workspace montado. Sem argumento, roda a
lista completa (`datasets/listas/cves-sast.txt`).

Saída bruta em `results/codeql/raw/<CVE>.sarif`, log em
`logs/execution-log-codeql.csv`. O laço é idempotente: CVE cujo raw já existe
é registrado como `PULADO`.

### Por que `--user` e `HOME`

Sem `--user`, o container roda como root e os artefatos saem com dono root no
volume montado — o usuário do hospedeiro não os reescreve, e o git roda como
usuário. Resolver na origem é melhor que `chown` pós-lote, que só desfaz o
atrito depois de criado.

O `-e HOME=/tmp` está aqui por **uniformidade com as outras duas imagens**,
não porque o CodeQL precise dele neste hospedeiro. `node:24-bookworm` já traz
um usuário de uid 1000 (`node`), então sob uid 1000 o `HOME` resolve sozinho.
Sob uid 1001 — o do runner do GitHub Actions — `HOME` viraria `/`, como
acontece com o Semgrep e o Snyk. Medido em 08/09/2026.

`WORKDIR` e `DBDIR` vivem em `/tmp`, fora do volume: `/tmp` permanece
gravável sob `--user`, verificado.

## Formato da saída

SARIF 2.1.0. Pontos que o normalizador precisa saber:

- o CWE está na **regra**, em `tool.driver.rules[].properties.tags[]`, com
  prefixo `external/cwe/` e em minúsculas
- a severidade também está só na regra (`defaultConfiguration.level`): é a
  única das três ferramentas que exige junção, e o dado que mais facilmente
  vira nulo silencioso. A junção é por `ruleId`, nunca por `ruleIndex`
- `endLine` está ausente em 96,7% dos achados
- `security-severity` é campo à parte, exclusivo desta ferramenta, e **não**
  serve de base para a severidade normalizada: mede impacto em estilo CVSS,
  enquanto o `level` mede confiança na alegação
- o caminho sai **relativo e limpo** (`app.js`), sem prefixo do diretório de
  trabalho — propriedade que vem de invocar a ferramenta com
  `--source-root=.` de dentro do WORKDIR, e da qual todo o cruzamento depende
- `database analyze` sai **0 mesmo com achados**: checar `RC != 0` não
  rebaixa análise bem-sucedida
- o SARIF **não** traz inventário de arquivos varridos. `gt_file_scanned` do
  CodeQL é `null` por assimetria declarada, não por omissão
