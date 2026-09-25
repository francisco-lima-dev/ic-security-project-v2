# Tabela dos CVEs do estudo

Saída de `tools/tabela-cves.py`, gerada pelo script — não editar à mão.
Uma linha por CVE do OpenSSF CVE Benchmark, **223 linhas**, ordenadas por
ano e depois pelo número do CVE, numericamente (`CVE-2018-3719` antes de
`CVE-2018-16472`).

## Comando

```bash
python3 tools/tabela-cves.py
```

Sem argumentos: entradas e saída padrão. Determinística — nenhum carimbo
de execução; `git diff --exit-code results/tabela-cves/` depois de
reexecutar denuncia saída desatualizada.

## Arquivos

| Arquivo | sha256 |
|---|---|
| `tabela-cves.csv` | `24c8c28af23f0d8d1f0b3f6e814355535bfd00c1619244cc34be774f7b4b1132` |
| `tabela-cves.md` | `e953b1d37383977b2ba58ec02eb0a78f0c70da69677298269604a7862f2e9232` |

## Colunas

| Coluna | Conteúdo |
|---|---|
| `cve` | identificador |
| `repositorio` | `dono/nome`, derivado da URL |
| `url` | URL do repositório, como no benchmark |
| `commit_vulneravel` | `PrePatchCommit`, 40 hex — o commit analisado |
| `cwes` | `gt_cwes`: o conjunto declarado, normalizado para três dígitos, na ordem do benchmark, separado por `\|` |
| `cwe_primario` | `gt_cwe_primary`; vazio no `CVE-2018-16472` (primário indefinido na tabela) e no `CVE-2018-1000096` (sem CWE) |
| `arquivo` | `gt_file_path` normalizado (o `CVE-2019-12041` sem a barra inicial) |
| `linhas` | `gt_file_lines`, separadas por `\|` |
| `situacao` | ver abaixo |
| `descricao` | o campo `Explanation` do benchmark, como veio |

O campo `cwes` **não é classificação do defeito**: em 163 dos 223 CVEs é
o conjunto de tags da consulta do CodeQL que originou o registro (ver
`results/proveniencia/`). O `cwe_primario` é a seleção feita pelo estudo
dentro desse conjunto, pela tabela `datasets/cwe-primario.csv`.

## Situação

| situação | CVEs | quais |
|---|---:|---|
| `analisado` | 220 | no denominador de 220 pares |
| `fora: repositório inexistente` | 1 | `CVE-2016-1000229` |
| `fora: commit inexistente` | 1 | `CVE-2018-8035` |
| `fora: sem CWE` | 1 | `CVE-2018-1000096` |

A lista dos excluídos vem de `FORA_DO_DENOMINADOR`, do
`tools/cruza-deteccao.py`; o script só a traduz em rótulo. O
`CVE-2018-1000096` foi analisado nas três ferramentas, mas não entra na
matriz por não ter CWE. Os outros dois não tiveram código analisado:
nenhuma ferramenta foi confrontada com eles.

## O que a tabela NÃO contém

**Detecção alguma.** Nenhuma coluna de achado, de acerto ou de resultado
de ferramenta, e o script não lê tratado, matriz de detecção nem log de
execução. Também não traz o `PostPatchCommit`, que só entra na segunda
campanha, nem a proveniência da etiqueta (herdada ou não do CodeQL), que
está em `results/proveniencia/` e `results/circularidade/`.

## Fontes

Todas versionadas. Caminho relativo ao repositório, sha256.

| Fonte | Para quê | sha256 |
|---|---|---|
| `datasets/listas/cves-sast.txt` | ground truth normalizado e denominador, via `carregar_gt()` | `7b300e43c561470a7d4952cdd0789cd231fab2f3b38a00f047967bb6ab49b277` |
| `datasets/cwe-primario.csv` | `cwe_primario` dos conjuntos multivalorados | `cf77014f582170df920bbe7200aa8e68c7e7c90f9d561a36f9ac39320dcf9fbe` |
| `datasets/cve-metadata.csv` | `descricao`; e conferência 0 de URL, commit, CWEs, arquivo e linhas | `d202df0214078faf2d4be53f94789b2e153baa5f898205572b7539c9ef44f598` |
| `results/por-cwe/distribuicao-primario.csv` | só a conferência 4 | `86a9f13bcb50a7f20b448bc39aea154a2bda753ef9c441fef2c4ab9f52718fa1` |
| `tools/tabela-cves.py` | código | `ed8b6a3da63248d1446778ebdac1e3fafdd8cf4118757acafd4ce42547a580b2` |
| `tools/cruza-deteccao.py` | código | `8fea5aaba3202b019b92fd27ad6472b7c9ef7eab31dfa5a3130f1e266053c44c` |
| `tools/normalize.py` | código | `0e2a0b1229762732a62579fac1a1411a9549249cd5fccd32e17caf45b258b1d0` |

Nada é reimplementado: o ground truth normalizado e o denominador vêm de
`carregar_gt()` do `cruza-deteccao.py`, que aplica `carregar_lista`,
`normalizar_cwe`, `normalizar_gt_file_path` e `resolver_primario` do
`normalize.py`. O `cve-metadata.csv` é lido com o módulo `csv`, porque
sete descrições têm aspas escapadas por duplicação.

## Conferências que precedem a gravação

Falhando qualquer uma, o script sai com código não nulo e nada é gravado.
Cada uma tem controle positivo — mutante que precisa disparar a
conferência pretendida —, rodado antes das conferências reais.

| Conferência | Estado |
|---|---|
| 0 lista = cve-metadata.csv em CVE, URL, commit, CWEs, arquivo, linhas | OK |
| 1 223 linhas, 223 CVEs distintos | OK |
| 2 186 repositórios e 38 CWEs distintos (V10, §2.2) | OK |
| 3 situação: 220 analisado, 1 de cada exclusão nominada; cwe\_primario vazio só em CVE-2018-1000096 e CVE-2018-16472 | OK |
| 4 cwe\_primario = results/por-cwe, CVE a CVE (220) | OK, 0 divergências |
| 5 CSV temporário relido com o módulo csv; .md gravado relido, 223 linhas | OK |
| controle positivo, conferências 0 a 4 (15 mutantes, alvo CVE-2016-10735) | OK, todos dispararam |
|   c0: commit divergente entre lista e metadata | disparou |
|   c0: CVE ausente do metadata | disparou |
|   c1: linha removida (222) | disparou |
|   c1: CVE duplicado, 223 linhas | disparou |
|   c2: repositorio a mais (187) | disparou |
|   c2: CWE a mais (39) | disparou |
|   c2: URL nova sob o mesmo dono/nome | disparou |
|   c3: analisado rebaixado a fora | disparou |
|   c3: rotulos de exclusao trocados entre CVEs | disparou |
|   c3: quinto valor de situacao | disparou |
|   c3: terceiro cwe\_primario vazio | disparou |
|   c4: primario alterado na tabela | disparou |
|   c4: CVE ausente de por-cwe | disparou |
|   c4: CVE fora do denominador presente em por-cwe | disparou |
|   guarda: entrada externa com saida no repositorio | disparou |
| controle positivo, conferência 5 (12 mutantes, em arquivo) | OK, cada um pelo item pretendido |
|   5.0: cabecalho alterado | disparou 5.0 |
|   5.0: campo excedente numa linha | disparou 5.0 |
|   5.1: ultima linha perdida | disparou 5.1 |
|   5.2: CVE com quebra de linha final | disparou 5.2,5.3,5.4 |
|   5.2: commit abreviado | disparou 5.2,5.4 |
|   5.2: CWE sem zero a esquerda | disparou 5.2,5.4 |
|   5.2: cwe\_primario fora da forma | disparou 5.2,5.4 |
|   5.2: linha zero na coluna linhas | disparou 5.2,5.4 |
|   5.3: descricao com quebra de linha | disparou 5.3,5.4 |
|   5.4: aspas perdidas na descricao | disparou 5.4 |
|   5.4: duas linhas trocadas de posicao | disparou 5.4 |
|   5.5: md com uma linha de dados a menos | disparou 5.5 |

## Alcance das conferências

Nem todas são prova independente, e o "OK" acima não diz qual é:

- **A única com âncora externa é a 2** — 186 e 38 vêm da V10 (§2.2).
- **A 1 é verdadeira por construção** na execução real: `carregar_gt`
  já para fora de 223 CVEs, e o ground truth é chaveado por CVE. Ela pega
  defeito da montagem da tabela, não da lista.
- **Na 3, o "220 analisado" é verdadeiro por construção**: situação e
  denominador vêm da mesma `FORA_DO_DENOMINADOR`, e `carregar_gt` já para
  fora de 220. O que ela acrescenta é o par CVE → rótulo contra a lista
  nominada à mão, e o conjunto exato de `cwe_primario` vazio.
- **A 4 pega arquivo desatualizado ou entrada trocada, não erro na tabela
  de primário**: `results/por-cwe/` aplica a mesma tabela pela mesma
  `resolver_primario`.
- **A 0 compara fontes independentes** (lista e `cve-metadata.csv`), mas
  depois de passar as duas pelas mesmas `normalizar_cwe` e
  `normalizar_gt_file_path`: divergência que a normalização apague — como
  `/index.js` contra `index.js` — ou defeito dela mesma não aparece.

## Escrita

Os três arquivos são gravados com nome temporário; o CSV é relido com o
módulo `csv` e o `.md` gravado é relido (conferência 5), e só então os
três ocupam o nome definitivo, na ordem CSV, `.md`, README — este por
último, porque declara o sha256 dos outros dois. Depois da promoção, o
conteúdo de cada nome definitivo é conferido por sha256 contra o aprovado.
**Limite declarado:** os três renames não são atômicos como conjunto.
Falha entre eles é nomeada pelo script, mas interrupção abrupta (SIGKILL)
deixa arquivos de execuções diferentes, detectáveis só conferindo à mão
os sha256 da tabela "Arquivos" — não há modo de conferência automático.

O determinismo é conferido fora do script, com `PYTHONHASHSEED` distintos.
O script recusa gravar dentro do repositório se alguma entrada estiver
fora dele, porque o caminho da máquina do operador iria para este README.
