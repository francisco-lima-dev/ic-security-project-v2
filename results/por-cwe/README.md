# Distribuição do CWE primário no denominador

Saída de `tools/distribuicao-cwe-primario.py`. Versionada ao lado de
`results/cruzamento/` e `results/circularidade/`, e pela mesma razão: fixa a
base sobre a qual o limiar da decomposição por categoria é escolhido, antes de
existir número de detecção por categoria.

**Gerada em 25/09/2026.**

## Como foi produzida

```bash
python3 tools/distribuicao-cwe-primario.py
```

Sem argumentos: as entradas e a saída são as padrão. O texto sai também em
stdout, idêntico ao `.txt`.

## O que contém

- `distribuicao-primario.csv` — uma linha por categoria (`gt_cwe_primary`, ou
  `SEM_PRIMARIO` para o `CVE-2018-16472`), com `n`, os conjuntos `gt_cwes` que
  a originam e a contagem de cada um, a lista ordenada dos CVEs e a nota das
  duas exceções documentadas do conjunto `CWE-400|CWE-730`
  (`CVE-2017-16023`, `CVE-2018-7560`).
- `distribuicao-primario.txt` — a mesma tabela, o resumo (categorias
  distintas, soma, saltos entre n consecutivos, patamares), o estado de cada
  conferência e o sha256 de cada fonte e dos três scripts envolvidos.

## Fontes lidas

Todas versionadas.

| Fonte | Para quê |
|---|---|
| `datasets/listas/cves-sast.txt` | denominador e `gt_cwes`, via `carregar_gt()` do `tools/cruza-deteccao.py` |
| `datasets/cwe-primario.csv` | primário dos conjuntos multivalorados, via `normalize.carregar_tabela_primario` e `resolver_primario` |
| `datasets/cve-metadata.csv` | o benchmark antes do gerador de listas: terceira fonte independente do primário |
| `results/codeql/treated/*.json` | só o bloco `metadata` (`gt_cwe_primary`, `gt_cwes`) |
| `results/semgrep/treated/*.json` | idem |

Os tratados do Snyk Code **não** são fonte: faltam-lhe os cinco
`SEM_ARQUIVO_ANALISAVEL`. O script **não reimplementa** denominador nem
primário: importa as funções do `cruza-deteccao.py` e do `normalize.py`.

## O que este diretório NÃO contém

**Detecção alguma.** O script não lê a matriz de detecção, os agregados da
circularidade nem o campo `findings` dos tratados. A distribuição é
propriedade do ground truth.

## Conferências que precedem a gravação

Falhando qualquer uma, o script sai com código não nulo e nada é gravado.

1. Soma 220, e `SEM_PRIMARIO` é exatamente `CVE-2018-16472`. A soma é
   verdadeira por construção — o `carregar_gt` já para fora de 220 —; o que a
   conferência mede é o `SEM_PRIMARIO`.
2. O primário e o conjunto `gt_cwes` são idênticos, CVE a CVE, nas quatro
   fontes (lista, CodeQL, Semgrep, `cve-metadata.csv`). Pega entrada
   divergente e tratado desatualizado, **não** erro na tabela de primário: as
   quatro fontes a aplicam pela mesma função. Contra a tabela, a única prova
   independente é a 3, que cobre 10 categorias e 187 dos 220 CVEs.
3. As dez contagens da tabela de composição do `CLAUDE.md` (seção
   "Circularidade da proveniência") são reproduzidas exatamente.
4. Controle positivo das conferências 1 a 3, com mutantes em memória.
5. (Determinismo: conferido fora do script, com quatro `PYTHONHASHSEED`
   distintos.)
6. O CSV é gravado com nome temporário e relido com o módulo `csv`: forma
   (cabeçalho, número de campos, categoria), IDs bem formados, número de IDs
   igual a `n`, nenhum ID em duas linhas, união igual ao denominador, e cada
   categoria igual à estrutura que a gerou. Só então as
   duas saídas ocupam o nome definitivo; reprovado, os temporários são
   removidos e a saída aprovada anterior fica. A conferência 6 tem controle
   positivo próprio, sobre cópias mutadas do arquivo, um mutante por item.

```bash
python3 tools/distribuicao-cwe-primario.py --conferir-csv ARQ
```

roda só a conferência 6 contra um CSV qualquer, sem gravar nada, precedida do
controle positivo dela. Havendo `distribuicao-primario.txt` ao lado, confere
também o par (item 6.6): o `.txt` declara o sha256 do CSV da mesma execução.

**Limite declarado.** Os dois renames não são atômicos como par. Interrupção
entre eles deixa o CSV novo com o `.txt` anterior; o script nomeia a falha
quando ela é exceção, e o item 6.6 a detecta depois, mas nada a impede.

## Determinismo

Mesmos bytes em reexecução, com `PYTHONHASHSEED` 0, 1, 7 e 12345, para o CSV,
o texto e o stdout. Sem carimbo de execução;
`git diff --exit-code results/por-cwe/` depois de reexecutar denuncia saída
desatualizada. O script recusa gravar em qualquer diretório do repositório,
este inclusive, se alguma entrada estiver fora dele — cada uma resolvida por
inteiro, symlink incluso, e o diretório de tratado de cada ferramenta
conferido à parte —, porque o caminho da máquina do operador iria para o
`.txt`.
