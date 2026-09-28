# Caracterização dos pares vulnerável → corrigido

Saídas de `tools/caracteriza-pares.py`. Propriedade do **ground truth**, e não
resultado de detecção: nenhuma ferramenta SAST rodou, e nenhum tratado, matriz
ou log de análise foi lido. O `PostPatchCommit` foi obtido, como preparação da
campanha da versão corrigida — a única que a regra crítica do `CLAUDE.md`
admite sobre ele —, e não foi submetido a ferramenta alguma.

```
python3 tools/caracteriza-pares.py --workdir <diretorio em disco, fora do repositorio>
```

| Arquivo | Conteúdo |
|---|---|
| `pares.csv` | uma linha por CVE, 223 |
| `pares.txt` | contagens e listas nominais; traz o sha256 do CSV da mesma execução |
| `../../datasets/postpatch-expansoes.csv` | os `PostPatchCommit` malformados, com as quatro condições da expansão |
| `../../logs/pares/caracterizacao-pares.csv` | log por CVE, no molde dos da campanha |
| `../../logs/pares/clones.csv` | um por repositório: modo do clone, código de retorno, duração, tamanho |

## As duas colunas de linha são descrição, não critério

`gt_linhas_em_trecho_alterado` e `gt_linhas_deslocadas` **não** decidem onde
fica o ponto da falha na versão corrigida. Essa decisão é da §8 do
`docs/criterios-cruzamento.md`, e não foi tomada. O cálculo simples por
deslocamento está aqui para **informar** essa decisão:

- `gt_linhas_em_trecho_alterado`: por linha do ground truth, `sim` se ela cai
  num trecho removido ou modificado do lado `pre` do
  `git diff -U0 -M pre post -- <arquivo>`, `nao` caso contrário; separadas por
  `|`, na ordem de `gt_linhas`.
- `gt_linhas_deslocadas`: para cada linha **não** alterada, o número dela no
  `post`, somando o saldo (linhas acrescidas − removidas) dos trechos que
  terminam antes dela. **Posicional**, alinhada a `gt_linhas`: a posição de
  uma linha alterada fica vazia (`5|` = primeira linha deslocada para 5,
  segunda alterada).

Uma linha `nao` com número deslocado significa que o texto daquela linha
sobreviveu à correção sem mudança — não que a correção deixou de tocar o
defeito, que pode ter sido corrigido noutra linha do mesmo arquivo ou noutro
arquivo.

## Pontos na versão corrigida — também descrição

Duas colunas acrescentadas em 28/09/2026, **depois** das existentes, que não
mudaram. Alinhadas a `gt_linhas`, separadas por `|`. Informam a §8, que decide
como usá-las; não são critério.

O bloco vem do cabeçalho `@@ -a,b +c,d @@` do mesmo diff `-U0`: lado `pre` de
`a` a `a+b-1`, lado `post` de `c` a `c+d-1`; contagem omitida vale 1.

| `gt_tipo_ponto` | quando | `gt_ponto_post` |
|---|---|---|
| `inalterada` | a linha não cai em bloco com `b ≥ 1` | o número dela no `post` (igual a `gt_linhas_deslocadas`) |
| `trecho` | cai em bloco com `b ≥ 1` e `d ≥ 1` | `inicio-fim` do lado `post` desse bloco |
| `so_remocao` | cai em bloco com `d = 0` | `del:N`, com `N = c + 1`: no git, `+c,0` quer dizer que as linhas saíram **depois** da linha `c` do `post` |

Se `c + 1` passa do fim do arquivo no `post`, `N` é a última linha e a marca é
`del:N:fim`. Arquivo ausente do `post` tem zero linhas, e sai `del:0:fim`
(nenhum caso nos 223: nenhum arquivo do ground truth foi removido).

O `pares.txt` traz as contagens por tipo (por linha e por CVE), o tamanho dos
trechos (`fim - inicio + 1`) em faixas, os dez maiores trechos com os dois
intervalos, e a lista nominal dos `so_remocao`.

## Como cada coluna é obtida

- **Clone por repositório**, 186, e não por CVE:
  `git clone --filter=blob:none --no-checkout --no-single-branch`, anônimo
  (configuração global e de sistema em `/dev/null`, `credential.helper` vazio),
  limite de 900 s. Servidor que ignora o filtro só avisa, e o clone sai
  completo: registrado em `clones.csv` como `completo_filtro_ignorado`.
  Parcial recusado sem estouro tem uma tentativa de clone completo.
- **Existência** (`pre_existe`, `post_existe`): o objeto está no clone, ou é
  obtido por fetch por SHA (limite 300 s). `upload-pack: not our ref` → `nao`;
  estouro ou outra falha → `indeterminado`.
- **`post_tipo`** por `git cat-file -t`. Um objeto de tag é descascado até o
  commit para as colunas seguintes, e o log o diz.
- **`relacao`** por `git merge-base --is-ancestor`, nos dois sentidos;
  **`distancia`** por `git rev-list --count pre..post`, só quando o `post`
  descende do `pre`; **`pre_e_pai_de_post`** pelos pais do `post`.
- **`arquivos_alterados`**: `git diff --name-status --no-renames pre post`, contando as entradas.
  Renomeação conta como dois (remoção e acréscimo): a contagem é sobre
  árvores, sem buscar conteúdo.
- **`gt_arquivo_no_post`**: `presente` se o caminho existe no `post`; senão,
  detecção de renomeação (`-M`, similaridade padrão de 50%) entre o caminho do
  ground truth e os arquivos acrescentados → `renomeado:<novo caminho>`; senão
  `removido`. **`gt_arquivo_alterado`**: o blob difere entre `pre` e `post`
  (no novo caminho, se renomeado).
- **`gt_arquivo_no_pre`**: coluna a mais que o pedido — sem ela, arquivo do
  ground truth ausente do próprio `pre` apareceria como vazio sem causa.
- Caminho e linhas do ground truth vêm de `normalize.carregar_lista()`
  (o `/index.js` do `CVE-2019-12041` sai `index.js`), e o `cve-metadata.csv`
  é conferido contra eles CVE a CVE.

Toda inspeção local roda com `GIT_NO_LAZY_FETCH=1`: só os diffs que precisam
de conteúdo buscam blobs, e sob limite.

## Determinismo

A classificação é determinística: mesma entrada, mesmo código e mesmo estado
dos repositórios remotos dão o mesmo `pares.csv`, fora `duracao_segundos`, e o
mesmo `pares.txt` byte a byte. **O estado dos remotos não é fixo** — ramo
removido, repositório apagado ou força-empurrado mudam existência e relação —,
e por isso a execução é observação datada, como a sondagem.
