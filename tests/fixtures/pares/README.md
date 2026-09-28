# Fixtures de `tools/caracteriza-pares.py`

Não há repositório versionado aqui: `repo_sintetico.py` **constrói** um
repositório git pequeno num diretório temporário, a cada execução da suíte, e
devolve o valor esperado de cada coluna por caso. Datas e identidade são fixas;
nenhum valor esperado depende de SHA literal — os SHA são lidos do repositório
construído, pelo nome do commit.

```
python3 tests/run-fixtures.py     # seção "caracteriza-pares.py"
```

É o controle positivo da classificação: todo `sim`, `nao` e zero do conjunto
real só vale se o mesmo código acertou o caso conhecido.

## Casos

| CVE da fixture | Caso |
|---|---|
| `CVE-2099-0001` | `post` filho direto de `pre`, alterando a linha do ground truth |
| `CVE-2099-0002` | `post` a três commits de `pre` |
| `CVE-2099-0003` | `post` sem relação com `pre` (outro ramo) |
| `CVE-2018-1000096` | `post` igual a `pre`; id real, para exercitar `fora_do_denominador` |
| `CVE-2099-0005` | arquivo removido no `post` |
| `CVE-2099-0006` | arquivo renomeado (`-M`), com a linha do ground truth deslocada por inserção no topo |
| `CVE-2099-0007` | correção que não toca o arquivo do ground truth |
| `CVE-2099-0008` | duas linhas: uma fora de trecho alterado, deslocada +3 por inserção acima; outra alterada |
| `CVE-2099-0009` | objeto de **tag anotada** no lugar do `post` |
| `CVE-2099-0010` | prefixo **ambíguo** de 1 caractere, comum a dois commits (garantido por casa dos pombos: 20 commits vazios num ramo de enchimento) |
| `CVE-2099-0011` | prefixo único de commit que **não** descende de `pre` (c3 falsa) |
| `CVE-2099-0012` | prefixo único que expande — as quatro condições verdadeiras |
| `CVE-2099-0013` | prefixo de descendente que não altera o arquivo do ground truth (c4 falsa) |
| `CVE-2099-0014` | prefixo de objeto de tag (c2 falsa) |
| `CVE-2099-0015` | `pre` descende de `post` |
| `CVE-2099-0016` | `post` inexistente: `upload-pack: not our ref` → `post_existe = nao` |
| `CVE-2099-0017` | `pre` inexistente |
| `CVE-2099-0018` | `post` só em `refs/pull/1/head`, fora de todo ramo: obtido por fetch por SHA |
| `CVE-2099-0019` | arquivo do ground truth ausente do `pre` |
| `CVE-2099-0020` | servidor que **ignora** o filtro (cópia nua sem `uploadpack.allowFilter`): clone registrado como completo, classificação igual à do caso 1 |
| `CVE-2099-0021` | repositório inexistente: parcial e completo recusados |
| `CVE-2099-0022` | repositório inexistente com `post` malformado: linha de expansão com as quatro condições não avaliadas |
| `CVE-2099-0023` | prefixo que passaria c1–c3 com o arquivo do ground truth ausente do `pre`: c4 falsa (sem a guarda, `alterado` saía verdadeiro por comparação contra nada) |
| `CVE-2099-0025` | modificação 1 → 1 em `m.js`: `trecho`, `5-5` |
| `CVE-2099-0026` | modificação 1 → 3: `trecho`, `8-10` |
| `CVE-2099-0027` | bloco de 3 linhas `pre` trocado por 4 `post`, com o gt no meio (`trecho`, `12-15`), e uma linha inalterada acima (`inalterada`, `2`) |
| `CVE-2099-0028` | remoção pura no meio (`-5,2 +4,0`): `so_remocao`, `del:5` |
| `CVE-2099-0029` | remoção pura no fim (`-20,2 +19,0`, post com 19 linhas): `so_remocao`, `del:19:fim` |
| `CVE-2099-0024` | prefixo de commit que só entra no clone pelo fetch de **outro** CVE (o 0018, ordenado antes): c1 falsa, porque os candidatos são listados logo após o clone |

Além dos casos, a seção exercita, com `git` substituto (`--git`): estouro de
clone, por um substituto cujo `sleep 60` é **filho** do shell — só a morte do
grupo de processos o alcança; estouro de fetch por SHA (`indeterminado`, nunca
`nao`); erro de inspeção depois da expansão (o CVE sai `ERRO_INSPECAO`, a
expansão sobrevive, a execução segue); falha na listagem de objetos (o
malformado sai com linha não avaliada); recusa de clone que cita o destino
(o caminho do workdir é trocado por `<clone>`); SIGTERM no meio do clone
(sai 130, sem resto no workdir); divergência entre metadata e lista (parada); as guardas de caminho e de
limite; a releitura do CSV contra mutantes do arquivo gravado; o vocabulário;
as funções puras de trechos e deslocamento; e o determinismo entre duas
execuções.

O servidor da fixture aceita filtro e SHA alcançável fora de ramo
(`uploadpack.allowFilter`, `uploadpack.allowReachableSHA1InWant`), como o
GitHub. **Não exercitado:** servidor que *recusa* com erro o clone parcial e
aceita o completo — o ramo existe no código, mas não se conseguiu servidor
local que o produza; o caso 21 passa pelo mesmo caminho, com as duas
tentativas recusadas.
