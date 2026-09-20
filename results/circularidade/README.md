# Apuração da circularidade da proveniência

Saída de `tools/circularidade-proveniencia.py`. Versionada ao lado de
`results/cruzamento/` e `results/proveniencia/`, e pela mesma razão: sustenta
uma ameaça à validade que vai ao texto.

**Gerada em 20/09/2026.**

## Como foi produzida

```bash
O=results/proveniencia
python3 tools/circularidade-proveniencia.py $O/cotejo-ref.json $O/cotejo-sens.json \
    --json results/circularidade/circularidade.json \
    > results/circularidade/circularidade.txt
```

Entradas, todas versionadas: `results/cruzamento/matriz-deteccao.csv` e os
dois relatórios do cotejo. O script **não recomputa** nem o cruzamento nem o
critério de casamento da proveniência — consome `por_relacao` e `sem_casar` do
relatório do cotejo, e lê a matriz.

O JSON grava o sha256 da matriz e o de cada relatório de proveniência.
O script **recusa** gravar aqui se alguma entrada estiver fora do repositório,
porque o caminho da máquina do operador iria para o JSON.

## Determinismo

Mesmos bytes em reexecução, conferido com três `PYTHONHASHSEED` distintos.
Sem carimbo de execução; `git diff --exit-code results/circularidade/`
denuncia saída desatualizada.

## O que a apuração faz

Parte o denominador de 220 pares em dois grupos pela proveniência da etiqueta
e compara a taxa de acerto das três ferramentas em cada grupo, nos sete
níveis. Emite numerador e denominador em toda taxa. **Não conclui, não aplica
teste estatístico e não calcula precisão.** Os números estão no `CLAUDE.md`,
seção "Circularidade da proveniência"; a leitura é do texto da monografia.

## Ressalva do método, que vale para todo uso destes números

**A partição é por `explanation`, não pela etiqueta de CWE**, e os níveis 2 e
4 usam o conjunto de CWEs. Na referência as duas coincidem — 163 casados, 163
`identico` —, mas **a recíproca não vale**: CVE de explanation em prosa pode
carregar conjunto de CWEs igual ao de uma consulta. O `CVE-2019-10745` é o
caso exemplar, e o próprio relatório conta o fenômeno.

## Validação que precede qualquer número

Partição disjunta, cobrindo os 223, somando exatamente 220 com as três
exclusões nominadas; as duas fontes de `gt_cwes` — matriz e cotejo —
reconciliadas por CVE; autoteste do caminho de contagem, com mutação de zero
para um, antes de tocar o conjunto real. Falhando qualquer uma, o script sai
com código não nulo e **nenhum número vai ao stdout**.
