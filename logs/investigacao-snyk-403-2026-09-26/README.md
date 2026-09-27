# Investigação do 403 do Snyk Code — 26/09/2026

Resumo, sem segredo, da investigação da mensagem `ERROR Forbidden
(SNYK-CLI-0000)`, HTTP 403, que encerrou todo teste do Snyk Code **com
achados** na campanha de detecção de 16 e 17/09/2026 (133 de 133), e nenhum
dos 83 sem achados.

**Resultado:** a recusa incide sobre uma única requisição — a leitura do nome
curto da organização (`GET /rest/orgs/<org>`), feita antes da análise. Envio
do código, análise e obtenção dos resultados respondem normalmente, o código
de saída não muda, e os achados são idênticos, campo a campo, aos da campanha.

## Orçamento

Quatro invocações de `snyk code test` (T1 a T4), de um máximo de seis fixado
antes. As outras duas não foram usadas. A calibração da depuração usou cinco
invocações de `snyk whoami --experimental`, que é consulta de conta e não
teste de código.

## Imagem

A da campanha, pelo digest vigente:

```
ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:cdde5e9c6e5777c91052d8e438075337e26c7754dd526bcb51bb6d86c05a78d7
```

CLI 1.1306.1.

## CVEs

Escolhidos nos logs versionados da campanha, entre os de repositório pequeno e
análise rápida:

- T1 e T2: `CVE-2017-16084` (`OK`, 5 achados, lote `aa`);
- T3: `CVE-2017-16023` (`SEM_ACHADOS`, lote `aa`);
- T4: `CVE-2018-20835` (`OK`, 8 achados, lote `ac`).

O `container/lote.txt` versionado da campanha traz o 403 nos dois primeiros e
não no terceiro.

## Comandos

Cada invocação em workspace próprio, fora de `results/` e de `logs/`, com uma
lista de um CVE e o descritor do CLI. O token entra por arquivo de variáveis
de ambiente, nunca pela linha de comando.

T2, T3 e T4, pelo próprio `run_snyk-code.sh` da imagem, com a invocação da
campanha:

```
docker run --rm --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e XDG_CACHE_HOME=/tmp -e TIMEOUT_ANALISE=900 \
    --env-file <arquivo-de-credencial> \
    -v "<workspace>":/workspace \
    ghcr.io/francisco-lima-dev/ic-security-lab-snyk-code@sha256:cdde5e9c… \
    datasets/listas/<lista-de-um-cve>
```

T1, pela opção (a): a mesma imagem, `--user`, `HOME`, `XDG_CACHE_HOME` e
arquivo de credencial; o commit obtido por fetch raso e conferido por
`git rev-parse HEAD`, como no script; e a chamada do script acrescida de `-d`,
fora dele:

```
timeout 900 snyk code test --sarif-file-output=<saida>.sarif -d < /dev/null
```

## Calibração da depuração

O script chama o Snyk com argumentos fixos, e a investigação não podia
alterá-lo. Procurou-se, por isso, variável de ambiente que ligasse a
depuração, com `snyk whoami --experimental`, que faz requisições de rede sem
consumir teste:

| Execução | Linhas de saída |
|---|---:|
| `-d` | 109, com registro de cada requisição HTTP |
| `SNYK_LOG_LEVEL=debug` | 1 |
| `SNYK_LOG_LEVEL=trace` | 1 |
| `DEBUG=1` | 1 |
| nenhuma | 1 |

**O `-d` reproduz o registro HTTP; nenhuma variável de ambiente reproduz.** A
T1 foi, por isso, pela opção (a).

## Arquivos

- `invocacoes.csv` — uma linha por invocação. `codigo_cli` é o código do
  `snyk`; `codigo_container`, o do `docker run`, que nas T2 a T4 é o do
  script ao fim do lote (o código do `snyk` vai para o log, não é
  propagado). `duracao_container_segundos` é o relógio do hospedeiro em torno
  do `docker run`; o log do script registrou 14, 11 e 11 s nas T2, T3 e T4.
- `requisicoes-T1.txt` — as 20 respostas HTTP da T1, em ordem: método, host,
  caminho e status. O identificador da organização está substituído por
  `<org>`, o do teste por `<teste>` e o do documento de resultados por
  `<documento>`; o hash do pacote de código fica. Sem cabeçalhos e sem corpo.
- `comparacao.csv` — T1, T2 e T4 normalizados pelo `tools/normalize.py` e
  comparados, achado a achado e em todos os campos, com o tratado versionado
  do mesmo CVE. Divergência só em `analysis_date`.

## O que NÃO está aqui

**A saída de depuração, bruta ou mascarada, não entra no repositório.** Ela
contém cabeçalhos de autenticação e identificadores da conta. A bruta foi
apagada logo depois de conferida quanto ao token; a mascarada ficou só fora da
árvore do projeto. Os SARIF e os tratados das quatro invocações também não
entram: a comparação com a campanha está em `comparacao.csv`.

## Varredura antes da gravação

**A varredura do token é parcial.** O arquivo de credencial já tinha sido
apagado quando os quatro arquivos foram gravados, e o valor do token não pôde
ser procurado neles. O que a sustenta: as fontes de onde os arquivos saíram —
as saídas mascaradas das invocações e a comparação com os tratados — tinham
zero ocorrências do token, completo e nos 12 primeiros caracteres, quando
conferidas durante a investigação; e os arquivos não contêm cabeçalhos nem
corpo de resposta.

As varreduras do identificador da organização, do identificador do teste e
do identificador do documento de resultados (completos e os 8 primeiros
caracteres de cada), do nome de usuário da conta e de endereços de e-mail rodaram
normalmente sobre os quatro arquivos, com zero ocorrências, e com controle
positivo: um arquivo com os três identificadores foi acusado, completos e
pelo prefixo.
