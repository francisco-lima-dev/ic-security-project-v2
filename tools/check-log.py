#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check-log.py — confere a coerência entre o log de execução e a saída bruta.

    python3 tools/check-log.py --tool {codeql|semgrep|snyk-code} \
        [--log ARQ] [--raw-dir DIR] [--lista-lote ARQ]

INDEPENDENTE DO NORMALIZADOR, por desenho: nenhum dos dois importa, lê ou
invoca o outro. A separação entre coleta e normalização existe para que a
etapa barata (normalize.py) não herde as dependências da cara; as
conferências que PRECISAM do log vivem aqui, e só aqui.

Lê logs/execution-log-<ferramenta>.csv e results/<tool>/raw/.

DEDUPLICAÇÃO
------------
Reexecução acrescenta uma linha PULADO por CVE já feito, e o log não tem
timestamp nem id de execução: a última linha de cada CVE é a que vale. A
deduplicação é por ordem de arquivo, que é ordem de escrita (append).

AS CONFERÊNCIAS
--------------
  (1) raw existe e o status da última linha é de erro
  (2) status OK ou SEM_ACHADOS e não existe raw
  (3) SEM_ARQUIVO_ANALISAVEL sem raw → ESPERADO, apenas contado
  (4) CVE do lote sem raw E sem linha de log  → só com --lista-lote

A (3) não é falha: é o exit 3 do Snyk Code, "nenhum projeto suportado", que
é resultado e não erro. Por construção não há raw que o sinalize — fabricar
um SARIF que a ferramenta não emitiu seria pior.

A (4) é a assinatura observável do defeito do fd 0: com `done < "$LISTA"` a
lista fica no stdin do laço, um filho que leia stdin engole linhas do lote, e
os CVEs somem SEM linha de log — não há erro, não há raw, não há registro. É
por não produzir sinal algum que esse defeito está no "o que NÃO fazer" do
CLAUDE.md, e é por isso que só uma conferência de fora o alcança.

`--lista-lote` exige a lista **do lote executado**, jamais a lista completa:
contra a completa, todo CVE de lote ainda não rodado apareceria como ausente
e a conferência viraria ruído. Por isso o nome difere do `--lista` do
normalizador, que tem a semântica oposta (lá é a lista completa, de onde vêm
os campos de ground truth). Mesmo nome com semânticas opostas nos dois
programas seria confusão garantida.

Nenhuma das conferências precisa do commit, então a coluna `mensagem` não é
parseada.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
EXTENSAO_RAW = {"codeql": ".sarif", "semgrep": ".json", "snyk-code": ".sarif"}

CABECALHO = "cve,repo,commit,status,mensagem,duracao_segundos"

STATUS_SUCESSO = {"OK", "SEM_ACHADOS"}
STATUS_ERRO = {"ERRO_LINHA", "ERRO_FETCH", "ERRO_CHECKOUT", "ERRO_ANALISE"}
STATUS_CONHECIDOS = STATUS_SUCESSO | STATUS_ERRO | {"PULADO", "SEM_ARQUIVO_ANALISAVEL"}


def ler_log(caminho):
    """Devolve (ultimo_status_por_cve, contagem_de_linhas, status_desconhecidos).

    Lido com split(',') e não com csv: a invariante do projeto é que nenhum
    campo contenha vírgula, e o registrar() do script de análise troca vírgula
    por ponto-e-vírgula antes de gravar. Um parser que aceitasse aspas
    mascararia a violação.
    """
    ultimo = {}
    linhas = 0
    desconhecidos = []
    with open(caminho, encoding="utf-8") as arquivo:
        for numero, linha in enumerate(arquivo, 1):
            linha = linha.rstrip("\n").rstrip("\r")
            if not linha.strip():
                continue
            if linha == CABECALHO:
                continue
            partes = linha.split(",")
            if len(partes) < 4:
                desconhecidos.append({"linha": numero, "conteudo": linha[:200],
                                      "motivo": "menos de 4 campos"})
                continue
            cve, _repo, _commit, status = partes[0], partes[1], partes[2], partes[3]
            linhas += 1
            if status not in STATUS_CONHECIDOS:
                desconhecidos.append({"linha": numero, "cve": cve, "status": status})
            # A ÚLTIMA linha de cada CVE é a que vale.
            ultimo[cve] = status
    return ultimo, linhas, desconhecidos


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Confere a coerência entre o log de execução e a saída bruta."
    )
    analisador.add_argument("--tool", required=True, choices=list(FERRAMENTAS))
    analisador.add_argument("--log", help="padrão: logs/execution-log-<tool>.csv")
    analisador.add_argument("--raw-dir", help="padrão: results/<tool>/raw/")
    analisador.add_argument(
        "--lista-lote",
        help="lista DO LOTE EXECUTADO (nunca a completa), habilitando a "
             "conferência (4): CVE do lote sem raw e sem linha de log")
    args = analisador.parse_args(argv)

    ferramenta = args.tool
    log = Path(args.log) if args.log else RAIZ / "logs" / ("execution-log-%s.csv" % ferramenta)
    raw_dir = Path(args.raw_dir) if args.raw_dir else RAIZ / "results" / ferramenta / "raw"

    if not log.is_file():
        print("ERRO: log de execucao ausente: %s" % log, file=sys.stderr)
        print("  Sem o log nao ha o que conferir. O lote chegou a rodar?", file=sys.stderr)
        return 2
    if not raw_dir.is_dir():
        print("ERRO: diretorio de raw ausente: %s" % raw_dir, file=sys.stderr)
        return 2

    ultimo, total_linhas, desconhecidos = ler_log(log)

    extensao = EXTENSAO_RAW[ferramenta]
    raws = {p.stem for p in raw_dir.iterdir() if p.is_file() and p.name.endswith(extensao)}

    erro_com_raw = sorted(
        cve for cve, status in ultimo.items() if status in STATUS_ERRO and cve in raws
    )
    sucesso_sem_raw = sorted(
        cve for cve, status in ultimo.items() if status in STATUS_SUCESSO and cve not in raws
    )
    sem_arquivo_analisavel = sorted(
        cve for cve, status in ultimo.items()
        if status == "SEM_ARQUIVO_ANALISAVEL" and cve not in raws
    )
    # Este é anômalo e vale reportar: SEM_ARQUIVO_ANALISAVEL COM raw não
    # deveria existir — o script remove a saída parcial antes de registrá-lo.
    sem_arquivo_com_raw = sorted(
        cve for cve, status in ultimo.items()
        if status == "SEM_ARQUIVO_ANALISAVEL" and cve in raws
    )
    raws_sem_linha = sorted(raws - set(ultimo))
    # PULADO só é gravado PORQUE o raw existia. PULADO sem raw significa raw
    # sumido depois — apagado, artifact perdido, --raw-dir errado —, que é
    # precisamente a incoerência que este script existe para pegar.
    pulado_sem_raw = sorted(
        cve for cve, status in ultimo.items() if status == "PULADO" and cve not in raws
    )

    cves_do_lote = None
    if args.lista_lote:
        lote = Path(args.lista_lote)
        if not lote.is_file():
            print("ERRO: lista de lote ausente: %s" % lote, file=sys.stderr)
            return 2
        cves_do_lote = []
        with open(lote, encoding="utf-8") as arquivo:
            for numero, linha in enumerate(arquivo, 1):
                linha = linha.rstrip("\n").rstrip("\r")
                if not linha.strip() or linha.lstrip().startswith("#"):
                    continue
                cve = linha.split(",")[0].strip()
                if not cve:
                    print("ERRO: %s linha %d sem CVE" % (lote, numero), file=sys.stderr)
                    return 2
                cves_do_lote.append(cve)
        # Uma lista completa passada aqui por engano produziria dezenas de
        # "sumiu sem deixar rastro" que na verdade são lotes ainda não
        # rodados. O aviso é o único jeito de distinguir os dois casos.
        if len(cves_do_lote) > 60:
            print("AVISO: %s tem %d CVEs. --lista-lote espera a lista DO LOTE "
                  "executado, nao a completa; contra a completa a conferencia "
                  "(4) acusa todo lote ainda nao rodado."
                  % (lote, len(cves_do_lote)), file=sys.stderr)

    sumidos = []
    if cves_do_lote is not None:
        sumidos = sorted({c for c in cves_do_lote
                          if c not in raws and c not in ultimo})

    contagem = {}
    for status in ultimo.values():
        contagem[status] = contagem.get(status, 0) + 1

    print("--- coerencia log x raw: %s ---" % ferramenta)
    print("  log: %s" % log)
    print("  raw: %s" % raw_dir)
    print("  linhas no log: %d | CVEs distintos apos deduplicacao: %d | raws: %d"
          % (total_linhas, len(ultimo), len(raws)))
    print("  ultimo status por CVE: %s" % (dict(sorted(contagem.items())) or "{}"))
    print()
    print("  (1) raw existe e o ultimo status e de erro: %d" % len(erro_com_raw))
    for cve in erro_com_raw:
        print("        %s  [%s]" % (cve, ultimo[cve]))
    print("  (2) status OK/SEM_ACHADOS e nao existe raw: %d" % len(sucesso_sem_raw))
    for cve in sucesso_sem_raw:
        print("        %s  [%s]" % (cve, ultimo[cve]))
    print("  (3) SEM_ARQUIVO_ANALISAVEL sem raw: %d  (ESPERADO — resultado, nao falha)"
          % len(sem_arquivo_analisavel))
    if cves_do_lote is None:
        print("  (4) CVE do lote sem raw e sem linha de log: nao conferido "
              "(passe --lista-lote com a lista DO LOTE executado)")
    else:
        print("  (4) CVE do lote sem raw e sem linha de log: %d de %d"
              % (len(sumidos), len(cves_do_lote)))
        for cve in sumidos:
            print("        %s  <- sumiu sem deixar rastro" % cve)

    if pulado_sem_raw:
        print()
        print("  ANOMALO: PULADO sem raw: %d  (o raw existia quando o lote rodou)"
              % len(pulado_sem_raw))
        for cve in pulado_sem_raw:
            print("        %s" % cve)
    if sem_arquivo_com_raw:
        print()
        print("  ANOMALO: SEM_ARQUIVO_ANALISAVEL COM raw: %d" % len(sem_arquivo_com_raw))
        for cve in sem_arquivo_com_raw:
            print("        %s" % cve)
    if raws_sem_linha:
        print()
        print("  ANOMALO: raw sem linha alguma no log: %d" % len(raws_sem_linha))
        for cve in raws_sem_linha:
            print("        %s" % cve)
    if desconhecidos:
        print()
        print("  ANOMALO: linhas de log irreconheciveis ou com status fora do conjunto: %d"
              % len(desconhecidos))
        for item in desconhecidos[:20]:
            print("        %s" % item)

    problemas = (erro_com_raw or sucesso_sem_raw or sem_arquivo_com_raw
                 or raws_sem_linha or pulado_sem_raw or sumidos or desconhecidos)
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
