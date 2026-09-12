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
  (5) vocabulário da obtenção do código → CONTAGEM, não conferência

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

A (5) é métrica, não conferência: conta quantos CVEs caíram no fallback de
clone completo e discrimina a causa. O protocolo a exige como métrica própria
— "elevação súbita indica mudança no servidor ou degradação do conjunto" —, e
ela é o que sustenta manter o lote em 30 apoiado no comportamento medido em
vez do pior caso, que não cabe no teto de 6 h do job. Nada dela entra na
conta de problemas nem muda o código de saída.

Nenhuma conferência precisa do commit. A coluna `mensagem` é parseada apenas
pela (5).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
EXTENSAO_RAW = {"codeql": ".sarif", "semgrep": ".json", "snyk-code": ".sarif"}

CABECALHO = "cve,repo,commit,status,mensagem,duracao_segundos"

# --------------------------------------------------------------------------
# Vocabulário da obtenção do código, DECLARADO
# --------------------------------------------------------------------------
# A mensagem do log é uma junção por "; ": o registrar() prefixa a versão da
# ferramenta e o laço acumula em MENSAGEM. O SEGMENTO é, portanto, a unidade
# do formato, e é nele que o casamento se dá.
#
# Casar por prefixo da MENSAGEM não casaria nada — o prefixo é a versão da
# ferramenta. Casar por subcadeia solta casaria trecho de outro segmento. A
# regra do projeto vale aqui como vale para contagem de regras: parser do
# formato, nunca regex sobre prosa.
#
# Os literais abaixo são os dos scripts de análise.
SEG_FALLBACK = "fallback de clone completo"
# A redação ANTERIOR à Fase G-1b tinha DUAS formas, não uma:
#   (A) clone deu certo  -> MENSAGEM="fallback de clone completo", SOZINHO
#   (B) clone falhou     -> "fetch raso e clone completo falharam"
# A forma (A) é BYTE-IDÊNTICA ao rótulo da redação nova, e só se distingue
# dela pela AUSÊNCIA do segmento de causa. Por isso ela não tem constante
# própria: é identificada adiante, por `fallback sem causa`, estado que a
# redação nova torna inalcançável — lá o rótulo sempre vem seguido de
# MOTIVO_FETCH, e os dois caminhos que perdem o motivo são forçados a
# "indeterminada". Sem essa inferência a forma (A) sairia atribuída a
# "novo" por suposição e cairia fora dos três baldes de causa, fazendo a
# soma das causas ser menor que o total sem uma palavra de explicação.
SEG_VOCAB_ANTIGO = "fetch raso e clone completo falharam"
PRE_FETCH_ESTOURO = "fetch raso excedeu "
PRE_FETCH_OUTRO = "fetch raso saiu com "
PRE_CLONE_ESTOURO = "clone completo excedeu "
PRE_CLONE_OUTRO = "clone completo saiu com "
# Dois caminhos do ramo de contingência que registram mensagem literal e
# descartam MENSAGEM: o log diz que o fallback ocorreu, mas não carrega o
# motivo do fetch. São declarados para não saírem como "nao reconhecida".
PRE_CLONE_SEM_DIR = "clone completo nao produziu "
SEG_SEM_TMP = "nao foi possivel voltar para /tmp"


# Marcas de forma do vocabulário de obtenção, DECLARADAS em vez de
# derivadas dos literais acima: derivá-las (por exemplo de
# SEG_FALLBACK.split()[0]) faria o escopo do pré-filtro mudar sozinho
# quando alguém reescrevesse a prosa de uma constante.
#
# ALCANCE DA REDE, declarado: ela pega a divergência de um segmento que
# conserve alguma destas marcas. Reescrita que as perca inteiras — do
# literal de "/tmp", por exemplo — deixa de casar E de ser reportada. A
# garantia é de forma, não de identidade.
MARCAS_OBTENCAO = ("fallback", "fetch raso", "clone completo", "voltar para /tmp")


def _parece_obtencao(segmento):
    """Pré-filtro do que DEVERIA ter casado o vocabulário e não casou."""
    return any(marca in segmento for marca in MARCAS_OBTENCAO)


def classificar_obtencao(mensagem):
    """Classifica a mensagem de UM CVE quanto à obtenção do código.

    Devolve dict com:
      fallback        — o ramo de contingência foi tomado
      vocabulario     — "novo", "antigo" ou None
      causa_fetch     — "estouro", "outro", "indeterminada" ou None
      clone_falhou    — "estouro", "outro", "indeterminada" ou None
      nao_reconhecidos— segmentos que pareciam de obtenção e não casaram
    """
    r = {"fallback": False, "vocabulario": None, "causa_fetch": None,
         "clone_falhou": None, "nao_reconhecidos": []}
    for bruto in mensagem.split(";"):
        seg = bruto.strip()
        if not seg:
            continue
        if seg == SEG_FALLBACK:
            r["fallback"] = True
            r["vocabulario"] = "novo"
        elif seg == SEG_VOCAB_ANTIGO:
            r["fallback"] = True
            r["vocabulario"] = "antigo"
            r["causa_fetch"] = "indeterminada"
            r["clone_falhou"] = "indeterminada"
        # Os quatro segmentos abaixo só são escritos DENTRO do ramo de
        # contingência (MOTIVO_FETCH e MOTIVO_CLONE só existem lá), logo
        # cada um deles implica que o fallback ocorreu. Sem isto o total
        # perderia o caso em que o clone também falhou: essa linha registra
        # "clone completo ...; fetch raso ..." e NÃO repete o segmento
        # "fallback de clone completo", porque ali o registrar() recebe
        # mensagem própria em vez de acumular MENSAGEM.
        elif seg.startswith(PRE_FETCH_ESTOURO):
            r["fallback"] = True
            r["vocabulario"] = r["vocabulario"] or "novo"
            r["causa_fetch"] = "estouro"
        elif seg.startswith(PRE_FETCH_OUTRO):
            r["fallback"] = True
            r["vocabulario"] = r["vocabulario"] or "novo"
            r["causa_fetch"] = "outro"
        elif seg.startswith(PRE_CLONE_ESTOURO):
            r["fallback"] = True
            r["vocabulario"] = r["vocabulario"] or "novo"
            r["clone_falhou"] = "estouro"
        elif seg.startswith(PRE_CLONE_OUTRO):
            r["fallback"] = True
            r["vocabulario"] = r["vocabulario"] or "novo"
            r["clone_falhou"] = "outro"
        elif seg.startswith(PRE_CLONE_SEM_DIR) or seg == SEG_SEM_TMP:
            # O fallback ocorreu e o log não carrega o motivo do fetch.
            r["fallback"] = True
            if r["vocabulario"] is None:
                r["vocabulario"] = "novo"
            if r["causa_fetch"] is None:
                r["causa_fetch"] = "indeterminada"
        elif _parece_obtencao(seg):
            r["nao_reconhecidos"].append(seg)
    # Fallback SEM causa só é produzível pela forma (A) do vocabulário
    # antigo. Atribuí-la a "novo" seria afirmar que a linha veio da redação
    # que discrimina causa, e ela não veio; deixá-la sem causa a faria sumir
    # dos três baldes, que é subtração silenciosa numa métrica de
    # vigilância.
    if r["fallback"] and r["causa_fetch"] is None:
        r["vocabulario"] = "antigo"
        r["causa_fetch"] = "indeterminada"
    return r


STATUS_SUCESSO = {"OK", "SEM_ACHADOS"}
STATUS_ERRO = {"ERRO_LINHA", "ERRO_FETCH", "ERRO_CHECKOUT", "ERRO_ANALISE"}
STATUS_CONHECIDOS = STATUS_SUCESSO | STATUS_ERRO | {"PULADO", "SEM_ARQUIVO_ANALISAVEL"}


def ler_log(caminho):
    """Devolve (ultimo_status, ultima_mensagem, contagem_linhas, desconhecidos).

    Lido com split(',') e não com csv: a invariante do projeto é que nenhum
    campo contenha vírgula, e o registrar() do script de análise troca vírgula
    por ponto-e-vírgula antes de gravar. Um parser que aceitasse aspas
    mascararia a violação.
    """
    ultimo = {}
    # Dicionário SEPARADO em vez de tupla dentro de `ultimo`: assim as
    # conferências (1) a (4) seguem lendo cve -> status como sempre leram, e
    # a adição não pode alterar o que já havia.
    mensagens = {}
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
            # A mensagem é reconstruída em vez de lida como partes[4]: se uma
            # vírgula escapar da raspagem do registrar(), partes[4] traria só
            # o pedaço ANTERIOR a ela, e um segmento de fallback vindo depois
            # sumiria — a contagem daria zero por não ter perguntado, que é o
            # defeito que a (5) existe para não cometer.
            if len(partes) >= 6:
                mensagens[cve] = ",".join(partes[4:-1])
            elif len(partes) == 5:
                mensagens[cve] = partes[4]
            else:
                mensagens[cve] = ""
            if status not in STATUS_CONHECIDOS:
                desconhecidos.append({"linha": numero, "cve": cve, "status": status})
            # A ÚLTIMA linha de cada CVE é a que vale.
            ultimo[cve] = status
    return ultimo, mensagens, linhas, desconhecidos


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

    ultimo, mensagens, total_linhas, desconhecidos = ler_log(log)

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

    # --- (5) vocabulario da obtencao do codigo: CONTA e REPORTA, nao julga.
    # Opera sobre o resultado da DEDUPLICACAO, como as demais: a ultima linha
    # de cada CVE e a que vale, e uma reexecucao nao pode inflar a contagem.
    obtencao = {}
    for cve in ultimo:
        r = classificar_obtencao(mensagens.get(cve, ""))
        if r["fallback"] or r["clone_falhou"] or r["nao_reconhecidos"]:
            obtencao[cve] = r
    fallback_cves = sorted(c for c, r in obtencao.items() if r["fallback"])
    vocab = {"novo": 0, "antigo": 0}
    causa_fetch = {"estouro": 0, "outro": 0, "indeterminada": 0}
    causa_clone = {"estouro": 0, "outro": 0, "indeterminada": 0}
    for cve in fallback_cves:
        r = obtencao[cve]
        if r["vocabulario"] in vocab:
            vocab[r["vocabulario"]] += 1
        if r["causa_fetch"] in causa_fetch:
            causa_fetch[r["causa_fetch"]] += 1
    clone_falhou_cves = sorted(c for c, r in obtencao.items() if r["clone_falhou"])
    for cve in clone_falhou_cves:
        r = obtencao[cve]
        if r["clone_falhou"] in causa_clone:
            causa_clone[r["clone_falhou"]] += 1
    nao_reconhecidos = sorted(
        (cve, seg) for cve, r in obtencao.items() for seg in r["nao_reconhecidos"])

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

    print()
    print("  (5) obtencao do codigo — METRICA, nao conferencia")
    pulados = contagem.get("PULADO", 0)
    print("      base: %d CVEs apos deduplicacao (a ultima linha de cada um)"
          % len(ultimo))
    if pulados:
        # A deduplicacao nao infla a metrica — e DEFLACIONA. A reexecucao
        # grava PULADO, a ultima linha vence, e o CVE que usou fallback passa
        # a contar zero. Para metrica de vigilancia a direcao perigosa e
        # essa, e o numero abaixo e piso, nao valor.
        print("      ATENCAO: %d CVEs tem PULADO como ultimo status. A linha de "
              "fallback deles foi substituida pela da reexecucao, logo as "
              "contagens abaixo sao PISO." % pulados)
    print("      fallback de clone completo: %d" % len(fallback_cves))
    print("        por vocabulario:  novo %d | antigo %d  (o antigo e a redacao "
          "anterior a G-1b e NAO discrimina causa)"
          % (vocab["novo"], vocab["antigo"]))
    print("        causa do fetch:   estouro do limite %d | outro codigo %d | "
          "indeterminada %d"
          % (causa_fetch["estouro"], causa_fetch["outro"],
             causa_fetch["indeterminada"]))
    print("      clone de contingencia tambem falhou: %d" % len(clone_falhou_cves))
    print("        causa do clone:   estouro do limite %d | outro codigo %d | "
          "indeterminada %d"
          % (causa_clone["estouro"], causa_clone["outro"],
             causa_clone["indeterminada"]))
    soma_causas = sum(causa_fetch.values())
    if soma_causas != len(fallback_cves):
        # Identidade aritmetica declarada e CONFERIDA: todo CVE em fallback
        # tem exatamente uma causa de fetch. Divergencia significa que ha
        # forma de mensagem que a classificacao nao atribuiu a balde algum —
        # subtracao silenciosa, que e o defeito que esta conferencia existe
        # para nao cometer.
        print("      INCOERENTE: as causas somam %d contra %d CVEs em "
              "fallback. Ha forma de mensagem sem balde." 
              % (soma_causas, len(fallback_cves)))
    for cve in fallback_cves:
        r = obtencao[cve]
        print("        %s  [%s]  vocabulario=%s fetch=%s clone=%s"
              % (cve, ultimo.get(cve, "?"), r["vocabulario"],
                 r["causa_fetch"], r["clone_falhou"]))
    if nao_reconhecidos:
        # Silenciar o que nao casou reproduziria o defeito que a (5) existe
        # para nao cometer: o contador diria zero por nao ter perguntado.
        print("      NAO RECONHECIDO: segmentos com cara de obtencao que nao "
              "casaram o vocabulario declarado: %d" % len(nao_reconhecidos))
        for cve, seg in nao_reconhecidos[:20]:
            print("        %s  %r" % (cve, seg))


    problemas = (erro_com_raw or sucesso_sem_raw or sem_arquivo_com_raw
                 or raws_sem_linha or pulado_sem_raw or sumidos or desconhecidos)
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
