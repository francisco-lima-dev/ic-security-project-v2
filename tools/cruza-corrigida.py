#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cruza-corrigida.py — aplica a §11 do docs/criterios-cruzamento.md: o cruzamento
da versao corrigida (PostPatchCommit) com o ponto corrigido do ground truth.

    python3 tools/cruza-corrigida.py [--saida-dir DIR]

APLICA a §11; nao a altera nem a reinterpreta. Nenhuma saida traz leitura.

LEITURA PRINCIPAL — a matriz de quatro celulas, sobre 212 CVEs (os 220 do
denominador menos os 8 so_remocao), nos niveis 3, 4 generosa e 4 estrita:
  lado vulneravel  VP / FN, LIDOS de results/cruzamento/matriz-deteccao.csv,
                   nunca recomputados;
  lado corrigido   FP / VN / sem analise, apurados aqui sobre
                   results/corrigida/<ferramenta>/treated/, no ponto corrigido
                   de results/pares/pares.csv (gt_tipo_ponto, gt_ponto_post).
A variante estrita nao se aplica ao CVE de primario indefinido
(CVE-2018-16472), nos dois lados; a base da estrita o desconta.

O casamento e o do cruza-deteccao.py, importado: apurar_cve() com o
gt_file_lines trocado pelas linhas do ponto corrigido. Sobreposicao do
intervalo do achado com qualquer linha do ponto e o mesmo que sobreposicao com
o intervalo inicio-fim do trecho, porque o ponto e um conjunto de inteiros.
Nenhum criterio de casamento, de CWE ou de leitura de tratado e reimplementado.

SEM ANALISE — status final no log da campanha corrigida diferente de OK e de
SEM_ACHADOS, ou tratado ausente. Nao e VN nem FP; a especificidade e VN sobre a
base, com a categoria ao lado. Vale a ultima linha de cada CVE, lida pelo
ler_log() do check-log.py, com os logs em ordem cronologica de execucao: os
oito lotes e, depois, o redisparo.

SENSIBILIDADE — a mesma apuracao sobre os 220, com os 8 so_remocao no ponto
del:N (a linha N). Se algum dos 8 ficar sem analise em alguma ferramenta, o
script PARA: a §11 manda retira-lo da sensibilidade, e o pedido desta apuracao,
mante-lo como sem analise — decisao que nao cabe ao codigo.

LEITURA SECUNDARIA — a da ferramenta de relatorio do benchmark (§8, conferida
contra contrib/reports/explore-server/src no commit 91c59fd), sobre os 220:
deteccao por igualdade exata de arquivo e de line_start com alguma linha do
ground truth, no lado vulneravel; regras desses achados; alertas de cada regra
no repositorio inteiro, nos dois lados. Na ordem do codigo do benchmark:
ausente (a ferramenta nao analisou algum dos dois lados), nao computavel (sem
deteccao), reconhecida (alguma regra com menos alertas no corrigido), nao
reconhecida. Le os tratados das duas campanhas.

SAIDAS — em results/cruzamento-corrigida/, escritas so depois de todas as
conferencias e relidas antes da promocao; deterministicas, sem carimbo de
execucao:
  matriz-corrigida.csv                  (CVE, ferramenta, nivel), nos 220
  cruzamento-corrigida-<ferramenta>.json agregados, fontes, conferencias
  leitura-benchmark.csv                  (CVE, ferramenta), leitura secundaria
  cruzamento-corrigida.txt               tabelas, sem comentario
O README.md do diretorio e escrito a mao.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
from fractions import Fraction
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CRUZA_PY = RAIZ / "tools" / "cruza-deteccao.py"


def _importar(nome, caminho):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(nome, caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


CRUZA = _importar("cruza_deteccao", CRUZA_PY)
Parada = CRUZA.Parada
FERRAMENTAS = CRUZA.FERRAMENTAS

LISTA_DETECCAO = RAIZ / "datasets" / "listas" / "cves-sast.txt"
LISTA_CORRIGIDA = RAIZ / "datasets" / "listas" / "cves-sast-corrigida.txt"
MATRIZ = RAIZ / "results" / "cruzamento" / "matriz-deteccao.csv"
# Registrado no CLAUDE.md ("Cruzamento SAST — resultados") e em cada
# cruzamento-<ferramenta>.json. A matriz e entrada, e lida como veio.
MATRIZ_SHA256 = "f80158b730794c3135701a8631e551d89610775562577322b806fcc180452825"
JSON_DETECCAO = RAIZ / "results" / "cruzamento"
PARES = RAIZ / "results" / "pares" / "pares.csv"
PARES_TXT = RAIZ / "results" / "pares" / "pares.txt"
LOGS_DETECCAO = RAIZ / "logs" / "campanha-2026-09-17"
LOGS_CORRIGIDA = RAIZ / "logs" / "campanha-corrigida-2026-09-29"
# Ordem CRONOLOGICA de execucao: vale a ultima linha de cada CVE.
LOTES_CORRIGIDA = tuple("cves-sast-corrigida-batch-%s" % l
                        for l in ("aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"))
REEXECUCOES = ("cves-sast-corrigida-reexec-2026-09-29",)
LISTAS = RAIZ / "datasets" / "listas"
TREATED_CORRIGIDA = RAIZ / "results" / "corrigida"
TREATED_DETECCAO = RAIZ / "results"
SAIDA_PADRAO = RAIZ / "results" / "cruzamento-corrigida"
CRITERIOS = CRUZA.CRITERIOS

VERSAO = "1"
NIVEIS = ("nivel_3", "nivel_4_generosa", "nivel_4_estrita")
ESTRITO = "nivel_4_estrita"
PRINCIPAL = 212
SENSIBILIDADE = 220
# Nominados na §11. A conferencia exige que o pares.csv de exatamente estes.
SO_REMOCAO_11 = ("CVE-2017-16043", "CVE-2017-16118", "CVE-2017-16119", "CVE-2018-16460",
                 "CVE-2018-20801", "CVE-2019-10761", "CVE-2020-26256", "CVE-2020-7720")
# Os cinco SEM_ARQUIVO_ANALISAVEL do Snyk Code (CLAUDE.md), nas duas campanhas.
SNYK_SEM_ARQUIVO = ("CVE-2018-16479", "CVE-2018-16480", "CVE-2018-3731",
                    "CVE-2018-3747", "CVE-2019-5423")
# O unico CVE redisparado (CLAUDE.md, regra de redisparo de 29/09/2026), e so no
# Snyk Code. Sem analise alem destes e parada, nunca categoria aceita.
REDISPARADO = {"cves-sast-corrigida-reexec-2026-09-29": ("snyk-code", "CVE-2019-15479")}
STATUS_ANALISADO = {"OK", "SEM_ACHADOS"}

VULNERAVEL = ("VP", "FN", "nao_se_aplica")
CORRIGIDO = ("FP", "VN", "sem_analise", "nao_se_aplica")
LEITURA = ("reconhecida", "nao_reconhecida", "nao_computavel", "ausente")

COLUNAS_MATRIZ = ("cve", "ferramenta", "nivel", "gt_tipo_ponto", "gt_ponto_post",
                  "na_principal", "motivo_fora_principal", "lado_vulneravel",
                  "status_corrigida", "tratado_corrigido", "lado_corrigido")
COLUNAS_LEITURA = ("cve", "ferramenta", "status_vulneravel", "status_corrigida",
                   "detectado_criterio_benchmark", "resultado", "regras",
                   "alertas_vulneravel", "alertas_corrigida")
NOME_MATRIZ = "matriz-corrigida.csv"
NOME_LEITURA = "leitura-benchmark.csv"
NOME_TXT = "cruzamento-corrigida.txt"
PREFIXO_TEMP = ".cruzamento-corrigida-tmp-"


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------
def sha256_arquivo(caminho):
    return hashlib.sha256(Path(caminho).read_bytes()).hexdigest()


def rotulo(caminho):
    return CRUZA.rotulo_caminho(caminho)


def fracao(num, den):
    """{num, den, valor}; valor nulo quando o denominador e zero."""
    return {"num": num, "den": den,
            "valor": None if den == 0 else round(float(Fraction(num, den)), 4)}


def texto_csv(colunas, linhas):
    motivos = [repr(c) for linha in linhas for c in linha
               if any(p in c for p in (",", "\n", "\r"))]
    if motivos:
        raise Parada("CSV violaria a invariante de nenhum campo com virgula", motivos[:10])
    return "".join(",".join(l) + "\n" for l in [list(colunas), *linhas])


def ler_csv_split(texto, colunas):
    """Leitura por split, como toda lista do projeto. (linhas, erros)."""
    erros = []
    if not texto.endswith("\n"):
        erros.append("CSV sem quebra de linha final")
    partes = texto.split("\n")[:-1] if texto.endswith("\n") else texto.split("\n")
    if not partes or partes[0].split(",") != list(colunas):
        return [], erros + ["cabecalho divergente"]
    linhas = []
    for numero, bruta in enumerate(partes[1:], 2):
        campos = bruta.split(",")
        if len(campos) != len(colunas):
            erros.append("linha %d com %d campos" % (numero, len(campos)))
            continue
        linhas.append(campos)
    return linhas, erros


# ---------------------------------------------------------------------------
# O ponto corrigido
# ---------------------------------------------------------------------------
_RE_INALTERADA = re.compile(r"^([1-9][0-9]*)$")
_RE_TRECHO = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")
_RE_DEL = re.compile(r"^del:([1-9][0-9]*)(:fim)?$")


def ponto_corrigido(tipo_campo, ponto_campo, linhas_campo, gt_file_lines):
    """(tipo, [(ini, fim), ...], linhas). Levanta ValueError se fora da forma.

    Uma entrada por linha registrada do ground truth, alinhada a gt_linhas.
    so_remocao devolve o ponto del:N como (N, N): e o ponto da SENSIBILIDADE;
    a principal nao o usa.
    """
    tipos = tipo_campo.split("|")
    pontos = ponto_campo.split("|")
    try:
        linhas = [int(x) for x in linhas_campo.split("|")]
    except ValueError:
        raise ValueError("gt_linhas fora da forma: %r" % linhas_campo)
    if not (len(tipos) == len(pontos) == len(linhas)):
        raise ValueError("colunas desalinhadas: %r %r %r" % (tipo_campo, ponto_campo, linhas_campo))
    if linhas != list(gt_file_lines):
        raise ValueError("gt_linhas %r difere do gt_file_lines da lista %r"
                         % (linhas, list(gt_file_lines)))
    if len(set(tipos)) != 1:
        raise ValueError("tipos mistos no mesmo CVE: %r" % tipo_campo)
    tipo = tipos[0]
    intervalos = []
    for ponto in pontos:
        if tipo == "inalterada" and _RE_INALTERADA.match(ponto):
            n = int(ponto)
            intervalos.append((n, n))
        elif tipo == "trecho" and _RE_TRECHO.match(ponto):
            ini, fim = (int(x) for x in _RE_TRECHO.match(ponto).groups())
            if fim < ini:
                raise ValueError("trecho invertido: %r" % ponto)
            intervalos.append((ini, fim))
        elif tipo == "so_remocao" and _RE_DEL.match(ponto):
            n = int(_RE_DEL.match(ponto).group(1))
            intervalos.append((n, n))
        else:
            raise ValueError("ponto %r fora da forma do tipo %r" % (ponto, tipo))
    return tipo, intervalos, sorted({l for ini, fim in intervalos for l in range(ini, fim + 1)})


# ---------------------------------------------------------------------------
# Classificacao, por (CVE, ferramenta)
# ---------------------------------------------------------------------------
def classificar_corrigido(gt, linhas_ponto, status, tratado):
    """{nivel: FP | VN | sem_analise | nao_se_aplica}, e os casados do nivel 3.

    A estrita nao se aplica primeiro: e propriedade do ground truth, e vale
    tambem quando nao houve analise. Depois, sem analise. Depois, o casamento
    do cruza-deteccao.py com o ponto corrigido no lugar das linhas vulneraveis.
    """
    estrita = gt["gt_cwe_primary"] is not None
    if status not in STATUS_ANALISADO or tratado is None:
        return ({n: ("nao_se_aplica" if n == ESTRITO and not estrita else "sem_analise")
                 for n in NIVEIS}, [])
    gt_ponto = dict(gt, gt_file_lines=list(linhas_ponto))
    res = CRUZA.apurar_cve(gt_ponto, tratado["findings"])
    saida = {}
    for nivel in NIVEIS:
        valor = res["niveis"][nivel]
        saida[nivel] = "nao_se_aplica" if valor is None else ("FP" if valor else "VN")
    return saida, res["casados"]["nivel_3"]


def lado_vulneravel(linha_matriz, nivel):
    valor = linha_matriz[nivel]
    return {"true": "VP", "false": "FN", "": "nao_se_aplica"}[valor]


def leitura_benchmark(gt, tratado_pre, status_pre, tratado_post, status_post):
    """(resultado, detectado, [(regra, antes, depois)]) — a leitura do benchmark.

    Ordem de getRelevantRuleAlertCountsConclusion: ausente antes de nao
    computavel. Deteccao: isOnTarget, igualdade exata de arquivo e de linha
    (line_start) com alguma weakness do lado vulneravel.
    """
    analisado_pre = status_pre in STATUS_ANALISADO and tratado_pre is not None
    analisado_post = status_post in STATUS_ANALISADO and tratado_post is not None
    alvo = set(gt["gt_file_lines"])
    regras = set()
    if analisado_pre:
        for achado in tratado_pre["findings"]:
            if achado["file_path"] == gt["gt_file_path"] and achado["line_start"] in alvo:
                if not isinstance(achado["rule_id"], str) or not achado["rule_id"]:
                    raise ValueError("achado no alvo sem rule_id: %s" % achado["finding_id"])
                if "|" in achado["rule_id"]:
                    # A coluna regras do CSV separa por '|'.
                    raise ValueError("rule_id com '|': %r" % achado["rule_id"])
                regras.add(achado["rule_id"])
    if not (analisado_pre and analisado_post):
        return "ausente", (bool(regras) if analisado_pre else None), []
    if not regras:
        return "nao_computavel", False, []
    contagem = []
    for regra in sorted(regras):
        antes = sum(1 for a in tratado_pre["findings"] if a["rule_id"] == regra)
        depois = sum(1 for a in tratado_post["findings"] if a["rule_id"] == regra)
        contagem.append((regra, antes, depois))
    if any(depois < antes for _, antes, depois in contagem):
        return "reconhecida", True, contagem
    return "nao_reconhecida", True, contagem


def metricas(celulas):
    """Contagens e fracoes de uma (ferramenta, nivel) sobre um universo."""
    c = {k: 0 for k in ("VP", "FN", "FP", "VN", "sem_analise",
                        "nao_se_aplica_vulneravel", "nao_se_aplica_corrigido")}
    for vul, cor in celulas:
        c["nao_se_aplica_vulneravel" if vul == "nao_se_aplica" else vul] += 1
        c["nao_se_aplica_corrigido" if cor == "nao_se_aplica" else cor] += 1
    base = len(celulas) - c["nao_se_aplica_corrigido"]
    recall = fracao(c["VP"], c["VP"] + c["FN"])
    precisao = fracao(c["VP"], c["VP"] + c["FP"])
    if recall["valor"] is None or precisao["valor"] is None or c["VP"] == 0:
        f1 = None if (c["VP"] + c["FN"] == 0 or c["VP"] + c["FP"] == 0) else 0.0
    else:
        p, r = Fraction(c["VP"], c["VP"] + c["FP"]), Fraction(c["VP"], c["VP"] + c["FN"])
        f1 = round(float(2 * p * r / (p + r)), 4)
    return {"universo": len(celulas), "base": base, **c, "recall": recall,
            "precisao": precisao, "especificidade": fracao(c["VN"], base),
            "sem_analise_sobre_base": fracao(c["sem_analise"], base), "f1": f1}


# ---------------------------------------------------------------------------
# Leitura das entradas
# ---------------------------------------------------------------------------
def ler_pares(caminho, gt):
    """{cve: {tipo, intervalos, linhas, ponto_post, post, fora}}. Levanta Parada."""
    motivos, pares = [], {}
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        for linha in csv.DictReader(arquivo):
            cve = linha["cve"]
            if cve in pares:
                motivos.append("pares.csv: CVE repetido %s" % cve)
                continue
            item = {"post": linha["post"], "pre": linha["pre"],
                    "fora": linha["fora_do_denominador"], "gt_arquivo": linha["gt_arquivo"],
                    "no_post": linha["gt_arquivo_no_post"],
                    "ponto_post": linha["gt_ponto_post"], "tipo": None, "intervalos": None,
                    "linhas": None}
            if cve in gt and not item["fora"]:
                try:
                    item["tipo"], item["intervalos"], item["linhas"] = ponto_corrigido(
                        linha["gt_tipo_ponto"], linha["gt_ponto_post"], linha["gt_linhas"],
                        gt[cve]["gt_file_lines"])
                except ValueError as erro:
                    motivos.append("pares.csv %s: %s" % (cve, erro))
            pares[cve] = item
    if motivos:
        raise Parada("pares.csv fora da forma", motivos)
    return pares


def ler_lista(caminho):
    commits = {}
    for linha in Path(caminho).read_text(encoding="utf-8").splitlines():
        if linha:
            partes = linha.split(",")
            commits[partes[0]] = partes[2]
    return commits


def carregar_registro_corrigida(diretorio, check_log, pares=None):
    """{ferramenta: {cve: status final}}, e os logs lidos. Levanta Parada.

    Cada log cobre exatamente os CVEs da lista do seu lote; nenhum CVE em dois
    lotes; a uniao e a lista corrigida completa. A reexecucao so pode trazer
    CVE cujo status ate ali era de erro, e o substitui: vale a ultima linha.
    """
    diretorio = Path(diretorio)
    motivos, arquivos = [], []
    registro = {f: {} for f in FERRAMENTAS}
    universo = set(ler_lista(LISTA_CORRIGIDA))
    for lote in LOTES_CORRIGIDA + REEXECUCOES:
        cves_lote = sorted(ler_lista(LISTAS / lote))
        reexec = lote in REEXECUCOES
        for ferramenta in FERRAMENTAS:
            log = diretorio / lote / ("execution-log-%s.csv" % ferramenta)
            # Da reexecucao so o log da ferramenta redisparada foi importado, e
            # ele e obrigatorio; os das outras duas nao entram no registro.
            exigido = not reexec or ferramenta == REDISPARADO[lote][0]
            if not exigido:
                continue
            if not log.is_file():
                motivos.append("%s: log ausente: %s" % (ferramenta, rotulo(log)))
                continue
            arquivos.append(log)
            ultimo, _, linhas, desconhecidos = check_log.ler_log(log)
            if log.read_text(encoding="utf-8").split("\n", 1)[0] != check_log.CABECALHO:
                motivos.append("%s %s: sem cabecalho" % (ferramenta, lote))
            for item in desconhecidos:
                motivos.append("%s %s: linha fora do formato: %s" % (ferramenta, lote, item))
            if linhas != len(ultimo):
                motivos.append("%s %s: CVE repetido no log" % (ferramenta, lote))
            if sorted(ultimo) != cves_lote:
                motivos.append("%s %s: CVEs do log diferem da lista do lote" % (ferramenta, lote))
            # O commit ANALISADO: a coluna commit do log, contra o post. O
            # metadata.commit do tratado vem da lista e so prova a lista usada.
            if pares is not None:
                for bruta in log.read_text(encoding="utf-8").splitlines()[1:]:
                    partes = bruta.split(",")
                    if len(partes) >= 3 and partes[0] in pares and partes[2] != pares[partes[0]]["post"]:
                        motivos.append("%s %s %s: commit analisado %s nao e o post"
                                       % (ferramenta, lote, partes[0], partes[2]))
            for cve, status in sorted(ultimo.items()):
                anterior = registro[ferramenta].get(cve)
                if reexec:
                    if anterior is None or anterior in STATUS_ANALISADO or anterior == "SEM_ARQUIVO_ANALISAVEL":
                        motivos.append("%s %s: reexecutado sem falha anterior que o admita (%s)"
                                       % (ferramenta, cve, anterior))
                elif anterior is not None:
                    motivos.append("%s %s: CVE em dois lotes" % (ferramenta, cve))
                registro[ferramenta][cve] = status
    for ferramenta in FERRAMENTAS:
        if set(registro[ferramenta]) != universo:
            motivos.append("%s: CVEs do registro diferem da lista corrigida (%d x %d)"
                           % (ferramenta, len(registro[ferramenta]), len(universo)))
    if motivos:
        raise Parada("logs da campanha corrigida nao conferem", motivos)
    return registro, arquivos


def gt_do_corrigido(gt, pares):
    """O gt da lista de deteccao com o commit trocado pelo PostPatchCommit.

    Os campos de ground truth da lista corrigida sao os do benchmark (CLAUDE.md,
    convencoes da campanha corrigida); so o commit muda. validar_tratado() do
    cruza-deteccao.py confere cada tratado contra este gt.
    """
    gt_post = copy.deepcopy(gt)
    for cve in gt_post:
        gt_post[cve]["commit"] = pares[cve]["post"]
    return gt_post


# ---------------------------------------------------------------------------
# Conferencias — cada uma devolve a lista de motivos; vazia = passou
# ---------------------------------------------------------------------------
def tratados_esperados(registro):
    """220 / 220 / 215: o Snyk Code sem os cinco exit 3 e, so se o redisparo
    tiver falhado, sem o CVE redisparado. Nao sai do registro que confere."""
    lote, (ferr, cve) = next(iter(REDISPARADO.items()))
    snyk = SENSIBILIDADE - len(SNYK_SEM_ARQUIVO)
    if registro[ferr][cve] not in STATUS_ANALISADO:
        snyk -= 1
    return {"codeql": SENSIBILIDADE, "semgrep": SENSIBILIDADE, "snyk-code": snyk}


def conf1_proveniencia(sha_matriz, sha_matriz_json, sha_pares, sha_pares_txt,
                       tratados, registro, pares):
    m = []
    esperados = tratados_esperados(registro)
    for f in FERRAMENTAS:
        if len(tratados[f]) != esperados[f]:
            m.append("%s: %d tratados corrigidos, esperados %d" % (f, len(tratados[f]), esperados[f]))
    if sha_matriz != MATRIZ_SHA256:
        m.append("matriz-deteccao.csv com sha256 %s, registrado %s" % (sha_matriz, MATRIZ_SHA256))
    for f, sha in sha_matriz_json.items():
        if sha != sha_matriz:
            m.append("cruzamento-%s.json liga outra matriz: %s" % (f, sha))
    if sha_pares != sha_pares_txt:
        m.append("pares.csv com sha256 %s, pares.txt registra %s" % (sha_pares, sha_pares_txt))
    for f in FERRAMENTAS:
        analisados = {c for c, s in registro[f].items() if s in STATUS_ANALISADO}
        if set(tratados[f]) != analisados:
            m.append("%s: tratados corrigidos (%d) != CVEs analisados no registro (%d)"
                     % (f, len(tratados[f]), len(analisados)))
        for cve, t in tratados[f].items():
            if t["metadata"]["commit"] != pares[cve]["post"]:
                m.append("%s %s: metadata.commit nao e o post do pares.csv" % (f, cve))
    return m


def conf2_universo(principal, sensibilidade, so_remocao, fora):
    m = []
    if len(principal) != PRINCIPAL:
        m.append("principal com %d CVEs, esperados %d" % (len(principal), PRINCIPAL))
    if len(sensibilidade) != SENSIBILIDADE:
        m.append("sensibilidade com %d CVEs, esperados %d" % (len(sensibilidade), SENSIBILIDADE))
    if sorted(so_remocao) != sorted(SO_REMOCAO_11):
        m.append("so_remocao do pares.csv %s difere dos nominados na §11" % sorted(so_remocao))
    if set(sensibilidade) - set(principal) != set(so_remocao):
        m.append("sensibilidade menos principal != os so_remocao")
    presentes = sorted(set(fora) & set(sensibilidade))
    if presentes:
        m.append("CVE fora do denominador no universo: %s" % presentes)
    return m


def conf3_reconstrucao(vulneravel, principal, so_remocao, agregados_publicados):
    """VP/FN nos 212 + nos 8 = celulas publicadas dos niveis 3, 4g e 4e."""
    m = []
    for f in FERRAMENTAS:
        for nivel in NIVEIS:
            conta = {"acertos": 0, "nao_acertos": 0}
            if nivel == ESTRITO:
                conta["nao_se_aplica"] = 0
            for cve in list(principal) + list(so_remocao):
                v = vulneravel[(cve, f, nivel)]
                conta["acertos" if v == "VP" else "nao_acertos" if v == "FN" else "nao_se_aplica"] += 1
            if conta != agregados_publicados[f][nivel]:
                m.append("%s %s: reconstruido %s, publicado %s"
                         % (f, nivel, conta, agregados_publicados[f][nivel]))
    return m


def conf4_particao(corrigido, principal):
    m = []
    for f in FERRAMENTAS:
        for nivel in NIVEIS:
            soma = sum(1 for cve in principal if corrigido[(cve, f, nivel)] in CORRIGIDO)
            estados = {corrigido[(cve, f, nivel)] for cve in principal}
            if soma != len(principal) or not estados <= set(CORRIGIDO):
                m.append("%s %s: particao do lado corrigido fecha em %d de %d"
                         % (f, nivel, soma, len(principal)))
            if nivel != ESTRITO and "nao_se_aplica" in estados:
                m.append("%s %s: nao_se_aplica fora da estrita" % (f, nivel))
    return m


def conf5_sem_analise(corrigido, sensibilidade, registro):
    m = []
    esperado_snyk = set(SNYK_SEM_ARQUIVO)
    _, (ferr, cve) = next(iter(REDISPARADO.items()))
    if registro[ferr][cve] not in STATUS_ANALISADO:
        esperado_snyk.add(cve)
    for f in FERRAMENTAS:
        obtido = {cve for cve in sensibilidade if corrigido[(cve, f, "nivel_3")] == "sem_analise"}
        esperado = esperado_snyk if f == "snyk-code" else set()
        if obtido != esperado:
            m.append("%s: sem analise %s, esperado %s" % (f, sorted(obtido), sorted(esperado)))
    return m


def conf6_sensibilidade(corr_principal, corr_sens, principal, so_remocao):
    m = []
    for (cve, f, nivel), valor in corr_principal.items():
        if corr_sens.get((cve, f, nivel)) != valor:
            m.append("%s %s %s: sensibilidade difere da principal num CVE da principal"
                     % (f, cve, nivel))
    extras = {k[0] for k in corr_sens} - set(principal)
    if extras != set(so_remocao):
        m.append("sensibilidade acrescenta %s, esperados os so_remocao" % sorted(extras))
    return m


def conf7_leitura(leitura, sensibilidade, vulneravel):
    m = []
    for f in FERRAMENTAS:
        estados = [leitura.get((cve, f), (None,))[0] for cve in sensibilidade]
        if len(sensibilidade) != SENSIBILIDADE or not set(estados) <= set(LEITURA):
            m.append("%s: leitura nao fecha em %d" % (f, SENSIBILIDADE))
        for cve in sensibilidade:
            if leitura.get((cve, f), (None, None))[1] is True and vulneravel[(cve, f, "nivel_3")] != "VP":
                m.append("%s %s: detectado por igualdade exata sem nivel 3" % (f, cve))
    return m


def conf8_releitura(texto_gravado, colunas, linhas_memoria):
    lidas, erros = ler_csv_split(texto_gravado, colunas)
    if erros:
        return erros
    if lidas != linhas_memoria:
        return ["CSV relido difere do gerado em memoria"]
    return []


# ---------------------------------------------------------------------------
# Controle positivo das conferencias — cada mutante tem de ser acusado
# ---------------------------------------------------------------------------
def controle_positivo(ctx):
    """ctx: os argumentos reais de cada conferencia. Devolve (resultados, falhas)."""
    resultados, falhas = [], []

    def caso(nome, conferencia, *args):
        acusou = bool(conferencia(*args))
        resultados.append({"conferencia": nome, "mutante_acusado": acusou})
        if not acusou:
            falhas.append("mutante nao acusado: %s" % nome)

    c1 = ctx["conf1"]
    caso("1 proveniencia: sha256 da matriz", conf1_proveniencia, "0" * 64, *c1[1:])
    f0 = FERRAMENTAS[0]
    trat = copy.deepcopy(c1[4])
    alvo = sorted(trat[f0])[0]
    trat[f0][alvo]["metadata"]["commit"] = "0" * 40
    caso("1 proveniencia: metadata.commit", conf1_proveniencia, *c1[:4], trat, *c1[5:])
    # Um erro novo no Snyk Code, com o tratado sumindo junto: o conjunto de
    # tratados segue igual ao de analisados, e so a contagem fixa o pega.
    reg = copy.deepcopy(c1[5])
    trat = copy.deepcopy(c1[4])
    vitima = sorted(trat["snyk-code"])[0]
    reg["snyk-code"][vitima] = "ERRO_ANALISE"
    del trat["snyk-code"][vitima]
    caso("1 proveniencia: Snyk com 214, erro novo absorvido", conf1_proveniencia,
         *c1[:4], trat, reg, *c1[6:])
    c2 = ctx["conf2"]
    caso("2 universo: principal com 213", conf2_universo, list(c2[0]) + [c2[2][0]], *c2[1:])
    c3 = ctx["conf3"]
    vul = dict(c3[0])
    chave = (c3[1][0], f0, "nivel_3")
    vul[chave] = "FN" if vul[chave] == "VP" else "VP"
    caso("3 reconstrucao: uma celula trocada", conf3_reconstrucao, vul, *c3[1:])
    c4 = ctx["conf4"]
    cor = dict(c4[0])
    cor[(c4[1][0], f0, "nivel_3")] = "talvez"
    caso("4 particao: estado fora do vocabulario", conf4_particao, cor, c4[1])
    c5 = ctx["conf5"]
    cor = dict(c5[0])
    cor[(c5[1][0], f0, "nivel_3")] = "sem_analise"
    caso("5 sem analise: CodeQL com um", conf5_sem_analise, cor, *c5[1:])
    cor = dict(c5[0])
    reg = copy.deepcopy(c5[2])
    extra = next(c for c in c5[1] if c not in SNYK_SEM_ARQUIVO)
    for nivel in NIVEIS:
        cor[(extra, "snyk-code", nivel)] = "sem_analise"
    reg["snyk-code"][extra] = "ERRO_ANALISE"
    caso("5 sem analise: Snyk com um erro novo no registro", conf5_sem_analise, cor, c5[1], reg)
    c6 = ctx["conf6"]
    sens = dict(c6[1])
    k = next(iter(c6[0]))
    sens[k] = "FP" if sens[k] != "FP" else "VN"
    caso("6 sensibilidade: CVE da principal alterado", conf6_sensibilidade, c6[0], sens, *c6[2:])
    c7 = ctx["conf7"]
    lei = dict(c7[0])
    fn = next(k for k in c7[2] if k[2] == "nivel_3" and c7[2][k] == "FN" and k[0] in c7[1])
    lei[(fn[0], fn[1])] = ("nao_reconhecida", True, [])
    caso("7 leitura: detectado sem nivel 3", conf7_leitura, lei, *c7[1:])
    lei = dict(c7[0])
    del lei[next(iter(lei))]
    caso("7 leitura: entrada faltante", conf7_leitura, lei, *c7[1:])
    c8 = ctx["conf8"]
    caso("8 releitura: CSV adulterado", conf8_releitura, c8[0].replace("true", "false", 1),
         *c8[1:])
    return resultados, falhas


# ---------------------------------------------------------------------------
# Laco principal
# ---------------------------------------------------------------------------
def executar(args):
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO
    entradas = (LISTA_DETECCAO, LISTA_CORRIGIDA, MATRIZ, PARES, PARES_TXT, LOGS_DETECCAO,
                LOGS_CORRIGIDA, TREATED_CORRIGIDA, TREATED_DETECCAO)
    if saida.resolve() == SAIDA_PADRAO.resolve():
        fora = [str(e) for e in entradas if not Path(e).resolve().is_relative_to(RAIZ)]
        if fora:
            raise Parada("a saida versionada exige entradas dentro do repositorio", fora)

    norm = CRUZA.importar("normalize", CRUZA.NORMALIZE)
    check_log = CRUZA.importar("check_log", CRUZA.CHECK_LOG)

    gt, denominador, _ = CRUZA.carregar_gt(norm, LISTA_DETECCAO)
    pares = ler_pares(PARES, gt)
    lista_corrigida = ler_lista(LISTA_CORRIGIDA)
    motivos = []
    if sorted(lista_corrigida) != denominador:
        motivos.append("lista corrigida (%d) difere do denominador (%d)"
                       % (len(lista_corrigida), len(denominador)))
    for cve, commit in lista_corrigida.items():
        if cve in pares and commit != pares[cve]["post"]:
            motivos.append("%s: commit da lista corrigida nao e o post do pares.csv" % cve)
        if cve in gt and pares.get(cve, {}).get("gt_arquivo") != gt[cve]["gt_file_path"]:
            motivos.append("%s: gt_arquivo do pares.csv difere do gt_file_path" % cve)
        # §11: nenhum arquivo do ground truth removido nem renomeado. Arquivo
        # ausente do post daria VN silencioso, a favor da ferramenta.
        if pares.get(cve, {}).get("no_post") != "presente":
            motivos.append("%s: arquivo do ground truth nao esta presente no post (%r)"
                           % (cve, pares.get(cve, {}).get("no_post")))
    if motivos:
        raise Parada("entradas nao conferem entre si", motivos)

    so_remocao = sorted(c for c in denominador if pares[c]["tipo"] == "so_remocao")
    principal = [c for c in denominador if c not in so_remocao]
    sensibilidade = list(denominador)

    # Lado vulneravel: da matriz publicada.
    texto_matriz = MATRIZ.read_text(encoding="utf-8")
    linhas_matriz, erros = CRUZA.ler_csv(texto_matriz)
    if erros:
        raise Parada("matriz-deteccao.csv ilegivel", erros)
    matriz = {(l["cve"], l["ferramenta"]): l for l in linhas_matriz}
    vulneravel = {}
    for cve in sensibilidade:
        for f in FERRAMENTAS:
            l = matriz[(cve, f)]
            if l["no_denominador"] != "true":
                raise Parada("CVE do denominador fora dele na matriz", [cve])
            for nivel in NIVEIS:
                vulneravel[(cve, f, nivel)] = lado_vulneravel(l, nivel)
    publicados, sha_json = {}, {}
    for f in FERRAMENTAS:
        dados = json.loads((JSON_DETECCAO / ("cruzamento-%s.json" % f)).read_text(encoding="utf-8"))
        publicados[f] = dados["agregados"]
        sha_json[f] = dados["csv_da_mesma_execucao"]["sha256"]

    # Lado corrigido.
    registro, logs_lidos = carregar_registro_corrigida(LOGS_CORRIGIDA, check_log, pares)
    gt_post = gt_do_corrigido(gt, pares)
    tratados, resumos, anomalias = {}, {}, []
    for f in FERRAMENTAS:
        tratados[f], presentes, encontradas, resumos[f] = CRUZA.carregar_tratados(
            TREATED_CORRIGIDA, f, gt_post, norm)
        anomalias.extend(encontradas)
        fora_220 = sorted(presentes - set(lista_corrigida))
        if fora_220:
            raise Parada("tratado corrigido de CVE fora dos 220", ["%s %s" % (f, c) for c in fora_220])
        # O registro corrigido so tem os 220; conferir_status_achados indexa por CVE.
        anomalias.extend(CRUZA.conferir_status_achados(f, tratados[f], registro))
    if anomalias:
        raise Parada("tratados corrigidos com anomalia", anomalias)

    def apurar(universo, usar_del):
        resultado, casados = {}, {}
        for cve in universo:
            p = pares[cve]
            if p["tipo"] == "so_remocao" and not usar_del:
                continue
            for f in FERRAMENTAS:
                valores, ids = classificar_corrigido(gt[cve], p["linhas"], registro[f][cve],
                                                     tratados[f].get(cve))
                for nivel in NIVEIS:
                    resultado[(cve, f, nivel)] = valores[nivel]
                casados[(cve, f)] = ids
        return resultado, casados

    corr_principal, casados = apurar(principal, False)
    corr_sens, _ = apurar(sensibilidade, True)
    sem_analise_8 = sorted({(c, f) for (c, f, n), v in corr_sens.items()
                            if c in so_remocao and v == "sem_analise"})
    if sem_analise_8:
        raise Parada("um so_remocao sem analise: a §11 o retira da sensibilidade, e o pedido "
                     "o mantem como sem analise — decisao que nao cabe ao codigo",
                     ["%s %s" % x for x in sem_analise_8])

    # Leitura secundaria: tratados da deteccao.
    registro_det, _, _ = CRUZA.carregar_registro(LOGS_DETECCAO, gt, check_log)
    tratados_det = {}
    for f in FERRAMENTAS:
        tratados_det[f], _, encontradas, _ = CRUZA.carregar_tratados(TREATED_DETECCAO, f, gt, norm)
        if encontradas:
            raise Parada("tratados da deteccao com anomalia", encontradas)
    leitura = {}
    for cve in sensibilidade:
        for f in FERRAMENTAS:
            try:
                leitura[(cve, f)] = leitura_benchmark(
                    gt[cve], tratados_det[f].get(cve), registro_det[f][cve],
                    tratados[f].get(cve), registro[f][cve])
            except ValueError as erro:
                raise Parada("leitura do benchmark", ["%s %s: %s" % (f, cve, erro)])

    # Saidas em memoria.
    linhas_m = []
    for cve in sensibilidade:
        p = pares[cve]
        for f in FERRAMENTAS:
            for nivel in NIVEIS:
                linhas_m.append([
                    cve, f, nivel, p["tipo"], p["ponto_post"],
                    "false" if cve in so_remocao else "true",
                    "so_remocao" if cve in so_remocao else "",
                    vulneravel[(cve, f, nivel)], registro[f][cve],
                    "true" if cve in tratados[f] else "false",
                    corr_sens[(cve, f, nivel)]])
    csv_m = texto_csv(COLUNAS_MATRIZ, linhas_m)
    linhas_l = []
    for cve in sensibilidade:
        for f in FERRAMENTAS:
            resultado, detectado, regras = leitura[(cve, f)]
            linhas_l.append([
                cve, f, registro_det[f][cve], registro[f][cve],
                "" if detectado is None else ("true" if detectado else "false"), resultado,
                "|".join(r for r, _, _ in regras), "|".join(str(a) for _, a, _ in regras),
                "|".join(str(d) for _, _, d in regras)])
    csv_l = texto_csv(COLUNAS_LEITURA, linhas_l)

    # Conferencias 1 a 7, com o controle positivo de cada uma.
    sha_matriz = hashlib.sha256(texto_matriz.encode("utf-8")).hexdigest()
    sha_pares = sha256_arquivo(PARES)
    m_txt = re.search(r"csv desta execucao \(sha256\): ([0-9a-f]{64})",
                      PARES_TXT.read_text(encoding="utf-8"))
    sha_pares_txt = m_txt.group(1) if m_txt else None
    ctx = {
        "conf1": (sha_matriz, sha_json, sha_pares, sha_pares_txt, tratados, registro, pares),
        "conf2": (principal, sensibilidade, so_remocao, sorted(CRUZA.FORA_DO_DENOMINADOR)),
        "conf3": (vulneravel, principal, so_remocao, publicados),
        "conf4": (corr_principal, principal),
        "conf5": (corr_sens, sensibilidade, registro),
        "conf6": (corr_principal, corr_sens, principal, so_remocao),
        "conf7": (leitura, sensibilidade, vulneravel),
        "conf8": (csv_m, COLUNAS_MATRIZ, linhas_m),
    }
    motivos = (conf1_proveniencia(*ctx["conf1"]) + conf2_universo(*ctx["conf2"])
               + conf3_reconstrucao(*ctx["conf3"]) + conf4_particao(*ctx["conf4"])
               + conf5_sem_analise(*ctx["conf5"]) + conf6_sensibilidade(*ctx["conf6"])
               + conf7_leitura(*ctx["conf7"]))
    if motivos:
        raise Parada("conferencias nao passaram", motivos)
    controle, falhas = controle_positivo(ctx)
    if falhas:
        raise Parada("controle positivo das conferencias falhou", falhas)

    # Agregados.
    relatorios = {}
    fontes = {
        "matriz_deteccao": {"caminho": rotulo(MATRIZ), "sha256": sha_matriz},
        "pares": {"caminho": rotulo(PARES), "sha256": sha_pares},
        "lista_deteccao": {"caminho": rotulo(LISTA_DETECCAO), "sha256": sha256_arquivo(LISTA_DETECCAO)},
        "lista_corrigida": {"caminho": rotulo(LISTA_CORRIGIDA), "sha256": sha256_arquivo(LISTA_CORRIGIDA)},
        "tabela_primario": {"caminho": rotulo(norm.TABELA_PRIMARIO),
                            "sha256": sha256_arquivo(norm.TABELA_PRIMARIO)},
        "logs_corrigida": {"diretorio": rotulo(LOGS_CORRIGIDA), "arquivos": len(logs_lidos),
                           "sha256_conjunto": CRUZA.sha256_conjunto(logs_lidos, LOGS_CORRIGIDA)},
        "criterios": {"caminho": rotulo(CRITERIOS), "sha256": sha256_arquivo(CRITERIOS)},
        "codigo": {rotulo(c): sha256_arquivo(c) for c in (Path(__file__).resolve(), CRUZA_PY,
                                                           CRUZA.NORMALIZE, CRUZA.CHECK_LOG)},
    }
    for f in FERRAMENTAS:
        principal_f, sens_f, grupos, recall_220 = {}, {}, {}, {}
        for nivel in NIVEIS:
            principal_f[nivel] = metricas([(vulneravel[(c, f, nivel)], corr_principal[(c, f, nivel)])
                                           for c in principal])
            sens_f[nivel] = metricas([(vulneravel[(c, f, nivel)], corr_sens[(c, f, nivel)])
                                      for c in sensibilidade])
            pub = publicados[f][nivel]
            recall_220[nivel] = fracao(pub["acertos"], pub["acertos"] + pub["nao_acertos"])
            grupos[nivel] = {}
            for grupo in ("inalterada", "trecho"):
                membros = [c for c in principal if pares[c]["tipo"] == grupo]
                cont = {k: sum(1 for c in membros if corr_principal[(c, f, nivel)] == k)
                        for k in CORRIGIDO}
                grupos[nivel][grupo] = {"cves": len(membros), **cont}
        contagem_leitura = {k: sum(1 for c in sensibilidade if leitura[(c, f)][0] == k)
                            for k in LEITURA}
        relatorios[f] = {
            "ferramenta": f, "versao": VERSAO,
            "criterios": "docs/criterios-cruzamento.md, §11",
            "fontes": dict(fontes, tratados_corrigidos={
                "diretorio": rotulo(TREATED_CORRIGIDA / f / "treated"),
                "arquivos": len(tratados[f]), "sha256_conjunto": resumos[f]}),
            "universo": {"principal": len(principal), "sensibilidade": len(sensibilidade),
                         "so_remocao_fora_da_principal": so_remocao,
                         "fora_do_denominador": sorted(CRUZA.FORA_DO_DENOMINADOR),
                         "grupos_principal": {g: sum(1 for c in principal if pares[c]["tipo"] == g)
                                              for g in ("inalterada", "trecho")}},
            "sem_analise": {
                "principal": sorted(c for c in principal if corr_principal[(c, f, "nivel_3")] == "sem_analise"),
                "sensibilidade": sorted(c for c in sensibilidade if corr_sens[(c, f, "nivel_3")] == "sem_analise"),
                "status": {c: registro[f][c] for c in sensibilidade
                           if registro[f][c] not in STATUS_ANALISADO}},
            "estrita_nao_se_aplica": sorted(c for c in principal
                                            if corr_principal[(c, f, ESTRITO)] == "nao_se_aplica"),
            "principal": principal_f,
            "recall_sobre_220_publicado": recall_220,
            "decomposicao_por_grupo_principal": grupos,
            "sensibilidade": sens_f,
            "leitura_benchmark": {"universo": len(sensibilidade), **contagem_leitura,
                                  "detectados_criterio_exato": sum(
                                      1 for c in sensibilidade if leitura[(c, f)][1] is True)},
            "achados_casados_nivel_3_corrigido": {c: casados[(c, f)] for c in principal
                                                  if casados.get((c, f))},
            "conferencias": {"1_a_7": "passaram", "controle_positivo": controle},
        }

    txt = texto_legivel(relatorios)

    # Gravacao: temporarios, releitura (conferencia 8), promocao.
    saida.mkdir(parents=True, exist_ok=True)
    for residuo in saida.glob(PREFIXO_TEMP + "*"):
        residuo.unlink()
    arquivos = {NOME_MATRIZ: csv_m, NOME_LEITURA: csv_l, NOME_TXT: txt}
    for f in FERRAMENTAS:
        arquivos["cruzamento-corrigida-%s.json" % f] = (
            json.dumps(relatorios[f], indent=2, ensure_ascii=False) + "\n")
    temps = {}
    for nome, conteudo in arquivos.items():
        temps[nome] = saida / (PREFIXO_TEMP + nome)
        temps[nome].write_text(conteudo, encoding="utf-8")
    releitura = (conf8_releitura(temps[NOME_MATRIZ].read_text(encoding="utf-8"),
                                 COLUNAS_MATRIZ, linhas_m)
                 + conf8_releitura(temps[NOME_LEITURA].read_text(encoding="utf-8"),
                                   COLUNAS_LEITURA, linhas_l))
    for nome, caminho in temps.items():
        if caminho.read_text(encoding="utf-8") != arquivos[nome]:
            releitura.append("%s relido difere do gerado" % nome)
        if nome.endswith(".json") and json.loads(caminho.read_text(encoding="utf-8")) != \
                json.loads(arquivos[nome]):
            releitura.append("%s nao reproduz o JSON" % nome)
    if releitura:
        for caminho in temps.values():
            caminho.unlink()
        raise Parada("releitura das saidas falhou", releitura)
    for nome, caminho in temps.items():
        os.replace(caminho, saida / nome)
    print(txt, end="")
    print("saidas em %s: %s" % (rotulo(saida), ", ".join(sorted(arquivos))))
    return 0


# ---------------------------------------------------------------------------
# Texto legivel — so tabelas
# ---------------------------------------------------------------------------
def _v(fr):
    if isinstance(fr, dict):
        return "—" if fr["valor"] is None else "%.4f" % fr["valor"]
    return "—" if fr is None else "%.4f" % fr


def texto_legivel(rel):
    s = io.StringIO()
    w = lambda t="": s.write(t + "\n")
    r0 = rel[FERRAMENTAS[0]]
    w("Cruzamento da versao corrigida — docs/criterios-cruzamento.md, §11")
    w()
    w("matriz-deteccao.csv sha256 %s" % r0["fontes"]["matriz_deteccao"]["sha256"])
    w("pares.csv           sha256 %s" % r0["fontes"]["pares"]["sha256"])
    w("principal: %d CVEs (inalterada %d, trecho %d); sensibilidade: %d"
      % (r0["universo"]["principal"], r0["universo"]["grupos_principal"]["inalterada"],
         r0["universo"]["grupos_principal"]["trecho"], r0["universo"]["sensibilidade"]))
    w("fora da principal (so_remocao): " + ", ".join(r0["universo"]["so_remocao_fora_da_principal"]))
    w()
    cab = "%-10s %4s %4s %4s %4s %4s %4s %4s %9s %9s %9s %9s %9s"
    for titulo, chave in (("PRINCIPAL", "principal"), ("SENSIBILIDADE", "sensibilidade")):
        for nivel in NIVEIS:
            w("%s — %s" % (titulo, nivel))
            w(cab % ("", "VP", "FN", "FP", "VN", "s/a", "nsa", "base", "recall",
                     "precisao", "especif.", "s/a/base", "F1"))
            for f in FERRAMENTAS:
                m = rel[f][chave][nivel]
                w(cab % (f, m["VP"], m["FN"], m["FP"], m["VN"], m["sem_analise"],
                         m["nao_se_aplica_corrigido"], m["base"], _v(m["recall"]),
                         _v(m["precisao"]), _v(m["especificidade"]),
                         _v(m["sem_analise_sobre_base"]), _v(m["f1"])))
            w()
    w("RECALL — sobre os 212 (principal) e sobre os 220 (matriz publicada)")
    w("%-10s %-18s %12s %12s" % ("", "nivel", "212", "220"))
    for f in FERRAMENTAS:
        for nivel in NIVEIS:
            a, b = rel[f]["principal"][nivel]["recall"], rel[f]["recall_sobre_220_publicado"][nivel]
            w("%-10s %-18s %12s %12s" % (f, nivel, "%d/%d" % (a["num"], a["den"]),
                                          "%d/%d" % (b["num"], b["den"])))
    w()
    w("DECOMPOSICAO DO LADO CORRIGIDO POR GRUPO — principal")
    w("%-10s %-18s %-11s %5s %4s %4s %4s %4s" % ("", "nivel", "grupo", "CVEs", "FP", "VN", "s/a", "nsa"))
    for f in FERRAMENTAS:
        for nivel in NIVEIS:
            for grupo in ("inalterada", "trecho"):
                g = rel[f]["decomposicao_por_grupo_principal"][nivel][grupo]
                w("%-10s %-18s %-11s %5d %4d %4d %4d %4d" % (f, nivel, grupo, g["cves"], g["FP"],
                                                            g["VN"], g["sem_analise"], g["nao_se_aplica"]))
    w()
    w("SEM ANALISE NO LADO CORRIGIDO")
    for f in FERRAMENTAS:
        sa = rel[f]["sem_analise"]
        w("%-10s principal %d, sensibilidade %d%s" % (f, len(sa["principal"]), len(sa["sensibilidade"]),
                                                     (": " + ", ".join(sa["sensibilidade"])) if sa["sensibilidade"] else ""))
    w()
    w("LEITURA SECUNDARIA — a do benchmark, sobre os 220")
    w("%-10s %12s %16s %15s %8s %11s" % ("", "reconhecida", "nao_reconhecida", "nao_computavel",
                                         "ausente", "detectados"))
    for f in FERRAMENTAS:
        l = rel[f]["leitura_benchmark"]
        w("%-10s %12d %16d %15d %8d %11d" % (f, l["reconhecida"], l["nao_reconhecida"],
                                             l["nao_computavel"], l["ausente"],
                                             l["detectados_criterio_exato"]))
    w()
    w("s/a = sem analise; nsa = nao se aplica (estrita, primario indefinido); base = universo - nsa;")
    w("especificidade = VN / base; recall = VP / (VP + FN); precisao = VP / (VP + FP).")
    return s.getvalue()


def main(argv=None):
    analisador = argparse.ArgumentParser(description="Aplica a §11: cruzamento da versao corrigida.")
    analisador.add_argument("--saida-dir", help="padrao: results/cruzamento-corrigida/")
    args = analisador.parse_args(argv)
    try:
        return executar(args)
    except Parada as parada:
        print("\nPARADO: %s. Nenhuma saida escrita." % parada.titulo, file=sys.stderr)
        for motivo in parada.motivos[:60]:
            print("  - %s" % motivo, file=sys.stderr)
        if len(parada.motivos) > 60:
            print("  ... e mais %d" % (len(parada.motivos) - 60), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
