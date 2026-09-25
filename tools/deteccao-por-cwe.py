#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deteccao-por-cwe.py — decomposicao da deteccao por categoria de CWE, pelo
criterio da secao 9 de docs/criterios-cruzamento.md.

    python3 tools/deteccao-por-cwe.py [--matriz ARQ] [--distribuicao ARQ]
                                      [--cruzamento-dir DIR] [--saida-dir DIR]

NAO RECOMPUTA DETECCAO. Os acertos por (CVE, ferramenta, nivel) vem de
results/cruzamento/matriz-deteccao.csv, produzida pelo cruza-deteccao.py com
os criterios das secoes 2 a 5; aqui eles so sao reagrupados pela categoria do
CVE. Reimplementar criterio e o erro registrado na secao 12.5 da V10.

CRITERIO (criterios-cruzamento.md, secao 9) — aplicado, nao reinterpretado
  categoria        o gt_cwe_primary do CVE, nunca o CWE do achado, lida de
                   results/por-cwe/distribuicao-primario.csv
  SEM_PRIMARIO     o CVE-2018-16472: entra em 0, 1, 3 e nas generosas; nas
                   estritas nao se aplica, como na matriz
  limiar           K_LIMIAR = 10: taxa e intervalo so com n >= K_LIMIAR;
                   abaixo dele, so contagens; nenhuma linha de agregado
  intervalo        Wilson de 95%, sem correcao de continuidade, z = Z_WILSON

ENTRADAS — todas versionadas, conferidas por sha256
  results/cruzamento/matriz-deteccao.csv    sha256 fixado em SHA_MATRIZ
  results/cruzamento/cruzamento-<f>.json    agregados, segunda fonte das somas
  results/por-cwe/distribuicao-primario.csv sha256 declarado no .txt irmao

SAIDAS — results/por-cwe/deteccao-por-categoria.{csv,txt}, e o texto em
stdout. Deterministicas, sem carimbo de execucao. Escrita atomica com
releitura do CSV antes da promocao, e guarda de entrada fora do repositorio,
ambas reaproveitadas do distribuicao-cwe-primario.py.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.util
import io
import json
import math
import re
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

RAIZ = Path(__file__).resolve().parent.parent
DISTRIBUICAO_PY = RAIZ / "tools" / "distribuicao-cwe-primario.py"

# --- Criterio: docs/criterios-cruzamento.md, secao 9 -----------------------
K_LIMIAR = 10          # secao 9, "O limiar"
Z_WILSON = 1.96        # secao 9, "Incerteza": 95%, sem correcao de continuidade

MATRIZ_PADRAO = RAIZ / "results" / "cruzamento" / "matriz-deteccao.csv"
CRUZAMENTO_DIR_PADRAO = RAIZ / "results" / "cruzamento"
DISTRIBUICAO_PADRAO = RAIZ / "results" / "por-cwe" / "distribuicao-primario.csv"
SAIDA_PADRAO = RAIZ / "results" / "por-cwe"
NOME_CSV = "deteccao-por-categoria.csv"
NOME_TXT = "deteccao-por-categoria.txt"
PREFIXO_TEMP = ".tmp-"

# O sha256 registrado no CLAUDE.md ("Cruzamento SAST — resultados") e em
# csv_da_mesma_execucao de cada cruzamento-<ferramenta>.json.
SHA_MATRIZ = "f80158b730794c3135701a8631e551d89610775562577322b806fcc180452825"

FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
NIVEIS = (("0", "nivel_0"), ("1", "nivel_1"), ("2g", "nivel_2_generosa"),
          ("2e", "nivel_2_estrita"), ("3", "nivel_3"), ("4g", "nivel_4_generosa"),
          ("4e", "nivel_4_estrita"))
ESTRITOS = {"2e", "4e"}
SEM_PRIMARIO = "SEM_PRIMARIO"
PARES = 220

COLUNAS_CSV = ["categoria", "n", "acima_do_limiar", "ferramenta", "nivel", "acertos",
               "base", "nao_se_aplica", "taxa", "wilson_inf", "wilson_sup"]
PREFIXO_SHA_CSV = "csv desta execucao (sha256): "

# Matriz publicada: numeros de documento (CLAUDE.md, "Matriz — acertos /
# nao-acertos / nao se aplica"). (acertos, base, nao_se_aplica).
PUBLICADA = {
    "codeql": {"0": (190, 220, 0), "1": (140, 220, 0), "2g": (126, 220, 0),
               "2e": (124, 219, 1), "3": (101, 220, 0), "4g": (95, 220, 0),
               "4e": (94, 219, 1)},
    "semgrep": {"0": (183, 220, 0), "1": (98, 220, 0), "2g": (48, 220, 0),
                "2e": (46, 219, 1), "3": (25, 220, 0), "4g": (20, 220, 0),
                "4e": (20, 219, 1)},
    "snyk-code": {"0": (132, 220, 0), "1": (45, 220, 0), "2g": (16, 220, 0),
                  "2e": (9, 219, 1), "3": (22, 220, 0), "4g": (10, 220, 0),
                  "4e": (6, 219, 1)},
}

# Os 22 de prototype pollution (CLAUDE.md, secao de proveniencia): os 23 do
# CWE-915 menos o CVE-2019-10745. Tabela "Os 22 de prototype pollution" do
# CLAUDE.md, produzida pelo circularidade-proveniencia.py em 20/09/2026.
PP22 = ("CVE-2018-16487", "CVE-2018-16489", "CVE-2018-16490", "CVE-2018-16491",
        "CVE-2018-16492", "CVE-2018-3719", "CVE-2018-3721", "CVE-2018-3722",
        "CVE-2018-3728", "CVE-2018-3750", "CVE-2018-3752", "CVE-2019-10746",
        "CVE-2019-10747", "CVE-2019-10750", "CVE-2019-11358", "CVE-2020-15256",
        "CVE-2020-5258", "CVE-2020-7638", "CVE-2020-7699", "CVE-2020-7720",
        "CVE-2020-8116", "CVE-2020-8203")
PP22_PUBLICADO = {"codeql": {"1": 17, "2e": 16, "3": 14, "4e": 13},
                  "semgrep": {"1": 12, "2e": 11, "3": 1, "4e": 1},
                  "snyk-code": {"1": 1, "2e": 0, "3": 0, "4e": 0}}

SEM_ARQUIVO = ("CVE-2018-16479", "CVE-2018-16480", "CVE-2018-3731", "CVE-2018-3747",
               "CVE-2019-5423")

# Valores de referencia do Wilson, fornecidos no enunciado da fase 1 e
# conferidos por bissecao na equacao do score (wilson_por_bissecao).
WILSON_REFERENCIA = {(0, 23): (0.0000, 0.1431), (23, 23): (0.8569, 1.0000),
                     (10, 20): (0.2993, 0.7007)}
TOLERANCIA_REF = 1e-4
N_MAX_PROPRIEDADE = 47

# O que a secao 9 afirma sobre o corte (numeros de documento, conferencia 7).
ACIMA_DO_LIMIAR_DOC = ("CWE-079", "CWE-022", "CWE-400", "CWE-078", "CWE-915", "CWE-094")
CVES_ACIMA_DOC = 164
CATEGORIAS_ABAIXO_DOC = 22
CVES_ABAIXO_DOC = 56
_RE_CATEGORIA = re.compile(r"CWE-[0-9]{3,}")


class Parada(Exception):
    def __init__(self, titulo, motivos, escrita_parcial=False):
        super().__init__(titulo)
        self.titulo = titulo
        self.motivos = list(motivos)
        # Verdadeiro so quando o CSV novo ja foi promovido e o .txt nao.
        self.escrita_parcial = escrita_parcial


def importar(nome, caminho):
    spec = importlib.util.spec_from_file_location(nome, caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


DIST = importar("distribuicao_cwe_primario", DISTRIBUICAO_PY)
rotulo = DIST.rotulo
sha256_arquivo = DIST.sha256_arquivo
entradas_fora = DIST.entradas_fora


# ---------------------------------------------------------------------------
# Wilson
# ---------------------------------------------------------------------------
def wilson(x, n, z=Z_WILSON):
    """Intervalo de Wilson, sem correcao de continuidade.

    O limite inferior vem da forma racionalizada, que e exatamente 0 em x = 0
    (a forma centro - meia-largura da -1e-17 ali); o superior, da forma
    direta, que e exatamente 1 em x = n. As duas sao independentes, de modo
    que a propriedade do espelho, na conferencia 6, nao vale por construcao.
    """
    s = math.sqrt(z * z + 4.0 * x * (n - x) / n)
    inf = 4.0 * x * x * (1.0 + z * z / n) / (2.0 * (n + z * z) * (2.0 * x + z * z + z * s))
    sup = (2.0 * x + z * z + z * s) / (2.0 * (n + z * z))
    return inf, sup


def wald(x, n, z=Z_WILSON):
    """So para o controle positivo da conferencia 6."""
    p = x / n
    m = z * math.sqrt(p * (1 - p) / n)
    return p - m, p + m


def wilson_por_bissecao(x, n, z=Z_WILSON):
    """Raizes de (x/n - p)^2 = z^2 p (1 - p) / n, por bissecao: outro metodo."""
    p0 = x / n

    def f(p):
        return (p0 - p) ** 2 - z * z * p * (1 - p) / n

    def raiz(lo, hi, crescente_para_dentro):
        if f(lo if crescente_para_dentro else hi) <= 0:
            return lo if crescente_para_dentro else hi
        for _ in range(200):
            meio = (lo + hi) / 2
            if (f(meio) > 0) == crescente_para_dentro:
                lo = meio
            else:
                hi = meio
        return (lo + hi) / 2

    return raiz(0.0, p0, True), raiz(p0, 1.0, False)


def conferir_wilson(funcao):
    """Conferencia 6: referencias, bissecao e propriedades, sobre `funcao`."""
    motivos = []
    for (x, n), (ref_inf, ref_sup) in sorted(WILSON_REFERENCIA.items()):
        inf, sup = funcao(x, n)
        if abs(inf - ref_inf) > TOLERANCIA_REF or abs(sup - ref_sup) > TOLERANCIA_REF:
            motivos.append("6.ref %d/%d: [%.6f, %.6f], esperado [%.4f, %.4f]"
                           % (x, n, inf, sup, ref_inf, ref_sup))
    if funcao(0, 23)[0] != 0.0:
        motivos.append("6.borda 0/23: limite inferior %r, nao exatamente 0" % funcao(0, 23)[0])
    if funcao(23, 23)[1] != 1.0:
        motivos.append("6.borda 23/23: limite superior %r, nao exatamente 1" % funcao(23, 23)[1])
    for n in range(1, N_MAX_PROPRIEDADE + 1):
        for x in range(0, n + 1):
            inf, sup = funcao(x, n)
            if not (0.0 <= inf <= 1.0 and 0.0 <= sup <= 1.0):
                motivos.append("6.intervalo %d/%d fora de [0, 1]: [%r, %r]" % (x, n, inf, sup))
            if not (inf <= x / n <= sup):
                motivos.append("6.contem %d/%d nao contem x/n: [%r, %r]" % (x, n, inf, sup))
            e_inf, e_sup = funcao(n - x, n)
            if abs(inf - (1 - e_sup)) > 1e-12 or abs(sup - (1 - e_inf)) > 1e-12:
                motivos.append("6.espelho %d/%d nao e espelho de %d/%d" % (x, n, n - x, n))
            b_inf, b_sup = wilson_por_bissecao(x, n)
            if abs(inf - b_inf) > 1e-9 or abs(sup - b_sup) > 1e-9:
                motivos.append("6.bissecao %d/%d diverge da bissecao: [%r, %r] x [%r, %r]"
                               % (x, n, inf, sup, b_inf, b_sup))
    return motivos


# ---------------------------------------------------------------------------
# Entradas
# ---------------------------------------------------------------------------
def ler_distribuicao(caminho):
    """[(categoria, n, [cves])] na ordem do arquivo."""
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != DIST.COLUNAS_CSV:
            raise Parada("distribuicao-primario.csv fora de forma",
                         ["cabecalho %r" % leitor.fieldnames])
        return [(r["gt_cwe_primary"], int(r["n"]), r["cves"].split("|")) for r in leitor]


def ler_matriz(caminho):
    """{(cve, ferramenta): linha}. A forma e conferida por conferir_forma_matriz."""
    motivos, matriz = [], {}
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        for linha in csv.DictReader(arquivo):
            chave = (linha["cve"], linha["ferramenta"])
            if chave in matriz:
                motivos.append("0 matriz: %s %s repetido" % chave)
            matriz[chave] = linha
    return matriz, motivos


def conferir_forma_matriz(matriz):
    """0: no denominador, todo nivel e 'true' ou 'false'; vazio so na estrita
    com estrita_aplicavel == 'false'. Qualquer outra grafia ('TRUE', '1') e
    parada: apurar() conta so o literal 'true'."""
    motivos = []
    for chave in sorted(matriz):
        linha = matriz[chave]
        if linha["no_denominador"] != "true":
            continue
        for codigo, coluna in NIVEIS:
            valor = linha[coluna]
            if valor in ("true", "false"):
                continue
            if valor == "" and codigo in ESTRITOS and linha["estrita_aplicavel"] == "false":
                continue
            motivos.append("0 matriz: %s %s %s = %r" % (chave[0], chave[1], coluna, valor))
    return motivos


def ler_agregados(diretorio):
    agregados, shas = {}, {}
    for f in FERRAMENTAS:
        with open(Path(diretorio) / ("cruzamento-%s.json" % f), encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        agregados[f] = dados["agregados"]
        shas[f] = dados["csv_da_mesma_execucao"]["sha256"]
    return agregados, shas


# ---------------------------------------------------------------------------
# Apuracao — so reagrupamento
# ---------------------------------------------------------------------------
def apurar(categorias, matriz):
    """{(categoria, ferramenta, nivel): (acertos, base, nao_se_aplica)}."""
    celulas = {}
    for categoria, _, cves in categorias:
        for f in FERRAMENTAS:
            for codigo, coluna in NIVEIS:
                acertos = base = nsa = 0
                for cve in cves:
                    valor = matriz[(cve, f)][coluna]
                    if valor == "":
                        nsa += 1
                        continue
                    base += 1
                    acertos += valor == "true"
                celulas[(categoria, f, codigo)] = (acertos, base, nsa)
    return celulas


def somar(celulas):
    soma = {}
    for (_, f, codigo), (a, b, s) in celulas.items():
        x = soma.get((f, codigo), (0, 0, 0))
        soma[(f, codigo)] = (x[0] + a, x[1] + b, x[2] + s)
    return soma


def montar_linhas(categorias, celulas, funcao_ic=wilson):
    linhas = []
    for categoria, n, _ in categorias:
        acima = categoria != SEM_PRIMARIO and n >= K_LIMIAR
        for f in FERRAMENTAS:
            for codigo, _ in NIVEIS:
                a, b, s = celulas[(categoria, f, codigo)]
                taxa = inf = sup = ""
                if acima:
                    lo, hi = funcao_ic(a, b)
                    taxa, inf, sup = "%.4f" % (a / b), "%.4f" % lo, "%.4f" % hi
                linhas.append({"categoria": categoria, "n": str(n),
                               "acima_do_limiar": "sim" if acima else "nao",
                               "ferramenta": f, "nivel": codigo, "acertos": str(a),
                               "base": str(b), "nao_se_aplica": str(s), "taxa": taxa,
                               "wilson_inf": inf, "wilson_sup": sup})
    return linhas


# ---------------------------------------------------------------------------
# Conferencias — funcoes puras, exercidas pelo controle positivo
# ---------------------------------------------------------------------------
def conferir_proveniencia(sha_matriz, shas_json, sha_dist, sha_dist_declarado):
    """1: sha256 da matriz (esperado e o de cada JSON) e da distribuicao."""
    motivos = []
    if sha_matriz != SHA_MATRIZ:
        motivos.append("1 matriz com sha256 %s, esperado %s" % (sha_matriz, SHA_MATRIZ))
    for f in FERRAMENTAS:
        if shas_json.get(f) != sha_matriz:
            motivos.append("1 cruzamento-%s.json declara matriz %s, a lida e %s"
                           % (f, shas_json.get(f), sha_matriz))
    if sha_dist_declarado != [sha_dist]:
        motivos.append("1 distribuicao-primario.csv com sha256 %s, o .txt declara %s"
                       % (sha_dist, sha_dist_declarado or "nenhum"))
    return motivos


def conferir_universo(categorias, matriz):
    """2: denominador da matriz por ferramenta == os 220 da distribuicao, e o
    gt_cwe_primary da matriz == a categoria da distribuicao, CVE a CVE."""
    motivos = []
    categoria_de = {}
    for categoria, n, cves in categorias:
        if len(cves) != n:
            motivos.append("2 distribuicao: %s com n %d e %d CVEs" % (categoria, n, len(cves)))
        for cve in cves:
            if cve in categoria_de:
                motivos.append("2 distribuicao: %s em duas categorias" % cve)
            categoria_de[cve] = categoria
    if len(categoria_de) != PARES:
        motivos.append("2 distribuicao com %d CVEs, esperados %d" % (len(categoria_de), PARES))
    for f in FERRAMENTAS:
        no_den = {cve for (cve, ff), l in matriz.items() if ff == f and l["no_denominador"] == "true"}
        for cve in sorted(no_den - set(categoria_de)):
            motivos.append("2 %s: %s no denominador da matriz e fora da distribuicao" % (f, cve))
        for cve in sorted(set(categoria_de) - no_den):
            motivos.append("2 %s: %s da distribuicao fora do denominador da matriz" % (f, cve))
        for cve in sorted(no_den & set(categoria_de)):
            primario = matriz[(cve, f)]["gt_cwe_primary"] or SEM_PRIMARIO
            if primario != categoria_de[cve]:
                motivos.append("2 %s: %s gt_cwe_primary %s na matriz, %s na distribuicao"
                               % (f, cve, primario, categoria_de[cve]))
    return motivos


def conferir_reconstrucao(celulas, agregados):
    """3: a soma das categorias == matriz publicada (documento) e == agregados
    de cada cruzamento-<f>.json. LIMITE: deslocar um acerto entre categorias
    sem mudar o total passa por aqui."""
    motivos = []
    soma = somar(celulas)
    for f in FERRAMENTAS:
        for codigo, coluna in NIVEIS:
            obtido = soma[(f, codigo)]
            if obtido != PUBLICADA[f][codigo]:
                motivos.append("3 %s nivel %s: soma %s, publicado %s"
                               % (f, codigo, obtido, PUBLICADA[f][codigo]))
            ag = agregados[f][coluna]
            do_json = (ag["acertos"], ag["acertos"] + ag["nao_acertos"], ag.get("nao_se_aplica", 0))
            if obtido != do_json:
                motivos.append("3 %s nivel %s: soma %s, cruzamento-%s.json %s"
                               % (f, codigo, obtido, f, do_json))
    # 3c: a estrita nunca acerta mais que a generosa, em celula alguma.
    for (categoria, f, codigo), (a, _, _) in sorted(celulas.items()):
        if codigo in ESTRITOS:
            generosa = celulas[(categoria, f, codigo[0] + "g")][0]
            if a > generosa:
                motivos.append("3c %s %s nivel %s: estrita %d > generosa %d"
                               % (categoria, f, codigo, a, generosa))
    return motivos


def conferir_pp22(categorias, matriz, pp22=PP22):
    """4: o recorte dos 22 dentro do CWE-915 reproduz a tabela publicada."""
    motivos = []
    cwe915 = next((cves for c, _, cves in categorias if c == "CWE-915"), [])
    esperado = sorted(set(cwe915) - {"CVE-2019-10745"})
    if esperado != sorted(pp22):
        motivos.append("4 os 22 nao sao o CWE-915 menos CVE-2019-10745: %s"
                       % sorted(set(esperado) ^ set(pp22)))
    coluna = dict(NIVEIS)
    for f in FERRAMENTAS:
        for codigo, publicado in sorted(PP22_PUBLICADO[f].items()):
            obtido = sum(matriz[(cve, f)][coluna[codigo]] == "true" for cve in pp22)
            if obtido != publicado:
                motivos.append("4 %s nivel %s nos 22: %d, publicado %d" % (f, codigo, obtido, publicado))
    return motivos


def conferir_sem_arquivo(categorias, matriz):
    """5: os cinco SEM_ARQUIVO_ANALISAVEL estao no denominador e nao acertam
    nivel algum no Snyk Code. Devolve (motivos, {cve: categoria})."""
    motivos, onde = [], {}
    categoria_de = {cve: c for c, _, cves in categorias for cve in cves}
    for cve in SEM_ARQUIVO:
        linha = matriz.get((cve, "snyk-code"))
        if cve not in categoria_de or linha is None or linha["no_denominador"] != "true":
            motivos.append("5 %s fora do denominador" % cve)
            continue
        onde[cve] = categoria_de[cve]
        if linha["status_campanha"] != "SEM_ARQUIVO_ANALISAVEL":
            motivos.append("5 %s com status %s" % (cve, linha["status_campanha"]))
        for codigo, coluna in NIVEIS:
            if linha[coluna] != "false":
                motivos.append("5 %s nivel %s = %r, esperado false" % (cve, codigo, linha[coluna]))
    com_status = sorted(cve for (cve, f), l in matriz.items()
                        if l["status_campanha"] == "SEM_ARQUIVO_ANALISAVEL")
    if com_status != sorted(SEM_ARQUIVO):
        motivos.append("5 SEM_ARQUIVO_ANALISAVEL na matriz: %s, esperados %s"
                       % (com_status, sorted(SEM_ARQUIVO)))
    return motivos, onde


def conferir_limiar(linhas):
    """7: taxa e Wilson preenchidos exatamente nas categorias acima do limiar."""
    motivos = []
    for l in linhas:
        cheio = [l[c] != "" for c in ("taxa", "wilson_inf", "wilson_sup")]
        acima = l["acima_do_limiar"] == "sim"
        if acima != (l["categoria"] != SEM_PRIMARIO and int(l["n"]) >= K_LIMIAR):
            motivos.append("7 %s: acima_do_limiar %s com n %s" % (l["categoria"], l["acima_do_limiar"], l["n"]))
        if acima and not all(cheio):
            motivos.append("7 %s %s %s: taxa ou intervalo vazio acima do limiar"
                           % (l["categoria"], l["ferramenta"], l["nivel"]))
        if not acima and any(cheio):
            motivos.append("7 %s %s %s: taxa ou intervalo abaixo do limiar"
                           % (l["categoria"], l["ferramenta"], l["nivel"]))
    # Toda linha e de uma categoria: CWE-<n> ou SEM_PRIMARIO. Pega agregado
    # com qualquer grafia ("outros", "Outros", "total"), e nao so as listadas.
    n_de = {}
    for l in linhas:
        if l["categoria"] != SEM_PRIMARIO and not _RE_CATEGORIA.fullmatch(l["categoria"]):
            motivos.append("7 linha que nao e categoria: %r" % l["categoria"])
        n_de[l["categoria"]] = int(l["n"])
    # O corte conferido contra o que a secao 9 afirma, e nao so contra si.
    # Ordem de aparicao: a da distribuicao, n decrescente, como na secao 9.
    acima = [c for c in n_de if c != SEM_PRIMARIO and n_de[c] >= K_LIMIAR]
    abaixo = [c for c in n_de if c not in acima]
    if acima != list(ACIMA_DO_LIMIAR_DOC):
        motivos.append("7 acima do limiar %s, a secao 9 diz %s" % (acima, list(ACIMA_DO_LIMIAR_DOC)))
    if sum(n_de[c] for c in acima) != CVES_ACIMA_DOC:
        motivos.append("7 %d CVEs acima do limiar, a secao 9 diz %d"
                       % (sum(n_de[c] for c in acima), CVES_ACIMA_DOC))
    if len(abaixo) != CATEGORIAS_ABAIXO_DOC or sum(n_de[c] for c in abaixo) != CVES_ABAIXO_DOC:
        motivos.append("7 abaixo do limiar: %d categorias e %d CVEs, a secao 9 diz %d e %d"
                       % (len(abaixo), sum(n_de[c] for c in abaixo),
                          CATEGORIAS_ABAIXO_DOC, CVES_ABAIXO_DOC))
    return motivos


def conferir_arquivo(caminho, linhas, n_categorias):
    """8: releitura do CSV gravado — forma, 588 linhas, cada celula == memoria."""
    motivos = []
    esperado_linhas = n_categorias * len(FERRAMENTAS) * len(NIVEIS)
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != COLUNAS_CSV:
            return ["8 cabecalho %r, esperado %r" % (leitor.fieldnames, COLUNAS_CSV)]
        lidas = list(leitor)
    for numero, registro in enumerate(lidas, 2):
        if None in registro or None in registro.values():
            motivos.append("8 linha %d: numero de campos diferente do cabecalho" % numero)
    if len(lidas) != esperado_linhas:
        motivos.append("8 %d linhas, esperadas %d" % (len(lidas), esperado_linhas))
    if len(linhas) != esperado_linhas:
        motivos.append("8 memoria com %d linhas, esperadas %d" % (len(linhas), esperado_linhas))
    for numero, (lido, memoria) in enumerate(zip(lidas, linhas), 2):
        for coluna in COLUNAS_CSV:
            if lido.get(coluna) != memoria[coluna]:
                motivos.append("8 linha %d coluna %s: arquivo %r, memoria %r"
                               % (numero, coluna, lido.get(coluna), memoria[coluna]))
    return motivos


# ---------------------------------------------------------------------------
# Controle positivo (conferencia 9)
# ---------------------------------------------------------------------------
def gerar_csv(linhas):
    saida = io.StringIO()
    escritor = csv.DictWriter(saida, fieldnames=COLUNAS_CSV, lineterminator="\n")
    escritor.writeheader()
    escritor.writerows(linhas)
    return saida.getvalue()


def _deslocar(matriz, f, coluna, de, para):
    """Move um acerto de `de` para `para` (mesma ferramenta, mesmo nivel)."""
    m = copy.deepcopy(matriz)
    assert m[(de, f)][coluna] == "true" and m[(para, f)][coluna] == "false"
    m[(de, f)][coluna], m[(para, f)][coluna] = "false", "true"
    return m


def controle_positivo(categorias, matriz, agregados, shas, sha_dist, linhas, n_cat):
    """Cada mutante tem de disparar a conferencia pretendida.

    Devolve [(nome, pretendida, disparou, conferencias que dispararam)]. Nos
    mutantes de deslocamento o esperado e o SILENCIO da 3; e o limite dela.
    """
    resultados = []

    def rodar(m_cat=categorias, m_mat=matriz, m_ag=agregados, m_shas=shas,
              m_sha_mat=SHA_MATRIZ, m_sha_dist=(sha_dist, [sha_dist])):
        cel = apurar(m_cat, m_mat)
        motivos = (conferir_proveniencia(m_sha_mat, m_shas, *m_sha_dist)
                   + conferir_forma_matriz(m_mat)
                   + conferir_universo(m_cat, m_mat)
                   + conferir_reconstrucao(cel, m_ag)
                   + conferir_pp22(m_cat, m_mat)
                   + conferir_sem_arquivo(m_cat, m_mat)[0])
        return sorted({m.split(" ", 1)[0] for m in motivos})

    def registra(nome, pretendida, disparadas, exato=False):
        ok = disparadas == [pretendida] if exato else pretendida in disparadas
        resultados.append((nome, pretendida, ok, disparadas))

    categoria_de = {cve: c for c, _, cves in categorias for cve in cves}

    def primeiro(f, coluna, valor, categoria, excluir=()):
        cve = next((cve for cve in sorted(categoria_de) if categoria_de[cve] == categoria
                    and cve not in excluir and matriz[(cve, f)][coluna] == valor), None)
        if cve is None:
            raise Parada("controle positivo sem candidato",
                         ["%s %s = %s em %s" % (f, coluna, valor, categoria)])
        return cve

    def itens(motivos):
        return sorted({m.split(" ", 1)[0] for m in motivos})

    # 0 — forma da matriz
    alvo0 = primeiro("semgrep", "nivel_1", "true", "CWE-079")
    m = copy.deepcopy(matriz); m[(alvo0, "semgrep")]["nivel_1"] = "TRUE"
    registra("0: nivel grafado TRUE na matriz", "0", rodar(m_mat=m))

    # 1 — proveniencia
    registra("1: matriz com outro sha256", "1", rodar(m_sha_mat="0" * 64), exato=True)
    registra("1: json declara outra matriz", "1",
             rodar(m_shas={**shas, "semgrep": "0" * 64}), exato=True)
    registra("1: distribuicao difere do .txt", "1",
             rodar(m_sha_dist=(sha_dist, ["0" * 64])), exato=True)

    # 2 — universo
    alvo = primeiro("codeql", "nivel_0", "false", "CWE-079")
    m = copy.deepcopy(matriz); m[(alvo, "codeql")]["no_denominador"] = "false"
    registra("2: CVE fora do denominador da matriz no codeql", "2", rodar(m_mat=m))
    m = copy.deepcopy(matriz); m[(alvo, "semgrep")]["gt_cwe_primary"] = "CWE-022"
    registra("2: gt_cwe_primary divergente na matriz", "2", rodar(m_mat=m), exato=True)
    m_cat = [(c, n + (1 if c == "CWE-601" else 0), cves) for c, n, cves in categorias]
    registra("2: distribuicao com n diferente da lista", "2", rodar(m_cat=m_cat), exato=True)
    m_cat = [(c, n, cves + ([alvo] if c == "CWE-022" else [])) for c, n, cves in categorias]
    registra("2: CVE em duas categorias da distribuicao", "2", rodar(m_cat=m_cat))

    # 3 — reconstrucao: um acerto a mais muda o total
    m = copy.deepcopy(matriz); m[(alvo, "codeql")]["nivel_0"] = "true"
    registra("3: acerto acrescentado no codeql nivel 0", "3", rodar(m_mat=m), exato=True)
    ag = copy.deepcopy(agregados); ag["snyk-code"]["nivel_3"]["acertos"] += 1
    registra("3: agregado do json alterado", "3", rodar(m_ag=ag), exato=True)
    alvo3c = primeiro("snyk-code", "nivel_2_generosa", "false", "CWE-079")
    m = copy.deepcopy(matriz); m[(alvo3c, "snyk-code")]["nivel_2_estrita"] = "true"
    registra("3c: estrita acerta onde a generosa nao", "3c", rodar(m_mat=m))

    # 3 — LIMITE: deslocamento entre categorias, total mantido, fora dos 22
    de = primeiro("codeql", "nivel_1", "true", "CWE-079")
    para = primeiro("codeql", "nivel_1", "false", "CWE-022")
    desl = rodar(m_mat=_deslocar(matriz, "codeql", "nivel_1", de, para))
    resultados.append(("3 limite: acerto deslocado CWE-079 -> CWE-022, fora dos 22",
                       "nenhuma", desl == [], desl))
    # ... e dentro dos 22: a 4 pega o que a 3 nao pega
    de = primeiro("codeql", "nivel_1", "true", "CWE-915", excluir=("CVE-2019-10745",))
    para = primeiro("codeql", "nivel_1", "false", "CWE-079")
    registra("3 limite: acerto deslocado de um dos 22 para CWE-079", "4",
             rodar(m_mat=_deslocar(matriz, "codeql", "nivel_1", de, para)), exato=True)

    # 4 — os 22, com a 3 disparando junto (muda o total)
    m = copy.deepcopy(matriz); m[(PP22[0], "snyk-code")]["nivel_3"] = "true"
    registra("4: um dos 22 passa a acertar nivel 3 no snyk", "4", rodar(m_mat=m))
    lista = ("CVE-2019-10745",) + PP22[1:]
    registra("4: lista dos 22 com o CVE-2019-10745 no lugar de um deles", "4",
             itens(conferir_pp22(categorias, matriz, pp22=lista)))

    # 5 — SEM_ARQUIVO_ANALISAVEL
    m = copy.deepcopy(matriz); m[(SEM_ARQUIVO[0], "snyk-code")]["nivel_0"] = "true"
    registra("5: SEM_ARQUIVO com acerto no snyk", "5", rodar(m_mat=m))
    m = copy.deepcopy(matriz); m[(SEM_ARQUIVO[1], "snyk-code")]["status_campanha"] = "OK"
    registra("5: SEM_ARQUIVO com outro status", "5", rodar(m_mat=m), exato=True)
    m = copy.deepcopy(matriz); m[(alvo, "snyk-code")]["status_campanha"] = "SEM_ARQUIVO_ANALISAVEL"
    registra("5: sexto CVE com SEM_ARQUIVO_ANALISAVEL", "5", rodar(m_mat=m), exato=True)

    # 6 — um mutante por subitem da conferencia 6
    def ingenuo(x, n, z=Z_WILSON):
        p = x / n
        d = 1 + z * z / n
        c = (p + z * z / (2 * n)) / d
        h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
        return c - h, c + h

    def deslocado(x, n):
        inf, sup = wilson(x, n)
        return (inf, sup) if x == 0 else (min(x / n + 1e-3, sup), sup)

    def assimetrico(x, n):
        inf, sup = wilson(x, n)
        return inf, sup if x == n else sup * (1 - 1e-6)

    def fora(x, n):
        inf, sup = wilson(x, n)
        return (inf, sup) if x != 1 else (inf - 0.5, sup)

    registra("6.ref: Wald no lugar de Wilson", "6.ref", itens(conferir_wilson(wald)))
    registra("6.borda: forma centro - meia-largura (-1e-17 em 0/n)", "6.borda",
             itens(conferir_wilson(ingenuo)))
    registra("6.intervalo: limite inferior abaixo de 0 em 1/n", "6.intervalo",
             itens(conferir_wilson(fora)))
    registra("6.contem: limite inferior acima de x/n", "6.contem", itens(conferir_wilson(deslocado)))
    registra("6.espelho: limite superior encolhido", "6.espelho", itens(conferir_wilson(assimetrico)))
    registra("6.bissecao: limite superior encolhido", "6.bissecao",
             itens(conferir_wilson(assimetrico)))

    # 7 — limiar
    m = copy.deepcopy(linhas)
    abaixo = next(l for l in m if l["acima_do_limiar"] == "nao")
    abaixo["taxa"] = "0.5000"
    registra("7: taxa abaixo do limiar", "7", sorted({x.split(" ")[0] for x in conferir_limiar(m)}))
    m = copy.deepcopy(linhas); m[0]["wilson_sup"] = ""
    registra("7: intervalo vazio acima do limiar", "7",
             sorted({x.split(" ")[0] for x in conferir_limiar(m)}))
    m = copy.deepcopy(linhas) + [dict(linhas[-1], categoria="Outros")]
    registra("7: linha de agregado 'Outros'", "7", itens(conferir_limiar(m)))
    m = copy.deepcopy(linhas)
    for l in m:
        if l["categoria"] == "CWE-116":
            l.update(n="10", acima_do_limiar="sim", taxa="0.5000", wilson_inf="0.2", wilson_sup="0.8")
    registra("7: CWE-116 com n 10, coerente consigo mas nao com a secao 9", "7",
             itens(conferir_limiar(m)), exato=True)

    # 8 — arquivo: mutantes gravados e relidos
    texto = gerar_csv(linhas)
    mutantes = []
    regs = list(csv.reader(io.StringIO(texto)))
    r = [list(x) for x in regs]; r[0][COLUNAS_CSV.index("taxa")] = "tx"
    mutantes.append(("8: cabecalho alterado", r))
    r = [list(x) for x in regs]; r[5][COLUNAS_CSV.index("acertos")] = str(int(r[5][COLUNAS_CSV.index("acertos")]) + 1)
    mutantes.append(("8: celula de acertos alterada no arquivo", r))
    r = [list(x) for x in regs][:-1]
    mutantes.append(("8: ultima linha removida", r))
    r = [list(x) for x in regs]; r[3] = r[3] + ["excedente"]
    mutantes.append(("8: campo excedente", r))
    with tempfile.TemporaryDirectory(prefix="deteccao-c8-") as diretorio:
        for indice, (nome, regs_m) in enumerate(mutantes):
            caminho = Path(diretorio) / ("m%d.csv" % indice)
            with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
                csv.writer(arquivo, lineterminator="\n").writerows(regs_m)
            registra(nome, "8", sorted({x.split(" ")[0] for x in conferir_arquivo(caminho, linhas, n_cat)}))
    return resultados


# ---------------------------------------------------------------------------
# Texto
# ---------------------------------------------------------------------------
def gerar_txt(categorias, celulas, linhas, fontes_desc, conferencias, onde_sem_arquivo, sha_csv):
    out = []
    w = out.append
    w("Deteccao por categoria de CWE (criterios-cruzamento.md, secao 9)")
    w("Reagrupamento da matriz publicada; nenhuma deteccao recomputada.")
    w("Categoria = gt_cwe_primary do CVE. Limiar k = %d. Wilson 95%%, sem correcao"
      " de continuidade, z = %.2f, so acima do limiar." % (K_LIMIAR, Z_WILSON))
    w("")
    w("  " + PREFIXO_SHA_CSV + sha_csv)
    w("")
    w("Fontes (caminho relativo ao repositorio, sha256):")
    for nome, caminho, digest in fontes_desc:
        w("  %-13s %s  %s" % (nome, caminho, digest))
    w("")
    w("Conferencias:")
    for nome, estado in conferencias:
        w("  %-70s %s" % (nome, estado))
    w("")
    w("SEM_ARQUIVO_ANALISAVEL do Snyk Code, por categoria:")
    for cve in SEM_ARQUIVO:
        w("  %s  %s" % (cve, onde_sem_arquivo[cve]))
    w("")
    acima = [c for c, n, _ in categorias if c != SEM_PRIMARIO and n >= K_LIMIAR]
    abaixo = [c for c, n, _ in categorias if c not in acima]
    n_de = {c: n for c, n, _ in categorias}
    w("ACIMA DO LIMIAR (n >= %d): acertos/base  taxa  [wilson_inf, wilson_sup]" % K_LIMIAR)
    por_chave = {(l["categoria"], l["ferramenta"], l["nivel"]): l for l in linhas}
    for f in FERRAMENTAS:
        w("")
        w("  %s" % f)
        w("  %-9s %-5s %-9s %-7s %s" % ("categoria", "nivel", "a/base", "taxa", "IC 95%"))
        for c in acima:
            for codigo, _ in NIVEIS:
                l = por_chave[(c, f, codigo)]
                w("  %-9s %-5s %-9s %-7s [%s, %s]" % (
                    "%s" % c if codigo == "0" else "", codigo,
                    "%s/%s" % (l["acertos"], l["base"]), l["taxa"], l["wilson_inf"], l["wilson_sup"]))
        w("  (n: %s)" % ", ".join("%s %d" % (c, n_de[c]) for c in acima))
    w("")
    w("ABAIXO DO LIMIAR: so contagens, acertos/base; sem total")
    niveis = [codigo for codigo, _ in NIVEIS]
    for f in FERRAMENTAS:
        w("")
        w("  %s" % f)
        w("  %-13s %3s  " % ("categoria", "n") + " ".join("%7s" % c for c in niveis))
        for c in abaixo:
            celulas_txt = []
            for codigo in niveis:
                a, b, s = celulas[(c, f, codigo)]
                celulas_txt.append("%7s" % ("n.s.a." if b == 0 else "%d/%d" % (a, b)))
            w("  %-13s %3d  " % (c, n_de[c]) + " ".join(celulas_txt))
    w("")
    w("DIFERENCA ENTRE VARIANTES, em acertos: generosa - estrita")
    w("  %-13s %3s  " % ("", "") + " | ".join("%-13s" % f for f in FERRAMENTAS))
    w("  %-13s %3s  " % ("categoria", "n") + " | ".join("%6s %6s" % ("2g-2e", "4g-4e")
                                                       for _ in FERRAMENTAS))
    for c, n, _ in categorias:
        partes = []
        for f in FERRAMENTAS:
            par = []
            for g, e in (("2g", "2e"), ("4g", "4e")):
                ag = celulas[(c, f, g)][0]
                ae, be, _ = celulas[(c, f, e)]
                par.append("n.s.a." if be == 0 else "%d" % (ag - ae))
            partes.append("%6s %6s" % tuple(par))
        w("  %-13s %3d  " % (c, n) + " | ".join(partes))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
def executar(args):
    matriz_caminho = Path(args.matriz) if args.matriz else MATRIZ_PADRAO
    dist_caminho = Path(args.distribuicao) if args.distribuicao else DISTRIBUICAO_PADRAO
    cruz_dir = Path(args.cruzamento_dir) if args.cruzamento_dir else CRUZAMENTO_DIR_PADRAO
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO
    dist_txt = dist_caminho.with_name(DIST.NOME_TXT)
    jsons = [cruz_dir / ("cruzamento-%s.json" % f) for f in FERRAMENTAS]

    fora = entradas_fora(saida, [matriz_caminho, dist_caminho, dist_txt, cruz_dir] + jsons)
    if fora:
        raise Parada("saida dentro do repositorio exige entradas dentro dele: "
                     "o caminho de fora iria para o .txt", fora)
    faltando = [str(c) for c in [matriz_caminho, dist_caminho, dist_txt] + jsons if not c.is_file()]
    if faltando:
        raise Parada("entradas ausentes", faltando)

    # 1 — proveniencia, antes de ler a matriz e a distribuicao
    sha_mat = sha256_arquivo(matriz_caminho)
    sha_dist = sha256_arquivo(dist_caminho)
    declarado = [linha[len("  " + DIST.PREFIXO_SHA_CSV):] for linha
                 in dist_txt.read_text(encoding="utf-8").splitlines()
                 if linha.startswith("  " + DIST.PREFIXO_SHA_CSV)]
    try:
        agregados, shas_json = ler_agregados(cruz_dir)
    except (OSError, ValueError, KeyError, TypeError) as erro:
        raise Parada("cruzamento-<ferramenta>.json ilegivel", ["%s: %s" % (type(erro).__name__, erro)])
    c1 = conferir_proveniencia(sha_mat, shas_json, sha_dist, declarado)
    if c1:
        raise Parada("conferencia 1 (proveniencia das entradas)", c1)

    categorias = ler_distribuicao(dist_caminho)
    matriz, repetidos = ler_matriz(matriz_caminho)
    c0 = repetidos + conferir_forma_matriz(matriz)
    if c0:
        raise Parada("conferencia 0 (forma da matriz)", c0)

    c2 = conferir_universo(categorias, matriz)
    if c2:
        raise Parada("conferencia 2 (mesmo universo)", c2)

    celulas = apurar(categorias, matriz)
    linhas = montar_linhas(categorias, celulas)
    n_cat = len(categorias)

    c5, onde_sem_arquivo = conferir_sem_arquivo(categorias, matriz)
    for titulo, motivos in (("conferencia 3 (reconstrucao da matriz publicada)",
                             conferir_reconstrucao(celulas, agregados)),
                            ("conferencia 4 (os 22 de prototype pollution)",
                             conferir_pp22(categorias, matriz)),
                            ("conferencia 5 (SEM_ARQUIVO_ANALISAVEL)", c5),
                            ("conferencia 6 (Wilson)", conferir_wilson(wilson)),
                            ("conferencia 7 (limiar aplicado)", conferir_limiar(linhas))):
        if motivos:
            raise Parada(titulo, motivos)

    # 9 — controle positivo DEPOIS das conferencias reais: falha nos dados sai
    # com o titulo da conferencia que reprovou, e nao como falha de mutante.
    controle = controle_positivo(categorias, matriz, agregados, shas_json, sha_dist, linhas, n_cat)
    falhas = ["%s: pretendida %s, dispararam %s" % (nome, pret, disp or "nenhuma")
              for nome, pret, ok, disp in controle if not ok]
    if falhas:
        raise Parada("conferencia 9 (controle positivo) falhou", falhas)

    fontes_desc = [
        ("matriz", rotulo(matriz_caminho), sha_mat),
        ("distribuicao", rotulo(dist_caminho), sha_dist),
    ] + [("cruzamento", rotulo(j), sha256_arquivo(j)) for j in jsons] + [
        ("codigo", rotulo(Path(__file__)), sha256_arquivo(__file__)),
        ("codigo", rotulo(DISTRIBUICAO_PY), sha256_arquivo(DISTRIBUICAO_PY)),
    ]
    conferencias = [
        ("0 forma da matriz: niveis 'true'/'false', vazio so na estrita n.s.a.", "OK"),
        ("1 sha256 da matriz (= CLAUDE.md = 3 JSON) e da distribuicao (= .txt)", "OK"),
        ("2 denominador da matriz = 220 da distribuicao, nas 3; primario igual", "OK"),
        ("3 soma das categorias = matriz publicada e = agregados dos 3 JSON (21)", "OK"),
        ("  limite: deslocamento de acerto entre categorias com total mantido", "nao pego pela 3"),
        ("3c estrita <= generosa em toda celula", "OK"),
        ("4 os 22 de prototype pollution = tabela publicada (12 celulas)", "OK"),
        ("5 SEM_ARQUIVO_ANALISAVEL no denominador, nao-acerto em todo nivel", "OK"),
        ("6 Wilson: 3 referencias, bissecao, [0,1], contem x/n, espelho, n<=%d"
         % N_MAX_PROPRIEDADE, "OK"),
        ("7 taxa e IC so acima do limiar; so categorias; corte = secao 9", "OK"),
        ("8 CSV gravado relido (publicado so se aprovado)", "OK"),
        ("9 controle positivo (%d mutantes)" % len(controle), "OK"),
    ]
    for nome, pret, _, disp in controle:
        conferencias.append(("    %s" % nome, "pretendida %s; dispararam %s"
                             % (pret, ",".join(disp) if disp else "nenhuma")))

    tabela_csv = gerar_csv(linhas)
    texto = gerar_txt(categorias, celulas, linhas, fontes_desc, conferencias, onde_sem_arquivo,
                      hashlib.sha256(tabela_csv.encode("utf-8")).hexdigest())

    saida.mkdir(parents=True, exist_ok=True)
    temporarios = {nome: saida / (PREFIXO_TEMP + nome) for nome in (NOME_CSV, NOME_TXT)}
    for temporario in temporarios.values():
        temporario.unlink(missing_ok=True)
    try:
        temporarios[NOME_CSV].write_text(tabela_csv, encoding="utf-8")
        temporarios[NOME_TXT].write_text(texto, encoding="utf-8")
        c8 = conferir_arquivo(temporarios[NOME_CSV], linhas, n_cat)
        if c8:
            raise Parada("conferencia 8 (releitura do CSV gravado)", c8)
        temporarios[NOME_CSV].replace(saida / NOME_CSV)
        try:
            temporarios[NOME_TXT].replace(saida / NOME_TXT)
        except OSError as erro:
            raise Parada("promocao incompleta: CSV novo gravado, .txt anterior no lugar",
                         ["%s: %s" % (type(erro).__name__, erro)], escrita_parcial=True)
    finally:
        for temporario in temporarios.values():
            try:
                temporario.unlink(missing_ok=True)
            except OSError as erro:
                print("AVISO: temporario nao removido: %s: %s" % (temporario, erro), file=sys.stderr)
    sys.stdout.write(texto)
    return 0


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Deteccao por categoria de CWE (criterios-cruzamento.md, secao 9).")
    analisador.add_argument("--matriz", help="padrao: results/cruzamento/matriz-deteccao.csv")
    analisador.add_argument("--distribuicao", help="padrao: results/por-cwe/distribuicao-primario.csv")
    analisador.add_argument("--cruzamento-dir", help="padrao: results/cruzamento/")
    analisador.add_argument("--saida-dir", help="padrao: results/por-cwe/")
    args = analisador.parse_args(argv)
    try:
        return executar(args)
    except Parada as parada:
        if parada.escrita_parcial:
            print("\nPARADO: %s. ESCRITA PARCIAL: o CSV novo foi promovido e o .txt nao; "
                  "o par em disco esta inconsistente." % parada.titulo, file=sys.stderr)
        else:
            print("\nPARADO: %s. Nenhuma saida escrita." % parada.titulo, file=sys.stderr)
        for motivo in parada.motivos:
            print("  - %s" % motivo, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
