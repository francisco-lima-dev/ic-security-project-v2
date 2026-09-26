#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capacidade-empirica.py — capacidade empirica por CWE do achado e delimitacao
por linguagem, pelo criterio da secao 10 de docs/criterios-cruzamento.md.

    python3 tools/capacidade-empirica.py [--treated-root DIR] [--regras ARQ]
                                         [--logs-dir DIR] [--saida-dir DIR]

DESCRITIVO. Mede o que as ferramentas REPORTAM, e nao o que acertam. Nada
aqui cruza com o ground truth: dos tratados le-se, de cada achado, `cwe`,
`file_path` e `rule_id`; do metadata, so `cve_id`, `tool` e, no Snyk Code,
`coverage`. Nenhum campo gt_* e lido.

CRITERIO (criterios-cruzamento.md, secao 10) — aplicado, nao reinterpretado
  eixo        o CWE do achado; achado com varios CWEs conta em cada um;
              achado sem CWE vai para SEM_CWE
  universo    todos os CVEs com tratado: 221 / 221 / 216
  unidades    CVEs com ao menos um achado da categoria (principal) e
              achados (secundaria, com o maior CVE ao lado)
  JS/TS       pela extensao do arquivo do achado (EXT_JS_TS), nas tres; e,
              so no Semgrep, pela linguagem da regra, lida EXCLUSIVAMENTE da
              juncao com results/capacidade/regras-linguagens.csv — nunca do
              prefixo do check_id
  versoes     `todos` e `js_ts_extensao`; a segunda e a principal

EXTENSAO: o sufixo depois do ultimo ponto do NOME do arquivo (o que vem
depois da ultima '/'), em minusculas; sem ponto no nome, ou com o ponto no
fim, nao ha extensao. `x.d.ts` -> ts; `.eslintrc.js` -> js; `bin/public` ->
sem extensao.

ENTRADAS
  results/<f>/treated/*.json                          os achados
  results/capacidade/regras-linguagens.csv            sha256 fixado em SHA_REGRAS
  logs/campanha-2026-09-17/cves-sast-batch-*/normalize-report-<f>.json
                                                      so para conferir totais

SAIDAS — results/capacidade/{capacidade-por-cwe.csv, delimitacao-linguagem.csv,
capacidade.txt}, e o texto em stdout. Deterministicas, sem carimbo de
execucao. Escrita atomica com releitura dos CSV antes da promocao, e guarda de
entrada fora do repositorio, reaproveitadas do distribuicao-cwe-primario.py.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.util
import io
import json
import re
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

RAIZ = Path(__file__).resolve().parent.parent
DISTRIBUICAO_PY = RAIZ / "tools" / "distribuicao-cwe-primario.py"

# --- Criterio: docs/criterios-cruzamento.md, secao 10 ----------------------
EXT_JS_TS = frozenset({"js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"})
LINGUAGENS_REGRA_JS_TS = ("javascript", "js", "typescript", "ts")
SEM_CWE = "SEM_CWE"
SEM_EXTENSAO = "(sem extensao)"

TREATED_ROOT_PADRAO = RAIZ / "results"
REGRAS_PADRAO = RAIZ / "results" / "capacidade" / "regras-linguagens.csv"
LOGS_PADRAO = RAIZ / "logs" / "campanha-2026-09-17"
SAIDA_PADRAO = RAIZ / "results" / "capacidade"
NOME_CAP = "capacidade-por-cwe.csv"
NOME_DEL = "delimitacao-linguagem.csv"
NOME_TXT = "capacidade.txt"
PREFIXO_TEMP = ".tmp-"

# sha256 do regras-linguagens.csv no commit ec1a351.
SHA_REGRAS = "83b7fe5faf523450d2d37514a4e4ae0c6d053a0416c12384cc3131a43b42307e"
REGRAS_TOTAL = 1074

FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
UNIVERSO = {"codeql": 221, "semgrep": 221, "snyk-code": 216}
LOTES = ("aa", "ab", "ac", "ad", "ae", "af", "ag", "ah")
# Numeros de documento (CLAUDE.md, "Achados brutos"): divergencia e parada.
TOTAL_PUBLICADO = {"codeql": 3230, "semgrep": 11768, "snyk-code": 3666}
SEM_CWE_PUBLICADO = {"codeql": 0, "semgrep": 0, "snyk-code": 0}
CVE_5850, ACHADOS_5850 = "CVE-2018-20801", 5850
# CLAUDE.md, "Cobertura": as duas baixas sem raw, e os cinco exit 3 do Snyk Code.
BAIXAS = ("CVE-2016-1000229", "CVE-2018-8035")
SEM_ARQUIVO = ("CVE-2018-16479", "CVE-2018-16480", "CVE-2018-3731", "CVE-2018-3747",
               "CVE-2019-5423")

VERSOES = ("js_ts_extensao", "todos")          # ordem do CSV: principal primeiro
CELULAS_2X2 = ("regra_js_ts|arquivo_js_ts", "regra_js_ts|arquivo_fora",
               "regra_fora|arquivo_js_ts", "regra_fora|arquivo_fora")
COLUNAS_CAP = ["ferramenta", "versao", "categoria", "universo_cves", "cves_com_achado",
               "achados", "maior_cve", "achados_maior_cve"]
COLUNAS_DEL = ["ferramenta", "criterio", "celula", "achados", "cves_com_achado",
               "proporcao_achados", "proporcao_cves"]
TOP_SEGUNDO_CAMINHO = 10

# Tres digitos com zero a esquerda, ou quatro+ sem: CWE-0079 e forma fora da
# canonica, e viraria categoria distinta de CWE-079 (revisao, risco 2).
_RE_CWE = re.compile(r"CWE-(?:0[0-9]{2}|[1-9][0-9]{2,})")
_RE_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_RE_CATEGORIA = re.compile(_RE_CWE.pattern + "|" + SEM_CWE)


class Parada(Exception):
    def __init__(self, titulo, motivos, escrita_parcial=False):
        super().__init__(titulo)
        self.titulo = titulo
        self.motivos = list(motivos)
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
# Extensao — dois metodos independentes
# ---------------------------------------------------------------------------
def extensao(caminho):
    """Laco principal: por particao de cadeia. None se nao ha extensao."""
    nome = caminho.rsplit("/", 1)[-1]
    if "." not in nome:
        return None
    sufixo = nome.rsplit(".", 1)[1].lower()
    return sufixo or None


_RE_EXTENSAO = re.compile(r"(?:.*/)?[^/]*\.([^./]*)")


def extensao_regex(caminho):
    """Segundo caminho (conferencia 8): por expressao regular."""
    casamento = _RE_EXTENSAO.fullmatch(caminho)
    if casamento is None or casamento.group(1) == "":
        return None
    return casamento.group(1).lower()


def e_js_ts(caminho):
    return extensao(caminho) in EXT_JS_TS


def chave_categoria(categoria):
    """Ordem por numero, SEM_CWE no fim; forma estranha depois de tudo."""
    if categoria == SEM_CWE:
        return (1, 0, "")
    if _RE_CWE.fullmatch(categoria or ""):
        return (0, int(categoria.split("-", 1)[1]), "")
    return (2, 0, str(categoria))


def categorias_de(cwes):
    return tuple(cwes) if cwes else (SEM_CWE,)


# ---------------------------------------------------------------------------
# Entradas
# ---------------------------------------------------------------------------
def ler_regras(caminho):
    """{check_id: (languages, js_ts_bool)}."""
    regras, motivos = {}, []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != ["check_id", "languages", "js_ts"]:
            raise Parada("regras-linguagens.csv fora de forma", ["cabecalho %r" % leitor.fieldnames])
        for r in leitor:
            if r["check_id"] in regras:
                motivos.append("4 regras: check_id repetido %s" % r["check_id"])
            if r["js_ts"] not in ("sim", "nao"):
                motivos.append("4 regras: js_ts %r em %s" % (r["js_ts"], r["check_id"]))
            langs = r["languages"].split("|")
            if (r["js_ts"] == "sim") != any(l in LINGUAGENS_REGRA_JS_TS for l in langs):
                motivos.append("4 regras: js_ts %s incoerente com languages %s em %s"
                               % (r["js_ts"], r["languages"], r["check_id"]))
            regras[r["check_id"]] = (r["languages"], r["js_ts"] == "sim")
    if motivos:
        raise Parada("regras-linguagens.csv incoerente", motivos)
    return regras


def ler_tratados(raiz_tratados):
    """{ferramenta: {cve: {"achados": [(cwes, caminho, regra)], "coverage": ...}}}.

    Nao filtra nem corrige: a forma e conferida depois, pela 3.
    """
    dados, motivos = {}, []
    for f in FERRAMENTAS:
        dados[f] = {}
        for caminho in sorted((Path(raiz_tratados) / f / "treated").glob("*.json")):
            try:
                with open(caminho, encoding="utf-8") as arquivo:
                    tratado = json.load(arquivo)
                meta = tratado["metadata"]
                cve = meta["cve_id"]
                achados = [(f_["cwe"], f_["file_path"], f_["rule_id"], f_["has_cwe"])
                           for f_ in tratado["findings"]]
            except (OSError, ValueError, KeyError, TypeError) as erro:
                motivos.append("1 %s: ilegivel: %s: %s" % (rotulo(caminho), type(erro).__name__, erro))
                continue
            if cve != caminho.stem or meta.get("tool") != f or not _RE_CVE.fullmatch(cve or ""):
                motivos.append("1 %s: cve_id %r / tool %r nao batem com o arquivo"
                               % (rotulo(caminho), cve, meta.get("tool")))
                continue
            dados[f][cve] = {"achados": achados,
                              "coverage": meta.get("coverage") if f == "snyk-code" else None}
    return dados, motivos


def ler_relatorios(logs_dir):
    """{ferramenta: [(lote, total, sem_cwe)]}."""
    relatorios, motivos, arquivos = {}, [], []
    for f in FERRAMENTAS:
        relatorios[f] = []
        for lote in LOTES:
            caminho = Path(logs_dir) / ("cves-sast-batch-%s" % lote) / ("normalize-report-%s.json" % f)
            arquivos.append(caminho)
            try:
                with open(caminho, encoding="utf-8") as arquivo:
                    dados = json.load(arquivo)
                relatorios[f].append((lote, dados["achados"]["total"], dados["achados"]["sem_cwe"]))
            except (OSError, ValueError, KeyError, TypeError) as erro:
                motivos.append("2 %s: %s: %s" % (rotulo(caminho), type(erro).__name__, erro))
    return relatorios, arquivos, motivos


# ---------------------------------------------------------------------------
# Apuracao — laco principal
# ---------------------------------------------------------------------------
def _maior(por_cve):
    """(cve, n) com mais achados; empate pelo identificador."""
    if not por_cve:
        return "", 0
    cve = min(por_cve, key=lambda c: (-por_cve[c], c))
    return cve, por_cve[cve]


def apurar(dados, regras):
    """Devolve (capacidade, delimitacao, extras).

    capacidade[(f, versao, categoria)] = {"cves": set, "por_cve": {cve: n}}
    delimitacao[(f, criterio, celula)] = {"achados": n, "cves": set}
    """
    capacidade, delimitacao = {}, {}
    extras = {"total": {}, "multi_cwe": {}, "soma_categorias": {}, "fora_ext": {},
              "regra": {}, "por_cve": {}, "regras_vistas": set(), "nao_resolvidas": {}}
    for f in FERRAMENTAS:
        celulas = [("extensao", c) for c in ("js_ts", "fora")]
        if f == "semgrep":
            celulas += [("regra_x_extensao", c) for c in CELULAS_2X2]
        for criterio, celula in celulas:
            delimitacao[(f, criterio, celula)] = {"achados": 0, "cves": set()}
        total = multi = 0
        fora_ext, por_regra, por_cve_total = {}, {}, {}
        vistas = set()
        for cve in sorted(dados[f]):
            for cwes, caminho, regra, _ in dados[f][cve]["achados"]:
                total += 1
                por_cve_total[cve] = por_cve_total.get(cve, 0) + 1
                if len(cwes) > 1:
                    multi += 1
                js = e_js_ts(caminho)
                chave = "js_ts" if js else "fora"
                d = delimitacao[(f, "extensao", chave)]
                d["achados"] += 1
                d["cves"].add(cve)
                if not js:
                    ext = extensao(caminho) or SEM_EXTENSAO
                    e = fora_ext.setdefault(ext, {"achados": 0, "cves": set()})
                    e["achados"] += 1
                    e["cves"].add(cve)
                if f == "semgrep":
                    info = regras.get(regra)
                    if info is None:
                        extras["nao_resolvidas"].setdefault(regra, 0)
                        extras["nao_resolvidas"][regra] += 1
                    else:
                        vistas.add(regra)
                        cel = "%s|%s" % ("regra_js_ts" if info[1] else "regra_fora",
                                         "arquivo_js_ts" if js else "arquivo_fora")
                        d = delimitacao[(f, "regra_x_extensao", cel)]
                        d["achados"] += 1
                        d["cves"].add(cve)
                    por_regra[regra] = por_regra.get(regra, 0) + 1
                versoes = ("todos", "js_ts_extensao") if js else ("todos",)
                for categoria in categorias_de(cwes):
                    for versao in versoes:
                        c = capacidade.setdefault((f, versao, categoria), {"cves": set(), "por_cve": {}})
                        c["cves"].add(cve)
                        c["por_cve"][cve] = c["por_cve"].get(cve, 0) + 1
        # Todas as categorias da ferramenta nas duas versoes, e SEM_CWE sempre:
        # zero explicito, e nunca presumido (secao 10, "O eixo").
        categorias = {k[2] for k in capacidade if k[0] == f} | {SEM_CWE}
        for categoria in categorias:
            for versao in VERSOES:
                capacidade.setdefault((f, versao, categoria), {"cves": set(), "por_cve": {}})
        extras["total"][f] = total
        extras["multi_cwe"][f] = multi
        extras["fora_ext"][f] = fora_ext
        extras["regra"][f] = por_regra
        extras["por_cve"][f] = por_cve_total
        if f == "semgrep":
            extras["regras_vistas"] = vistas
        for versao in VERSOES:
            extras["soma_categorias"][(f, versao)] = sum(
                sum(c["por_cve"].values()) for k, c in capacidade.items() if k[:2] == (f, versao))
    return capacidade, delimitacao, extras


def linhas_capacidade(capacidade, universo=UNIVERSO):
    linhas = []
    for f in FERRAMENTAS:
        for versao in VERSOES:
            chaves = [k for k in capacidade if k[:2] == (f, versao)]
            chaves.sort(key=lambda k: (-len(capacidade[k]["cves"]),
                                       -sum(capacidade[k]["por_cve"].values()),
                                       chave_categoria(k[2])))
            for k in chaves:
                c = capacidade[k]
                maior, n_maior = _maior(c["por_cve"])
                linhas.append({"ferramenta": f, "versao": versao, "categoria": k[2],
                               "universo_cves": str(universo[f]),
                               "cves_com_achado": str(len(c["cves"])),
                               "achados": str(sum(c["por_cve"].values())),
                               "maior_cve": maior, "achados_maior_cve": str(n_maior)})
    return linhas


def linhas_delimitacao(delimitacao, extras, universo=UNIVERSO):
    linhas = []
    for f in FERRAMENTAS:
        total = extras["total"][f]
        celulas = [("extensao", c) for c in ("js_ts", "fora")]
        if f == "semgrep":
            celulas += [("regra_x_extensao", c) for c in CELULAS_2X2]
        for criterio, celula in celulas:
            d = delimitacao[(f, criterio, celula)]
            linhas.append({"ferramenta": f, "criterio": criterio, "celula": celula,
                           "achados": str(d["achados"]), "cves_com_achado": str(len(d["cves"])),
                           "proporcao_achados": "%.4f" % (d["achados"] / total if total else 0.0),
                           "proporcao_cves": "%.4f" % (len(d["cves"]) / universo[f])})
    return linhas


# ---------------------------------------------------------------------------
# Conferencias (o primeiro token de cada motivo e o numero da conferencia)
# ---------------------------------------------------------------------------
def conferir_proveniencia(sha_regras, dados, universo=UNIVERSO):
    """1: sha256 do regras-linguagens.csv; 221 / 221 / 216 tratados."""
    motivos = []
    if sha_regras != SHA_REGRAS:
        motivos.append("1 regras-linguagens.csv sha256 %s, esperado %s" % (sha_regras, SHA_REGRAS))
    for f in FERRAMENTAS:
        if len(dados[f]) != universo[f]:
            motivos.append("1 %s: %d tratados, esperados %d" % (f, len(dados[f]), universo[f]))
    # O conjunto, e nao so a contagem (revisao): as duas baixas fora das tres,
    # CodeQL = Semgrep, e o Snyk Code = eles menos os cinco SEM_ARQUIVO_ANALISAVEL.
    for f in FERRAMENTAS:
        presentes = sorted(set(BAIXAS) & set(dados[f]))
        if presentes:
            motivos.append("1 %s: tratado de baixa por codigo indisponivel %s" % (f, presentes))
    if set(dados["codeql"]) != set(dados["semgrep"]):
        motivos.append("1 conjuntos de CVE do CodeQL e do Semgrep diferem: %s"
                       % sorted(set(dados["codeql"]) ^ set(dados["semgrep"])))
    if set(dados["codeql"]) - set(dados["snyk-code"]) != set(SEM_ARQUIVO) or \
            set(dados["snyk-code"]) - set(dados["codeql"]):
        motivos.append("1 Snyk Code: ausentes %s, esperados os cinco SEM_ARQUIVO_ANALISAVEL"
                       % sorted(set(dados["codeql"]) ^ set(dados["snyk-code"])))
    return motivos


def conferir_totais(relatorios, extras, capacidade):
    """2: total e SEM_CWE dos tratados = soma dos 8 relatorios = publicado."""
    motivos = []
    for f in FERRAMENTAS:
        lotes = [r[0] for r in relatorios[f]]
        if lotes != list(LOTES):
            motivos.append("2 %s: relatorios dos lotes %s, esperados %s" % (f, lotes, list(LOTES)))
        soma_total = sum(r[1] for r in relatorios[f])
        soma_sem = sum(r[2] for r in relatorios[f])
        lido_sem = sum(capacidade[(f, "todos", SEM_CWE)]["por_cve"].values())
        for nome, lido, relatorio, publicado in (
                ("total", extras["total"][f], soma_total, TOTAL_PUBLICADO[f]),
                ("sem_cwe", lido_sem, soma_sem, SEM_CWE_PUBLICADO[f])):
            if not lido == relatorio == publicado:
                motivos.append("2 %s %s: tratados %d, relatorios %d, publicado %d"
                               % (f, nome, lido, relatorio, publicado))
    return motivos


def _relativo(caminho):
    return (isinstance(caminho, str) and caminho != "" and not caminho.startswith("/")
            and "\\" not in caminho and not re.match(r"[A-Za-z]:", caminho)
            and ".." not in caminho.split("/") and caminho.strip() == caminho)


def conferir_forma(dados):
    """3: CWE ^CWE-[0-9]{3,}$, sem repeticao, coerente com has_cwe; file_path
    relativo e nao vazio; rule_id cadeia; coverage do Snyk na forma medida."""
    motivos = []
    for f in FERRAMENTAS:
        for cve in sorted(dados[f]):
            for i, (cwes, caminho, regra, has_cwe) in enumerate(dados[f][cve]["achados"]):
                onde = "%s %s achado %d" % (f, cve, i)
                if not isinstance(cwes, list) or any(not isinstance(c, str) or not _RE_CWE.fullmatch(c)
                                                     for c in cwes):
                    motivos.append("3 %s: cwe %r fora de forma" % (onde, cwes))
                elif len(set(cwes)) != len(cwes):
                    motivos.append("3 %s: cwe repetido %r" % (onde, cwes))
                elif has_cwe is not bool(cwes):
                    motivos.append("3 %s: has_cwe %r com cwe %r" % (onde, has_cwe, cwes))
                if not _relativo(caminho):
                    motivos.append("3 %s: file_path %r nao relativo ou vazio" % (onde, caminho))
                if not isinstance(regra, str) or not regra:
                    motivos.append("3 %s: rule_id %r" % (onde, regra))
            if f == "snyk-code":
                cov = dados[f][cve]["coverage"]
                if not isinstance(cov, list):
                    motivos.append("3 %s %s: coverage %r nao e lista" % (f, cve, cov))
                    continue
                for e in cov:
                    if (not isinstance(e, dict) or sorted(e) != ["files", "isSupported", "lang", "type"]
                            or type(e["files"]) is not int or type(e["isSupported"]) is not bool
                            or not isinstance(e["lang"], str) or not e["lang"].startswith(".")):
                        motivos.append("3 %s %s: entrada de coverage fora de forma %r" % (f, cve, e))
    return motivos


def conferir_juncao(extras):
    """4: todo rule_id do Semgrep resolve em regras-linguagens.csv."""
    return ["4 semgrep: rule_id nao resolvido %s (%d achados)" % (r, n)
            for r, n in sorted(extras["nao_resolvidas"].items())]


def conferir_particao(delimitacao, extras):
    """5: js_ts + fora = total; 2x2 soma o total; margens = criterio sozinho."""
    motivos = []
    for f in FERRAMENTAS:
        total = extras["total"][f]
        js = delimitacao[(f, "extensao", "js_ts")]
        fo = delimitacao[(f, "extensao", "fora")]
        if js["achados"] + fo["achados"] != total:
            motivos.append("5 %s: js_ts %d + fora %d != total %d"
                           % (f, js["achados"], fo["achados"], total))
    if "semgrep" in extras["total"]:
        g = {c: delimitacao[("semgrep", "regra_x_extensao", c)] for c in CELULAS_2X2}
        total = extras["total"]["semgrep"]
        if sum(x["achados"] for x in g.values()) != total:
            motivos.append("5 semgrep: 2x2 soma %d != total %d"
                           % (sum(x["achados"] for x in g.values()), total))
        # margem por arquivo = criterio de extensao sozinho, em achados e em CVEs
        for arq, cel_ext in (("arquivo_js_ts", "js_ts"), ("arquivo_fora", "fora")):
            par = [g["regra_js_ts|" + arq], g["regra_fora|" + arq]]
            ext = delimitacao[("semgrep", "extensao", cel_ext)]
            if sum(x["achados"] for x in par) != ext["achados"] or \
                    (par[0]["cves"] | par[1]["cves"]) != ext["cves"]:
                motivos.append("5 semgrep: margem %s != extensao %s" % (arq, cel_ext))
        # margem por regra = criterio de regra sozinho, por travessia propria
        regra_js = sum(n for r, n in extras["regra"]["semgrep"].items()
                       if extras["regras_js_ts"].get(r))
        regra_fora = total - regra_js
        m_js = g["regra_js_ts|arquivo_js_ts"]["achados"] + g["regra_js_ts|arquivo_fora"]["achados"]
        m_fo = g["regra_fora|arquivo_js_ts"]["achados"] + g["regra_fora|arquivo_fora"]["achados"]
        if (m_js, m_fo) != (regra_js, regra_fora):
            motivos.append("5 semgrep: margens por regra %d/%d != criterio da regra %d/%d"
                           % (m_js, m_fo, regra_js, regra_fora))
    return motivos


def conferir_multi_cwe(dados, extras):
    """6: soma das categorias >= total; igual sse nenhum achado multi-CWE.
    O excesso tem de ser exatamente sum(len(cwe) - 1) sobre os achados."""
    motivos = []
    for f in FERRAMENTAS:
        for versao in VERSOES:
            achados = [a for cve in dados[f] for a in dados[f][cve]["achados"]
                       if versao == "todos" or e_js_ts(a[1])]
            total = len(achados)
            excesso = sum(max(len(a[0]), 1) - 1 for a in achados)
            multi = sum(1 for a in achados if len(a[0]) > 1)
            soma = extras["soma_categorias"][(f, versao)]
            if soma < total or (soma == total) != (multi == 0) or soma - total != excesso:
                motivos.append("6 %s %s: soma das categorias %d, total %d, excesso esperado %d"
                               % (f, versao, soma, total, excesso))
    return motivos


def conferir_5850(extras):
    """7: achados do Semgrep no CVE-2018-20801 = 5.850."""
    n = extras["por_cve"].get("semgrep", {}).get(CVE_5850, 0)
    return [] if n == ACHADOS_5850 else ["7 semgrep %s: %d achados, documentado %d"
                                         % (CVE_5850, n, ACHADOS_5850)]


def segundo_caminho(dados):
    """Travessia independente: por CVE, o conjunto de caminhos e, por caminho,
    a uniao dos CWEs. Extensao por expressao regular, nao pelo laco principal.

    Devolve ({(f, celula): n_cves}, {(f, categoria): n_cves na versao principal}).
    """
    ext_cves, cat_cves = {}, {}
    for f in FERRAMENTAS:
        for cve, registro in dados[f].items():
            caminhos = {}
            for cwes, caminho, _, _ in registro["achados"]:
                caminhos.setdefault(caminho, set()).update(cwes if cwes else [SEM_CWE])
            js = {c for c in caminhos if extensao_regex(c) in EXT_JS_TS}
            if js:
                ext_cves[(f, "js_ts")] = ext_cves.get((f, "js_ts"), 0) + 1
            if set(caminhos) - js:
                ext_cves[(f, "fora")] = ext_cves.get((f, "fora"), 0) + 1
            for categoria in set().union(*(caminhos[c] for c in js)) if js else ():
                cat_cves[(f, categoria)] = cat_cves.get((f, categoria), 0) + 1
    return ext_cves, cat_cves


def conferir_segundo_caminho(linhas_cap, delimitacao, dados):
    """8: cves_com_achado das celulas `extensao` e das dez maiores categorias
    da versao principal, pelos dois caminhos."""
    motivos = []
    ext_cves, cat_cves = segundo_caminho(dados)
    for f in FERRAMENTAS:
        for celula in ("js_ts", "fora"):
            a = len(delimitacao[(f, "extensao", celula)]["cves"])
            b = ext_cves.get((f, celula), 0)
            if a != b:
                motivos.append("8 %s extensao %s: laco %d, segundo caminho %d" % (f, celula, a, b))
        principais = [l for l in linhas_cap if l["ferramenta"] == f and l["versao"] == "js_ts_extensao"]
        topo = principais[:TOP_SEGUNDO_CAMINHO]
        for l in topo:
            b = cat_cves.get((f, l["categoria"]), 0)
            if int(l["cves_com_achado"]) != b:
                motivos.append("8 %s %s: laco %s, segundo caminho %d"
                               % (f, l["categoria"], l["cves_com_achado"], b))
        # nenhuma categoria de fora do topo pode passar a decima no segundo caminho
        if len(topo) == TOP_SEGUNDO_CAMINHO:
            corte = int(topo[-1]["cves_com_achado"])
            nomes = {l["categoria"] for l in topo}
            for (g, categoria), n in sorted(cat_cves.items()):
                if g == f and categoria not in nomes and n > corte:
                    motivos.append("8 %s %s: %d CVEs no segundo caminho, acima do corte %d do laco"
                                   % (f, categoria, n, corte))
    return motivos


def _ler_csv(caminho, colunas):
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != colunas:
            return None, ["9 %s: cabecalho %r" % (Path(caminho).name, leitor.fieldnames)]
        return list(leitor), []


def conferir_arquivos(caminho_cap, caminho_del, linhas_cap, linhas_del):
    """9: releitura dos dois CSV gravados — forma e cada celula == memoria."""
    motivos = []
    for caminho, colunas, memoria in ((caminho_cap, COLUNAS_CAP, linhas_cap),
                                      (caminho_del, COLUNAS_DEL, linhas_del)):
        lidas, m = _ler_csv(caminho, colunas)
        motivos += m
        if lidas is None:
            continue
        nome = Path(caminho).name
        if not Path(caminho).read_bytes().endswith(b"\n"):
            motivos.append("9 %s: sem quebra de linha final" % nome)
        for numero, registro in enumerate(lidas, 2):
            if None in registro or None in registro.values():
                motivos.append("9 %s linha %d: numero de campos diferente do cabecalho" % (nome, numero))
            if "categoria" in registro and not _RE_CATEGORIA.fullmatch(registro["categoria"] or ""):
                motivos.append("9 %s linha %d: categoria %r" % (nome, numero, registro["categoria"]))
        if len(lidas) != len(memoria):
            motivos.append("9 %s: %d linhas, memoria %d" % (nome, len(lidas), len(memoria)))
        for numero, (lido, mem) in enumerate(zip(lidas, memoria), 2):
            for coluna in colunas:
                if lido.get(coluna) != mem[coluna]:
                    motivos.append("9 %s linha %d coluna %s: arquivo %r, memoria %r"
                                   % (nome, numero, coluna, lido.get(coluna), mem[coluna]))
    return motivos


def gerar_csv(linhas, colunas):
    saida = io.StringIO()
    escritor = csv.DictWriter(saida, fieldnames=colunas, lineterminator="\n")
    escritor.writeheader()
    escritor.writerows(linhas)
    return saida.getvalue()


# ---------------------------------------------------------------------------
# Conjunto das conferencias 1-8, sobre entradas possivelmente mutadas
# ---------------------------------------------------------------------------
def todas(sha_regras, dados, regras, relatorios, mutar=None):
    """Roda apuracao e conferencias 1 a 8. `mutar(cap, dlm, ext)` altera a
    estrutura apurada antes das conferencias, para os mutantes de 5, 6 e 8."""
    # 3 antes da apuracao: apurar() supoe a forma, e achado fora dela daria
    # traceback em vez de parada nomeada (revisao, risco 1).
    forma = conferir_forma(dados)
    if forma:
        return None, None, None, None, conferir_proveniencia(sha_regras, dados) + forma
    cap, dlm, ext = apurar(dados, regras)
    ext["regras_js_ts"] = {r: info[1] for r, info in regras.items()}
    if mutar:
        mutar(cap, dlm, ext)
    linhas = linhas_capacidade(cap)
    motivos = (conferir_proveniencia(sha_regras, dados)
               + conferir_totais(relatorios, ext, cap)
               + conferir_juncao(ext)
               + conferir_particao(dlm, ext)
               + conferir_multi_cwe(dados, ext)
               + conferir_5850(ext)
               + conferir_segundo_caminho(linhas, dlm, dados))
    return cap, dlm, ext, linhas, motivos


def itens(motivos):
    return sorted({m.split(" ", 1)[0] for m in motivos})


# ---------------------------------------------------------------------------
# Controle positivo (conferencia 10)
# ---------------------------------------------------------------------------
def controle_positivo(sha_regras, dados, regras, relatorios, linhas_cap, linhas_del):
    resultados = []

    def registra(nome, pretendida, disparadas):
        resultados.append((nome, pretendida, pretendida in disparadas, disparadas))

    def rodar(**kw):
        args = dict(sha_regras=sha_regras, dados=dados, regras=regras, relatorios=relatorios)
        args.update(kw)
        return itens(todas(**args)[4])

    def primeiro(f, filtro):
        for cve in sorted(dados[f]):
            for i, a in enumerate(dados[f][cve]["achados"]):
                if filtro(a):
                    return cve, i
        raise Parada("controle positivo sem candidato", [f])

    def com_achado(f, cve, i, novo):
        d = copy.deepcopy(dados)
        d[f][cve]["achados"][i] = novo
        return d

    # 1
    registra("1: sha256 do regras-linguagens.csv adulterado", "1", rodar(sha_regras="0" * 64))
    d = copy.deepcopy(dados); d["snyk-code"].pop(sorted(d["snyk-code"])[0])
    registra("1: um tratado a menos no Snyk Code", "1", rodar(dados=d))
    d = copy.deepcopy(dados)
    trocado = sorted(set(d["snyk-code"]) - set(SEM_ARQUIVO))[0]
    d["snyk-code"][SEM_ARQUIVO[0]] = d["snyk-code"].pop(trocado)
    registra("1: Snyk Code com um SEM_ARQUIVO no lugar de outro CVE (contagem mantida)", "1",
             rodar(dados=d))
    # 2
    cve, i = primeiro("codeql", lambda a: True)
    d = copy.deepcopy(dados); d["codeql"][cve]["achados"].pop(i)
    registra("2: um achado a menos no CodeQL", "2", rodar(dados=d))
    cve, i = primeiro("snyk-code", lambda a: len(a[0]) == 1)
    a = dados["snyk-code"][cve]["achados"][i]
    registra("2: achado do Snyk Code sem CWE (SEM_CWE != 0)", "2",
             rodar(dados=com_achado("snyk-code", cve, i, ([], a[1], a[2], False))))
    r = copy.deepcopy(relatorios); r["semgrep"][0] = (r["semgrep"][0][0], r["semgrep"][0][1] + 1,
                                                      r["semgrep"][0][2])
    registra("2: relatorio de normalizacao do Semgrep +1", "2", rodar(relatorios=r))
    # 3
    cve, i = primeiro("codeql", lambda a: a[0])
    a = dados["codeql"][cve]["achados"][i]
    registra("3: CWE sem zero a esquerda (CWE-79)", "3",
             rodar(dados=com_achado("codeql", cve, i, (["CWE-79"] + a[0][1:], a[1], a[2], a[3]))))
    registra("3: file_path absoluto", "3",
             rodar(dados=com_achado("codeql", cve, i, (a[0], "/" + a[1], a[2], a[3]))))
    registra("3: file_path vazio", "3",
             rodar(dados=com_achado("codeql", cve, i, (a[0], "", a[2], a[3]))))
    registra("3: CWE com zero a esquerda sobrando (CWE-0079)", "3",
             rodar(dados=com_achado("codeql", cve, i, (["CWE-0079"] + a[0][1:], a[1], a[2], a[3]))))
    # risco 1 da revisao: forma que apurar() nao suporta para na 3, sem traceback
    registra("3: cwe nulo", "3", rodar(dados=com_achado("codeql", cve, i, (None, a[1], a[2], a[3]))))
    registra("3: cwe como cadeia nua", "3",
             rodar(dados=com_achado("codeql", cve, i, (a[0][0], a[1], a[2], a[3]))))
    registra("3: file_path nulo", "3",
             rodar(dados=com_achado("codeql", cve, i, (a[0], None, a[2], a[3]))))
    cs_, is_ = primeiro("semgrep", lambda a: True)
    b_ = dados["semgrep"][cs_]["achados"][is_]
    registra("3: rule_id nulo no Semgrep", "3",
             rodar(dados=com_achado("semgrep", cs_, is_, (b_[0], b_[1], None, b_[3]))))
    d = copy.deepcopy(dados)
    cs = next(c for c in sorted(d["snyk-code"]) if d["snyk-code"][c]["coverage"])
    d["snyk-code"][cs]["coverage"][0]["lang"] = "js"
    registra("3: coverage do Snyk com lang sem ponto", "3", rodar(dados=d))
    # 4
    cve, i = primeiro("semgrep", lambda a: a[2].startswith("javascript."))
    a = dados["semgrep"][cve]["achados"][i]
    registra("4: rule_id com prefixo de diretorio (packs.javascript...)", "4",
             rodar(dados=com_achado("semgrep", cve, i, (a[0], a[1], "packs." + a[2], a[3]))))

    # 5, 6, 8 — mutacao da estrutura apurada
    def m5(cap, dlm, ext):
        dlm[("codeql", "extensao", "js_ts")]["achados"] += 1
    registra("5: celula js_ts do CodeQL +1", "5", rodar(mutar=m5))

    def m5b(cap, dlm, ext):
        dlm[("semgrep", "regra_x_extensao", "regra_js_ts|arquivo_fora")]["achados"] += 1
        dlm[("semgrep", "regra_x_extensao", "regra_fora|arquivo_fora")]["achados"] -= 1
    registra("5: deslocamento entre celulas da 2x2 com total mantido", "5", rodar(mutar=m5b))

    def m6(cap, dlm, ext):
        ext["soma_categorias"][("snyk-code", "todos")] -= 1
    registra("6: soma das categorias do Snyk Code -1", "6", rodar(mutar=m6))

    def m6b(cap, dlm, ext):
        ext["soma_categorias"][("semgrep", "js_ts_extensao")] += 1
    registra("6: soma das categorias do Semgrep js_ts +1 (excesso inexistente)", "6", rodar(mutar=m6b))
    # 7
    d = copy.deepcopy(dados); d["semgrep"][CVE_5850]["achados"].pop()
    registra("7: um achado a menos no CVE-2018-20801", "7", rodar(dados=d))

    # 8
    def m8(cap, dlm, ext):
        dlm[("semgrep", "extensao", "fora")]["cves"].add("CVE-0000-00000")
    registra("8: CVE espurio na celula fora do Semgrep", "8", rodar(mutar=m8))

    def m8b(cap, dlm, ext):
        topo = max((k for k in cap if k[:2] == ("codeql", "js_ts_extensao")),
                   key=lambda k: (len(cap[k]["cves"]), k[2]))
        cap[topo]["cves"].discard(sorted(cap[topo]["cves"])[0])
    registra("8: CVE a menos na maior categoria do CodeQL", "8", rodar(mutar=m8b))

    # 9 — releitura: grava, adultera uma celula, rele. Em diretorio temporario
    # do sistema, nunca na saida versionada (revisao, risco 3).
    for nome_m, alvo in (("capacidade", "cap"), ("delimitacao", "del")):
        with tempfile.TemporaryDirectory(prefix="capacidade-cp-") as tmp:
            cap_tmp = Path(tmp) / NOME_CAP
            del_tmp = Path(tmp) / NOME_DEL
            cap_tmp.write_text(gerar_csv(linhas_cap, COLUNAS_CAP), encoding="utf-8")
            del_tmp.write_text(gerar_csv(linhas_del, COLUNAS_DEL), encoding="utf-8")
            alvo_p = cap_tmp if alvo == "cap" else del_tmp
            texto = alvo_p.read_text(encoding="utf-8").split("\n")
            campos = texto[1].split(",")
            campos[4] = str(int(campos[4]) + 1)
            texto[1] = ",".join(campos)
            alvo_p.write_text("\n".join(texto), encoding="utf-8")
            registra("9: %s.csv com cves_com_achado adulterado" % nome_m, "9",
                     itens(conferir_arquivos(cap_tmp, del_tmp, linhas_cap, linhas_del)))

    # classificacao de extensao: x.d.ts em js_ts, bin/public em fora, pelo laco
    # inteiro, e nao so pela funcao
    cve, i = primeiro("codeql", lambda a: e_js_ts(a[1]))
    a = dados["codeql"][cve]["achados"][i]
    base = todas(sha_regras, dados, regras, relatorios)[1]
    for caminho, celula in (("x.d.ts", "js_ts"), ("bin/public", "fora"), (".eslintrc.js", "js_ts"),
                            ("src/A.TSX", "js_ts"), ("index.html", "fora")):
        d = copy.deepcopy(dados); d["codeql"][cve]["achados"].append((a[0], caminho, a[2], a[3]))
        dlm = todas(sha_regras, d, regras, relatorios)[1]
        delta = {c: dlm[("codeql", "extensao", c)]["achados"] - base[("codeql", "extensao", c)]["achados"]
                 for c in ("js_ts", "fora")}
        ok = delta[celula] == 1 and sum(delta.values()) == 1 \
            and (extensao(caminho) in EXT_JS_TS) == (extensao_regex(caminho) in EXT_JS_TS)
        resultados.append(("ext: achado em %s cai em %s" % (caminho, celula), "ext", ok,
                           ["ext"] if ok else ["delta %r" % delta]))
    return resultados


# ---------------------------------------------------------------------------
# Snyk Code: coverage
# ---------------------------------------------------------------------------
def coverage_snyk(dados):
    """({lang: (n_cves, soma_files)}, [(cve, langs_fora, achados_fora_ext)])."""
    por_lang, fora = {}, []
    for cve in sorted(dados["snyk-code"]):
        reg = dados["snyk-code"][cve]
        langs = {}
        for e in reg["coverage"]:
            if e["isSupported"] is True and e["files"] > 0:
                langs[e["lang"]] = langs.get(e["lang"], 0) + e["files"]
        for lang, n in langs.items():
            x = por_lang.get(lang, (0, 0))
            por_lang[lang] = (x[0] + 1, x[1] + n)
        nao_js = sorted(l for l in langs if l[1:].lower() not in EXT_JS_TS)
        if nao_js:
            n_fora = sum(1 for a in reg["achados"] if not e_js_ts(a[1]))
            fora.append((cve, nao_js, n_fora))
    return por_lang, fora


# ---------------------------------------------------------------------------
# Texto
# ---------------------------------------------------------------------------
def gerar_txt(fontes, conferencias, linhas_cap, linhas_del, cap, dlm, ext, dados, regras, shas_csv):
    L = []
    w = L.append
    w("Capacidade empirica e delimitacao por linguagem (criterios-cruzamento.md, secao 10)")
    w("Gerado por tools/capacidade-empirica.py. Descritivo: o que as ferramentas reportam,")
    w("e nao o que acertam. Nenhum campo gt_* e lido.")
    w("")
    w("1. FONTES")
    for papel, rot, sha in fontes:
        w("  %-12s %s" % (papel, rot))
        w("  %-12s sha256 %s" % ("", sha))
    for nome, sha in shas_csv:
        w("  saida        %s sha256 %s" % (nome, sha))
    w("")
    w("  Extensao: o sufixo depois do ultimo ponto do NOME do arquivo (depois da ultima '/'),")
    w("  em minusculas; sem ponto no nome, ou com o ponto no fim, nao ha extensao.")
    w("  x.d.ts -> ts; .eslintrc.js -> js; bin/public -> sem extensao.")
    w("  JS/TS pela extensao: %s" % " ".join("." + e for e in sorted(EXT_JS_TS)))
    w("  JS/TS pela linguagem da regra (so Semgrep): languages contem um de %s"
      % ", ".join(LINGUAGENS_REGRA_JS_TS))
    w("  Linguagem da regra lida so da juncao com regras-linguagens.csv, nunca do prefixo do check_id.")
    w("")
    w("2. CONFERENCIAS")
    for nome, resultado in conferencias:
        w("  %-76s %s" % (nome, resultado))
    w("")
    w("3. CAPACIDADE, VERSAO PRINCIPAL (achados em arquivo JS/TS pela extensao)")
    w("  Um achado com mais de um CWE conta em cada um: as categorias NAO somam o total.")
    for f in FERRAMENTAS:
        ls = [l for l in linhas_cap if l["ferramenta"] == f and l["versao"] == "js_ts_extensao"]
        tot_js = dlm[(f, "extensao", "js_ts")]["achados"]
        w("")
        w("  %s — universo %d CVEs; %d achados em JS/TS, %d categorias com achado"
          % (f, UNIVERSO[f], tot_js, sum(1 for l in ls if l["cves_com_achado"] != "0")))
        w("  %-9s %8s %8s  %-16s %6s" % ("categoria", "cves", "achados", "maior_cve", "n"))
        for l in ls:
            w("  %-9s %8s %8s  %-16s %6s" % (l["categoria"], l["cves_com_achado"], l["achados"],
                                            l["maior_cve"] or "-", l["achados_maior_cve"]))
    w("")
    w("4. DELIMITACAO POR LINGUAGEM")
    w("  %-10s %-18s %-26s %8s %6s %8s %8s" % ("ferramenta", "criterio", "celula", "achados",
                                                "cves", "p_achad", "p_cves"))
    for l in linhas_del:
        w("  %-10s %-18s %-26s %8s %6s %8s %8s" % (l["ferramenta"], l["criterio"], l["celula"],
                                                    l["achados"], l["cves_com_achado"],
                                                    l["proporcao_achados"], l["proporcao_cves"]))
    g = {c: dlm[("semgrep", "regra_x_extensao", c)] for c in CELULAS_2X2}
    for unidade, val in (("achados", lambda x: x["achados"]), ("CVEs", lambda x: len(x["cves"]))):
        w("")
        w("  Semgrep 2x2, em %s (linhas: regra; colunas: arquivo)" % unidade)
        w("  %-12s %12s %12s" % ("", "arq JS/TS", "arq fora"))
        for r_, nome in (("regra_js_ts", "regra JS/TS"), ("regra_fora", "regra fora")):
            w("  %-12s %12d %12d" % (nome, val(g[r_ + "|arquivo_js_ts"]), val(g[r_ + "|arquivo_fora"])))
    w("  Em CVEs as celulas nao somam o universo: um CVE pode estar em mais de uma.")
    w("")
    w("5. EXTENSOES DOS ACHADOS FORA DE JS/TS")
    for f in FERRAMENTAS:
        fe = ext["fora_ext"][f]
        w("")
        w("  %s — %d achados fora de JS/TS" % (f, sum(x["achados"] for x in fe.values())))
        w("  %-18s %8s %6s" % ("extensao", "achados", "cves"))
        for e in sorted(fe, key=lambda e: (-fe[e]["achados"], -len(fe[e]["cves"]), e)):
            w("  %-18s %8d %6d" % ("." + e if e != SEM_EXTENSAO else e, fe[e]["achados"],
                                   len(fe[e]["cves"])))
        if not fe:
            w("  (nenhum)")
    w("")
    w("6. CONCENTRACAO NO SEMGREP")
    tot = ext["total"]["semgrep"]
    pc = ext["por_cve"]["semgrep"]
    top = sorted(pc, key=lambda c: (-pc[c], c))[:10]
    w("  total %d achados, em %d CVEs com achado de %d" % (tot, len(pc), UNIVERSO["semgrep"]))
    w("  %-16s %8s %8s" % ("CVE", "achados", "parcela"))
    for c in top:
        w("  %-16s %8d %8.4f" % (c, pc[c], pc[c] / tot))
    w("  dez maiores somam %d (%.4f)" % (sum(pc[c] for c in top), sum(pc[c] for c in top) / tot))
    w("  parcela do maior CVE: %.4f" % (pc[top[0]] / tot))
    pr = ext["regra"]["semgrep"]
    topr = sorted(pr, key=lambda r: (-pr[r], r))[:10]
    w("")
    w("  %-78s %8s %8s %-18s %s" % ("regra", "achados", "parcela", "languages", "js_ts"))
    for r in topr:
        w("  %-78s %8d %8.4f %-18s %s" % (r, pr[r], pr[r] / tot, regras[r][0],
                                          "sim" if regras[r][1] else "nao"))
    w("  parcela da maior regra: %.4f" % (pr[topr[0]] / tot))
    w("")
    w("7. CORROBORACAO PELO coverage DO SNYK CODE")
    w("  Limitacao declarada: coverage[] e agregada e nao enumera caminhos. O campo `lang`")
    w("  traz uma extensao ('.js', '.html'), nao um nome de linguagem; JS/TS aqui e a mesma")
    w("  lista de extensoes do criterio. Conta-se a entrada com isSupported verdadeiro e files > 0.")
    por_lang, fora = coverage_snyk(dados)
    w("")
    w("  %-10s %6s %10s %6s" % ("lang", "cves", "arquivos", "js_ts"))
    for lang in sorted(por_lang, key=lambda l: (-por_lang[l][0], l)):
        w("  %-10s %6d %10d %6s" % (lang, por_lang[lang][0], por_lang[lang][1],
                                    "sim" if lang[1:].lower() in EXT_JS_TS else "nao"))
    com = sum(1 for x in fora if x[2] > 0)
    w("")
    w("  CVEs com alguma lang analisada fora de JS/TS: %d de %d; destes, com achado fora de"
      % (len(fora), UNIVERSO["snyk-code"]))
    w("  JS/TS pela extensao: %d; sem: %d" % (com, len(fora) - com))
    fora_cves = {x[0] for x in fora}
    so_achado = sorted(c for c in dados["snyk-code"] if c not in fora_cves
                       and any(not e_js_ts(a[1]) for a in dados["snyk-code"][c]["achados"]))
    w("  CVEs com achado fora de JS/TS pela extensao e sem lang fora de JS/TS no coverage: %d"
      % len(so_achado))
    for c in so_achado:
        exts = sorted({extensao(a[1]) or SEM_EXTENSAO for a in dados["snyk-code"][c]["achados"]
                       if not e_js_ts(a[1])})
        w("    %s  %s" % (c, " ".join(exts)))
    w("")
    w("  %-16s %-40s %s" % ("CVE", "langs fora de JS/TS", "achados fora (extensao)"))
    for cve, langs, n in fora:
        w("  %-16s %-40s %d" % (cve, " ".join(langs), n))
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
def executar(args):
    raiz_tratados = Path(args.treated_root) if args.treated_root else TREATED_ROOT_PADRAO
    regras_caminho = Path(args.regras) if args.regras else REGRAS_PADRAO
    logs_dir = Path(args.logs_dir) if args.logs_dir else LOGS_PADRAO
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO
    dirs_tratados = [raiz_tratados / f / "treated" for f in FERRAMENTAS]

    fora = entradas_fora(saida, [raiz_tratados, regras_caminho, logs_dir] + dirs_tratados)
    if fora:
        raise Parada("saida dentro do repositorio exige entradas dentro dele: "
                     "o caminho de fora iria para o .txt", fora)
    faltando = [str(c) for c in dirs_tratados + [logs_dir] if not c.is_dir()]
    faltando += [str(regras_caminho)] if not regras_caminho.is_file() else []
    if faltando:
        raise Parada("entradas ausentes", faltando)

    sha_regras = sha256_arquivo(regras_caminho)
    if sha_regras != SHA_REGRAS:
        raise Parada("conferencia 1 (proveniencia)", ["1 regras-linguagens.csv sha256 %s, esperado %s"
                                                      % (sha_regras, SHA_REGRAS)])
    regras = ler_regras(regras_caminho)
    if len(regras) != REGRAS_TOTAL:
        raise Parada("conferencia 1 (proveniencia)", ["1 %d regras, esperadas %d"
                                                      % (len(regras), REGRAS_TOTAL)])
    dados, m_leitura = ler_tratados(raiz_tratados)
    relatorios, arquivos_rel, m_rel = ler_relatorios(logs_dir)
    if m_leitura or m_rel:
        raise Parada("entradas ilegiveis", m_leitura + m_rel)
    fora_rel = entradas_fora(saida, arquivos_rel)
    if fora_rel:
        raise Parada("relatorio de normalizacao fora do repositorio", fora_rel)

    cap, dlm, ext, linhas_cap, motivos = todas(sha_regras, dados, regras, relatorios)
    titulos = {"1": "proveniencia", "2": "totais contra a normalizacao", "3": "forma dos achados",
               "4": "juncao com as regras", "5": "particao", "6": "multi-CWE", "7": "o 5.850",
               "8": "segundo caminho"}
    if motivos:
        primeira = itens(motivos)[0]
        mostrados = motivos[:200]
        if len(motivos) > 200:
            mostrados.append("... e mais %d motivos omitidos" % (len(motivos) - 200))
        raise Parada("conferencia %s (%s)" % (primeira, titulos.get(primeira, "?")), mostrados)
    linhas_del = linhas_delimitacao(dlm, ext)

    controle = controle_positivo(sha_regras, dados, regras, relatorios, linhas_cap, linhas_del)
    falhas = ["%s: pretendida %s, dispararam %s" % (n, p, d or "nenhuma")
              for n, p, ok, d in controle if not ok]
    if falhas:
        raise Parada("conferencia 10 (controle positivo) falhou", falhas)

    multi = {f: ext["multi_cwe"][f] for f in FERRAMENTAS}
    multi_js = {f: sum(1 for c in dados[f].values() for a in c["achados"]
                       if len(a[0]) > 1 and e_js_ts(a[1])) for f in FERRAMENTAS}
    conferencias = [
        ("1 sha256 do regras-linguagens.csv = %s..; tratados 221/221/216" % SHA_REGRAS[:12], "OK"),
        ("  conjunto: sem as 2 baixas; CodeQL = Semgrep; Snyk = eles - 5 SEM_ARQUIVO", "OK"),
        ("2 total e SEM_CWE dos tratados = soma dos 8 relatorios = publicado", "OK"),
        ("  totais: codeql %d, semgrep %d, snyk-code %d; SEM_CWE 0/0/0"
         % tuple(ext["total"][f] for f in FERRAMENTAS), ""),
        ("3 CWE canonico (3 digitos, sem zero sobrando) sem repeticao; file_path", "OK"),
        ("  relativo; coverage do Snyk na forma; antes da apuracao", ""),
        ("4 todo rule_id do Semgrep resolve em regras-linguagens.csv", "OK"),
        ("  regras do pack com algum achado: %d de %d" % (len(ext["regras_vistas"]), REGRAS_TOTAL), ""),
        ("5 js_ts + fora = total; 2x2 soma o total; margens = criterios sozinhos", "OK"),
        ("6 soma das categorias - total = sum(len(cwe) - 1), nas duas versoes", "OK"),
        ("  achados com mais de um CWE (todos / js_ts): codeql %d/%d, semgrep %d/%d, snyk-code %d/%d"
         % tuple(x for f in FERRAMENTAS for x in (multi[f], multi_js[f])), ""),
        ("7 achados do Semgrep no %s = %d" % (CVE_5850, ACHADOS_5850), "OK"),
        ("8 segundo caminho: celulas extensao e 10 maiores categorias, nas 3", "OK"),
        ("9 os dois CSV gravados relidos (publicados so se aprovados)", "OK"),
        ("10 controle positivo (%d casos)" % len(controle), "OK"),
    ]
    for nome, pret, _, disp in controle:
        conferencias.append(("    %s" % nome, "pretendida %s; dispararam %s"
                             % (pret, ",".join(disp) if disp else "nenhuma")))
    conferencias.append(("11 determinismo: NAO verificado por este script; conferido por fora", "ver README"))

    csv_cap = gerar_csv(linhas_cap, COLUNAS_CAP)
    csv_del = gerar_csv(linhas_del, COLUNAS_DEL)
    fontes = ([("regras", rotulo(regras_caminho), sha_regras)]
              + [("tratados", rotulo(d_), DIST.sha256_conjunto(sorted(d_.glob("*.json"))))
                 for d_ in dirs_tratados]
              + [("relatorios", rotulo(logs_dir) + "/cves-sast-batch-*/normalize-report-*.json",
                  DIST.sha256_conjunto(arquivos_rel))]
              + [("codigo", rotulo(Path(__file__)), sha256_arquivo(__file__)),
                 ("codigo", rotulo(DISTRIBUICAO_PY), sha256_arquivo(DISTRIBUICAO_PY))])
    shas_csv = [(NOME_CAP, hashlib.sha256(csv_cap.encode()).hexdigest()),
                (NOME_DEL, hashlib.sha256(csv_del.encode()).hexdigest())]
    texto = gerar_txt(fontes, conferencias, linhas_cap, linhas_del, cap, dlm, ext, dados, regras,
                      shas_csv)

    saida.mkdir(parents=True, exist_ok=True)
    nomes = (NOME_CAP, NOME_DEL, NOME_TXT)
    temporarios = {n: saida / (PREFIXO_TEMP + n) for n in nomes}
    for t in temporarios.values():
        t.unlink(missing_ok=True)
    promovidos = []
    try:
        temporarios[NOME_CAP].write_text(csv_cap, encoding="utf-8")
        temporarios[NOME_DEL].write_text(csv_del, encoding="utf-8")
        temporarios[NOME_TXT].write_text(texto, encoding="utf-8")
        c9 = conferir_arquivos(temporarios[NOME_CAP], temporarios[NOME_DEL], linhas_cap, linhas_del)
        if c9:
            raise Parada("conferencia 9 (releitura dos CSV gravados)", c9)
        try:
            for n in nomes:
                temporarios[n].replace(saida / n)
                promovidos.append(n)
        except OSError as erro:
            raise Parada("promocao incompleta: promovidos %s" % promovidos,
                         ["%s: %s" % (type(erro).__name__, erro)], escrita_parcial=bool(promovidos))
    finally:
        for t in temporarios.values():
            try:
                t.unlink(missing_ok=True)
            except OSError as erro:
                print("AVISO: temporario nao removido: %s: %s" % (t, erro), file=sys.stderr)
    sys.stdout.write(texto)
    return 0


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Capacidade empirica e delimitacao por linguagem (criterios-cruzamento.md, secao 10).")
    analisador.add_argument("--treated-root", help="padrao: results/ (le <f>/treated/)")
    analisador.add_argument("--regras", help="padrao: results/capacidade/regras-linguagens.csv")
    analisador.add_argument("--logs-dir", help="padrao: logs/campanha-2026-09-17/")
    analisador.add_argument("--saida-dir", help="padrao: results/capacidade/")
    args = analisador.parse_args(argv)
    try:
        return executar(args)
    except Parada as parada:
        if parada.escrita_parcial:
            print("\nPARADO: %s. ESCRITA PARCIAL: o conjunto em disco esta inconsistente."
                  % parada.titulo, file=sys.stderr)
        else:
            print("\nPARADO: %s. Nenhuma saida escrita." % parada.titulo, file=sys.stderr)
        for motivo in parada.motivos:
            print("  - %s" % motivo, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
