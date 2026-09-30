#!/usr/bin/env python3
"""Confere as afirmações numéricas da metodologia contra as fontes versionadas.

O documento entra como TEXTO DE ENTRADA, nunca como verdade: cada número é
extraído dele e recomputado a partir de `results/`, `logs/` e `datasets/`.

    python3 tools/confere-numeros-v10.py --texto docs/metodologia-V10.md
    python3 tools/confere-numeros-v10.py --texto <arq> --controle-positivo

A extração exige casamento único: padrão que não case, ou que case mais de uma
vez, é FALHA DE EXTRACAO e nunca silêncio — zero indistinguível de ausência não
é resultado (regra geral de contagem do projeto).

O controle positivo adultera uma célula por família de verificação e exige que
a verificação correspondente acuse. Sem ele, "nenhuma divergência" não é
afirmável.
"""

import argparse
import datetime
import csv
import json
import pathlib
import re
import statistics
import sys
from collections import Counter, defaultdict
from decimal import ROUND_HALF_UP, Decimal

FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
NIVEIS = (
    "nivel_0",
    "nivel_1",
    "nivel_2_generosa",
    "nivel_2_estrita",
    "nivel_3",
    "nivel_4_generosa",
    "nivel_4_estrita",
)


# --------------------------------------------------------------------------
# leitura do texto
# --------------------------------------------------------------------------
class FalhaDeExtracao(Exception):
    pass


def numeros(texto):
    """Todos os números de uma cadeia, na grafia do documento (1.074 · 77,8)."""
    achados = []
    for bruto in re.findall(r"\d[\d.]*(?:,\d+)?", texto):
        limpo = bruto.rstrip(".")
        if re.fullmatch(r"\d{1,3}(?:\.\d{3})+", limpo):  # milhar com ponto
            limpo = limpo.replace(".", "")
        elif "." in limpo and "," not in limpo:
            # 2.2.1, 1.2 e afins: só é número se tiver um ponto e parecer versão
            partes = limpo.split(".")
            if len(partes) > 2 or len(partes[-1]) != 3:
                continue
            limpo = limpo.replace(".", "")
        limpo = limpo.replace(",", ".")
        achados.append(float(limpo))
    return achados


def um_numero(texto):
    n = numeros(texto)
    if len(n) != 1:
        raise FalhaDeExtracao(f"esperava um número em {texto!r}, achei {n}")
    return n[0]


class Documento:
    def __init__(self, linhas):
        self.linhas = list(linhas)

    @classmethod
    def de_arquivo(cls, caminho):
        return cls(pathlib.Path(caminho).read_text(encoding="utf-8").splitlines())

    def com_troca(self, antigo, novo):
        """Cópia do documento com uma substituição única — para o controle."""
        texto = "\n".join(self.linhas)
        if texto.count(antigo) != 1:
            raise FalhaDeExtracao(
                f"mutação não aplicável: {texto.count(antigo)} ocorrências de {antigo!r}"
            )
        return Documento(texto.replace(antigo, novo).splitlines())

    def secao(self, prefixo):
        """Bloco da seção cujo título começa por `prefixo` (ex.: '### 9.2')."""
        inicio = None
        padrao = re.compile(re.escape(prefixo) + r"(?![\d.])")
        for i, linha in enumerate(self.linhas):
            if padrao.match(linha):
                if inicio is not None:
                    raise FalhaDeExtracao(f"prefixo de seção ambíguo: {prefixo!r}")
                inicio = i
        if inicio is None:
            raise FalhaDeExtracao(f"seção não encontrada: {prefixo!r}")
        nivel = len(self.linhas[inicio]) - len(self.linhas[inicio].lstrip("#"))
        fim = len(self.linhas)
        for j in range(inicio + 1, len(self.linhas)):
            cabecalho = re.match(r"^(#{2,6})\s", self.linhas[j])
            if cabecalho and len(cabecalho.group(1)) <= nivel:
                fim = j
                break
        return self.linhas[inicio:fim]

    @staticmethod
    def tabelas(bloco):
        tabelas, corrente = [], []
        for linha in bloco:
            if linha.strip().startswith("|"):
                celulas = [c.strip() for c in linha.strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in celulas):
                    corrente.append(celulas)
            elif corrente:
                tabelas.append(corrente)
                corrente = []
        if corrente:
            tabelas.append(corrente)
        return tabelas

    def tabela(self, prefixo, indice=0):
        tabelas = self.tabelas(self.secao(prefixo))
        if indice >= len(tabelas):
            raise FalhaDeExtracao(
                f"{prefixo}: pedida a tabela {indice}, há {len(tabelas)}"
            )
        return tabelas[indice]

    @staticmethod
    def linha_da_tabela(tabela, rotulo):
        achadas = [l for l in tabela if l and rotulo in l[0]]
        if len(achadas) != 1:
            raise FalhaDeExtracao(
                f"linha {rotulo!r}: {len(achadas)} correspondências na tabela"
            )
        return achadas[0]

    def inline(self, prefixo, padrao):
        bloco = "\n".join(self.secao(prefixo))
        achados = re.findall(padrao, bloco)
        if len(achados) != 1:
            raise FalhaDeExtracao(
                f"{prefixo}: padrão {padrao!r} casou {len(achados)} vezes"
            )
        return achados[0]


# --------------------------------------------------------------------------
# fontes versionadas
# --------------------------------------------------------------------------
class Fontes:
    def __init__(self, raiz):
        self.raiz = pathlib.Path(raiz)
        self._cache = {}

    def _memo(self, chave, fn):
        if chave not in self._cache:
            self._cache[chave] = fn()
        return self._cache[chave]

    # ---- ground truth -----------------------------------------------------
    @property
    def metadata(self):
        def carrega():
            with open(self.raiz / "datasets/cve-metadata.csv", encoding="utf-8") as fh:
                return list(csv.DictReader(fh))

        return self._memo("metadata", carrega)

    @staticmethod
    def cwes_de(registro):
        bruto = registro["CWEs"].strip()
        if not bruto:
            return []
        saida = []
        for parte in re.split(r"[|,]", bruto):
            parte = parte.strip()
            if not parte:
                continue
            m = re.fullmatch(r"CWE-(\d+)", parte)
            if not m:
                raise ValueError(f"CWE fora de forma: {parte!r}")
            saida.append(f"CWE-{int(m.group(1)):03d}")
        return saida

    @property
    def lista(self):
        def carrega():
            linhas = (
                (self.raiz / "datasets/listas/cves-sast.txt")
                .read_text(encoding="utf-8")
                .splitlines()
            )
            saida = {}
            for linha in linhas:
                if not linha.strip():
                    continue
                cve, url, commit, cwes, caminho, linhas_gt = linha.split(",")
                saida[cve] = {
                    "url": url,
                    "commit": commit,
                    "cwes": cwes.split("|") if cwes else [],
                    "file": caminho,
                    "lines": [int(x) for x in linhas_gt.split("|") if x],
                }
            return saida

        return self._memo("lista", carrega)

    # ---- tratados ---------------------------------------------------------
    def tratados(self, ferramenta):
        def carrega():
            caminho = self.raiz / f"results/{ferramenta}/treated"
            return [
                json.loads(p.read_text(encoding="utf-8"))
                for p in sorted(caminho.glob("CVE-*.json"))
            ]

        return self._memo(f"tratados:{ferramenta}", carrega)

    # ---- cruzamento e circularidade ---------------------------------------
    def cruzamento(self, ferramenta):
        return self._memo(
            f"cruz:{ferramenta}",
            lambda: json.loads(
                (self.raiz / f"results/cruzamento/cruzamento-{ferramenta}.json").read_text(
                    encoding="utf-8"
                )
            ),
        )

    @property
    def matriz(self):
        def carrega():
            with open(
                self.raiz / "results/cruzamento/matriz-deteccao.csv", encoding="utf-8"
            ) as fh:
                return list(csv.DictReader(fh))

        return self._memo("matriz", carrega)

    @property
    def circularidade(self):
        return self._memo(
            "circ",
            lambda: json.loads(
                (self.raiz / "results/circularidade/circularidade.json").read_text(
                    encoding="utf-8"
                )
            ),
        )

    def particao(self, rotulo="ref"):
        for p in self.circularidade["particoes"]:
            if p["rotulo"] == rotulo:
                return p
        raise FalhaDeExtracao(f"partição {rotulo} ausente")

    def proveniencia(self, nome):
        return self._memo(
            f"prov:{nome}",
            lambda: json.loads(
                (self.raiz / f"results/proveniencia/{nome}.json").read_text(
                    encoding="utf-8"
                )
            ),
        )

    # ---- logs e relatórios ------------------------------------------------
    def logs_campanha(self, ferramenta):
        """Última linha de cada CVE, na leitura do check-log.py."""

        def carrega():
            saida = {}
            base = self.raiz / "logs/campanha-2026-09-17"
            for lote in sorted(base.glob("cves-sast-batch-*")):
                arq = lote / f"execution-log-{ferramenta}.csv"
                with open(arq, encoding="utf-8") as fh:
                    for reg in csv.DictReader(fh):
                        reg["lote"] = lote.name
                        saida[reg["cve"]] = reg
            return saida

        return self._memo(f"logs:{ferramenta}", carrega)

    def relatorios_normalizacao(self, ferramenta):
        def carrega():
            base = self.raiz / "logs/campanha-2026-09-17"
            return [
                json.loads((lote / f"normalize-report-{ferramenta}.json").read_text(encoding="utf-8"))
                for lote in sorted(base.glob("cves-sast-batch-*"))
            ]

        return self._memo(f"relnorm:{ferramenta}", carrega)

    def relatorio_avulso(self, caminho):
        return self._memo(
            f"avulso:{caminho}",
            lambda: json.loads((self.raiz / caminho).read_text(encoding="utf-8")),
        )

    def log_avulso(self, caminho):
        def carrega():
            with open(self.raiz / caminho, encoding="utf-8") as fh:
                saida = {}
                for reg in csv.DictReader(fh):
                    saida[reg["cve"]] = reg
                return saida

        return self._memo(f"logavulso:{caminho}", carrega)

    def csv(self, caminho):
        def carrega():
            with open(self.raiz / caminho, encoding="utf-8", newline="") as fh:
                return list(csv.DictReader(fh))

        return self._memo(f"csv:{caminho}", carrega)

    @property
    def capacidade_txt(self):
        return self._memo(
            "captxt",
            lambda: (self.raiz / "results/capacidade/capacidade.txt").read_text(encoding="utf-8"),
        )

    @property
    def wilson(self):
        """A wilson() do tools/deteccao-por-cwe.py, importada e não reimplementada."""

        def carrega():
            import importlib.util

            sys.dont_write_bytecode = True
            spec = importlib.util.spec_from_file_location(
                "deteccao_por_cwe", self.raiz / "tools/deteccao-por-cwe.py"
            )
            modulo = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(modulo)
            return modulo.wilson

        return self._memo("wilson", carrega)

    @property
    def claude_md(self):
        return self._memo(
            "claude",
            lambda: (self.raiz / "CLAUDE.md").read_text(encoding="utf-8"),
        )

    # ---- derivados --------------------------------------------------------
    @property
    def inventario_codeql(self):
        def carrega():
            saida = {}
            for rel in self.relatorios_normalizacao("codeql"):
                for item in rel["codeql_inventario"]:
                    saida[item["cve"]] = item
            return saida

        return self._memo("inv", carrega)


# --------------------------------------------------------------------------
# verificações
# --------------------------------------------------------------------------
VERIFICACOES = []


def verificacao(ident, secao, fonte):
    def registra(fn):
        VERIFICACOES.append(
            {"id": ident, "secao": secao, "fonte": fonte, "fn": fn}
        )
        return fn

    return registra


def par(rotulo, esperado, obtido, tolerancia=0.0):
    return {
        "rotulo": rotulo,
        "esperado": esperado,
        "obtido": obtido,
        "tolerancia": tolerancia,
    }


ROTULOS_ESTRUTURA = {
    "CVEs no conjunto": "CVEs no conjunto",
    "CVEs que apontam exatamente um arquivo": "apontam exatamente um arquivo",
    "Weaknesses": "Weaknesses (localizações)",
    "CVEs com mais de uma weakness": "mais de uma weakness",
    "CVEs com um único CWE": "um único CWE atribuído",
    "CVEs com mais de um CWE": "mais de um CWE atribuído",
    "CVEs sem CWE": "sem CWE atribuído",
    "Pares (CWE, arquivo) efetivamente afirmados": "efetivamente afirmados",
    "Pares gerados por expansão cartesiana": "expansão cartesiana",
    "CVEs com identificador de CWE sem zero": "sem zero à esquerda",
    "CVEs com caminho de arquivo fora de forma canônica": "fora de forma canônica",
}

ROTULOS_GRANDEZA = {
    "CVEs no conjunto": "CVEs no conjunto",
    "Pares (CWE, arquivo) afirmados": "arquivo) afirmados",
    "Pares no denominador": "Pares no denominador",
    "CVEs com saída bruta no CodeQL e no Semgrep": "no CodeQL e no Semgrep",
    "CVEs com saída bruta no Snyk Code": "no Snyk Code",
}


# ---- 2.2.1 caracterização estrutural -------------------------------------
@verificacao("2.2.1-estrutura", "2.2.1", "datasets/cve-metadata.csv")
def _(doc, f):
    tab = doc.tabela("#### 2.2.1", 0)
    meta = f.metadata
    cwes = {r["CVE"]: f.cwes_de(r) for r in meta}
    linhas_gt = {
        r["CVE"]: [x for x in r["FileLine"].split("|") if x.strip()] for r in meta
    }
    pares = sum(1 for c in cwes.values() if c)
    cartesiano = sum(len(c) for c in cwes.values() if c)
    sem_zero = sum(
        1
        for r in meta
        if any(
            re.fullmatch(r"CWE-\d{1,2}", p.strip())
            for p in re.split(r"[|,]", r["CWEs"])
            if p.strip()
        )
    )
    fora_canonica = sum(
        1 for r in meta if r["FilePath"] != r["FilePath"].strip().lstrip("/")
    )
    esperados = {
        "CVEs no conjunto": len(meta),
        "CVEs que apontam exatamente um arquivo": sum(
            1 for r in meta if r["FilePath"]
        ),
        "Weaknesses": sum(len(v) for v in linhas_gt.values()),
        "CVEs com mais de uma weakness": sum(1 for v in linhas_gt.values() if len(v) > 1),
        "CVEs com um único CWE": sum(1 for c in cwes.values() if len(c) == 1),
        "CVEs com mais de um CWE": sum(1 for c in cwes.values() if len(c) > 1),
        "CVEs sem CWE": sum(1 for c in cwes.values() if not c),
        "Pares (CWE, arquivo) efetivamente afirmados": pares,
        "Pares gerados por expansão cartesiana": cartesiano,
        "CVEs com identificador de CWE sem zero": sem_zero,
        "CVEs com caminho de arquivo fora de forma canônica": fora_canonica,
    }
    resultados = []
    for rotulo, obtido in esperados.items():
        linha = doc.linha_da_tabela(tab, ROTULOS_ESTRUTURA[rotulo])
        resultados.append(par(rotulo, numeros(linha[1])[0], obtido))
    # percentuais declarados entre parênteses
    linha_multi = doc.linha_da_tabela(tab, "CVEs com mais de um CWE")
    pct = numeros(linha_multi[1])[1]
    resultados.append(
        par(
            "% de CVEs multivalorados",
            pct,
            round(100 * esperados["CVEs com mais de um CWE"] / len(meta), 1),
            0.05,
        )
    )
    linha_cart = doc.linha_da_tabela(tab, "Pares gerados por expansão")
    resultados.append(
        par(
            "acréscimo da expansão cartesiana (%)",
            numeros(linha_cart[1])[1],
            round(100 * (cartesiano - pares) / pares, 1),
            0.05,
        )
    )
    return resultados


@verificacao("2.2.1-extensoes", "2.2.1", "datasets/cve-metadata.csv")
def _(doc, f):
    tab = doc.tabela("#### 2.2.1", 1)
    contagem = Counter()
    for r in f.metadata:
        nome = r["FilePath"].rsplit("/", 1)[-1]
        contagem["." + nome.rsplit(".", 1)[1] if "." in nome else "sem extensão"] += 1
    resultados = []
    for linha in tab[1:]:
        rotulo = linha[0].strip("`")
        resultados.append(par(f"extensão {rotulo}", um_numero(linha[1]), contagem[rotulo]))
    resultados.append(
        par("soma das extensões", sum(um_numero(l[1]) for l in tab[1:]), len(f.metadata))
    )
    return resultados


@verificacao("2.2.1-repositorios", "2.2.1", "datasets/cve-metadata.csv")
def _(doc, f):
    contagem = Counter(r["Repository"] for r in f.metadata)
    bloco = doc.secao("#### 2.2.1")
    texto = "\n".join(bloco)
    resultados = [
        par(
            "repositórios distintos",
            um_numero(re.search(r"vêm de (\d+) repositórios", texto).group(1)),
            len(contagem),
        )
    ]
    nomes = {
        "Bootstrap": "twbs/bootstrap",
        "Lodash": "lodash/lodash",
        "jQuery": "jquery/jquery",
        "Rendertron": "GoogleChrome/rendertron",
        "Next.js": "zeit/next.js",
    }
    declarado = re.search(
        r"o Bootstrap com (\d+), o Lodash com (\d+), o jQuery e o Rendertron com (\d+),?"
        r" o Next\.js com (\d+)",
        texto,
    )
    if not declarado:
        raise FalhaDeExtracao("2.2.1: frase de contagem por repositório não casou")
    valores = {
        "Bootstrap": int(declarado.group(1)),
        "Lodash": int(declarado.group(2)),
        "jQuery": int(declarado.group(3)),
        "Rendertron": int(declarado.group(3)),
        "Next.js": int(declarado.group(4)),
    }
    for nome, chave in nomes.items():
        obtido = sum(v for k, v in contagem.items() if k.endswith(chave + ".git"))
        resultados.append(par(f"CVEs de {nome}", valores[nome], obtido))
    # commits do Rendertron
    commits = {
        r["PrePatchCommit"]
        for r in f.metadata
        if "rendertron" in r["Repository"].lower()
    }
    resultados.append(par("commits distintos do Rendertron", 1, len(commits)))
    return resultados


@verificacao("2.2-conjunto", "2.2", "datasets/cve-metadata.csv")
def _(doc, f):
    texto = "\n".join(doc.secao("### 2.2 "))
    m = re.search(
        r"compreende (\d+) CVEs, distribuídos por (\d+) repositórios distintos e (\d+) CWEs",
        texto,
    )
    if not m:
        raise FalhaDeExtracao("2.2: frase de composição do conjunto não casou")
    distintos = set()
    for r in f.metadata:
        distintos.update(f.cwes_de(r))
    return [
        par("CVEs", int(m.group(1)), len(f.metadata)),
        par(
            "repositórios",
            int(m.group(2)),
            len({r["Repository"] for r in f.metadata}),
        ),
        par("CWEs distintos após normalização", int(m.group(3)), len(distintos)),
    ]


# ---- 2.2.2 proveniência ---------------------------------------------------
@verificacao("2.2.2-proveniencia", "2.2.2", "results/proveniencia/")
def _(doc, f):
    tab = doc.tabela("#### 2.2.2 ", 0)
    ref = f.proveniencia("cotejo-ref")
    total = ref["cves"]
    casados = ref["casados_normalizado"]
    identicos = len(ref["por_relacao"].get("identico", []))
    resultados = []
    linha = doc.linha_da_tabela(tab, "Descrições idênticas")
    resultados.append(par("casados na referência", numeros(linha[1])[0], casados))
    resultados.append(par("total de registros", numeros(linha[1])[1], total))
    resultados.append(
        par("percentual de herança", numeros(linha[1])[2], round(100 * casados / total, 1), 0.05)
    )
    linha = doc.linha_da_tabela(tab, "Destas, com conjunto de CWEs idêntico")
    resultados.append(par("idênticos em conjunto", numeros(linha[1])[0], identicos))
    return resultados


# ---- 3.1 digests ----------------------------------------------------------
@verificacao("3.1-digests", "3.1", "CLAUDE.md")
def _(doc, f):
    bloco = "\n".join(doc.secao("### 3.1"))
    declarados = dict(
        re.findall(r"ic-security-lab-([a-z-]+)\s+@(sha256:[0-9a-f]{64})", bloco)
    )
    if len(declarados) != 3:
        raise FalhaDeExtracao(f"3.1: {len(declarados)} digests no texto")
    vigentes = dict(
        re.findall(
            r"ghcr\.io/[^/]+/ic-security-lab-([a-z-]+)@(sha256:[0-9a-f]{64})",
            f.claude_md.split("### Histórico")[0],
        )
    )
    resultados = [
        par(f"digest {nome}", declarados[nome], vigentes.get(nome))
        for nome in sorted(declarados)
    ]
    execucao = re.search(r"execução `(\d+)`", bloco).group(1)
    resultados.append(
        par(
            "execução do rebuild",
            execucao,
            re.search(r"Execução `(\d+)`, construída em", f.claude_md).group(1),
        )
    )
    return resultados


# ---- 4.4 / 9.4 duração ----------------------------------------------------
def duracoes(f, ferramenta, so_analisados=False):
    """Durações por CVE. A campanha publicou sobre as 223 linhas do registro."""
    return [
        int(reg["duracao_segundos"])
        for reg in f.logs_campanha(ferramenta).values()
        if not so_analisados or reg["status"] in ("OK", "SEM_ACHADOS")
    ]


@verificacao("9.4-duracao", "9.4", "logs/campanha-2026-09-17/")
def _(doc, f):
    tab = doc.tabela("### 9.4", 0)
    rotulos = {"CodeQL": "codeql", "Semgrep": "semgrep", "Snyk Code": "snyk-code"}
    resultados = []
    for rotulo, ferramenta in rotulos.items():
        linha = doc.linha_da_tabela(tab, rotulo)
        d = duracoes(f, ferramenta)
        resultados += [
            par(f"{rotulo}: mediana", um_numero(linha[1]), round(statistics.median(d))),
            par(f"{rotulo}: média", um_numero(linha[2]), round(statistics.mean(d), 1), 0.05),
            par(f"{rotulo}: máximo", um_numero(linha[3]), max(d)),
            par(f"{rotulo}: 1º quartil", numeros(linha[4])[0], quartil(d, 0.25)),
            par(f"{rotulo}: 3º quartil", numeros(linha[4])[1], quartil(d, 0.75)),
            par(f"{rotulo}: soma (h)", um_numero(linha[5]), round(sum(d) / 3600, 2), 0.005),
        ]
    return resultados


def quartil(valores, q):
    quartis = statistics.quantiles(sorted(valores), n=4, method="inclusive")
    return round(quartis[0] if q == 0.25 else quartis[2])


@verificacao("9.4-porte", "9.4", "logs/campanha-2026-09-17/ + normalize-report")
def _(doc, f):
    tab = doc.tabela("### 9.4", 1)
    inv = f.inventario_codeql
    logs = f.logs_campanha("codeql")
    faixas = [
        ("0–10", 0, 10),
        ("11–50", 11, 50),
        ("51–100", 51, 100),
        ("101–200", 101, 200),
        ("201–500", 201, 500),
        ("501–1000", 501, 1000),
        ("mais de 1000", 1001, 10 ** 9),
    ]
    resultados = []
    for rotulo, minimo, maximo in faixas:
        linha = doc.linha_da_tabela(tab, rotulo)
        casos = [
            int(logs[cve]["duracao_segundos"])
            for cve, item in inv.items()
            if minimo <= item["notificacao"] <= maximo and cve in logs
        ]
        resultados += [
            par(f"faixa {rotulo}: CVEs", um_numero(linha[1]), len(casos)),
            par(f"faixa {rotulo}: mediana", um_numero(linha[2]), round(statistics.median(casos))),
        ]
    texto = "\n".join(doc.secao("### 9.4"))
    m = re.search(r"(\d+) dos (\d+) CVEs têm (\d+) arquivos ou menos", texto)
    resultados.append(
        par(
            "CVEs com até 50 arquivos",
            int(m.group(1)),
            sum(1 for item in inv.values() if item["notificacao"] <= int(m.group(3))),
        )
    )
    resultados.append(par("CVEs no inventário", int(m.group(2)), len(inv)))
    m = re.search(r"com ([\d.]+) arquivos extraídos, custou (\d+) segundos", texto)
    maior = max(inv.items(), key=lambda kv: kv[1]["notificacao"])
    resultados += [
        par("maior extração", um_numero(m.group(1)), maior[1]["notificacao"]),
        par(
            "duração do maior caso",
            int(m.group(2)),
            int(logs[maior[0]]["duracao_segundos"]),
        ),
    ]
    return resultados


# ---- 5.5 volume -----------------------------------------------------------
@verificacao("5.5-volume", "5.5", "results/*/treated + CLAUDE.md")
def _(doc, f):
    texto = "\n".join(doc.secao("### 5.5"))
    m = re.search(r"Os resultados normalizados somam ([\d,]+) MiB", texto)
    total = 0
    for ferramenta in FERRAMENTAS:
        for p in (f.raiz / f"results/{ferramenta}/treated").glob("CVE-*.json"):
            total += p.stat().st_size
    resultados = [
        par(
            "tratados (MiB)",
            um_numero(m.group(1)),
            round(total / 1024 / 1024, 1),
            0.05,
        )
    ]
    # os brutos não são versionados: a fonte declarada é o CLAUDE.md
    bruto = re.search(r"(\d+) MiB de saída bruta, dos quais o Semgrep responde por (\d+) MiB \((\d+)%\)", texto)
    claude = f.claude_md
    resultados += [
        par(
            "bruto total (MiB)",
            int(bruto.group(1)),
            round(um_numero(re.search(r"\*\*Total\*\* \| \*\*658\*\* \| \*\*([\d,]+) MiB", claude).group(1))),
        ),
        par(
            "bruto do Semgrep (MiB)",
            int(bruto.group(2)),
            round(um_numero(re.search(r"Semgrep responde por 88% do volume bruto\*\* — ([\d,]+) dos", claude).group(1))),
        ),
    ]
    copia = re.search(r"somando ([\d,]+) MiB", texto)
    resultados.append(
        par(
            "cópia externa (MiB)",
            um_numero(copia.group(1)),
            round(
                sum(
                    int(x.replace(".", ""))
                    for x in re.findall(
                        r"raws-[a-z-]+-2026-09-17\.tar\.zst` \| ([\d.]+) \|", claude
                    )
                )
                / 1024
                / 1024,
                2,
            ),
            0.01,
        )
    )
    return resultados


# ---- 5.6 normalização -----------------------------------------------------
@verificacao("5.6-normalizacao", "5.6", "logs/campanha-2026-09-17/normalize-report-*")
def _(doc, f):
    tab = doc.tabela("### 5.6", 0)
    rotulos = {"CodeQL": "codeql", "Semgrep": "semgrep", "Snyk Code": "snyk-code"}
    resultados = []
    for rotulo, ferramenta in rotulos.items():
        linha = doc.linha_da_tabela(tab, rotulo)
        soma = sum(r["duracao_segundos"]["total"] for r in f.relatorios_normalizacao(ferramenta))
        resultados.append(
            par(f"normalização {rotulo} (s)", um_numero(linha[1]), round(soma, 2), 0.005)
        )
    texto = "\n".join(doc.secao("### 5.6"))
    m = re.search(r"rodou sobre ([\d.]+) achados reais, em (\d+) resultados", texto)
    total_achados = sum(
        len(t["findings"]) for ferramenta in FERRAMENTAS for t in f.tratados(ferramenta)
    )
    total_tratados = sum(len(f.tratados(ferramenta)) for ferramenta in FERRAMENTAS)
    resultados += [
        par("achados normalizados", um_numero(m.group(1)), total_achados),
        par("tratados produzidos", int(m.group(2)), total_tratados),
    ]
    m = re.search(r"Zero colisões nas três ferramentas, sobre os ([\d.]+) achados", texto)
    resultados.append(par("achados na conferência de colisão", um_numero(m.group(1)), total_achados))
    colisoes = {
        ferramenta: sum(
            r["colisoes_chave_ordenacao"]["total"]
            for r in f.relatorios_normalizacao(ferramenta)
        )
        for ferramenta in FERRAMENTAS
    }
    for ferramenta in FERRAMENTAS:
        resultados.append(par(f"colisões {ferramenta}", 0, colisoes[ferramenta]))
    m = re.search(r"acusa (\d+), (\d+) e (\d+) colisões", texto)
    if m:
        controle = colisoes_sem_colunas(f)
        for i, ferramenta in enumerate(FERRAMENTAS):
            resultados.append(
                par(
                    f"controle positivo, colisões sem coluna ({ferramenta})",
                    int(m.group(i + 1)),
                    controle[ferramenta],
                )
            )
    return resultados


def colisoes_sem_colunas(f):
    """Reconta colisões com a chave do schema 1.1 — o controle positivo."""
    saida = {}
    for ferramenta in FERRAMENTAS:
        total = 0
        for tratado in f.tratados(ferramenta):
            chaves = Counter(
                (
                    a["file_path"],
                    a["line_start"],
                    a["line_end"],
                    a["rule_id"],
                    a["message"],
                )
                for a in tratado["findings"]
            )
            total += sum(v - 1 for v in chaves.values() if v > 1)
        saida[ferramenta] = total
    return saida


# ---- 7.4 denominador e tabela de primário ---------------------------------
@verificacao("7.4-grandezas", "7.4", "results/cruzamento/ + results/*/treated")
def _(doc, f):
    tab = [t for t in doc.tabelas(doc.secao("### 7.4")) if any("Grandeza" in c for c in t[0])]
    if len(tab) != 1:
        raise FalhaDeExtracao("7.4: tabela de grandezas não encontrada")
    tab = tab[0]
    cruz = f.cruzamento("codeql")
    valores = {
        "CVEs no conjunto": len(f.lista),
        "Pares (CWE, arquivo) afirmados": sum(
            1 for r in f.metadata if f.cwes_de(r)
        ),
        "Pares no denominador": cruz["denominador"]["pares"],
        "CVEs com saída bruta no CodeQL e no Semgrep": len(f.tratados("codeql")),
        "CVEs com saída bruta no Snyk Code": len(f.tratados("snyk-code")),
    }
    resultados = []
    for rotulo, obtido in valores.items():
        linha = doc.linha_da_tabela(tab, ROTULOS_GRANDEZA[rotulo])
        resultados.append(par(rotulo, um_numero(linha[1]), obtido))
    resultados.append(
        par(
            "tratados do Semgrep (mesmo número do CodeQL)",
            valores["CVEs com saída bruta no CodeQL e no Semgrep"],
            len(f.tratados("semgrep")),
        )
    )
    return resultados


@verificacao("7.4-primario", "7.4", "datasets/cve-metadata.csv + datasets/cwe-primario.csv")
def _(doc, f):
    tab = [t for t in doc.tabelas(doc.secao("### 7.4")) if any("Conjunto declarado" in c for c in t[0])]
    if len(tab) != 1:
        raise FalhaDeExtracao("7.4: tabela de CWE primário não encontrada")
    tab = tab[0]
    conjuntos = Counter()
    for r in f.metadata:
        cwes = f.cwes_de(r)
        if len(cwes) > 1:
            conjuntos["|".join(sorted(cwes))] += 1
    with open(f.raiz / "datasets/cwe-primario.csv", encoding="utf-8") as fh:
        tabela_versionada = {
            "|".join(sorted(l["conjunto"].split("|"))): l for l in csv.DictReader(fh)
        }
    resultados = []
    soma_texto = 0
    for linha in tab[1:]:
        declarados = re.findall(r"(?:CWE-)?(\d{2,3})\b", linha[0])
        chave = "|".join(sorted(f"CWE-{int(x):03d}" for x in declarados))
        quantidade = um_numero(linha[1])
        soma_texto += quantidade
        resultados.append(par(f"conjunto {chave}", quantidade, conjuntos.get(chave, 0)))
        if chave in tabela_versionada:
            resultados.append(
                par(
                    f"primário de {chave}",
                    re.sub(r"\s+", "", linha[2]).replace("adefinir", "a definir"),
                    tabela_versionada[chave]["primario"] or "a definir",
                )
            )
    resultados.append(
        par("soma dos conjuntos multivalorados", soma_texto, sum(conjuntos.values()))
    )
    resultados.append(
        par("conjuntos distintos", len(tab) - 1, len(conjuntos))
    )
    return resultados


# ---- 7.7 critério de linha ------------------------------------------------
@verificacao("7.7-linha", "7.7", "results/*/treated + datasets/listas/cves-sast.txt")
def _(doc, f):
    texto = "\n".join(doc.secao("### 7.7"))
    m = re.search(
        r"ganho da sobreposição sobre a coincidência exata da linha inicial é de\s+"
        r"\*\*(\d+), (\d+) e (\d+) achados\*\*",
        texto,
    )
    if not m:
        raise FalhaDeExtracao("7.7: frase do ganho não casou")
    m2 = re.search(r"sobre ([\d.]+), (\d+) e (\d+) achados no arquivo", texto)
    resultados = []
    for i, ferramenta in enumerate(FERRAMENTAS):
        ganho, no_arquivo = ganhos_de_sobreposicao(f, ferramenta)
        resultados.append(par(f"ganho da sobreposição ({ferramenta})", int(m.group(i + 1)), ganho))
        resultados.append(
            par(f"achados no arquivo do gt ({ferramenta})", um_numero(m2.group(i + 1)), no_arquivo)
        )
    m3 = re.search(r"distância mediana até a linha do ground truth mais próxima é de (\d+), (\d+) e (\d+) linhas", texto)
    m4 = re.search(r"mais de (\d+)% dos achados estão a mais de (\d+) linhas", texto)
    for i, ferramenta in enumerate(FERRAMENTAS):
        distancias = distancias_no_arquivo(f, ferramenta)
        resultados.append(
            par(f"distância mediana ({ferramenta})", int(m3.group(i + 1)), int(statistics.median(distancias)))
        )
        acima = 100 * sum(1 for d in distancias if d > int(m4.group(2))) / len(distancias)
        resultados.append(
            par(
                f"fração acima de {m4.group(2)} linhas ({ferramenta}) ≥ {m4.group(1)}%",
                True,
                acima > int(m4.group(1)),
            )
        )
    m5 = re.search(r"(\d+,\d+)% dos achados do CodeQL não trazem linha final", texto)
    achados = f.tratados("codeql")
    total = sum(len(t["findings"]) for t in achados)
    nulos = sum(1 for t in achados for a in t["findings"] if a["line_end"] is None)
    resultados.append(
        par("% do CodeQL sem linha final", um_numero(m5.group(1)), round(100 * nulos / total, 1), 0.05)
    )
    for ferramenta in ("semgrep", "snyk-code"):
        nulos_outros = sum(
            1 for t in f.tratados(ferramenta) for a in t["findings"] if a["line_end"] is None
        )
        resultados.append(par(f"achados sem linha final ({ferramenta})", 0, nulos_outros))
    m6 = re.search(r"\*\*nenhum\*\* achado sem CWE, em ([\d.]+)", texto)
    sem_cwe = sum(
        1
        for ferramenta in FERRAMENTAS
        for t in f.tratados(ferramenta)
        for a in t["findings"]
        if not a["cwe"]
    )
    resultados.append(par("achados sem CWE", 0, sem_cwe))
    resultados.append(
        par(
            "universo da verificação de CWE",
            um_numero(m6.group(1)),
            sum(len(t["findings"]) for ft in FERRAMENTAS for t in f.tratados(ft)),
        )
    )
    m7 = re.search(r"recuperou (\d+) achados que sairiam sem CWE", texto)
    cadeia_nua = sum(
        len(r["cwe"].get("semgrep_cadeia_nua", []))
        for r in f.relatorios_normalizacao("semgrep")
    )
    resultados.append(par("achados de cadeia nua no Semgrep", int(m7.group(1)), cadeia_nua))
    return resultados


def _linhas_gt(f, cve):
    return f.lista[cve]["lines"]


def ganhos_de_sobreposicao(f, ferramenta):
    """Achados que casam por sobreposição e não casariam por linha inicial."""
    ganho = no_arquivo = 0
    for tratado in f.tratados(ferramenta):
        meta = tratado["metadata"]
        gt_linhas = set(meta["gt_file_lines"] or [])
        for a in tratado["findings"]:
            if a["file_path"] != meta["gt_file_path"]:
                continue
            no_arquivo += 1
            inicio = a["line_start"]
            fim = a["line_end"] if a["line_end"] is not None else inicio
            if inicio is None:
                continue
            exato = inicio in gt_linhas
            intervalo = any(inicio <= l <= fim for l in gt_linhas)
            if intervalo and not exato:
                ganho += 1
    return ganho, no_arquivo


def distancias_no_arquivo(f, ferramenta):
    distancias = []
    for tratado in f.tratados(ferramenta):
        meta = tratado["metadata"]
        gt_linhas = meta["gt_file_lines"] or []
        if not gt_linhas:
            continue
        for a in tratado["findings"]:
            if a["file_path"] != meta["gt_file_path"] or a["line_start"] is None:
                continue
            distancias.append(min(abs(a["line_start"] - l) for l in gt_linhas))
    return distancias


# ---- 8.6 ensaio local -----------------------------------------------------
@verificacao("8.6-ensaio-local", "8.6", "logs/execution-log-*.csv + logs/normalize-report-codeql.json")
def _(doc, f):
    texto = "\n".join(doc.secao("### 8.6"))
    m = re.search(r"a totalidade dos (\d+) achados produzidos", texto)
    resultados = []
    m2 = re.search(
        r"medianas por CVE de (\d+) s, (\d+) s e (\d+) s para Semgrep, CodeQL e Snyk Code, "
        r"com máximos de (\d+) s, (\d+) s e (\d+) s",
        texto,
    )
    ordem = ["semgrep", "codeql", "snyk-code"]
    for i, ferramenta in enumerate(ordem):
        log = f.log_avulso(f"logs/execution-log-{ferramenta}.csv")
        d = [
            int(r["duracao_segundos"])
            for r in log.values()
            if r["status"] in ("OK", "SEM_ACHADOS")
        ]
        resultados += [
            par(
                f"ensaio local, mediana {ferramenta}",
                int(m2.group(i + 1)),
                round(statistics.median(d)),
            ),
            par(f"ensaio local, máximo {ferramenta}", int(m2.group(i + 4)), max(d)),
        ]
    tabela = doc.tabela("### 8.6", 1)
    inv = {
        item["cve"]: item
        for item in f.relatorio_avulso("logs/normalize-report-codeql.json")["codeql_inventario"]
    }
    log = f.log_avulso("logs/execution-log-codeql.csv")
    for linha in tabela[1:]:
        cve = linha[0].strip("`")
        resultados += [
            par(f"{cve}: duração", um_numero(linha[1]), int(log[cve]["duracao_segundos"])),
            par(f"{cve}: arquivos extraídos", um_numero(linha[2]), inv[cve]["notificacao"]),
        ]
    return resultados


# ---- 8.7 ensaio de fumaça -------------------------------------------------
@verificacao("8.7-fumaca", "8.7", "logs/ensaio-fumaca-2026-09-16/")
def _(doc, f):
    texto = "\n".join(doc.secao("### 8.7"))
    log = f.log_avulso("logs/ensaio-fumaca-2026-09-16/execution-log-codeql.csv")
    resultados = []
    m = re.search(r"lote dirigido de (\w+) CVEs", texto)
    por_extenso = {"sete": 7, "seis": 6, "cinco": 5}
    resultados.append(par("CVEs do ensaio de fumaça", por_extenso[m.group(1)], len(log)))
    m = re.search(r"execução `(\d+)`", texto)
    resultados.append(
        par(
            "identificador da execução",
            m.group(1),
            re.search(r"Execução `(\d+)` do `analise-lote\.yml`", f.claude_md).group(1),
        )
    )
    rel = f.relatorio_avulso("logs/ensaio-fumaca-2026-09-16/normalize-report-codeql.json")
    inv = {i["cve"]: i for i in rel["codeql_inventario"]}
    m = re.search(r"(\d+) arquivos `\.ts` extraídos no `(CVE-[\d-]+)`", texto)
    resultados.append(
        par(
            "inventário do CodeQL: fontes que batem",
            len(inv),
            sum(1 for i in inv.values() if i["bate"]),
        )
    )
    m2 = re.search(r"inclusive no multilíngue, com (\d+) arquivos extraídos", texto)
    resultados.append(
        par("maior extração do ensaio", int(m2.group(1)), max(i["notificacao"] for i in inv.values()))
    )
    m3 = re.search(r"com (\d+) arquivos, custou (\d+) segundos no CodeQL, menos que um CVE de (\d+) arquivos \((\d+) segundos\)", texto)
    if m3:
        cve_grande = [c for c, i in inv.items() if i["notificacao"] == int(m3.group(1))]
        resultados.append(
            par(
                "duração do CVE de maior porte",
                int(m3.group(2)),
                int(log[cve_grande[0]]["duracao_segundos"]),
            )
        )
        cve_medio = [c for c, i in inv.items() if i["notificacao"] == int(m3.group(3))]
        resultados.append(
            par(
                "duração do CVE de 58 arquivos",
                int(m3.group(4)),
                int(log[cve_medio[0]]["duracao_segundos"]),
            )
        )
    return resultados


# ---- 8.8 campanha ---------------------------------------------------------
@verificacao("8.8-campanha", "8.8", "logs/campanha-2026-09-17/ + CLAUDE.md")
def _(doc, f):
    tab = doc.tabela("### 8.8", 0)
    declarados = {}
    for linha in tab[1:]:
        for i in (0, 4):
            if i + 2 < len(linha) and linha[i].strip("`"):
                declarados[linha[i].strip("` ")] = (
                    linha[i + 1].strip("` "),
                    linha[i + 2].strip(),
                )
    claude = f.claude_md
    resultados = [par("lotes na tabela", 8, len(declarados))]
    for lote, (execucao, data) in sorted(declarados.items()):
        esperado = re.search(
            rf"\| `{lote}` \| `(\d+)`", claude
        )
        resultados.append(
            par(f"execução do lote {lote}", execucao, esperado.group(1) if esperado else None)
        )
        caminho = f.raiz / f"logs/campanha-2026-09-17/cves-sast-batch-{lote}"
        resultados.append(par(f"logs do lote {lote}", True, caminho.is_dir()))
    texto = "\n".join(doc.secao("### 8.8"))
    m = re.search(r"o commit do repositório do estudo `(\w+)` em todos", texto)
    resultados.append(par("commit da campanha", m.group(1), re.search(r"commit `(\w+)` em todos", claude).group(1)))
    m = re.search(r"limites de análise em (\d+) segundos, conferidos pela linha que o próprio container imprime em (\d+) de (\d+) jobs", texto)
    limites = set()
    for ferramenta in FERRAMENTAS:
        for reg in f.logs_campanha(ferramenta).values():
            limites.update(int(x) for x in re.findall(r"TIMEOUT_(?:ANALYZE|ANALISE|CREATE)=(\d+)", reg["mensagem"]))
    resultados.append(par("limite de análise efetivo", {int(m.group(1))}, limites))
    m = re.search(r"(\d+) de (\d+) testes com achados, e nenhum dos (\d+) sem achados", texto)
    logs_snyk = f.logs_campanha("snyk-code")
    com_achados = sum(1 for r in logs_snyk.values() if r["status"] == "OK")
    sem_achados = sum(1 for r in logs_snyk.values() if r["status"] == "SEM_ACHADOS")
    resultados += [
        par("testes do Snyk com achados", int(m.group(1)), com_achados),
        par("testes do Snyk sem achados", int(m.group(3)), sem_achados),
    ]
    return resultados


# ---- 9.1 cobertura --------------------------------------------------------
@verificacao("9.1-cobertura", "9.1", "results/*/treated + results/cruzamento/")
def _(doc, f):
    tab = doc.tabela("### 9.1", 0)
    linha = doc.linha_da_tabela(tab, "CVEs com saída bruta")
    resultados = [
        par(f"tratados de {ferramenta}", um_numero(linha[i + 1]), len(f.tratados(ferramenta)))
        for i, ferramenta in enumerate(FERRAMENTAS)
    ]
    resultados.append(par("total declarado na linha", um_numero(linha[0].split("de")[-1]), len(f.lista)))
    linha = doc.linha_da_tabela(tab, "Pares no denominador")
    for i, ferramenta in enumerate(FERRAMENTAS):
        resultados.append(
            par(
                f"denominador de {ferramenta}",
                um_numero(linha[i + 1]),
                f.cruzamento(ferramenta)["denominador"]["pares"],
            )
        )
    return resultados


# ---- 9.2 matriz -----------------------------------------------------------
ROTULOS_NIVEL = {
    "0 — achado na árvore": "nivel_0",
    "1 — arquivo": "nivel_1",
    "2 generosa": "nivel_2_generosa",
    "2 estrita": "nivel_2_estrita",
    "3 — arquivo e linha": "nivel_3",
    "4 generosa": "nivel_4_generosa",
    "4 estrita": "nivel_4_estrita",
}


@verificacao("9.2-matriz", "9.2", "results/cruzamento/cruzamento-*.json")
def _(doc, f):
    tab = doc.tabela("### 9.2", 0)
    resultados = []
    for rotulo, chave in ROTULOS_NIVEL.items():
        linha = doc.linha_da_tabela(tab, rotulo)
        for i, ferramenta in enumerate(FERRAMENTAS):
            valores = numeros(linha[i + 1])
            agregado = f.cruzamento(ferramenta)["agregados"][chave]
            base = agregado["acertos"] + agregado["nao_acertos"]
            resultados.append(
                par(f"{chave} de {ferramenta}", valores[0], agregado["acertos"])
            )
            if len(valores) > 1:
                resultados.append(
                    par(
                        f"{chave} de {ferramenta} (%)",
                        valores[1],
                        round(100 * agregado["acertos"] / base, 1),
                        0.05,
                    )
                )
    return resultados


# ---- 9.3 nível 1 × nível 3 ------------------------------------------------
@verificacao("9.3-nivel1-nivel3", "9.3", "results/cruzamento/cruzamento-*.json")
def _(doc, f):
    tab = doc.tabela("### 9.3", 0)
    linhas = {
        "CVEs no nível 1": "cves_nivel_1",
        "destes, também no nível 3": "destes_nivel_3",
        "perdidos": "destes_sem_nivel_3",
    }
    resultados = []
    for rotulo, chave in linhas.items():
        linha = doc.linha_da_tabela(tab, rotulo)
        for i, ferramenta in enumerate(FERRAMENTAS):
            valores = numeros(linha[i + 1])
            bloco = f.cruzamento(ferramenta)["nivel_1_e_nivel_3"]
            resultados.append(par(f"{chave} de {ferramenta}", valores[0], bloco[chave]))
            if len(valores) > 1:
                resultados.append(
                    par(
                        f"{chave} de {ferramenta} (%)",
                        valores[1],
                        round(100 * bloco["destes_sem_nivel_3"] / bloco["cves_nivel_1"]),
                        0.5,
                    )
                )
    return resultados


# ---- 9.5 volume de alertas ------------------------------------------------
@verificacao("9.5-volume", "9.5", "results/*/treated")
def _(doc, f):
    tab = doc.tabela("### 9.5", 0)
    achados = doc.linha_da_tabela(tab, "Achados")
    fracao = doc.linha_da_tabela(tab, "Fração fora do arquivo")
    resultados = []
    for i, ferramenta in enumerate(FERRAMENTAS):
        tratados = f.tratados(ferramenta)
        total = sum(len(t["findings"]) for t in tratados)
        fora = sum(
            1
            for t in tratados
            for a in t["findings"]
            if a["file_path"] != t["metadata"]["gt_file_path"]
        )
        resultados += [
            par(f"achados de {ferramenta}", um_numero(achados[i + 1]), total),
            par(
                f"fração fora do arquivo ({ferramenta})",
                um_numero(fracao[i + 1]),
                round(100 * fora / total, 1),
                0.05,
            ),
        ]
    texto = "\n".join(doc.secao("### 9.5"))
    m = re.search(r"um único — o `(CVE-[\d-]+)` — responde por ([\d.]+)", texto)
    tratado = [t for t in f.tratados("semgrep") if t["metadata"]["cve_id"] == m.group(1)][0]
    resultados.append(
        par(f"achados do {m.group(1)} no Semgrep", um_numero(m.group(2)), len(tratado["findings"]))
    )
    return resultados


# ---- 9.6 inventário -------------------------------------------------------
@verificacao("9.6-inventario", "9.6", "logs/campanha-2026-09-17/normalize-report-codeql.json")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.6"))
    inv = f.inventario_codeql
    m = re.search(r"bateu em \*\*(\d+) dos (\d+) CVEs\*\*", texto)
    resultados = [
        par("CVEs em que o inventário bate", int(m.group(1)), sum(1 for i in inv.values() if i["bate"])),
        par("CVEs no inventário", int(m.group(2)), len(inv)),
    ]
    m = re.search(r"maior extração observada foi de ([\d.]+) arquivos", texto)
    resultados.append(
        par("maior extração", um_numero(m.group(1)), max(i["notificacao"] for i in inv.values()))
    )
    divergentes_texto = sorted(set(re.findall(r"`(CVE-[\d-]+)`", texto)))
    divergentes = sorted(c for c, i in inv.items() if not i["bate"])
    resultados.append(par("CVEs divergentes nomeados", divergentes_texto, divergentes))
    m = re.search(r"tem de (\d+) a (\d+) arquivos a mais", texto)
    diferencas = [
        i["artifacts_depurado"] - i["notificacao"] for i in inv.values() if not i["bate"]
    ]
    resultados += [
        par("diferença mínima", int(m.group(1)), min(diferencas)),
        par("diferença máxima", int(m.group(2)), max(diferencas)),
        par("divergências no sentido do artifacts", True, all(d > 0 for d in diferencas)),
    ]
    m = re.search(r"Os (\d+) arquivos a mais somados", texto)
    resultados.append(par("arquivos a mais somados", int(m.group(1)), sum(diferencas)))
    return resultados


# ---- 9.7 cobertura por arquivo --------------------------------------------
@verificacao("9.7-cobertura-arquivo", "9.7", "results/cruzamento/cruzamento-*.json")
def _(doc, f):
    tab = doc.tabela("### 9.7", 0)
    considerado = doc.linha_da_tabela(tab, "Arquivo do ground truth considerado")
    nao = doc.linha_da_tabela(tab, "Não considerado")
    resultados = []
    for i, ferramenta in ((0, "codeql"), (1, "semgrep")):
        estados = Counter(
            t["metadata"]["gt_file_scanned"] for t in f.tratados(ferramenta)
        )
        resultados += [
            par(f"gt_file_scanned true ({ferramenta})", um_numero(considerado[i + 1]), estados[True]),
            par(f"gt_file_scanned false ({ferramenta})", um_numero(nao[i + 1]), estados[False]),
        ]
    texto = "\n".join(doc.secao("### 9.7"))
    m = re.search(r"a condição é indeterminada nos (\d+)", texto)
    nulos = sum(
        1 for t in f.tratados("snyk-code") if t["metadata"]["gt_file_scanned"] is None
    )
    resultados.append(par("indeterminados no Snyk Code", int(m.group(1)), nulos))
    return resultados


# ---- 9.10 circularidade ---------------------------------------------------
@verificacao("9.10-particao", "9.10", "results/circularidade/circularidade.json")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.10"))
    p = f.particao("ref")
    tamanhos = p["tamanhos"]
    m = re.search(r"\*\*(\d+) CVEs com etiqueta herdada e (\d+) sem\*\*", texto)
    resultados = [
        par("grupo herdado", int(m.group(1)), tamanhos["herdado"]),
        par("grupo não herdado", int(m.group(2)), tamanhos["nao_herdado"]),
    ]
    m = re.search(r"reconstrói a matriz da Seção 9\.2 em (\d+) células", texto)
    resultados.append(par("células reconstruídas", int(m.group(1)), len(p["tabela"])))
    m = re.search(r"em \*\*(\d+) dos (\d+) CVEs \((\d+,\d+)%\)\*\*", texto)
    ref = f.proveniencia("cotejo-ref")
    resultados += [
        par("casados citados na 9.10", int(m.group(1)), ref["casados_normalizado"]),
        par("conjunto citado na 9.10", int(m.group(2)), ref["cves"]),
        par(
            "percentual de herança citado",
            um_numero(m.group(3)),
            round(100 * ref["casados_normalizado"] / ref["cves"], 1),
            0.05,
        ),
    ]
    return resultados


@verificacao("9.10-tabelas", "9.10", "results/circularidade/circularidade.json")
def _(doc, f):
    p = f.particao("ref")
    tabela = p["tabela"]
    acertos = doc.tabela("### 9.10", 0)
    deltas = doc.tabela("### 9.10", 1)
    colunas = [
        ("codeql", "herdado"),
        ("codeql", "nao_herdado"),
        ("semgrep", "herdado"),
        ("semgrep", "nao_herdado"),
        ("snyk-code", "herdado"),
        ("snyk-code", "nao_herdado"),
    ]
    rotulos = {
        "| 0 ": "nivel_0",
        "| 1 ": "nivel_1",
        "2 generosa": "nivel_2_generosa",
        "2 estrita": "nivel_2_estrita",
        "| 3 ": "nivel_3",
        "4 generosa": "nivel_4_generosa",
        "4 estrita": "nivel_4_estrita",
    }
    resultados = []
    for linha in acertos[1:]:
        chave = nivel_da_linha(linha[0])
        for i, (ferramenta, grupo) in enumerate(colunas):
            valores = numeros(linha[i + 1])
            celula = tabela[f"{ferramenta}|{chave}"][grupo]
            resultados += [
                par(f"{chave} {ferramenta} {grupo}: acertos", valores[0], celula["acertos"]),
                par(f"{chave} {ferramenta} {grupo}: base", valores[1], celula["base"]),
            ]
    for linha in deltas[1:]:
        chave = nivel_da_linha(linha[0])
        for i, ferramenta in enumerate(FERRAMENTAS):
            valor = numeros(linha[i + 1].replace("−", "-"))[0]
            sinal = -1 if "−" in linha[i + 1] or linha[i + 1].strip().startswith("-") else 1
            resultados.append(
                par(
                    f"delta {chave} {ferramenta} (pp)",
                    sinal * valor,
                    round(tabela[f"{ferramenta}|{chave}"]["delta_pp"], 1),
                    0.05,
                )
            )
    return resultados


def nivel_da_linha(rotulo):
    rotulo = rotulo.strip()
    if "generosa" in rotulo:
        base = "generosa"
    elif "estrita" in rotulo:
        base = "estrita"
    else:
        base = None
    numero = re.match(r"(\d)", rotulo)
    if not numero:
        raise FalhaDeExtracao(f"rótulo de nível não reconhecido: {rotulo!r}")
    if base:
        return f"nivel_{numero.group(1)}_{base}"
    return f"nivel_{numero.group(1)}"


@verificacao("9.10-composicao", "9.10", "results/circularidade/circularidade.json")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.10"))
    p = f.particao("ref")
    dist = p["distribuicao_gt_cwe_primary"]
    m = re.search(
        r"O CWE-915 \(poluição de protótipo\) é (\d+) dos (\d+) do grupo não herdado e nenhum do herdado;"
        r" o CWE-022 é (\d+) contra (\d+); o CWE-078, (\d+) contra (\d+)",
        texto,
    )
    resultados = [
        par("CWE-915 no não herdado", int(m.group(1)), dist["nao_herdado"].get("CWE-915", 0)),
        par("CWE-915 no herdado", 0, dist["herdado"].get("CWE-915", 0)),
        par("CWE-022 no herdado", int(m.group(3)), dist["herdado"].get("CWE-022", 0)),
        par("CWE-022 no não herdado", int(m.group(4)), dist["nao_herdado"].get("CWE-022", 0)),
        par("CWE-078 no herdado", int(m.group(5)), dist["herdado"].get("CWE-078", 0)),
        par("CWE-078 no não herdado", int(m.group(6)), dist["nao_herdado"].get("CWE-078", 0)),
    ]
    m = re.search(r"no nível 3 — sem herança e sem CWE —, o CodeQL acerta \*\*(\d+) de (\d+)\*\*, o Semgrep \*\*(\d+)\*\* e o Snyk Code \*\*(\d+)\*\*", texto)
    tabela = p["tabela"]
    resultados += [
        par("nível 3, não herdado, CodeQL", int(m.group(1)), tabela["codeql|nivel_3"]["nao_herdado"]["acertos"]),
        par("base do grupo não herdado", int(m.group(2)), tabela["codeql|nivel_3"]["nao_herdado"]["base"]),
        par("nível 3, não herdado, Semgrep", int(m.group(3)), tabela["semgrep|nivel_3"]["nao_herdado"]["acertos"]),
        par("nível 3, não herdado, Snyk Code", int(m.group(4)), tabela["snyk-code|nivel_3"]["nao_herdado"]["acertos"]),
    ]
    m = re.search(r"\*\*seis\*\* CVEs do grupo não herdado carregam conjunto", texto)
    ressalva = p["ressalva_da_particao"]
    if m:
        resultados.append(
            par(
                "CVEs não herdados com conjunto idêntico ao de consulta",
                6,
                len(ressalva.get("nao_herdado_com_conjunto_de_consulta_multiplo", [])),
            )
        )
    m = re.search(
        r"o CodeQL acerta (\d+) no nível 1 e (\d+) no nível 4 estrita; o Semgrep, (\d+) e (\d+); o Snyk Code, (\d+) e (\d+)",
        texto,
    )
    aux = f.circularidade["auxiliar_sem_as_trocas"][0]
    trocas = set(aux["excluidos"])
    resultados.append(par("CVEs de poluição de protótipo", 22, len(trocas)))
    for rotulo, chave, grupo in (
        ("CodeQL nível 1", "codeql|nivel_1", 1),
        ("CodeQL nível 4 estrita", "codeql|nivel_4_estrita", 2),
        ("Semgrep nível 1", "semgrep|nivel_1", 3),
        ("Semgrep nível 4 estrita", "semgrep|nivel_4_estrita", 4),
        ("Snyk nível 1", "snyk-code|nivel_1", 5),
        ("Snyk nível 4 estrita", "snyk-code|nivel_4_estrita", 6),
    ):
        ferramenta, nivel = chave.split("|")
        acertos = sum(
            1
            for linha in f.matriz
            if linha["cve"] in trocas
            and linha["ferramenta"] == ferramenta
            and linha[nivel] == "true"
        )
        resultados.append(par(f"22 de protótipo: {rotulo}", int(m.group(grupo)), acertos))
    m = re.search(r"as partições pelas duas referências coincidem\*\* — (\d+) e (\d+) CVEs", texto)
    resultados += [
        par("herdado sem as trocas", int(m.group(1)), aux["tamanhos"]["herdado"]),
        par("não herdado sem as trocas", int(m.group(2)), aux["tamanhos"]["nao_herdado"]),
    ]
    return resultados


# ---- 4.4 limites, razão entre ambientes e o caso do next.js ---------------
@verificacao("4.4-limites", "4.4", "logs/campanha-2026-09-17/ + logs/ensaio-fumaca-2026-09-16/")
def _(doc, f):
    texto = "\n".join(doc.secao("### 4.4"))
    resultados = []
    m = re.search(r"decidido em setembro de 2026: (\d+) segundos", texto)
    limites = set()
    for ferramenta in FERRAMENTAS:
        for reg in f.logs_campanha(ferramenta).values():
            limites.update(
                int(x)
                for x in re.findall(
                    r"TIMEOUT_(?:ANALYZE|ANALISE|CREATE)=(\d+)", reg["mensagem"]
                )
            )
    resultados.append(par("limite de análise na campanha", {int(m.group(1))}, limites))
    m = re.search(
        r"máximo observado nos (\d+) CVEs foi de (\d+) segundos, no CodeQL", texto
    )
    resultados += [
        par("CVEs no registro", int(m.group(1)), len(f.logs_campanha("codeql"))),
        par("máximo do CodeQL", int(m.group(2)), max(duracoes(f, "codeql"))),
    ]
    m = re.search(
        r"com razões entre (\d+,\d+) e (\d+,\d+) em (\w+) CVEs pareados", texto
    )
    local = f.log_avulso("logs/execution-log-codeql.csv")
    fumaca = f.log_avulso("logs/ensaio-fumaca-2026-09-16/execution-log-codeql.csv")
    razoes = []
    for cve in sorted(set(local) & set(fumaca)):
        a = int(local[cve]["duracao_segundos"])
        b = int(fumaca[cve]["duracao_segundos"])
        if a:
            razoes.append(b / a)
    por_extenso = {"quatro": 4, "cinco": 5, "seis": 6, "sete": 7}
    resultados += [
        par("CVEs pareados", por_extenso[m.group(3)], len(razoes)),
        par("razão mínima", um_numero(m.group(1)), round(min(razoes), 2), 0.005),
        par("razão máxima", um_numero(m.group(2)), round(max(razoes), 2), 0.005),
    ]
    m = re.search(
        r"foi analisado pelo CodeQL em (\d+) segundos na campanha, com (\d+) arquivos extraídos",
        texto,
    )
    logs = f.logs_campanha("codeql")
    inv = f.inventario_codeql
    candidatos = [
        cve
        for cve, reg in logs.items()
        if "next.js" in reg["repo"] and int(reg["duracao_segundos"]) == int(m.group(1))
    ]
    resultados.append(par("CVEs do next.js com essa duração", 1, len(candidatos)))
    if candidatos:
        resultados += [
            par(
                "arquivos extraídos no caso do next.js",
                int(m.group(2)),
                inv[candidatos[0]]["notificacao"],
            ),
            par(
                "fallback no caso do next.js",
                False,
                "fallback" in logs[candidatos[0]]["mensagem"],
            ),
        ]
    return resultados


# ---- 6.1 campanha DAST ----------------------------------------------------
@verificacao("6.1-zap", "6.1", "results/zap/*.json")
def _(doc, f):
    """Contagens do ZAP, com aplicação e modo decididos pelo próprio relatório."""
    tab = doc.tabela("### 6.1", 0)
    medidos = {}
    for caminho in sorted((f.raiz / "results/zap").glob("*.json")):
        d = json.loads(caminho.read_text(encoding="utf-8"))
        site = d["site"][0]
        alertas = site["alerts"]
        # modo por evidência independente da contagem: regra de varredura ativa
        ativa = any(str(a.get("pluginid", "")).startswith("4") and len(str(a["pluginid"])) == 5 for a in alertas)
        aplicacao = "Juice Shop" if ":3000" in site["@name"] else "NodeGoat"
        modo = "Full" if ativa else "Baseline"
        niveis = Counter(a["riskdesc"].split(" ")[0] for a in alertas)
        medidos[(aplicacao, modo)] = (
            niveis.get("High", 0),
            niveis.get("Medium", 0),
            niveis.get("Low", 0),
            niveis.get("Informational", 0),
            len(alertas),
        )
    resultados = [par("relatórios do ZAP", 4, len(medidos))]
    for linha in tab[1:]:
        chave = (linha[0], linha[1])
        if chave not in medidos:
            raise FalhaDeExtracao(f"6.1: {chave} não corresponde a relatório algum")
        for i, rotulo in enumerate(("alto", "médio", "baixo", "informativo", "total")):
            resultados.append(
                par(f"{chave[0]} {chave[1]}: {rotulo}", um_numero(linha[i + 2]), medidos[chave][i])
            )
    return resultados


# ---- 4.4 / 8.8 duração de lote e sobrecarga do laço -----------------------
def duracao_de_lote(f):
    """duracao_segundos de cada (lote, ferramenta), do README do artifact."""
    saida = {}
    base = f.raiz / "logs/campanha-2026-09-17"
    for lote in sorted(base.glob("cves-sast-batch-*")):
        for ferramenta in FERRAMENTAS:
            readme = lote / ferramenta / "README.txt"
            if not readme.is_file():
                continue
            m = re.search(r"^duracao_segundos: (\d+)", readme.read_text(encoding="utf-8"), re.M)
            if m:
                saida[(lote.name, ferramenta)] = int(m.group(1))
    return saida


@verificacao("4.4-lotes", "4.4", "logs/campanha-2026-09-17/<lote>/<ferramenta>/README.txt")
def _(doc, f):
    """Duração de container por lote — a única versionada; job não é."""
    texto = "\n".join(doc.secao("### 4.4"))
    m = re.search(
        r"O lote mais lento é sempre o do (\w+), e consumiu \*\*de (\d+) a (\d+) minutos\*\* "
        r"nos (\w+) lotes de (\d+) CVEs, e (\d+) minutos no lote de (\d+)",
        texto,
    )
    if not m:
        raise FalhaDeExtracao("4.4: frase da duração por lote não casou")
    duracoes_lote = duracao_de_lote(f)
    if not duracoes_lote:
        raise FalhaDeExtracao("4.4: nenhum README de lote encontrado")
    lentos = set()
    for lote in sorted({k[0] for k in duracoes_lote}):
        do_lote = {k[1]: v for k, v in duracoes_lote.items() if k[0] == lote}
        lentos.add(max(do_lote, key=do_lote.get))
    tamanho = {}
    base = f.raiz / "logs/campanha-2026-09-17"
    for lote in sorted(base.glob("cves-sast-batch-*")):
        with open(lote / "execution-log-codeql.csv", encoding="utf-8") as fh:
            tamanho[lote.name] = sum(1 for _ in csv.DictReader(fh))
    grandes = [
        v / 60
        for k, v in duracoes_lote.items()
        if k[1] == "codeql" and tamanho[k[0]] == int(m.group(5))
    ]
    pequenos = [
        v / 60
        for k, v in duracoes_lote.items()
        if k[1] == "codeql" and tamanho[k[0]] == int(m.group(7))
    ]
    por_extenso = {"sete": 7, "seis": 6, "oito": 8}
    return [
        par("ferramenta do lote mais lento", {m.group(1).lower()}, lentos),
        par("lotes grandes", por_extenso[m.group(4)], len(grandes)),
        par("lote grande mais rápido (min)", int(m.group(2)), round(min(grandes))),
        par("lote grande mais lento (min)", int(m.group(3)), round(max(grandes))),
        par("lotes pequenos", 1, len(pequenos)),
        par("duração do lote pequeno (min)", int(m.group(6)), round(pequenos[0])),
    ]


@verificacao("8.8-sobrecarga", "8.8", "logs/campanha-2026-09-17/")
def _(doc, f):
    texto = "\n".join(doc.secao("### 8.8"))
    m = re.search(r"ficou entre (\d+) e (\d+) segundos por lote", texto)
    duracoes_lote = duracao_de_lote(f)
    sobrecargas = []
    base = f.raiz / "logs/campanha-2026-09-17"
    for (lote, ferramenta), total in duracoes_lote.items():
        with open(base / lote / f"execution-log-{ferramenta}.csv", encoding="utf-8") as fh:
            soma = sum(int(r["duracao_segundos"]) for r in csv.DictReader(fh))
        sobrecargas.append(total - soma)
    return [
        par("sobrecarga mínima do laço", int(m.group(1)), min(sobrecargas)),
        par("sobrecarga máxima do laço", int(m.group(2)), max(sobrecargas)),
    ]


# ---- 8.8 recusa de acesso do Snyk Code (403) ------------------------------
INVESTIGACAO_403 = "logs/investigacao-snyk-403-2026-09-26"


def lote_txt_403(f):
    """{cve: {"403": n, "antes_do_resumo": n}} nos container/lote.txt da campanha.

    Um bloco se abre em 'Testing /tmp/src-<CVE> ...' e se fecha em qualquer
    linha que cite OUTRO /tmp/src-<CVE>, ou comece por [<CVE>] (a forma dos
    avisos do script) — os SEM_ARQUIVO_ANALISAVEL e os ERRO_*
    não imprimem 'Testing', e a saída deles caía no bloco anterior (revisão,
    risco 1). Um 403 é atribuído ao bloco em que está; bloco aberto por outro
    caminho entra no dicionário com "testado": False. 403 antes do primeiro
    bloco é falha, nunca descartado."""
    saida = {}
    for lote in sorted((f.raiz / "logs/campanha-2026-09-17").glob("cves-sast-batch-*")):
        atual = None
        with open(lote / "snyk-code/container/lote.txt", encoding="utf-8", errors="replace") as fh:
            for linha in fh:
                m = re.search(r"Testing /tmp/src-(CVE-\d+-\d+) \.\.\.", linha)
                if m:
                    if saida.get(m.group(1), {}).get("testado"):
                        raise FalhaDeExtracao(f"lote.txt: {m.group(1)} testado mais de uma vez")
                    atual = m.group(1)
                    saida[atual] = {"testado": True, "403": 0, "antes_do_resumo": 0, "resumo": False}
                    continue
                outro = re.search(r"/tmp/src-(CVE-\d+-\d+)|^\[(CVE-\d+-\d+)\]", linha)
                citado = outro and (outro.group(1) or outro.group(2))
                if citado and citado != atual:
                    atual = citado
                    saida.setdefault(atual, {"testado": False, "403": 0, "antes_do_resumo": 0, "resumo": False})
                if atual and "Test Summary" in linha:
                    saida[atual]["resumo"] = True
                if "Status:  403" in linha:
                    if atual is None:
                        raise FalhaDeExtracao(f"lote.txt de {lote.name}: 403 antes de qualquer CVE")
                    saida[atual]["403"] += 1
                    if not saida[atual]["resumo"]:
                        saida[atual]["antes_do_resumo"] += 1
    return saida


def _investigacao(f):
    inv = f.csv(f"{INVESTIGACAO_403}/invocacoes.csv")
    comp = f.csv(f"{INVESTIGACAO_403}/comparacao.csv")
    reqs = [l.split(" ") for l in (f.raiz / INVESTIGACAO_403 / "requisicoes-T1.txt").read_text(encoding="utf-8").splitlines()]
    if any(len(q) != 4 for q in reqs):
        raise FalhaDeExtracao("requisicoes-T1.txt: linha sem os quatro campos método, host, caminho, status")
    return inv, comp, reqs


EXTENSO = {"duas": 2, "dois": 2, "três": 3, "quatro": 4, "cinco": 5, "seis": 6, "sete": 7, "oito": 8}


@verificacao("8.8-snyk-403", "8.8, 12.1",
             f"{INVESTIGACAO_403}/ + logs/campanha-2026-09-17/ (logs e container/lote.txt) + tratados do Snyk Code")
def _(doc, f):
    """Afirmações do TEXTO, cada uma lida dele e comparada com fonte."""
    texto = "\n".join(doc.secao("### 8.8"))
    texto_12_1 = "\n".join(doc.secao("### 12.1"))
    inv, comp, reqs = _investigacao(f)
    r = []

    # 133 e 83 contra a SAÍDA do lote, cruzada por CVE com o status do log
    g = busca_unica(texto, r"impressa depois do resumo: (\d+) de (\d+) testes com achados, e nenhum dos (\d+) sem achados", "8.8")
    logs = f.logs_campanha("snyk-code")
    blocos = lote_txt_403(f)
    ok = [c for c, reg in logs.items() if reg["status"] == "OK"]
    sem = [c for c, reg in logs.items() if reg["status"] == "SEM_ACHADOS"]
    testados = sorted(c for c, b in blocos.items() if b["testado"])
    r += [par("campanha: testes com achados com exatamente um 403", int(g[0]),
              sum(1 for c in ok if blocos.get(c, {}).get("403") == 1)),
          par("campanha: testes com achados", int(g[1]), len(ok)),
          par("campanha: testes sem achados", int(g[2]), len(sem)),
          par("campanha: testes sem achados com 403", 0, sum(1 for c in sem if blocos.get(c, {}).get("403", 0))),
          par("campanha: 403 em bloco de CVE não testado", 0,
              sum(b["403"] for b in blocos.values() if not b["testado"])),
          par("campanha: 403 impresso antes do resumo", 0, sum(b["antes_do_resumo"] for b in blocos.values())),
          par("campanha: CVEs testados = OK + SEM_ACHADOS", sorted(ok + sem), testados)]

    g = busca_unica(texto, r"A investigação, com (\w+) invocações sobre a imagem da campanha", "8.8")
    r.append(par("invocações", EXTENSO.get(g, g), len(inv)))

    # uma única requisição recusada: a leitura da organização, antes do envio
    busca_unica(texto, r"a recusa incide sobre uma única requisição — a leitura do nome curto da organização, feita antes da análise", "8.8")
    recusadas = [i for i, q in enumerate(reqs) if q[3] == "403"]
    envio = [i for i, q in enumerate(reqs) if q[0] == "POST" and q[2] == "/bundle"]
    r += [par("T1: respostas 403", 1, len(recusadas)),
          par("T1: a recusada é a leitura da organização", True,
              len(recusadas) == 1 and reqs[recusadas[0]][0] == "GET"
              and re.fullmatch(r"/rest/orgs/<org>(\?.*)?", reqs[recusadas[0]][2]) is not None),
          par("T1: a recusa vem antes do envio do código", True,
              len(recusadas) == 1 and len(envio) == 1 and recusadas[0] < envio[0])]
    busca_unica(texto, r"o envio do código, a análise e a obtenção dos resultados respondem normalmente", "8.8")
    r.append(par("T1: as demais respostas são 2xx", True,
                 all(q[3].startswith("2") for i, q in enumerate(reqs) if i not in recusadas)))

    # código de saída: sem o 403 virar erro (2) — 1 com achados, 0 sem, como
    # a semântica do Snyk que o run_snyk-code.sh documenta (revisão, risco 3)
    busca_unica(texto, r"O código de saída não muda: a mensagem só é anexada ao fim", "8.8")
    for x in inv:
        esperado = 1 if int(x["achados"]) > 0 else 0
        r.append(par(f"{x['invocacao']}: código da CLI = semântica sem erro", esperado, int(x["codigo_cli"])))
        m = re.search(r"snyk exit (\d+)", logs[x["cve"]]["mensagem"])
        r.append(par(f"{x['invocacao']}: código da CLI = o da campanha", int(m.group(1)) if m else None,
                     int(x["codigo_cli"])))

    # dois CVEs com achados, três execuções; achados contra o tratado versionado
    g = busca_unica(texto, r"Nos (\w+) CVEs com achados, em (\w+) execuções, o resultado é idêntico, campo a campo, ao da campanha, mais de uma semana depois", "8.8")
    r += [par("CVEs com achados comparados", EXTENSO.get(g[0], g[0]), len({x["cve"] for x in comp})),
          par("execuções comparadas", EXTENSO.get(g[1], g[1]), len(comp))]
    tratados = {t["metadata"]["cve_id"]: t for t in f.tratados("snyk-code")}
    for x in comp:
        t = tratados.get(x["cve"])
        r.append(par(f"{x['invocacao']} {x['cve']}: achados da campanha = tratado versionado",
                     len(t["findings"]) if t else None, int(x["achados_campanha"])))
        # "mais de uma semana depois": data da análise da campanha contra a da investigação
        dias = (datetime.date(2026, 9, 26) - datetime.date.fromisoformat(t["metadata"]["analysis_date"][:10])).days if t else None
        r.append(par(f"{x['cve']}: mais de uma semana entre a campanha e a investigação", True, dias is not None and dias > 7))
    g = busca_unica(texto, r"mas a amostra é de (\w+)\.", "8.8")
    r.append(par("amostra (CVEs)", EXTENSO.get(g, g), len({x["cve"] for x in comp})))
    g = busca_unica(texto_12_1, r"reproduziu, campo a campo, o resultado de (\w+) CVEs", "12.1")
    r.append(par("12.1: CVEs reproduzidos", EXTENSO.get(g, g), len({x["cve"] for x in comp})))
    return r


@verificacao("8.8-snyk-403-arquivos", "—", f"{INVESTIGACAO_403}/ (consistência interna, não afirmação do texto)")
def _(doc, f):
    """Consistência entre os arquivos da investigação. NÃO confere o texto —
    separada da família do texto para não inflar as afirmações conferidas
    (revisão, risco 2). O "idêntico, campo a campo" em si não é reconferível
    do repositório: está em NAO_CONFERIVEIS."""
    inv, comp, reqs = _investigacao(f)
    por_inv = {x["invocacao"]: x for x in inv}
    r = [par("invocações nomeadas T1 a T4", ["T1", "T2", "T3", "T4"], [x["invocacao"] for x in inv]),
         par("403 presente sse há achados", True,
             all((x["403_presente"] == "sim") == (int(x["achados"]) > 0) for x in inv)),
         par("comparadas = as invocações com achados", sorted(x["invocacao"] for x in inv if int(x["achados"]) > 0),
             sorted(x["invocacao"] for x in comp))]
    for x in comp:
        onde = f"{x['invocacao']} {x['cve']}"
        r += [par(f"{onde}: arquivo declara lista idêntica", "sim", x["lista_identica"]),
              par(f"{onde}: arquivo declara 0 só no novo e 0 só na campanha", (0, 0),
                  (int(x["so_no_novo"]), int(x["so_na_campanha"]))),
              par(f"{onde}: arquivo declara divergência só na data", "analysis_date", x["metadata_divergente"]),
              par(f"{onde}: achados novos = invocação", int(por_inv[x["invocacao"]]["achados"]), int(x["achados_novo"]))]
    # identificador da organização mascarado em toda forma de caminho (risco 4)
    r.append(par("organização mascarada em /orgs/ e em org=", [],
                 [q[2] for q in reqs if re.search(r"(/orgs/|[?&]org=)(?!<org>)", q[2])]))
    return r


# ---- 9.9 detecção por categoria de CWE ------------------------------------
# Fonte: results/por-cwe/deteccao-por-categoria.csv. Taxa e limites do
# intervalo são arredondados a UMA casa a partir do VALOR EXATO — a taxa como
# acertos/base, em aritmética racional; os limites pela wilson() importada do
# tools/deteccao-por-cwe.py, nunca reimplementada —, e nunca do valor do CSV,
# que já vem arredondado a quatro casas: arredondar duas vezes muda a última
# casa (0,5465 → 54,7, quando o exato é 54,6495 → 54,6).
NIVEIS_9_9 = {"Nível 1": "1", "Nível 2 estrita": "2e", "Nível 3": "3", "Nível 4 estrita": "4e"}
FERRAMENTA_DO_ROTULO = {"CodeQL": "codeql", "Semgrep": "semgrep", "Snyk Code": "snyk-code"}
_CELULA_9_9 = re.compile(r"(\d+) · (\d+,\d)% \[(\d+,\d); (\d+,\d)\]")


def arredonda(valor, casas):
    """Meio para cima, sobre a expansão decimal exata do valor.

    Valor a menos de 1e-9 unidades da última casa de um empate é recusado:
    ali a representação em ponto flutuante decide o resultado, e a
    conferência não pode afirmá-lo.
    """
    exato = valor if isinstance(valor, Decimal) else Decimal(valor)
    escala = Decimal(1).scaleb(-casas)
    resto = (exato / escala) % 1
    if not isinstance(valor, Decimal) and abs(resto - Decimal("0.5")) < Decimal("1e-9"):
        raise ValueError(f"valor {valor!r} em empate de arredondamento a {casas} casa(s)")
    return float(exato.quantize(escala, rounding=ROUND_HALF_UP))


def taxa_exata(acertos, base, casas=1):
    return arredonda(Decimal(100 * acertos) / Decimal(base), casas)


def deteccao_por_categoria(f):
    return {(r["categoria"], r["ferramenta"], r["nivel"]): r for r in f.csv("results/por-cwe/deteccao-por-categoria.csv")}


def tabelas_rotuladas(bloco):
    """[(rótulo em negrito que precede a tabela, tabela)]."""
    saida, rotulo, corrente = [], None, []
    for linha in bloco + [""]:
        if linha.strip().startswith("|"):
            celulas = [c.strip() for c in linha.strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-{2,}:?", c) for c in celulas):
                corrente.append(celulas)
            continue
        if corrente:
            saida.append((rotulo, corrente))
            corrente = []
        # rótulo = negrito no início do parágrafo; outro texto o anula, para
        # que tabela sem rótulo próprio não herde o da anterior
        m = re.match(r"\*\*([^*]+)\*\*", linha.strip())
        if m:
            rotulo = m.group(1)
        elif linha.strip():
            rotulo = None
    return saida


def busca_unica(texto, padrao, onde):
    achados = re.findall(padrao, texto)
    if len(achados) != 1:
        raise FalhaDeExtracao(f"{onde}: padrão {padrao!r} casou {len(achados)} vezes")
    return achados[0]


def tabela_rotulada(bloco, prefixo_rotulo, onde):
    """A única tabela cujo rótulo começa por `prefixo_rotulo` (revisão, risco 6)."""
    achadas = [t for r, t in tabelas_rotuladas(bloco) if r and r.startswith(prefixo_rotulo)]
    if len(achadas) != 1:
        raise FalhaDeExtracao(f"{onde}: {len(achadas)} tabelas com rótulo {prefixo_rotulo!r}")
    return achadas[0]


@verificacao("9.9-acima", "9.9", "results/por-cwe/deteccao-por-categoria.csv + wilson() do deteccao-por-cwe.py")
def _(doc, f):
    det = deteccao_por_categoria(f)
    wilson = f.wilson
    rotuladas = [(r, t) for r, t in tabelas_rotuladas(doc.secao("### 9.9")) if r in FERRAMENTA_DO_ROTULO]
    tabelas = dict(rotuladas)
    if len(tabelas) != 3 or len(rotuladas) != 3:
        raise FalhaDeExtracao(f"9.9: tabelas por ferramenta encontradas: {sorted(tabelas)}")
    acima = sorted({c for (c, _, _), r in det.items() if r["acima_do_limiar"] == "sim"})
    resultados = []
    for rotulo, tab in tabelas.items():
        ferramenta = FERRAMENTA_DO_ROTULO[rotulo]
        cabecalho = tab[0]
        colunas = {i: NIVEIS_9_9[c] for i, c in enumerate(cabecalho) if c in NIVEIS_9_9}
        if sorted(colunas.values()) != sorted(NIVEIS_9_9.values()):
            raise FalhaDeExtracao(f"9.9 {rotulo}: cabeçalho {cabecalho}")
        vistas = []
        for linha in tab[1:]:
            categoria = re.match(r"CWE-\d+", linha[0])
            if not categoria:
                raise FalhaDeExtracao(f"9.9 {rotulo}: categoria {linha[0]!r}")
            categoria = categoria.group(0)
            vistas.append(categoria)
            n = int(um_numero(linha[1]))
            for i, nivel in colunas.items():
                m = _CELULA_9_9.fullmatch(linha[i])
                if not m:
                    raise FalhaDeExtracao(f"9.9 {rotulo} {categoria}: célula {linha[i]!r}")
                r = det[(categoria, ferramenta, nivel)]
                a, b = int(r["acertos"]), int(r["base"])
                inf, sup = wilson(a, b)
                onde = f"{ferramenta} {categoria} nível {nivel}"
                # o CSV, a quatro casas, tem de ser o recálculo arredondado:
                # CSV defasado não passa em silêncio (revisão, observação)
                resultados += [
                    par(f"{onde}: CSV wilson_inf = recálculo", float(r["wilson_inf"]), arredonda(inf, 4)),
                    par(f"{onde}: CSV wilson_sup = recálculo", float(r["wilson_sup"]), arredonda(sup, 4)),
                ]
                resultados += [
                    par(f"{onde}: acertos", int(m.group(1)), a),
                    par(f"{onde}: n", n, b),
                    par(f"{onde}: taxa", float(m.group(2).replace(",", ".")), taxa_exata(a, b)),
                    par(f"{onde}: Wilson inferior", float(m.group(3).replace(",", ".")), arredonda(100 * inf, 1)),
                    par(f"{onde}: Wilson superior", float(m.group(4).replace(",", ".")), arredonda(100 * sup, 1)),
                ]
        resultados.append(par(f"{rotulo}: categorias acima do limiar", acima, sorted(vistas)))
    return resultados


@verificacao("9.9-abaixo", "9.9", "results/por-cwe/deteccao-por-categoria.csv")
def _(doc, f):
    det = deteccao_por_categoria(f)
    tab = tabela_rotulada(doc.secao("### 9.9"), "Categorias abaixo do limiar", "9.9")
    n_de = {c: int(r["n"]) for (c, _, _), r in det.items()}
    abaixo = {c for (c, _, _), r in det.items() if r["acima_do_limiar"] == "nao"}
    unitarias = sorted(c for c in abaixo if n_de[c] == 1 and c != "SEM_PRIMARIO")
    ferramentas = [FERRAMENTA_DO_ROTULO[c.rsplit(" 1 / 4e", 1)[0]] for c in tab[0][2:]]
    resultados, vistas = [], []
    for linha in tab[1:]:
        rotulo = linha[0].strip("`")
        if rotulo.startswith("dez categorias"):
            grupo = unitarias
        else:
            grupo = [rotulo]
            vistas.append(rotulo)
        resultados.append(par(f"{rotulo}: n", int(um_numero(linha[1])), sum(n_de[c] for c in grupo)))
        if len(linha[2:]) != len(ferramentas) or len(ferramentas) != 3:
            raise FalhaDeExtracao(f"9.9 abaixo: linha {rotulo!r} com {len(linha[2:])} células de ferramenta")
        for ferramenta, celula in zip(ferramentas, linha[2:]):
            partes = [p.strip() for p in celula.split("/")]
            if len(partes) != 2:
                raise FalhaDeExtracao(f"9.9 abaixo: {rotulo} {ferramenta}: célula {celula!r} sem 'nível 1 / 4e'")
            for nivel, texto in zip(("1", "4e"), partes):
                linhas_csv = [det[(c, ferramenta, nivel)] for c in grupo]
                onde = f"{rotulo} {ferramenta} nível {nivel}"
                if texto == "n.s.a.":
                    resultados.append(par(f"{onde}: não se aplica", True,
                                          all(r["base"] == "0" and r["nao_se_aplica"] == "1" for r in linhas_csv)))
                else:
                    resultados.append(par(onde, int(texto), sum(int(r["acertos"]) for r in linhas_csv)))
                    # número onde o CSV diz não se aplica não passa por ser 0
                    # (revisão, risco 2)
                    resultados.append(par(f"{onde}: aplica-se", True,
                                          all(r["nao_se_aplica"] == "0" for r in linhas_csv)))
    texto = "\n".join(doc.secao("### 9.9"))
    g = busca_unica(texto, r"dez categorias de 1 CVE são CWE-(\d+), ([\d, ]+) e (\d+), discriminadas", "9.9")
    listadas = sorted(f"CWE-{int(x):03d}" for x in [g[0]] + re.findall(r"\d+", g[1]) + [g[2]])
    resultados += [
        par("rótulo 'dez categorias de 1 CVE'", 10, len(unitarias)),
        par("as dez categorias de 1 CVE nomeadas", unitarias, listadas),
        par("categorias abaixo do limiar com n > 1 na tabela",
            sorted(c for c in abaixo if n_de[c] > 1 or c == "SEM_PRIMARIO"), sorted(vistas)),
    ]
    return resultados


@verificacao("9.9-leitura", "9.9", "deteccao-por-categoria.csv, capacidade-por-cwe.csv, circularidade.json, distribuicao-primario.csv, logs")
def _(doc, f):
    det = deteccao_por_categoria(f)
    texto = "\n".join(doc.secao("### 9.9"))
    seis = sorted({c for (c, _, _), r in det.items() if r["acima_do_limiar"] == "sim"})

    def a(c, ferr, nivel):
        return int(det[(c, ferr, nivel)]["acertos"])

    def busca(padrao):
        achados = re.findall(padrao, texto)
        if len(achados) != 1:
            raise FalhaDeExtracao(f"9.9: padrão {padrao!r} casou {len(achados)} vezes")
        return achados[0]

    r = []
    # critério
    categorias = {c for (c, _, _) in det}
    n_de = {c: int(det[(c, "codeql", "1")]["n"]) for c in categorias}
    g = busca(r"As (\d+) categorias, (\d+) com primário e a categoria `SEM_PRIMARIO`, formam uma partição do denominador de (\d+)")
    r += [par("categorias", int(g[0]), len(categorias)),
          par("categorias com primário", int(g[1]), len(categorias - {"SEM_PRIMARIO"})),
          par("denominador", int(g[2]), sum(n_de.values()))]
    extenso = {"cinco": 5, "seis": 6, "sete": 7, "oito": 8}
    g = busca(r"As (\w+) categorias com (\d+) CVEs ou mais recebem taxa")
    k = int(g[1])
    r += [par("categorias acima do limiar", extenso.get(g[0], g[0]), len(seis)),
          # o limiar do texto é o que o CSV aplicou (revisão, observação)
          par(f"acima_do_limiar == (n >= {k})", True,
              all((det[(c, "codeql", "1")]["acima_do_limiar"] == "sim") == (n_de[c] >= k) for c in categorias))]
    g = busca(r"Nenhuma categoria tem entre (\d+) e (\d+) CVEs")
    r.append(par(f"categorias com n entre {g[0]} e {g[1]}", 0,
                 sum(1 for n in n_de.values() if int(g[0]) <= n <= int(g[1]))))
    g = busca(r"qualquer limiar de (\d+) a (\d+) produziria o mesmo corte")
    cortes = {frozenset(c for c in categorias if n_de[c] >= limiar) for limiar in range(int(g[0]), int(g[1]) + 1)}
    r.append(par(f"limiares de {g[0]} a {g[1]} dão o mesmo corte", 1, len(cortes)))
    # ordem no nível 4 estrito
    busca(r"No nível 4 estrito, o CodeQL lidera nas seis categorias")
    r.append(par("CodeQL > as outras duas no 4e, nas seis", True,
                 all(a(c, "codeql", "4e") > max(a(c, "semgrep", "4e"), a(c, "snyk-code", "4e")) for c in seis)))
    r.append(par("Semgrep >= Snyk Code no 4e, nas seis", True,
                 all(a(c, "semgrep", "4e") >= a(c, "snyk-code", "4e") for c in seis)))
    busca(r"os empates são em CWE-400 e CWE-094, com zero nas duas")
    r.append(par("empates Semgrep = Snyk no 4e", ["CWE-094", "CWE-400"],
                 sorted(c for c in seis if a(c, "semgrep", "4e") == a(c, "snyk-code", "4e"))))
    r.append(par("empates com zero", True, all(a(c, "semgrep", "4e") == 0 for c in ("CWE-094", "CWE-400"))))
    g = busca(r"o Semgrep chega ao arquivo em (\d+) de (\d+) CVEs, contra (\d+) do CodeQL")
    r += [par("Semgrep CWE-022 nível 1", int(g[0]), a("CWE-022", "semgrep", "1")),
          par("n de CWE-022", int(g[1]), n_de["CWE-022"]),
          par("CodeQL CWE-022 nível 1", int(g[2]), a("CWE-022", "codeql", "1"))]
    g = busca(r"passa de (\d+) CVEs no nível 1 para (\d+) no nível 3; em poluição de protótipo, de (\d+) para (\d+)")
    r += [par("Semgrep CWE-022 nível 1", int(g[0]), a("CWE-022", "semgrep", "1")),
          par("Semgrep CWE-022 nível 3", int(g[1]), a("CWE-022", "semgrep", "3")),
          par("Semgrep CWE-915 nível 1", int(g[2]), a("CWE-915", "semgrep", "1")),
          par("Semgrep CWE-915 nível 3", int(g[3]), a("CWE-915", "semgrep", "3"))]
    # ReDoS
    g = busca(r"não produz alerta no arquivo do ground truth em nenhum dos (\d+) CVEs")
    r += [par("n de CWE-400", int(g), n_de["CWE-400"]),
          par("Snyk CWE-400 nível 1", 0, a("CWE-400", "snyk-code", "1"))]
    g = busca(r"O Semgrep chega ao arquivo em (\d+), e à natureza certa em nenhum")
    r += [par("Semgrep CWE-400 nível 1", int(g), a("CWE-400", "semgrep", "1")),
          par("Semgrep CWE-400 nível 2 estrita", 0, a("CWE-400", "semgrep", "2e"))]
    g = busca(r"O CodeQL chega ao arquivo e à natureza em (\d+), mas à linha em (\d+)")
    r += [par("CodeQL CWE-400 nível 2 estrita", int(g[0]), a("CWE-400", "codeql", "2e")),
          par("CodeQL CWE-400 nível 3", int(g[1]), a("CWE-400", "codeql", "3"))]
    busca(r"é a categoria em que ele mais perde do nível 2 para o 3")
    perdas = {c: a(c, "codeql", "2e") - a(c, "codeql", "3") for c in seis}
    maior = max(perdas.values())
    r.append(par("categoria de maior perda 2e → 3 do CodeQL", ["CWE-400"],
                 sorted(c for c, p in perdas.items() if p == maior)))
    # generosa x estrita
    g = busca(r"(\d+) contra (\d+) no nível 2, e (\d+) contra (\d+) no nível 4")
    r += [par("Snyk CWE-022 2 generosa", int(g[0]), a("CWE-022", "snyk-code", "2g")),
          par("Snyk CWE-022 2 estrita", int(g[1]), a("CWE-022", "snyk-code", "2e")),
          par("Snyk CWE-022 4 generosa", int(g[2]), a("CWE-022", "snyk-code", "4g")),
          par("Snyk CWE-022 4 estrita", int(g[3]), a("CWE-022", "snyk-code", "4e"))]
    busca(r"Nas demais células a diferença é de 0 ou 1")
    excecoes = sorted(
        f"{c} {ferr} {n}" for (c, ferr, niv) in det if niv in ("2g", "4g")
        for n in [niv[0]]
        if a(c, ferr, niv) - a(c, ferr, n + "e") > 1
    )
    r.append(par("células com generosa − estrita > 1", ["CWE-022 snyk-code 2", "CWE-022 snyk-code 4"], excecoes))
    g = busca(r"mostra o CWE-023 em alertas do Snyk Code em (\d+) CVEs")
    cap = {(x["ferramenta"], x["versao"], x["categoria"]): x for x in f.csv("results/capacidade/capacidade-por-cwe.csv")}
    r.append(par("Snyk CWE-023, CVEs com alerta (versão principal)", int(g),
                 int(cap[("snyk-code", "js_ts_extensao", "CWE-023")]["cves_com_achado"])))
    g = busca(r"Em injeção de código, com (\d+) CVEs, o intervalo do CodeQL no nível 4 estrito vai de (\d+,\d)% a (\d+,\d)%")
    inf, sup = f.wilson(a("CWE-094", "codeql", "4e"), n_de["CWE-094"])
    r += [par("n de CWE-094", int(g[0]), n_de["CWE-094"]),
          par("CodeQL CWE-094 4e, Wilson inferior", float(g[1].replace(",", ".")), arredonda(100 * inf, 1)),
          par("CodeQL CWE-094 4e, Wilson superior", float(g[2].replace(",", ".")), arredonda(100 * sup, 1))]
    # circularidade
    herdados = set(f.particao("ref")["grupos"]["herdado"])
    dist = {x["gt_cwe_primary"]: x["cves"].split("|") for x in f.csv("results/por-cwe/distribuicao-primario.csv")}
    busca(r"Em cinco das seis categorias a maior parte dos CVEs tem etiqueta herdada")
    r.append(par("categorias, das seis, com maioria herdada", 5,
                 sum(1 for c in seis if 2 * len(set(dist[c]) & herdados) > len(dist[c]))))
    g = busca(r"nenhum dos (\d+) é herdado sob a âncora")
    r += [par("n de CWE-915", int(g), len(dist["CWE-915"])),
          par("CWE-915 herdados", 0, len(set(dist["CWE-915"]) & herdados))]
    g = busca(r"Nele o CodeQL acerta (\d+) no nível 4 estrito, contra (\d+) do Semgrep e (\d+) do Snyk Code")
    r += [par("CWE-915 4e CodeQL", int(g[0]), a("CWE-915", "codeql", "4e")),
          par("CWE-915 4e Semgrep", int(g[1]), a("CWE-915", "semgrep", "4e")),
          par("CWE-915 4e Snyk Code", int(g[2]), a("CWE-915", "snyk-code", "4e"))]
    # os cinco SEM_ARQUIVO_ANALISAVEL
    g = busca(r"\*\*Os (\w+) CVEs sem material analisável do Snyk Code\*\*")
    lido = extenso.get(g, g)
    g = busca(r"caem em CWE-022 \((\d+)\), CWE-079 \((\d+)\) e CWE-116 \((\d+)\)")
    sem_arquivo = {c for c, reg in f.logs_campanha("snyk-code").items() if reg["status"] == "SEM_ARQUIVO_ANALISAVEL"}
    primario = {cve: c for c, cves in dist.items() for cve in cves}
    contagem = Counter(primario[c] for c in sem_arquivo)
    r += [par("SEM_ARQUIVO_ANALISAVEL no Snyk Code", lido, len(sem_arquivo)),
          par("distribuição dos cinco por primário",
              {"CWE-022": int(g[0]), "CWE-079": int(g[1]), "CWE-116": int(g[2])}, dict(contagem))]
    return r


# ---- 9.11 capacidade empírica e delimitação por linguagem -----------------
def capacidade_txt_secao(f, numero):
    """Linhas da seção `numero` do capacidade.txt (cabeçalho 'N. TITULO')."""
    linhas = f.capacidade_txt.splitlines()
    inicio = [i for i, l in enumerate(linhas) if re.match(rf"{numero}\. [A-Z]", l)]
    if len(inicio) != 1:
        raise FalhaDeExtracao(f"capacidade.txt: seção {numero} casou {len(inicio)} vezes")
    fim = next((j for j in range(inicio[0] + 1, len(linhas)) if re.match(r"\d+\. [A-Z]", linhas[j])), len(linhas))
    return linhas[inicio[0]:fim]


def extensoes_fora(f):
    """{ferramenta: {extensão: (achados, cves)}} e {ferramenta: total}, do capacidade.txt."""
    saida, totais, corrente = {}, {}, None
    for linha in capacidade_txt_secao(f, 5):
        m = re.fullmatch(r"  (codeql|semgrep|snyk-code) — (\d+) achados fora de JS/TS", linha)
        if m:
            corrente = m.group(1)
            totais[corrente] = int(m.group(2))
            saida[corrente] = {}
            continue
        m = re.fullmatch(r"  (\.\S+|\(sem extensao\))\s+(\d+)\s+(\d+)", linha)
        if m and corrente:
            saida[corrente][m.group(1)] = (int(m.group(2)), int(m.group(3)))
    return saida, totais


def delimitacao(f):
    return {(x["ferramenta"], x["criterio"], x["celula"]): x for x in f.csv("results/capacidade/delimitacao-linguagem.csv")}


@verificacao("9.11-delimitacao", "9.11", "results/capacidade/delimitacao-linguagem.csv + relatórios de normalização")
def _(doc, f):
    d = delimitacao(f)
    texto = "\n".join(doc.secao("### 9.11"))
    bloco = doc.secao("### 9.11")
    r = []
    total = {ferr: int(d[(ferr, "extensao", "js_ts")]["achados"]) + int(d[(ferr, "extensao", "fora")]["achados"])
             for ferr in FERRAMENTAS}
    m = re.findall(r"Os totais conferem com os relatórios de normalização: ([\d.]+), ([\d.]+) e ([\d.]+) alertas", texto)
    if len(m) != 1:
        raise FalhaDeExtracao(f"9.11: totais casaram {len(m)} vezes")
    for ferr, bruto in zip(FERRAMENTAS, m[0]):
        relatorios = sum(x["achados"]["total"] for x in f.relatorios_normalizacao(ferr))
        r += [par(f"{ferr}: total, delimitação", um_numero(bruto), total[ferr]),
              par(f"{ferr}: total, relatórios de normalização", um_numero(bruto), relatorios)]
    g = busca_unica(texto, r"O universo são todos os CVEs com resultado normalizado: (\d+) no CodeQL e no Semgrep, (\d+) no Snyk Code", "9.11")
    cap = f.csv("results/capacidade/capacidade-por-cwe.csv")
    universo = {x["ferramenta"]: int(x["universo_cves"]) for x in cap}
    r += [par("universo CodeQL", int(g[0]), universo["codeql"]),
          par("universo Semgrep", int(g[0]), universo["semgrep"]),
          par("universo Snyk Code", int(g[1]), universo["snyk-code"])]
    tab = tabela_rotulada(bloco, "Delimitação por linguagem", "9.11")
    for rotulo, ferr in FERRAMENTA_DO_ROTULO.items():
        linha = doc.linha_da_tabela(tab, rotulo)
        js, pjs = numeros(linha[1])
        fo, pfo = numeros(linha[2])
        cjs = d[(ferr, "extensao", "js_ts")]
        cfo = d[(ferr, "extensao", "fora")]
        r += [par(f"{ferr}: alertas em JS/TS", js, int(cjs["achados"])),
              par(f"{ferr}: % em JS/TS", pjs, taxa_exata(int(cjs["achados"]), total[ferr])),
              par(f"{ferr}: alertas fora", fo, int(cfo["achados"])),
              par(f"{ferr}: % fora", pfo, taxa_exata(int(cfo["achados"]), total[ferr])),
              par(f"{ferr}: CVEs com alerta fora", um_numero(linha[3]), int(cfo["cves_com_achado"]))]
    tab = tabela_rotulada(bloco, "No Semgrep, os dois critérios cruzados", "9.11")
    celulas = {("regra de JS/TS", 1): "regra_js_ts|arquivo_js_ts", ("regra de JS/TS", 2): "regra_js_ts|arquivo_fora",
               ("regra de outra linguagem", 1): "regra_fora|arquivo_js_ts",
               ("regra de outra linguagem", 2): "regra_fora|arquivo_fora"}
    for (rotulo, col), celula in celulas.items():
        linha = doc.linha_da_tabela(tab, rotulo)
        r.append(par(f"2x2 {celula}", um_numero(linha[col]),
                     int(d[("semgrep", "regra_x_extensao", celula)]["achados"])))
    m = re.findall(r"Os dois critérios concordam em (\d+,\d+)% dos alertas", texto)
    if len(m) != 1:
        raise FalhaDeExtracao(f"9.11: concordância casou {len(m)} vezes")
    concordam = sum(int(d[("semgrep", "regra_x_extensao", c)]["achados"])
                    for c in ("regra_js_ts|arquivo_js_ts", "regra_fora|arquivo_fora"))
    r.append(par("concordância dos dois critérios (%)", um_numero(m[0]),
                 taxa_exata(concordam, total["semgrep"], casas=2)))
    return r


@verificacao("9.11-extensoes", "9.11", "results/capacidade/capacidade.txt + delimitacao-linguagem.csv")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.11"))
    ext, totais = extensoes_fora(f)
    d = delimitacao(f)
    r = []

    def busca(padrao):
        achados = re.findall(padrao, texto)
        if len(achados) != 1:
            raise FalhaDeExtracao(f"9.11: padrão {padrao!r} casou {len(achados)} vezes")
        return achados[0]

    for ferr in FERRAMENTAS:
        r.append(par(f"{ferr}: fora de JS/TS, capacidade.txt = CSV", totais[ferr],
                     int(d[(ferr, "extensao", "fora")]["achados"])))
    g = busca(r"No CodeQL, ([\d.]+) dos ([\d.]+) em `\.html`")
    r += [par("CodeQL .html", um_numero(g[0]), ext["codeql"][".html"][0]),
          par("CodeQL fora", um_numero(g[1]), totais["codeql"])]
    # cada reaparição do número, lida no seu contexto (revisão, defeito 1);
    # e nenhuma outra: o número não pode aparecer fora dos contextos lidos
    for padrao in (r"e seus ([\d.]+) alertas ali", r"pelas regras dos ([\d.]+) alertas"):
        r.append(par(f"CodeQL .html em {padrao!r}", um_numero(busca(padrao)), ext["codeql"][".html"][0]))
    r.append(par("ocorrências de '600' na 9.11", 3, len(re.findall(r"(?<![\d.,])600(?![\d,])", texto))))
    g = busca(r"No Semgrep, ([\d.]+) dos ([\d.]+) em `\.html`")
    r += [par("Semgrep .html", um_numero(g[0]), ext["semgrep"][".html"][0]),
          par("Semgrep fora", um_numero(g[1]), totais["semgrep"])]
    g = busca(r"`\.java` \((\d+)\), `\.jsp` \((\d+)\), `\.php` \((\d+)\), `\.cc` \((\d+)\)")
    snyk = ext["snyk-code"]
    for e, v in zip((".java", ".jsp", ".php", ".cc"), g):
        r.append(par(f"Snyk Code {e}", int(v), snyk[e][0]))
    r.append(par("Snyk Code: as quatro são as maiores", [".java", ".jsp", ".php", ".cc"],
                 sorted(snyk, key=lambda e: (-snyk[e][0], e))[:4]))
    g = busca(r"analisou arquivos de outras linguagens em (\d+) dos (\d+) CVEs")
    m = [re.search(r"CVEs com alguma lang analisada fora de JS/TS: (\d+) de (\d+)", l) for l in capacidade_txt_secao(f, 7)]
    m = [x for x in m if x]
    if len(m) != 1:
        raise FalhaDeExtracao(f"capacidade.txt: linha de cobertura casou {len(m)} vezes")
    r += [par("Snyk: CVEs com lang fora de JS/TS", int(g[0]), int(m[0].group(1))),
          par("Snyk: universo", int(g[1]), int(m[0].group(2)))]
    # concentração
    sec6 = capacidade_txt_secao(f, 6)
    def linha_unica(padrao):
        achados = [m for m in (re.fullmatch(padrao, l) for l in sec6) if m]
        if len(achados) != 1:
            raise FalhaDeExtracao(f"capacidade.txt: {padrao!r} casou {len(achados)} vezes")
        return achados[0]

    tot = int(linha_unica(r"  total (\d+) achados, em \d+ CVEs com achado de \d+").group(1))
    cves = {m.group(1): int(m.group(2)) for m in (re.fullmatch(r"  (CVE-\S+)\s+(\d+)\s+[\d.]+", l) for l in sec6) if m}
    dez = int(linha_unica(r"  dez maiores somam (\d+) \([\d.]+\)").group(1))
    regras = [m.groups() for m in (re.fullmatch(r"  (\S+)\s+(\d+)\s+[\d.]+ (\S+)\s+(sim|nao)", l) for l in sec6) if m]
    g = busca(r"Um único CVE, o `(CVE-[\d-]+)`, responde por ([\d.]+) alertas \((\d+,\d)%\), e os dez maiores por (\d+,\d)%")
    maior = max(cves, key=lambda c: (cves[c], c))
    r += [par("maior CVE do Semgrep", g[0], maior),
          par("alertas do maior CVE", um_numero(g[1]), cves[maior]),
          par("% do maior CVE", um_numero(g[2]), taxa_exata(cves[maior], tot)),
          par("% dos dez maiores", um_numero(g[3]), taxa_exata(dez, tot)),
          par("dez CVEs listados no capacidade.txt", 10, len(cves)),
          par("dez maiores = soma dos listados", dez, sum(cves.values()))]
    g = busca(r"declarada como genérica, responde por ([\d.]+) alertas \((\d+,\d)%\)")
    regra_maior = regras[0]
    r += [par("regra de maior volume", "html.security.audit.missing-integrity.missing-integrity", regra_maior[0]),
          par("regra de maior volume é a de maior contagem", True, all(int(regra_maior[1]) >= int(x[1]) for x in regras)),
          par("alertas da maior regra", um_numero(g[0]), int(regra_maior[1])),
          par("% da maior regra", um_numero(g[1]), taxa_exata(int(regra_maior[1]), tot)),
          par("linguagem declarada da maior regra", "generic", regra_maior[2])]
    g = busca(r"nesta campanha são (\d+,\d)% e (\d+,\d)%")
    r += [par("Semgrep: % em JS/TS", um_numero(g[0]),
              taxa_exata(int(d[("semgrep", "extensao", "js_ts")]["achados"]), tot)),
          par("% da maior regra (repetido)", um_numero(g[1]), taxa_exata(int(regra_maior[1]), tot))]
    r.append(par("total do Semgrep no capacidade.txt = relatórios", tot,
                 sum(x["achados"]["total"] for x in f.relatorios_normalizacao("semgrep"))))
    return r


# O 77% da 9.5 em família própria, e não dentro da 9.11 (revisão): falha de
# extração de outra afirmação da 9.11 não pode levar esta junto.
LOTES_CAMPANHA = tuple(f"cves-sast-batch-{x}" for x in ("aa", "ab", "ac", "ad", "ae", "af", "ag", "ah"))
LOTES_EM_SERIE = LOTES_CAMPANHA[:2]  # aa e ab, 16/09; os seis últimos, 17/09 (CLAUDE.md)


@verificacao("9.5-concentracao", "9.5, 9.11",
             "results/semgrep/treated + logs/campanha-2026-09-17 (logs de execução e relatórios de normalização)")
def _(doc, f):
    """Os dez maiores CVEs dos SEIS ÚLTIMOS lotes sobre os achados desses
    lotes — o recorte da 9.5, distinto do dos oito lotes da 9.11."""
    base = f.raiz / "logs/campanha-2026-09-17"
    lotes = tuple(sorted(p.name for p in base.glob("cves-sast-batch-*")))
    # lotes por NOME, e não por posição (revisão, risco 1)
    if lotes != LOTES_CAMPANHA:
        raise FalhaDeExtracao(f"lotes da campanha: {lotes}")
    ultimos = [l for l in LOTES_CAMPANHA if l not in LOTES_EM_SERIE]
    # cada CVE em exatamente um lote, lido lote a lote e não pelo dicionário
    # que sobrescreve (revisão, risco 2)
    lote_de = defaultdict(set)
    for lote in LOTES_CAMPANHA:
        with open(base / lote / "execution-log-semgrep.csv", encoding="utf-8") as fh:
            for reg in csv.DictReader(fh):
                lote_de[reg["cve"]].add(lote)
    em_varios = sorted(c for c, ls in lote_de.items() if len(ls) != 1)
    por_cve = {t["metadata"]["cve_id"]: len(t["findings"]) for t in f.tratados("semgrep")}
    sem_log = sorted(set(por_cve) - set(lote_de))
    seis = {c: n for c, n in por_cve.items() if lote_de[c] & set(ultimos)}
    extenso = {"dez": 10, "doze": 12, "oito": 8, "cinco": 5, "seis": 6, "sete": 7}
    g = busca_unica("\n".join(doc.secao("### 9.5")),
                    r"Nos (\w+) últimos lotes, (\w+) CVEs somam (\d+)% dos achados da ferramenta nesses lotes", "9.5")
    n_lotes, n_cves = extenso.get(g[0], g[0]), extenso.get(g[1], g[1])
    if not isinstance(n_cves, int):
        raise FalhaDeExtracao(f"9.5: número de CVEs {g[1]!r}")
    maiores = sum(sorted(seis.values(), reverse=True)[:n_cves])
    pct = taxa_exata(maiores, sum(seis.values()), casas=0)
    # contraprova do denominador pelos relatórios de normalização (revisão)
    relatorios = sum(
        json.loads((base / l / "normalize-report-semgrep.json").read_text(encoding="utf-8"))["achados"]["total"]
        for l in ultimos
    )
    remissao = busca_unica("\n".join(doc.secao("### 9.11")),
                           r"a Seção 9\.5 registra (\d+)% para os (\w+) maiores dos (\w+) últimos lotes, recorte distinto",
                           "9.11")
    return [
        par("CVEs em mais de um lote", [], em_varios),
        par("CVEs com tratado sem linha de log", [], sem_log),
        par("9.5: número de lotes", n_lotes, len(ultimos)),
        par("9.5: denominador, tratados = relatórios de normalização", relatorios, sum(seis.values())),
        par("9.5: dez maiores dos seis últimos lotes (%)", int(g[2]), pct),
        par("9.11: remissão ao recorte da 9.5 (%)", int(remissao[0]), pct),
        par("9.11: remissão, número de CVEs", n_cves, extenso.get(remissao[1], remissao[1])),
        par("9.11: remissão, número de lotes", n_lotes, extenso.get(remissao[2], remissao[2])),
    ]


@verificacao("9.11-capacidade", "9.11", "results/capacidade/capacidade-por-cwe.csv, tratados, distribuicao-primario.csv")
def _(doc, f):
    cap = [x for x in f.csv("results/capacidade/capacidade-por-cwe.csv") if x["versao"] == "js_ts_extensao"]
    por = {(x["ferramenta"], x["categoria"]): x for x in cap}
    texto = "\n".join(doc.secao("### 9.11"))
    tab = tabela_rotulada(doc.secao("### 9.11"), "Capacidade, versão principal", "9.11")
    colunas = {}
    for i, c in enumerate(tab[0]):
        m = re.fullmatch(r"(CodeQL|Semgrep|Snyk Code) \(de (\d+)\)", c)
        if m:
            colunas[i] = (FERRAMENTA_DO_ROTULO[m.group(1)], int(m.group(2)))
    if len(colunas) != 3:
        raise FalhaDeExtracao(f"9.11: cabeçalho da capacidade {tab[0]}")
    r = []
    posicoes = [int(l[0]) for l in tab[1:] if l[0].isdigit()]
    busca_unica("\n".join(doc.secao("### 9.11")), r"As (oito) categorias com mais CVEs", "9.11")
    r.append(par("posições da tabela", list(range(1, 9)), posicoes))
    for i, (ferr, universo) in colunas.items():
        ordem = [x for x in cap if x["ferramenta"] == ferr]
        # a posição vem da ordem do CSV: confere-se que ela é a de CVEs
        # decrescente, e que não há empate na fronteira 8/9 (revisão, risco 5)
        chave = [(-int(x["cves_com_achado"]), -int(x["achados"])) for x in ordem]
        r.append(par(f"{ferr}: CSV em ordem de CVEs e achados decrescentes", True, chave == sorted(chave)))
        r.append(par(f"{ferr}: sem empate de CVEs entre a 8ª e a 9ª", True,
                     int(ordem[7]["cves_com_achado"]) > int(ordem[8]["cves_com_achado"])))
        r.append(par(f"{ferr}: universo", universo, int(ordem[0]["universo_cves"])))
        for linha in tab[1:]:
            if linha[0].isdigit():
                pos = int(linha[0])
                m = re.fullmatch(r"(CWE-\d+): (\d+)", linha[i])
                if not m:
                    raise FalhaDeExtracao(f"9.11: célula {linha[i]!r}")
                r += [par(f"{ferr} posição {pos}: categoria", m.group(1), ordem[pos - 1]["categoria"]),
                      par(f"{ferr} posição {pos}: CVEs", int(m.group(2)), int(ordem[pos - 1]["cves_com_achado"]))]
            elif linha[0] == "Categorias distintas":
                r.append(par(f"{ferr}: categorias distintas", um_numero(linha[i]),
                             sum(1 for x in ordem if int(x["cves_com_achado"]) > 0)))
            else:
                raise FalhaDeExtracao(f"9.11: linha {linha[0]!r}")
    # multi-CWE, recontado dos tratados — caminho independente do capacidade-empirica.py
    js_ts = {"js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"}

    def em_js_ts(caminho):
        nome = caminho.rsplit("/", 1)[-1]
        return "." in nome and nome.rsplit(".", 1)[1].lower() in js_ts

    multi, alertas = {}, {}
    for ferr in FERRAMENTAS:
        achados = [a for t in f.tratados(ferr) for a in t["findings"] if em_js_ts(a["file_path"])]
        alertas[ferr] = len(achados)
        multi[ferr] = sum(1 for a in achados if len(a["cwe"]) > 1)
    m = re.findall(r"dos ([\d.]+) alertas do CodeQL em JS/TS, ([\d.]+) têm mais de um CWE; no Semgrep, nenhum; no Snyk Code, ([\d.]+) de ([\d.]+)", texto)
    if len(m) != 1:
        raise FalhaDeExtracao(f"9.11: frase de multi-CWE casou {len(m)} vezes")
    g = m[0]
    r += [par("CodeQL: alertas em JS/TS", um_numero(g[0]), alertas["codeql"]),
          par("CodeQL: com mais de um CWE", um_numero(g[1]), multi["codeql"]),
          par("Semgrep: com mais de um CWE", 0, multi["semgrep"]),
          par("Snyk Code: com mais de um CWE", um_numero(g[2]), multi["snyk-code"]),
          par("Snyk Code: alertas em JS/TS", um_numero(g[3]), alertas["snyk-code"])]
    m = re.findall(r"(\d+) CVEs em CWE-022 e (\d+) em cada um de CWE-023, 036, 073 e 099", texto)
    if len(m) != 1:
        raise FalhaDeExtracao(f"9.11: frase de travessia casou {len(m)} vezes")
    r.append(par("CodeQL CWE-022", int(m[0][0]), int(por[("codeql", "CWE-022")]["cves_com_achado"])))
    for c in ("CWE-023", "CWE-036", "CWE-073", "CWE-099"):
        r.append(par(f"CodeQL {c}", int(m[0][1]), int(por[("codeql", c)]["cves_com_achado"])))
    m = [busca_unica(texto, r"Os (\d+) contra (\d+) medem a prática de etiquetagem", "9.11")]
    distintas = {ferr: sum(1 for x in cap if x["ferramenta"] == ferr and int(x["cves_com_achado"]) > 0) for ferr in FERRAMENTAS}
    r += [par("categorias do CodeQL (ressalva)", int(m[0][0]), distintas["codeql"]),
          par("categorias do Semgrep (ressalva)", int(m[0][1]), distintas["semgrep"])]
    m = [busca_unica(texto, r"O CodeQL reporta alertas de CWE-400 em (\d+) CVEs, e o ground truth tem (\d+) CVEs dessa categoria", "9.11")]
    dist = {x["gt_cwe_primary"]: int(x["n"]) for x in f.csv("results/por-cwe/distribuicao-primario.csv")}
    r += [par("CodeQL CWE-400, CVEs com alerta", int(m[0][0]), int(por[("codeql", "CWE-400")]["cves_com_achado"])),
          par("CWE-400 no ground truth (primário)", int(m[0][1]), dist["CWE-400"])]
    return r


# ---- 9.8 e 8.9: versão corrigida (revisão de 29/09/2026) -------------------
CC_DIR = "results/cruzamento-corrigida"
LOGS_CORRIGIDA = "logs/campanha-corrigida-2026-09-29"
NIVEL_DO_ROTULO_98 = {"3": "nivel_3", "4 generosa": "nivel_4_generosa", "4 estrita": "nivel_4_estrita"}
ORDEM_FERR_98 = (("CodeQL", "codeql"), ("Semgrep", "semgrep"), ("Snyk Code", "snyk-code"))


def cc_json(f, ferramenta):
    return f.relatorio_avulso(f"{CC_DIR}/cruzamento-corrigida-{ferramenta}.json")


def pct_exato(num, den, casas=1):
    """Porcentagem em aritmética exata, arredondada meio para cima."""
    return arredonda(Decimal(100 * num) / Decimal(den), casas)


def f1_exato(vp, fp, fn):
    """F1 = 2·VP / (2·VP + FP + FN), exato, em porcentagem a uma casa."""
    return arredonda(Decimal(100 * 2 * vp) / Decimal(2 * vp + fp + fn), 1)


def tabela_por_cabecalho(bloco, celulas_iniciais, onde):
    """A única tabela do bloco cujo cabeçalho começa pelas células dadas."""
    achadas = [t for t in Documento.tabelas(bloco)
               if t and t[0][:len(celulas_iniciais)] == list(celulas_iniciais)]
    if len(achadas) != 1:
        raise FalhaDeExtracao(f"{onde}: {len(achadas)} tabelas com cabeçalho {celulas_iniciais!r}")
    return achadas[0]


def matriz_corrigida_principal(f):
    """{(ferramenta, nível): [(tipo, lado vulnerável, lado corrigido)]}, nos 212."""
    saida = defaultdict(list)
    for r in f.csv(f"{CC_DIR}/matriz-corrigida.csv"):
        if r["na_principal"] == "true":
            saida[(r["ferramenta"], r["nivel"])].append(
                (r["gt_tipo_ponto"], r["lado_vulneravel"], r["lado_corrigido"]))
    return saida


@verificacao("9.8-principal", "9.8", f"{CC_DIR}/cruzamento-corrigida-*.json")
def _(doc, f):
    bloco = doc.secao("### 9.8")
    texto = "\n".join(bloco)
    tab = tabela_por_cabecalho(bloco, ["Nível", "Ferramenta", "VP", "FN", "FP", "VN", "Sem análise",
                                       "Recall", "Precisão", "Especificidade", "F1"], "9.8 matriz principal")
    linhas = tab[1:]
    res = [par("linhas da tabela principal", len(linhas), 9)]
    vistos = set()
    for linha in linhas:
        nivel = NIVEL_DO_ROTULO_98.get(linha[0])
        ferr = FERRAMENTA_DO_ROTULO.get(linha[1])
        if nivel is None or ferr is None:
            raise FalhaDeExtracao(f"9.8: linha com rótulo inesperado {linha[:2]!r}")
        vistos.add((nivel, ferr))
        m = cc_json(f, ferr)["principal"][nivel]
        rot = f"{linha[0]} {linha[1]}"
        for i, chave in enumerate(("VP", "FN", "FP", "VN", "sem_analise"), start=2):
            res.append(par(f"{rot}: {chave}", um_numero(linha[i]), m[chave]))
        res.append(par(f"{rot}: recall (%)", um_numero(linha[7]), pct_exato(m["VP"], m["VP"] + m["FN"])))
        res.append(par(f"{rot}: precisão (%)", um_numero(linha[8]), pct_exato(m["VP"], m["VP"] + m["FP"])))
        res.append(par(f"{rot}: especificidade (%)", um_numero(linha[9]), pct_exato(m["VN"], m["base"])))
        res.append(par(f"{rot}: F1 (%)", um_numero(linha[10]), f1_exato(m["VP"], m["FP"], m["FN"])))
    res.append(par("células distintas (nível, ferramenta)", len(vistos), 9))
    r0 = cc_json(f, "codeql")
    res.append(par("universo da principal", int(busca_unica(texto, r"Universo de \*\*(\d+) CVEs\*\*", "9.8")),
                   r0["universo"]["principal"]))
    res.append(par("CVEs inalterada", int(busca_unica(texto, r"não a alterou \((\d+) CVEs\)", "9.8")),
                   r0["universo"]["grupos_principal"]["inalterada"]))
    res.append(par("CVEs trecho", int(busca_unica(texto, r"que a substituiu \((\d+) CVEs\)", "9.8")),
                   r0["universo"]["grupos_principal"]["trecho"]))
    res.append(par("base da estrita", int(busca_unica(texto, r"Na variante estrita, a base é (\d+)", "9.8")),
                   r0["principal"]["nivel_4_estrita"]["base"]))
    res.append(par("CVEs excluídos (os 8)", int(busca_unica(texto, r"menos os (\d+) cuja correção só removeu", "9.8")),
                   len(r0["universo"]["so_remocao_fora_da_principal"])))
    res.append(par("denominador de que se parte", int(busca_unica(texto, r"os (\d+) do denominador menos os", "9.8")),
                   r0["universo"]["sensibilidade"]))
    fecha = int(busca_unica(texto, r"FP \+ VN \+ sem análise fecha em (\d+) em todas as células", "9.8"))
    for (ferr, nivel), cel in sorted(matriz_corrigida_principal(f).items()):
        nsa = sum(1 for _, _, cor in cel if cor == "nao_se_aplica")
        soma = sum(1 for _, _, cor in cel if cor in ("FP", "VN", "sem_analise"))
        res.append(par(f"{ferr} {nivel}: FP + VN + sem análise (+ n.s.a.)", fecha, soma + nsa))
    return res


@verificacao("9.8-recall-220", "9.8", f"{CC_DIR}/cruzamento-corrigida-*.json + results/cruzamento/matriz-deteccao.csv")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.8"))
    g = busca_unica(texto, r"(\d+) contra (\d+) no CodeQL, (\d+) contra (\d+) no Semgrep e (\d+) contra (\d+) no Snyk Code", "9.8")
    res = []
    matriz = f.matriz
    for i, (rotulo, ferr) in enumerate(ORDEM_FERR_98):
        r = cc_json(f, ferr)
        res.append(par(f"{rotulo}: VP nos 212, nível 3", int(g[2 * i]), r["principal"]["nivel_3"]["recall"]["num"]))
        res.append(par(f"{rotulo}: VP nos 220 (JSON)", int(g[2 * i + 1]), r["recall_sobre_220_publicado"]["nivel_3"]["num"]))
        publicados = sum(1 for l in matriz if l["ferramenta"] == ferr and l["no_denominador"] == "true" and l["nivel_3"] == "true")
        res.append(par(f"{rotulo}: VP nos 220 (matriz publicada)", int(g[2 * i + 1]), publicados))
    return res


@verificacao("9.8-sensibilidade", "9.8", f"{CC_DIR}/cruzamento-corrigida-*.json + matriz-corrigida.csv")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.8"))
    g = busca_unica(texto, r"a precisão passa de ([\d,]+)% para ([\d,]+)% no CodeQL, de ([\d,]+)% para ([\d,]+)% no Semgrep, e fica em ([\d,]+)% no Snyk Code", "9.8")
    res = []
    valores = [um_numero(x) for x in g]
    for i, (rotulo, ferr) in enumerate(ORDEM_FERR_98[:2]):
        r = cc_json(f, ferr)
        p, s = r["principal"]["nivel_3"], r["sensibilidade"]["nivel_3"]
        res.append(par(f"{rotulo}: precisão principal", valores[2 * i], pct_exato(p["VP"], p["VP"] + p["FP"])))
        res.append(par(f"{rotulo}: precisão sensibilidade", valores[2 * i + 1], pct_exato(s["VP"], s["VP"] + s["FP"])))
    r = cc_json(f, "snyk-code")
    p, s = r["principal"]["nivel_3"], r["sensibilidade"]["nivel_3"]
    res.append(par("Snyk Code: precisão principal ('fica em')", valores[4], pct_exato(p["VP"], p["VP"] + p["FP"])))
    res.append(par("Snyk Code: precisão sensibilidade ('fica em')", valores[4], pct_exato(s["VP"], s["VP"] + s["FP"])))
    busca_unica(texto, r"Nenhum dos 8 gerou falso positivo em ferramenta alguma", "9.8")
    for _, ferr in ORDEM_FERR_98:
        r = cc_json(f, ferr)
        for nivel in NIVEL_DO_ROTULO_98.values():
            res.append(par(f"{ferr} {nivel}: FP da sensibilidade = FP da principal",
                           r["principal"][nivel]["FP"], r["sensibilidade"][nivel]["FP"]))
    fp_nos_8 = sum(1 for l in f.csv(f"{CC_DIR}/matriz-corrigida.csv")
                   if l["na_principal"] == "false" and l["lado_corrigido"] == "FP")
    res.append(par("FP nos 8 so_remocao (matriz-corrigida.csv)", 0, fp_nos_8))
    return res


@verificacao("9.8-grupo", "9.8", f"{CC_DIR}/cruzamento-corrigida-*.json")
def _(doc, f):
    bloco = doc.secao("### 9.8")
    achadas = [t for t in Documento.tabelas(bloco)
               if t and len(t[0]) == 3 and t[0][0] == "Ferramenta" and t[0][1].startswith("FP, linha inalterada")
               and t[0][2].startswith("FP, trecho substituído")]
    if len(achadas) != 1:
        raise FalhaDeExtracao(f"9.8 por grupo: {len(achadas)} tabelas com o cabeçalho esperado")
    tab = achadas[0]
    cab = tab[0]
    if len(cab) != 3 or "inalterada" not in cab[1] or "trecho" not in cab[2]:
        raise FalhaDeExtracao(f"9.8 por grupo: cabeçalho inesperado {cab!r}")
    res = []
    r0 = cc_json(f, "codeql")["decomposicao_por_grupo_principal"]["nivel_3"]
    res.append(par("CVEs inalterada (cabeçalho)", um_numero(cab[1]), r0["inalterada"]["cves"]))
    res.append(par("CVEs trecho (cabeçalho)", um_numero(cab[2]), r0["trecho"]["cves"]))
    ini, tre = busca_unica("\n".join(bloco), r"inalterada em (\d+) CVEs e a substituiu em (\d+):", "9.8")
    res.append(par("CVEs inalterada (texto)", int(ini), r0["inalterada"]["cves"]))
    res.append(par("CVEs trecho (texto)", int(tre), r0["trecho"]["cves"]))
    for rotulo, ferr in ORDEM_FERR_98:
        linha = Documento.linha_da_tabela(tab[1:], rotulo)
        g = cc_json(f, ferr)["decomposicao_por_grupo_principal"]["nivel_3"]
        res.append(par(f"{rotulo}: FP inalterada", um_numero(linha[1]), g["inalterada"]["FP"]))
        res.append(par(f"{rotulo}: FP trecho", um_numero(linha[2]), g["trecho"]["FP"]))
    return res


def cruzado_98(f, ferr):
    """Contagens do nível 3 por lado vulnerável, recalculadas da matriz-corrigida.csv."""
    celulas = matriz_corrigida_principal(f)[(ferr, "nivel_3")]
    c = Counter((vul, cor) for _, vul, cor in celulas)
    grupo = Counter((tipo, vul, cor) for tipo, vul, cor in celulas)
    vp = sum(n for (v, _), n in c.items() if v == "VP")
    fn = sum(n for (v, _), n in c.items() if v == "FN")
    return {"vp": vp, "vp_fp": c[("VP", "FP")], "vp_vn": c[("VP", "VN")], "fn": fn,
            "fn_fp": c[("FN", "FP")], "fp": sum(n for (_, k), n in c.items() if k == "FP"),
            "grupo": {t: {"vp": sum(n for (tt, v, _), n in grupo.items() if tt == t and v == "VP"),
                          "vp_fp": grupo[(t, "VP", "FP")]} for t in ("inalterada", "trecho")}}


@verificacao("9.8-exploratoria", "9.8", f"{CC_DIR}/matriz-corrigida.csv (recalculado)")
def _(doc, f):
    bloco = doc.secao("### 9.8")
    t1 = tabela_por_cabecalho(bloco, ["Ferramenta", "Detectados (VP)", "… e FP depois", "… e VN depois",
                                      "Não detectados (FN)", "… e FP depois"], "9.8 exploratória 1")
    t2 = tabela_por_cabecalho(bloco, ["Ferramenta", "Linha inalterada: detectados / FP",
                                      "Trecho substituído: detectados / FP"], "9.8 exploratória 2")
    res = []
    for rotulo, ferr in ORDEM_FERR_98:
        x = cruzado_98(f, ferr)
        l1 = Documento.linha_da_tabela(t1[1:], rotulo)
        for i, chave in enumerate(("vp", "vp_fp", "vp_vn", "fn", "fn_fp"), start=1):
            res.append(par(f"{rotulo}: {chave}", um_numero(l1[i]), x[chave]))
        l2 = Documento.linha_da_tabela(t2[1:], rotulo)
        for i, tipo in ((1, "inalterada"), (2, "trecho")):
            det, fp = numeros(l2[i])
            res.append(par(f"{rotulo}: {tipo} detectados", det, x["grupo"][tipo]["vp"]))
            res.append(par(f"{rotulo}: {tipo} FP", fp, x["grupo"][tipo]["vp_fp"]))
    return res


@verificacao("9.8-benchmark", "9.8", f"{CC_DIR}/cruzamento-corrigida-*.json + leitura-benchmark.csv")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.8"))
    g = busca_unica(texto, r"em \*\*(\d+) de (\d+)\*\* no CodeQL, \*\*(\d+) de (\d+)\*\* no Semgrep e \*\*(\d+) de (\d+)\*\* no Snyk Code", "9.8")
    aus = int(busca_unica(texto, r"e os (\d+) sem análise do Snyk Code, ausentes", "9.8"))
    leitura = f.csv(f"{CC_DIR}/leitura-benchmark.csv")
    res = []
    for i, (rotulo, ferr) in enumerate(ORDEM_FERR_98):
        lb = cc_json(f, ferr)["leitura_benchmark"]
        linhas = [l for l in leitura if l["ferramenta"] == ferr]
        res.append(par(f"{rotulo}: reconhecida (JSON)", int(g[2 * i]), lb["reconhecida"]))
        res.append(par(f"{rotulo}: reconhecida (CSV)", int(g[2 * i]), sum(l["resultado"] == "reconhecida" for l in linhas)))
        res.append(par(f"{rotulo}: detectados (JSON)", int(g[2 * i + 1]), lb["detectados_criterio_exato"]))
        res.append(par(f"{rotulo}: detectados (CSV)", int(g[2 * i + 1]), sum(l["detectado_criterio_benchmark"] == "true" for l in linhas)))
    lb = cc_json(f, "snyk-code")["leitura_benchmark"]
    res.append(par("Snyk Code: ausentes (JSON)", aus, lb["ausente"]))
    res.append(par("Snyk Code: ausentes (CSV)", aus, sum(1 for l in leitura if l["ferramenta"] == "snyk-code" and l["resultado"] == "ausente")))
    return res


@verificacao("9.8-leitura", "9.8", f"{CC_DIR}/matriz-corrigida.csv (recalculado) + cruzamento-corrigida-*.json")
def _(doc, f):
    texto = "\n".join(doc.secao("### 9.8"))
    res = []
    x = {ferr: cruzado_98(f, ferr) for _, ferr in ORDEM_FERR_98}
    g = busca_unica(texto, r"(\d+) de (\d+) no CodeQL, (\d+) de (\d+) no Semgrep e (\d+) de (\d+) no Snyk Code\. Uma ferramenta", "9.8")
    for i, (rotulo, ferr) in enumerate(ORDEM_FERR_98):
        res.append(par(f"{rotulo}: FP vindo de VP", int(g[2 * i]), x[ferr]["vp_fp"]))
        res.append(par(f"{rotulo}: FP total", int(g[2 * i + 1]), x[ferr]["fp"]))
    g = busca_unica(texto, r"em (\d+) de (\d+) \((\d+)%\), contra (\d+) de (\d+) no Semgrep \((\d+)%\) e (\d+) de (\d+) no Snyk Code \((\d+)%\)", "9.8")
    for i, (rotulo, ferr) in enumerate(ORDEM_FERR_98):
        a, b, pc = (int(v) for v in g[3 * i:3 * i + 3])
        res.append(par(f"{rotulo}: VN entre detectados", a, x[ferr]["vp_vn"]))
        res.append(par(f"{rotulo}: detectados", b, x[ferr]["vp"]))
        res.append(par(f"{rotulo}: % VN entre detectados", pc, pct_exato(x[ferr]["vp_vn"], x[ferr]["vp"], 0)))
    g = busca_unica(texto, r"vai na mesma direção \((\d+)%, (\d+)% e (\d+)%\)", "9.8")
    for i, (rotulo, ferr) in enumerate(ORDEM_FERR_98):
        lb = cc_json(f, ferr)["leitura_benchmark"]
        res.append(par(f"{rotulo}: % reconhecida (benchmark)", int(g[i]),
                       pct_exato(lb["reconhecida"], lb["detectados_criterio_exato"], 0)))
    g = busca_unica(texto, r"o Semgrep alertou de novo em (\d+) de (\d+) CVEs detectados e o Snyk Code em (\d+) de (\d+); o CodeQL, em (\d+) de (\d+)", "9.8")
    for i, ferr in enumerate(("semgrep", "snyk-code", "codeql")):
        res.append(par(f"{ferr}: FP entre detectados, linha inalterada", int(g[2 * i]), x[ferr]["grupo"]["inalterada"]["vp_fp"]))
        res.append(par(f"{ferr}: detectados, linha inalterada", int(g[2 * i + 1]), x[ferr]["grupo"]["inalterada"]["vp"]))
    lo, hi = busca_unica(texto, r"têm de (\d+) a (\d+) casos", "9.8")
    # "subgrupos": os detectados de cada uma e a divisão deles pelo que a
    # correção fez com a linha — as bases das frações da leitura.
    sub = [x[ferr]["vp"] for ferr in ("semgrep", "snyk-code")] + \
          [x[ferr]["grupo"][t]["vp"] for ferr in ("semgrep", "snyk-code") for t in ("inalterada", "trecho")]
    res.append(par("menor subgrupo de Semgrep e Snyk Code", int(lo), min(sub)))
    res.append(par("maior subgrupo de Semgrep e Snyk Code", int(hi), max(sub)))
    busca_unica(texto, r"o CodeQL tem o maior número de falsos positivos e a menor especificidade", "9.8")
    for nivel in NIVEL_DO_ROTULO_98.values():
        fp = {ferr: cc_json(f, ferr)["principal"][nivel]["FP"] for _, ferr in ORDEM_FERR_98}
        # Fração exata, não o valor arredondado do JSON: dois valores distintos
        # podem colidir a quatro casas.
        esp = {ferr: Decimal(cc_json(f, ferr)["principal"][nivel]["especificidade"]["num"])
                     / Decimal(cc_json(f, ferr)["principal"][nivel]["especificidade"]["den"])
               for _, ferr in ORDEM_FERR_98}
        # Empate não conta a favor de ninguém: "o maior" exige máximo único.
        maiores = [k for k, v in fp.items() if v == max(fp.values())]
        menores = [k for k, v in esp.items() if v == min(esp.values())]
        res.append(par(f"{nivel}: ferramenta(s) com mais FP", ["codeql"], maiores))
        res.append(par(f"{nivel}: ferramenta(s) com menor especificidade", ["codeql"], menores))
    return res


def logs_corrigida(f):
    """(registro final {ferramenta: {cve: linha}}, linhas todas) — oito lotes e o redisparo, em ordem."""
    base = f.raiz / LOGS_CORRIGIDA
    ordem = sorted(base.glob("cves-sast-corrigida-batch-*")) + sorted(base.glob("cves-sast-corrigida-reexec-*"))
    final, todas = defaultdict(dict), []
    for lote in ordem:
        for ferr in FERRAMENTAS:
            arq = lote / f"execution-log-{ferr}.csv"
            if not arq.is_file():
                continue
            with open(arq, encoding="utf-8") as fh:
                for reg in csv.DictReader(fh):
                    reg["lote"], reg["ferramenta"] = lote.name, ferr
                    final[ferr][reg["cve"]] = reg
                    todas.append(reg)
    return final, todas


@verificacao("8.9", "8.9", "results/pares/pares.csv + datasets/listas/ + logs/campanha-corrigida-2026-09-29/ + README dos artifacts")
def _(doc, f):
    texto = "\n".join(doc.secao("### 8.9"))
    res = []
    pares = f.csv("results/pares/pares.csv")
    desc, dist1 = busca_unica(texto, r"em (\d+) CVEs o commit corrigido descende do vulnerável, a um commit de distância em (\d+)", "8.9")
    res.append(par("CVEs com post descendendo do pre", int(desc), sum(p["relacao"] == "post_descende_de_pre" for p in pares)))
    res.append(par("CVEs a um commit de distância", int(dist1), sum(p["relacao"] == "post_descende_de_pre" and p["distancia"] == "1" for p in pares)))
    fumaca = [l for l in (f.raiz / "datasets/listas/cves-sast-corrigida-fumaca").read_text(encoding="utf-8").splitlines() if l]
    res.append(par("CVEs do ensaio", int(busca_unica(texto, r"com (\d+) CVEs escolhidos pela caracterização", "8.9")), len(fumaca)))
    final, todas = logs_corrigida(f)
    post = {p["cve"]: p["post"] for p in pares}
    n_pares = int(busca_unica(texto, r"Nos (\d+) pares \(CVE, ferramenta\)", "8.9"))
    res.append(par("pares (CVE, ferramenta) no registro final", n_pares, sum(len(v) for v in final.values())))
    res.append(par("pares com commit analisado = post", n_pares,
                   sum(1 for v in final.values() for c, r in v.items() if r["commit"] == post[c])))
    # Os zeros abaixo so valem presos a frase do texto que os afirma.
    busca_unica(texto, r"o commit analisado é o corrigido; não houve falha de obtenção nem de checkout, "
                       r"nem recurso ao clone de contingência", "8.9")
    res.append(par("linhas de log com commit diferente do post", 0, sum(1 for r in todas if r["commit"] != post[r["cve"]])))
    res.append(par("ERRO_FETCH ou ERRO_CHECKOUT", 0, sum(1 for r in todas if r["status"] in ("ERRO_FETCH", "ERRO_CHECKOUT"))))
    fallback = 0
    check_logs = sorted((f.raiz / LOGS_CORRIGIDA).glob("cves-sast-corrigida-*/*/portoes/check-log.txt"))
    for arq in check_logs:
        fallback += int(busca_unica(arq.read_text(encoding="utf-8"), r"fallback de clone completo: (\d+)", str(arq)))
    # "Nao ha" x "nao perguntei": um check-log.txt por job importado.
    jobs_importados = sorted((f.raiz / LOGS_CORRIGIDA).glob("cves-sast-corrigida-*/*/README.txt"))
    res.append(par("check-log.txt lidos = jobs importados", len(jobs_importados), len(check_logs)))
    res.append(par("recurso ao clone de contingência", 0, fallback))
    lotes = sorted((f.raiz / LOGS_CORRIGIDA).glob("cves-sast-corrigida-batch-*"))
    res.append(par("lotes", EXTENSO.get(busca_unica(texto, r"\*\*Execução\.\*\* (\w+) lotes", "8.9").lower()), len(lotes)))
    busca_unica(texto, r"com a mesma partição da campanha de detecção", "8.9")
    listas = f.raiz / "datasets/listas"
    fora = {l.split(",")[0] for l in (listas / "cves-sast.txt").read_text(encoding="utf-8").splitlines() if l} - \
           {l.split(",")[0] for l in (listas / "cves-sast-corrigida.txt").read_text(encoding="utf-8").splitlines() if l}
    mesma = all([l.split(",")[0] for l in (listas / lote.name).read_text(encoding="utf-8").splitlines() if l] ==
                [c for c in (l.split(",")[0] for l in (listas / lote.name.replace("-corrigida", "")).read_text(encoding="utf-8").splitlines() if l)
                 if c not in fora] for lote in lotes)
    res.append(par("lote corrigido = lote de detecção de mesma letra menos as exclusões", True, mesma))
    unico = busca_unica(texto, r"\*\*Redisparo\.\*\* (\w+) CVE, o `CVE", "8.9")
    erros_lotes = [r for r in todas if r["lote"].startswith("cves-sast-corrigida-batch-") and r["status"].startswith("ERRO")]
    res.append(par("CVEs com erro nos lotes ('Um CVE')", {"um": 1, "Um": 1}.get(unico), len(erros_lotes)))
    leias = [lote / ferr / "README.txt" for lote in lotes for ferr in FERRAMENTAS]
    n_jobs = int(busca_unica(texto, r"Os (\d+) jobs terminaram com sucesso", "8.9"))
    res.append(par("jobs com README", n_jobs, sum(1 for x in leias if x.is_file())))
    sucesso = 0
    for x in leias:
        t = x.read_text(encoding="utf-8")
        desfecho = re.findall(r"^(preparar|portao previo \(fixtures\)|imagem por digest|lote|normalize\.py|check-log\.py|portao de lote sem raw): (\w+)$", t, re.M)
        sucesso += len(desfecho) == 7 and all(v == "success" for _, v in desfecho)
    res.append(par("jobs com todos os passos em success", n_jobs, sucesso))
    extenso = busca_unica(texto, r"sem material analisável nos mesmos (\w+) CVEs da detecção", "8.9")
    sem_corr = {c for c, r in final["snyk-code"].items() if r["status"] == "SEM_ARQUIVO_ANALISAVEL"}
    sem_det = {c for c, r in f.logs_campanha("snyk-code").items() if r["status"] == "SEM_ARQUIVO_ANALISAVEL"}
    res.append(par("sem material analisável no Snyk Code", EXTENSO.get(extenso), len(sem_corr)))
    res.append(par("os mesmos da detecção", True, sem_corr == sem_det))
    res.append(par("sem análise do Snyk Code (JSON do cruzamento) = os da detecção", True,
                   set(cc_json(f, "snyk-code")["sem_analise"]["sensibilidade"]) == sem_det))
    res.append(par("sem material analisável no CodeQL e no Semgrep", 0,
                   sum(1 for ferr in ("codeql", "semgrep") for r in final[ferr].values() if r["status"] == "SEM_ARQUIVO_ANALISAVEL")))
    v_det, v_cor = busca_unica(texto, r"\(`([\d.]+)` na detecção, `([\d.]+)` na versão corrigida\)", "8.9")
    def versoes(padrao):
        vs = set()
        for x in sorted((f.raiz).glob(padrao)):
            m = re.search(r"^runner_image_version: (\S+)$", x.read_text(encoding="utf-8"), re.M)
            vs.add(m.group(1) if m else None)
        return vs
    res.append(par("imagem do runner na detecção", {v_det}, versoes("logs/campanha-2026-09-17/cves-sast-batch-*/*/README.txt")))
    res.append(par("imagem do runner na versão corrigida", {v_cor}, versoes(f"{LOGS_CORRIGIDA}/cves-sast-corrigida-*/*/README.txt")))
    cve_redisp = busca_unica(texto, r"Um CVE, o `(CVE-\d+-\d+)`, falhou no Snyk Code", "8.9")
    busca_unica(texto, r"antes do redisparo, que terminou com sucesso", "8.9")
    res.append(par(f"status final do {cve_redisp} no Snyk Code", "OK", final["snyk-code"][cve_redisp]["status"]))
    res.append(par(f"status do {cve_redisp} no lote, antes do redisparo", "ERRO_ANALISE",
                   next(r["status"] for r in todas if r["cve"] == cve_redisp and r["ferramenta"] == "snyk-code"
                        and r["lote"].startswith("cves-sast-corrigida-batch-"))))
    return res


# Afirmações declaradas NÃO conferíveis a partir do repositório: impressas na
# saída, nunca contadas como falha. (padrão no texto, seção, motivo)
NAO_CONFERIVEIS = [
    (r"o resultado é idêntico, campo a campo, ao da campanha", "### 8.8",
     "SARIF e tratados das invocações de 26/09/2026 não são versionados; o repositório guarda só o resumo da comparação"),
    (r"só 20,7% dos alertas do Semgrep", "### 9.11", "campanha preliminar: dados não versionados neste repositório"),
    (r"respondia por 56,5% do total", "### 9.11", "campanha preliminar: dados não versionados neste repositório"),
    (r"por timeout de conexão com a API, antes do início do teste", "### 8.9",
     "a causa está no container/lote.txt do Snyk Code do lote af; o log de execução diz só 'snyk saiu com 2'"),
    (r"o primeiro sozinho, com leitura antes dos demais", "### 8.9",
     "ordem de disparo e leitura: horários de execução no GitHub Actions, não versionados"),
    (r"foi registrada e commitada antes do redisparo", "### 8.9",
     "ordem entre commit e disparo: está no histórico do git (8039cc7) e no horário da execução, não em arquivo versionado"),
    (r"passou em todas as conferências e revelou um defeito", "### 8.9",
     "conferências do ensaio feitas no relatório da sessão; o repositório guarda os registros, não o resultado das conferências"),
]


# ---- coerência interna do próprio documento ------------------------------
@verificacao("coerencia-interna", "várias", "o próprio documento")
def _(doc, f):
    """Número repetido em mais de uma seção precisa ser o mesmo nas duas.

    O valor é extraído da seção de referência e procurado nas demais, na
    grafia do documento — não se compara com constante alguma daqui.
    """
    repetidos = [
        ("achados normalizados", "### 5.6", r"rodou sobre ([\d.]+) achados reais", ["### 7.7", "### 12.1"]),
        ("inventário que bate", "### 9.6", r"bateu em \*\*(\d+) dos \d+ CVEs\*\*", ["### 12.1"]),
        ("percentual de herança", "#### 2.2.2 ", r"\*\*163 de 223 \((\d+,\d+)%\)\*\*", ["### 9.10", "### 12.2"]),
        ("maior extração", "### 9.6", r"maior extração observada foi de ([\d.]+) arquivos", ["### 9.4", "### 12.2"]),
        ("denominador", "### 9.1", r"\| Pares no denominador \| (\d+) \|", ["### 7.4", "### 9.2"]),
    ]
    resultados = []
    for rotulo, referencia, padrao, outras in repetidos:
        bruto = doc.inline(referencia, padrao)
        grafia = re.escape(bruto)
        for prefixo in outras:
            bloco = "\n".join(doc.secao(prefixo))
            resultados.append(
                par(
                    f"{rotulo} ({bruto}) reaparece em {prefixo.strip()}",
                    True,
                    bool(re.search(rf"(?<![\d.,]){grafia}(?!\d)", bloco)),
                )
            )
    return resultados


# --------------------------------------------------------------------------
# execução
# --------------------------------------------------------------------------
def compara(p):
    esperado, obtido, tol = p["esperado"], p["obtido"], p["tolerancia"]
    if isinstance(esperado, (int, float)) and isinstance(obtido, (int, float)):
        return abs(float(esperado) - float(obtido)) <= tol + 1e-9
    return esperado == obtido


def roda(doc, fontes, apenas=None):
    linhas = []
    for v in VERIFICACOES:
        if apenas and v["id"] not in apenas:
            continue
        try:
            pares = v["fn"](doc, fontes)
        except Exception as exc:  # falha de extração ou de fonte
            linhas.append(
                {
                    "id": v["id"],
                    "secao": v["secao"],
                    "fonte": v["fonte"],
                    "rotulo": "(falha)",
                    "esperado": "—",
                    "obtido": f"{type(exc).__name__}: {exc}",
                    "ok": False,
                    "falha": True,
                }
            )
            continue
        for p in pares:
            linhas.append(
                {
                    "id": v["id"],
                    "secao": v["secao"],
                    "fonte": v["fonte"],
                    "rotulo": p["rotulo"],
                    "esperado": p["esperado"],
                    "obtido": p["obtido"],
                    "ok": compara(p),
                    "falha": False,
                }
            )
    return linhas


MUTACOES = [
    ("9.2: acertos do CodeQL no nível 1", "| 1 — arquivo | 140 (63,6%)", "| 1 — arquivo | 141 (63,6%)", "9.2-matriz"),
    ("9.5: total de achados do Semgrep", "| Achados | 3.230 | 11.768 |", "| Achados | 3.230 | 11.769 |", "9.5-volume"),
    ("2.2.1: CVEs com extensão .js", "| `.js` | 202 |", "| `.js` | 203 |", "2.2.1-extensoes"),
    ("9.10: tamanho do grupo herdado", "**161 CVEs com etiqueta herdada e 59 sem**", "**162 CVEs com etiqueta herdada e 59 sem**", "9.10-particao"),
    ("9.4: mediana do CodeQL", "| CodeQL | 47 s | 58,6 s |", "| CodeQL | 48 s | 58,6 s |", "9.4-duracao"),
    ("4.4: duração do lote mais lento", "**de 26 a 33 minutos**", "**de 26 a 34 minutos**", "4.4-lotes"),
    ("9.6: CVEs em que o inventário bate", "bateu em **211 dos 221 CVEs**", "bateu em **212 dos 221 CVEs**", "9.6-inventario"),
    ("7.4: pares no denominador", "| **Pares no denominador** | **220** |", "| **Pares no denominador** | **219** |", "7.4-grandezas"),
    ("7.7: ganho da sobreposição", "**5, 1 e 13 achados**", "**6, 1 e 13 achados**", "7.7-linha"),
    ("6.1: alertas do full scan do NodeGoat", "| NodeGoat | Full | 3 | 7 | 9 | 10 | 29 |", "| NodeGoat | Full | 3 | 7 | 9 | 10 | 30 |", "6.1-zap"),
    ("8.8: sobrecarga do laço", "ficou entre 1 e 4 segundos por lote", "ficou entre 1 e 5 segundos por lote", "8.8-sobrecarga"),
    ("9.9: limite superior de uma célula acima do limiar", "| 14 | 7 · 50,0% [26,8; 73,2]", "| 14 | 7 · 50,0% [26,8; 73,3]", "9.9-acima"),
    ("9.9: limite pelo CSV arredondado duas vezes (54,7)", "4 · 28,6% [11,7; 54,6] | 4 · 28,6%", "4 · 28,6% [11,7; 54,7] | 4 · 28,6%", "9.9-acima"),
    ("9.9: contagem abaixo do limiar", "| CWE-116 | 9 | 8 / 7 |", "| CWE-116 | 9 | 8 / 6 |", "9.9-abaixo"),
    ("9.9: soma das dez categorias de 1 CVE", "| dez categorias de 1 CVE | 10 | 5 / 2 |", "| dez categorias de 1 CVE | 10 | 5 / 3 |", "9.9-abaixo"),
    ("9.9: número da leitura", "contra 17 do CodeQL", "contra 18 do CodeQL", "9.9-leitura"),
    ("9.11: concordância dos dois critérios", "concordam em 99,01%", "concordam em 99,02%", "9.11-delimitacao"),
    ("9.11: alertas do CodeQL em .html", "No CodeQL, 600 dos 673", "No CodeQL, 601 dos 673", "9.11-extensoes"),
    ("9.11: célula da tabela de capacidade", "| 3 | CWE-079: 91 |", "| 3 | CWE-079: 92 |", "9.11-capacidade"),
    ("9.11: reaparição do 600 na ressalva", "e seus 600 alertas ali", "e seus 610 alertas ali", "9.11-extensoes"),
    ("9.9: 'n.s.a.' trocado por 0", "| `SEM_PRIMARIO` | 1 | 0 / n.s.a. | 0 / n.s.a. | 0 / n.s.a. |",
     "| `SEM_PRIMARIO` | 1 | 0 / 0 | 0 / n.s.a. | 0 / n.s.a. |", "9.9-abaixo"),
    ("9.9: 'cinco' CVEs sem material analisável", "**Os cinco CVEs sem material analisável", "**Os seis CVEs sem material analisável", "9.9-leitura"),
    ("9.5: dez maiores dos seis últimos lotes", "dez CVEs somam 77% dos achados", "dez CVEs somam 78% dos achados", "9.5-concentracao"),
    ("9.11: remissão ao 77% da 9.5", "a Seção 9.5 registra 77%", "a Seção 9.5 registra 76%", "9.5-concentracao"),
    ("9.5: número de CVEs do recorte", "Nos seis últimos lotes, dez CVEs somam", "Nos seis últimos lotes, doze CVEs somam", "9.5-concentracao"),
    ("9.5: número de lotes do recorte", "Nos seis últimos lotes, dez CVEs", "Nos sete últimos lotes, dez CVEs", "9.5-concentracao"),
    ("8.8: número de invocações", "com quatro invocações sobre a imagem", "com cinco invocações sobre a imagem", "8.8-snyk-403"),
    ("8.8: testes com achados e com 403", "133 de 133 testes com achados, e nenhum", "132 de 133 testes com achados, e nenhum", "8.8-snyk-403"),
    ("8.8: testes sem achados", "e nenhum dos 83 sem achados", "e nenhum dos 84 sem achados", "8.8-snyk-403"),
    ("8.8: execuções comparadas", "em três execuções, o resultado", "em duas execuções, o resultado", "8.8-snyk-403"),
    ("8.8: amostra", "mas a amostra é de dois.", "mas a amostra é de três.", "8.8-snyk-403"),
    ("12.1: CVEs reproduzidos", "o resultado de dois CVEs mais de uma semana", "o resultado de três CVEs mais de uma semana", "8.8-snyk-403"),
    ("9.9: limiar do critério", "qualquer limiar de 10 a 14 produziria", "qualquer limiar de 10 a 15 produziria", "9.9-leitura"),
    ("9.8: precisão do CodeQL no nível 3", "| 3 | CodeQL | 98 | 114 | 42 | 170 | 0 | 46,2% | 70,0%", "| 3 | CodeQL | 98 | 114 | 42 | 170 | 0 | 46,2% | 70,1%", "9.8-principal"),
    ("9.8: recall sobre os 220 do Semgrep", "24 contra 25 no Semgrep", "24 contra 26 no Semgrep", "9.8-recall-220"),
    ("9.8: precisão da sensibilidade do CodeQL", "de 70,0% para 70,6% no CodeQL", "de 70,0% para 70,7% no CodeQL", "9.8-sensibilidade"),
    ("9.8: FP por grupo do Semgrep", "| Semgrep | 9 | 4 |", "| Semgrep | 9 | 5 |", "9.8-grupo"),
    ("9.8: FN seguidos de FP no Snyk Code", "| Snyk Code | 22 | 18 | 4 | 190 | 2 |", "| Snyk Code | 22 | 18 | 4 | 190 | 3 |", "9.8-exploratoria"),
    ("9.8: reconhecidos no benchmark, Semgrep", "**11 de 24** no Semgrep", "**12 de 24** no Semgrep", "9.8-benchmark"),
    ("9.8: percentual inteiro da leitura", "4 de 22 no Snyk Code (18%)", "4 de 22 no Snyk Code (19%)", "9.8-leitura"),
    ("8.9: CVEs a um commit de distância", "a um commit de distância em 209", "a um commit de distância em 208", "8.9"),
    ("8.9: pares (CVE, ferramenta)", "Nos 660 pares (CVE, ferramenta)", "Nos 661 pares (CVE, ferramenta)", "8.9"),
    ("8.9: jobs", "Os 24 jobs terminaram com sucesso", "Os 23 jobs terminaram com sucesso", "8.9"),
    ("8.9: CVEs sem material analisável", "nos mesmos cinco CVEs da detecção", "nos mesmos seis CVEs da detecção", "8.9"),
    ("8.9: versão da imagem do runner", "`20260920.314.1` na versão corrigida", "`20260920.315.1` na versão corrigida", "8.9"),
    ("8.9: número de lotes", "**Execução.** Oito lotes", "**Execução.** Sete lotes", "8.9"),
    ("9.8: fechamento das células", "FP + VN + sem análise fecha em 212", "FP + VN + sem análise fecha em 211", "9.8-principal"),
]


def controle_positivo(doc, fontes):
    print("\nCONTROLE POSITIVO — uma célula adulterada por família\n")
    acusadas = 0
    for descricao, antigo, novo, alvo in MUTACOES:
        try:
            mutante = doc.com_troca(antigo, novo)
        except FalhaDeExtracao as exc:
            print(f"  NÃO APLICÁVEL  {descricao}: {exc}")
            continue
        # A família tem de estar limpa sem a mutação, e o mutante tem de
        # produzir divergência de valor, não falha de extração: sem isso, uma
        # família que já falha por extração "acusaria" qualquer mutante.
        base = [l for l in roda(doc, fontes, apenas={alvo}) if not l["ok"]]
        if base:
            print(f"  BASE SUJA      {descricao} → {alvo} ({len(base)} divergência(s) sem mutação)")
            continue
        linhas = roda(mutante, fontes, apenas={alvo})
        divergentes = [l for l in linhas if not l["ok"] and not l["falha"]]
        if any(l["falha"] for l in linhas):
            print(f"  FALHA          {descricao} → {alvo}: o mutante quebrou a extração")
        elif divergentes:
            acusadas += 1
            print(f"  ACUSADA        {descricao} → {alvo} ({len(divergentes)} divergência(s))")
        else:
            print(f"  NÃO ACUSADA    {descricao} → {alvo}")
    print(f"\n  {acusadas} de {len(MUTACOES)} mutações acusadas.")
    return acusadas == len(MUTACOES)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--texto", default="docs/metodologia-V10.md")
    ap.add_argument("--raiz", default=".")
    ap.add_argument("--controle-positivo", action="store_true")
    ap.add_argument("--apenas", nargs="*")
    args = ap.parse_args()

    fontes = Fontes(args.raiz)
    doc = Documento.de_arquivo(args.texto)
    linhas = roda(doc, fontes, set(args.apenas) if args.apenas else None)

    divergentes = [l for l in linhas if not l["ok"]]
    print(f"{len(linhas)} afirmações conferidas, {len(divergentes)} divergentes\n")
    for l in divergentes:
        marca = "FALHA DE EXTRACAO" if l["falha"] else "DIVERGENCIA"
        print(f"[{marca}] {l['id']} ({l['secao']}) — {l['rotulo']}")
        print(f"    texto : {l['esperado']}")
        print(f"    fonte : {l['obtido']}   ({l['fonte']})")
    por_familia = Counter(l["id"] for l in linhas)
    print("\nconferidas por família:")
    for ident, n in sorted(por_familia.items()):
        ruins = sum(1 for l in linhas if l["id"] == ident and not l["ok"])
        print(f"  {ident:28s} {n:4d}  divergentes: {ruins}")

    print("\nnão conferíveis a partir do repositório (declarados, não contados como falha):")
    for padrao, prefixo, motivo in NAO_CONFERIVEIS:
        try:
            doc.inline(prefixo, padrao)
            estado = "presente"
        except FalhaDeExtracao as exc:
            estado = f"extração: {exc}"
        print(f"  {prefixo.strip()} {padrao!r} — {motivo} [{estado}]")

    ok_controle = True
    if args.controle_positivo:
        ok_controle = controle_positivo(doc, fontes)

    return 0 if not divergentes and ok_controle else 1


if __name__ == "__main__":
    sys.exit(main())
