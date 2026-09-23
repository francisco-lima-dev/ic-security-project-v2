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
import csv
import json
import pathlib
import re
import statistics
import sys
from collections import Counter, defaultdict

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
        linhas = roda(mutante, fontes, apenas={alvo})
        divergentes = [l for l in linhas if not l["ok"]]
        if divergentes:
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

    ok_controle = True
    if args.controle_positivo:
        ok_controle = controle_positivo(doc, fontes)

    return 0 if not divergentes and ok_controle else 1


if __name__ == "__main__":
    sys.exit(main())
