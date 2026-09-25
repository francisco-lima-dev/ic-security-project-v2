#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
distribuicao-cwe-primario.py — distribuicao do gt_cwe_primary nos 220 pares
do denominador. Propriedade do ground truth, NAO resultado de deteccao.

    python3 tools/distribuicao-cwe-primario.py [--lista ARQ] [--metadata ARQ]
                                               [--treated-root DIR] [--saida-dir DIR]

Existe para que o limiar k da decomposicao por categoria (V10, secao 9.9) seja
escolhido pelo formato desta distribuicao, antes de existir numero de deteccao
por categoria. Por isso NAO le a matriz de deteccao nem os agregados da
circularidade, e dos tratados le so o bloco `metadata` — nunca `findings`.

DEFINICOES REAPROVEITADAS, nao reimplementadas
  denominador      cruza-deteccao.carregar_gt(): a lista menos as tres
                   exclusoes nominadas (FORA_DO_DENOMINADOR), 220 pares
  gt_cwes          normalize.carregar_lista(), via carregar_gt()
  gt_cwe_primary   normalize.carregar_tabela_primario() + resolver_primario()
  forma do CWE     normalize.normalizar_cwe(), normalize.chave_canonica()

FONTES DO PRIMARIO, conferidas CVE a CVE — divergencia e parada
  codeql     results/codeql/treated/<CVE>.json, metadata.gt_cwe_primary
  semgrep    results/semgrep/treated/<CVE>.json, idem
  metadata   datasets/cve-metadata.csv (o benchmark, antes do gerador de
             listas), com a tabela aplicada pela funcao do normalize.py
  lista      datasets/listas/cves-sast.txt, com a mesma tabela (carregar_gt)
O Snyk Code nao e fonte: faltam-lhe os cinco SEM_ARQUIVO_ANALISAVEL.

SAIDAS — results/por-cwe/distribuicao-primario.{csv,txt}, e o texto em stdout.
Deterministicas: nenhum carimbo de execucao, toda ordenacao explicita.
Gravar em results/por-cwe/ exige todas as entradas dentro do repositorio.

ESCRITA — as duas saidas vao primeiro para nome temporario; o CSV temporario e
relido com o modulo csv (conferencia 6) e so entao os dois sao renomeados para
o nome definitivo. Reprovado, os temporarios sao removidos e a saida aprovada
anterior fica no lugar. A conferencia 6 tem controle positivo proprio, sobre
copias mutadas do arquivo gravado, e nao sobre a estrutura em memoria.

    python3 tools/distribuicao-cwe-primario.py --conferir-csv ARQ

roda so a conferencia 6 contra um CSV qualquer, com a estrutura em memoria
derivada das fontes, e nao grava nada.
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
CRUZA = RAIZ / "tools" / "cruza-deteccao.py"
NORMALIZE = RAIZ / "tools" / "normalize.py"

LISTA_PADRAO = RAIZ / "datasets" / "listas" / "cves-sast.txt"
METADATA_PADRAO = RAIZ / "datasets" / "cve-metadata.csv"
TREATED_ROOT_PADRAO = RAIZ / "results"
SAIDA_PADRAO = RAIZ / "results" / "por-cwe"
NOME_CSV = "distribuicao-primario.csv"
NOME_TXT = "distribuicao-primario.txt"

FONTES_TRATADO = ("codeql", "semgrep")
SEM_PRIMARIO = "SEM_PRIMARIO"
SEM_PRIMARIO_ESPERADO = ["CVE-2018-16472"]

# Excecoes documentadas do conjunto CWE-400|CWE-730 (CLAUDE.md, "Regra de
# fechamento"; evidencia da linha em datasets/cwe-primario.csv): injecao de
# expressao regular, nao ReDoS. Recebem o primario do grupo.
EXCECOES = {
    "CVE-2017-16023": "injecao de expressao regular, nao ReDoS",
    "CVE-2018-7560": "injecao de expressao regular, nao ReDoS",
}
CONJUNTO_DAS_EXCECOES = "CWE-400|CWE-730"
PRIMARIO_DAS_EXCECOES = "CWE-400"

# Controle contra numero publicado. Fonte: tabela "Composicao de CWE dos dois
# grupos" (herdado + nao herdado), CLAUDE.md, secao "Circularidade da
# proveniencia". Vem de documento: divergencia e parada, nunca ajuste.
TITULO_C6 = "conferencia 6 (arquivo gravado)"
# fullmatch e [0-9]: `$` aceitaria um \n final, e \d aceitaria digito Unicode.
_RE_ID_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_RE_CATEGORIA = re.compile(r"CWE-[0-9]{3,}")
COLUNAS_CSV = ["gt_cwe_primary", "n", "conjuntos_gt_cwes", "cves", "nota"]
PREFIXO_SHA_CSV = "csv desta execucao (sha256): "
PREFIXO_TEMP = ".tmp-"

PUBLICADOS = {
    "CWE-079": 47, "CWE-022": 29, "CWE-400": 26, "CWE-078": 25, "CWE-915": 23,
    "CWE-094": 14, "CWE-116": 9, "CWE-601": 7, "CWE-770": 4, "CWE-730": 3,
}


class Parada(Exception):
    def __init__(self, titulo, motivos):
        super().__init__(titulo)
        self.titulo = titulo
        self.motivos = list(motivos)


def rotulo(caminho):
    caminho = Path(caminho).resolve()
    try:
        return str(caminho.relative_to(RAIZ))
    except ValueError:
        return str(caminho)


def sha256_arquivo(caminho):
    return hashlib.sha256(Path(caminho).read_bytes()).hexdigest()


def sha256_conjunto(arquivos):
    """sha256 sobre (caminho relativo, sha256) de cada arquivo, em ordem."""
    h = hashlib.sha256()
    for caminho in sorted(arquivos, key=lambda p: rotulo(p)):
        h.update(("%s\0%s\n" % (rotulo(caminho), sha256_arquivo(caminho))).encode())
    return h.hexdigest()


def chave_segura(categoria):
    """chave_cwe para o que veio de arquivo: forma estranha ordena no fim."""
    if categoria == SEM_PRIMARIO or _RE_CATEGORIA.fullmatch(categoria or ""):
        return (0, chave_cwe(categoria))
    return (1, (0, 0), str(categoria))


def chave_cwe(cwe):
    """Ordem por numero, nao por cadeia: 'CWE-1321' vem depois de 'CWE-200'."""
    if cwe == SEM_PRIMARIO:
        return (1, 0)
    return (0, int(cwe.split("-", 1)[1]))


# ---------------------------------------------------------------------------
# Fontes
# ---------------------------------------------------------------------------
def primario_dos_tratados(raiz, ferramenta, denominador, norm):
    """{cve: (gt_cwe_primary, chave canonica de gt_cwes)} lido de metadata."""
    diretorio = Path(raiz) / ferramenta / "treated"
    fonte, motivos, arquivos = {}, [], []
    for cve in denominador:
        caminho = diretorio / ("%s.json" % cve)
        if not caminho.is_file():
            motivos.append("%s: %s sem tratado no denominador" % (ferramenta, cve))
            continue
        arquivos.append(caminho)
        try:
            with open(caminho, encoding="utf-8") as arquivo:
                metadata = json.load(arquivo)["metadata"]
            metadata["gt_cwe_primary"], metadata["gt_cwes"]
        except (OSError, ValueError, KeyError, TypeError) as erro:
            motivos.append("%s: %s ilegivel: %s: %s" % (ferramenta, cve, type(erro).__name__, erro))
            continue
        if metadata.get("schema_version") != norm.SCHEMA_VERSION:
            motivos.append("%s: %s schema %r, esperado %r" % (
                ferramenta, cve, metadata.get("schema_version"), norm.SCHEMA_VERSION))
        if metadata.get("cve_id") != cve:
            motivos.append("%s: %s com cve_id %r" % (ferramenta, caminho.name, metadata.get("cve_id")))
        fonte[cve] = (metadata["gt_cwe_primary"], norm.chave_canonica(metadata["gt_cwes"]))
    return fonte, motivos, arquivos


def primario_do_metadata(caminho, denominador, norm, tabela):
    """Aplica a tabela ao benchmark (cve-metadata.csv), pelas funcoes do normalize."""
    fonte, motivos, vistos = {}, [], set()
    relatorio = norm.relatorio_vazio("codeql")
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if not {"CVE", "CWEs"} <= set(leitor.fieldnames or []):
            return {}, ["metadata: cabecalho sem CVE e CWEs: %r" % leitor.fieldnames]
        for registro in leitor:
            cve = registro["CVE"]
            if cve in vistos:
                motivos.append("metadata: %s repetido" % cve)
            vistos.add(cve)
            cwes = []
            for bruto in registro["CWEs"].split(","):
                if not bruto.strip():
                    continue
                normalizado = norm.normalizar_cwe(bruto)
                if normalizado is None:
                    motivos.append("metadata: %s CWE irreconhecivel %r" % (cve, bruto))
                    continue
                if normalizado not in cwes:
                    cwes.append(normalizado)
            try:
                primario = norm.resolver_primario(cwes, tabela, relatorio, cve)
            except norm.FalhaCVE as erro:
                motivos.append("metadata: %s: %s" % (cve, erro))
                continue
            fonte[cve] = (primario, norm.chave_canonica(cwes))
    for cve in denominador:
        if cve not in fonte:
            motivos.append("metadata: %s do denominador ausente do benchmark" % cve)
    return {cve: fonte[cve] for cve in denominador if cve in fonte}, motivos


def primario_da_lista(gt, denominador, norm):
    return {cve: (gt[cve]["gt_cwe_primary"], norm.chave_canonica(gt[cve]["gt_cwes"]))
            for cve in denominador}


# ---------------------------------------------------------------------------
# Conferencias — funcoes puras, para que o controle positivo exerca as mesmas
# ---------------------------------------------------------------------------
def conferir_soma(atribuicao, esperado_total):
    """Conferencia 1. atribuicao: {cve: primario ou None}."""
    motivos = []
    if len(atribuicao) != esperado_total:
        motivos.append("soma %d, esperada %d" % (len(atribuicao), esperado_total))
    nulos = sorted(cve for cve, p in atribuicao.items() if p is None)
    if nulos != SEM_PRIMARIO_ESPERADO:
        motivos.append("%s = %s, esperado exatamente %s"
                       % (SEM_PRIMARIO, nulos or "nenhum", SEM_PRIMARIO_ESPERADO))
    return motivos


def conferir_fontes(fontes, denominador):
    """Conferencia 2. fontes: {nome: {cve: (primario, conjunto)}}.

    Toda divergencia e listada nominalmente, CVE a CVE; o conjunto gt_cwes
    tambem e comparado, porque e ele que vai para a tabela.
    """
    motivos = []
    nomes = sorted(fontes)
    for cve in denominador:
        valores = {nome: fontes[nome].get(cve, "AUSENTE") for nome in nomes}
        if len(set(map(repr, valores.values()))) != 1:
            motivos.append("%s: %s" % (cve, "; ".join(
                "%s=%s" % (nome, valores[nome]) for nome in nomes)))
    for nome in nomes:
        extras = sorted(set(fontes[nome]) - set(denominador))
        if extras:
            motivos.append("%s: CVEs fora do denominador: %s" % (nome, extras))
    return motivos


def conferir_publicados(contagem):
    """Conferencia 3."""
    return ["%s: saida %d, publicado %d" % (cwe, contagem.get(cwe, 0), n)
            for cwe, n in sorted(PUBLICADOS.items(), key=lambda i: chave_cwe(i[0]))
            if contagem.get(cwe, 0) != n]


def conferir_excecoes(atribuicao):
    motivos = []
    for cve in sorted(EXCECOES):
        if cve not in atribuicao:
            motivos.append("excecao %s fora do denominador" % cve)
        elif atribuicao[cve] != (PRIMARIO_DAS_EXCECOES, CONJUNTO_DAS_EXCECOES):
            motivos.append("excecao %s com %s, esperado %s de %s" % (
                cve, atribuicao[cve], PRIMARIO_DAS_EXCECOES, CONJUNTO_DAS_EXCECOES))
    return motivos


def conferir_arquivo(caminho, linhas, denominador):
    """Conferencia 6: rele o CSV gravado com o modulo csv.

    Cada motivo comeca pelo item (6.0 a 6.5) e nomeia a linha e o ID:
      6.0 forma: cabecalho, numero de campos, categoria CWE-<n> ou SEM_PRIMARIO
      6.1 todo ID da coluna cves casa CVE-<4 digitos>-<4+ digitos>, inteiro
      6.2 em cada linha, numero de IDs == n
      6.3 nenhum ID em duas linhas
      6.4 a uniao dos IDs e o denominador, como conjunto
      6.5 o conjunto de CVEs de cada categoria e o da estrutura em memoria
    """
    motivos = []
    esperado = {l["gt_cwe_primary"]: set(l["cves"]) for l in linhas}
    lido, onde = {}, {}
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != COLUNAS_CSV:
            # Sem o cabecalho esperado nenhuma coluna tem sentido: para aqui.
            return ["6.0 cabecalho %r, esperado %r" % (leitor.fieldnames, COLUNAS_CSV)]
        for numero, registro in enumerate(leitor, 2):
            categoria = registro["gt_cwe_primary"]
            rotulo_linha = "linha %d (%s)" % (numero, categoria)
            if None in registro or None in registro.values():
                motivos.append("6.0 %s: numero de campos diferente do cabecalho" % rotulo_linha)
                continue
            if categoria != SEM_PRIMARIO and not _RE_CATEGORIA.fullmatch(categoria):
                motivos.append("6.0 %s: categoria fora da forma CWE-<n>" % rotulo_linha)
            ids = registro["cves"].split("|") if registro["cves"] else []
            for cve in ids:
                if not _RE_ID_CVE.fullmatch(cve):
                    motivos.append("6.1 %s: ID malformado %r" % (rotulo_linha, cve))
            try:
                n = int(registro["n"])
            except ValueError:
                n = None
            if n != len(ids):
                motivos.append("6.2 %s: n = %s, %d IDs" % (rotulo_linha, registro["n"], len(ids)))
            for cve in ids:
                if cve in onde:
                    motivos.append("6.3 %s: ID %s ja esta em %s" % (rotulo_linha, cve, onde[cve]))
                else:
                    onde[cve] = rotulo_linha
            if categoria in lido:
                motivos.append("6.5 %s: categoria repetida" % rotulo_linha)
            lido[categoria] = set(ids)
    uniao = set(onde)
    for cve in sorted(uniao - set(denominador)):
        motivos.append("6.4 ID %s (%s) fora do denominador" % (cve, onde[cve]))
    for cve in sorted(set(denominador) - uniao):
        motivos.append("6.4 ID %s do denominador ausente do arquivo" % cve)
    for categoria in sorted(set(esperado) | set(lido), key=chave_segura):
        if lido.get(categoria) != esperado.get(categoria):
            a_mais = sorted(lido.get(categoria, set()) - esperado.get(categoria, set()))
            a_menos = sorted(esperado.get(categoria, set()) - lido.get(categoria, set()))
            motivos.append("6.5 categoria %s: no arquivo e nao na memoria %s; na memoria e "
                           "nao no arquivo %s" % (categoria, a_mais, a_menos))
    return motivos


def conferir_par(caminho_csv):
    """6.6: o .txt irmao, se existir, declara o sha256 deste CSV.

    Pega o par misto que dois renames nao atomicos podem deixar.
    """
    txt = Path(caminho_csv).with_name(NOME_TXT)
    if not txt.is_file():
        return []
    declarados = [linha[len("  " + PREFIXO_SHA_CSV):] for linha
                  in txt.read_text(encoding="utf-8").splitlines()
                  if linha.startswith("  " + PREFIXO_SHA_CSV)]
    atual = sha256_arquivo(caminho_csv)
    if declarados != [atual]:
        return ["6.6 par misto: %s declara %s, o CSV tem %s"
                % (txt.name, declarados or "nenhum sha256", atual)]
    return []


def mutantes_do_arquivo(texto_csv):
    """Um mutante por item da conferencia 6, como texto de CSV.

    Devolve [(nome, item pretendido, texto mutado)]. Os mutantes partem do
    texto gravado, e nao da estrutura em memoria.
    """
    cabecalho, *registros = list(csv.reader(io.StringIO(texto_csv)))
    i_cves, i_n = cabecalho.index("cves"), cabecalho.index("n")

    def serializar(regs):
        saida = io.StringIO()
        escritor = csv.writer(saida, lineterminator="\n")
        escritor.writerow(cabecalho)
        escritor.writerows(regs)
        return saida.getvalue()

    def copia():
        return [list(r) for r in registros]

    # Duas primeiras linhas: as categorias maiores, com n >= 2.
    a, b = 0, 1
    mutantes = []

    regs = copia(); ids = regs[a][i_cves].split("|")
    ids[0] = ids[0].replace("CVE-", "CVE--", 1)
    regs[a][i_cves] = "|".join(ids)
    mutantes.append(("ID corrompido", "6.1", serializar(regs)))

    regs = copia(); ids = regs[a][i_cves].split("|")
    regs[a][i_cves] = "|".join(ids[1:])
    mutantes.append(("ID removido, n mantido", "6.2", serializar(regs)))

    regs = copia(); ids_b = regs[b][i_cves].split("|")
    regs[b][i_cves] = "|".join(ids_b + [regs[a][i_cves].split("|")[0]])
    regs[b][i_n] = str(len(ids_b) + 1)
    mutantes.append(("ID duplicado em duas linhas", "6.3", serializar(regs)))

    regs = copia(); ids = regs[a][i_cves].split("|")
    regs[a][i_cves] = "|".join(ids + ["CVE-2016-1000229"])
    regs[a][i_n] = str(len(ids) + 1)
    mutantes.append(("ID fora do denominador", "6.4", serializar(regs)))

    regs = copia()
    ids_a, ids_b = regs[a][i_cves].split("|"), regs[b][i_cves].split("|")
    ids_a[0], ids_b[0] = ids_b[0], ids_a[0]
    regs[a][i_cves], regs[b][i_cves] = "|".join(ids_a), "|".join(ids_b)
    mutantes.append(("CVE trocado entre duas categorias", "6.5", serializar(regs)))

    # Correcoes da revisao, cada uma com mutante proprio.
    regs = copia(); ids = regs[a][i_cves].split("|")
    ids[0] = ids[0] + "\n"
    regs[a][i_cves] = "|".join(ids)
    mutantes.append(("ID com quebra de linha final", "6.1", serializar(regs)))

    cab = list(cabecalho); cab[i_cves] = "cve"
    saida = io.StringIO()
    escritor = csv.writer(saida, lineterminator="\n")
    escritor.writerow(cab)
    escritor.writerows(registros)
    mutantes.append(("cabecalho alterado", "6.0", saida.getvalue()))

    regs = copia(); regs[a][0] = "cwe79"
    mutantes.append(("categoria fora da forma", "6.0", serializar(regs)))

    regs = copia(); regs[a] = regs[a] + ["excedente"]
    mutantes.append(("campo excedente numa linha", "6.0", serializar(regs)))
    return mutantes


def controle_positivo_arquivo(texto_csv, linhas, denominador):
    """Grava cada mutante em arquivo e o rele pela conferencia 6.

    Um mutante passa quando dispara o item pretendido. Para a troca entre
    categorias exige-se ainda que 6.1 a 6.4 fiquem mudos: e o caso que so o
    item 5 pega. Devolve [(nome, item, disparou, itens que dispararam)].
    """
    resultados = []
    with tempfile.TemporaryDirectory(prefix="distribuicao-c6-") as diretorio:
        for indice, (nome, item, texto) in enumerate(mutantes_do_arquivo(texto_csv)):
            caminho = Path(diretorio) / ("mutante-%d.csv" % indice)
            caminho.write_text(texto, encoding="utf-8")
            itens = sorted({m.split(" ", 1)[0] for m in conferir_arquivo(caminho, linhas, denominador)})
            disparou = item in itens
            if item == "6.5":
                disparou = disparou and itens == ["6.5"]
            resultados.append((nome, item, disparou, itens))
    return resultados


# ---------------------------------------------------------------------------
# Distribuicao
# ---------------------------------------------------------------------------
def distribuir(atribuicao):
    """atribuicao: {cve: (primario, conjunto)} -> linhas ordenadas."""
    por_categoria = {}
    for cve, (primario, conjunto) in atribuicao.items():
        por_categoria.setdefault(primario or SEM_PRIMARIO, []).append((cve, conjunto))
    linhas = []
    for categoria, membros in por_categoria.items():
        conjuntos = {}
        for _, conjunto in membros:
            conjuntos[conjunto] = conjuntos.get(conjunto, 0) + 1
        excecoes = sorted(cve for cve, _ in membros if cve in EXCECOES)
        linhas.append({
            "gt_cwe_primary": categoria,
            "n": len(membros),
            "conjuntos": sorted(conjuntos.items(), key=lambda i: (-i[1], i[0])),
            "cves": sorted(cve for cve, _ in membros),
            "nota": ("excecoes documentadas do conjunto %s (%s): %s"
                     % (CONJUNTO_DAS_EXCECOES, EXCECOES[excecoes[0]], ", ".join(excecoes))
                     if excecoes else ""),
        })
    linhas.sort(key=lambda l: (-l["n"], chave_cwe(l["gt_cwe_primary"])))
    return linhas


def texto_conjuntos(conjuntos):
    return "; ".join("%s=%d" % (conjunto or "(vazio)", n) for conjunto, n in conjuntos)


def gerar_csv(linhas):
    saida = io.StringIO()
    escritor = csv.writer(saida, lineterminator="\n")
    escritor.writerow(("gt_cwe_primary", "n", "conjuntos_gt_cwes", "cves", "nota"))
    for l in linhas:
        escritor.writerow((l["gt_cwe_primary"], l["n"], texto_conjuntos(l["conjuntos"]),
                           "|".join(l["cves"]), l["nota"]))
    return saida.getvalue()


def resumo(linhas):
    com = [l for l in linhas if l["gt_cwe_primary"] != SEM_PRIMARIO]
    ns = [l["n"] for l in com]
    saltos = [a - b for a, b in zip(ns, ns[1:])]
    # Quantas categorias e quantos CVEs ficam em n >= t, para cada t distinto.
    patamares = []
    for t in sorted(set(ns), reverse=True):
        dentro = [n for n in ns if n >= t]
        patamares.append((t, sum(1 for n in ns if n == t), len(dentro), sum(dentro)))
    return {
        "categorias_com_sem_primario": len(linhas),
        "categorias_sem_sem_primario": len(com),
        "soma_n": sum(l["n"] for l in linhas),
        "soma_n_com_primario": sum(ns),
        "ns": ns,
        "saltos": saltos,
        "patamares": patamares,
    }


def gerar_txt(linhas, res, fontes_desc, conferencias, sha_csv):
    out = []
    w = out.append
    w("Distribuicao de gt_cwe_primary no denominador (220 pares)")
    w("Propriedade do ground truth; nenhuma deteccao lida ou computada.")
    w("")
    w("  " + PREFIXO_SHA_CSV + sha_csv)
    w("")
    w("Fontes (caminho relativo ao repositorio, sha256):")
    for nome, caminho, digest in fontes_desc:
        w("  %-10s %s  %s" % (nome, caminho, digest))
    w("")
    w("Conferencias:")
    for nome, estado in conferencias:
        w("  %-66s %s" % (nome, estado))
    w("")
    w("Alcance das conferencias:")
    w("  1 a soma 220 e verdadeira por construcao: carregar_gt ja para se o")
    w("    denominador nao tiver 220. O que 1 mede e o SEM_PRIMARIO.")
    w("  2 'CVE fora do denominador' e verdadeiro por construcao: as fontes sao")
    w("    lidas so para os CVEs do denominador. 2 pega entrada divergente e")
    w("    tratado desatualizado, mas NAO erro na tabela de primario: as quatro")
    w("    fontes a aplicam pela mesma funcao. Contra a tabela, a unica prova")
    w("    independente e 3, que cobre 10 categorias e 187 dos 220 CVEs.")
    w("")
    w("Tabela (n decrescente; empate por numero do CWE; %s por ultimo no empate):" % SEM_PRIMARIO)
    w("")
    w("  %-13s %4s  %s" % ("gt_cwe_primary", "n", "conjuntos_gt_cwes"))
    for l in linhas:
        w("  %-13s %4d  %s" % (l["gt_cwe_primary"], l["n"], texto_conjuntos(l["conjuntos"])))
        if l["nota"]:
            w("  %-13s %4s  nota: %s" % ("", "", l["nota"]))
    w("")
    w("CVEs por categoria:")
    for l in linhas:
        w("  %s (%d): %s" % (l["gt_cwe_primary"], l["n"], "|".join(l["cves"])))
    w("")
    w("Resumo:")
    w("  categorias distintas, com %s: %d" % (SEM_PRIMARIO, res["categorias_com_sem_primario"]))
    w("  categorias distintas, sem %s: %d" % (SEM_PRIMARIO, res["categorias_sem_sem_primario"]))
    w("  soma de n: %d (com primario: %d)" % (res["soma_n"], res["soma_n_com_primario"]))
    w("  n em ordem (sem %s): %s" % (SEM_PRIMARIO, " ".join(map(str, res["ns"]))))
    w("  saltos n_i - n_(i+1): %s" % " ".join(map(str, res["saltos"])))
    w("")
    w("  Patamares (sem %s): para cada n distinto t, categorias com n == t,"
      % SEM_PRIMARIO)
    w("  categorias com n >= t e CVEs cobertos por elas:")
    w("  %5s %8s %9s %8s" % ("t", "n == t", "n >= t", "CVEs"))
    for t, igual, cats, cves in res["patamares"]:
        w("  %5d %8d %9d %8d" % (t, igual, cats, cves))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Controle positivo (conferencias 1, 2 e 3)
# ---------------------------------------------------------------------------
def controle_positivo(fontes, denominador):
    """Cada mutante tem de disparar a conferencia pretendida, citando o CVE."""
    base = fontes["lista"]
    alvo_079 = next((c for c in denominador if base[c][0] == "CWE-079"), None)
    if alvo_079 is None:
        raise Parada("controle positivo sem alvo", ["nenhum CVE com primario CWE-079"])
    resultados = []

    def registra(nome, motivos, marca):
        disparou = bool(motivos) and any(marca in m for m in motivos)
        resultados.append((nome, disparou, motivos[:2]))

    # A linha de base sem mutacao sao as proprias conferencias reais, que rodam
    # depois e param com o proprio titulo; aqui so os mutantes.
    atrib = {c: p for c, (p, _) in base.items()}

    # Conferencia 1
    m = dict(atrib); del m[alvo_079]
    registra("c1: CVE removido (soma 219)", conferir_soma(m, len(denominador)), "soma 219")
    m = dict(atrib); m["CVE-2018-16472"] = "CWE-400"
    registra("c1: CVE-2018-16472 recebe primario", conferir_soma(m, len(denominador)), "nenhum")
    m = dict(atrib); m[alvo_079] = None
    registra("c1: segundo CVE em %s" % SEM_PRIMARIO, conferir_soma(m, len(denominador)), alvo_079)

    # Conferencia 2 — primario alterado numa fonte de cada vez
    for nome in sorted(fontes):
        mut = copy.deepcopy(fontes)
        primario, conjunto = mut[nome][alvo_079]
        mut[nome][alvo_079] = ("CWE-022", conjunto)
        registra("c2: primario alterado em %s" % nome, conferir_fontes(mut, denominador), alvo_079)
    mut = copy.deepcopy(fontes); del mut["semgrep"][alvo_079]
    registra("c2: CVE ausente de semgrep", conferir_fontes(mut, denominador), alvo_079)
    mut = copy.deepcopy(fontes)
    mut["codeql"][alvo_079] = (mut["codeql"][alvo_079][0], "CWE-079")
    registra("c2: conjunto alterado em codeql", conferir_fontes(mut, denominador), alvo_079)

    # Conferencia 3 — CVE trocado de categoria em todas as fontes
    mut = dict(base); mut[alvo_079] = ("CWE-022", base[alvo_079][1])
    registra("c3: CVE trocado de CWE-079 para CWE-022", conferir_publicados(contar(mut)), "CWE-079")

    # Excecoes documentadas
    mut = dict(base); mut["CVE-2018-7560"] = ("CWE-400", "CWE-400")
    registra("cx: excecao com conjunto alterado", conferir_excecoes(mut), "CVE-2018-7560")

    # Guarda de entrada fora do repositorio (revisao, riscos 1 e 2)
    fora_raiz = Path(tempfile.gettempdir()).resolve() / "entrada-externa"
    registra("guarda: saida versionada fora de por-cwe, entrada externa",
             entradas_fora(RAIZ / "results" / "cruzamento", [LISTA_PADRAO, fora_raiz]),
             "entrada-externa")
    registra("guarda: diretorio de tratado de uma ferramenta externo",
             entradas_fora(SAIDA_PADRAO, [TREATED_ROOT_PADRAO, fora_raiz / "codeql" / "treated"]),
             "entrada-externa")
    return alvo_079, resultados


def entradas_fora(saida, entradas):
    """Entradas fora do repositorio, quando a saida esta DENTRO dele.

    Qualquer saida dentro da arvore pode ir ao versionamento, nao so
    results/por-cwe/ (revisao, risco 1). Cada entrada e resolvida por inteiro,
    symlink incluso, e a lista inclui o diretorio de tratado de cada
    ferramenta, e nao so a raiz (risco 2).
    """
    if not Path(saida).resolve().is_relative_to(RAIZ):
        return []
    return [str(c) for c in entradas if not Path(c).resolve().is_relative_to(RAIZ)]


def contar(atribuicao):
    contagem = {}
    for primario, _ in atribuicao.values():
        chave = primario or SEM_PRIMARIO
        contagem[chave] = contagem.get(chave, 0) + 1
    return contagem


# ---------------------------------------------------------------------------
def executar(args):
    lista = Path(args.lista) if args.lista else LISTA_PADRAO
    metadata = Path(args.metadata) if args.metadata else METADATA_PADRAO
    raiz_tratados = Path(args.treated_root) if args.treated_root else TREATED_ROOT_PADRAO
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO

    spec = importlib.util.spec_from_file_location("cruza_deteccao", CRUZA)
    cruza_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cruza_mod)
    norm = cruza_mod.importar("normalize", NORMALIZE)
    tabela_caminho = norm.TABELA_PRIMARIO

    entradas = [lista, metadata, raiz_tratados, tabela_caminho] + [
        Path(raiz_tratados) / f / "treated" for f in FONTES_TRATADO]
    fora = entradas_fora(saida, entradas)
    if fora:
        raise Parada("saida dentro do repositorio exige entradas dentro dele: "
                     "o caminho de fora iria para o .txt", fora)

    try:
        gt, denominador, _ = cruza_mod.carregar_gt(norm, lista)
    except cruza_mod.Parada as p:
        raise Parada("cruza-deteccao.carregar_gt: " + p.titulo, p.motivos)
    try:
        tabela = norm.carregar_tabela_primario(tabela_caminho)
    except SystemExit as erro:
        raise Parada("tabela de primario ilegivel", [str(erro.code)])

    fontes, motivos, arquivos = {"lista": primario_da_lista(gt, denominador, norm)}, [], {}
    for ferramenta in FONTES_TRATADO:
        fonte, m, arqs = primario_dos_tratados(raiz_tratados, ferramenta, denominador, norm)
        fontes[ferramenta], arquivos[ferramenta] = fonte, arqs
        motivos += m
    fontes["metadata"], m = primario_do_metadata(metadata, denominador, norm, tabela)
    motivos += m
    if motivos:
        raise Parada("fontes ilegiveis ou incompletas", motivos)

    # Controle positivo antes das conferencias reais: se o metodo nao acusa o
    # que foi plantado, o zero das conferencias nao vale como resultado.
    alvo, controle = controle_positivo(fontes, denominador)
    falhas = ["%s: nao disparou (%s)" % (nome, amostra)
              for nome, disparou, amostra in controle if not disparou]
    if falhas:
        raise Parada("controle positivo falhou", falhas)

    base = fontes["lista"]
    c1 = conferir_soma({c: p for c, (p, _) in base.items()}, cruza_mod.PARES_NO_DENOMINADOR)
    c2 = conferir_fontes(fontes, denominador)
    c3 = conferir_publicados(contar(base))
    cx = conferir_excecoes(base)
    for titulo, m in (("conferencia 1 (soma e SEM_PRIMARIO)", c1),
                      ("conferencia 2 (fontes independentes)", c2),
                      ("conferencia 3 (numeros publicados)", c3),
                      ("excecoes documentadas", cx)):
        if m:
            raise Parada(titulo, m)

    linhas = distribuir(base)
    res = resumo(linhas)
    fontes_desc = [
        ("lista", rotulo(lista), sha256_arquivo(lista)),
        ("tabela", rotulo(tabela_caminho), sha256_arquivo(tabela_caminho)),
        ("metadata", rotulo(metadata), sha256_arquivo(metadata)),
    ] + [("%s" % f, rotulo(Path(raiz_tratados) / f / "treated") + "/ (%d, conjunto)"
          % len(arquivos[f]), sha256_conjunto(arquivos[f])) for f in FONTES_TRATADO] + [
        ("codigo", rotulo(Path(__file__)), sha256_arquivo(__file__)),
        ("codigo", rotulo(CRUZA), sha256_arquivo(CRUZA)),
        ("codigo", rotulo(NORMALIZE), sha256_arquivo(NORMALIZE)),
    ]
    conferencias = [
        ("1 soma = 220, SEM_PRIMARIO = {CVE-2018-16472}", "OK"),
        ("2 lista = codeql = semgrep = metadata, CVE a CVE (%d)" % len(denominador), "OK, 0 divergencias"),
        ("3 contagens publicadas (%d categorias)" % len(PUBLICADOS), "OK"),
        ("  excecoes CVE-2017-16023, CVE-2018-7560 em CWE-400", "OK"),
        ("4 controle positivo (%d mutantes, alvo %s)" % (len(controle), alvo),
         "OK, todos dispararam"),
    ]
    for nome, _, _ in controle:
        conferencias.append(("    " + nome, "disparou"))

    tabela_csv = gerar_csv(linhas)

    # O controle da conferencia 6 roda sobre o texto que vai ser gravado,
    # mutado e gravado em arquivo, antes de qualquer uso da conferencia —
    # inclusive no --conferir-csv (revisao, risco 5).
    controle_c6 = controle_positivo_arquivo(tabela_csv, linhas, denominador)
    falhas = ["%s: esperado %s, dispararam %s" % (nome, item, itens or "nenhum")
              for nome, item, disparou, itens in controle_c6 if not disparou]
    if falhas:
        raise Parada("controle positivo da " + TITULO_C6 + " falhou", falhas)

    if args.conferir_csv:
        alvo_csv = Path(args.conferir_csv)
        m = conferir_arquivo(alvo_csv, linhas, denominador) + conferir_par(alvo_csv)
        if m:
            raise Parada(TITULO_C6, m)
        print("%s: OK, %s (controle positivo: %d mutantes no arquivo, todos pelo item "
              "pretendido)" % (TITULO_C6, args.conferir_csv, len(controle_c6)))
        return 0

    conferencias.append(("6 CSV gravado relido (publicado so se aprovado)", "OK"))
    conferencias.append(("  controle positivo no arquivo (%d mutantes)" % len(controle_c6),
                         "OK, cada um pelo item pretendido"))
    for nome, item, _, itens in controle_c6:
        conferencias.append(("    %s: %s" % (item, nome), "disparou %s" % ",".join(itens)))

    texto = gerar_txt(linhas, res, fontes_desc, conferencias,
                      hashlib.sha256(tabela_csv.encode("utf-8")).hexdigest())
    saida.mkdir(parents=True, exist_ok=True)
    temporarios = {nome: saida / (PREFIXO_TEMP + nome) for nome in (NOME_CSV, NOME_TXT)}
    # Residuo de execucao interrompida sai antes de escrever.
    for temporario in temporarios.values():
        temporario.unlink(missing_ok=True)
    try:
        temporarios[NOME_CSV].write_text(tabela_csv, encoding="utf-8")
        temporarios[NOME_TXT].write_text(texto, encoding="utf-8")
        m = conferir_arquivo(temporarios[NOME_CSV], linhas, denominador)
        if m:
            raise Parada(TITULO_C6, m)
        # Dois renames nao sao atomicos como par (revisao, risco 3). Falha
        # entre eles deixa CSV novo com .txt anterior: e nomeada aqui, e o
        # sha256 do CSV gravado no .txt torna o par misto detectavel depois,
        # pelo --conferir-csv (item 6.6).
        temporarios[NOME_CSV].replace(saida / NOME_CSV)
        try:
            temporarios[NOME_TXT].replace(saida / NOME_TXT)
        except OSError as erro:
            raise Parada("promocao incompleta: CSV novo gravado, .txt anterior no lugar",
                         ["%s: %s" % (type(erro).__name__, erro)])
    finally:
        # Reprovado ou interrompido: nenhum temporario fica. Falha de remocao
        # e avisada, sem mascarar a excecao original.
        for temporario in temporarios.values():
            try:
                temporario.unlink(missing_ok=True)
            except OSError as erro:
                print("AVISO: temporario nao removido: %s: %s" % (temporario, erro),
                      file=sys.stderr)
    sys.stdout.write(texto)
    return 0


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Distribuicao de gt_cwe_primary nos 220 pares do denominador.")
    analisador.add_argument("--lista", help="padrao: datasets/listas/cves-sast.txt")
    analisador.add_argument("--metadata", help="padrao: datasets/cve-metadata.csv")
    analisador.add_argument("--treated-root", help="padrao: results/")
    analisador.add_argument("--saida-dir", help="padrao: results/por-cwe/")
    analisador.add_argument("--conferir-csv",
                            help="roda so a conferencia 6 contra este CSV; nao grava nada")
    args = analisador.parse_args(argv)
    try:
        return executar(args)
    except Parada as parada:
        print("\nPARADO: %s. Nenhuma saida escrita." % parada.titulo, file=sys.stderr)
        for motivo in parada.motivos:
            print("  - %s" % motivo, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
