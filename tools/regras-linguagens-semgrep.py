#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
regras-linguagens-semgrep.py — tabela regra -> linguagens do pack vendorizado
do Semgrep, base do criterio "pela linguagem da regra" da secao 10 de
docs/criterios-cruzamento.md.

    python3 tools/regras-linguagens-semgrep.py [--pack ARQ] [--descritor ARQ]
                                               [--saida-dir DIR]

NAO CONTA ACHADO ALGUM. Le so o pack; nenhum tratado e aberto.

PARSER — o YAML e lido por ruamel.yaml DENTRO da imagem do Semgrep da campanha,
referenciada pelo digest vigente (IMAGEM), sem rede, com o pack montado so para
leitura. O ambiente local nao tem parser YAML, e contar o pack com grep ou regex
ja produziu dois numeros errados (CLAUDE.md, "Regra geral de contagem"). O
container so faz o parse e devolve, em JSON, o `id` e o `languages` de cada
regra com o tipo preservado; toda conferencia roda aqui, no hospedeiro. A
linguagem nunca e tirada do prefixo do check_id: prefixo e convencao de nome,
nao declaracao.

SAIDAS — results/capacidade/regras-linguagens.{csv,txt}, e o texto em stdout.
Deterministicas, sem carimbo de execucao. Escrita atomica com releitura do CSV
antes da promocao, e guarda de entrada fora do repositorio, reaproveitadas do
distribuicao-cwe-primario.py.
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
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

RAIZ = Path(__file__).resolve().parent.parent
DISTRIBUICAO_PY = RAIZ / "tools" / "distribuicao-cwe-primario.py"

PACK_PADRAO = RAIZ / "ic-security-lab-semgrep" / "rules" / "semgrep-default.yaml"
DESCRITOR_PADRAO = RAIZ / "ic-security-lab-semgrep" / "rules" / "semgrep-default.meta.json"
SAIDA_PADRAO = RAIZ / "results" / "capacidade"
NOME_CSV = "regras-linguagens.csv"
NOME_TXT = "regras-linguagens.txt"
PREFIXO_TEMP = ".tmp-"
PREFIXO_SHA_CSV = "csv desta execucao (sha256): "

# Digest vigente da imagem do Semgrep (CLAUDE.md, "Imagens da campanha —
# digests publicados", rebuild de H0c, 15/09/2026).
IMAGEM = ("ghcr.io/francisco-lima-dev/ic-security-lab-semgrep@sha256:"
          "de71bdfbdf81d495781a4c80052c5f7d128ec9b76eba2304978e08b88ba5d000")
PACK_NO_CONTAINER = "/pack/semgrep-default.yaml"

COLUNAS_CSV = ["check_id", "languages", "js_ts"]
LINGUAGENS_JS_TS = ("javascript", "js", "typescript", "ts")
DESTACADAS = ("generic", "regex")

# Numeros de documento (CLAUDE.md, secao do Semgrep; descritor do pack).
REGRAS_TOTAL = 1074
REGRAS_JS_TS = 163
COMPOSICAO_JS_TS = {"javascript": 152, "js": 1, "typescript": 150, "ts": 5}

# Executado dentro da imagem. So parse: nenhuma decisao aqui.
EXTRATOR = r'''
import json, sys
import ruamel.yaml
yaml = ruamel.yaml.YAML(typ="safe", pure=True)
with open(sys.argv[1], encoding="utf-8") as f:
    dados = yaml.load(f)
regras = []
for r in dados["rules"]:
    if "languages" not in r:
        lang = {"ausente": True}
    elif isinstance(r["languages"], list):
        lang = {"lista": [str(x) for x in r["languages"]],
                "tipos": [type(x).__name__ for x in r["languages"]]}
    else:
        lang = {"outro_tipo": type(r["languages"]).__name__, "valor": str(r["languages"])}
    regras.append({"id": r.get("id"), "languages": lang})
json.dump({"parser": "ruamel.yaml " + ruamel.yaml.__version__,
           "python": sys.version.split()[0],
           "chave_topo": sorted(dados.keys()),
           "regras": regras}, sys.stdout)
'''


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
# Extracao (container)
# ---------------------------------------------------------------------------
def conferir_montavel(pack):
    """3m: o `docker -v origem:destino:ro` separa por ':'; caminho com ':' ou
    ',' nao monta, ou monta outra coisa. Recusado antes de invocar."""
    caminho = str(Path(pack).resolve())
    if ":" in caminho or "," in caminho:
        return ["3m caminho do pack com ':' ou ',' nao e montavel por -v: %s" % caminho]
    return []


def extrair(pack):
    comando = ["docker", "run", "--rm", "--network=none",
               "--user", "%d:%d" % (os.getuid(), os.getgid()),
               "-e", "HOME=/tmp", "-e", "XDG_CACHE_HOME=/tmp",
               "-v", "%s:%s:ro" % (Path(pack).resolve(), PACK_NO_CONTAINER),
               "--entrypoint", "python3", IMAGEM, "-c", EXTRATOR, PACK_NO_CONTAINER]
    try:
        processo = subprocess.run(comando, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except OSError as erro:
        raise Parada("docker indisponivel", ["%s: %s" % (type(erro).__name__, erro)])
    if processo.returncode != 0:
        # O stderr do container vai inteiro para o motivo: nunca descartado.
        raise Parada("extracao no container falhou (rc %d)" % processo.returncode,
                     processo.stderr.strip().splitlines() or ["stderr vazio"])
    if processo.stderr.strip():
        print(processo.stderr, file=sys.stderr, end="")
    try:
        return json.loads(processo.stdout)
    except ValueError as erro:
        raise Parada("saida do container nao e JSON", ["%s" % erro])


YAML_CONTROLE = """rules:
- id: controle.lista
  languages: [javascript, TS]
- id: controle.cadeia
  languages: javascript
- id: controle.nulo
  languages: [javascript, null]
- id: controle.ausente
  message: sem languages
"""
YAML_DUPLICADA = """rules:
- id: controle.dup
  id: controle.dup2
  languages: [python]
"""


def controle_extrator():
    """Passa YAML mutante pelo extrair() de verdade, no container: o
    isinstance do extrator tem de classificar cada forma, e chave duplicada
    tem de falhar ruidosamente. Devolve [(nome, ok, detalhe)]."""
    resultados = []
    with tempfile.TemporaryDirectory(prefix="regras-extrator-") as diretorio:
        caminho = Path(diretorio) / "controle.yaml"
        caminho.write_text(YAML_CONTROLE, encoding="utf-8")
        os.chmod(diretorio, 0o755)
        os.chmod(caminho, 0o644)
        regras = {r["id"]: r for r in extrair(caminho)["regras"]}
        esperado = {
            "controle.lista": {"lista": ["javascript", "TS"], "tipos": ["str", "str"]},
            "controle.cadeia": {"outro_tipo": "str", "valor": "javascript"},
            "controle.nulo": {"lista": ["javascript", "None"], "tipos": ["str", "NoneType"]},
            "controle.ausente": {"ausente": True},
        }
        for rid, forma in sorted(esperado.items()):
            obtido = regras.get(rid, {}).get("languages")
            resultados.append(("extrator: %s" % rid, obtido == forma, obtido))
        disparou = sorted({m.split(" ", 1)[0] for m in conferir_forma_languages(list(regras.values()))})
        resultados.append(("extrator: conferencia 4 sobre o YAML mutante", disparou == ["4"], disparou))
        caminho.write_text(YAML_DUPLICADA, encoding="utf-8")
        try:
            extrair(caminho)
            resultados.append(("extrator: chave duplicada falha", False, "aceita em silencio"))
        except Parada as parada:
            erro = next((m for m in parada.motivos if "Error" in m), parada.titulo)
            resultados.append(("extrator: chave duplicada falha", True, erro.strip()[:60]))
    return resultados


# ---------------------------------------------------------------------------
# Tabela
# ---------------------------------------------------------------------------
def linguagens(regra):
    """Lista normalizada (minusculas, sem repeticao, ordenada), ou None."""
    lang = regra["languages"]
    if set(lang) != {"lista", "tipos"} or any(t != "str" for t in lang["tipos"]):
        return None
    return sorted({x.lower() for x in lang["lista"]})


def montar_linhas(regras):
    linhas = []
    for regra in sorted(regras, key=lambda r: str(r["id"])):
        langs = linguagens(regra) or []
        linhas.append({"check_id": regra["id"], "languages": "|".join(langs),
                       "js_ts": "sim" if set(langs) & set(LINGUAGENS_JS_TS) else "nao"})
    return linhas


def rules_id_sha256(ids):
    """Metodo do descritor: check_id ordenados, um por linha, com \\n final."""
    return hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Conferencias
# ---------------------------------------------------------------------------
def conferir_total(regras):
    """1: 1074 regras e 1074 check_id distintos, todos cadeia nao vazia."""
    motivos = []
    ids = [r["id"] for r in regras]
    if len(regras) != REGRAS_TOTAL:
        motivos.append("1 %d regras, esperadas %d" % (len(regras), REGRAS_TOTAL))
    if any(not isinstance(i, str) or not i for i in ids):
        motivos.append("1 regra sem id em cadeia")
    distintos = {i for i in ids if isinstance(i, str)}
    if len(distintos) != REGRAS_TOTAL:
        motivos.append("1 %d check_id distintos, esperados %d" % (len(distintos), REGRAS_TOTAL))
    repetidos = sorted({i for i in distintos if ids.count(i) > 1})
    if repetidos:
        motivos.append("1 check_id repetidos: %s" % repetidos)
    return motivos


def contar_js_ts(regras):
    composicao = {l: 0 for l in LINGUAGENS_JS_TS}
    uniao = 0
    for regra in regras:
        langs = set(linguagens(regra) or [])
        for l in LINGUAGENS_JS_TS:
            composicao[l] += l in langs
        uniao += bool(langs & set(LINGUAGENS_JS_TS))
    return composicao, uniao


def conferir_js_ts(regras):
    """2: as quatro grafias e a uniao, contra o CLAUDE.md e o descritor."""
    motivos = []
    composicao, uniao = contar_js_ts(regras)
    for l in LINGUAGENS_JS_TS:
        if composicao[l] != COMPOSICAO_JS_TS[l]:
            motivos.append("2 %s: %d regras, registrado %d" % (l, composicao[l], COMPOSICAO_JS_TS[l]))
    if uniao != REGRAS_JS_TS:
        motivos.append("2 uniao JS/TS: %d regras, registrado %d" % (uniao, REGRAS_JS_TS))
    return motivos


def conferir_identidade(sha_pack, ids, descritor):
    """3: sha256 do arquivo e rules_id_sha256 iguais aos do descritor."""
    motivos = []
    if sha_pack != descritor.get("sha256"):
        motivos.append("3 pack com sha256 %s, descritor %s" % (sha_pack, descritor.get("sha256")))
    calculado = rules_id_sha256([i for i in ids if isinstance(i, str)])
    if calculado != descritor.get("rules_id_sha256"):
        motivos.append("3 rules_id_sha256 %s, descritor %s" % (calculado, descritor.get("rules_id_sha256")))
    if descritor.get("rules_total") != REGRAS_TOTAL or descritor.get("rules_js_ts") != REGRAS_JS_TS:
        motivos.append("3 descritor declara rules_total %r e rules_js_ts %r"
                       % (descritor.get("rules_total"), descritor.get("rules_js_ts")))
    return motivos


def conferir_forma_languages(regras):
    """4: toda regra tem languages, e ele e lista de cadeias nao vazias."""
    motivos = []
    for regra in sorted(regras, key=lambda r: str(r["id"])):
        lang = regra["languages"]
        if lang.get("ausente"):
            motivos.append("4 %s sem languages" % regra["id"])
        elif "outro_tipo" in lang:
            motivos.append("4 %s: languages e %s (%r), nao lista"
                           % (regra["id"], lang["outro_tipo"], lang["valor"]))
        elif not lang["lista"] or any(not x for x in lang["lista"]):
            motivos.append("4 %s: languages vazio ou com elemento vazio" % regra["id"])
        elif any(t != "str" for t in lang.get("tipos", [None])):
            motivos.append("4 %s: languages com elemento que nao e cadeia: %s"
                           % (regra["id"], lang.get("tipos")))
    return motivos


def conferir_arquivo(caminho, linhas):
    """5: releitura do CSV gravado."""
    motivos = []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != COLUNAS_CSV:
            return ["5 cabecalho %r, esperado %r" % (leitor.fieldnames, COLUNAS_CSV)]
        lidas = list(leitor)
    for numero, registro in enumerate(lidas, 2):
        if None in registro or None in registro.values():
            motivos.append("5 linha %d: numero de campos diferente de 3" % numero)
        elif registro["js_ts"] not in ("sim", "nao"):
            motivos.append("5 linha %d: js_ts %r" % (numero, registro["js_ts"]))
    if len(lidas) != REGRAS_TOTAL:
        motivos.append("5 %d linhas, esperadas %d" % (len(lidas), REGRAS_TOTAL))
    for numero, (lido, memoria) in enumerate(zip(lidas, linhas), 2):
        for coluna in COLUNAS_CSV:
            if lido.get(coluna) != memoria[coluna]:
                motivos.append("5 linha %d coluna %s: arquivo %r, memoria %r"
                               % (numero, coluna, lido.get(coluna), memoria[coluna]))
    return motivos


def gerar_csv(linhas):
    saida = io.StringIO()
    escritor = csv.DictWriter(saida, fieldnames=COLUNAS_CSV, lineterminator="\n")
    escritor.writeheader()
    escritor.writerows(linhas)
    return saida.getvalue()


# ---------------------------------------------------------------------------
# Controle positivo (6)
# ---------------------------------------------------------------------------
def controle_positivo(regras, sha_pack, descritor, linhas):
    resultados = []

    def itens(motivos):
        return sorted({m.split(" ", 1)[0] for m in motivos})

    def rodar(m_regras=regras, m_sha=sha_pack, m_desc=descritor):
        return itens(conferir_total(m_regras) + conferir_js_ts(m_regras)
                     + conferir_identidade(m_sha, [r["id"] for r in m_regras], m_desc)
                     + conferir_forma_languages(m_regras))

    def registra(nome, pretendida, disparadas, exato=False):
        ok = disparadas == [pretendida] if exato else pretendida in disparadas
        resultados.append((nome, pretendida, ok, disparadas))

    por_id = sorted(regras, key=lambda r: str(r["id"]))
    python_so = next((r for r in por_id if linguagens(r) == ["python"]), None)
    so_js = next((r for r in por_id if linguagens(r) == ["javascript"]), None)
    so_ts = next((r for r in por_id if linguagens(r) == ["ts"]), None)
    if python_so is None or so_js is None or so_ts is None:
        raise Parada("controle positivo sem candidato", ["regra so python, so javascript ou so ts"])

    # 1
    m = copy.deepcopy(regras); m.append(copy.deepcopy(python_so))
    registra("1: check_id repetido", "1", rodar(m_regras=m))
    m = [r for r in regras if r["id"] != python_so["id"]]
    registra("1: regra removida", "1", rodar(m_regras=m))
    # 2 — uma regra so javascript passa a ser so python (uniao e javascript caem)
    m = copy.deepcopy(regras)
    next(r for r in m if r["id"] == so_js["id"])["languages"] = {"lista": ["python"], "tipos": ["str"]}
    registra("2: regra javascript vira python", "2", rodar(m_regras=m), exato=True)
    # 2 — grafia: 'ts' vira 'typescript' (uniao igual, composicao nao)
    m = copy.deepcopy(regras)
    next(r for r in m if r["id"] == so_ts["id"])["languages"] = {"lista": ["typescript"], "tipos": ["str"]}
    registra("2: grafia ts trocada por typescript, uniao mantida", "2", rodar(m_regras=m), exato=True)
    # 3
    registra("3: sha256 do pack diferente do descritor", "3", rodar(m_sha="0" * 64), exato=True)
    m = copy.deepcopy(regras)
    next(r for r in m if r["id"] == python_so["id"])["id"] = python_so["id"] + ".x"
    registra("3: check_id alterado (rules_id_sha256)", "3", rodar(m_regras=m), exato=True)
    # 4
    m = copy.deepcopy(regras)
    next(r for r in m if r["id"] == so_js["id"])["languages"] = {"outro_tipo": "str", "valor": "javascript"}
    registra("4: languages como cadeia nua", "4", rodar(m_regras=m))
    m = copy.deepcopy(regras)
    next(r for r in m if r["id"] == python_so["id"])["languages"] = {"ausente": True}
    registra("4: regra sem languages", "4", rodar(m_regras=m), exato=True)
    m = copy.deepcopy(regras)
    next(r for r in m if r["id"] == python_so["id"])["languages"] = {"lista": ["None"], "tipos": ["NoneType"]}
    registra("4: elemento de languages que nao e cadeia", "4", rodar(m_regras=m), exato=True)
    # 3 — caminho que o docker -v nao monta
    registra("3m: caminho de pack com ':'", "3m",
             itens(conferir_montavel(Path("/tmp/a:b/semgrep-default.yaml"))), exato=True)
    # 5 — arquivo gravado e relido
    texto = gerar_csv(linhas)
    regs = list(csv.reader(io.StringIO(texto)))
    mutantes = []
    r = [list(x) for x in regs]; r[0][2] = "jsts"; mutantes.append(("5: cabecalho alterado", r))
    r = [list(x) for x in regs]; r[1][2] = "talvez"; mutantes.append(("5: js_ts fora de sim/nao", r))
    r = [list(x) for x in regs]; r[2][2] = "sim" if r[2][2] == "nao" else "nao"
    mutantes.append(("5: js_ts invertido numa linha", r))
    r = [list(x) for x in regs][:-1]; mutantes.append(("5: ultima linha removida", r))
    r = [list(x) for x in regs]; r[3] = r[3] + ["excedente"]; mutantes.append(("5: campo excedente", r))
    with tempfile.TemporaryDirectory(prefix="regras-c5-") as diretorio:
        for indice, (nome, regs_m) in enumerate(mutantes):
            caminho = Path(diretorio) / ("m%d.csv" % indice)
            with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
                csv.writer(arquivo, lineterminator="\n").writerows(regs_m)
            registra(nome, "5", itens(conferir_arquivo(caminho, linhas)), exato=True)
    return resultados


# ---------------------------------------------------------------------------
# Texto
# ---------------------------------------------------------------------------
def gerar_txt(extracao, fontes_desc, conferencias, linhas, composicao, uniao, sha_csv, rid):
    out = []
    w = out.append
    w("Tabela regra -> linguagens do pack vendorizado do Semgrep")
    w("Base do criterio 'pela linguagem da regra' (criterios-cruzamento.md, secao 10).")
    w("Nenhum achado lido ou contado.")
    w("")
    w("  " + PREFIXO_SHA_CSV + sha_csv)
    w("  rules_id_sha256 recalculado: " + rid)
    w("")
    w("Parser: %s, Python %s, dentro de" % (extracao["parser"], extracao["python"]))
    w("  " + IMAGEM)
    w("  (sem rede, --user, pack montado so para leitura)")
    w("")
    w("Fontes (caminho relativo ao repositorio, sha256):")
    for nome, caminho, digest in fontes_desc:
        w("  %-10s %s  %s" % (nome, caminho, digest))
    w("")
    w("Conferencias:")
    for nome, estado in conferencias:
        w("  %-66s %s" % (nome, estado))
    w("")
    w("Coluna languages do CSV: NORMALIZADA (minusculas, sem repeticao, ordenada),")
    w("nao o texto literal do pack. Criterio do descritor: case-insensitive.")
    w("Equivalencia com o parser interno do Semgrep 1.171.0 nao e verificada: os")
    w("numeros batem com o descritor, contado com o mesmo parser na mesma imagem.")
    w("")
    w("Composicao JS/TS (uma regra pode declarar mais de uma grafia):")
    for l in LINGUAGENS_JS_TS:
        w("  %-11s %4d" % (l, composicao[l]))
    w("  %-11s %4d" % ("uniao", uniao))
    w("")
    dist = {}
    for l in linhas:
        dist[l["languages"]] = dist.get(l["languages"], 0) + 1
    w("Distribuicao de regras por valor de languages (%d valores distintos):" % len(dist))
    w("  %5s  %-5s  %s" % ("regras", "JS/TS", "languages"))
    js = {l["languages"]: l["js_ts"] for l in linhas}
    for valor, n in sorted(dist.items(), key=lambda i: (-i[1], i[0])):
        destaque = "  <-- " + "/".join(d for d in DESTACADAS if d in valor.split("|")) \
            if set(valor.split("|")) & set(DESTACADAS) else ""
        w("  %5d  %-5s  %s%s" % (n, js[valor], valor, destaque))
    w("")
    w("Regras generic e regex: disparam em qualquer arquivo, JS inclusive, sem serem")
    w("regras de JS. Pelo criterio da regra, saem fora de JS/TS (ponto cego da secao 10).")
    for d in DESTACADAS:
        ids = [l["check_id"] for l in linhas if d in l["languages"].split("|")]
        w("  %s: %d regras" % (d, len(ids)))
        for i in ids:
            w("    %s" % i)
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
def executar(args):
    pack = Path(args.pack) if args.pack else PACK_PADRAO
    descritor_caminho = Path(args.descritor) if args.descritor else DESCRITOR_PADRAO
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO

    fora = entradas_fora(saida, [pack, descritor_caminho])
    if fora:
        raise Parada("saida dentro do repositorio exige entradas dentro dele: "
                     "o caminho de fora iria para o .txt", fora)
    faltando = [str(c) for c in (pack, descritor_caminho) if not c.is_file()]
    if faltando:
        raise Parada("entradas ausentes", faltando)
    try:
        descritor = json.loads(descritor_caminho.read_text(encoding="utf-8"))
    except ValueError as erro:
        raise Parada("descritor ilegivel", ["%s" % erro])

    c3m = conferir_montavel(pack)
    if c3m:
        raise Parada("conferencia 3m (pack montavel no container)", c3m)
    sha_pack = sha256_arquivo(pack)
    extracao = extrair(pack)
    if extracao.get("chave_topo") != ["rules"]:
        raise Parada("pack fora de forma", ["chaves de topo %r" % extracao.get("chave_topo")])
    regras = extracao["regras"]

    for titulo, motivos in (("conferencia 1 (total de regras)", conferir_total(regras)),
                            ("conferencia 4 (forma de languages)", conferir_forma_languages(regras)),
                            ("conferencia 2 (regras JS/TS)", conferir_js_ts(regras)),
                            ("conferencia 3 (identidade do pack)",
                             conferir_identidade(sha_pack, [r["id"] for r in regras], descritor))):
        if motivos:
            raise Parada(titulo, motivos)

    linhas = montar_linhas(regras)
    controle = controle_positivo(regras, sha_pack, descritor, linhas)
    falhas = ["%s: pretendida %s, dispararam %s" % (nome, pret, disp or "nenhuma")
              for nome, pret, ok, disp in controle if not ok]
    if falhas:
        raise Parada("conferencia 6 (controle positivo) falhou", falhas)
    extrator = controle_extrator()
    falhas = ["%s: obtido %r" % (nome, det) for nome, ok, det in extrator if not ok]
    if falhas:
        raise Parada("conferencia 6 (controle do extrator no container) falhou", falhas)

    composicao, uniao = contar_js_ts(regras)
    rid = rules_id_sha256([r["id"] for r in regras])
    fontes_desc = [
        ("pack", rotulo(pack), sha_pack),
        ("descritor", rotulo(descritor_caminho), sha256_arquivo(descritor_caminho)),
        ("codigo", rotulo(Path(__file__)), sha256_arquivo(__file__)),
        ("codigo", rotulo(DISTRIBUICAO_PY), sha256_arquivo(DISTRIBUICAO_PY)),
    ]
    conferencias = [
        ("1 %d regras, %d check_id distintos" % (REGRAS_TOTAL, REGRAS_TOTAL), "OK"),
        ("2 JS/TS: javascript 152, js 1, typescript 150, ts 5, uniao 163", "OK"),
        ("3 sha256 do pack e rules_id_sha256 = descritor", "OK"),
        ("4 toda regra com languages em lista", "OK"),
        ("5 CSV gravado relido (publicado so se aprovado)", "OK"),
        ("6 controle positivo (%d mutantes)" % len(controle), "OK"),
    ]
    for nome, pret, _, disp in controle:
        conferencias.append(("    %s" % nome, "pretendida %s; dispararam %s"
                             % (pret, ",".join(disp) if disp else "nenhuma")))
    conferencias.append(("  controle do extrator, YAML mutante no container (%d)" % len(extrator), "OK"))
    for nome, _, det in extrator:
        conferencias.append(("    %s" % nome, "OK" if not isinstance(det, str) else "OK: " + det))

    tabela_csv = gerar_csv(linhas)
    texto = gerar_txt(extracao, fontes_desc, conferencias, linhas, composicao, uniao,
                      hashlib.sha256(tabela_csv.encode("utf-8")).hexdigest(), rid)

    saida.mkdir(parents=True, exist_ok=True)
    temporarios = {nome: saida / (PREFIXO_TEMP + nome) for nome in (NOME_CSV, NOME_TXT)}
    for temporario in temporarios.values():
        temporario.unlink(missing_ok=True)
    try:
        temporarios[NOME_CSV].write_text(tabela_csv, encoding="utf-8")
        temporarios[NOME_TXT].write_text(texto, encoding="utf-8")
        c5 = conferir_arquivo(temporarios[NOME_CSV], linhas)
        if c5:
            raise Parada("conferencia 5 (releitura do CSV gravado)", c5)
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
        description="Tabela regra -> linguagens do pack vendorizado do Semgrep.")
    analisador.add_argument("--pack", help="padrao: ic-security-lab-semgrep/rules/semgrep-default.yaml")
    analisador.add_argument("--descritor", help="padrao: ic-security-lab-semgrep/rules/semgrep-default.meta.json")
    analisador.add_argument("--saida-dir", help="padrao: results/capacidade/")
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
