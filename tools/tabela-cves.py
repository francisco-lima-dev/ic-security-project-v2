#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tabela-cves.py — tabela dos 223 CVEs do estudo: ground truth e situacao no
estudo. NENHUMA coluna de deteccao, de achado ou de resultado de ferramenta.

    python3 tools/tabela-cves.py [--lista ARQ] [--metadata ARQ]
                                 [--por-cwe ARQ] [--saida-dir DIR]

DEFINICOES REAPROVEITADAS, nao reimplementadas
  denominador      cruza-deteccao.carregar_gt(): a lista menos as tres
                   exclusoes nominadas (FORA_DO_DENOMINADOR), 220 pares
  gt_cwes          normalize.carregar_lista(), via carregar_gt()
  gt_cwe_primary   normalize.resolver_primario(), via carregar_gt()
  gt_file_path     normalize.normalizar_gt_file_path(), via carregar_lista()
  situacao         o motivo de FORA_DO_DENOMINADOR, traduzido por ROTULO_SITUACAO

FONTES
  datasets/listas/cves-sast.txt           ground truth normalizado (carregar_gt)
  datasets/cve-metadata.csv               URL, commit e Explanation, lidos com
                                          o modulo csv (sete Explanation com
                                          aspas escapadas por duplicacao)
  results/por-cwe/distribuicao-primario.csv
                                          so para a conferencia 4

SAIDAS — results/tabela-cves/tabela-cves.{csv,md} e README.md. Deterministicas:
nenhum carimbo de execucao, toda ordenacao explicita. Gravar dentro do
repositorio exige todas as entradas dentro dele.

CONFERENCIAS — qualquer falha para o script sem gravar
  0 lista e cve-metadata.csv concordam em CVE, URL, commit, CWEs, arquivo, linhas
  1 223 linhas, 223 CVEs distintos
  2 186 repositorios distintos e 38 CWEs distintos (V10, secao 2.2)
  3 situacao: 220 analisado e um de cada exclusao, nos CVEs nominados
  4 cwe_primario igual ao de results/por-cwe/, CVE a CVE, nos 220
  5 o CSV temporario, relido com o modulo csv, antes de ocupar o nome
    definitivo; e o .md com 223 linhas de dados
Cada uma tem controle positivo, com ao menos um mutante, rodado ANTES das
conferencias reais: se o metodo nao acusa o que foi plantado, o zero nao vale.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
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
POR_CWE_PADRAO = RAIZ / "results" / "por-cwe" / "distribuicao-primario.csv"
SAIDA_PADRAO = RAIZ / "results" / "tabela-cves"
NOME_CSV = "tabela-cves.csv"
NOME_MD = "tabela-cves.md"
NOME_README = "README.md"
PREFIXO_TEMP = ".tmp-"

COLUNAS = ["cve", "repositorio", "url", "commit_vulneravel", "cwes", "cwe_primario",
           "arquivo", "linhas", "situacao", "descricao"]

ANALISADO = "analisado"
# Traducao dos motivos de cruza-deteccao.FORA_DO_DENOMINADOR. A LISTA de
# excluidos vem de la; daqui so o rotulo. Motivo sem rotulo e parada.
ROTULO_SITUACAO = {
    "codigo_indisponivel_repositorio_inexistente": "fora: repositório inexistente",
    "codigo_indisponivel_commit_inexistente": "fora: commit inexistente",
    "sem_cwe_no_ground_truth": "fora: sem CWE",
}

# Contra o que a saida e conferida. Vem da especificacao da tabela e da V10:
# divergencia e parada, nunca ajuste.
TOTAL_CVES = 223
TOTAL_ANALISADOS = 220
PUBLICADO_REPOSITORIOS = 186   # metodologia-V10, secao 2.2
PUBLICADO_CWES = 38            # idem
SITUACAO_ESPERADA = {
    "CVE-2016-1000229": "fora: repositório inexistente",
    "CVE-2018-8035": "fora: commit inexistente",
    "CVE-2018-1000096": "fora: sem CWE",
}
PRIMARIO_VAZIO_ESPERADO = ["CVE-2018-1000096", "CVE-2018-16472"]
SEM_PRIMARIO = "SEM_PRIMARIO"   # rotulo do CSV de results/por-cwe/

# fullmatch e [0-9]: `$` aceitaria um \n final, e \d aceitaria digito Unicode.
_RE_ID_CVE = re.compile(r"CVE-([0-9]{4})-([0-9]{4,})")
_RE_URL = re.compile(r"https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)\.git")
_RE_COMMIT = re.compile(r"[0-9a-f]{40}")
_RE_CWE = re.compile(r"CWE-[0-9]{3,}")
_RE_LINHA = re.compile(r"[1-9][0-9]*")

# Caracteres com sentido em celula de tabela GFM. Escapados, a descricao sai
# literal: `__proto__` entre crases nao vira negrito, `*sanitsed*` nao vira
# italico, e `|` dos CWEs nao abre coluna.
_ESPECIAIS_MD = "\\`*_|<>[]"


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


def sha256_texto(texto):
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def chave_cve(cve):
    """Ano, depois numero, NUMERICAMENTE: CVE-2018-3719 antes de CVE-2018-16472."""
    achado = _RE_ID_CVE.fullmatch(cve)
    if not achado:
        raise Parada("identificador de CVE fora da forma", [repr(cve)])
    return (int(achado.group(1)), int(achado.group(2)))


def entradas_fora(saida, entradas):
    """Entradas fora do repositorio, quando a saida esta DENTRO dele.

    Mesma guarda do distribuicao-cwe-primario.py: cada entrada resolvida por
    inteiro, symlink incluso. O caminho de fora iria para o README versionado.
    """
    if not Path(saida).resolve().is_relative_to(RAIZ):
        return []
    return [str(c) for c in entradas if not Path(c).resolve().is_relative_to(RAIZ)]


# ---------------------------------------------------------------------------
# Fontes
# ---------------------------------------------------------------------------
def ler_metadata(caminho, norm):
    """{cve: registro} do benchmark, com CWEs e arquivo pelas funcoes do normalize."""
    fonte, motivos = {}, []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        necessarias = {"CVE", "Repository", "PrePatchCommit", "CWEs", "Explanation",
                       "FilePath", "FileLine"}
        if not necessarias <= set(leitor.fieldnames or []):
            raise Parada("cve-metadata.csv sem as colunas esperadas",
                         ["cabecalho %r" % leitor.fieldnames])
        for numero, registro in enumerate(leitor, 2):
            if None in registro or None in registro.values():
                motivos.append("metadata linha %d: numero de campos diferente do cabecalho"
                               % numero)
                continue
            cve = registro["CVE"]
            if cve in fonte:
                motivos.append("metadata: %s repetido" % cve)
                continue
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
            linhas = []
            for parte in registro["FileLine"].split("|"):
                if not parte.strip():
                    continue
                if not _RE_LINHA.fullmatch(parte.strip()):
                    motivos.append("metadata: %s FileLine nao numerico %r" % (cve, parte))
                    continue
                linhas.append(int(parte))
            fonte[cve] = {
                "url": registro["Repository"],
                "commit": registro["PrePatchCommit"],
                "cwes": cwes,
                "arquivo": norm.normalizar_gt_file_path(registro["FilePath"])[0],
                "linhas": linhas,
                "descricao": registro["Explanation"],
            }
    return fonte, motivos


def ler_por_cwe(caminho):
    """{cve: primario ou ''} do CSV de results/por-cwe/; SEM_PRIMARIO -> ''."""
    mapa, motivos = {}, []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if not {"gt_cwe_primary", "cves"} <= set(leitor.fieldnames or []):
            raise Parada("distribuicao-primario.csv sem as colunas esperadas",
                         ["cabecalho %r" % leitor.fieldnames])
        for registro in leitor:
            categoria = registro["gt_cwe_primary"]
            primario = "" if categoria == SEM_PRIMARIO else categoria
            for cve in (registro["cves"] or "").split("|"):
                if not cve:
                    continue
                if cve in mapa:
                    motivos.append("por-cwe: %s em duas categorias" % cve)
                mapa[cve] = primario
    return mapa, motivos


def repositorio_da_url(url):
    achado = _RE_URL.fullmatch(url)
    if not achado:
        return None
    return "%s/%s" % (achado.group(1), achado.group(2))


def montar_linhas(gt, metadata, fora_do_denominador):
    """Uma linha por CVE, 223, ordenadas por ano e numero. Levanta Parada."""
    motivos = []
    linhas = []
    for cve in sorted(gt, key=chave_cve):
        g, m = gt[cve], metadata.get(cve)
        if m is None:
            motivos.append("%s ausente de cve-metadata.csv" % cve)
            continue
        repositorio = repositorio_da_url(g["repository"])
        if repositorio is None:
            motivos.append("%s: URL fora da forma https://github.com/dono/nome.git: %r"
                           % (cve, g["repository"]))
            continue
        if cve in fora_do_denominador:
            motivo = fora_do_denominador[cve]
            if motivo not in ROTULO_SITUACAO:
                motivos.append("%s: motivo de exclusao %r sem rotulo" % (cve, motivo))
                continue
            situacao = ROTULO_SITUACAO[motivo]
        else:
            situacao = ANALISADO
        linhas.append({
            "cve": cve,
            "repositorio": repositorio,
            "url": g["repository"],
            "commit_vulneravel": g["commit"],
            "cwes": "|".join(g["gt_cwes"]),
            "cwe_primario": g["gt_cwe_primary"] or "",
            "arquivo": g["gt_file_path"],
            "linhas": "|".join(str(n) for n in g["gt_file_lines"]),
            "situacao": situacao,
            "descricao": m["descricao"],
        })
    if motivos:
        raise Parada("montagem da tabela", motivos)
    return linhas


# ---------------------------------------------------------------------------
# Conferencias — funcoes puras, para que o controle positivo exerca as mesmas
# ---------------------------------------------------------------------------
def conferir_fontes(gt, metadata):
    """Conferencia 0: a lista e o benchmark dizem o mesmo, CVE a CVE."""
    motivos = []
    for cve in sorted(set(gt) - set(metadata), key=chave_cve):
        motivos.append("%s na lista e nao no metadata" % cve)
    for cve in sorted(set(metadata) - set(gt), key=chave_cve):
        motivos.append("%s no metadata e nao na lista" % cve)
    for cve in sorted(set(gt) & set(metadata), key=chave_cve):
        g, m = gt[cve], metadata[cve]
        for campo_g, campo_m in (("repository", "url"), ("commit", "commit"),
                                 ("gt_cwes", "cwes"), ("gt_file_path", "arquivo"),
                                 ("gt_file_lines", "linhas")):
            if g[campo_g] != m[campo_m]:
                motivos.append("%s: %s lista=%r, metadata=%r"
                               % (cve, campo_m, g[campo_g], m[campo_m]))
    return motivos


def conferir_contagem(linhas):
    """Conferencia 1."""
    motivos = []
    if len(linhas) != TOTAL_CVES:
        motivos.append("%d linhas, esperadas %d" % (len(linhas), TOTAL_CVES))
    distintos = {l["cve"] for l in linhas}
    if len(distintos) != TOTAL_CVES:
        repetidos = sorted({l["cve"] for l in linhas
                            if sum(1 for o in linhas if o["cve"] == l["cve"]) > 1})
        motivos.append("%d CVEs distintos, esperados %d; repetidos: %s"
                       % (len(distintos), TOTAL_CVES, repetidos or "nenhum"))
    return motivos


def conferir_publicados(linhas):
    """Conferencia 2."""
    motivos = []
    repositorios = {l["repositorio"] for l in linhas}
    if len(repositorios) != PUBLICADO_REPOSITORIOS:
        motivos.append("%d repositorios distintos, publicado %d"
                       % (len(repositorios), PUBLICADO_REPOSITORIOS))
    # A URL tambem, para que duas URLs sob o mesmo dono/nome (grafias
    # distintas do mesmo repositorio) nao se escondam atras dele. O inverso e
    # impossivel por construcao: repositorio e funcao da URL.
    urls = {l["url"] for l in linhas}
    if len(urls) != len(repositorios):
        motivos.append("%d URLs distintas contra %d repositorios distintos"
                       % (len(urls), len(repositorios)))
    cwes = {c for l in linhas for c in l["cwes"].split("|") if c}
    if len(cwes) != PUBLICADO_CWES:
        motivos.append("%d CWEs distintos, publicado %d" % (len(cwes), PUBLICADO_CWES))
    return motivos


def conferir_situacao(linhas):
    """Conferencia 3."""
    motivos = []
    analisados = sum(1 for l in linhas if l["situacao"] == ANALISADO)
    if analisados != TOTAL_ANALISADOS:
        motivos.append("%d %s, esperados %d" % (analisados, ANALISADO, TOTAL_ANALISADOS))
    fora = {l["cve"]: l["situacao"] for l in linhas if l["situacao"] != ANALISADO}
    if fora != SITUACAO_ESPERADA:
        motivos.append("fora do denominador %s, esperado %s"
                       % (sorted(fora.items()), sorted(SITUACAO_ESPERADA.items())))
    valores = {l["situacao"] for l in linhas}
    estranhos = valores - {ANALISADO} - set(SITUACAO_ESPERADA.values())
    if estranhos:
        motivos.append("valores de situacao fora dos quatro: %s" % sorted(estranhos))
    vazios = sorted((l["cve"] for l in linhas if not l["cwe_primario"]), key=chave_cve)
    if vazios != sorted(PRIMARIO_VAZIO_ESPERADO, key=chave_cve):
        motivos.append("cwe_primario vazio em %s, esperado exatamente %s"
                       % (vazios or "nenhum", PRIMARIO_VAZIO_ESPERADO))
    return motivos


def conferir_por_cwe(linhas, por_cwe):
    """Conferencia 4: primario identico ao de results/por-cwe/, nos 220."""
    motivos = []
    analisados = {l["cve"]: l["cwe_primario"] for l in linhas if l["situacao"] == ANALISADO}
    for cve in sorted(set(analisados) | set(por_cwe), key=chave_cve):
        if cve not in por_cwe:
            motivos.append("%s analisado e ausente de por-cwe" % cve)
        elif cve not in analisados:
            motivos.append("%s em por-cwe e nao analisado na tabela" % cve)
        elif analisados[cve] != por_cwe[cve]:
            motivos.append("%s: tabela %r, por-cwe %r" % (cve, analisados[cve], por_cwe[cve]))
    return motivos


def conferir_arquivo(caminho, linhas):
    """Conferencia 5: rele o CSV gravado com o modulo csv.

      5.0 cabecalho e 10 campos em toda linha
      5.1 223 linhas de dados
      5.2 IDs bem formados: CVE, commit de 40 hex, CWE, linhas numericas
      5.3 nenhum campo com quebra de linha
      5.4 cada linha identica a da estrutura em memoria, na mesma posicao
    """
    motivos = []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        registros = list(csv.reader(arquivo))
    if not registros or registros[0] != COLUNAS:
        return ["5.0 cabecalho %r, esperado %r" % (registros[0] if registros else None, COLUNAS)]
    dados = registros[1:]
    if len(dados) != TOTAL_CVES:
        motivos.append("5.1 %d linhas de dados, esperadas %d" % (len(dados), TOTAL_CVES))
    for numero, campos in enumerate(dados, 2):
        onde = "linha %d (%s)" % (numero, campos[0] if campos else "vazia")
        if len(campos) != len(COLUNAS):
            motivos.append("5.0 %s: %d campos, esperados %d" % (onde, len(campos), len(COLUNAS)))
            continue
        r = dict(zip(COLUNAS, campos))
        if not _RE_ID_CVE.fullmatch(r["cve"]):
            motivos.append("5.2 %s: CVE malformado %r" % (onde, r["cve"]))
        if not _RE_COMMIT.fullmatch(r["commit_vulneravel"]):
            motivos.append("5.2 %s: commit malformado %r" % (onde, r["commit_vulneravel"]))
        for cwe in [c for c in r["cwes"].split("|") if r["cwes"]] + (
                [r["cwe_primario"]] if r["cwe_primario"] else []):
            if not _RE_CWE.fullmatch(cwe):
                motivos.append("5.2 %s: CWE malformado %r" % (onde, cwe))
        for n in [p for p in r["linhas"].split("|") if r["linhas"]]:
            if not _RE_LINHA.fullmatch(n):
                motivos.append("5.2 %s: linha malformada %r" % (onde, n))
        for coluna, valor in r.items():
            if "\n" in valor or "\r" in valor:
                motivos.append("5.3 %s: quebra de linha em %s" % (onde, coluna))
        indice = numero - 2
        if indice < len(linhas) and r != linhas[indice]:
            diferentes = [c for c in COLUNAS if r[c] != linhas[indice][c]]
            motivos.append("5.4 %s: difere da memoria em %s" % (onde, diferentes))
    return motivos


def conferir_md(texto_md):
    """5.5: o .md tem exatamente 223 linhas de dados na tabela."""
    corpo = [l for l in texto_md.splitlines() if l.startswith("| CVE-")]
    if len(corpo) != TOTAL_CVES:
        return ["5.5 o .md tem %d linhas de dados, esperadas %d" % (len(corpo), TOTAL_CVES)]
    return []


# ---------------------------------------------------------------------------
# Saidas
# ---------------------------------------------------------------------------
def gerar_csv(linhas):
    saida = io.StringIO()
    escritor = csv.DictWriter(saida, fieldnames=COLUNAS, lineterminator="\n")
    escritor.writeheader()
    escritor.writerows(linhas)
    return saida.getvalue()


def escapar_md(texto):
    return "".join("\\" + c if c in _ESPECIAIS_MD else c for c in texto)


def contagem_situacao(linhas):
    ordem = [ANALISADO] + [SITUACAO_ESPERADA[c] for c in sorted(SITUACAO_ESPERADA, key=chave_cve)]
    return [(s, sum(1 for l in linhas if l["situacao"] == s)) for s in ordem]


def gerar_md(linhas):
    out = []
    w = out.append
    w("# CVEs do estudo — ground truth e situação")
    w("")
    w("Gerada por `tools/tabela-cves.py`; a mesma tabela de `tabela-cves.csv`. "
      "Só ground truth e situação no estudo: nenhuma coluna de detecção. "
      "Procedência e fontes no `README.md` deste diretório.")
    w("")
    w("| situação | CVEs |")
    w("|---|---:|")
    for situacao, n in contagem_situacao(linhas):
        w("| %s | %d |" % (situacao, n))
    w("")
    w("| " + " | ".join(COLUNAS) + " |")
    w("|" + "---|" * len(COLUNAS))
    for l in linhas:
        w("| " + " | ".join(escapar_md(l[c]) for c in COLUNAS) + " |")
    return "\n".join(out) + "\n"


def gerar_readme(linhas, fontes_desc, conferencias, sha_csv, sha_md):
    out = []
    w = out.append
    w("# Tabela dos CVEs do estudo")
    w("")
    w("Saída de `tools/tabela-cves.py`, gerada pelo script — não editar à mão.")
    w("Uma linha por CVE do OpenSSF CVE Benchmark, **223 linhas**, ordenadas por")
    w("ano e depois pelo número do CVE, numericamente (`CVE-2018-3719` antes de")
    w("`CVE-2018-16472`).")
    w("")
    w("## Comando")
    w("")
    w("```bash")
    w("python3 tools/tabela-cves.py")
    w("```")
    w("")
    w("Sem argumentos: entradas e saída padrão. Determinística — nenhum carimbo")
    w("de execução; `git diff --exit-code results/tabela-cves/` depois de")
    w("reexecutar denuncia saída desatualizada.")
    w("")
    w("## Arquivos")
    w("")
    w("| Arquivo | sha256 |")
    w("|---|---|")
    w("| `%s` | `%s` |" % (NOME_CSV, sha_csv))
    w("| `%s` | `%s` |" % (NOME_MD, sha_md))
    w("")
    w("## Colunas")
    w("")
    w("| Coluna | Conteúdo |")
    w("|---|---|")
    w("| `cve` | identificador |")
    w("| `repositorio` | `dono/nome`, derivado da URL |")
    w("| `url` | URL do repositório, como no benchmark |")
    w("| `commit_vulneravel` | `PrePatchCommit`, 40 hex — o commit analisado |")
    w("| `cwes` | `gt_cwes`: o conjunto declarado, normalizado para três dígitos, "
      "na ordem do benchmark, separado por `\\|` |")
    w("| `cwe_primario` | `gt_cwe_primary`; vazio no `CVE-2018-16472` (primário "
      "indefinido na tabela) e no `CVE-2018-1000096` (sem CWE) |")
    w("| `arquivo` | `gt_file_path` normalizado (o `CVE-2019-12041` sem a barra inicial) |")
    w("| `linhas` | `gt_file_lines`, separadas por `\\|` |")
    w("| `situacao` | ver abaixo |")
    w("| `descricao` | o campo `Explanation` do benchmark, como veio |")
    w("")
    w("O campo `cwes` **não é classificação do defeito**: em 163 dos 223 CVEs é")
    w("o conjunto de tags da consulta do CodeQL que originou o registro (ver")
    w("`results/proveniencia/`). O `cwe_primario` é a seleção feita pelo estudo")
    w("dentro desse conjunto, pela tabela `datasets/cwe-primario.csv`.")
    w("")
    w("## Situação")
    w("")
    w("| situação | CVEs | quais |")
    w("|---|---:|---|")
    for situacao, n in contagem_situacao(linhas):
        if situacao == ANALISADO:
            w("| `%s` | %d | no denominador de 220 pares |" % (situacao, n))
        else:
            quais = ", ".join("`%s`" % l["cve"] for l in linhas if l["situacao"] == situacao)
            w("| `%s` | %d | %s |" % (situacao, n, quais))
    w("")
    w("A lista dos excluídos vem de `FORA_DO_DENOMINADOR`, do")
    w("`tools/cruza-deteccao.py`; o script só a traduz em rótulo. O")
    w("`CVE-2018-1000096` foi analisado nas três ferramentas, mas não entra na")
    w("matriz por não ter CWE. Os outros dois não tiveram código analisado:")
    w("nenhuma ferramenta foi confrontada com eles.")
    w("")
    w("## O que a tabela NÃO contém")
    w("")
    w("**Detecção alguma.** Nenhuma coluna de achado, de acerto ou de resultado")
    w("de ferramenta, e o script não lê tratado, matriz de detecção nem log de")
    w("execução. Também não traz o `PostPatchCommit`, que só entra na segunda")
    w("campanha, nem a proveniência da etiqueta (herdada ou não do CodeQL), que")
    w("está em `results/proveniencia/` e `results/circularidade/`.")
    w("")
    w("## Fontes")
    w("")
    w("Todas versionadas. Caminho relativo ao repositório, sha256.")
    w("")
    w("| Fonte | Para quê | sha256 |")
    w("|---|---|---|")
    for caminho, papel, digest in fontes_desc:
        w("| `%s` | %s | `%s` |" % (caminho, papel, digest))
    w("")
    w("Nada é reimplementado: o ground truth normalizado e o denominador vêm de")
    w("`carregar_gt()` do `cruza-deteccao.py`, que aplica `carregar_lista`,")
    w("`normalizar_cwe`, `normalizar_gt_file_path` e `resolver_primario` do")
    w("`normalize.py`. O `cve-metadata.csv` é lido com o módulo `csv`, porque")
    w("sete descrições têm aspas escapadas por duplicação.")
    w("")
    w("## Conferências que precedem a gravação")
    w("")
    w("Falhando qualquer uma, o script sai com código não nulo e nada é gravado.")
    w("Cada uma tem controle positivo — mutante que precisa disparar a")
    w("conferência pretendida —, rodado antes das conferências reais.")
    w("")
    w("| Conferência | Estado |")
    w("|---|---|")
    for nome, estado in conferencias:
        w("| %s | %s |" % (escapar_md(nome), escapar_md(estado)))
    w("")
    w("## Alcance das conferências")
    w("")
    w("Nem todas são prova independente, e o \"OK\" acima não diz qual é:")
    w("")
    w("- **A única com âncora externa é a 2** — 186 e 38 vêm da V10 (§2.2).")
    w("- **A 1 é verdadeira por construção** na execução real: `carregar_gt`")
    w("  já para fora de 223 CVEs, e o ground truth é chaveado por CVE. Ela pega")
    w("  defeito da montagem da tabela, não da lista.")
    w("- **Na 3, o \"220 analisado\" é verdadeiro por construção**: situação e")
    w("  denominador vêm da mesma `FORA_DO_DENOMINADOR`, e `carregar_gt` já para")
    w("  fora de 220. O que ela acrescenta é o par CVE → rótulo contra a lista")
    w("  nominada à mão, e o conjunto exato de `cwe_primario` vazio.")
    w("- **A 4 pega arquivo desatualizado ou entrada trocada, não erro na tabela")
    w("  de primário**: `results/por-cwe/` aplica a mesma tabela pela mesma")
    w("  `resolver_primario`.")
    w("- **A 0 compara fontes independentes** (lista e `cve-metadata.csv`), mas")
    w("  depois de passar as duas pelas mesmas `normalizar_cwe` e")
    w("  `normalizar_gt_file_path`: divergência que a normalização apague — como")
    w("  `/index.js` contra `index.js` — ou defeito dela mesma não aparece.")
    w("")
    w("## Escrita")
    w("")
    w("Os três arquivos são gravados com nome temporário; o CSV é relido com o")
    w("módulo `csv` e o `.md` gravado é relido (conferência 5), e só então os")
    w("três ocupam o nome definitivo, na ordem CSV, `.md`, README — este por")
    w("último, porque declara o sha256 dos outros dois. Depois da promoção, o")
    w("conteúdo de cada nome definitivo é conferido por sha256 contra o aprovado.")
    w("**Limite declarado:** os três renames não são atômicos como conjunto.")
    w("Falha entre eles é nomeada pelo script, mas interrupção abrupta (SIGKILL)")
    w("deixa arquivos de execuções diferentes, detectáveis só conferindo à mão")
    w("os sha256 da tabela \"Arquivos\" — não há modo de conferência automático.")
    w("")
    w("O determinismo é conferido fora do script, com `PYTHONHASHSEED` distintos.")
    w("O script recusa gravar dentro do repositório se alguma entrada estiver")
    w("fora dele, porque o caminho da máquina do operador iria para este README.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Controle positivo
# ---------------------------------------------------------------------------
def copia(linhas):
    return [dict(l) for l in linhas]


def indice_de(linhas, cve):
    return next(i for i, l in enumerate(linhas) if l["cve"] == cve)


def controle_positivo(linhas, gt, metadata, por_cwe):
    """Conferencias 0 a 4, com mutantes em memoria. [(nome, disparou, amostra)]."""
    resultados = []

    def registra(nome, motivos, marca):
        disparou = any(marca in m for m in motivos)
        resultados.append((nome, disparou, motivos[:2]))

    # Os mutantes de repositorio e de URL da conferencia 2 so disparam se o
    # repositorio do alvo tiver outro CVE: com um so, a URL antiga some e a
    # contagem nao muda (revisao, risco 3). A condicao e escolhida E assertada.
    por_repositorio = {}
    for l in linhas:
        por_repositorio[l["repositorio"]] = por_repositorio.get(l["repositorio"], 0) + 1
    alvo = next((l for l in linhas if l["situacao"] == ANALISADO and l["cwe_primario"]
                 and por_repositorio[l["repositorio"]] > 1), None)
    if alvo is None:
        raise Parada("controle positivo sem alvo",
                     ["nenhum CVE analisado, com primario, de repositorio com mais de um CVE"])
    i_alvo = indice_de(linhas, alvo["cve"])

    # Conferencia 0
    m = {c: dict(v) for c, v in metadata.items()}
    m[alvo["cve"]]["commit"] = "0" * 40
    registra("c0: commit divergente entre lista e metadata", conferir_fontes(gt, m), alvo["cve"])
    m = {c: dict(v) for c, v in metadata.items()}
    del m[alvo["cve"]]
    registra("c0: CVE ausente do metadata", conferir_fontes(gt, m), alvo["cve"])

    # Conferencia 1
    mut = copia(linhas); del mut[i_alvo]
    registra("c1: linha removida (222)", conferir_contagem(mut), "222 linhas")
    mut = copia(linhas); mut[i_alvo + 1] = dict(mut[i_alvo])
    registra("c1: CVE duplicado, 223 linhas", conferir_contagem(mut), alvo["cve"])

    # Conferencia 2
    mut = copia(linhas); mut[i_alvo]["repositorio"] = "mutante/novo"
    mut[i_alvo]["url"] = "https://github.com/mutante/novo.git"
    registra("c2: repositorio a mais (187)", conferir_publicados(mut), "187 repositorios")
    mut = copia(linhas); mut[i_alvo]["cwes"] += "|CWE-999"
    registra("c2: CWE a mais (39)", conferir_publicados(mut), "39 CWEs")
    mut = copia(linhas); mut[i_alvo]["url"] = mut[i_alvo]["url"].replace(".git", "-x.git")
    registra("c2: URL nova sob o mesmo dono/nome", conferir_publicados(mut), "URLs distintas")

    # Conferencia 3
    mut = copia(linhas); mut[i_alvo]["situacao"] = "fora: sem CWE"
    registra("c3: analisado rebaixado a fora", conferir_situacao(mut), "219 analisado")
    mut = copia(linhas)
    a, b = indice_de(mut, "CVE-2016-1000229"), indice_de(mut, "CVE-2018-8035")
    mut[a]["situacao"], mut[b]["situacao"] = mut[b]["situacao"], mut[a]["situacao"]
    registra("c3: rotulos de exclusao trocados entre CVEs", conferir_situacao(mut),
             "CVE-2016-1000229")
    mut = copia(linhas); mut[indice_de(mut, "CVE-2018-1000096")]["situacao"] = "fora: outro"
    registra("c3: quinto valor de situacao", conferir_situacao(mut), "fora dos quatro")
    mut = copia(linhas); mut[i_alvo]["cwe_primario"] = ""
    registra("c3: terceiro cwe_primario vazio", conferir_situacao(mut), alvo["cve"])

    # Conferencia 4
    mut = copia(linhas); mut[i_alvo]["cwe_primario"] = "CWE-022" \
        if alvo["cwe_primario"] != "CWE-022" else "CWE-079"
    registra("c4: primario alterado na tabela", conferir_por_cwe(mut, por_cwe), alvo["cve"])
    p = dict(por_cwe); del p[alvo["cve"]]
    registra("c4: CVE ausente de por-cwe", conferir_por_cwe(linhas, p), alvo["cve"])
    p = dict(por_cwe); p["CVE-2018-8035"] = "CWE-079"
    registra("c4: CVE fora do denominador presente em por-cwe", conferir_por_cwe(linhas, p),
             "CVE-2018-8035")

    # Guarda de entrada fora do repositorio
    fora_raiz = Path(tempfile.gettempdir()).resolve() / "entrada-externa"
    registra("guarda: entrada externa com saida no repositorio",
             entradas_fora(SAIDA_PADRAO, [LISTA_PADRAO, fora_raiz]), "entrada-externa")
    return alvo["cve"], resultados


def mutantes_do_arquivo(texto_csv):
    """Um mutante ao menos por item da conferencia 5, como texto de CSV."""
    cabecalho, *registros = list(csv.reader(io.StringIO(texto_csv)))
    i = {c: cabecalho.index(c) for c in cabecalho}

    def serializar(regs, cab=None):
        saida = io.StringIO()
        escritor = csv.writer(saida, lineterminator="\n")
        escritor.writerow(cab or cabecalho)
        escritor.writerows(regs)
        return saida.getvalue()

    def regs():
        return [list(r) for r in registros]

    # Alvo com aspas na descricao: o caso que motiva ler com o modulo csv.
    aspas = next(k for k, r in enumerate(registros) if '"' in r[i["descricao"]])
    mutantes = []
    cab = list(cabecalho); cab[i["cwes"]] = "cwe"
    mutantes.append(("cabecalho alterado", "5.0", serializar(registros, cab)))
    r = regs(); r[0] = r[0] + ["excedente"]
    mutantes.append(("campo excedente numa linha", "5.0", serializar(r)))
    r = regs(); del r[-1]
    mutantes.append(("ultima linha perdida", "5.1", serializar(r)))
    r = regs(); r[0][i["cve"]] = r[0][i["cve"]] + "\n"
    mutantes.append(("CVE com quebra de linha final", "5.2", serializar(r)))
    r = regs(); r[0][i["commit_vulneravel"]] = r[0][i["commit_vulneravel"]][:7]
    mutantes.append(("commit abreviado", "5.2", serializar(r)))
    r = regs(); r[0][i["cwes"]] = r[0][i["cwes"]].replace("CWE-0", "CWE-", 1)
    mutantes.append(("CWE sem zero a esquerda", "5.2", serializar(r)))
    r = regs(); r[0][i["cwe_primario"]] = "cwe79"
    mutantes.append(("cwe_primario fora da forma", "5.2", serializar(r)))
    r = regs(); r[0][i["linhas"]] = r[0][i["linhas"]] + "|0"
    mutantes.append(("linha zero na coluna linhas", "5.2", serializar(r)))
    r = regs(); r[aspas][i["descricao"]] = r[aspas][i["descricao"]].replace(" ", "\n", 1)
    mutantes.append(("descricao com quebra de linha", "5.3", serializar(r)))
    r = regs(); r[aspas][i["descricao"]] = r[aspas][i["descricao"]].replace('"', "", 1)
    mutantes.append(("aspas perdidas na descricao", "5.4", serializar(r)))
    r = regs(); r[0], r[1] = r[1], r[0]
    mutantes.append(("duas linhas trocadas de posicao", "5.4", serializar(r)))
    return mutantes


def controle_positivo_arquivo(texto_csv, texto_md, linhas):
    """Grava cada mutante em arquivo e o rele pela conferencia 5."""
    resultados = []
    with tempfile.TemporaryDirectory(prefix="tabela-cves-c5-") as diretorio:
        for indice, (nome, item, texto) in enumerate(mutantes_do_arquivo(texto_csv)):
            caminho = Path(diretorio) / ("mutante-%d.csv" % indice)
            caminho.write_text(texto, encoding="utf-8")
            itens = sorted({m.split(" ", 1)[0] for m in conferir_arquivo(caminho, linhas)})
            resultados.append((nome, item, item in itens, itens))
    corpo = texto_md.splitlines()
    sem_uma = "\n".join(l for k, l in enumerate(corpo)
                        if k != next(j for j, x in enumerate(corpo) if x.startswith("| CVE-")))
    itens = sorted({m.split(" ", 1)[0] for m in conferir_md(sem_uma)})
    resultados.append(("md com uma linha de dados a menos", "5.5", "5.5" in itens, itens))
    return resultados


# ---------------------------------------------------------------------------
def executar(args):
    lista = Path(args.lista) if args.lista else LISTA_PADRAO
    metadata_caminho = Path(args.metadata) if args.metadata else METADATA_PADRAO
    por_cwe_caminho = Path(args.por_cwe) if args.por_cwe else POR_CWE_PADRAO
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO

    spec = importlib.util.spec_from_file_location("cruza_deteccao", CRUZA)
    cruza_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cruza_mod)
    norm = cruza_mod.importar("normalize", NORMALIZE)
    tabela_primario = norm.TABELA_PRIMARIO

    fora = entradas_fora(saida, [lista, metadata_caminho, por_cwe_caminho, tabela_primario])
    if fora:
        raise Parada("saida dentro do repositorio exige entradas dentro dele: "
                     "o caminho de fora iria para o README", fora)

    try:
        gt, denominador, _ = cruza_mod.carregar_gt(norm, lista)
    except cruza_mod.Parada as p:
        raise Parada("cruza-deteccao.carregar_gt: " + p.titulo, p.motivos)
    metadata, m1 = ler_metadata(metadata_caminho, norm)
    por_cwe, m2 = ler_por_cwe(por_cwe_caminho)
    if m1 + m2:
        raise Parada("fontes ilegiveis ou incompletas", m1 + m2)

    linhas = montar_linhas(gt, metadata, cruza_mod.FORA_DO_DENOMINADOR)
    analisados = sorted(l["cve"] for l in linhas if l["situacao"] == ANALISADO)
    if analisados != sorted(denominador):
        raise Parada("situacao analisado difere do denominador de carregar_gt",
                     sorted(set(analisados) ^ set(denominador)))

    alvo, controle = controle_positivo(linhas, gt, metadata, por_cwe)
    falhas = ["%s: nao disparou (%s)" % (nome, amostra)
              for nome, disparou, amostra in controle if not disparou]
    texto_csv, texto_md = gerar_csv(linhas), gerar_md(linhas)
    controle_c5 = controle_positivo_arquivo(texto_csv, texto_md, linhas)
    falhas += ["%s: esperado %s, dispararam %s" % (nome, item, itens or "nenhum")
               for nome, item, disparou, itens in controle_c5 if not disparou]
    if falhas:
        raise Parada("controle positivo falhou", falhas)

    for titulo, motivos in (
            ("conferencia 0 (lista x cve-metadata.csv)", conferir_fontes(gt, metadata)),
            ("conferencia 1 (223 linhas, 223 CVEs)", conferir_contagem(linhas)),
            ("conferencia 2 (186 repositorios, 38 CWEs)", conferir_publicados(linhas)),
            ("conferencia 3 (situacao)", conferir_situacao(linhas)),
            ("conferencia 4 (primario x results/por-cwe)", conferir_por_cwe(linhas, por_cwe)),
            ("conferencia 5.5 (.md)", conferir_md(texto_md))):
        if motivos:
            raise Parada(titulo, motivos)

    conferencias = [
        ("0 lista = cve-metadata.csv em CVE, URL, commit, CWEs, arquivo, linhas", "OK"),
        ("1 223 linhas, 223 CVEs distintos", "OK"),
        ("2 186 repositórios e 38 CWEs distintos (V10, §2.2)", "OK"),
        ("3 situação: 220 analisado, 1 de cada exclusão nominada; "
         "cwe_primario vazio só em CVE-2018-1000096 e CVE-2018-16472", "OK"),
        ("4 cwe_primario = results/por-cwe, CVE a CVE (220)", "OK, 0 divergências"),
        ("5 CSV temporário relido com o módulo csv; .md gravado relido, 223 linhas", "OK"),
        ("controle positivo, conferências 0 a 4 (%d mutantes, alvo %s)"
         % (len(controle), alvo), "OK, todos dispararam"),
    ]
    conferencias += [("  " + nome, "disparou") for nome, _, _ in controle]
    conferencias.append(("controle positivo, conferência 5 (%d mutantes, em arquivo)"
                         % len(controle_c5), "OK, cada um pelo item pretendido"))
    conferencias += [("  %s: %s" % (item, nome), "disparou %s" % ",".join(itens))
                     for nome, item, _, itens in controle_c5]

    fontes_desc = [
        (rotulo(lista), "ground truth normalizado e denominador, via `carregar_gt()`",
         sha256_arquivo(lista)),
        (rotulo(tabela_primario), "`cwe_primario` dos conjuntos multivalorados",
         sha256_arquivo(tabela_primario)),
        (rotulo(metadata_caminho), "`descricao`; e conferência 0 de URL, commit, CWEs, "
         "arquivo e linhas", sha256_arquivo(metadata_caminho)),
        (rotulo(por_cwe_caminho), "só a conferência 4", sha256_arquivo(por_cwe_caminho)),
        (rotulo(Path(__file__)), "código", sha256_arquivo(__file__)),
        (rotulo(CRUZA), "código", sha256_arquivo(CRUZA)),
        (rotulo(NORMALIZE), "código", sha256_arquivo(NORMALIZE)),
    ]
    readme = gerar_readme(linhas, fontes_desc, conferencias,
                          sha256_texto(texto_csv), sha256_texto(texto_md))

    saida.mkdir(parents=True, exist_ok=True)
    conteudo = {NOME_CSV: texto_csv, NOME_MD: texto_md, NOME_README: readme}
    temporarios = {nome: saida / (PREFIXO_TEMP + nome) for nome in conteudo}
    for temporario in temporarios.values():
        temporario.unlink(missing_ok=True)
    try:
        for nome, texto in conteudo.items():
            temporarios[nome].write_text(texto, encoding="utf-8")
        motivos = conferir_arquivo(temporarios[NOME_CSV], linhas) + conferir_md(
            temporarios[NOME_MD].read_text(encoding="utf-8"))
        if motivos:
            raise Parada("conferencia 5 (arquivos gravados)", motivos)
        # Tres renames nao sao atomicos como conjunto (revisao, risco 2): falha
        # no meio e nomeada, com o que ficou promovido.
        promovidos = []
        for nome in (NOME_CSV, NOME_MD, NOME_README):
            try:
                temporarios[nome].replace(saida / nome)
            except OSError as erro:
                raise Parada("promocao incompleta: %s ja promovidos, %s nao"
                             % (promovidos or "nenhum", nome),
                             ["%s: %s" % (type(erro).__name__, erro)])
            promovidos.append(nome)
        # E a promocao conferida pelo resultado, nao pela ausencia de excecao:
        # o que esta no nome definitivo e byte a byte o que foi aprovado.
        divergentes = [nome for nome, texto in conteudo.items()
                       if sha256_arquivo(saida / nome) != sha256_texto(texto)]
        if divergentes:
            raise Parada("promocao incoerente: nome definitivo difere do aprovado",
                         divergentes)
    finally:
        for temporario in temporarios.values():
            try:
                temporario.unlink(missing_ok=True)
            except OSError as erro:
                print("AVISO: temporario nao removido: %s: %s" % (temporario, erro),
                      file=sys.stderr)

    print("tabela-cves: %d linhas gravadas em %s" % (len(linhas), rotulo(saida)))
    for situacao, n in contagem_situacao(linhas):
        print("  %-32s %d" % (situacao, n))
    for nome, estado in conferencias:
        print("  %-78s %s" % (nome, estado))
    return 0


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Tabela dos 223 CVEs do estudo: ground truth e situacao.")
    analisador.add_argument("--lista", help="padrao: datasets/listas/cves-sast.txt")
    analisador.add_argument("--metadata", help="padrao: datasets/cve-metadata.csv")
    analisador.add_argument("--por-cwe", help="padrao: results/por-cwe/distribuicao-primario.csv")
    analisador.add_argument("--saida-dir", help="padrao: results/tabela-cves/")
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
