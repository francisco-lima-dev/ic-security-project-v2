#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
importa-artifacts.py — traz para o repositório o que um artifact do
analise-lote.yml tem de versionável: os tratados e os dois registros do lote.

    python3 tools/importa-artifacts.py --artifact <dir> --campanha corrigida \
        --data AAAA-MM-DD [--dry-run]

<dir> é o diretório de UM artifact já baixado (`gh run download <run> -n
<nome> -D <dir>`): um lote, uma ferramenta. O script lê do README.txt do
artifact a campanha, o lote e a ferramenta, e copia byte a byte:

    results/<ferramenta>/treated/CVE-*.json
        → deteccao:  results/<ferramenta>/treated/
        → corrigida: results/corrigida/<ferramenta>/treated/
    logs/execution-log-<ferramenta>.csv, logs/normalize-report-<ferramenta>.json
    README.txt → <ferramenta>/README.txt
        → deteccao:  logs/campanha-<data>/<lote>/
        → corrigida: logs/campanha-corrigida-<data>/<lote>/

A primeira campanha foi importada à mão (`gh run download` e `cmp`, ver
logs/campanha-2026-09-17/README.md). Este script existe para a segunda, em que
o mesmo nome de arquivo — CVE-<id>.json — designa resultado de outro commit, e
um tratado da versão corrigida gravado em results/<ferramenta>/treated/
sobrescreveria, ou se misturaria a, um resultado da detecção sem erro algum.

Guardas, todas conferidas ANTES de qualquer escrita; um problema qualquer e
nada é gravado:

  1. destino por campanha: tratado da campanha corrigida só vai para
     results/corrigida/<ferramenta>/treated/, e o da detecção nunca para
     dentro de results/corrigida/ — inclusive quando o destino é dado à mão
     em --treated-dir;
  2. commit: o metadata.commit de cada tratado é o commit do CVE na lista do
     lote (datasets/listas/<lote>) — o PostPatchCommit na campanha corrigida,
     o PrePatchCommit na de detecção — e o CVE pertence ao lote. O
     metadata.commit vem da lista completa, e só prova que o normalize.py usou
     a lista certa; o commit ANALISADO é conferido na coluna `commit` do log de
     execução, linha a linha, contra a mesma lista do lote;
  3. sem sobrescrita: arquivo de destino existente é recusado. Cada arquivo é
     criado com abertura exclusiva, e a corrida entre conferência e escrita
     também falha em vez de sobrescrever.

Conferências acessórias: a campanha do README do artifact é a pedida em
--campanha; a campanha e o lote passam pelo tools/confere-campanha.sh; a
ferramenta do README é a dos tratados e a dos nomes dos logs; o normalize-report
registra como `lista` a lista completa da campanha.

O que NÃO importa: o raw (não versionado; ver o CLAUDE.md) e o restante do
artifact — container/, portoes/, disco.txt, rede-semgrep/ e as sondagens. O
container/lote.txt do job do Snyk Code é stdout e stderr de um container que
recebeu o token, e na primeira campanha só entrou depois de varredura de
segredo; esse passo continua manual.

Códigos de saída: 0 importou (ou --dry-run conferiu), 1 guarda recusou, 2 uso.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

RAIZ_PADRAO = Path(__file__).resolve().parent.parent
FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
CAMPANHAS = ("deteccao", "corrigida")
LISTA_COMPLETA = {"deteccao": "cves-sast.txt", "corrigida": "cves-sast-corrigida.txt"}
RE_CVE_ARQ = re.compile(r"^CVE-\d{4}-\d{4,}\.json$")
# O marcador versionado de results/<ferramenta>/treated/ vai junto no artifact:
# o passo de montagem copia o diretório inteiro. É o ÚNICO nome ignorado ali;
# qualquer outro que não seja CVE-*.json continua recusado. Medido no ensaio de
# 28/09/2026 (execução 36467129181), cujos três artifacts o traziam.
MARCADOR_TREATED = ".gitkeep"
RE_DATA = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RE_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class Recusa(Exception):
    """Guarda recusou a importação; a mensagem nomeia a guarda."""


def ler_readme(artifact: Path) -> dict:
    leia = artifact / "README.txt"
    if not leia.is_file():
        raise Recusa("README.txt ausente do artifact: %s" % leia)
    campos = {}
    with open(leia, encoding="utf-8") as arquivo:
        for linha in arquivo:
            m = re.match(r"^(campanha|lote|ferramenta): (.*)$", linha.rstrip("\n"))
            if m and m.group(1) not in campos:
                campos[m.group(1)] = m.group(2)
    for chave in ("campanha", "lote", "ferramenta"):
        if chave not in campos:
            raise Recusa("README.txt do artifact sem a linha '%s:' — artifact anterior à "
                         "entrada `campanha`, ou não é do analise-lote.yml" % chave)
    return campos


def ler_lista(caminho: Path) -> dict:
    """CVE -> commit, da lista de seis campos. Forma errada é recusa."""
    if not caminho.is_file():
        raise Recusa("lista do lote inexistente: %s" % caminho)
    commits = {}
    with open(caminho, encoding="utf-8") as arquivo:
        for numero, linha in enumerate(arquivo, 1):
            linha = linha.rstrip("\n")
            if not linha:
                continue
            partes = linha.split(",")
            if len(partes) != 6:
                raise Recusa("%s linha %d: %d campos, esperado 6" % (caminho, numero, len(partes)))
            cve, commit = partes[0], partes[2]
            if not RE_HEX40.match(commit):
                raise Recusa("%s linha %d: commit de %s não é 40 hex" % (caminho, numero, cve))
            if cve in commits:
                raise Recusa("%s: CVE repetido %s" % (caminho, cve))
            commits[cve] = commit
    if not commits:
        raise Recusa("lista do lote vazia: %s" % caminho)
    return commits


def treated_padrao(raiz: Path, campanha: str, ferramenta: str) -> Path:
    if campanha == "corrigida":
        return raiz / "results" / "corrigida" / ferramenta / "treated"
    return raiz / "results" / ferramenta / "treated"


def conferir_destino_treated(raiz: Path, campanha: str, ferramenta: str, destino: Path) -> None:
    """Guarda 1. Compara caminhos resolvidos, não cadeias."""
    esperado = treated_padrao(raiz, campanha, ferramenta).resolve()
    real = destino.resolve()
    corrigida = (raiz / "results" / "corrigida").resolve()
    dentro_corrigida = real == corrigida or corrigida in real.parents
    if campanha == "corrigida" and real != esperado:
        raise Recusa("destino de tratados %s recusado: a campanha corrigida só grava em %s"
                     % (destino, esperado))
    if campanha == "deteccao" and (dentro_corrigida or real != esperado):
        raise Recusa("destino de tratados %s recusado: a campanha de detecção só grava em %s, "
                     "e nunca sob results/corrigida/" % (destino, esperado))


def planejar(args) -> list:
    """Todas as conferências; devolve [(origem, destino)] sem escrever nada."""
    raiz = Path(args.raiz).resolve()
    artifact = Path(args.artifact)
    if not artifact.is_dir():
        raise Recusa("artifact não é diretório: %s" % artifact)
    if args.campanha not in CAMPANHAS:
        raise Recusa("--campanha desconhecida: %r" % args.campanha)
    if not RE_DATA.match(args.data):
        raise Recusa("--data fora da forma AAAA-MM-DD: %r" % args.data)

    leia = ler_readme(artifact)
    if leia["campanha"] != args.campanha:
        raise Recusa("campanha do artifact (%r, no README.txt) difere da pedida (%r)"
                     % (leia["campanha"], args.campanha))
    ferramenta, lote = leia["ferramenta"], leia["lote"]
    if ferramenta not in FERRAMENTAS:
        raise Recusa("ferramenta desconhecida no README.txt: %r" % ferramenta)
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", lote):
        raise Recusa("lote com forma inválida no README.txt: %r" % lote)

    confere = subprocess.run([str(RAIZ_PADRAO / "tools" / "confere-campanha.sh"), args.campanha, lote],
                             capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if confere.returncode != 0:
        raise Recusa("confere-campanha.sh recusou (campanha %s, lote %s): %s"
                     % (args.campanha, lote, confere.stderr.strip()))

    commits = ler_lista(raiz / "datasets" / "listas" / lote)

    destino_treated = Path(args.treated_dir) if args.treated_dir else \
        treated_padrao(raiz, args.campanha, ferramenta)
    conferir_destino_treated(raiz, args.campanha, ferramenta, destino_treated)

    prefixo = "campanha-corrigida-" if args.campanha == "corrigida" else "campanha-"
    destino_logs = raiz / "logs" / (prefixo + args.data) / lote

    plano = []
    problemas = []

    # --- tratados: guarda 2 ---
    origem_treated = artifact / "results" / ferramenta / "treated"
    outros = [p.name for p in (artifact / "results").iterdir()
              if p.name != ferramenta] if (artifact / "results").is_dir() else []
    if outros:
        problemas.append("results/ do artifact traz outra ferramenta: %s" % ", ".join(sorted(outros)))
    if not origem_treated.is_dir():
        raise Recusa("artifact sem tratados: %s" % origem_treated)
    for arq in sorted(origem_treated.iterdir()):
        if arq.name == MARCADOR_TREATED and arq.is_file():
            continue
        if not RE_CVE_ARQ.match(arq.name):
            problemas.append("arquivo inesperado entre os tratados: %s" % arq.name)
            continue
        cve = arq.name[:-len(".json")]
        try:
            with open(arq, encoding="utf-8") as f:
                meta = json.load(f)["metadata"]
        except (OSError, ValueError, KeyError, TypeError) as erro:
            problemas.append("%s: tratado ilegível (%s)" % (arq.name, type(erro).__name__))
            continue
        if not isinstance(meta, dict):
            problemas.append("%s: metadata não é objeto" % arq.name)
            continue
        if meta.get("cve_id") != cve:
            problemas.append("%s: metadata.cve_id %r difere do nome" % (arq.name, meta.get("cve_id")))
        if meta.get("tool") != ferramenta:
            problemas.append("%s: metadata.tool %r difere da ferramenta do artifact %r"
                             % (arq.name, meta.get("tool"), ferramenta))
        if cve not in commits:
            problemas.append("%s: CVE fora do lote %s" % (arq.name, lote))
        elif meta.get("commit") != commits[cve]:
            papel = "PostPatchCommit" if args.campanha == "corrigida" else "PrePatchCommit"
            problemas.append("%s: metadata.commit %r não é o %s da lista do lote (%s)"
                             % (arq.name, meta.get("commit"), papel, commits[cve]))
        plano.append((arq, destino_treated / arq.name))

    # --- registros do lote ---
    log = artifact / "logs" / ("execution-log-%s.csv" % ferramenta)
    relatorio = artifact / "logs" / ("normalize-report-%s.json" % ferramenta)
    for arq in (log, relatorio):
        if not arq.is_file():
            problemas.append("registro ausente do artifact: %s" % arq.relative_to(artifact))
        else:
            plano.append((arq, destino_logs / arq.name))
    # O metadata.commit do tratado vem da LISTA completa (normalize.py), e
    # prova só que a lista certa foi usada. O commit ANALISADO está no log de
    # execução, coluna `commit`: é ali que a guarda 2 se fecha sobre o dado
    # efetivo, e não só por construção da asserção dos run_*.sh.
    if log.is_file():
        import csv
        try:
            with open(log, newline="", encoding="utf-8") as f:
                leitor = csv.DictReader(f)
                if leitor.fieldnames is None or "cve" not in leitor.fieldnames \
                        or "commit" not in leitor.fieldnames:
                    problemas.append("log de execução sem as colunas cve e commit")
                else:
                    for numero, linha in enumerate(leitor, 2):
                        cve = linha["cve"]
                        if cve not in commits:
                            problemas.append("log de execução linha %d: %s fora do lote %s"
                                             % (numero, cve, lote))
                        elif linha["commit"] != commits[cve]:
                            problemas.append("log de execução linha %d: %s analisado em %r, e a lista "
                                             "do lote traz %s" % (numero, cve, linha["commit"], commits[cve]))
        except (OSError, UnicodeDecodeError, csv.Error) as erro:
            problemas.append("log de execução ilegível (%s)" % type(erro).__name__)
    if relatorio.is_file():
        try:
            with open(relatorio, encoding="utf-8") as f:
                lista_rel = json.load(f).get("lista")
        except (OSError, ValueError, AttributeError) as erro:
            problemas.append("normalize-report ilegível (%s)" % type(erro).__name__)
        else:
            if not isinstance(lista_rel, str) or Path(lista_rel).name != LISTA_COMPLETA[args.campanha]:
                problemas.append("normalize-report registra a lista %r; a campanha %s normaliza contra %s"
                                 % (lista_rel, args.campanha, LISTA_COMPLETA[args.campanha]))
    plano.append((artifact / "README.txt", destino_logs / ferramenta / "README.txt"))

    # --- guarda 3: sem sobrescrita ---
    destinos = [d for _, d in plano]
    for d in destinos:
        if d.exists():
            problemas.append("destino existente, não sobrescrevo: %s" % d)
    if len(set(destinos)) != len(destinos):
        problemas.append("dois arquivos com o mesmo destino")

    if problemas:
        raise Recusa("%d problema(s):\n  - %s" % (len(problemas), "\n  - ".join(problemas)))
    return plano


def copiar_exclusivo(origem: Path, destino: Path) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    with open(origem, "rb") as entrada, open(destino, "xb") as saida:
        shutil.copyfileobj(entrada, saida)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--artifact", required=True, help="diretório de um artifact baixado")
    p.add_argument("--campanha", required=True, help="deteccao ou corrigida")
    p.add_argument("--data", required=True, help="data da campanha, AAAA-MM-DD, no nome do diretório de logs")
    p.add_argument("--treated-dir", help="destino dos tratados; conferido contra a campanha")
    p.add_argument("--raiz", default=str(RAIZ_PADRAO), help=argparse.SUPPRESS)
    p.add_argument("--dry-run", action="store_true", help="confere e lista, sem escrever")
    args = p.parse_args(argv)

    try:
        plano = planejar(args)
    except Recusa as recusa:
        print("RECUSADO: %s" % recusa, file=sys.stderr)
        print("Nada foi gravado.", file=sys.stderr)
        return 1

    raiz = Path(args.raiz).resolve()
    rotulo = "conferido (dry-run)" if args.dry_run else "importado"
    gravados = []
    for origem, destino in plano:
        if not args.dry_run:
            try:
                copiar_exclusivo(origem, destino)
            except OSError as erro:
                # Desfaz o que ESTA execução gravou: importação parcial seria
                # lote pela metade sem sinal. FileExistsError cai aqui também —
                # o destino surgiu entre a conferência e a escrita.
                for g in gravados:
                    g.unlink()
                print("RECUSADO: falha ao gravar %s (%s: %s); %d arquivo(s) já gravado(s) "
                      "nesta execução foram removidos" % (destino, type(erro).__name__, erro, len(gravados)),
                      file=sys.stderr)
                return 1
            gravados.append(destino)
        print("%s: %s" % (rotulo, os.path.relpath(destino, raiz)))
    print("%d arquivo(s) %s" % (len(plano), rotulo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
