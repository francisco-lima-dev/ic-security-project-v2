#!/usr/bin/env python3
"""Passada de extensoes sobre o conjunto do benchmark (Fase H, item H0).

Emite a distribuicao COMPLETA de extensoes do campo FilePath e, dela,
os candidatos a CVE de TypeScript para a lista cves-sast-fumaca.

Aceita duas formas de entrada:
  - CSV com cabecalho: localiza a coluna pelo nome (FilePath, file_path,
    filepath), case-insensitive;
  - lista sem cabecalho no formato de seis campos do projeto
    (CVE,URL,PrePatchCommit,CWEs,FilePath,FileLine): usa a 5a coluna.

Nao normaliza, nao corrige e nao descarta linha alguma: linha que nao
tenha o numero de campos esperado e reportada e a saida termina com
codigo nao nulo.

Uso:
    python3 extensoes.py <arquivo.csv>
"""

import csv
import os
import sys
from collections import Counter

CAMPOS_LISTA = ["CVE", "URL", "PrePatchCommit", "CWEs", "FilePath", "FileLine"]
NOMES_FILEPATH = {"filepath", "file_path", "file path", "path", "arquivo"}
EXT_TS = {".ts", ".tsx", ".mts", ".cts"}
SEM_EXTENSAO = "(sem extensao)"


def extensao(caminho):
    """Extensao em minusculas do basename, ou SEM_EXTENSAO.

    '.d.ts' nao e tratado aqui como extensao propria: splitext devolve
    '.ts', e a distincao entre modulo e declaracao e feita a parte, por
    basename, para que a distribuicao nao invente categoria.
    """
    base = os.path.basename(caminho.strip())
    _, ext = os.path.splitext(base)
    if not ext or base.startswith(".") and base.count(".") == 1:
        return SEM_EXTENSAO
    return ext.lower()


def e_declaracao(caminho):
    return os.path.basename(caminho.strip()).lower().endswith(".d.ts")


def carregar(caminho_csv):
    """Devolve (linhas, origem_da_coluna) onde linhas e uma lista de
    dicionarios com as chaves 'cve' e 'filepath'."""
    with open(caminho_csv, newline="", encoding="utf-8") as fh:
        amostra = fh.read()
    if not amostra.endswith("\n"):
        print("AVISO: arquivo nao termina com quebra de linha final.",
              file=sys.stderr)

    leitor = list(csv.reader(amostra.splitlines()))
    if not leitor:
        raise SystemExit("ERRO: arquivo vazio.")

    cabecalho = [c.strip().lower() for c in leitor[0]]
    tem_cabecalho = any(c in NOMES_FILEPATH for c in cabecalho)

    linhas, defeituosas = [], []
    if tem_cabecalho:
        i_fp = next(i for i, c in enumerate(cabecalho) if c in NOMES_FILEPATH)
        i_cve = next((i for i, c in enumerate(cabecalho)
                      if c in {"cve", "cve_id", "id"}), 0)
        origem = f"coluna '{leitor[0][i_fp]}' (indice {i_fp}), por cabecalho"
        corpo = leitor[1:]
    else:
        i_fp, i_cve = 4, 0
        origem = "5o campo, formato de seis campos sem cabecalho"
        corpo = leitor

    largura = max(i_fp, i_cve) + 1
    for n, linha in enumerate(corpo, start=2 if tem_cabecalho else 1):
        if len(linha) < largura:
            defeituosas.append((n, linha))
            continue
        if not tem_cabecalho and len(linha) != len(CAMPOS_LISTA):
            defeituosas.append((n, linha))
            continue
        linhas.append({"cve": linha[i_cve].strip(),
                       "filepath": linha[i_fp].strip()})
    return linhas, origem, defeituosas


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    linhas, origem, defeituosas = carregar(sys.argv[1])

    print(f"Fonte da coluna: {origem}")
    print(f"Registros lidos: {len(linhas)}")
    cves = [l["cve"] for l in linhas]
    print(f"CVEs distintos: {len(set(cves))}")
    if len(set(cves)) != len(cves):
        dups = [c for c, n in Counter(cves).items() if n > 1]
        print(f"AVISO: CVE repetido: {', '.join(sorted(dups))}")

    dist = Counter(extensao(l["filepath"]) for l in linhas)
    total = sum(dist.values())
    print("\n== Distribuicao de extensoes (todos os registros) ==")
    largura = max((len(e) for e in dist), default=0)
    for ext, n in sorted(dist.items(), key=lambda kv: (-kv[1], kv[0])):
        pct = 100.0 * n / total if total else 0.0
        print(f"  {ext:<{largura}}  {n:>4}  {pct:5.1f}%")
    print(f"  {'TOTAL':<{largura}}  {total:>4}")
    if total != len(linhas):
        print("INCOERENTE: soma da distribuicao difere do total de registros.")
        return 1

    print("\n== Registros sem extensao ==")
    sem = [l for l in linhas if extensao(l["filepath"]) == SEM_EXTENSAO]
    if not sem:
        print("  nenhum")
    for l in sorted(sem, key=lambda l: l["cve"]):
        print(f"  {l['cve']}  {l['filepath']}")

    print("\n== Candidatos a CVE de TypeScript ==")
    cand = [l for l in linhas if extensao(l["filepath"]) in EXT_TS]
    aptos = [l for l in cand if not e_declaracao(l["filepath"])]
    excl = [l for l in cand if e_declaracao(l["filepath"])]
    print(f"  extensao de TypeScript: {len(cand)}")
    print(f"  aptos (modulo):         {len(aptos)}")
    print(f"  excluidos (.d.ts):      {len(excl)}")
    for rotulo, grupo in (("APTO", aptos), ("EXCLUIDO .d.ts", excl)):
        for l in sorted(grupo, key=lambda l: l["cve"]):
            print(f"  [{rotulo}] {l['cve']}  {l['filepath']}")
    if not aptos:
        print("\n  NENHUM CANDIDATO APTO. A verificacao do extrator de "
              "TypeScript atravessando o laco nao fecha com este conjunto, "
              "e isso deve ser declarado, nao contornado.")

    if defeituosas:
        print(f"\n== Linhas com numero de campos inesperado: "
              f"{len(defeituosas)} ==")
        for n, linha in defeituosas:
            print(f"  linha {n}: {len(linha)} campos: {linha}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
