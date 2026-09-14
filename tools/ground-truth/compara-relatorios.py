#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
compara-relatorios.py — diferença NOMINAL entre dois relatórios JSON do
cruza-codeql.py.

    python3 tools/ground-truth/compara-relatorios.py <A.json> <B.json>

Existe para que nenhuma diferença entre dois estados seja apurada por
subtração de totais nem digitada à mão. Dois totais podem esconder trocas que
se compensam — foi o que produziu a explicação refutada da Fase P, em que
29 casamentos ganhos e 7 perdidos no catálogo atual se passaram por "+22".
Aqui toda diferença sai com os CVEs nomeados.

Três perguntas, cada uma com lista nominal:

  1. ground truth   o rótulo de cada CVE (explanation e CWEs) é o mesmo nos
                    dois relatórios? Trocas agrupadas por (antes -> depois).
  2. casamento      que CVEs casam só em A e só em B, agrupados pela
                    consulta que casou?
  3. persistência   dos que casam nos dois, quais mudaram de consulta ou de
                    relação entre os conjuntos de CWEs?

Relatório sem o campo `gt` — gerado antes de o cruza-codeql.py gravá-lo —
aborta: sem ele a pergunta 1 não tem resposta, e responder só as outras
duas deixaria "ground truth igual" presumido.
"""
from __future__ import annotations

import argparse
import json
import sys


def carregar(caminho):
    with open(caminho, encoding="utf-8") as f:
        r = json.load(f)
    if "gt" not in r or "por_relacao" not in r:
        print("ERRO: %s nao e relatorio do cruza-codeql.py com o campo gt."
              % caminho, file=sys.stderr)
        sys.exit(2)
    casados = {x["cve"]: {**x, "relacao": rel}
               for rel, lista in r["por_relacao"].items() for x in lista}
    return r, casados


def imprime_grupos(grupos, recuo="       "):
    """grupos: {rotulo: [cves]}, do maior para o menor, depois por rotulo."""
    for rotulo, cves in sorted(grupos.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print("%s%d  %s" % (recuo, len(cves), rotulo))
        print("%s   %s" % (recuo, " ".join(sorted(cves))))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a", help="relatório JSON do cruza-codeql.py (A)")
    ap.add_argument("b", help="relatório JSON do cruza-codeql.py (B)")
    args = ap.parse_args(argv)

    ra, ca = carregar(args.a)
    rb, cb = carregar(args.b)
    ga, gb = ra["gt"], rb["gt"]

    for nome, r in (("A", ra), ("B", rb)):
        print("--- %s: [%s]" % (nome, r.get("rotulo") or "sem rotulo"))
        print("      ground truth: %s" % r.get("fonte_ground_truth"))
        print("      consultas   : %s" % r["consultas_dir"])
    print()

    # 1. ground truth
    so_a, so_b = sorted(set(ga) - set(gb)), sorted(set(gb) - set(ga))
    trocas = {}
    for cve in sorted(set(ga) & set(gb)):
        x, y = ga[cve], gb[cve]
        if x != y:
            rotulo = '"%s" %s  ->  "%s" %s' % (
                x["explanation"], x["cwes"] or "-",
                y["explanation"], y["cwes"] or "-")
            trocas.setdefault(rotulo, []).append(cve)
    print("  1. ground truth")
    print("     CVEs em A: %d | em B: %d | nos dois: %d"
          % (len(ga), len(gb), len(set(ga) & set(gb))))
    print("     so em A: %d %s" % (len(so_a), " ".join(so_a)))
    print("     so em B: %d %s" % (len(so_b), " ".join(so_b)))
    print("     nos dois, com rotulo diferente: %d"
          % sum(len(v) for v in trocas.values()))
    imprime_grupos(trocas)
    print()

    # 2. casamento
    print("  2. casamento")
    print("     casados em A: %d | em B: %d" % (len(ca), len(cb)))
    for nome, lista, c in (("A", sorted(set(ca) - set(cb)), ca),
                           ("B", sorted(set(cb) - set(ca)), cb)):
        print("     casados so em %s: %d" % (nome, len(lista)))
        grupos = {}
        for cve in lista:
            grupos.setdefault(c[cve]["arquivo"], []).append(cve)
        imprime_grupos(grupos)
    print()

    # 3. persistência
    ambos = sorted(set(ca) & set(cb))
    mud_q, mud_r = {}, {}
    for cve in ambos:
        if ca[cve]["arquivo"] != cb[cve]["arquivo"]:
            mud_q.setdefault("%s -> %s" % (ca[cve]["arquivo"], cb[cve]["arquivo"]),
                             []).append(cve)
        if ca[cve]["relacao"] != cb[cve]["relacao"]:
            mud_r.setdefault("%s -> %s" % (ca[cve]["relacao"], cb[cve]["relacao"]),
                             []).append(cve)
    print("  3. casados nos dois: %d" % len(ambos))
    print("     com consulta diferente: %d" % sum(len(v) for v in mud_q.values()))
    imprime_grupos(mud_q)
    print("     com relacao diferente: %d" % sum(len(v) for v in mud_r.values()))
    imprime_grupos(mud_r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
