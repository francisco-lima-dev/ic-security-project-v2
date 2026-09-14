#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cruza-codeql.py — coteja o ground truth do OpenSSF CVE Benchmark contra o
catálogo de consultas JavaScript do CodeQL, num commit FIXADO.

    python3 tools/ground-truth/cruza-codeql.py <dir-consultas> [--rotulo X]
                                              [--json F] [--csv F] [--clone D]
                                              [--gt-json D]

É a reconstrução do cotejo que produziu o achado mais forte do estudo — que
`explanation` e `CWEs` do ground truth foram herdados da consulta do CodeQL
que identificou o caso — e que até esta fase era o único achado que um
terceiro não reproduzia.

ESCOLHA DE LINGUAGEM, declarada: Python, e não Node como o script de
controle. O cotejo principal não precisa de parser YAML — lê CSV e o
cabeçalho QLDoc dos `.ql`, ambos com a biblioteca padrão —, então escrevê-lo
em Python elimina a dependência de `node_modules` para a metade que carrega
o achado. O controle permanece em Node por outro motivo, declarado lá.

FONTE DO GROUND TRUTH. Por padrão, o CSV versionado, que corresponde ao
benchmark no commit do clone conferido — não ao commit do release. Com
`--gt-json`, uma pasta `CVEs/` do benchmark em qualquer estado — o anterior
ao release e o do próprio release, que o obter-catalogos.sh materializa.
Nesse modo não há equivalência a conferir: a fonte é o próprio JSON.

Leitura do JSON, e o que aborta:
  - as weaknesses vêm de `prePatch.weaknesses`; na ausência de `prePatch`,
    de `patchBase.weaknesses`, forma mais antiga do schema, que o estado
    prévio ao release ainda usa em um CVE. Sem nenhuma das duas chaves:
    ABORTA — tratar como "sem weakness" seria artefato de formato;
  - explanation distintas entre weaknesses do mesmo CVE: ABORTA, porque o
    CSV tem uma por CVE e escolher uma em silêncio mudaria o casamento;
  - CVE repetido, ou campo `CVE` diferente do nome do arquivo: ABORTA;
  - lista de weaknesses vazia, ou todas com explanation vazia: o CVE entra
    com explanation vazia, não casa, e é LISTADO — é ausência de rótulo,
    não ambiguidade.

CRITÉRIO DE CASAMENTO — e por que não é subcadeia.
Duas medidas, ambas reportadas:

  exato        igualdade byte a byte, após `strip()`
  normalizado  minúsculas, acentos removidos, tudo que não é alfanumérico
               vira espaço, espaços colapsados

O normalizado é a medida de manchete. A normalização é EQUIVALENTE à do
script de controle sobre este ground truth, não idêntica em geral: aqui a
decomposição NFD vem antes das minúsculas e sai toda a categoria Mn; lá as
minúsculas vêm antes e sai só a faixa U+0300–U+036F. Sobre ASCII as duas
coincidem, e as 223 `explanation` são ASCII (conferido em 13/09/2026). O
exato é reportado junto para que se saiba quanto da correspondência vem de
diferença de pontuação ou caixa, e quanto é identidade literal. Explanation
cuja chave normalizada é vazia não casa com nada.

NUNCA subcadeia. O CLAUDE.md registra que os 17% obtidos por subcadeia no
controle do Semgrep eram termos genéricos — "cross site scripting" — dentro
de descrições sobre outra coisa. Subcadeia mede vocabulário compartilhado,
não herança.

ESCOPO DO CATÁLOGO, declarado: todo `.ql` sob o diretório dado, INCLUSIVE
`experimental/`. O relatório conta quantos casamentos vêm de consulta
experimental. No catálogo atual são 3, por `experimental/Security/CWE-918/
SSRF.ql`, que herdou o @name de `Security/CWE-918/RequestForgery.ql` de 2020.

CWE: normalizado para três dígitos DOS DOIS LADOS. O ground truth tem CVEs
com CWE sem zero à esquerda, e o catálogo do CodeQL grava a tag em
minúsculas (`external/cwe/cwe-079`). Comparar sem normalizar produziria
divergência que é do formato, não do dado.

TAG FORA DA FORMA CANÔNICA: só `external/cwe/cwe-NNN` entra no conjunto da
consulta. Qualquer outra grafia começada por `external/cwe` é LISTADA no
relatório, nunca descartada em silêncio. Em dezembro de 2020 há exatamente
uma, `external/cwe-295`, em `Security/CWE-295/DisablingCertificateValidation.ql`
— a consulta cujo @name casa o CVE-2018-1000096, único do benchmark sem CWE.
Com a tag fora do conjunto, esse CVE sai "identico" com os dois conjuntos
vazios; o relatório conta essas identidades vazias à parte.

CONJUNTO VAZIO, decisão declarada: CVE sem CWE contra consulta COM tags é
"divergente", e não "gt_subconjunto_da_consulta", embora o vazio seja
subconjunto de todo conjunto — conjunto vazio não afirma herança parcial de
coisa alguma. É o que separa 108/74/3 de 108/75/2 no catálogo atual; o
relatório imprime também a contagem com o vazio tratado como subconjunto.

EQUIVALÊNCIA CSV × BENCHMARK: quando o ground truth vem do CSV e o clone do
benchmark está presente, a equivalência é CONFERIDA — explanation de todas
as weaknesses e conjunto canônico de CWEs, CVE a CVE — e divergência aborta.
Clone ausente gera aviso, não presunção silenciosa.

O relatório JSON grava o rótulo de TODO CVE do ground truth, casado ou não,
para que compara-relatorios.py nomeie diferenças entre dois estados sem
recorrer a subtração de totais.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import unicodedata
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent.parent
CSV_PADRAO = RAIZ / "datasets" / "cve-metadata.csv"
CLONE_PADRAO = RAIZ / "ossf-cve-benchmark" / "CVEs"


def chave(texto):
    """Normalização de texto; equivalente à do controle sobre ASCII."""
    t = unicodedata.normalize("NFD", str(texto)).lower()
    t = "".join(c for c in t if unicodedata.category(c) != "Mn")
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return t.strip()


def cwe_canonico(bruto):
    """CWE-79, cwe-079, external/cwe/cwe-79 -> CWE-079."""
    m = re.search(r"(\d+)\s*$", str(bruto).strip())
    if not m:
        return None
    return "CWE-%03d" % int(m.group(1))


def ler_ground_truth(caminho):
    """Lê os 223 CVEs do CSV versionado.

    Lido com o módulo csv, não com split(','): o campo Explanation de sete
    CVEs de Zip Slip contém aspas, escapadas por duplicação conforme a
    RFC 4180, e um split ingênuo os quebraria.
    """
    registros = []
    with open(caminho, encoding="utf-8", newline="") as f:
        for linha in csv.DictReader(f):
            cwes = {cwe_canonico(c) for c in (linha["CWEs"] or "").split(",")}
            registros.append({
                "cve": linha["CVE"].strip(),
                "explanation": (linha["Explanation"] or "").strip(),
                "cwes": {c for c in cwes if c},
            })
    return registros


def ler_ground_truth_json(pasta):
    """Lê o ground truth de uma pasta CVEs/ do benchmark.

    Devolve (registros, problemas, sem_explanation, forma_antiga). Ver
    "Leitura do JSON" no docstring do módulo para o que é problema (aborta)
    e o que é listado.
    """
    registros, problemas, sem_explanation, forma_antiga = [], [], [], []
    vistos = set()
    for arq in sorted(Path(pasta).glob("*.json")):
        d = json.loads(arq.read_text(encoding="utf-8"))
        cve = str(d.get("CVE") or "").strip()
        if cve != arq.stem:
            problemas.append("%s: campo CVE %r difere do nome do arquivo"
                             % (arq.name, cve))
            continue
        if cve in vistos:
            problemas.append("%s: CVE repetido" % cve)
            continue
        vistos.add(cve)
        if "prePatch" in d:
            base = d["prePatch"]
        elif "patchBase" in d:
            base = d["patchBase"]
            forma_antiga.append(cve)
        else:
            problemas.append("%s: sem prePatch nem patchBase" % cve)
            continue
        weaknesses = (base or {}).get("weaknesses") or []
        exps = {(w.get("explanation") or "").strip() for w in weaknesses} - {""}
        if len(exps) > 1:
            problemas.append("%s: %d explanation distintas" % (cve, len(exps)))
            continue
        if not exps:
            sem_explanation.append(cve)
        cwes = {cwe_canonico(x) for x in (d.get("CWEs") or [])} - {None}
        registros.append({
            "cve": cve,
            "explanation": exps.pop() if exps else "",
            "cwes": cwes,
        })
    return registros, problemas, sem_explanation, forma_antiga


def conferir_clone(gt, pasta):
    """Confere o CSV contra os JSON do clone do benchmark.

    Devolve o número de CVEs conferidos, None se o clone está ausente, e -1
    se há divergência (já reportada no stderr). Pasta presente sem JSON algum
    é divergência — os 223 ficam "só no CSV" —, não conferência vazia.
    """
    p = Path(pasta)
    if not p.is_dir():
        print("AVISO: clone do benchmark ausente em %s; equivalencia CSV x "
              "JSON NAO conferida." % pasta, file=sys.stderr)
        return None
    do_csv = {c["cve"]: c for c in gt}
    difs, so_clone, vistos = [], [], set()
    for arq in sorted(p.glob("*.json")):
        d = json.loads(arq.read_text(encoding="utf-8"))
        cve = d["CVE"]
        vistos.add(cve)
        if cve not in do_csv:
            so_clone.append(cve)
            continue
        exps = {(w.get("explanation") or "").strip()
                for w in d["prePatch"]["weaknesses"]}
        cwes = {cwe_canonico(x) for x in (d.get("CWEs") or [])} - {None}
        c = do_csv[cve]
        if exps != {c["explanation"]}:
            difs.append("%s explanation csv=%r json=%r"
                        % (cve, c["explanation"], sorted(exps)))
        if cwes != c["cwes"]:
            difs.append("%s CWEs csv=%s json=%s"
                        % (cve, sorted(c["cwes"]), sorted(cwes)))
    so_csv = sorted(set(do_csv) - vistos)
    if difs or so_clone or so_csv:
        print("ERRO: CSV e clone do benchmark divergem: %d diferenca(s), "
              "%d so no clone, %d so no CSV. O cotejo nao vale."
              % (len(difs), len(so_clone), len(so_csv)), file=sys.stderr)
        for x in (difs + ["so no clone: " + c for c in so_clone]
                  + ["so no CSV: " + c for c in so_csv])[:10]:
            print("  " + x, file=sys.stderr)
        return -1
    return len(vistos)


def ler_consultas(diretorio):
    """Extrai @name e tags external/cwe/ do cabeçalho QLDoc de cada .ql."""
    consultas = []
    for ql in sorted(Path(diretorio).rglob("*.ql")):
        texto = ql.read_text(encoding="utf-8", errors="replace")
        bloco = re.search(r"/\*\*(.*?)\*/", texto, re.S)
        if not bloco:
            continue
        cab = bloco.group(1)
        # @name pode ocupar mais de uma linha; termina na próxima diretiva.
        m = re.search(r"^\s*\*?\s*@name\s+(.*?)(?=^\s*\*?\s*@|\Z)",
                      cab, re.S | re.M)
        if not m:
            continue
        nome = re.sub(r"^\s*\*\s?", "", m.group(1), flags=re.M)
        nome = re.sub(r"\s+", " ", nome).strip()
        cwes = {cwe_canonico(t) for t in
                re.findall(r"external/cwe/cwe-(\d+)", cab)}
        nao_canonicas = [t for t in re.findall(r"external/cwe\S*", cab)
                         if not re.match(r"external/cwe/cwe-\d+", t)]
        consultas.append({
            "arquivo": str(Path(ql).relative_to(diretorio)),
            "nome": nome,
            "cwes": {c for c in cwes if c},
            "tags_nao_canonicas": nao_canonicas,
        })
    return consultas


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("consultas", help="diretório com as consultas .ql")
    ap.add_argument("--csv", default=str(CSV_PADRAO))
    ap.add_argument("--clone", default=str(CLONE_PADRAO),
                    help="pasta CVEs/ do clone do benchmark, para conferir "
                         "a equivalência com o CSV")
    ap.add_argument("--gt-json",
                    help="lê o ground truth desta pasta CVEs/ em vez do CSV "
                         "(ex.: benchmark anterior ao release, ou no release)")
    ap.add_argument("--rotulo", default="", help="rótulo do estado cotejado")
    ap.add_argument("--json", help="grava o relatório também em JSON")
    args = ap.parse_args(argv)

    if args.gt_json:
        gt, problemas, sem_explanation, forma_antiga = \
            ler_ground_truth_json(args.gt_json)
        if problemas:
            print("ERRO: ground truth em %s com %d CVE(s) problematico(s):"
                  % (args.gt_json, len(problemas)), file=sys.stderr)
            for p in problemas[:10]:
                print("  " + p, file=sys.stderr)
            return 2
        if not gt:
            print("ERRO: nenhum CVE lido em %s" % args.gt_json, file=sys.stderr)
            print("  Zero aqui e 'nao perguntei', nao 'nao ha'.", file=sys.stderr)
            return 2
        fonte = args.gt_json
        equivalencia = "nao_se_aplica"
    else:
        gt = ler_ground_truth(args.csv)
        sem_explanation, forma_antiga = [], []
        fonte = args.csv
        equivalencia = conferir_clone(gt, args.clone)
        if equivalencia == -1:
            return 2
    qs = ler_consultas(args.consultas)
    if not qs:
        print("ERRO: nenhuma consulta .ql lida em %s" % args.consultas,
              file=sys.stderr)
        print("  Zero aqui e 'nao perguntei', nao 'nao ha'.", file=sys.stderr)
        return 2

    por_chave, por_exato = {}, {}
    for q in qs:
        por_chave.setdefault(chave(q["nome"]), q)
        por_exato.setdefault(q["nome"], q)

    casados, sem_casar = [], []
    for c in gt:
        k = chave(c["explanation"])
        q = por_chave.get(k) if k else None
        if q is None:
            sem_casar.append(c)
            continue
        if c["cwes"] == q["cwes"]:
            rel = "identico"
        elif c["cwes"] and c["cwes"] < q["cwes"]:
            # Vazio contra não vazio NÃO entra aqui: ver CONJUNTO VAZIO.
            rel = "gt_subconjunto_da_consulta"
        elif q["cwes"] and q["cwes"] < c["cwes"]:
            rel = "consulta_subconjunto_do_gt"
        else:
            rel = "divergente"
        casados.append({**c, "consulta": q, "relacao": rel})

    exatos = sum(1 for c in gt if c["explanation"] and c["explanation"] in por_exato)
    conta = {}
    for c in casados:
        conta[c["relacao"]] = conta.get(c["relacao"], 0) + 1
    identicos_vazios = sorted(c["cve"] for c in casados
                              if c["relacao"] == "identico" and not c["cwes"])
    vazio_contra_tags = sorted(c["cve"] for c in casados
                               if c["relacao"] == "divergente"
                               and not c["cwes"] and c["consulta"]["cwes"])
    via_experimental = sorted(c["cve"] for c in casados
                              if c["consulta"]["arquivo"].startswith("experimental/"))
    nao_canonicas = [(q["arquivo"], t) for q in qs
                     for t in q["tags_nao_canonicas"]]

    rot = (" [%s]" % args.rotulo) if args.rotulo else ""
    print("--- cotejo ground truth x CodeQL%s ---" % rot)
    print("  consultas: %s" % args.consultas)
    print("  ground truth: %s" % fonte)
    print("  .ql lidos com @name: %d | com tag external/cwe/: %d"
          % (len(qs), sum(1 for q in qs if q["cwes"])))
    print("  CVEs no ground truth: %d" % len(gt))
    print("  CVEs sem explanation (nao casam): %d %s"
          % (len(sem_explanation), sem_explanation or ""))
    print("  CVEs em forma antiga do schema (patchBase): %d %s"
          % (len(forma_antiga), forma_antiga or ""))
    if equivalencia == "nao_se_aplica":
        print("  equivalencia CSV x clone do benchmark: nao se aplica "
              "(ground truth lido do JSON)")
    elif equivalencia is None:
        print("  equivalencia CSV x clone do benchmark: NAO CONFERIDA (clone ausente)")
    else:
        print("  equivalencia CSV x clone do benchmark: CONFERIDA em %d CVEs"
              % equivalencia)
    print()
    print("  explanation identica ao @name de consulta:")
    print("     normalizado : %d de %d (%.1f%%)"
          % (len(casados), len(gt), 100.0 * len(casados) / len(gt)))
    print("     exato       : %d de %d (%.1f%%)"
          % (exatos, len(gt), 100.0 * exatos / len(gt)))
    print("     via consulta experimental/: %d %s"
          % (len(via_experimental), via_experimental or ""))
    print()
    print("  dos casados, relacao entre o conjunto CWEs do benchmark e as")
    print("  tags external/cwe/ da consulta:")
    for rel in ("identico", "gt_subconjunto_da_consulta",
                "consulta_subconjunto_do_gt", "divergente"):
        print("     %-28s %d" % (rel, conta.get(rel, 0)))
    print("     identicos com os dois conjuntos vazios: %d %s"
          % (len(identicos_vazios), identicos_vazios or ""))
    print("     com vazio tratado como subconjunto: gt_subconjunto %d, "
          "divergente %d"
          % (conta.get("gt_subconjunto_da_consulta", 0) + len(vazio_contra_tags),
             conta.get("divergente", 0) - len(vazio_contra_tags)))
    print()
    print("  tags external/cwe fora da forma canonica (fora do conjunto): %d"
          % len(nao_canonicas))
    for arquivo, tag in nao_canonicas:
        print("     %s  %s" % (arquivo, tag))
    print()

    # Lista NOMINAL. Divergência contada e não nomeada não é verificável.
    for rel in ("divergente", "consulta_subconjunto_do_gt",
                "gt_subconjunto_da_consulta"):
        lista = [c for c in casados if c["relacao"] == rel]
        if not lista:
            continue
        print("  --- %s (%d), nominal:" % (rel, len(lista)))
        for c in sorted(lista, key=lambda x: x["cve"]):
            print("     %s  gt=%s  consulta=%s  [%s]"
                  % (c["cve"], sorted(c["cwes"]) or "-",
                     sorted(c["consulta"]["cwes"]) or "-",
                     c["consulta"]["arquivo"]))
        print()

    print("  --- sem casar (%d), nominal:" % len(sem_casar))
    for c in sorted(sem_casar, key=lambda x: x["cve"]):
        print("     %s  \"%s\"" % (c["cve"], c["explanation"][:90]))

    if args.json:
        Path(args.json).write_text(json.dumps({
            "rotulo": args.rotulo,
            "consultas_dir": args.consultas,
            "fonte_ground_truth": fonte,
            "ql_lidos": len(qs),
            "ql_com_cwe": sum(1 for q in qs if q["cwes"]),
            "cves": len(gt),
            "gt_sem_explanation": sem_explanation,
            "gt_forma_antiga": forma_antiga,
            "equivalencia_clone_cves": equivalencia,
            "casados_normalizado": len(casados),
            "casados_exato": exatos,
            "casados_via_experimental": via_experimental,
            "relacao_cwes": conta,
            "identicos_vazios": identicos_vazios,
            "vazio_contra_tags": vazio_contra_tags,
            "tags_nao_canonicas": [{"arquivo": a, "tag": t}
                                   for a, t in nao_canonicas],
            "sem_casar": [c["cve"] for c in sorted(sem_casar, key=lambda x: x["cve"])],
            "por_relacao": {
                rel: [{"cve": c["cve"], "gt": sorted(c["cwes"]),
                       "consulta": sorted(c["consulta"]["cwes"]),
                       "arquivo": c["consulta"]["arquivo"]}
                      for c in sorted(casados, key=lambda x: x["cve"])
                      if c["relacao"] == rel]
                for rel in conta},
            "gt": {c["cve"]: {"explanation": c["explanation"],
                              "cwes": sorted(c["cwes"])}
                   for c in sorted(gt, key=lambda x: x["cve"])},
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("\n  relatorio JSON: %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
