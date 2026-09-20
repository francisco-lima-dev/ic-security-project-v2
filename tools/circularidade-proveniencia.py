#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
circularidade-proveniencia.py — parte o denominador do cruzamento pela
PROVENIÊNCIA da etiqueta de CWE e compara a taxa de acerto das três
ferramentas em cada grupo, nos sete níveis.

    python3 tools/circularidade-proveniencia.py <relatorio-proveniencia.json>...
                                                [--matriz F] [--json F]

MEDE UMA AMEAÇA À VALIDADE, não um resultado de detecção. Os níveis 2 e 4 do
cruzamento dependem de casamento de CWE, e o cotejo de proveniência
estabeleceu que a maior parte das etiquetas de CWE do benchmark foi herdada
da consulta do CodeQL que identificou o caso. O CodeQL é, nesses níveis,
medido contra etiquetas derivadas dele próprio. Este script parte o
denominador em dois grupos — herdado e não herdado — e emite a tabela
ferramenta x nível x grupo que permite ler se a vantagem do CodeQL varia com
a proveniência da etiqueta.

O QUE ESTE SCRIPT NÃO FAZ, deliberadamente:

  - NÃO conclui pela circularidade nem contra ela. Emite a tabela e as
    diferenças aritméticas entre grupos; a leitura é do texto.
  - NÃO aplica teste estatístico algum. Os grupos são de tamanhos muito
    desiguais (161 contra 59 no denominador, sob a referência `ec573b51`;
    MEDIDO, não estimado — os 163 casados do cotejo incluem dois CVEs que
    o denominador exclui), e toda taxa sai acompanhada de
    numerador e denominador justamente para que ninguém leia ponto
    percentual isolado no grupo menor.
  - NÃO recomputa o cruzamento nem o cotejo de proveniência. Lê a matriz
    versionada de `results/cruzamento/` e o relatório JSON do
    `tools/ground-truth/cruza-codeql.py`, que é quem detém o critério de
    casamento. Reimplementar o critério aqui criaria uma segunda versão dele
    para divergir da primeira.
  - NÃO calcula precisão nem nada que use achado fora do arquivo do ground
    truth como denominador, pela razão da secao 1 de docs/criterios-cruzamento.md.

PARTIÇÃO. O relatório do cotejo emite `por_relacao` (os casados, por relação
entre os conjuntos de CWE) e `sem_casar` (os que não casam). A partição é
essa, e não é inferida:

  grupo HERDADO      CVE cuja `explanation` casa o `@name` de uma consulta do
                     CodeQL no estado fixado, isto é, todo CVE de `por_relacao`
  grupo NAO_HERDADO  todo CVE de `sem_casar`

RESSALVA QUE A PARTIÇÃO CARREGA, e que vai ao texto: o `CVE-2018-1000096` sai
"identico" no cotejo com os DOIS conjuntos de CWE vazios — casamento de
`explanation` sem etiqueta alguma a herdar. Ele já está fora do denominador
do cruzamento por não ter CWE, então não contamina nenhum número daqui; o
script o nomeia para que a coincidência não passe por herança de etiqueta.

VALIDAÇÃO ESTRUTURAL FATAL, antes de qualquer número: os dois grupos têm de
ser disjuntos, cobrir os 223 CVEs do ground truth, e somar EXATAMENTE o
denominador de 220 depois das três exclusões nominadas. Partição que não
particiona invalida tudo o que vem depois, e o script para.

ZERO EXIGE CONTROLE. A regra geral do projeto — zero indistinguível de falha
não é resultado — vale aqui com força, porque uma célula vazia da tabela é
exatamente o que uma partição errada produziria. O caminho de contagem é
exercido contra fixture sintética de contagem conhecida ANTES de tocar o
conjunto real, e toda célula que sair zero é nomeada no relatório com o
controle que a sustenta.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
MATRIZ_PADRAO = RAIZ / "results" / "cruzamento" / "matriz-deteccao.csv"
SAIDA_VERSIONADA = RAIZ / "results" / "circularidade"

# Ordem fixa. Os níveis 1 e 3 não usam CWE e são o controle interno da
# análise: diferença entre grupos que apareça neles não pode ser
# circularidade de etiqueta.
NIVEIS = [
    ("nivel_0", "nivel 0  (achado na arvore)", False),
    ("nivel_1", "nivel 1  (arquivo)", False),
    ("nivel_2_generosa", "nivel 2  generosa (arquivo+CWE)", True),
    ("nivel_2_estrita", "nivel 2  estrita  (arquivo+CWE)", True),
    ("nivel_3", "nivel 3  (arquivo+linha)", False),
    ("nivel_4_generosa", "nivel 4  generosa (arq+linha+CWE)", True),
    ("nivel_4_estrita", "nivel 4  estrita  (arq+linha+CWE)", True),
]
# Só as variantes estritas têm terceira parcela.
ESTRITAS = {"nivel_2_estrita", "nivel_4_estrita"}
FERRAMENTAS = ["codeql", "semgrep", "snyk-code"]
# Os tres CVEs que o `docs/criterios-cruzamento.md` tira do denominador, por
# nome. Ancoram a leitura da matriz: contagem que bate com o total errado
# pelos CVEs errados nao e contagem que bate.
EXCLUSOES_ESPERADAS = {"CVE-2016-1000229", "CVE-2018-1000096", "CVE-2018-8035"}


def rotulo_caminho(caminho):
    """Caminho relativo ao repositorio quando estiver dentro dele; absoluto,
    caso contrario. Mesma funcao do `cruza-deteccao.py`, e pelo mesmo motivo:
    caminho da maquina do operador nao vai para JSON versionado."""
    caminho = Path(caminho).resolve()
    try:
        return str(caminho.relative_to(RAIZ))
    except ValueError:
        return str(caminho)


def sha256(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 16), b""):
            h.update(bloco)
    return h.hexdigest()


def booleano(valor, campo, cve, ferramenta):
    """'true'/'false' e nada mais. Campo vazio dentro do denominador é
    defeito da matriz, e vira erro nomeado em vez de virar False em
    silêncio."""
    if valor == "true":
        return True
    if valor == "false":
        return False
    return "ERRO: %s=%r em (%s, %s); esperado true ou false" % (
        campo, valor, cve, ferramenta)


def ler_matriz(caminho):
    """Lê a matriz do cruzamento. Devolve (linhas, erros)."""
    erros = []
    with open(caminho, encoding="utf-8") as f:
        linhas = list(csv.DictReader(f))
    if not linhas:
        erros.append("ERRO: matriz %s sem linhas. Zero aqui e 'nao perguntei', "
                     "nao 'nao ha'." % caminho)
        return [], erros
    faltando = [c for c in ("cve", "ferramenta", "no_denominador",
                            "estrita_aplicavel", "tratado_presente",
                            "gt_cwe_primary", "gt_cwes",
                            "motivo_fora_denominador", "status_campanha")
                + tuple(n for n, _, _ in NIVEIS)
                if c not in linhas[0]]
    if faltando:
        erros.append("ERRO: matriz sem as colunas %s" % faltando)
        return linhas, erros

    vistos = collections.Counter()
    for r in linhas:
        vistos[(r["cve"], r["ferramenta"])] += 1
        if r["ferramenta"] not in FERRAMENTAS:
            erros.append("ERRO: ferramenta desconhecida %r em %s"
                         % (r["ferramenta"], r["cve"]))
    repetidos = sorted(k for k, n in vistos.items() if n > 1)
    if repetidos:
        erros.append("ERRO: pares (cve, ferramenta) repetidos: %s"
                     % repetidos[:10])
    cves = sorted({r["cve"] for r in linhas})
    por_cve = collections.defaultdict(list)
    for r in linhas:
        por_cve[r["cve"]].append(r)
    # Campos de GROUND TRUTH: iguais nas tres ferramentas, por construcao da
    # matriz. A distribuicao de CWE adiante le so a linha do codeql, e a
    # composicao por grupo depende do denominador ser o mesmo nas tres. O
    # script CONFERE em vez de supor — divergencia aqui faria a distribuicao
    # sair de uma ferramenta e a tabela de outra, sem sinal algum.
    GT = ("gt_cwes", "gt_cwe_primary", "no_denominador",
          "motivo_fora_denominador", "estrita_aplicavel")
    for cve in cves:
        presentes = sorted(r["ferramenta"] for r in por_cve[cve])
        if presentes != sorted(FERRAMENTAS):
            erros.append("ERRO: %s nao tem uma linha por ferramenta: %s"
                         % (cve, presentes))
            continue
        distintos = {tuple(r[c] for c in GT) for r in por_cve[cve]}
        if len(distintos) > 1:
            erros.append("ERRO: %s tem campos de ground truth diferentes entre "
                         "ferramentas (%s): %s" % (cve, GT, sorted(distintos)))
    return linhas, erros


def ler_proveniencia(caminho):
    """Lê o relatório do cruza-codeql.py. NÃO reimplementa o casamento:
    consome `por_relacao` (casados) e `sem_casar`."""
    erros = []
    with open(caminho, encoding="utf-8") as f:
        rel = json.load(f)
    for chave in ("por_relacao", "sem_casar", "gt", "rotulo", "consultas_dir",
                  "casados_normalizado", "cves"):
        if chave not in rel:
            erros.append("ERRO: %s nao e relatorio do cruza-codeql.py: falta %r"
                         % (caminho, chave))
    if erros:
        return None, erros

    herdado = {}
    for relacao, lista in rel["por_relacao"].items():
        for item in lista:
            if item["cve"] in herdado:
                erros.append("ERRO: %s aparece em mais de uma relacao"
                             % item["cve"])
            herdado[item["cve"]] = {"relacao": relacao,
                                    "consulta": item["arquivo"],
                                    "gt": item["gt"],
                                    "consulta_cwes": item["consulta"]}
    nao_herdado = set(rel["sem_casar"])

    # O total de casados do relatório tem de bater com o que se leu de
    # `por_relacao`. Divergência aqui significa relatório inconsistente, e
    # nenhum número adiante valeria.
    if len(herdado) != rel["casados_normalizado"]:
        erros.append("ERRO: %s declara %d casados, `por_relacao` traz %d"
                     % (caminho, rel["casados_normalizado"], len(herdado)))
    return {"rotulo": rel["rotulo"] or Path(caminho).stem,
            "caminho": caminho,
            "consultas_dir": rel["consultas_dir"],
            "fonte_gt": rel.get("fonte_ground_truth", ""),
            "herdado": herdado,
            "nao_herdado": nao_herdado,
            "gt": rel["gt"],
            "identicos_vazios": rel.get("identicos_vazios", []),
            "cves": rel["cves"]}, erros


def validar_particao(prov, cves_matriz, cves_denominador, linhas_por_cve):
    """FATAL. Partição que não particiona invalida tudo o que vem depois."""
    erros = []
    herdado, nao_herdado = set(prov["herdado"]), set(prov["nao_herdado"])

    if prov["cves"] != len(prov["gt"]):
        erros.append("ERRO: o cotejo declara %d CVEs e o campo `gt` traz %d"
                     % (prov["cves"], len(prov["gt"])))
    inter = herdado & nao_herdado
    if inter:
        erros.append("ERRO: grupos nao disjuntos; %d CVE(s) nos dois: %s"
                     % (len(inter), sorted(inter)[:10]))
    uniao = herdado | nao_herdado
    gt = set(prov["gt"])
    if uniao != gt:
        erros.append("ERRO: a uniao dos grupos (%d) nao cobre o ground truth "
                     "do cotejo (%d); so na uniao: %s; so no gt: %s"
                     % (len(uniao), len(gt), sorted(uniao - gt)[:10],
                        sorted(gt - uniao)[:10]))
    if gt != cves_matriz:
        erros.append("ERRO: o ground truth do cotejo (%d CVEs) diverge dos "
                     "CVEs da matriz (%d); so no cotejo: %s; so na matriz: %s"
                     % (len(gt), len(cves_matriz),
                        sorted(gt - cves_matriz)[:10],
                        sorted(cves_matriz - gt)[:10]))

    # DUAS FONTES DO MESMO FATO, reconciliadas. O `gt_cwes` da matriz e o
    # `gt.cwes` do relatorio do cotejo descrevem o mesmo conjunto; se o
    # relatorio foi produzido com --gt-json sobre outro estado do benchmark,
    # a particao viria de um ground truth e as distribuicoes de outro, sem
    # sinal algum. Chaveado por CVE, nunca por ordem.
    for cve in sorted(gt & cves_matriz):
        da_matriz = frozenset(
            c for c in linhas_por_cve[(cve, "codeql")]["gt_cwes"].split("|") if c)
        do_cotejo = frozenset(prov["gt"][cve]["cwes"])
        if da_matriz != do_cotejo:
            erros.append("ERRO: %s tem gt_cwes divergente entre a matriz (%s) "
                         "e o relatorio do cotejo (%s)"
                         % (cve, sorted(da_matriz), sorted(do_cotejo)))

    h_den = herdado & cves_denominador
    n_den = nao_herdado & cves_denominador
    if h_den & n_den:
        erros.append("ERRO: grupos nao disjuntos dentro do denominador: %s"
                     % sorted(h_den & n_den)[:10])
    if len(h_den) + len(n_den) != len(cves_denominador):
        erros.append("ERRO: os grupos somam %d no denominador, e o "
                     "denominador e %d. Particao que nao particiona invalida "
                     "tudo o que vem depois."
                     % (len(h_den) + len(n_den), len(cves_denominador)))
    if (h_den | n_den) != cves_denominador:
        erros.append("ERRO: a uniao dos grupos no denominador nao e o "
                     "denominador; faltam %s; sobram %s"
                     % (sorted(cves_denominador - (h_den | n_den))[:10],
                        sorted((h_den | n_den) - cves_denominador)[:10]))
    return h_den, n_den, erros


def contar(linhas_por_cve, cves, ferramenta, nivel):
    """Conta acertos de uma ferramenta num nível, sobre um conjunto de CVEs.

    Devolve (acertos, nao_acertos, nao_se_aplica, erros). O `nao_se_aplica`
    só existe nas variantes estritas, onde `gt_cwe_primary` nulo torna a
    variante inaplicável ao CVE: contá-lo como nao-acerto imputaria a
    ferramenta uma falha que e do ground truth.
    """
    acertos = nao_acertos = nao_se_aplica = 0
    erros = []
    for cve in sorted(cves):
        r = linhas_por_cve[(cve, ferramenta)]
        if nivel in ESTRITAS:
            ap = booleano(r["estrita_aplicavel"], "estrita_aplicavel",
                          cve, ferramenta)
            if isinstance(ap, str):
                erros.append(ap)
                continue
            if not ap:
                nao_se_aplica += 1
                continue
        v = booleano(r[nivel], nivel, cve, ferramenta)
        if isinstance(v, str):
            erros.append(v)
            continue
        if v:
            acertos += 1
        else:
            nao_acertos += 1
    return acertos, nao_acertos, nao_se_aplica, erros


def taxa(acertos, base):
    """Percentual, ou None quando a base e zero. Nunca se imprime taxa sem o
    par numerador/denominador ao lado."""
    return None if base == 0 else 100.0 * acertos / base


def fmt_celula(a, base, na):
    """`acertos/base (xx,x%)`, com a terceira parcela quando existir."""
    t = taxa(a, base)
    s = "%3d/%-3d" % (a, base)
    s += " (  -  )" if t is None else " (%5.1f%%)" % t
    if na:
        s += " na=%d" % na
    return s


# ---------------------------------------------------------------- controles

def autoteste():
    """Exercita o caminho de contagem contra fixture de contagem CONHECIDA,
    antes de tocar o conjunto real. Sem isto, uma celula zero da tabela seria
    indistinguivel de caminho de contagem quebrado.

    Cobre: acerto, nao-acerto, nao-se-aplica, campo malformado, e o controle
    de MUTACAO — mudar uma celula tem de mudar a contagem."""
    falhas = []

    def linha(cve, ferr, **kw):
        base = {"cve": cve, "ferramenta": ferr, "estrita_aplicavel": "true"}
        base.update({n: "false" for n, _, _ in NIVEIS})
        base.update(kw)
        return base

    # 4 CVEs: dois acertam nivel_1, um acerta, e um e inaplicavel na estrita.
    fx = {}
    for cve, kw in (("CVE-A", {"nivel_1": "true", "nivel_2_estrita": "true"}),
                    ("CVE-B", {"nivel_1": "true"}),
                    ("CVE-C", {}),
                    ("CVE-D", {"estrita_aplicavel": "false",
                               "nivel_2_estrita": ""})):
        fx[(cve, "codeql")] = linha(cve, "codeql", **kw)
    cves = {"CVE-A", "CVE-B", "CVE-C", "CVE-D"}

    esperado = {
        "nivel_1": (2, 2, 0),
        "nivel_2_estrita": (1, 2, 1),
        "nivel_0": (0, 4, 0),
    }
    for nivel, (ea, en, ena) in esperado.items():
        a, n, na, err = contar(fx, cves, "codeql", nivel)
        if err:
            falhas.append("autoteste: %s deu erro inesperado %s" % (nivel, err))
        if (a, n, na) != (ea, en, ena):
            falhas.append("autoteste: %s deu (%d,%d,%d), esperado (%d,%d,%d)"
                          % (nivel, a, n, na, ea, en, ena))

    # CONTROLE DE ZERO. `nivel_0` acima da zero acertos. O mesmo caminho,
    # sobre a mesma fixture com uma celula mutada, tem de dar 1: e o que
    # distingue "nao ha acerto" de "a contagem nao funciona".
    fx_mut = {k: dict(v) for k, v in fx.items()}
    fx_mut[("CVE-C", "codeql")]["nivel_0"] = "true"
    a, _, _, _ = contar(fx_mut, cves, "codeql", "nivel_0")
    if a != 1:
        falhas.append("autoteste: controle de zero falhou; mutacao deu %d, "
                      "esperado 1" % a)

    # Campo malformado tem de virar erro NOMEADO, nunca False silencioso.
    fx_mal = {k: dict(v) for k, v in fx.items()}
    fx_mal[("CVE-A", "codeql")]["nivel_1"] = "sim"
    _, _, _, err = contar(fx_mal, cves, "codeql", "nivel_1")
    if not err:
        falhas.append("autoteste: campo malformado passou sem erro")

    # Conjunto vazio de CVEs: base zero, taxa None, nunca divisao por zero.
    a, n, na, err = contar(fx, set(), "codeql", "nivel_1")
    if (a, n, na) != (0, 0, 0) or taxa(0, 0) is not None:
        falhas.append("autoteste: conjunto vazio nao deu base zero limpa")

    return falhas


# ------------------------------------------------------------------ analise

def distribuicao_cwe(linhas_por_cve, cves):
    """gt_cwe_primary e conjunto gt_cwes completo, contados sobre os CVEs do
    grupo. Uma linha por CVE basta: os campos de ground truth sao iguais nas
    tres ferramentas."""
    # `sorted`, e nao a iteracao do conjunto: a ordem de insercao do Counter
    # vira ordem de chave no JSON, e conjunto do Python nao tem ordem estavel
    # entre processos. Sem isto a saida versionada nao e reproduzivel byte a
    # byte, que e a propriedade que a politica de versionamento exige dela.
    prim, conj = collections.Counter(), collections.Counter()
    for cve in sorted(cves):
        r = linhas_por_cve[(cve, "codeql")]
        prim[r["gt_cwe_primary"] or "(nulo)"] += 1
        conj[r["gt_cwes"] or "(vazio)"] += 1
    return prim, conj


def ordenado(contador):
    """Counter -> dict com chaves ordenadas, para o JSON sair deterministico."""
    return {k: contador[k] for k in sorted(contador)}


def analisar(prov, linhas, linhas_por_cve, cves_denominador, saida):
    p = saida.append
    h_den, n_den, erros = validar_particao(
        prov, {r["cve"] for r in linhas}, cves_denominador, linhas_por_cve)
    if erros:
        return None, erros

    p("")
    p("=" * 78)
    p("PARTICAO PELA PROVENIENCIA DA ETIQUETA  [%s]" % prov["rotulo"])
    p("=" * 78)
    p("  relatorio do cotejo : %s" % rotulo_caminho(prov["caminho"]))
    p("  catalogo CodeQL     : %s" % prov["consultas_dir"])
    p("  ground truth        : %s" % prov["fonte_gt"])
    p("")
    p("  VALIDACAO ESTRUTURAL (fatal se falhar)")
    p("    CVEs no cotejo                      : %d" % prov["cves"])
    p("    herdado  (casa consulta do CodeQL)  : %d" % len(prov["herdado"]))
    p("    nao herdado (nao casa)              : %d" % len(prov["nao_herdado"]))
    p("    intersecao dos grupos               : %d  (exigido 0)"
      % len(set(prov["herdado"]) & prov["nao_herdado"]))
    p("    uniao dos grupos                    : %d  (= CVEs do cotejo)"
      % len(set(prov["herdado"]) | prov["nao_herdado"]))
    p("    dentro do denominador de %d:" % len(cves_denominador))
    p("      herdado %d + nao herdado %d = %d  (exigido %d)"
      % (len(h_den), len(n_den), len(h_den) + len(n_den),
         len(cves_denominador)))
    fora = (set(prov["herdado"]) | prov["nao_herdado"]) - cves_denominador
    p("    fora do denominador (%d), nominal:" % len(fora))
    for cve in sorted(fora):
        r = linhas_por_cve[(cve, "codeql")]
        grupo = "herdado" if cve in prov["herdado"] else "nao herdado"
        p("      %-18s %-12s %s" % (cve, grupo, r["motivo_fora_denominador"]))
    if prov["identicos_vazios"]:
        p("    ressalva: casamento de explanation SEM etiqueta a herdar "
          "(dois conjuntos de CWE vazios): %s"
          % " ".join(prov["identicos_vazios"]))

    p("")
    p("  TAMANHOS DESIGUAIS, declarado: %d contra %d no denominador. "
      % (len(h_den), len(n_den)))
    p("  Toda taxa sai com numerador e denominador. Diferenca de poucos")
    p("  pontos percentuais no grupo menor nao significa nada, e nenhum")
    p("  teste estatistico e aplicado.")

    # ---- tabela principal
    p("")
    p("  TABELA  ferramenta x nivel x grupo")
    p("  (acertos/base (taxa); `na` = nao se aplica, so nas variantes estritas;")
    p("   base da estrita = grupo menos os `na`)")
    p("")
    cab = "  %-34s %-22s %-22s %9s" % ("", "HERDADO", "NAO HERDADO", "delta pp")
    resultado = {}
    erros_contagem = []
    zeros = []
    for ferramenta in FERRAMENTAS:
        p("  --- %s" % ferramenta)
        p(cab)
        for nivel, rotulo, usa_cwe in NIVEIS:
            ha, hn, hna, e1 = contar(linhas_por_cve, h_den, ferramenta, nivel)
            na_, nn, nna, e2 = contar(linhas_por_cve, n_den, ferramenta, nivel)
            erros_contagem.extend(e1 + e2)
            hb, nb = ha + hn, na_ + nn
            th, tn = taxa(ha, hb), taxa(na_, nb)
            delta = ("%+8.1f" % (th - tn)) if (th is not None and tn is not None) else "     -  "
            marca = "" if usa_cwe else "  <- controle interno (nao usa CWE)"
            p("  %-34s %-22s %-22s %9s%s"
              % (rotulo, fmt_celula(ha, hb, hna), fmt_celula(na_, nb, nna),
                 delta, marca))
            resultado[(ferramenta, nivel)] = {
                "herdado": {"acertos": ha, "nao_acertos": hn,
                            "nao_se_aplica": hna, "base": hb, "taxa": th},
                "nao_herdado": {"acertos": na_, "nao_acertos": nn,
                                "nao_se_aplica": nna, "base": nb, "taxa": tn},
                "delta_pp": (th - tn) if (th is not None and tn is not None) else None,
            }
            for grupo, a, b in (("herdado", ha, hb), ("nao_herdado", na_, nb)):
                if a == 0 and b > 0:
                    zeros.append((ferramenta, nivel, grupo, b))
        p("")

    if erros_contagem:
        return None, erros_contagem

    # ---- zeros, com o controle que os sustenta
    p("  CELULAS ZERO, e o controle que as sustenta")
    if not zeros:
        p("    nenhuma celula da tabela saiu zero com base nao vazia.")
    else:
        for ferramenta, nivel, grupo, base in zeros:
            p("    %s / %s / %s: 0 de %d" % (ferramenta, nivel, grupo, base))
        p("    Controle: o autoteste exerceu este mesmo caminho de contagem")
        p("    contra fixture de contagem conhecida, incluindo mutacao de uma")
        p("    celula de zero para um.")
        # Segundo controle, CONFERIDO em vez de afirmado: a mesma coluna
        # (ferramenta x grupo) tem celula nao nula em outro nivel? Se a coluna
        # inteira fosse zero, a frase acima seria falsa e nao se imprime.
        for ferramenta, nivel, grupo, base in zeros:
            outras = [n for n, _, _ in NIVEIS
                      if n != nivel
                      and resultado[(ferramenta, n)][grupo]["acertos"] > 0]
            if outras:
                p("    %s/%s: a mesma coluna tem acerto em %s -> o caminho de"
                  % (ferramenta, grupo, ", ".join(outras)))
                p("      contagem esta exercitado sobre o conjunto real."
                  )
            else:
                p("    %s/%s: a COLUNA INTEIRA e zero. O caminho de contagem"
                  % (ferramenta, grupo))
                p("      nao fica exercitado sobre o conjunto real aqui; vale")
                p("      so o autoteste. Declarado, nao contornado.")

    # ---- composicao por ferramenta (tratados)
    p("")
    p("  COMPOSICAO DOS GRUPOS POR FERRAMENTA (tratado presente)")
    p("  %-12s %-22s %-22s" % ("", "HERDADO", "NAO HERDADO"))
    comp = {}
    for ferramenta in FERRAMENTAS:
        linha_c = []
        for grupo, cves in (("herdado", h_den), ("nao_herdado", n_den)):
            com = 0
            for c in cves:
                v = booleano(linhas_por_cve[(c, ferramenta)]["tratado_presente"],
                             "tratado_presente", c, ferramenta)
                if isinstance(v, str):
                    erros_contagem.append(v)
                elif v:
                    com += 1
            linha_c.append((com, len(cves)))
            comp[(ferramenta, grupo)] = {"com_tratado": com, "total": len(cves)}
        p("  %-12s %-22s %-22s"
          % (ferramenta,
             "%d/%d" % linha_c[0], "%d/%d" % linha_c[1]))
    if erros_contagem:
        return None, erros_contagem
    sem_tratado = collections.defaultdict(list)
    for ferramenta in FERRAMENTAS:
        for grupo, cves in (("herdado", h_den), ("nao_herdado", n_den)):
            for c in sorted(cves):
                if linhas_por_cve[(c, ferramenta)]["tratado_presente"] == "false":
                    sem_tratado[(ferramenta, grupo)].append(c)
    for (ferramenta, grupo), cves in sorted(sem_tratado.items()):
        p("    sem tratado em %s / %s (%d): %s"
          % (ferramenta, grupo, len(cves), " ".join(cves)))
        motivos = collections.Counter(
            linhas_por_cve[(c, ferramenta)]["status_campanha"] for c in cves)
        p("      status na campanha: %s" % dict(motivos))

    # ---- distribuicao de CWE
    p("")
    p("  DISTRIBUICAO DE gt_cwe_primary POR GRUPO")
    ph, ch = distribuicao_cwe(linhas_por_cve, h_den)
    pn, cn = distribuicao_cwe(linhas_por_cve, n_den)
    p("  %-14s %10s %10s" % ("gt_cwe_primary", "herdado", "nao herd."))
    for cwe in sorted(set(ph) | set(pn)):
        p("  %-14s %10d %10d" % (cwe, ph.get(cwe, 0), pn.get(cwe, 0)))
    p("  %-14s %10d %10d" % ("TOTAL", sum(ph.values()), sum(pn.values())))

    p("")
    p("  DISTRIBUICAO DO CONJUNTO gt_cwes COMPLETO POR GRUPO")
    p("  %-46s %9s %9s" % ("gt_cwes", "herdado", "nao herd."))
    for conj in sorted(set(ch) | set(cn),
                       key=lambda k: (-(ch.get(k, 0) + cn.get(k, 0)), k)):
        p("  %-46s %9d %9d" % (conj, ch.get(conj, 0), cn.get(conj, 0)))
    p("  %-46s %9d %9d" % ("TOTAL", sum(ch.values()), sum(cn.values())))

    vaz = vazamento_da_particao(prov, linhas_por_cve, h_den | n_den, saida)

    dados = {
        "rotulo": prov["rotulo"],
        "ressalva_da_particao": vaz,
        "relatorio_proveniencia": rotulo_caminho(prov["caminho"]),
        "relatorio_proveniencia_sha256": prov.get("sha256"),
        "catalogo": prov["consultas_dir"],
        "grupos": {"herdado": sorted(h_den), "nao_herdado": sorted(n_den)},
        "tamanhos": {"herdado": len(h_den), "nao_herdado": len(n_den),
                     "denominador": len(cves_denominador)},
        "fora_do_denominador": {
            c: {"grupo": "herdado" if c in prov["herdado"] else "nao_herdado",
                "motivo": linhas_por_cve[(c, "codeql")]["motivo_fora_denominador"]}
            for c in sorted(fora)},
        "tabela": {"%s|%s" % (f, n): v for (f, n), v in resultado.items()},
        "composicao_tratado": {"%s|%s" % (f, g): v for (f, g), v in comp.items()},
        "distribuicao_gt_cwe_primary": {"herdado": ordenado(ph),
                                        "nao_herdado": ordenado(pn)},
        "distribuicao_gt_cwes": {"herdado": ordenado(ch),
                                 "nao_herdado": ordenado(cn)},
        "celulas_zero": [{"ferramenta": f, "nivel": n, "grupo": g, "base": b}
                         for f, n, g, b in zeros],
    }
    return dados, []


def prototype_pollution(provs, linhas_por_cve, cves_denominador, saida):
    """Os CVEs que mudam de grupo entre as duas referencias. Derivados da
    diferenca entre os dois cotejos, nunca digitados."""
    p = saida.append
    if len(provs) != 2:
        # Com tres ou mais, `excluir` sairia de dois deles e seria aplicado a
        # todos, produzindo uma tabela "sem as trocas" cujo conjunto excluido
        # nao corresponde a referencia reapurada. Melhor nao emitir.
        if len(provs) > 2:
            p("")
            p("  (comparacao entre referencias nao emitida: %d relatorios; "
              "ela e definida para exatamente 2)" % len(provs))
            print("AVISO: comparacao entre referencias exige exatamente 2 "
                  "relatorios; recebidos %d" % len(provs), file=sys.stderr)
        return None
    a, b = provs[0], provs[1]
    so_em_b = sorted(set(b["herdado"]) - set(a["herdado"]))
    so_em_a = sorted(set(a["herdado"]) - set(b["herdado"]))
    p("")
    p("=" * 78)
    p("CVEs QUE MUDAM DE GRUPO ENTRE AS DUAS REFERENCIAS")
    p("=" * 78)
    p("  herdados so em [%s]: %d  %s"
      % (a["rotulo"], len(so_em_a), " ".join(so_em_a) or "-"))
    p("  herdados so em [%s]: %d" % (b["rotulo"], len(so_em_b)))
    consultas = collections.Counter(b["herdado"][c]["consulta"] for c in so_em_b)
    for consulta, n in consultas.most_common():
        p("    %d  por %s" % (n, consulta))
    p("")
    p("  %-18s %-6s %-26s %s" % ("CVE", "den.", "gt_cwes", "acertos por ferramenta"))
    p("  %-18s %-6s %-26s %s" % ("", "", "", "(n1 / n2e / n3 / n4e)"))
    detalhe = {}
    for cve in so_em_b:
        r = linhas_por_cve[(cve, "codeql")]
        no_den = cve in cves_denominador
        marcas = []
        for ferramenta in FERRAMENTAS:
            rr = linhas_por_cve[(cve, ferramenta)]
            def m(campo):
                # "x" = fora do denominador, logo NAO COMPUTADO; "-" = campo
                # que o cruzamento marcou como nao aplicavel. Confundir os
                # dois seria trocar "nao ha" por "nao perguntei".
                if not no_den:
                    return "x"
                return {"true": "S", "false": ".", "": "-"}[rr[campo]]
            marcas.append("%s:%s%s%s%s" % (ferramenta[:3], m("nivel_1"),
                                           m("nivel_2_estrita"), m("nivel_3"),
                                           m("nivel_4_estrita")))
        p("  %-18s %-6s %-26s %s"
          % (cve, "sim" if no_den else "NAO", r["gt_cwes"], "  ".join(marcas)))
        detalhe[cve] = {
            "no_denominador": no_den,
            "gt_cwes": r["gt_cwes"],
            "gt_cwe_primary": r["gt_cwe_primary"],
            "grupo_" + a["rotulo"]: "herdado" if cve in a["herdado"] else "nao_herdado",
            "grupo_" + b["rotulo"]: "herdado" if cve in b["herdado"] else "nao_herdado",
            "acertos": {f: {n: linhas_por_cve[(cve, f)][n]
                            for n, _, _ in NIVEIS} for f in FERRAMENTAS},
        }
    p("")
    p("  Legenda: S acerta, . nao acerta, - nao se aplica, "
      "x fora do denominador (nao computado).")
    p("  Colunas por ferramenta: nivel 1, nivel 2 estrita, nivel 3, nivel 4 estrita.")
    prim = collections.Counter(linhas_por_cve[(c, "codeql")]["gt_cwe_primary"]
                               for c in so_em_b)
    p("  gt_cwe_primary destes %d: %s" % (len(so_em_b), dict(prim)))
    return {"so_em_" + a["rotulo"]: so_em_a,
            "so_em_" + b["rotulo"]: so_em_b,
            "consultas": ordenado(consultas),
            "detalhe": detalhe}




def vazamento_da_particao(prov, linhas_por_cve, cves, saida):
    """RESSALVA MEDIDA sobre o que a particao de fato separa.

    A particao e por `explanation`: um CVE e "herdado" quando sua explanation
    casa o `@name` de uma consulta. Mas os niveis 2 e 4 usam o conjunto de
    CWEs, nao a explanation. As duas coisas andam juntas em 163 de 163 na
    referencia — todo casado sai `identico` —, e nada garante a reciproca:
    um CVE pode ter explanation em prosa, e portanto cair em "nao herdado",
    e ainda assim carregar um conjunto de CWEs igual ao de uma consulta.

    O caso existe e e nominado: `CVE-2019-10745` tem o mesmo conjunto dos 22
    de prototype pollution e explanation em prosa. Este bloco conta o
    fenomeno em vez de deixa-lo por conta de um exemplo.

    CONJUNTO UNITARIO CONTA A PARTE, e a razao e a regra geral do projeto
    sobre metodo de contagem: `CWE-079` sozinho coincide com a tag de muitas
    consultas por banalidade, nao por heranca. So a coincidencia de conjunto
    com dois ou mais CWEs e sinal.
    """
    p = saida.append
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "cruza_codeql", RAIZ / "tools" / "ground-truth" / "cruza-codeql.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        consultas = mod.ler_consultas(prov["consultas_dir"])
    except Exception as exc:                      # noqa: BLE001
        p("")
        p("  RESSALVA DA PARTICAO: nao apurada (%s: %s)"
          % (type(exc).__name__, exc))
        print("AVISO: ressalva da particao nao apurada (%s: %s)"
              % (type(exc).__name__, exc), file=sys.stderr)
        return None
    if not consultas:
        p("")
        p("  RESSALVA DA PARTICAO: nao apurada (nenhuma consulta lida em %s). "
          "Zero aqui e 'nao perguntei', nao 'nao ha'." % prov["consultas_dir"])
        print("AVISO: ressalva da particao nao apurada; nenhuma consulta lida "
              "em %s" % prov["consultas_dir"], file=sys.stderr)
        return None

    tags = {frozenset(q["cwes"]) for q in consultas if q["cwes"]}
    nao_herdado = sorted(set(prov["nao_herdado"]) & cves)
    coincide_mult, coincide_unit = [], []
    for cve in nao_herdado:
        conj = frozenset(c for c in
                         linhas_por_cve[(cve, "codeql")]["gt_cwes"].split("|") if c)
        if conj and conj in tags:
            (coincide_mult if len(conj) >= 2 else coincide_unit).append(cve)
    p("")
    p("  RESSALVA DA PARTICAO — o criterio e a explanation, os niveis 2 e 4")
    p("  usam o conjunto de CWEs. CVEs do grupo NAO HERDADO cujo conjunto de")
    p("  CWEs e, ainda assim, igual ao de uma consulta do catalogo:")
    p("    conjunto com 2+ CWEs : %d de %d  %s"
      % (len(coincide_mult), len(nao_herdado), " ".join(coincide_mult) or "-"))
    p("    conjunto unitario    : %d de %d  (contado a parte: CWE unico"
      % (len(coincide_unit), len(nao_herdado)))
    p("                           coincide por banalidade, nao por heranca)")
    p("    consultas com tag no catalogo: %d conjuntos distintos" % len(tags))
    p("    LIMITE declarado: o catalogo e lido do caminho que o relatorio do")
    p("    cotejo declara, e nem o cotejo nem este script gravam hash dele.")
    p("    Catalogo trocado nesse caminho produziria esta ressalva contra")
    p("    outro estado, sem sinal. O commit esta em proveniencia.meta.json.")
    return {"consultas_conjuntos_distintos": len(tags),
            "nao_herdado_com_conjunto_de_consulta_multiplo": coincide_mult,
            "nao_herdado_com_conjunto_de_consulta_unitario": coincide_unit,
            "nao_herdado_total": len(nao_herdado)}


def auxiliar_confusao(provs, linhas_por_cve, cves_denominador, saida, trocas):
    """AUXILIAR, e declarado como tal: reapura a tabela EXCLUINDO dos dois
    grupos os CVEs que trocam de grupo entre as duas referencias.

    Existe por uma razao medida, nao hipotetica: sob a referencia, esses CVEs
    caem TODOS num so grupo e tem TODOS o mesmo `gt_cwe_primary`. Enquanto
    estiverem dentro, proveniencia da etiqueta e tipo de vulnerabilidade
    variam juntos, e nenhuma das duas explica a diferenca sozinha. Excluindo-os,
    a comparacao passa a incidir sobre o que sobra dos dois grupos.

    Isto NAO e a medida principal nem substitui a tabela: e a aritmetica que
    isola o fator de confusao, e os tamanhos ficam ainda mais desiguais. A
    leitura continua sendo do texto.
    """
    if not trocas:
        return None
    p = saida.append
    excluir = set()
    for chave, lista in trocas.items():
        if chave.startswith("so_em_"):
            excluir |= set(lista)
    excluir &= cves_denominador
    p("")
    p("=" * 78)
    p("AUXILIAR — a mesma tabela SEM os %d CVEs que trocam de grupo" % len(excluir))
    p("=" * 78)
    p("  Excluidos dos dois grupos, em ambas as referencias. Com eles dentro,")
    p("  proveniencia da etiqueta e tipo de vulnerabilidade variam juntos.")
    p("")
    dados = []
    for prov in provs:
        h = (set(prov["herdado"]) & cves_denominador) - excluir
        n = (set(prov["nao_herdado"]) & cves_denominador) - excluir
        p("  --- [%s]  herdado %d, nao herdado %d  (total %d = %d - %d)"
          % (prov["rotulo"], len(h), len(n), len(h) + len(n),
             len(cves_denominador), len(excluir)))
        d = {"rotulo": prov["rotulo"], "excluidos": sorted(excluir),
             "tamanhos": {"herdado": len(h), "nao_herdado": len(n)},
             "tabela": {}}
        for ferramenta in FERRAMENTAS:
            celulas = []
            for nivel, rotulo, _ in NIVEIS:
                ha, hn, hna, e1 = contar(linhas_por_cve, h, ferramenta, nivel)
                na_, nn, nna, e2 = contar(linhas_por_cve, n, ferramenta, nivel)
                if e1 or e2:
                    p("  ERRO na apuracao auxiliar: %s" % (e1 + e2))
                    return None
                hb, nb = ha + hn, na_ + nn
                th, tn = taxa(ha, hb), taxa(na_, nb)
                delta = ("%+7.1f" % (th - tn)) if (th is not None and tn is not None) else "    -  "
                celulas.append("  %-34s %-22s %-22s %8s"
                               % (rotulo, fmt_celula(ha, hb, hna),
                                  fmt_celula(na_, nb, nna), delta))
                d["tabela"]["%s|%s" % (ferramenta, nivel)] = {
                    "herdado": {"acertos": ha, "base": hb, "nao_se_aplica": hna, "taxa": th},
                    "nao_herdado": {"acertos": na_, "base": nb, "nao_se_aplica": nna, "taxa": tn},
                    "delta_pp": (th - tn) if (th is not None and tn is not None) else None}
            p("  %s" % ferramenta)
            p("  %-34s %-22s %-22s %8s" % ("", "HERDADO", "NAO HERDADO", "delta pp"))
            for c in celulas:
                p(c)
            p("")
        dados.append(d)
    return dados


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proveniencia", nargs="+",
                    help="relatorio(s) JSON do cruza-codeql.py; o primeiro e "
                         "a referencia, os demais sao repeticoes da particao")
    ap.add_argument("--matriz", default=str(MATRIZ_PADRAO))
    ap.add_argument("--denominador", type=int, default=220,
                    help="tamanho esperado do denominador; a leitura da "
                         "matriz aborta se divergir (default 220)")
    ap.add_argument("--json", help="grava o relatorio tambem em JSON")
    args = ap.parse_args(argv)

    # 1. Controles ANTES de tocar o conjunto real.
    falhas = autoteste()
    if falhas:
        print("ERRO: autoteste do caminho de contagem falhou:", file=sys.stderr)
        for f in falhas:
            print("  " + f, file=sys.stderr)
        return 2

    # GUARDA DA SAIDA VERSIONADA, na mesma forma do cruza-deteccao.py.
    # `results/circularidade/` entra no repositorio; entrada de fora faria o
    # caminho da maquina do operador ir para o JSON.
    if args.json and Path(args.json).resolve().is_relative_to(SAIDA_VERSIONADA):
        fora = [c for c in [args.matriz] + list(args.proveniencia)
                if not Path(c).resolve().is_relative_to(RAIZ)]
        if fora:
            print("ERRO: a saida versionada exige entradas dentro do "
                  "repositorio: o caminho de fora iria para os JSON: %s"
                  % fora, file=sys.stderr)
            return 2

    saida = []
    p = saida.append
    p("--- circularidade da proveniencia do ground truth ---")
    p("  autoteste do caminho de contagem: OK "
      "(acerto, nao-acerto, nao-se-aplica, malformado, base zero, mutacao)")
    p("  matriz : %s" % rotulo_caminho(args.matriz))
    if not Path(args.matriz).is_file():
        print("\n".join(saida), file=sys.stderr)
        print("ERRO: matriz ausente: %s" % args.matriz, file=sys.stderr)
        return 2
    matriz_sha = sha256(args.matriz)
    p("           sha256 %s" % matriz_sha)

    linhas, erros = ler_matriz(args.matriz)
    if erros:
        print("\n".join(saida), file=sys.stderr)
        for e in erros:
            print(e, file=sys.stderr)
        return 2
    linhas_por_cve = {(r["cve"], r["ferramenta"]): r for r in linhas}

    cves_denominador, fora, erros_den = set(), {}, []
    for r in linhas:
        v = booleano(r["no_denominador"], "no_denominador", r["cve"],
                     r["ferramenta"])
        if isinstance(v, str):
            erros_den.append(v)
            continue
        if v:
            cves_denominador.add(r["cve"])
        else:
            fora[r["cve"]] = r["motivo_fora_denominador"]
    # ANCORAGEM. Sem isto a validacao da particao seria tautologica: ela
    # compara os grupos contra um denominador derivado desta mesma leitura,
    # e um campo fora de forma tiraria o CVE dos dois lados em silencio.
    if len(cves_denominador) != args.denominador:
        erros_den.append("ERRO: o denominador lido da matriz e %d; esperado %d"
                         % (len(cves_denominador), args.denominador))
    if set(fora) != EXCLUSOES_ESPERADAS:
        erros_den.append("ERRO: os CVEs fora do denominador sao %s; esperados %s"
                         % (sorted(fora), sorted(EXCLUSOES_ESPERADAS)))
    if erros_den:
        print("\n".join(saida), file=sys.stderr)
        for e in erros_den:
            print(e, file=sys.stderr)
        return 2
    p("  CVEs na matriz          : %d" % len({r["cve"] for r in linhas}))
    p("  CVEs no denominador     : %d" % len(cves_denominador))
    p("  fora do denominador (%d) : %s"
      % (len(fora), ", ".join("%s (%s)" % kv for kv in sorted(fora.items()))))

    provs, dados = [], []
    for caminho in args.proveniencia:
        prov, erros = ler_proveniencia(caminho)
        if erros:
            print("\n".join(saida), file=sys.stderr)
            for e in erros:
                print(e, file=sys.stderr)
            return 2
        prov["sha256"] = sha256(caminho)
        p("  proveniencia [%s]: %s" % (prov["rotulo"], rotulo_caminho(caminho)))
        p("           sha256 %s" % prov["sha256"])
        provs.append(prov)

    rotulos = [x["rotulo"] for x in provs]
    if len(set(rotulos)) != len(rotulos):
        print("\n".join(saida), file=sys.stderr)
        print("ERRO: rotulos repetidos entre os relatorios: %s. As chaves do "
              "JSON sao o rotulo, e o segundo sobrescreveria o primeiro."
              % rotulos, file=sys.stderr)
        return 2

    for prov in provs:
        d, erros = analisar(prov, linhas, linhas_por_cve, cves_denominador, saida)
        if erros:
            # A saida parcial vai ao STDERR, e nunca ao stdout: quem redireciona
            # stdout para arquivo nao pode ficar com uma tabela que o proprio
            # script considera invalida. Ver a nota sobre base encolhida em
            # `contar`.
            print("\n".join(saida), file=sys.stderr)
            print("\nERRO: a apuracao de [%s] falhou; nenhum numero e emitido. "
                  "Quando a falha e de campo malformado, a base da celula "
                  "encolheria em silencio, e por isso aborta." % prov["rotulo"],
                  file=sys.stderr)
            for e in erros:
                print("  " + e, file=sys.stderr)
            return 2
        dados.append(d)

    trocas = prototype_pollution(provs, linhas_por_cve, cves_denominador, saida)
    aux = auxiliar_confusao(provs, linhas_por_cve, cves_denominador, saida, trocas)

    print("\n".join(saida))
    if args.json:
        Path(args.json).write_text(json.dumps({
            "matriz": rotulo_caminho(args.matriz),
            "matriz_sha256": matriz_sha,
            "proveniencia_sha256": {x["rotulo"]: x["sha256"] for x in provs},
            "particoes": dados,
            "trocas_entre_referencias": trocas,
            "auxiliar_sem_as_trocas": aux,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("\n  relatorio JSON: %s" % rotulo_caminho(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
