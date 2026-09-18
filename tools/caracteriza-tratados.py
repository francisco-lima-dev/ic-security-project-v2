"""Apuracao previa ao cruzamento: caracteriza os tratados dos oito lotes.

Le results/<ferramenta>/treated/ e nao escreve nada. Nenhuma metrica de
deteccao: file_path x gt_file_path e usado so para delimitar o subconjunto
de achados em que distancia de linha tem sentido.
"""
import json, glob, statistics, sys, collections, os

# Raiz do repositorio derivada do proprio arquivo: tools/<script> -> raiz.
R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FERR = ("codeql", "semgrep", "snyk-code")
CHAVES_ACHADO = {"column_end", "column_start", "cwe", "file_path", "finding_id",
                 "has_cwe", "line_end", "line_start", "message", "rule_id",
                 "security_severity", "severity_normalized", "severity_original"}
VOCAB_SEV = {"high", "medium", "low", "unknown", "unresolved"}


def validar(cve, d, anom):
    """Acumula anomalia estrutural em anom. Nao corrige nada."""
    if set(d.keys()) != {"metadata", "findings"}:
        anom.append((cve, "chaves do topo", sorted(d.keys())))
        return
    m = d["metadata"]
    if m.get("schema_version") != "1.3":
        anom.append((cve, "schema_version", m.get("schema_version")))
    if not isinstance(m.get("gt_file_path"), str) or not m["gt_file_path"]:
        anom.append((cve, "gt_file_path", repr(m.get("gt_file_path"))))
    if not isinstance(m.get("gt_file_lines"), list):
        anom.append((cve, "gt_file_lines nao e lista", type(m.get("gt_file_lines")).__name__))
    else:
        for L in m["gt_file_lines"]:
            if not isinstance(L, int) or isinstance(L, bool):
                anom.append((cve, "elemento de gt_file_lines", repr(L)))
    if not isinstance(m.get("gt_cwes"), list):
        anom.append((cve, "gt_cwes nao e lista", type(m.get("gt_cwes")).__name__))
    if not isinstance(d["findings"], list):
        anom.append((cve, "findings nao e lista", type(d["findings"]).__name__))
        return
    for i, a in enumerate(d["findings"]):
        if set(a.keys()) != CHAVES_ACHADO:
            anom.append((cve, f"chaves do achado {i}", sorted(set(a.keys()) ^ CHAVES_ACHADO)))
            continue
        if not isinstance(a["has_cwe"], bool):
            anom.append((cve, f"has_cwe do achado {i}", repr(a["has_cwe"])))
        if not isinstance(a["cwe"], list):
            anom.append((cve, f"cwe do achado {i}", type(a["cwe"]).__name__))
        elif bool(a["cwe"]) != a["has_cwe"]:
            anom.append((cve, f"has_cwe x cwe do achado {i}", (a["has_cwe"], a["cwe"])))
        if not isinstance(a["file_path"], str):
            anom.append((cve, f"file_path do achado {i}", type(a["file_path"]).__name__))
        for campo in ("line_start", "line_end"):
            v = a[campo]
            if v is not None and (not isinstance(v, int) or isinstance(v, bool)):
                anom.append((cve, f"{campo} do achado {i}", repr(v)))
        if a["severity_normalized"] not in VOCAB_SEV:
            anom.append((cve, f"severity_normalized do achado {i}", repr(a["severity_normalized"])))


def autoteste():
    """Controle positivo: a validacao precisa acusar cada mutacao."""
    base = {"metadata": {"schema_version": "1.3", "gt_file_path": "a.js",
                         "gt_file_lines": [10], "gt_cwes": ["CWE-079"]},
            "findings": [{k: None for k in CHAVES_ACHADO}]}
    base["findings"][0].update({"cwe": ["CWE-079"], "has_cwe": True, "file_path": "a.js",
                                "line_start": 10, "line_end": 12,
                                "severity_normalized": "high"})
    limpo = []
    validar("CONTROLE", json.loads(json.dumps(base)), limpo)
    casos = []
    for nome, mut in (
        ("schema_version divergente", lambda d: d["metadata"].__setitem__("schema_version", "1.2")),
        ("gt_file_lines com string", lambda d: d["metadata"].__setitem__("gt_file_lines", ["10"])),
        ("achado sem uma chave", lambda d: d["findings"][0].pop("message")),
        ("has_cwe incoerente com cwe", lambda d: d["findings"][0].__setitem__("has_cwe", False)),
        ("line_start em string", lambda d: d["findings"][0].__setitem__("line_start", "10")),
        ("severity fora do vocabulario", lambda d: d["findings"][0].__setitem__("severity_normalized", "critical")),
    ):
        d = json.loads(json.dumps(base)); mut(d)
        saida = []; validar("MUTANTE", d, saida)
        casos.append((nome, len(saida)))
    return limpo, casos


def pct(vals, q):
    """Percentil por interpolacao linear sobre a amostra ordenada."""
    if not vals:
        return None
    s = sorted(vals)
    if len(s) == 1:
        return float(s[0])
    pos = (len(s) - 1) * q / 100
    lo = int(pos); hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def faixa(dist):
    if dist == 0: return "0"
    if dist <= 2: return "1-2"
    if dist <= 5: return "3-5"
    if dist <= 10: return "6-10"
    if dist <= 20: return "11-20"
    if dist <= 50: return "21-50"
    if dist <= 100: return "51-100"
    return ">100"

FAIXAS = ["0", "1-2", "3-5", "6-10", "11-20", "21-50", "51-100", ">100"]

# ---------------------------------------------------------------- carga
dados = {}
anomalias = []
for f in FERR:
    dados[f] = {}
    for p in sorted(glob.glob(f"{R}/results/{f}/treated/CVE-*.json")):
        cve = p.rsplit("/", 1)[1][:-5]
        with open(p) as fh:
            d = json.load(fh)
        validar(cve, d, anomalias)
        dados[f][cve] = d

limpo, casos_auto = autoteste()
print("===== 0. VALIDACAO ESTRUTURAL")
print(f"  arquivos lidos: " + ", ".join(f"{f}={len(dados[f])}" for f in FERR))
print(f"  anomalias estruturais: {len(anomalias)}")
for a in anomalias[:20]:
    print(f"    {a}")
print(f"  autoteste da validacao: registro integro -> {len(limpo)} anomalias (esperado 0)")
for nome, n in casos_auto:
    print(f"    mutante '{nome}' -> {n} anomalia(s) {'OK' if n else 'FALHOU: nao acusou'}")
if anomalias or limpo or any(n == 0 for _, n in casos_auto):
    print("\nPARADO: validacao estrutural nao passou. Nenhum numero emitido.")
    sys.exit(2)
print("  validacao passou; segue a apuracao.\n")

# ------------------------------------------------- 1. CWE
print("===== 1. CWE")
print("(a) achados sem CWE, sobre o total de achados da ferramenta")
print(f"  {'ferramenta':<12} {'achados':>8} {'sem CWE':>9} {'%':>7}")
for f in FERR:
    tot = sem = 0
    for d in dados[f].values():
        for a in d["findings"]:
            tot += 1
            if not a["has_cwe"]:
                sem += 1
    print(f"  {f:<12} {tot:>8} {sem:>9} {100*sem/tot if tot else 0:>6.1f}%")

print("\n(b) CVEs com achado no arquivo do ground truth em que NENHUM deles tem CWE")
print(f"  {'ferramenta':<12} {'CVEs c/ achado no gt_file':>26} {'destes, todos sem CWE':>23} {'%':>7}")
sem_cwe_no_gt = {}
for f in FERR:
    com, todos_sem = 0, []
    for cve, d in dados[f].items():
        gtp = d["metadata"]["gt_file_path"]
        no_gt = [a for a in d["findings"] if a["file_path"] == gtp]
        if no_gt:
            com += 1
            if not any(a["has_cwe"] for a in no_gt):
                todos_sem.append(cve)
    sem_cwe_no_gt[f] = todos_sem
    print(f"  {f:<12} {com:>26} {len(todos_sem):>23} {100*len(todos_sem)/com if com else 0:>6.1f}%")
for f in FERR:
    if sem_cwe_no_gt[f]:
        print(f"    {f}: {', '.join(sorted(sem_cwe_no_gt[f])[:12])}" +
              (" ..." if len(sem_cwe_no_gt[f]) > 12 else ""))

# ------------------------------------------------- 2. Linha
print("\n===== 2. LINHA (so achados com file_path == gt_file_path)")
resumo_dist = {}
for f in FERR:
    dists, n_gtlinhas_vazias, achados_gt = [], 0, 0
    zero = sobrepoe = 0
    fim_nulo_no_gt = 0
    for cve, d in dados[f].items():
        m = d["metadata"]
        gtp, linhas = m["gt_file_path"], m["gt_file_lines"]
        no_gt = [a for a in d["findings"] if a["file_path"] == gtp]
        if not no_gt:
            continue
        if not linhas:
            n_gtlinhas_vazias += len(no_gt)
            continue
        for a in no_gt:
            achados_gt += 1
            ini = a["line_start"]; fim = a["line_end"]
            dists.append(min(abs(ini - L) for L in linhas))
            if any(ini == L for L in linhas):
                zero += 1
            if fim is None:
                fim_nulo_no_gt += 1
                if any(ini == L for L in linhas):
                    sobrepoe += 1
            else:
                if any(ini <= L <= fim for L in linhas):
                    sobrepoe += 1
    resumo_dist[f] = (dists, zero, sobrepoe, achados_gt, n_gtlinhas_vazias, fim_nulo_no_gt)

print(f"  {'ferramenta':<12} {'achados no gt_file':>19} {'excluidos (gt sem linha)':>25}")
for f in FERR:
    _, _, _, n, exc, _ = resumo_dist[f]
    print(f"  {f:<12} {n:>19} {exc:>25}")

print("\n  histograma da distancia ate a linha do gt mais proxima")
print(f"  {'faixa':<8}" + "".join(f"{f:>26}" for f in FERR))
for fx in FAIXAS:
    linha = f"  {fx:<8}"
    for f in FERR:
        dists = resumo_dist[f][0]
        c = sum(1 for x in dists if faixa(x) == fx)
        linha += f"{c:>15} {100*c/len(dists) if dists else 0:>9.1f}%"
    print(linha)

print(f"\n  {'ferramenta':<12} {'mediana':>9} {'media':>9} {'p25':>8} {'p50':>8} {'p75':>8} {'p90':>9}")
for f in FERR:
    dists = resumo_dist[f][0]
    if not dists:
        print(f"  {f:<12} {'-':>9}"); continue
    print(f"  {f:<12} {statistics.median(dists):>9.1f} {statistics.mean(dists):>9.1f} "
          f"{pct(dists,25):>8.1f} {pct(dists,50):>8.1f} {pct(dists,75):>8.1f} {pct(dists,90):>9.1f}")

print(f"\n  {'ferramenta':<12} {'distancia 0':>12} {'sobrepoem':>11} {'ganho':>8} {'line_end nulo no gt_file':>26}")
for f in FERR:
    _, zero, sobre, n, _, fim_nulo = resumo_dist[f]
    print(f"  {f:<12} {zero:>12} {sobre:>11} {sobre-zero:>8} {fim_nulo:>26}")
print("  (achado com line_end nulo entrou na sobreposicao como intervalo [line_start, line_start])")

# ------------------------------------------------- 3. Extensao
print("\n===== 3. EXTENSAO DOS ACHADOS (line_end - line_start)")
print(f"  {'ferramenta':<12} {'com as 2 linhas':>16} {'mediana':>9} {'media':>9} {'p90':>8} {'max':>8}")
for f in FERR:
    ext = [a["line_end"] - a["line_start"] for d in dados[f].values() for a in d["findings"]
           if a["line_start"] is not None and a["line_end"] is not None]
    if not ext:
        print(f"  {f:<12} {0:>16} {'-':>9}"); continue
    print(f"  {f:<12} {len(ext):>16} {statistics.median(ext):>9.1f} {statistics.mean(ext):>9.2f} "
          f"{pct(ext,90):>8.1f} {max(ext):>8}")

print("\n  o mesmo, restrito aos achados no arquivo do ground truth (extra, mesma passada)")
print(f"  {'ferramenta':<12} {'com as 2 linhas':>16} {'mediana':>9} {'media':>9} {'p90':>8}")
for f in FERR:
    ext = []
    for d in dados[f].values():
        gtp = d["metadata"]["gt_file_path"]
        for a in d["findings"]:
            if a["file_path"] == gtp and a["line_start"] is not None and a["line_end"] is not None:
                ext.append(a["line_end"] - a["line_start"])
    if not ext:
        print(f"  {f:<12} {0:>16} {'-':>9}"); continue
    print(f"  {f:<12} {len(ext):>16} {statistics.median(ext):>9.1f} {statistics.mean(ext):>9.2f} {pct(ext,90):>8.1f}")

print(f"\n  {'ferramenta':<12} {'line_end nulo':>14} {'%':>7} {'line_start nulo':>16} {'%':>7}")
for f in FERR:
    tot = fim_n = ini_n = 0
    for d in dados[f].values():
        for a in d["findings"]:
            tot += 1
            fim_n += a["line_end"] is None
            ini_n += a["line_start"] is None
    print(f"  {f:<12} {fim_n:>14} {100*fim_n/tot:>6.1f}% {ini_n:>16} {100*ini_n/tot:>6.1f}%")

# ------------------------------------------------- 4. Caracterizacao
print("\n===== 4. CARACTERIZACAO")
print(f"  {'ferramenta':<12} {'CVEs':>6} {'achados':>8} {'mediana/CVE':>12} {'media/CVE':>10} {'CVEs com 0':>11} {'max':>7}")
for f in FERR:
    por_cve = [len(d["findings"]) for d in dados[f].values()]
    print(f"  {f:<12} {len(por_cve):>6} {sum(por_cve):>8} {statistics.median(por_cve):>12.1f} "
          f"{statistics.mean(por_cve):>10.1f} {sum(1 for x in por_cve if x == 0):>11} {max(por_cve):>7}")

print("\n  dez CVEs com mais achados, por ferramenta")
for f in FERR:
    top = sorted(((len(d["findings"]), cve) for cve, d in dados[f].items()), reverse=True)[:10]
    print(f"  {f}: " + ", ".join(f"{cve} {n}" for n, cve in top))

print("\n  distribuicao de severity_normalized")
print(f"  {'ferramenta':<12}" + "".join(f"{v:>12}" for v in ("high","medium","low","unknown","unresolved")))
for f in FERR:
    c = collections.Counter(a["severity_normalized"] for d in dados[f].values() for a in d["findings"])
    print(f"  {f:<12}" + "".join(f"{c.get(v,0):>12}" for v in ("high","medium","low","unknown","unresolved")))

print("\n  achados fora do arquivo do ground truth (o que o nivel 0 captura e o nivel 1 descarta)")
print(f"  {'ferramenta':<12} {'total':>8} {'no gt_file':>11} {'fora':>9} {'% fora':>8}")
for f in FERR:
    tot = dentro = 0
    for d in dados[f].values():
        gtp = d["metadata"]["gt_file_path"]
        for a in d["findings"]:
            tot += 1
            dentro += a["file_path"] == gtp
    print(f"  {f:<12} {tot:>8} {dentro:>11} {tot-dentro:>9} {100*(tot-dentro)/tot:>7.1f}%")

print("\n  conferencias de forma do caminho (nenhuma deve ocorrer)")
for f in FERR:
    abs_ = rel = 0
    for d in dados[f].values():
        for a in d["findings"]:
            abs_ += a["file_path"].startswith("/")
            rel += a["file_path"].startswith("./")
    print(f"    {f:<12} file_path absoluto: {abs_} | com './': {rel}")
print("\n  CVEs com gt_file_lines vazio, por ferramenta:")
for f in FERR:
    vazios = [cve for cve, d in dados[f].items() if not d["metadata"]["gt_file_lines"]]
    print(f"    {f:<12} {len(vazios)}" + (f" -> {', '.join(sorted(vazios)[:10])}" if vazios else ""))
