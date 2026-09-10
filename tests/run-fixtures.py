#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run-fixtures.py — exercita tools/normalize.py e tools/check-log.py contra as
fixtures sintéticas de tests/fixtures/.

    python3 tests/run-fixtures.py

Sem raws reais em disco, esta é a única verificação possível na Fase D. As
fixtures são escritas à mão, versionadas, e vivem FORA de results/*/raw/ —
aquele diretório é ignorado pelo git e seus nomes casariam com os globs do
normalizador.

Cada asserção nomeia a invariante que protege. Saída não nula = alguma falhou.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FIXTURES = RAIZ / "tests" / "fixtures"
NORMALIZE = RAIZ / "tools" / "normalize.py"
CHECK_LOG = RAIZ / "tools" / "check-log.py"

falhas = []
verificacoes = 0


def checar(condicao, descricao, detalhe=""):
    global verificacoes
    verificacoes += 1
    if condicao:
        print("  ok   %s" % descricao)
    else:
        print("  FALHA %s %s" % (descricao, detalhe))
        falhas.append(descricao)


def normalizar(ferramenta, raw_dir, treated_dir, relatorio, extra=()):
    comando = [sys.executable, str(NORMALIZE), "--tool", ferramenta,
               "--raw-dir", str(raw_dir), "--treated-dir", str(treated_dir),
               "--report-path", str(relatorio), *extra]
    processo = subprocess.run(comando, capture_output=True, text=True)
    return processo


def ler(caminho):
    with open(caminho, encoding="utf-8") as arquivo:
        return json.load(arquivo)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="fixtures-normalize-"))

    # ================================================================ CodeQL
    print("\n== CodeQL: casos normais ==")
    tratado_dir = tmp / "codeql"
    relatorio_path = tmp / "rel-codeql.json"
    p = normalizar("codeql", FIXTURES / "codeql", tratado_dir, relatorio_path)
    checar(p.returncode == 0, "codeql normal sai com 0", p.stderr[-600:])
    rel = ler(relatorio_path)
    checar(rel["cves"]["processados"] == 5, "5 CVEs processados",
           rel["cves"]["processados"])
    checar(rel["cves"]["raws_sem_linha_na_lista"] == [], "nenhum raw orfao")
    checar(rel["cves"]["linhas_da_lista_sem_raw"] == 218,
           "218 linhas da lista sem raw (223-5), normal e silencioso",
           rel["cves"]["linhas_da_lista_sem_raw"])

    t = ler(tratado_dir / "CVE-2018-14040.json")
    m, f = t["metadata"], t["findings"]

    # D.5 — validação obrigatória
    caminhos = sorted({x["file_path"] for x in f})
    checar(caminhos == ["js/collapse.js", "js/other.js"],
           "D.5 file_path normalizado: ./ , file:// e /tmp/src-CVE-*/ removidos",
           caminhos)
    checar(all(x["file_path"] == "js/collapse.js"
               for x in f if x["rule_id"] in ("js/reflected-xss", "js/path-injection")),
           "D.5 CVE-2018-14040 → js/collapse.js")
    # O contador conta ACHADOS transformados, nao motivos: um caminho pode
    # sofrer mais de uma transformacao (file:// e prefixo do WORKDIR, aqui).
    checar(rel["caminho"]["achados_com_caminho_transformado"] == 2,
           "2 achados com caminho transformado",
           rel["caminho"]["achados_com_caminho_transformado"])
    checar(rel["caminho"]["motivos_aplicados"] == 3,
           "3 motivos aplicados — grandeza distinta da anterior, e nomeada",
           rel["caminho"]["motivos_aplicados"])
    motivos_registrados = sorted(
        m for x in rel["caminho"]["achados_transformados"] for m in x["motivos"])
    checar(motivos_registrados == ["./ inicial", "esquema file://",
                                   "prefixo do diretorio de trabalho /tmp/src-CVE-*/"],
           "3 motivos ao todo, um caminho acumulando dois", motivos_registrados)
    checar(all("antes" in x and "depois" in x for x in rel["caminho"]["achados_transformados"]),
           "D.5 cada transformacao traz antes E depois")
    checar(all(x["antes"] != x["depois"] for x in rel["caminho"]["achados_transformados"]),
           "D.5 antes e depois efetivamente diferem")

    # D.3 — CWE
    xss = [x for x in f if x["rule_id"] == "js/reflected-xss"][0]
    checar(xss["cwe"] == ["CWE-079", "CWE-116"],
           "CWE do CodeQL: external/cwe/cwe-079 → CWE-079", xss["cwe"])
    checar(xss["has_cwe"] is True, "has_cwe true quando ha CWE")
    label = [x for x in f if x["rule_id"] == "js/unused-label"][0]
    checar(label["cwe"] == [] and label["has_cwe"] is False,
           "achado sem CWE → cwe: [] e has_cwe: false")
    ext = [x for x in f if x["rule_id"] == "js/ext-only-rule"][0]
    checar(ext["cwe"] == ["CWE-094"], "regra vinda de tool.extensions[] resolvida", ext["cwe"])

    # D.6 — severidade, os DOIS contadores separados
    pt = [x for x in f if x["rule_id"] == "js/path-injection"][0]
    checar(pt["severity_normalized"] == "unknown",
           "regra resolvida SEM defaultConfiguration.level → unknown",
           pt["severity_normalized"])
    fantasma = [x for x in f if x["rule_id"] == "js/regra-fantasma"][0]
    checar(fantasma["severity_normalized"] == "unresolved",
           "regra NAO resolvida NAO colapsa em unknown", fantasma["severity_normalized"])
    checar(len(rel["severidade"]["regra_resolvida_sem_nivel"]) == 1,
           "contador (1) de D.6 separado: 1 regra resolvida sem nivel")
    checar(len(rel["severidade"]["regra_nao_resolvida"]) == 1,
           "contador (2) de D.6 separado: 1 regra nao resolvida")
    checar(xss["severity_normalized"] == "high" and label["severity_normalized"] == "low",
           "error→high, note→low")

    # security_severity: float, nunca texto; "6.1" e 5 (int) aceitos
    checar(xss["security_severity"] == 6.1, "security-severity '6.1' → 6.1 float",
           xss["security_severity"])
    checar(pt["security_severity"] == 5.0, "security-severity 5 → 5.0 float",
           pt["security_severity"])

    # line_end nulo
    checar(xss["line_end"] is None, "line_end aceita nulo (ausente no CodeQL)")

    # D.9 — ordenação por chave total e colisões
    chaves = [(x["file_path"], x["line_start"] or 0) for x in f]
    checar(chaves == sorted(chaves), "achados ordenados pela chave total", chaves)
    checar([x["finding_id"] for x in f][0] == "codeql:CVE-2018-14040:0001",
           "finding_id no formato <tool>:<CVE>:<NNNN>")
    checar(rel["colisoes_chave_ordenacao"]["total"] == 1,
           "1 colisao sob a chave total, contada e reportada",
           rel["colisoes_chave_ordenacao"]["total"])

    # D.7 — gt_file_scanned e diagnósticos
    checar(m["gt_file_scanned"] is None,
           "gt_file_scanned do CodeQL e null (assimetria declarada)")
    checar(m["tool_diagnostics"]["notifications"] == 2,
           "toolExecutionNotifications contadas", m["tool_diagnostics"]["notifications"])
    checar(m["tool_diagnostics"]["errors"] is None
           and m["tool_diagnostics"]["skipped_paths"] is None,
           "campos sem fonte no CodeQL ficam null, nao zero")
    checar(m["tool_diagnostics"]["gt_file_affected"] is True,
           "gt_file_affected true: notificacao menciona js/collapse.js")

    # metadata
    checar(m["schema_version"] == "1.1" and m["tool"] == "codeql", "metadata basico")
    checar(m["commit"] == "13bf8aeae3db71e28af69782328c22215795c169",
           "commit vem da LISTA de entrada", m["commit"])
    checar(m["ruleset"]["rules_total"] == 104 and m["rules_applied"] is None,
           "CodeQL: rules_total 104, rules_applied NULO")
    checar(m["ruleset"]["rules_id_sha256"] is None,
           "rules_id_sha256 nulo fora do Semgrep — nao ha pack de arquivo")
    # 2.3: o campo e indicio, e o artefato tem de dize-lo
    checar("heuristica" in m["tool_diagnostics"]["gt_file_affected_method"],
           "gt_file_affected vem acompanhado do metodo, declarado heuristico",
           m["tool_diagnostics"].get("gt_file_affected_method"))
    checar(m["analysis_date"] == "2026-09-07T14:32:11Z"
           and m["analysis_date_source"] == "tool",
           "analysis_date de invocations[0].endTimeUtc, origem 'tool'")
    checar(m["gt_cwe_primary"] == "CWE-079",
           "gt_cwe_primary do conjunto CWE-079|CWE-116", m["gt_cwe_primary"])
    checar(m["gt_file_lines"] == [140], "gt_file_lines lista de inteiros")

    # D.4 — três ramos
    vazio = ler(tratado_dir / "CVE-2018-1000096.json")["metadata"]
    checar(vazio["gt_cwes"] == [] and vazio["gt_cwe_primary"] is None,
           "conjunto vazio → primario null SEM consultar a tabela")
    checar(vazio["cve_id"] in rel["gt_cwe_primary"]["nulo_conjunto_vazio"],
           "conjunto vazio contado no relatorio")
    checar(vazio["analysis_date_source"] == "file_mtime",
           "sem invocations → analysis_date por mtime, origem declarada")
    checar(vazio["tool_diagnostics"]["gt_file_affected"] is None,
           "sem fonte alguma de diagnostico → gt_file_affected null")
    checar(ler(tratado_dir / "CVE-2018-1000096.json")["findings"] == [],
           "raw sem achados produz tratado com findings: []")

    unitario = ler(tratado_dir / "CVE-2017-16011.json")["metadata"]
    checar(unitario["gt_cwes"] == ["CWE-079"] and unitario["gt_cwe_primary"] == "CWE-079",
           "conjunto unitario → o proprio, SEM consultar a tabela")

    indefinido = ler(tratado_dir / "CVE-2018-16472.json")["metadata"]
    checar(indefinido["gt_cwe_primary"] is None,
           "conjunto presente com primario vazio → null")
    checar(len(rel["gt_cwe_primary"]["nulo_primario_indefinido"]) == 1,
           "primario indefinido contado SEPARADAMENTE do conjunto vazio")
    checar(indefinido["tool_diagnostics"]["notifications"] == 0,
           "campo presente e vazio → 0, distinto de null")

    sem_ext = ler(tratado_dir / "CVE-2018-16480.json")["metadata"]
    checar(sem_ext["gt_file_path"] == "bin/public",
           "gt_file_path sem extensao preservado", sem_ext["gt_file_path"])

    # ============================================ CodeQL: raws com defeito
    print("\n== CodeQL: raw ilegivel e raw orfao ==")
    tratado_erros = tmp / "codeql-erros"
    rel_erros = tmp / "rel-codeql-erros.json"
    p = normalizar("codeql", FIXTURES / "codeql-erros", tratado_erros, rel_erros)
    checar(p.returncode != 0, "raw ilegivel/orfao → saida NAO nula", p.returncode)
    rel2 = ler(rel_erros)
    checar(not (tratado_erros / "CVE-2018-14041.json").exists(),
           "D.8 raw truncado NAO produz tratado")
    checar(len(rel2["raws_ilegiveis"]) == 2, "2 raws ilegiveis contados",
           rel2["raws_ilegiveis"])
    checar(rel2["cves"]["raws_sem_linha_na_lista"] == ["CVE-2099-12345"],
           "raw orfao e falha ruidosa, nomeado no relatorio",
           rel2["cves"]["raws_sem_linha_na_lista"])
    checar(not (tratado_erros / "CVE-2099-12345.json").exists(),
           "raw orfao nao produz tratado")
    checar("CVE-2099-12345" in p.stderr and "CVE-2018-14041" in p.stderr,
           "os defeitos aparecem no stderr")
    checar(not (tratado_erros / "CVE-2016-10735.json").exists(),
           "SARIF com runs[] e SEM results[] nao vira findings: []")
    checar(any(x["cve"] == "CVE-2016-10735" for x in rel2["raws_ilegiveis"]),
           "SARIF sem results[] contado como raw ilegivel, como no Semgrep",
           rel2["raws_ilegiveis"])

    # ============================== D1: gt_file_path com barra inicial
    print("\n== Ground truth com barra inicial (CVE-2019-12041) ==")
    tratado_gt = tmp / "gt-barra"
    rel_gt = tmp / "rel-gt-barra.json"
    p = normalizar("semgrep", FIXTURES / "gt-barra-inicial", tratado_gt, rel_gt)
    checar(p.returncode == 0, "CVE com /index.js processa sem falha", p.stderr[-400:])
    m = ler(tratado_gt / "CVE-2019-12041.json")["metadata"]
    checar(m["gt_file_path"] == "index.js",
           "barra inicial do ground truth removida", m["gt_file_path"])
    checar(m["gt_file_path_original"] == "/index.js",
           "caminho original do benchmark preservado no tratado",
           m.get("gt_file_path_original"))
    checar(m["gt_file_scanned"] is True,
           "gt_file_scanned agora casa com paths.scanned (era false por causa da barra)")
    checar(len(ler(rel_gt)["caminho"]["ground_truth_normalizado"]) == 1,
           "normalizacao do ground truth registrada com antes/depois")
    checar("CVE-2019-12041" in p.stderr, "avisado no stderr, nao so no relatorio")

    # =========================== D2: caminho absoluto nao reconhecido
    print("\n== Caminho absoluto sob prefixo nao previsto ==")
    tratado_abs = tmp / "abs"
    rel_abs = tmp / "rel-abs.json"
    p = normalizar("codeql", FIXTURES / "codeql-absoluto", tratado_abs, rel_abs)
    achado_abs = ler(tratado_abs / "CVE-2016-10735.json")["findings"][0]
    checar(achado_abs["file_path"] == "/home/runner/work/x/x/js/src/util.js",
           "caminho absoluto PRESERVADO, nao mutilado", achado_abs["file_path"])
    rel_a = ler(rel_abs)
    checar(len(rel_a["caminho"]["caminhos_absolutos_nao_reconhecidos"]) == 1,
           "caminho absoluto contado em campo proprio")
    checar("NAO se sustentou" in (rel_a["caminho"]["nota"] or ""),
           "a nota NAO afirma 'tudo limpo' quando sobrou caminho absoluto",
           rel_a["caminho"]["nota"])
    checar("ABSOLUTO" in p.stdout,
           "o resumo do console mostra os absolutos, nao so o JSON", p.stdout[-300:])
    # A ultima linha do resumo tem de ser o CAMINHO do relatorio. Uma local
    # homonima ja sombreou o parametro aqui e imprimiu o dicionario inteiro.
    ultima = [l for l in p.stdout.strip().splitlines() if l.startswith("  relatorio: ")][-1]
    checar(ultima.endswith(".json"),
           "o resumo imprime o CAMINHO do relatorio, nao o dicionario", ultima[:120])

    # ============================================================== Semgrep
    print("\n== Semgrep ==")
    tratado_sg = tmp / "semgrep"
    rel_sg_path = tmp / "rel-semgrep.json"
    p = normalizar("semgrep", FIXTURES / "semgrep", tratado_sg, rel_sg_path)
    checar(p.returncode == 0, "semgrep normal sai com 0", p.stderr[-600:])
    rel_sg = ler(rel_sg_path)
    t = ler(tratado_sg / "CVE-2018-14040.json")
    m, f = t["metadata"], t["findings"]

    nua = [x for x in f if x["rule_id"].endswith("code-string-concat")][0]
    checar(nua["cwe"] == ["CWE-094"],
           "extra.metadata.cwe como CADEIA NUA extraida corretamente", nua["cwe"])
    checar(nua["has_cwe"] is True, "cadeia nua NAO vira has_cwe false")
    checar(len(rel_sg["cwe"]["semgrep_cadeia_nua"]) == 1,
           "ocorrencia de cadeia nua contada no relatorio")
    lista_cwe = [x for x in f if x["rule_id"].endswith("direct-response-write")][0]
    checar(lista_cwe["cwe"] == ["CWE-079"],
           "extra.metadata.cwe como LISTA, CWE-79 → CWE-079", lista_cwe["cwe"])
    medio = [x for x in f if x["rule_id"].endswith("path-join-resolve-traversal")][0]
    checar(medio["severity_normalized"] == "medium", "MEDIUM → medium")
    checar(nua["severity_normalized"] == "high", "ERROR → high")
    sem_cwe = [x for x in f if x["rule_id"].endswith("useless-eqeq")][0]
    checar(sem_cwe["cwe"] == [] and sem_cwe["severity_normalized"] == "low",
           "metadata sem cwe → []; INFO → low")

    # MEDIDO NA FASE E: .time.rules[] traz as regras APLICADAS as linguagens
    # presentes, nao as 1074 carregadas — 256/297/297/370 nos quatro CVEs do
    # lote de teste, com as 256 do menor contidas nas 370 do maior. O fixture
    # usa 370, que e o valor real de twbs/bootstrap, e nao mais 1074.
    checar(m["rules_applied"] == 370 and m["ruleset"]["rules_total"] == 1074,
           "rules_applied de .time.rules[]; ruleset do descritor vendorizado",
           m.get("rules_applied"))
    checar("rules_loaded" not in m,
           "o campo antigo rules_loaded NAO sobrevive ao lado do novo")
    checar(m["ruleset"]["name"] == "p/default" and m["ruleset"]["sha256"],
           "ruleset e ESTRUTURA, com sha256 e obtained_at do descritor")
    checar(m["ruleset"]["rules_id_sha256"]
           == "725482bbbcd8439ab473c0139bd114ef92658bada2243dc779e505518e0a14a0",
           "ruleset traz rules_id_sha256: o sha256 identifica o ARQUIVO, este "
           "identifica o CONJUNTO (o registry serve em ordem nao deterministica)",
           m["ruleset"].get("rules_id_sha256"))
    checar(m["analysis_date_source"] == "file_mtime",
           "Semgrep nao tem carimbo de tempo → mtime, origem declarada")
    checar(m["gt_file_scanned"] is True,
           "gt_file_scanned true: paths.scanned contem js/collapse.js")
    checar(m["tool_diagnostics"]["skipped_paths"] == 1
           and m["tool_diagnostics"]["errors"] == 0,
           "errors e paths.skipped contados; notifications null",
           m["tool_diagnostics"])
    checar(m["tool_diagnostics"]["notifications"] is None,
           "Semgrep nao tem toolExecutionNotifications → null, nunca falha")
    checar(m["tool_diagnostics"]["gt_file_affected"] is True,
           "paths.skipped mencionando o gt_file_path → gt_file_affected true")
    checar(rel_sg["caminho"]["caminhos_scanned_transformados"] >= 1,
           "paths.scanned passa pela MESMA normalizacao de caminho")

    falso = ler(tratado_sg / "CVE-2018-16480.json")["metadata"]
    checar(falso["gt_file_scanned"] is False,
           "gt_file_scanned false quando o arquivo nao foi varrido")
    # errors[].type MUDA DE TIPO, como extra.metadata.cwe: cadeia nua numa
    # minoria e ["PartialParsing", [...]] na maioria. A segunda forma so
    # apareceu na saida real da Fase E; nenhum fixture a tinha.
    det = falso["tool_diagnostics"]["details"]
    checar(falso["tool_diagnostics"]["errors"] == 2,
           "os dois errors[] contados", falso["tool_diagnostics"]["errors"])
    checar(any("SourceParseError" in x for x in det),
           "errors[].type como CADEIA NUA vai para o detalhe", det)
    checar(any("PartialParsing" in x for x in det),
           "errors[].type como UNIAO ETIQUETADA tem a etiqueta extraida; "
           "sem isso o detalhe sai sem dizer que erro foi", det)
    checar(rel_sg["gt_file_scanned"] == {"true": 1, "false": 1, "null": 1,
                                         "lista_false": ["CVE-2018-16480"],
                                         "motivos_null": rel_sg["gt_file_scanned"]["motivos_null"]},
           "contagem true/false/null com a lista dos false",
           rel_sg["gt_file_scanned"])
    # rules_applied < rules_total e o caso COMUM, nao anomalia: 370 e 12 nao
    # podem ser reportados. So a violacao do limite superior e sinal, e vem do
    # CVE-2018-1000096, com 1075 > 1074.
    anomalos = rel_sg["semgrep_rules_applied_anomalo"]
    checar([x["cve"] for x in anomalos] == ["CVE-2018-1000096"],
           "so rules_applied > rules_total e anomalia; 370 e 12 NAO sao",
           anomalos)
    checar("ATENCAO" in p.stdout and "rules_applied > rules_total" in p.stdout,
           "a anomalia aparece no console, nao so no JSON do relatorio",
           p.stdout[-400:])
    nulo = ler(tratado_sg / "CVE-2018-1000096.json")["metadata"]
    checar(nulo["gt_file_scanned"] is None and "gt_file_scanned_reason" in nulo,
           "sem paths.scanned → null COM motivo declarado")

    print("\n== Semgrep: falhas previstas ==")
    tratado_sge = tmp / "semgrep-erros"
    rel_sge = tmp / "rel-semgrep-erros.json"
    p = normalizar("semgrep", FIXTURES / "semgrep-erros", tratado_sge, rel_sge)
    checar(p.returncode != 0, "semgrep com defeitos → saida nao nula")
    rel3 = ler(rel_sge)
    motivos = " ".join(x["motivo"] for x in rel3["cves"]["com_falha"])
    checar("time.rules" in motivos, "ausencia de .time e FALHA, nao rules_applied null")
    checar("CRITICAL" in motivos and "CVE-2018-16472" in motivos,
           "severidade fora da tabela falha nomeando valor e CVE", motivos)
    checar(list(tratado_sge.glob("*.json")) == [],
           "nenhum tratado escrito para os dois casos com defeito")
    # Raw integro produzido por invocacao errada NAO e raw ilegivel: a
    # contagem de ilegiveis e dado da monografia e nao pode absorver o outro.
    checar(rel3["raws_ilegiveis"] == [],
           "sem .time e severidade invalida NAO contam como raw ilegivel",
           rel3["raws_ilegiveis"])
    checar(len(rel3["cves"]["com_falha"]) == 2,
           "os dois contam como CVE com falha")

    print("\n== Conjunto de CWE ausente da tabela ==")
    tratado_ca = tmp / "conjunto-ausente"
    rel_ca = tmp / "rel-conjunto-ausente.json"
    p = normalizar("semgrep", FIXTURES / "conjunto-ausente", tratado_ca, rel_ca,
                   extra=["--lista", str(FIXTURES / "listas" / "lista-conjunto-ausente.txt")])
    checar(p.returncode != 0, "conjunto ausente da tabela → falha ruidosa")
    rel4 = ler(rel_ca)
    checar(len(rel4["gt_cwe_primary"]["conjuntos_ausentes_da_tabela"]) == 1,
           "conjunto ausente contado em campo PROPRIO, distinto de primario vazio",
           rel4["gt_cwe_primary"])
    checar(rel4["gt_cwe_primary"]["nulo_primario_indefinido"] == [],
           "ausente da tabela NAO se confunde com primario indefinido")

    # ================= 2.2: validacao da lista pelo proprio normalizador
    print("\n== Validacao da lista de entrada ==")
    listas_ruins = tmp / "listas-ruins"; listas_ruins.mkdir()
    raw_qq = tmp / "raw-qq"; raw_qq.mkdir()
    (raw_qq / "CVE-2018-14040.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {
            "name": "CodeQL", "semanticVersion": "2.25.4", "rules": []}},
            "results": []}]}), encoding="utf-8")
    casos = [
        ("commit-curto.txt",
         "CVE-2018-14040,https://x/y.git,13bf8aea,CWE-079|CWE-116,js/collapse.js,140\n",
         "40 hex"),
        ("cve-invalido.txt",
         "CVE-XX,https://x/y.git,13bf8aeae3db71e28af69782328c22215795c169,"
         "CWE-079|CWE-116,js/collapse.js,140\n",
         "CVE invalido"),
    ]
    for nome, conteudo, esperado in casos:
        alvo = listas_ruins / nome
        alvo.write_text(conteudo, encoding="utf-8")
        pp = normalizar("codeql", raw_qq, tmp / "tr-ruim", tmp / "rel-ruim.json",
                        extra=["--lista", str(alvo)])
        checar(pp.returncode != 0 and esperado in pp.stderr,
               "lista com %s e falha ruidosa no normalizador, nao linha pulada"
               % nome, pp.stderr[-200:])

    # ============================ 3.1: `none` do enum SARIF, mensagem propria
    print("\n== level 'none' do enum SARIF ==")
    raw_none = tmp / "raw-none"; raw_none.mkdir()
    (raw_none / "CVE-2018-14040.sarif").write_text(json.dumps({
        "version": "2.1.0", "runs": [{"tool": {"driver": {
            "name": "CodeQL", "semanticVersion": "2.25.4",
            "rules": [{"id": "js/x", "properties": {"tags": ["external/cwe/cwe-079"]},
                       "defaultConfiguration": {"level": "none"}}]}},
            "results": [{"ruleId": "js/x", "message": {"text": "m"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "js/collapse.js"},
                             "region": {"startLine": 1}}}]}]}]}), encoding="utf-8")
    pp = normalizar("codeql", raw_none, tmp / "tr-none", tmp / "rel-none.json")
    checar(pp.returncode != 0, "'none' continua derrubando o CVE, nao e mapeado")
    checar("VALOR LEGAL DO ENUM SARIF" in pp.stderr,
           "a mensagem nomeia 'none' como valor legal nao previsto, nao como lixo",
           pp.stderr[-300:])
    checar(list((tmp / "tr-none").glob("*.json")) == [],
           "nenhum tratado escrito para o CVE com 'none'")

    # ============================================================ Snyk Code
    print("\n== Snyk Code ==")
    tratado_sn = tmp / "snyk-code"
    rel_sn_path = tmp / "rel-snyk.json"
    p = normalizar("snyk-code", FIXTURES / "snyk-code", tratado_sn, rel_sn_path)
    checar(p.returncode == 0, "snyk normal sai com 0", p.stderr[-600:])
    rel_sn = ler(rel_sn_path)
    t = ler(tratado_sn / "CVE-2018-14040.json")
    m, f = t["metadata"], t["findings"]
    checar(m["ruleset"] is None and m["rules_applied"] is None,
           "Snyk: ruleset nulo inteiro e rules_applied nulo")
    checar(m["analysis_date"] == "2026-09-07T16:11:02Z"
           and m["analysis_date_source"] == "tool",
           "analysis_date extraido de automationDetails.id", m["analysis_date"])
    checar("coverage" in m and isinstance(m["coverage"], list),
           "coverage integro em metadata (so no Snyk)")
    checar(m["gt_file_scanned"] is None,
           "coverage agregada NAO decide sobre um arquivo → null, nao true")
    checar("agregada" in (m.get("gt_file_scanned_reason") or ""),
           "motivo do null declarado", m.get("gt_file_scanned_reason"))
    checar(m["tool_diagnostics"]["notifications"] is None,
           "toolExecutionNotifications ausente → null, NUNCA falha")
    xss = [x for x in f if x["rule_id"] == "javascript%2fXss"][0]
    checar(xss["cwe"] == ["CWE-079"], "CWE do Snyk: 'CWE-79' → CWE-079", xss["cwe"])
    checar(xss["severity_normalized"] == "high" and xss["security_severity"] is None,
           "results[].level do Snyk; security_severity nulo fora do CodeQL")
    pt = [x for x in f if x["rule_id"] == "javascript%2fPT"][0]
    checar(pt["cwe"] == ["CWE-022"], "properties.cwe como cadeia nua no Snyk", pt["cwe"])
    fant = [x for x in f if x["rule_id"] == "javascript%2fFantasma"][0]
    checar(fant["severity_normalized"] == "unresolved",
           "ruleId ausente de driver.rules[] no Snyk tambem nao vira unknown")

    varrido = ler(tratado_sn / "CVE-2018-16480.json")["metadata"]
    checar(varrido["gt_file_scanned"] is True,
           "coverage com inventario de caminhos → gt_file_scanned true")
    checar(varrido["analysis_date_source"] == "file_mtime",
           "sem automationDetails → mtime")
    checar(varrido["tool_diagnostics"]["notifications"] == 1
           and varrido["tool_diagnostics"]["gt_file_affected"] is True,
           "notificacao do Snyk contada e cruzada com o gt_file_path")
    achado = ler(tratado_sn / "CVE-2018-16480.json")["findings"][0]
    checar(achado["file_path"] == "bin/public", "./bin/public → bin/public",
           achado["file_path"])

    print("\n== Snyk Code: raw vazio e truncado ==")
    tratado_sne = tmp / "snyk-erros"
    rel_sne = tmp / "rel-snyk-erros.json"
    p = normalizar("snyk-code", FIXTURES / "snyk-code-erros", tratado_sne, rel_sne)
    checar(p.returncode != 0, "SARIF vazio/truncado do Snyk → saida nao nula")
    checar(list(tratado_sne.glob("*.json")) == [],
           "D.8 SARIF vazio {} NAO vira findings: [] — e o caso que so aqui e pego")
    checar(len(ler(rel_sne)["raws_ilegiveis"]) == 2, "2 raws ilegiveis contados")

    # ======================================================= idempotência
    print("\n== Idempotencia e schema_version ==")
    # Relatorio proprio: reaproveitar relatorio_path sobrescreveria o da
    # primeira execucao, que e o que se inspeciona depois de uma falha.
    rel_idem = tmp / "rel-codeql-idempotencia.json"
    p = normalizar("codeql", FIXTURES / "codeql", tratado_dir, rel_idem)
    checar(ler(rel_idem)["cves"]["pulados_por_idempotencia"] == 5,
           "segunda execucao pula os 5 pela idempotencia")
    p = normalizar("codeql", FIXTURES / "codeql", tratado_dir, rel_idem,
                   extra=["--overwrite"])
    checar(ler(rel_idem)["cves"]["processados"] == 5, "--overwrite reprocessa")

    alvo = tratado_dir / "CVE-2017-16011.json"
    dados = ler(alvo)
    dados["metadata"]["schema_version"] = "0.9"
    alvo.write_text(json.dumps(dados, indent=2), encoding="utf-8")
    p = normalizar("codeql", FIXTURES / "codeql", tratado_dir, rel_idem)
    checar(p.returncode != 0,
           "tratado com schema_version divergente NAO e pulado em silencio")
    checar("0.9" in p.stderr, "a divergencia de schema aparece no stderr", p.stderr[-300:])
    p = normalizar("codeql", FIXTURES / "codeql", tratado_dir, rel_idem,
                   extra=["--overwrite", "--cve", "CVE-2017-16011"])
    checar(p.returncode == 0 and ler(alvo)["metadata"]["schema_version"] == "1.1",
           "--overwrite reprocessa o tratado de schema antigo")

    # =================================== estabilidade da ordem (D.9)
    print("\n== Estabilidade da ordenacao ==")
    baralhado = tmp / "codeql-baralhado"
    baralhado.mkdir()
    origem = ler(FIXTURES / "codeql" / "CVE-2018-14040.sarif")
    origem["runs"][0]["results"].reverse()
    with open(baralhado / "CVE-2018-14040.sarif", "w", encoding="utf-8") as arquivo:
        json.dump(origem, arquivo)
    saida_b = tmp / "tratado-baralhado"
    normalizar("codeql", baralhado, saida_b, tmp / "rel-b.json")
    a = ler(tratado_dir / "CVE-2018-14040.json")["findings"]
    b = ler(saida_b / "CVE-2018-14040.json")["findings"]
    checar([x for x in a] == [x for x in b],
           "reordenar o raw NAO muda o tratado (ordem por chave total, nao de entrada)")

    # ============================================================ check-log
    print("\n== check-log.py ==")
    log_dir = tmp / "logs"; log_dir.mkdir()
    raw_log = tmp / "raw-log"; raw_log.mkdir()
    (raw_log / "CVE-A.sarif").write_text("{}", encoding="utf-8")   # (1) erro COM raw
    (raw_log / "CVE-D.sarif").write_text("{}", encoding="utf-8")   # normal
    log = log_dir / "l.csv"
    log.write_text(
        "cve,repo,commit,status,mensagem,duracao_segundos\n"
        "CVE-A,r,c,ERRO_ANALISE,falhou,10\n"          # (1) tem raw
        "CVE-B,r,c,OK,3 achados,20\n"                 # (2) sem raw
        "CVE-C,r,c,SEM_ARQUIVO_ANALISAVEL,exit 3,5\n" # (3) esperado
        "CVE-D,r,c,ERRO_FETCH,falhou,1\n"
        "CVE-D,r,c,OK,2 achados,30\n",                # dedup: ultima linha vale
        encoding="utf-8")
    p = subprocess.run([sys.executable, str(CHECK_LOG), "--tool", "snyk-code",
                        "--log", str(log), "--raw-dir", str(raw_log)],
                       capture_output=True, text=True)
    saida = p.stdout
    checar("(1) raw existe e o ultimo status e de erro: 1" in saida,
           "check-log (1): raw existe com status de erro", saida)
    checar("(2) status OK/SEM_ACHADOS e nao existe raw: 1" in saida,
           "check-log (2): OK sem raw", saida)
    checar("(3) SEM_ARQUIVO_ANALISAVEL sem raw: 1" in saida,
           "check-log (3): esperado, apenas contado", saida)
    checar("CVE-D" not in saida.split("(3)")[0].split("(1)")[1],
           "dedup mantem a ULTIMA linha: CVE-D nao aparece como erro")
    checar("PULADO sem raw" not in saida,
           "sem PULADO orfao, nada e reportado nessa categoria")
    checar(p.returncode == 1, "check-log com problemas → saida nao nula")

    log2 = log_dir / "l2.csv"
    log2.write_text(
        "cve,repo,commit,status,mensagem,duracao_segundos\n"
        "CVE-D,r,c,OK,2 achados,30\n"
        "CVE-E,r,c,PULADO,saida bruta ja existe,0\n",  # raw sumiu depois
        encoding="utf-8")
    p2 = subprocess.run([sys.executable, str(CHECK_LOG), "--tool", "snyk-code",
                         "--log", str(log2), "--raw-dir", str(raw_log)],
                        capture_output=True, text=True)
    checar("PULADO sem raw: 1" in p2.stdout and "CVE-E" in p2.stdout,
           "PULADO sem raw e anomalia: o raw existia quando o lote rodou",
           p2.stdout)
    checar(p2.returncode == 1, "PULADO orfao → saida nao nula")
    checar("(4) CVE do lote sem raw e sem linha de log: nao conferido" in saida,
           "sem --lista-lote, a (4) se declara NAO conferida em vez de calar")

    lote = log_dir / "lote.txt"
    lote.write_text(
        "CVE-A,https://x/y.git,0123456789abcdef0123456789abcdef01234567,CWE-079,a.js,1\n"
        "CVE-D,https://x/y.git,0123456789abcdef0123456789abcdef01234567,CWE-079,d.js,1\n"
        "CVE-SUMIU,https://x/y.git,0123456789abcdef0123456789abcdef01234567,CWE-079,s.js,1\n",
        encoding="utf-8")
    p4 = subprocess.run([sys.executable, str(CHECK_LOG), "--tool", "snyk-code",
                         "--log", str(log), "--raw-dir", str(raw_log),
                         "--lista-lote", str(lote)], capture_output=True, text=True)
    checar("(4) CVE do lote sem raw e sem linha de log: 1 de 3" in p4.stdout,
           "a (4) acha o CVE que sumiu sem raw e sem linha de log", p4.stdout)
    checar("CVE-SUMIU" in p4.stdout and "sumiu sem deixar rastro" in p4.stdout,
           "o CVE sumido e nomeado")
    checar(p4.returncode == 1, "CVE sumido → saida nao nula")

    lote_grande = log_dir / "lote-grande.txt"
    lote_grande.write_text("".join(
        "CVE-2000-%04d,https://x/y.git,%s,CWE-079,a.js,1\n" % (i, "0" * 40)
        for i in range(70)), encoding="utf-8")
    p5 = subprocess.run([sys.executable, str(CHECK_LOG), "--tool", "snyk-code",
                         "--log", str(log), "--raw-dir", str(raw_log),
                         "--lista-lote", str(lote_grande)],
                        capture_output=True, text=True)
    checar("espera a lista DO LOTE" in p5.stderr,
           "lista grande demais avisa que --lista-lote nao e a lista completa",
           p5.stderr[-200:])

    p = subprocess.run([sys.executable, str(CHECK_LOG), "--tool", "snyk-code",
                        "--log", str(log_dir / "inexistente.csv"),
                        "--raw-dir", str(raw_log)], capture_output=True, text=True)
    checar(p.returncode == 2 and "ausente" in p.stderr,
           "log ausente → mensagem clara e saida nao nula, sem excecao")

    # ================================ independencia do log de execucao
    print("\n== Invariantes de acoplamento ==")
    fonte = NORMALIZE.read_text(encoding="utf-8")
    checar("execution-log" not in fonte.replace(
        "logs/execution-log-*.csv", "").replace("execution-log-*.csv", ""),
        "normalize.py nao referencia o log de execucao fora dos comentarios")
    checar("check-log" not in fonte.split('"""')[2],
           "normalize.py nao importa nem invoca check-log.py")
    checar("import normalize" not in CHECK_LOG.read_text(encoding="utf-8"),
           "check-log.py nao importa normalize.py")

    print("\n%d verificacoes, %d falha(s)" % (verificacoes, len(falhas)))
    for descricao in falhas:
        print("  FALHOU: %s" % descricao)
    print("temporarios em %s" % tmp)
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
