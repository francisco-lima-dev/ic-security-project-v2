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

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FIXTURES = RAIZ / "tests" / "fixtures"
NORMALIZE = RAIZ / "tools" / "normalize.py"
CHECK_LOG = RAIZ / "tools" / "check-log.py"
CRUZA = RAIZ / "tools" / "cruza-deteccao.py"
LISTA_REAL = RAIZ / "datasets" / "listas" / "cves-sast.txt"

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
    # Schema 1.3: o CodeQL DECIDE, pela notificacao
    # js/diagnostics/successfully-extracted-files. js/collapse.js esta nela e
    # NAO tem achado — o caso que motiva o campo inteiro.
    checar(m["gt_file_scanned"] is True,
           "gt_file_scanned do CodeQL: true pela notificacao de extraidos",
           m["gt_file_scanned"])
    checar([x for x in f if x["file_path"] == "js/collapse.js"] == []
           or m["gt_file_scanned"] is True,
           "arquivo extraido e sem achado sai true, nao null")
    checar(m["tool_diagnostics"]["notifications"] == 2,
           "toolExecutionNotifications contadas", m["tool_diagnostics"]["notifications"])
    checar(m["tool_diagnostics"]["errors"] is None
           and m["tool_diagnostics"]["skipped_paths"] is None,
           "campos sem fonte no CodeQL ficam null, nao zero")
    # gt_file_affected foi REMOVIDO no schema 1.2: a polaridade invertia entre
    # ferramentas (no CodeQL as notificacoes sao de extracao BEM-SUCEDIDA) e o
    # booleano era calculado sobre a lista inteira enquanto details guarda so
    # as 20 primeiras — o registro nao sustentava a propria afirmacao.
    checar("gt_file_affected" not in m["tool_diagnostics"]
           and "gt_file_affected_method" not in m["tool_diagnostics"],
           "gt_file_affected e gt_file_affected_method NAO sobrevivem ao 1.2",
           sorted(m["tool_diagnostics"]))
    checar(any("js/collapse.js" in d for d in m["tool_diagnostics"]["details"]),
           "o caminho continua legivel em details[], sem virar conclusao",
           m["tool_diagnostics"]["details"])

    # metadata
    checar(m["schema_version"] == "1.3" and m["tool"] == "codeql", "metadata basico")
    checar(m["commit"] == "13bf8aeae3db71e28af69782328c22215795c169",
           "commit vem da LISTA de entrada", m["commit"])
    checar(m["ruleset"]["rules_total"] == 104 and m["rules_applied"] is None,
           "CodeQL: rules_total 104, rules_applied NULO")
    checar(m["ruleset"]["rules_id_sha256"] is None,
           "rules_id_sha256 nulo fora do Semgrep — nao ha pack de arquivo")
    # O motivo acompanha os TRES estados desde o 1.3, e diz de que UNIVERSO
    # o valor saiu: extraidos (CodeQL) nao e o mesmo que varridos (Semgrep).
    checar("EXTRAIDOS" in m["gt_file_scanned_reason"],
           "o motivo acompanha o true, nao so o null, e nomeia o universo",
           m.get("gt_file_scanned_reason"))
    # artifacts[] foi DESCARTADO como fonte: e superconjunto contaminado por
    # outras linguagens. A conferencia do teto o usa DEPURADO, so para contar.
    inv = {x["cve"]: x for x in rel["codeql_inventario"]}
    checar(inv["CVE-2018-14040"]["notificacao"] == 2
           and inv["CVE-2018-14040"]["bate"] is True,
           "conferencia do teto: notificacao x artifacts depurado", inv.get("CVE-2018-14040"))
    checar(inv["CVE-2018-16480"]["notificacao"] == 2
           and inv["CVE-2018-16480"]["artifacts_depurado"] == 2
           and inv["CVE-2018-16480"]["bate"] is True,
           "o .rb citado por notificacao de outra linguagem sai de artifacts na "
           "depuracao — usar artifacts cru reportaria varrido o que o extrator "
           "de JS nao tocou", inv.get("CVE-2018-16480"))
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
    checar(vazio["tool_diagnostics"]["notifications"] is None
           and vazio["tool_diagnostics"]["details"] == [],
           "sem fonte alguma de diagnostico → contagens null e details vazio",
           vazio["tool_diagnostics"])
    # Os TRES estados do tri-estado no CodeQL, que a decisao do 1.3 cria.
    # (null) notificacao AUSENTE nao e false: ausencia de inventario e
    # ausencia do arquivo no inventario sao coisas distintas — mesmo
    # principio que separa unknown de unresolved na severidade.
    checar(vazio["gt_file_scanned"] is None,
           "notificacao ausente → null, NUNCA false", vazio["gt_file_scanned"])
    checar("sem notificacao" in vazio["gt_file_scanned_reason"],
           "e o motivo diz que faltou o inventario, nao que faltou o arquivo",
           vazio.get("gt_file_scanned_reason"))
    # (false) notificacao presente, gt_file_path fora dela
    fora = ler(tratado_dir / "CVE-2018-16480.json")["metadata"]
    checar(fora["gt_file_scanned"] is False,
           "gt_file_path ausente do inventario → false", fora["gt_file_scanned"])
    checar("EXTRAIDOS" in fora["gt_file_scanned_reason"],
           "o motivo acompanha o false e nomeia o universo",
           fora.get("gt_file_scanned_reason"))
    checar(rel["gt_file_scanned"]["true"] >= 1
           and "CVE-2018-16480" in rel["gt_file_scanned"]["lista_false"]
           and rel["gt_file_scanned"]["null"] >= 1,
           "o relatorio do CodeQL passa a ter os tres estados",
           rel["gt_file_scanned"])
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
    checar(any("js/collapse.js" in d for d in m["tool_diagnostics"]["details"]),
           "no Semgrep o details[] segue trazendo o caminho mencionado",
           m["tool_diagnostics"]["details"])
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
    varrido_sg = rel_sg["gt_file_scanned"]
    checar((varrido_sg["true"], varrido_sg["false"], varrido_sg["null"],
            varrido_sg["lista_false"]) == (1, 1, 1, ["CVE-2018-16480"]),
           "contagem true/false/null com a lista dos false", varrido_sg)
    checar(set(varrido_sg["motivos_por_estado"]) == {"true", "false", "null"},
           "o motivo e agregado nos TRES estados, nao so no null",
           sorted(varrido_sg["motivos_por_estado"]))
    checar(all("VARRIDOS" in motivo
               for estado in ("true", "false")
               for motivo in varrido_sg["motivos_por_estado"][estado]),
           "no Semgrep o motivo nomeia o universo VARRIDOS nos dois booleanos")
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
    # 3.4: FAILED_PARSING promovido a tool_diagnostics.errors. A entrada real
    # traz CONTAGEM, nunca caminhos, e o detalhe tem de declarar isso — senao
    # quem le "errors: 8" supoe saber quais arquivos.
    checar(m["tool_diagnostics"]["errors"] == 8,
           "FAILED_PARSING promovido a errors: 7 .html + 1 .xml",
           m["tool_diagnostics"]["errors"])
    checar(any("nao discrimina caminhos" in d for d in m["tool_diagnostics"]["details"]),
           "o detalhe declara que a contagem nao discrimina caminhos",
           m["tool_diagnostics"]["details"])
    checar(t["metadata"]["cve_id"] in rel_sn["tool_diagnostics"]["cves_com_erro"],
           "o CVE entra em cves_com_erro pela cobertura, nao so por notificacao")
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
    # Guarda nova: caminho listado sob entrada NAO suportada nao e "varrido".
    # Hoje o Snyk so emite contagem, entao o ramo e defensivo — mas se um dia
    # enumerar caminhos, contar um arquivo que ele nao conseguiu ler daria
    # gt_file_scanned true para arquivo nunca analisado.
    checar(varrido["tool_diagnostics"]["errors"] == 1,
           "entrada FAILED_PARSING com caminho tambem conta como erro",
           varrido["tool_diagnostics"]["errors"])
    checar(varrido["gt_file_scanned"] is True,
           "coverage com inventario de caminhos → gt_file_scanned true")
    checar(varrido["analysis_date_source"] == "file_mtime",
           "sem automationDetails → mtime")
    checar(varrido["tool_diagnostics"]["notifications"] == 1
           and any("bin/public" in d for d in varrido["tool_diagnostics"]["details"]),
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
    checar(p.returncode == 0 and ler(alvo)["metadata"]["schema_version"] == "1.3",
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

    # O embaralhamento acima so exercitava o CodeQL, cujo fixture tem 1
    # colisao. As 11 colisoes REAIS da Fase E foram todas do Semgrep, e sao
    # elas que a coluna no schema 1.2 passou a distinguir — logo e no Semgrep
    # que a estabilidade precisa ser exercitada.
    bar_sg = tmp / "semgrep-baralhado"; bar_sg.mkdir()
    origem_sg = ler(FIXTURES / "semgrep" / "CVE-2018-14040.json")
    origem_sg["results"].reverse()
    with open(bar_sg / "CVE-2018-14040.json", "w", encoding="utf-8") as arquivo:
        json.dump(origem_sg, arquivo)
    saida_sg = tmp / "tratado-baralhado-sg"
    normalizar("semgrep", bar_sg, saida_sg, tmp / "rel-bsg.json")
    checar(ler(tratado_sg / "CVE-2018-14040.json")["findings"]
           == ler(saida_sg / "CVE-2018-14040.json")["findings"],
           "reordenar o raw do SEMGREP tambem nao muda o tratado")

    # =================================== colunas no schema (1.2)
    print("\n== Colunas no schema e na chave de ordenacao ==")
    for ferramenta, tratado in (("codeql", tratado_dir), ("semgrep", tratado_sg),
                                ("snyk-code", tratado_sn)):
        achados = ler(tratado / "CVE-2018-14040.json")["findings"]
        checar(all("column_start" in x and "column_end" in x for x in achados),
               "%s: todo achado tem column_start e column_end" % ferramenta)
    col = [x for x in ler(tratado_sg / "CVE-2018-14040.json")["findings"]
           if x["column_start"] is not None]
    checar(col, "o Semgrep grava coluna de fato, nao so a chave nula")
    # Dois achados que so diferem na coluna tem de sair em ordem estavel e
    # DISTINGUIVEL: antes do 1.2 eles empatavam na chave total.
    import itertools as _it
    achados_sg = ler(tratado_sg / "CVE-2018-14040.json")["findings"]
    chaves = [(x["file_path"], x["line_start"], x["line_end"],
               x["column_start"], x["column_end"], x["rule_id"], x["message"])
              for x in achados_sg]
    checar(len(chaves) == len(set(chaves)),
           "com a coluna na chave, nenhum achado do fixture empata em TODOS os "
           "campos que o schema grava")

    # =================================== limite inferior de rules_applied
    print("\n== rules_applied: os dois limites ==")
    raw_zero = tmp / "raw-rules-zero"; raw_zero.mkdir()
    base_zero = ler(FIXTURES / "semgrep" / "CVE-2018-14040.json")
    base_zero["time"]["rules"] = []
    (raw_zero / "CVE-2018-14040.json").write_text(json.dumps(base_zero), encoding="utf-8")
    rel_zero = tmp / "rel-zero.json"
    pz = normalizar("semgrep", raw_zero, tmp / "tr-zero", rel_zero)
    anom = ler(rel_zero)["semgrep_rules_applied_anomalo"]
    checar([x["rules_applied"] for x in anom] == [0],
           "rules_applied == 0 e anomalia: findings vazio nao significa ausencia "
           "de achados. A guarda `!=` antiga pegava isso de graca; a `>` sozinha "
           "deixaria sem vigia", anom)
    checar("ATENCAO" in pz.stdout, "o limite inferior tambem grita no console",
           pz.stdout[-300:])
    checar([x["rules_applied"] for x in ler(rel_sg_path)["semgrep_rules_applied"]] == [1075, 370, 12],
           "o valor de rules_applied de CADA CVE fica registrado no relatorio, "
           "nao so as anomalias",
           ler(rel_sg_path)["semgrep_rules_applied"])

    # =================================== terceira forma de errors[].type
    raw_t3 = tmp / "raw-tipo3"; raw_t3.mkdir()
    base_t3 = ler(FIXTURES / "semgrep" / "CVE-2018-14040.json")
    base_t3["errors"] = [{"level": "warn", "type": {"inesperado": 1},
                          "message": "algo", "path": "js/collapse.js"}]
    (raw_t3 / "CVE-2018-14040.json").write_text(json.dumps(base_t3), encoding="utf-8")
    rel_t3 = tmp / "rel-t3.json"
    normalizar("semgrep", raw_t3, tmp / "tr-t3", rel_t3)
    inesperados = ler(rel_t3)["cwe"]["semgrep_tipo_inesperado"]
    checar([x.get("campo") for x in inesperados] == ["errors[].type"],
           "terceira forma de errors[].type e CONTADA, nao silenciada: sem isso "
           "o detalhe sai parecendo completo e sem dizer que erro foi",
           inesperados)

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

    # ================== obtencao do codigo: estouro distinguivel de recusa
    # Fase G-1b. O rc do `timeout` no fetch raso e no clone de contingencia
    # era consumido pela condicao do `if` e se perdia: estouro do limite
    # (124) e recusa do servidor (`upload-pack: not our ref`, 128) caiam no
    # mesmo ramo e produziam a MESMA linha de log. Sao causas opostas —
    # lentidao contra ausencia do objeto — e a contagem de fallback, que o
    # protocolo exige como metrica de vigilancia, somava as duas no mesmo
    # balde.
    #
    # O ramo e exercitado por EXECUCAO REAL do script, com um stub de
    # `timeout` que devolve o codigo pedido em vez de medir tempo.
    #
    # Do que o ensaio depende no hospedeiro, declarado: `bash` e `git` (o
    # `git init` e o `git remote add` nao estao sob timeout e usam o git
    # real) e, se houver, o `codeql` do hospedeiro, invocado por
    # `codeql version` ANTES do laco e portanto fora do stub — o ensaio
    # passa com ou sem ele, mas o prefixo de versao da linha de log muda.
    #
    # O `exec "$@"` do stub e a parte honesta dele, e tambem a razao pela
    # qual a independencia de `codeql` vale so para os rc escolhidos aqui:
    # um cenario futuro com STUB_RC_FETCH=0 deixaria a analise rodar de
    # verdade no hospedeiro. Nos dois cenarios abaixo o laco da `continue`
    # antes disso.
    #
    # O script fixa WORKDIR=/tmp/src-$CVE_ID, fora do tempdir da suite e nao
    # parametrizavel; dai o CVE sintetico, que nenhuma campanha usa.
    #
    # O ensaio roda sobre o script do CodeQL, e a identidade do bloco nos
    # tres, asseverada abaixo, e o que o estende aos outros dois.
    print("\n== Obtencao do codigo: estouro distinguivel de recusa ==")
    obt = tmp / "obtencao"
    stub = obt / "stub"
    stub.mkdir(parents=True)
    (stub / "timeout").write_text(
        '#!/bin/sh\n'
        'shift\n'                      # descarta a duracao; $@ vira o comando
        'case "$*" in\n'
        '  *fetch*) exit "${STUB_RC_FETCH:-124}" ;;\n'
        '  *clone*) exit "${STUB_RC_CLONE:-124}" ;;\n'
        'esac\n'
        'exec "$@"\n', encoding="utf-8")
    (stub / "timeout").chmod(0o755)

    ws = obt / "ws"
    (ws / "datasets" / "listas").mkdir(parents=True)
    lista_obt = ws / "datasets" / "listas" / "lote"
    lista_obt.write_text(
        "CVE-0000-00000,https://github.com/x/y.git,"
        "0123456789abcdef0123456789abcdef01234567,CWE-079,a.js,1\n",
        encoding="utf-8")
    RUN_CODEQL = RAIZ / "ic-security-lab-codeql" / "scripts" / "run_codeql.sh"

    def ambiente_sem_limites():
        # Fase H, H0b: os run_*.sh passaram a ler TIMEOUT_* do ambiente.
        # Copiar o ambiente de quem roda a suite SEM retira-los faria o
        # resultado depender do shell do operador: um TIMEOUT_FETCH=60
        # exportado trocaria o "excedeu 300s" asseverado adiante, e um valor
        # invalido pararia o script na guarda de limites. Retira todo
        # TIMEOUT_*, nao so os cinco nomes atuais: nome acrescentado depois
        # nao pode reabrir o vazamento.
        env = dict(os.environ)
        for chave in [k for k in env if k.startswith("TIMEOUT_")]:
            del env[chave]
        # O bash nao interativo carrega o arquivo apontado por BASH_ENV, que
        # pode definir TIMEOUT_* — o mesmo vazamento por outro caminho.
        env.pop("BASH_ENV", None)
        return env

    def rodar_obtencao(rc_fetch, rc_clone):
        logs = ws / "logs"
        if logs.exists():
            shutil.rmtree(logs)
        env = ambiente_sem_limites()
        env["PATH"] = "%s:%s" % (stub, env.get("PATH", ""))
        env["WORKSPACE"] = str(ws)
        env["STUB_RC_FETCH"] = str(rc_fetch)
        env["STUB_RC_CLONE"] = str(rc_clone)
        # A guarda de integridade do bundle roda ANTES do laco e exige o
        # ENV que a imagem grava no build. Aqui se roda o script fora da
        # imagem, entao o ENV e suprido: sem ele o script aborta — e essa
        # fatalidade e asseverada em secao propria adiante, nao aqui.
        env["CODEQL_BUNDLE_SHA256"] = "a" * 64
        r = subprocess.run(["bash", str(RUN_CODEQL), str(lista_obt)],
                           env=env, capture_output=True, text=True)
        # Log ausente e RESULTADO da verificacao — o script nao chegou a
        # registrar —, e tem de sair como falha legivel. Deixar o
        # FileNotFoundError subir mataria a suite e suprimiria em silencio
        # todas as assercoes seguintes. Mesma blindagem de bloco_obtencao().
        alvo = logs / "execution-log-codeql.csv"
        if not alvo.is_file():
            return ("SEM_LOG: o log de execucao NAO FOI GERADO por %s (rc=%d); "
                    "stderr=%s" % (alvo.name, r.returncode, r.stderr[-200:]))
        linhas = alvo.read_text(encoding="utf-8").strip().splitlines()
        return linhas[-1] if linhas else ("LOG_VAZIO: %s existe e nao tem linha "
                                          "alguma" % alvo.name)

    # Campo de status POR POSICAO, sem excecao. O marcador devolvido acima
    # quando o log nao existe nao tem seis campos, e o `partes[3]` direto
    # levantava IndexError: a suite inteira morria com traceback, em vez de
    # ESTA verificacao falhar e as seguintes seguirem. Este arquivo e o portao
    # que roda 24 vezes na campanha, uma vez por job, e perder o portao inteiro
    # e pior que perder uma verificacao — o defeito e anterior a Fase H e foi
    # observado num mutante de H0b.
    #
    # Com log presente o valor devolvido e o mesmo `partes[3]` de antes: a
    # verificacao nao muda, e a contagem de verificacoes tampouco.
    def status_da_linha(linha):
        partes = linha.split(",")
        if len(partes) > 3:
            return partes[3]
        return "SEM_CAMPO_DE_STATUS (%s)" % linha[:160]

    l_estouro = rodar_obtencao(124, 124)
    l_recusa = rodar_obtencao(128, 128)

    checar(l_estouro != l_recusa,
           "estouro do limite e recusa do servidor NAO produzem mais a mesma "
           "linha de log: era o defeito que contaminava a contagem de fallback",
           "%s || %s" % (l_estouro, l_recusa))
    checar("fetch raso excedeu 300s" in l_estouro,
           "o estouro do fetch e nomeado COM o valor do limite", l_estouro)
    checar("clone completo excedeu 900s" in l_estouro,
           "o estouro do clone de contingencia e nomeado COM o valor do limite",
           l_estouro)
    checar("fetch raso saiu com 128" in l_recusa
           and "clone completo saiu com 128" in l_recusa,
           "a recusa do servidor e registrada com o codigo que o git devolveu",
           l_recusa)
    checar("excedeu" not in l_recusa,
           "recusa do servidor NUNCA e descrita como estouro de limite",
           l_recusa)
    checar(all(len(x.split(",")) == 6 for x in (l_estouro, l_recusa)),
           "a mensagem nova nao tem virgula: o CSV continua com 6 campos",
           "%d || %d" % (len(l_estouro.split(",")), len(l_recusa.split(","))))
    checar(all(status_da_linha(x) == "ERRO_FETCH" for x in (l_estouro, l_recusa)),
           "o conjunto de status e fechado: a correcao muda a mensagem e NAO "
           "acrescenta status",
           "%s || %s" % (status_da_linha(l_estouro), status_da_linha(l_recusa)))

    # A suite NAO executa os outros dois scripts — eles exigem pack em
    # /default.yaml e SNYK_TOKEN. O que estende o ensaio a eles e a
    # identidade byte a byte do bloco de obtencao.
    def bloco_obtencao(caminho):
        # Devolve None em vez de estourar: marcador ausente e RESULTADO da
        # verificacao — o script deixou de ter a forma esperada —, e tem de
        # sair como falha legivel, nunca como traceback que derruba a suite
        # inteira e esconde as assercoes seguintes.
        linhas = caminho.read_text(encoding="utf-8").splitlines()
        ini = [i for i, l in enumerate(linhas) if 'timeout "$TIMEOUT_FETCH"' in l]
        # O fim tem de vir DEPOIS do inicio: com `fim` sendo apenas o
        # primeiro REF="$COMMIT" do arquivo, um deslocamento futuro daria
        # fatia VAZIA, e tres blocos vazios satisfariam a igualdade adiante
        # — a assercao imprimiria `ok` tendo comparado nada.
        fim = [i for i, l in enumerate(linhas)
               if l.strip() == 'REF="$COMMIT"' and ini and i > ini[0]]
        if not ini or not fim:
            return None
        bloco = "\n".join(linhas[ini[0]:fim[0] + 1])
        return bloco if bloco.strip() else None

    blocos = {}
    for pasta in ("codeql", "semgrep", "snyk-code"):
        blocos[pasta] = bloco_obtencao(
            RAIZ / ("ic-security-lab-%s" % pasta) / "scripts"
            / ("run_%s.sh" % pasta))
    ausentes = [k for k, v in blocos.items() if v is None]
    checar(not ausentes,
           "o bloco de obtencao foi localizavel nos tres scripts",
           "sem marcador em: %s" % ausentes)
    checar(not ausentes and len(set(blocos.values())) == 1,
           "o bloco de obtencao e IDENTICO nos tres scripts: sem isso o ensaio "
           "acima valeria so para o CodeQL",
           "; ".join("%s:%s" % (k, "AUSENTE" if v is None
                                else "%d linhas" % (v.count(chr(10)) + 1))
                     for k, v in blocos.items()))

    for pasta, bloco in blocos.items():
        if bloco is None:
            continue
        atribuicoes = [l for l in bloco.splitlines()
                       if "MOTIVO_FETCH=" in l or "MOTIVO_CLONE=" in l
                       or 'MENSAGEM="fallback' in l]
        checar(len(atribuicoes) == 5 and not any("," in l for l in atribuicoes),
               "%s: as 5 mensagens novas existem e nenhuma tem virgula" % pasta,
               atribuicoes)

    for pasta in ("codeql", "semgrep", "snyk-code"):
        fonte_sh = (RAIZ / ("ic-security-lab-%s" % pasta) / "scripts"
                    / ("run_%s.sh" % pasta)).read_text(encoding="utf-8")
        checar("timeout 300 " not in fonte_sh and "timeout 900 " not in fonte_sh,
               "%s: nao sobrou literal de limite fora da constante" % pasta)

    # Defaults e sobrescrita dos limites, por EXECUCAO dos tres scripts.
    # Fase H, H0b: os limites viraram `${VAR-default}`. A assercao anterior
    # procurava o literal `TIMEOUT_FETCH=300` na fonte, e era a UNICA protecao
    # do default do Semgrep e do Snyk: o ensaio de obtencao acima roda so o
    # CodeQL, e o bloco comparado por identidade nao inclui as atribuicoes.
    #
    # Por execucao, e nao por grafia: a linha "limites efetivos em segundos:"
    # sai logo apos a guarda de limites e ANTES das guardas de pack, token e
    # sha256 — que aqui abortam por falta do ENV da imagem —, entao os tres
    # scripts a emitem fora da imagem e sem trabalho algum. Sem TIMEOUT_* no
    # ambiente, o que ela imprime SAO os defaults.
    #
    # Tres bracos, cada um pegando o que os outros deixam passar:
    #   default     — valor do codigo mudou, ou a linha deixou de ser emitida
    #   sobrescrita — o script ignora o ambiente (nome trocado, atribuicao
    #                 direta de volta)
    #   vazia       — `${VAR:-default}` de volta em QUALQUER das variaveis: a
    #                 vazia cairia no default em silencio em vez de parar
    #                 na guarda
    print("\n== Limites de tempo: defaults, sobrescrita e guarda ==")
    lim = obt / "limites-ws"   # nunca criado: o script aborta antes de usa-lo
    LIMITES = {
        "codeql": [("TIMEOUT_CREATE", "3600"), ("TIMEOUT_ANALYZE", "3600"),
                   ("TIMEOUT_FETCH", "300"), ("TIMEOUT_CLONE", "900")],
        "semgrep": [("TIMEOUT_ANALISE", "1800"),
                    ("TIMEOUT_FETCH", "300"), ("TIMEOUT_CLONE", "900")],
        "snyk-code": [("TIMEOUT_ANALISE", "1800"),
                      ("TIMEOUT_FETCH", "300"), ("TIMEOUT_CLONE", "900")],
    }

    def linha_limites(pares):
        return "limites efetivos em segundos: %s\n" % "; ".join(
            "%s=%s" % par for par in pares)

    def rodar_limites(pasta, extra):
        env = ambiente_sem_limites()
        # Sem o ENV da imagem e sem token: o script TEM de parar na guarda
        # seguinte a linha de limites. Com SNYK_TOKEN herdado do operador, o
        # do Snyk passaria adiante e invocaria `snyk --version`.
        for chave in ("PACK_SHA256", "SNYK_TOKEN", "SNYK_CLI_SHA256",
                      "CODEQL_BUNDLE_SHA256"):
            env.pop(chave, None)
        env["WORKSPACE"] = str(lim)
        env.update(extra)
        return subprocess.run(
            ["bash", str(RAIZ / ("ic-security-lab-%s" % pasta) / "scripts"
                         / ("run_%s.sh" % pasta))],
            env=env, capture_output=True, text=True)

    # A mensagem da guarda SEGUINTE a de limites, e nao so `rc == 1`: sem ela
    # a parada poderia vir de causa alheia — "lista nao encontrada", adiante,
    # tambem sai 1 — e a descricao "para na guarda seguinte" ficaria sem
    # conferencia.
    GUARDA_SEGUINTE = {
        "codeql": "ERRO: CODEQL_BUNDLE_SHA256 nao definido na imagem.",
        "semgrep": "ERRO: PACK_SHA256 nao definido.",
        "snyk-code": "ERRO: SNYK_TOKEN nao definido no ambiente.",
    }

    for pasta, pares in LIMITES.items():
        r = rodar_limites(pasta, {})
        checar(r.returncode == 1 and linha_limites(pares) in r.stderr
               and GUARDA_SEGUINTE[pasta] in r.stderr
               and "nao e um inteiro" not in r.stderr,
               "%s: sem TIMEOUT_* no ambiente, os limites efetivos sao os "
               "defaults do codigo, e o script para na guarda seguinte" % pasta,
               "rc=%d %s" % (r.returncode, r.stderr[-300:]))

        # Valores distintos por variavel: um mesmo valor em todas deixaria
        # passar duas variaveis trocadas entre si.
        outros = [(nome, str(11 + i)) for i, (nome, _) in enumerate(pares)]
        r = rodar_limites(pasta, dict(outros))
        checar(r.returncode == 1 and linha_limites(outros) in r.stderr
               and GUARDA_SEGUINTE[pasta] in r.stderr,
               "%s: TIMEOUT_* definido no ambiente sobrescreve o default, "
               "variavel a variavel" % pasta,
               "rc=%d %s" % (r.returncode, r.stderr[-300:]))

        # Vazio e zero, variavel a variavel. O zero e o caso que a guarda
        # existe para barrar: para o GNU `timeout` ele DESLIGA o limite com
        # rc 0, e sem a guarda nada falharia. Um afrouxamento da forma para
        # `^[0-9]+$` passaria por todos os outros bracos.
        for nome, _ in pares:
            for invalido, rotulo in (("", "VAZIO, e nao cai no default"),
                                     ("0", "ZERO, que desligaria o limite")):
                r = rodar_limites(pasta, {nome: invalido})
                checar(r.returncode == 1
                       and ("ERRO: %s nao e um inteiro positivo" % nome) in r.stderr
                       and ("obtido: '%s'" % invalido) in r.stderr
                       and "limites efetivos" not in r.stderr,
                       "%s: %s definido %s, para na guarda antes de qualquer "
                       "trabalho" % (pasta, nome, rotulo),
                       "rc=%d %s" % (r.returncode, r.stderr[-300:]))

    # check-log.py continua aceitando o que o script passou a escrever. O
    # status nao mudou, entao a classificacao nao pode ter mudado.
    log_obt = ws / "logs" / "obtencao.csv"
    # O diretorio pode NAO existir: rodar_obtencao() apaga ws/logs a cada braco,
    # e script que morre antes das pre-condicoes nao o recria. Sem esta linha a
    # suite morria aqui com FileNotFoundError — depois de a verificacao anterior
    # ja ter falhado de forma nomeada, e antes das secoes seguintes. Com o log
    # presente, criar o pai que ja existe nao muda nada.
    log_obt.parent.mkdir(parents=True, exist_ok=True)
    log_obt.write_text(
        "cve,repo,commit,status,mensagem,duracao_segundos\n"
        + l_estouro.replace("CVE-0000-00000", "CVE-X", 1) + "\n"
        + l_recusa.replace("CVE-0000-00000", "CVE-Y", 1) + "\n",
        encoding="utf-8")
    raw_vazio = obt / "raw-vazio"
    raw_vazio.mkdir()
    p_obt = subprocess.run(
        [sys.executable, str(CHECK_LOG), "--tool", "codeql",
         "--log", str(log_obt), "--raw-dir", str(raw_vazio)],
        capture_output=True, text=True)
    checar(p_obt.returncode == 0,
           "check-log.py aceita as linhas novas sem anomalia: erro sem raw e "
           "o caso normal",
           p_obt.stdout[-300:] + p_obt.stderr[-300:])
    checar("(1) raw existe e o ultimo status e de erro: 0" in p_obt.stdout,
           "check-log.py continua classificando ERRO_FETCH como status de erro",
           p_obt.stdout[-300:])

    # Estas duas linhas NAO sao escritas a mao: sairam da execucao real do
    # run_codeql.sh acima. Assertar a (5) sobre elas e o que amarra as
    # constantes do check-log.py ao texto que o script emite. Fixture escrita
    # a mao a partir da mesma fonte que as constantes seria tautologia: um
    # erro de copia estaria nos dois lados e passaria pela suite inteira.
    checar("fallback de clone completo: 2\n" in p_obt.stdout,
           "(5) reconhece o fallback em linha PRODUZIDA PELO SCRIPT, nao em "
           "fixture escrita a mao", p_obt.stdout[-600:])
    checar("novo 2 | antigo 0  (" in p_obt.stdout,
           "(5) classifica a linha real do script como vocabulario novo",
           p_obt.stdout[-600:])
    checar("causa do fetch:   estouro do limite 1 | outro codigo 1 | "
           "indeterminada 0\n" in p_obt.stdout,
           "(5) discrimina a causa nas linhas reais: uma por estouro e uma "
           "por outro codigo", p_obt.stdout[-600:])
    checar("causa do clone:   estouro do limite 1 | outro codigo 1 | "
           "indeterminada 0\n" in p_obt.stdout,
           "(5) discrimina a causa do clone nas linhas reais",
           p_obt.stdout[-600:])
    checar("NAO RECONHECIDO" not in p_obt.stdout,
           "nenhum segmento das linhas reais do script escapa ao vocabulario "
           "declarado: e a conferencia de que as constantes nao divergiram",
           p_obt.stdout[-600:])

    # ============ guarda de integridade do bundle e do CLI, em runtime
    # Fase G-2c. E a SEGUNDA comparacao de sha256, analoga a do pack do
    # Semgrep: a primeira vive no build (Dockerfile confere o download
    # contra o --build-arg); esta pega o modo de falha que aquela nao
    # alcanca — o descritor versionado mudou e ninguem reconstruiu.
    #
    # ASSIMETRIA: a do Semgrep termina em BYTES dos dois lados; esta
    # compara DOIS VALORES DECLARADOS, o ENV da imagem contra o campo do
    # descritor. Nao estabelece que /opt/codeql corresponde ao hash.
    print("\n== Guarda de integridade em runtime (segunda comparacao) ==")
    gi = tmp / "guarda"
    (gi / "ic-security-lab-codeql").mkdir(parents=True)
    lista_gi = gi / "lista"
    lista_gi.write_text("", encoding="utf-8")
    DESCRITOR_GI = gi / "ic-security-lab-codeql" / "codeql-bundle.meta.json"

    def rodar_guarda(env_sha, descritor_sha):
        """descritor_sha None = repositorio NAO montado (descritor ausente)."""
        if descritor_sha is None:
            if DESCRITOR_GI.exists():
                DESCRITOR_GI.unlink()
        else:
            DESCRITOR_GI.write_text(
                json.dumps({"sha256": descritor_sha}), encoding="utf-8")
        env = ambiente_sem_limites()
        env["WORKSPACE"] = str(gi)
        env["PATH"] = "%s:%s" % (stub, env.get("PATH", ""))
        env["STUB_RC_FETCH"] = "124"
        env["STUB_RC_CLONE"] = "124"
        if env_sha is None:
            env.pop("CODEQL_BUNDLE_SHA256", None)
        else:
            env["CODEQL_BUNDLE_SHA256"] = env_sha
        return subprocess.run(["bash", str(RUN_CODEQL), str(lista_gi)],
                              env=env, capture_output=True, text=True)

    SHA_A, SHA_B = "a" * 64, "b" * 64

    r = rodar_guarda(SHA_A, SHA_A)
    checar(r.returncode == 0 and "obsoleta" not in r.stderr,
           "guarda: ENV coincide com o descritor -> execucao segue",
           "rc=%d %s" % (r.returncode, r.stderr[-200:]))
    # `rc == 0` sozinho e observacao fraca: prova que nao abortou, nao que
    # chegou adiante. O log so nasce nas PRE-CONDICOES, depois da guarda.
    checar((gi / "logs" / "execution-log-codeql.csv").is_file(),
           "guarda: com ENV coincidente a execucao passa das PRE-CONDICOES, "
           "nao apenas da guarda — o log foi criado")

    r = rodar_guarda(SHA_A, SHA_B)
    checar(r.returncode == 1 and "obsoleta em relacao ao descritor" in r.stderr,
           "guarda: ENV DIVERGE do descritor -> aborta. E o modo de falha "
           "visado: descritor mudou e ninguem reconstruiu a imagem",
           "rc=%d %s" % (r.returncode, r.stderr[-300:]))

    r = rodar_guarda(SHA_A, None)
    # `returncode == 0` e a forma FORTE: a anterior era
    # `rc != 1 or "ausente" in stderr`, que o aviso sozinho ja satisfazia —
    # trocar o else por `exit 1` a deixava passar, e a propriedade nomeada
    # na descricao (NAO aborta) nao era verificada.
    checar(r.returncode == 0,
           "guarda: descritor ausente NAO aborta — abortar quebraria "
           "execucao legitima sem o volume montado",
           "rc=%d %s" % (r.returncode, r.stderr[-300:]))
    # Texto ESPECIFICO da guarda, nao a palavra "AVISO": o script emite
    # outro aviso — "nao foi possivel capturar a versao do codeql" — quando
    # o hospedeiro nao tem codeql no PATH, e casar so "AVISO" faria esta
    # assercao passar por motivo alheio, em maquina sem a ferramenta.
    checar("nao foi possivel conferir a imagem" in r.stderr
           and "obsoleta" not in r.stderr,
           "guarda: o caso 'sem volume' sai com o aviso PROPRIO dela, nunca "
           "como divergencia — sao coisas distintas", r.stderr[-300:])

    r = rodar_guarda(None, SHA_A)
    checar(r.returncode == 1 and "nao definido na imagem" in r.stderr,
           "guarda: ENV ausente aborta — imagem construida sem --build-arg "
           "nao pode rodar lote",
           "rc=%d %s" % (r.returncode, r.stderr[-300:]))

    r = rodar_guarda(SHA_A, "nao-e-um-sha256")
    checar(r.returncode == 1 and "malformado" in r.stderr,
           "guarda: descritor malformado sai como MALFORMADO, nao como "
           "imagem obsoleta — a mensagem tem de nomear a causa certa",
           "rc=%d %s" % (r.returncode, r.stderr[-300:]))

    # A guarda do Snyk e EXERCITADA, nao apenas procurada na fonte: as duas
    # guardas nao sao identicas byte a byte (node x jq, nomes e caminhos
    # distintos), entao o argumento de extensao por identidade — usado na
    # secao de obtencao deste mesmo arquivo — nao esta disponivel aqui, e
    # checagem de substring passaria com o `if` invertido ou o `exit 1`
    # removido.
    RUN_SNYK = RAIZ / "ic-security-lab-snyk-code" / "scripts" / "run_snyk-code.sh"
    gs = tmp / "guarda-snyk"
    (gs / "ic-security-lab-snyk-code").mkdir(parents=True)
    DESCRITOR_GS = gs / "ic-security-lab-snyk-code" / "snyk-cli.meta.json"

    def rodar_guarda_snyk(env_sha, descritor_sha):
        if descritor_sha is None:
            if DESCRITOR_GS.exists():
                DESCRITOR_GS.unlink()
        else:
            DESCRITOR_GS.write_text(
                json.dumps({"sha256": descritor_sha}), encoding="utf-8")
        env = ambiente_sem_limites()
        env["WORKSPACE"] = str(gs)
        env["SNYK_TOKEN"] = "irrelevante-para-a-guarda"
        if env_sha is None:
            env.pop("SNYK_CLI_SHA256", None)
        else:
            env["SNYK_CLI_SHA256"] = env_sha
        return subprocess.run(["bash", str(RUN_SNYK), str(lista_gi)],
                              env=env, capture_output=True, text=True)

    rs = rodar_guarda_snyk(SHA_A, SHA_B)
    checar(rs.returncode == 1 and "obsoleta em relacao ao descritor" in rs.stderr,
           "guarda do Snyk: ENV DIVERGE do descritor -> aborta",
           "rc=%d %s" % (rs.returncode, rs.stderr[-300:]))
    rs = rodar_guarda_snyk(SHA_A, SHA_A)
    checar(rs.returncode == 0,
           "guarda do Snyk: ENV coincide -> execucao segue",
           "rc=%d %s" % (rs.returncode, rs.stderr[-300:]))
    rs = rodar_guarda_snyk(SHA_A, None)
    checar(rs.returncode == 0
           and "nao foi possivel conferir a imagem" in rs.stderr,
           "guarda do Snyk: descritor ausente avisa e NAO aborta",
           "rc=%d %s" % (rs.returncode, rs.stderr[-300:]))
    rs = rodar_guarda_snyk(None, SHA_A)
    checar(rs.returncode == 1 and "nao definido na imagem" in rs.stderr,
           "guarda do Snyk: ENV ausente aborta",
           "rc=%d %s" % (rs.returncode, rs.stderr[-300:]))
    checar("snyk-cli.meta.json" in RUN_SNYK.read_text(encoding="utf-8"),
           "a guarda do Snyk aponta para o descritor versionado dele")

    # --------------- (5) do check-log.py: contagem de fallback e de estouro
    # Metrica de vigilancia que o protocolo exige e que nao existia em
    # codigo. So e defensavel manter o lote em 30 apoiado no comportamento
    # medido — fallback raro — se houver quem conte o fallback.
    print("\n== check-log.py (5): fallback e estouro ==")

    def rodar_check5(nome, linhas_log):
        alvo = obt / nome
        alvo.write_text(
            "cve,repo,commit,status,mensagem,duracao_segundos\n" + linhas_log,
            encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECK_LOG), "--tool", "codeql",
             "--log", str(alvo), "--raw-dir", str(raw_vazio)],
            capture_output=True, text=True)

    VERSAO = "codeql 2.25.4; suite qualquer"
    p5 = rodar_check5("cinco.csv", "".join([
        # vocabulario novo, estouro do limite de fetch, clone deu certo
        "CVE-N1,r,c,OK,%s; 3 achados; HEAD conferido; "
        "fallback de clone completo; fetch raso excedeu 300s,10\n" % VERSAO,
        # vocabulario novo, outro codigo de retorno no fetch
        "CVE-N2,r,c,OK,2 achados; HEAD conferido; "
        "fallback de clone completo; fetch raso saiu com 128,11\n",
        # vocabulario novo, clone de contingencia TAMBEM estourou. Esta linha
        # nao repete o segmento "fallback de clone completo" — e o caso que o
        # classificador perderia se nao inferisse o fallback da causa.
        "CVE-N3,r,c,ERRO_FETCH,clone completo excedeu 900s; "
        "fetch raso excedeu 300s,12\n",
        # vocabulario novo, clone falhou com outro codigo
        "CVE-N4,r,c,ERRO_FETCH,clone completo saiu com 128; "
        "fetch raso saiu com 128,13\n",
        # vocabulario ANTIGO (Fase E): conta no total, causa indeterminada
        "CVE-A1,r,c,ERRO_FETCH,fetch raso e clone completo falharam,14\n",
        # mensagem com cara de obtencao que nao casa o vocabulario
        "CVE-U1,r,c,ERRO_FETCH,fallback de clone incompleto,15\n",
        # sem fallback algum
        "CVE-Z1,r,c,ERRO_FETCH,checkout de FETCH_HEAD falhou,16\n",
    ]))
    s5 = p5.stdout
    checar("fallback de clone completo: 5\n" in s5,
           "(5) conta os CVEs que usaram fallback — inclusive aquele cuja "
           "linha so traz a causa e nao repete o rotulo; o nao reconhecido "
           "NAO entra no total, porque nao se sabe que ele e fallback", s5)
    checar("novo 4 | antigo 1  (" in s5,
           "(5) separa os dois vocabularios em vez de uniformiza-los: parte do "
           "corpus NAO discrimina causa e isso tem de ficar visivel", s5)
    checar("causa do fetch:   estouro do limite 2 | outro codigo 2 | "
           "indeterminada 1\n" in s5,
           "(5) discrimina estouro de outro codigo no fetch — junta-los "
           "desfaria a correcao da G-1b", s5)
    checar("clone de contingencia tambem falhou: 3\n" in s5,
           "(5) conta os CVEs em que o clone de contingencia tambem falhou", s5)
    checar("causa do clone:   estouro do limite 1 | outro codigo 1 | "
           "indeterminada 1\n" in s5,
           "(5) discrimina estouro de outro codigo tambem no clone", s5)
    checar("NAO RECONHECIDO" in s5 and "fallback de clone incompleto" in s5,
           "(5) reporta o que PARECE obtencao e nao casou: silenciar seria "
           "dizer zero por nao ter perguntado", s5)
    def secao5(saida):
        # Ausencia da secao e RESULTADO — o script nao a produz —, e tem de
        # sair como falha legivel. `saida.split("(5)")[1]` estouraria com
        # IndexError e derrubaria a suite, suprimindo as assercoes seguintes.
        # A (5) e o ULTIMO bloco da saida, depois dos ANOMALO, de modo que
        # a fatia ate o fim contem so ela. Se a ordem mudar, esta fatia passa
        # a engolir os blocos seguintes e a assercao adiante falha por motivo
        # alheio ao que ela nomeia.
        marca = "(5) obtencao do codigo"
        return saida.split(marca, 1)[1] if marca in saida else ""

    checar(secao5(s5) and "CVE-Z1" not in secao5(s5),
           "(5) nao conta como fallback um CVE que nao o usou", s5)
    # O log acima sai com rc 1 pela conferencia (2) — CVE-N1 e CVE-N2 estao
    # OK sem raw —, que e anomalia PRE-EXISTENTE e nada tem com a (5). Para
    # isolar a (5), um log so de ERRO_FETCH: erro sem raw e o caso normal.
    p5b = rodar_check5("so-fallback.csv", "".join([
        "CVE-M1,r,c,ERRO_FETCH,clone completo excedeu 900s; "
        "fetch raso excedeu 300s,1\n",
        "CVE-M2,r,c,ERRO_FETCH,fetch raso e clone completo falharam,2\n",
    ]))
    checar("fallback de clone completo: 2\n" in p5b.stdout
           and p5b.returncode == 0,
           "(5) e METRICA: fallback contado NAO entra na conta de problemas e "
           "nao muda o codigo de saida",
           "rc=%d %s" % (p5b.returncode, p5b.stdout[-200:]))

    # Contagem zero LEGITIMA: nenhum fallback, nenhum nao reconhecido.
    p0 = rodar_check5("zero.csv",
                      "CVE-Q1,r,c,ERRO_FETCH,checkout de FETCH_HEAD falhou,1\n"
                      "CVE-Q2,r,c,ERRO_ANALISE,semgrep excedeu 1800s,2\n")
    checar("fallback de clone completo: 0\n" in p0.stdout,
           "(5) diz ZERO quando nao houve fallback — e um zero que foi "
           "perguntado, com as demais contagens tambem em zero", p0.stdout)
    checar("NAO RECONHECIDO" not in p0.stdout,
           "(5) nao inventa nao-reconhecido: 'semgrep excedeu 1800s' e "
           "mensagem de ANALISE e nao tem cara de obtencao", p0.stdout)
    checar("base: 2 CVEs apos deduplicacao" in p0.stdout,
           "(5) declara que a base e o resultado da deduplicacao, nao o "
           "arquivo bruto", p0.stdout)

    # D1: a redacao ANTERIOR a G-1b tinha DUAS formas. A forma (A) — clone
    # deu certo — usa o rotulo SOZINHO, byte-identico ao da redacao nova, e
    # so se distingue pela ausencia da causa. Sem a inferencia ela sairia
    # como "novo" (atribuicao por suposicao) e cairia fora dos tres baldes,
    # fazendo a soma das causas ser menor que o total em silencio.
    pa = rodar_check5("forma-a.csv", "".join([
        "CVE-FA,r,c,ERRO_CHECKOUT,3 achados; fallback de clone completo,9\n",
        "CVE-FB,r,c,ERRO_FETCH,fetch raso e clone completo falharam,1\n",
    ]))
    checar("novo 0 | antigo 2  (" in pa.stdout,
           "(5) reconhece a forma (A) do vocabulario antigo — o rotulo sozinho "
           "— em vez de atribui-la a 'novo' por suposicao", pa.stdout)
    checar("causa do fetch:   estouro do limite 0 | outro codigo 0 | "
           "indeterminada 2\n" in pa.stdout,
           "(5) poe a forma (A) em causa INDETERMINADA: sem ela o CVE sumiria "
           "dos tres baldes e as causas somariam menos que o total", pa.stdout)
    checar("INCOERENTE" not in pa.stdout,
           "(5) confere a identidade aritmetica e ela fecha: toda causa tem "
           "balde", pa.stdout)

    # O4: o ramo de nao-reconhecido, isolado das demais conferencias, tambem
    # nao pode mexer no codigo de saida.
    pu = rodar_check5("so-nao-reconhecido.csv",
                      "CVE-U9,r,c,ERRO_FETCH,fallback de clone incompleto,1\n")
    checar("NAO RECONHECIDO" in pu.stdout and pu.returncode == 0,
           "(5) reporta o nao reconhecido SEM transformar em problema: "
           "metrica nao muda codigo de saida",
           "rc=%d %s" % (pu.returncode, pu.stdout[-200:]))

    # R3: a deduplicacao nao infla a metrica — DEFLACIONA. Para vigilancia a
    # direcao perigosa e essa, e o total tem de se declarar piso.
    pd = rodar_check5("dedup.csv",
                      "CVE-D9,r,c,OK,fallback de clone completo; "
                      "fetch raso excedeu 300s,1\n"
                      "CVE-D9,r,c,PULADO,saida bruta ja existe,0\n")
    checar("fallback de clone completo: 0\n" in pd.stdout,
           "(5) opera sobre a ULTIMA linha de cada CVE: a reexecucao PULADO "
           "substitui a linha de fallback, e o fallback que houve passa a "
           "contar ZERO — deflacao, nao inflacao", pd.stdout)
    checar("sao PISO" in pd.stdout and "1 CVEs tem PULADO" in pd.stdout,
           "(5) avisa que a contagem e PISO quando ha PULADO: sem isso a "
           "metrica de vigilancia cairia a zero sem sinal", pd.stdout)

    secao_cruzamento(tmp)

    print("\n%d verificacoes, %d falha(s)" % (verificacoes, len(falhas)))
    for descricao in falhas:
        print("  FALHOU: %s" % descricao)
    print("temporarios em %s" % tmp)
    return 1 if falhas else 0


# ============================================================ cruza-deteccao.py
# Universo sintetico sobre a LISTA REAL: as constantes do script (223 CVEs, 220
# pares, tres exclusoes nominadas) nao sao sobrescreviveis, entao a fixture
# tem de ter a forma do conjunto real. Os achados vem de
# tests/fixtures/cruzamento/casos.json; todo (ferramenta, CVE) sem caso recebe
# tratado sem achados. Nada aqui le results/*/treated/.
FERRAMENTAS_CRUZ = ("codeql", "semgrep", "snyk-code")
NIVEIS_CRUZ = ("nivel_0", "nivel_1", "nivel_2_generosa", "nivel_2_estrita",
               "nivel_3", "nivel_4_generosa", "nivel_4_estrita")
ESTRITOS_CRUZ = ("nivel_2_estrita", "nivel_4_estrita")
BAIXAS_CRUZ = {"CVE-2016-1000229": "ERRO_FETCH", "CVE-2018-8035": "ERRO_CHECKOUT"}
SEM_CWE_CRUZ = "CVE-2018-1000096"
# Os cinco da campanha; aqui sao dado da FIXTURE. O script nao os tem como
# constante: tira da lista o denominador, da ausencia do arquivo quais CVEs
# dele ficaram sem tratado, e dos logs de execucao a causa que admite cada
# ausencia.
SNYK_SEM_ARQUIVO_CRUZ = ("CVE-2018-16479", "CVE-2018-16480", "CVE-2018-3731",
                         "CVE-2018-3747", "CVE-2019-5423")


def _importar(nome, caminho):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(nome, caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def _gt_da_lista():
    """Mesmo carregador que o normalize.py usa para gravar os tratados."""
    norm = _importar("normalize", NORMALIZE)
    gt, _ = norm.carregar_lista(LISTA_REAL)
    tabela = norm.carregar_tabela_primario(norm.TABELA_PRIMARIO)
    relatorio = norm.relatorio_vazio("codeql")
    for cve, g in gt.items():
        g["gt_cwe_primary"] = norm.resolver_primario(g["gt_cwes"], tabela, relatorio, cve)
    return gt


def _achados_sinteticos(ferramenta, cve, especificacao):
    achados = []
    for posicao, item in enumerate(especificacao, 1):
        achados.append({
            "finding_id": "%s:%s:%04d" % (ferramenta, cve, posicao),
            "rule_id": "fixture/regra", "cwe": list(item["cwe"]),
            "has_cwe": bool(item["cwe"]), "severity_original": "warning",
            "severity_normalized": "medium", "security_severity": None,
            "file_path": item["file_path"], "line_start": item["line_start"],
            "line_end": item["line_end"], "column_start": 1, "column_end": 2,
            "message": "fixture"})
    return achados


def _tratado_sintetico(ferramenta, g, achados, varrido="padrao"):
    meta = {"schema_version": "1.3", "cve_id": g["cve_id"], "repository": g["repository"],
            "commit": g["commit"], "tool": ferramenta, "tool_version": "fixture",
            "ruleset": None, "rules_applied": None,
            "analysis_date": "2026-09-18T00:00:00Z", "analysis_date_source": "file_mtime",
            "gt_cwes": list(g["gt_cwes"]), "gt_cwe_primary": g["gt_cwe_primary"],
            "gt_file_path": g["gt_file_path"], "gt_file_lines": list(g["gt_file_lines"]),
            "gt_file_scanned": ((None if ferramenta == "snyk-code" else True)
                                if varrido == "padrao" else varrido),
            "tool_diagnostics": None, "gt_file_scanned_reason": "fixture sintetica"}
    if g["gt_file_path_original"]:
        meta["gt_file_path_original"] = g["gt_file_path_original"]
    if ferramenta == "snyk-code":
        meta["coverage"] = []
    return {"metadata": meta, "findings": achados}


def _escrever_json(caminho, dados):
    caminho.write_text(json.dumps(dados, indent=2) + "\n", encoding="utf-8")


def _celula(valor):
    return "" if valor is None else ("true" if valor is True else
                                     "false" if valor is False else str(valor))


def _chaves_recursivas(objeto):
    if isinstance(objeto, dict):
        for chave, valor in objeto.items():
            yield chave
            yield from _chaves_recursivas(valor)
    elif isinstance(objeto, list):
        for valor in objeto:
            yield from _chaves_recursivas(valor)


def secao_cruzamento(tmp):
    print("\n== cruza-deteccao.py: universo sintetico sobre a lista real ==")
    gt = _gt_da_lista()
    casos = ler(FIXTURES / "cruzamento" / "casos.json")["casos"]
    por_caso = {(c["ferramenta"], c["cve"]): c for c in casos}
    checar(len(por_caso) == len(casos), "casos: cada (ferramenta, CVE) aparece uma vez")

    # gt_assumido do caso x gt derivado da lista: caso sobre premissa velha
    # falha aqui, em vez de passar.
    for caso in casos:
        g = gt[caso["cve"]]
        derivado = {chave: g[chave] for chave in caso["gt_assumido"]}
        checar(derivado == caso["gt_assumido"],
               "caso %s: gt_assumido confere com a lista e a tabela" % caso["id"],
               "%s x %s" % (derivado, caso["gt_assumido"]))
        if caso.get("sem_tratado"):
            checar(caso["ferramenta"] == "snyk-code" and caso["cve"] in SNYK_SEM_ARQUIVO_CRUZ,
                   "caso %s: sem_tratado so em SEM_ARQUIVO_ANALISAVEL do Snyk" % caso["id"])

    universo = tmp / "cruz-universo"
    status_de = {f: {} for f in FERRAMENTAS_CRUZ}
    for ferramenta in FERRAMENTAS_CRUZ:
        destino = universo / ferramenta / "treated"
        destino.mkdir(parents=True)
        (destino / ".gitkeep").write_text("")
        for cve in sorted(gt):
            if cve in BAIXAS_CRUZ:
                status_de[ferramenta][cve] = BAIXAS_CRUZ[cve]
                continue
            if ferramenta == "snyk-code" and cve in SNYK_SEM_ARQUIVO_CRUZ:
                status_de[ferramenta][cve] = "SEM_ARQUIVO_ANALISAVEL"
                continue
            caso = por_caso.get((ferramenta, cve))
            achados = _achados_sinteticos(ferramenta, cve, caso["achados"] if caso else [])
            varrido = caso.get("gt_file_scanned", "padrao") if caso else "padrao"
            _escrever_json(destino / (cve + ".json"),
                           _tratado_sintetico(ferramenta, gt[cve], achados, varrido))
            status_de[ferramenta][cve] = "OK" if achados else "SEM_ACHADOS"

    # Logs de execucao sinteticos, um por (lote, ferramenta), nos lotes REAIS
    # de datasets/listas/ — o script confere cada log contra a lista do lote.
    logs_dir = tmp / "cruz-logs"
    lote_de = {}
    for lista_lote in sorted((RAIZ / "datasets" / "listas").glob("cves-sast-batch-*")):
        cves_lote = [l.split(",")[0] for l in
                     lista_lote.read_text(encoding="utf-8").splitlines() if l.strip()]
        (logs_dir / lista_lote.name).mkdir(parents=True)
        for cve in cves_lote:
            lote_de[cve] = lista_lote.name
        for ferramenta in FERRAMENTAS_CRUZ:
            corpo = "".join("%s,%s,%s,%s,fixture,1\n" % (
                cve, gt[cve]["repository"], gt[cve]["commit"], status_de[ferramenta][cve])
                for cve in cves_lote)
            (logs_dir / lista_lote.name / ("execution-log-%s.csv" % ferramenta)).write_text(
                "cve,repo,commit,status,mensagem,duracao_segundos\n" + corpo, encoding="utf-8")
    checar(sorted(lote_de) == sorted(gt), "fixture: os oito lotes reais cobrem a lista")

    def rodar(saida, lista=None):
        comando = [sys.executable, str(CRUZA), "--treated-root", str(universo),
                   "--logs-campanha", str(logs_dir), "--saida-dir", str(saida)]
        if lista is not None:
            comando += ["--lista", str(lista)]
        return subprocess.run(comando, capture_output=True, text=True)

    # ------------------------------------------------ execucao valida
    saida = tmp / "cruz-saida"
    p = rodar(saida)
    checar(p.returncode == 0, "cruzamento sobre o universo sintetico sai com 0",
           p.stderr[-1500:])
    if p.returncode != 0:
        return
    finais = sorted(x.name for x in saida.iterdir())
    checar(finais == ["cruzamento-codeql.json", "cruzamento-semgrep.json",
                      "cruzamento-snyk-code.json", "matriz-deteccao.csv"],
           "exatamente as quatro saidas, sem residuo temporario", finais)

    texto = (saida / "matriz-deteccao.csv").read_text(encoding="utf-8")
    checar(texto.endswith("\n"), "CSV termina com quebra de linha final")
    brutas = texto[:-1].split("\n")
    cabecalho = brutas[0].split(",")
    checar(all(len(b.split(",")) == len(cabecalho) for b in brutas),
           "CSV: toda linha com o numero de campos do cabecalho (nenhuma virgula em campo)")
    linhas = [dict(zip(cabecalho, b.split(","))) for b in brutas[1:]]
    checar(len(linhas) == 223 * 3, "CSV com uma linha por (CVE, ferramenta): 669",
           len(linhas))
    rel = {f: ler(saida / ("cruzamento-%s.json" % f)) for f in FERRAMENTAS_CRUZ}
    linha_de = {(l["ferramenta"], l["cve"]): l for l in linhas}

    for ferramenta in FERRAMENTAS_CRUZ:
        dentro = [l for l in linhas if l["ferramenta"] == ferramenta
                  and l["no_denominador"] == "true"]
        checar(len(dentro) == 220, "%s: 220 pares no denominador" % ferramenta, len(dentro))
        fora = {l["cve"]: l["motivo_fora_denominador"] for l in linhas
                if l["ferramenta"] == ferramenta and l["no_denominador"] == "false"}
        checar(fora == {"CVE-2016-1000229": "codigo_indisponivel_repositorio_inexistente",
                        "CVE-2018-8035": "codigo_indisponivel_commit_inexistente",
                        SEM_CWE_CRUZ: "sem_cwe_no_ground_truth"},
               "%s: as tres exclusoes, cada uma com seu motivo" % ferramenta, fora)
        checar(all(all(linha_de[(ferramenta, c)][n] == "" for n in NIVEIS_CRUZ) for c in fora),
               "%s: fora do denominador nenhuma coluna de nivel e preenchida" % ferramenta)
        checar(linha_de[(ferramenta, SEM_CWE_CRUZ)]["tratado_presente"] == "true",
               "%s: CVE-2018-1000096 fora da matriz mas COM tratado" % ferramenta)
        evidencia = [i for i in rel[ferramenta]["denominador"]["fora"]
                     if i["cve"] == SEM_CWE_CRUZ]
        checar(evidencia and evidencia[0]["gt_cwes_no_tratado"] == [],
               "%s: gt_cwes do CVE-2018-1000096 lido do tratado e vazio" % ferramenta,
               evidencia)

    # ------------------------------------------------ caso a caso
    for caso in casos:
        f, cve, esp = caso["ferramenta"], caso["cve"], caso["esperado"]
        linha = linha_de[(f, cve)]
        entrada = rel[f]["por_cve"][cve]
        obtido_csv = {n: linha[n] for n in NIVEIS_CRUZ}
        esperado_csv = {n: _celula(esp["niveis"][n]) for n in NIVEIS_CRUZ}
        checar(obtido_csv == esperado_csv,
               "caso %s (%s %s) CSV: niveis [%s]" % (caso["id"], f, cve,
                                                     ", ".join(caso["exercita"])),
               "%s x %s" % (obtido_csv, esperado_csv))
        checar(entrada["niveis"] == esp["niveis"],
               "caso %s JSON: niveis, com null onde a estrita nao se aplica" % caso["id"],
               "%s x %s" % (entrada["niveis"], esp["niveis"]))
        checar(entrada["achados_casados"] == esp["casados"],
               "caso %s JSON: achados casados por finding_id, nivel a nivel" % caso["id"],
               "%s x %s" % (entrada["achados_casados"], esp["casados"]))
        escalares = ("estrita_aplicavel", "achados_no_arquivo_gt",
                     "distancia_min_linha", "distancia_min_intervalo")
        checar(all(entrada[k] == esp[k] for k in escalares)
               and all(linha[k] == _celula(esp[k]) for k in escalares),
               "caso %s: estrita_aplicavel, achados no arquivo e distancias (CSV e JSON)"
               % caso["id"],
               "%s x %s" % ({k: entrada[k] for k in escalares}, {k: esp[k] for k in escalares}))
        checar(linha["tratado_presente"] == ("false" if caso.get("sem_tratado") else "true"),
               "caso %s: tratado_presente" % caso["id"])

    # ------------------------------------------------ agregados
    # Esperado derivado dos casos: todo par sem caso tem tratado sem achados
    # (tudo false), e a estrita e null onde o primario e nulo.
    denominador = sorted(c for c in gt if c not in BAIXAS_CRUZ and c != SEM_CWE_CRUZ)
    for ferramenta in FERRAMENTAS_CRUZ:
        valores = {}
        for cve in denominador:
            caso = por_caso.get((ferramenta, cve))
            if caso:
                valores[cve] = caso["esperado"]["niveis"]
            else:
                nulo = gt[cve]["gt_cwe_primary"] is None
                valores[cve] = {n: (None if n in ESTRITOS_CRUZ and nulo else False)
                                for n in NIVEIS_CRUZ}
        esperado = {}
        for n in NIVEIS_CRUZ:
            vs = [v[n] for v in valores.values()]
            esperado[n] = {"acertos": vs.count(True), "nao_acertos": vs.count(False)}
            if n in ESTRITOS_CRUZ:
                esperado[n]["nao_se_aplica"] = sum(v is None for v in vs)
        checar(rel[ferramenta]["agregados"] == esperado,
               "%s: agregados iguais aos derivados dos casos" % ferramenta,
               "%s x %s" % (rel[ferramenta]["agregados"], esperado))
        # Recontagem independente, a partir do CSV relido aqui.
        dentro = [l for l in linhas if l["ferramenta"] == ferramenta
                  and l["no_denominador"] == "true"]
        recontado = {}
        for n in NIVEIS_CRUZ:
            recontado[n] = {"acertos": sum(l[n] == "true" for l in dentro),
                            "nao_acertos": sum(l[n] == "false" for l in dentro)}
            if n in ESTRITOS_CRUZ:
                recontado[n]["nao_se_aplica"] = sum(l[n] == "" for l in dentro)
        checar(recontado == rel[ferramenta]["agregados"],
               "%s: recontagem independente do CSV = agregados do JSON" % ferramenta)
        checar(all(celula == _celula(rel[ferramenta]["por_cve"][l["cve"]]["niveis"][n])
                   for l in dentro for n, celula in ((n, l[n]) for n in NIVEIS_CRUZ)),
               "%s: CSV e JSON concordam em cada (CVE, nivel) do denominador" % ferramenta)
        n1 = [c for c, v in valores.items() if v["nivel_1"]]
        checar(rel[ferramenta]["nivel_1_e_nivel_3"] ==
               {"cves_nivel_1": len(n1),
                "destes_nivel_3": sum(1 for c in n1 if valores[c]["nivel_3"]),
                "destes_sem_nivel_3": sum(1 for c in n1 if not valores[c]["nivel_3"])},
               "%s: dos que acertam nivel 1, quantos acertam nivel 3" % ferramenta,
               rel[ferramenta]["nivel_1_e_nivel_3"])
        checar([i["cve"] for i in rel[ferramenta]["estrita_nao_se_aplica"]]
               == ["CVE-2018-16472"],
               "%s: estrita nao se aplica so ao CVE-2018-16472, contado a parte" % ferramenta,
               rel[ferramenta]["estrita_nao_se_aplica"])
        esperados_sem = list(SNYK_SEM_ARQUIVO_CRUZ) if ferramenta == "snyk-code" else []
        checar(sorted(i["cve"] for i in rel[ferramenta]["sem_tratado_no_denominador"])
               == sorted(esperados_sem),
               "%s: sem tratado no denominador = %d" % (ferramenta, len(esperados_sem)),
               rel[ferramenta]["sem_tratado_no_denominador"])
        validacao = rel[ferramenta]["validacao"]
        guardas = {m["guarda"] for m in validacao["autoteste"]}
        checar(len(validacao["autoteste"]) >= 30
               and guardas == {"validar_tratado", "conferir_presenca",
                               "conferir_status_achados"}
               and all(m["guarda_pretendida_disparou"] for m in validacao["autoteste"]),
               "%s: autoteste embutido, %d mutantes em %s, cada um pela guarda pretendida"
               % (ferramenta, len(validacao["autoteste"]), sorted(guardas)))
        checar(rel[ferramenta]["validacao"]["tratados_validados"]
               == (216 if ferramenta == "snyk-code" else 221),   # 223 - 2 baixas (- 5 no Snyk)
               "%s: tratados_validados e contagem da propria ferramenta" % ferramenta,
               rel[ferramenta]["validacao"]["tratados_validados"])
        checar(rel[ferramenta]["csv_da_mesma_execucao"]["sha256"]
               == hashlib.sha256((saida / "matriz-deteccao.csv").read_bytes()).hexdigest(),
               "%s: o JSON carrega o sha256 do CSV da mesma execucao" % ferramenta)
        codigo = rel[ferramenta]["fontes"]["codigo"]
        checar(codigo == {"tools/cruza-deteccao.py": hashlib.sha256(CRUZA.read_bytes()).hexdigest(),
                          "tools/normalize.py": hashlib.sha256(NORMALIZE.read_bytes()).hexdigest(),
                          "tools/check-log.py": hashlib.sha256(CHECK_LOG.read_bytes()).hexdigest()},
               "%s: fontes.codigo traz o sha256 dos tres scripts que moldam o resultado"
               % ferramenta, codigo)
        checar(rel[ferramenta]["fontes"]["logs_campanha"]["arquivos"] == 24
               and rel[ferramenta]["fontes"]["listas_de_lote"]["arquivos"] == 8
               and "registro_campanha" not in rel[ferramenta]["fontes"],
               "%s: status derivado dos 24 logs de lote, sem arquivo intermediario"
               % ferramenta, rel[ferramenta]["fontes"].get("logs_campanha"))
        checar(validacao["controle_positivo"]["divergencias"] == [],
               "%s: controle positivo embutido sem divergencia" % ferramenta)
        conferencia = rel[ferramenta]["conferencia_csv"]
        checar(conferencia["divergencias"] == 0
               and conferencia["controle_csv_adulterado_divergencias_acusadas"] > 0,
               "%s: conferencia CSV x JSON zero, e a mesma conferencia acusa CSV adulterado"
               % ferramenta, conferencia)
        proibidas = sorted({k for k in _chaves_recursivas(rel[ferramenta])
                            if re.search(r"precis|falso|false_pos|fp_|total", k)})
        checar(proibidas == [],
               "%s: nenhuma chave de precisao, falso positivo ou total de achados"
               % ferramenta, proibidas)
    # gt_file_scanned false (caso C19): o balde conta, e o CVE NAO sai do
    # denominador — a causa e interna a ferramenta.
    c19 = linha_de[("codeql", "CVE-2017-1000219")]
    checar(c19["gt_file_scanned"] == "false" and c19["no_denominador"] == "true",
           "gt_file_scanned false sai 'false' no CSV e o CVE permanece no denominador", c19)
    esperado_estados = {
        "codeql": {"true": 219, "false": 1, "null": 0, "sem_tratado": 0},
        "semgrep": {"true": 220, "false": 0, "null": 0, "sem_tratado": 0},
        "snyk-code": {"true": 0, "false": 0, "null": 215, "sem_tratado": 5}}
    for ferramenta in FERRAMENTAS_CRUZ:
        obtido = rel[ferramenta]["ressalvas"]["gt_file_scanned_no_denominador"]
        checar(obtido == esperado_estados[ferramenta],
               "%s: gt_file_scanned por estado, balde false exercitado" % ferramenta, obtido)
    checar(all(l["gt_file_scanned"] == "null" for l in linhas
               if l["ferramenta"] == "snyk-code" and l["tratado_presente"] == "true"
               and l["no_denominador"] == "true"),
           "gt_file_scanned null do Snyk sai 'null', distinto de vazio (sem tratado)")
    checar(all(l["gt_file_scanned"] == "" for l in linhas
               if l["tratado_presente"] == "false"),
           "gt_file_scanned vazio onde nao ha tratado")

    # ------------------------------------------------ determinismo e interface
    saida2 = tmp / "cruz-saida-2"
    p2 = rodar(saida2)
    checar(p2.returncode == 0
           and (saida2 / "matriz-deteccao.csv").read_bytes()
           == (saida / "matriz-deteccao.csv").read_bytes(),
           "segunda execucao: CSV byte-identico")
    if p2.returncode == 0:
        checar(all((saida2 / ("cruzamento-%s.json" % f)).read_bytes()
                   == (saida / ("cruzamento-%s.json" % f)).read_bytes()
                   for f in FERRAMENTAS_CRUZ),
               "segunda execucao na mesma maquina: os tres JSON byte-identicos")
    carimbo = (r"gerado|generated|criado|created|executado|data|date|hora|time|"
               r"instante|dia|host|usuario|user")
    checar(all(re.search(carimbo, k) for k in ("gerado_em", "generated_at", "timestamp",
                                               "executado_em", "host", "usuario")),
           "controle: o padrao de carimbo casa com os nomes que deveria pegar")
    # Controle do PERCURSO: uma chave aninhada em lista dentro de dict tem de
    # ser visitada, senao o zero abaixo seria zero por nao ter perguntado.
    injetado = json.loads(json.dumps(rel["codeql"]))
    injetado["fontes"]["x"] = [{"y": [{"gerado_em": 1}]}]
    checar(any(re.search(carimbo, k) for k in _chaves_recursivas(injetado)),
           "controle: o percurso das chaves alcanca chave aninhada em lista")
    checar(not any(re.search(carimbo, k)
                   for f in FERRAMENTAS_CRUZ for k in _chaves_recursivas(rel[f])),
           "nenhuma chave com nome de carimbo de execucao nos JSON")
    versionada = RAIZ / "results" / "cruzamento"

    def retrato_versionada():
        return ({x.name: x.read_bytes() for x in versionada.iterdir() if x.is_file()}
                if versionada.is_dir() else None)
    antes_versionada = retrato_versionada()
    try:
        pv = subprocess.run([sys.executable, str(CRUZA), "--treated-root", str(universo),
                             "--logs-campanha", str(logs_dir)],
                            capture_output=True, text=True)
    finally:
        depois_versionada = retrato_versionada()
        if depois_versionada != antes_versionada and antes_versionada is not None:
            for nome, conteudo in antes_versionada.items():
                (versionada / nome).write_bytes(conteudo)
    checar(pv.returncode == 2 and "exige entradas dentro do repositorio" in pv.stderr,
           "saida versionada recusa entradas de fora do repositorio",
           "rc=%d %s" % (pv.returncode, pv.stderr[-300:]))
    checar(depois_versionada == antes_versionada,
           "results/cruzamento/ intocado pela recusa")
    ajuda = subprocess.run([sys.executable, str(CRUZA), "--help"],
                           capture_output=True, text=True).stdout
    checar(set(re.findall(r"--[a-z][a-z-]*", ajuda))
           == {"--help", "--lista", "--treated-root", "--logs-campanha", "--saida-dir"},
           "interface: so opcoes de caminho, nenhuma que selecione recorte",
           sorted(set(re.findall(r"--[a-z][a-z-]*", ajuda))))

    # ------------------------------------------------ mutantes: validador contra positivo
    print("\n== cruza-deteccao.py: mutantes (cada um tem de PARAR sem escrever saida) ==")
    alvo = universo / "codeql" / "treated" / "CVE-2018-14040.json"   # caso C03, 1 achado
    original_alvo = alvo.read_bytes()
    def retrato_logs():
        return {str(x.relative_to(logs_dir)): x.read_bytes()
                for x in sorted(logs_dir.rglob("*")) if x.is_file()}
    original_logs = retrato_logs()
    contador = [0]

    def restaurar(caminho, conteudo):
        caminho.write_bytes(conteudo)

    def editar(caminho, mutacao):
        """JSON editado no lugar; o desfazer devolve os bytes originais."""
        guardado = caminho.read_bytes()

        def preparar():
            dados = json.loads(guardado)
            mutacao(dados)
            _escrever_json(caminho, dados)
        return preparar, lambda: restaurar(caminho, guardado)

    def editar_alvo(mutacao):
        return editar(alvo, mutacao)

    def caminho_log(ferramenta, cve):
        return logs_dir / lote_de[cve] / ("execution-log-%s.csv" % ferramenta)

    def editar_texto(caminho, transformar):
        guardado = caminho.read_bytes()
        return (lambda: caminho.write_text(transformar(guardado.decode("utf-8")),
                                           encoding="utf-8"),
                lambda: restaurar(caminho, guardado))

    def criar(caminho, conteudo):
        return (lambda: caminho.write_text(conteudo, encoding="utf-8"),
                lambda: caminho.unlink())

    def remover(caminho):
        guardado = caminho.read_bytes()
        return lambda: caminho.unlink(), lambda: caminho.write_bytes(guardado)

    def combinar(*pares):
        return (lambda: [p[0]() for p in pares], lambda: [p[1]() for p in reversed(pares)])

    def lista_mutada(mutacao):
        linhas_lista = LISTA_REAL.read_text(encoding="utf-8").splitlines(keepends=True)
        caminho = tmp / ("cruz-lista-%02d.txt" % (contador[0] + 1))
        caminho.write_text("".join(mutacao(linhas_lista)), encoding="utf-8")
        return caminho

    def mutante(nome, fragmento, preparar_desfazer=None, lista=None, saida_mut=None):
        contador[0] += 1
        destino = saida_mut or tmp / ("cruz-mutante-%02d" % contador[0])
        antes = ({x.name: x.read_bytes() for x in destino.iterdir()}
                 if destino.is_dir() else {})
        if preparar_desfazer:
            preparar_desfazer[0]()
        try:
            proc = rodar(destino, lista=lista)
        finally:
            if preparar_desfazer:
                preparar_desfazer[1]()
        depois = ({x.name: x.read_bytes() for x in destino.iterdir()}
                  if destino.is_dir() else {})
        checar(proc.returncode == 2 and "PARADO" in proc.stderr and fragmento in proc.stderr,
               "mutante acusado: %s" % nome, "rc=%d %s" % (proc.returncode, proc.stderr[-500:]))
        checar(depois == antes, "mutante '%s': nenhuma saida escrita nem alterada" % nome)
        return proc

    def tratado_de(ferramenta, cve, achados=()):
        return json.dumps(_tratado_sintetico(ferramenta, gt[cve], list(achados)))

    def achado0(chave, valor):
        return editar_alvo(lambda d: d["findings"][0].__setitem__(chave, valor))

    def meta(chave, valor):
        return editar_alvo(lambda d: d["metadata"].__setitem__(chave, valor))

    def status(ferramenta, cve, novo):
        """Troca o status do CVE no log do seu lote."""
        def trocar(texto):
            saida_linhas = []
            for linha in texto.splitlines(keepends=True):
                if linha.startswith(cve + ","):
                    partes = linha.split(",")
                    partes[3] = novo
                    linha = ",".join(partes)
                saida_linhas.append(linha)
            return "".join(saida_linhas)
        return editar_texto(caminho_log(ferramenta, cve), trocar)

    treated = {f: universo / f / "treated" for f in FERRAMENTAS_CRUZ}

    # Denominador e exclusoes
    mutante("tratado presente de CVE-2016-1000229 (repositorio inexistente)",
            "excluido por codigo indisponivel e TEM tratado",
            criar(treated["codeql"] / "CVE-2016-1000229.json",
                  tratado_de("codeql", "CVE-2016-1000229")))
    mutante("tratado presente de CVE-2018-8035 (commit inexistente)",
            "excluido por codigo indisponivel e TEM tratado",
            criar(treated["semgrep"] / "CVE-2018-8035.json",
                  tratado_de("semgrep", "CVE-2018-8035")))
    mutante("baixa com status OK no log", "excluido por codigo indisponivel, mas o registro diz OK",
            status("codeql", "CVE-2016-1000229", "OK"))
    mutante("baixa com o status do outro motivo (repositorio inexistente com ERRO_CHECKOUT)",
            "o motivo exige ERRO_FETCH",
            status("semgrep", "CVE-2016-1000229", "ERRO_CHECKOUT"))
    mutante("CVE-2018-1000096 com gt_cwes nao vazio no tratado",
            "premissa dos 222 pares esta errada",
            editar(treated["snyk-code"] / (SEM_CWE_CRUZ + ".json"),
                   lambda d: d["metadata"].__setitem__("gt_cwes", ["CWE-079"])))
    mutante("lista em que CVE-2018-1000096 tem CWE", "CVEs com gt_cwes vazio na lista",
            lista=lista_mutada(lambda ls: [l.replace(",,_read.js,", ",CWE-079,_read.js,")
                                           for l in ls]))
    mutante("lista com 222 CVEs", "a lista tem 222 CVEs",
            lista=lista_mutada(lambda ls: [l for l in ls if not l.startswith("CVE-2017-0931,")]))
    mutante("lista com FileLine vazio num CVE do denominador", "gt_file_lines vazio",
            lista=lista_mutada(lambda ls: [re.sub(r",43\n$", ",\n", l)
                                           if l.startswith("CVE-2017-0931,") else l
                                           for l in ls]))

    # Presenca de tratado x registro
    mutante("codeql sem tratado e registro diz SEM_ACHADOS", "tratado AUSENTE",
            remover(treated["codeql"] / "CVE-2017-0931.json"))
    mutante("codeql sem tratado com ERRO_ANALISE", "nao ha regra que o admita",
            combinar(remover(treated["codeql"] / "CVE-2017-0931.json"),
                     status("codeql", "CVE-2017-0931", "ERRO_ANALISE")))
    mutante("semgrep sem tratado com SEM_ARQUIVO_ANALISAVEL (so o Snyk o admite)",
            "nao ha regra que o admita",
            combinar(remover(treated["semgrep"] / "CVE-2017-0931.json"),
                     status("semgrep", "CVE-2017-0931", "SEM_ARQUIVO_ANALISAVEL")))
    mutante("snyk com tratado para CVE SEM_ARQUIVO_ANALISAVEL",
            "tratado presente com status SEM_ARQUIVO_ANALISAVEL",
            criar(treated["snyk-code"] / "CVE-2018-16480.json",
                  tratado_de("snyk-code", "CVE-2018-16480")))
    # Logs de execucao
    log_aa = logs_dir / "cves-sast-batch-aa" / "execution-log-semgrep.csv"
    mutante("log de lote sem um CVE", "CVEs do log diferem da lista do lote",
            editar_texto(log_aa, lambda t: "".join(t.splitlines(keepends=True)[:-1])))
    mutante("log com status desconhecido", "'status': 'QUEBRADO'",
            status("semgrep", "CVE-2017-0931", "QUEBRADO"))
    mutante("log com linha fora do formato", "menos de 4 campos",
            editar_texto(log_aa, lambda t: t + "CVE-2017-0931,x\n"))
    mutante("log sem cabecalho", "nao e o cabecalho do log",
            editar_texto(log_aa, lambda t: "".join(t.splitlines(keepends=True)[1:])))
    mutante("log ausente", "log ausente",
            remover(logs_dir / "cves-sast-batch-ac" / "execution-log-snyk-code.csv"))
    outro = next(c for c in sorted(lote_de) if lote_de[c] == "cves-sast-batch-aa")
    mutante("CVE em dois lotes", "CVE em dois lotes",
            editar_texto(logs_dir / "cves-sast-batch-ab" / "execution-log-codeql.csv",
                         lambda t: t + "%s,r,c,SEM_ACHADOS,fixture,1\n" % outro))
    # Segunda linha do mesmo CVE (log concatenado de duas execucoes): o
    # ler_log ficaria com a ultima, e o script exige uma linha por CVE.
    mutante("CVE repetido no log", "CVE repetido no log",
            editar_texto(caminho_log("codeql", "CVE-2017-0931"),
                         lambda t: t + "CVE-2017-0931,r,c,SEM_ACHADOS,reexecucao,0\n"))
    # Status x achados: pega log trocado entre ferramentas e achado descartado.
    mutante("OK no log e tratado sem achado", "OK no registro e tratado sem achado",
            status("codeql", "CVE-2017-0931", "OK"))
    mutante("SEM_ACHADOS no log e tratado com achado (caso C03)",
            "SEM_ACHADOS no registro e tratado com 1 achados",
            status("codeql", "CVE-2018-14040", "SEM_ACHADOS"))
    mutante("CVE sem CWE sem tratado", "exige o tratado",
            combinar(remover(treated["codeql"] / (SEM_CWE_CRUZ + ".json")),
                     status("codeql", SEM_CWE_CRUZ, "ERRO_ANALISE")))

    # Arquivos no diretorio de tratados
    mutante("tratado orfao", "tratado orfao",
            criar(treated["codeql"] / "CVE-2099-99999.json", "{}"))
    mutante("arquivo inesperado no diretorio", "arquivo inesperado",
            criar(treated["codeql"] / "notas.txt", "x"))
    proc = mutante("tratado ilegivel", "tratado ilegivel",
                   (lambda: alvo.write_bytes(original_alvo[:len(original_alvo) // 2]),
                    lambda: restaurar(alvo, original_alvo)))
    checar("AUSENTE" not in proc.stderr,
           "tratado ilegivel nao reaparece como 'tratado AUSENTE': presenca e do arquivo",
           proc.stderr[-400:])

    # Estrutura e tipos
    mutante("topo com chave extra", "chaves do topo",
            editar_alvo(lambda d: d.__setitem__("extra", 1)))
    mutante("schema_version 1.2", "schema_version '1.2'", meta("schema_version", "1.2"))
    mutante("metadata do snyk sem coverage", "metadata sem ['coverage']",
            editar(treated["snyk-code"] / "CVE-2017-0931.json",
                   lambda d: d["metadata"].pop("coverage")))
    mutante("tool divergente", "difere do diretorio", meta("tool", "semgrep"))
    mutante("gt_file_path divergente", "gt_file_path 'js/outro.js' difere",
            meta("gt_file_path", "js/outro.js"))
    mutante("gt_cwe_primary divergente", "gt_cwe_primary 'CWE-116' difere",
            meta("gt_cwe_primary", "CWE-116"))
    mutante("commit divergente", "difere do PrePatchCommit", meta("commit", "b" * 40))
    mutante("achado sem chave", "chaves divergentes",
            editar_alvo(lambda d: d["findings"][0].pop("message")))
    mutante("cwe fora da forma canonica", "cwe fora da forma canonica",
            achado0("cwe", ["CWE-79"]))
    mutante("has_cwe incoerente", "has_cwe", achado0("has_cwe", False))
    mutante("line_start em texto", "line_start nao e inteiro", achado0("line_start", "10"))
    mutante("line_end menor que line_start", "line_end 5 menor que line_start",
            achado0("line_end", 5))
    mutante("file_path absoluto", "file_path fora da forma canonica",
            achado0("file_path", "/js/collapse.js"))
    mutante("finding_id de outro CVE", "fora da forma <tool>:<CVE>:<NNNN>",
            achado0("finding_id", "codeql:CVE-2016-10735:0001"))
    mutante("finding_id repetido", "repetido",
            editar_alvo(lambda d: d["findings"].append(dict(d["findings"][0]))))

    # PARADA nao mexe em saida pre-existente, e o diz.
    proc = mutante("parada com saida pre-existente", "schema_version",
                   meta("schema_version", "1.2"), saida_mut=saida)
    checar("NAO foram atualizadas" in proc.stderr,
           "parada avisa que as saidas pre-existentes nao foram atualizadas")
    checar(alvo.read_bytes() == original_alvo and retrato_logs() == original_logs,
           "mutantes desfeitos: universo restaurado")


if __name__ == "__main__":
    sys.exit(main())
