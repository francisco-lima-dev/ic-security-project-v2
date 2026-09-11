#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
normalize.py — traduz a saída bruta das três ferramentas SAST para o schema
comum, um arquivo por CVE em results/<tool>/treated/<CVE>.json.

    python3 tools/normalize.py --tool {codeql|semgrep|snyk-code} \
        [--cve CVE-XXXX-YYYY] [--overwrite] \
        [--raw-dir DIR] [--treated-dir DIR] [--lista ARQ] [--report-path ARQ]

Roda FORA dos containers. É a etapa barata do pipeline: um defeito aqui se
conserta reexecutando segundos de parsing local, ao passo que embutida nas
imagens exigiria repetir clones e análises. Por isso a idempotência do laço
de análise olha o RAW, não o tratado.

INDEPENDÊNCIA DO LOG DE EXECUÇÃO
--------------------------------
Este script não lê, não importa e não invoca logs/execution-log-*.csv. A
separação entre coleta e normalização existe justamente para que a etapa
barata não herde as dependências da cara: log ausente ou parcial não pode
derrubar a normalização. As conferências que precisam do log vivem em
tools/check-log.py, script próprio.

O `metadata.commit` vem da lista de entrada, não do log. Os scripts de
análise assertam `git rev-parse HEAD` contra o PrePatchCommit e abortam o CVE
com ERRO_CHECKOUT se divergir; logo, para todo CVE que TEM raw, o commit
pretendido e o efetivo coincidem por construção. A evidência dessa
verificação é o log, que é versionado — não se replica aqui.

ASSIMETRIA ENTRE LISTA E RAW
----------------------------
  raw sem linha na lista  → falha ruidosa (raw órfão, nome errado, lista trocada)
  linha da lista sem raw  → normal e silencioso (os lotes ainda não rodaram todos)

O QUE FOI VERIFICADO E O QUE FOI ASSUMIDO
-----------------------------------------
Escrito antes de existir qualquer raw real: results/*/raw/ estava vazio.
Toda afirmação sobre a forma das saídas vem do CLAUDE.md, e a verificação
possível é sobre as fixtures sintéticas de tests/fixtures/.

VERIFICADO nesta fase:
  - a suíte javascript-security-extended.qls do bundle 2.25.4 resolve 104
    consultas (`codeql resolve queries`, na imagem construída)
  - o comportamento do código contra as fixtures de tests/fixtures/

ASSUMIDO da documentação, a confirmar na Fase E:
  - todos os caminhos de campo da tabela de "Formato das saídas" do CLAUDE.md
  - que `runs[0].properties.coverage[]` do Snyk permita decidir se UM arquivo
    foi varrido. Se a cobertura vier agregada por linguagem, sem inventário
    de caminhos, `gt_file_scanned` fica em null e o relatório diz quantos —
    ver derivar_gt_file_scanned_snyk()
  - que o Snyk preencha `toolExecutionNotifications`. O SARIF admite o campo,
    admitir não é emitir; ausência nunca é falha
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.3"
RAIZ = Path(__file__).resolve().parent.parent

FERRAMENTAS = ("codeql", "semgrep", "snyk-code")
# O run_semgrep.sh grava .json; run_codeql.sh e run_snyk-code.sh gravam .sarif.
EXTENSAO_RAW = {"codeql": ".sarif", "semgrep": ".json", "snyk-code": ".sarif"}

LISTA_PADRAO = RAIZ / "datasets" / "listas" / "cves-sast.txt"
TABELA_PRIMARIO = RAIZ / "datasets" / "cwe-primario.csv"
DESCRITOR_SEMGREP = RAIZ / "ic-security-lab-semgrep" / "rules" / "semgrep-default.meta.json"

# Referência da suíte e contagem de consultas: valores do bundle da IMAGEM
# (2.25.4), não do ensaio ponta a ponta do --build-mode=none, que rodou na
# 2.26.4 e viu 105. A diferença é evolução do catálogo entre versões.
CODEQL_SUITE = "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls"
CODEQL_RULES_TOTAL = 104
CODEQL_VERSAO_ESPERADA = "2.25.4"

# Limites declarados de tool_diagnostics.details (D.7).
LIMITE_DETALHES = 20
LIMITE_TEXTO_DETALHE = 500


class FalhaCVE(Exception):
    """Erro que interrompe UM cve, nunca a execução inteira.

    Raw ilegível, severidade fora da tabela, conjunto de CWE ausente da
    tabela de primário: nenhum deles produz tratado, todos são contados, e a
    execução termina com código não nulo.
    """


class RawIlegivel(FalhaCVE):
    """Raw que não parseia, ou que parseia sem a estrutura mínima.

    Subclasse própria, e não uma mensagem reconhecida por substring: a
    contagem de raws ilegíveis do relatório é dado da monografia, e casá-la
    por texto a quebraria em silêncio na primeira vez que alguém reescrevesse
    uma mensagem de erro.

    Distinta das demais FalhaCVE de propósito. Raw sem `.time` no Semgrep, ou
    com severidade fora da tabela, é raw ÍNTEGRO produzido por invocação
    errada — problema diferente, contado à parte.
    """


# ---------------------------------------------------------------------------
# CWE — uma única implementação, aplicada ao ground truth, às três ferramentas
# e à chave canônica da tabela de primário. Três implementações do mesmo
# padding é como CWE-79 e CWE-079 voltam a divergir em silêncio.
# ---------------------------------------------------------------------------
_RE_CWE = re.compile(r"cwe[-_ ]?0*(\d+)", re.IGNORECASE)
_RE_SO_NUMERO = re.compile(r"^\s*0*(\d+)\s*$")


def normalizar_cwe(valor):
    """'external/cwe/cwe-79', 'CWE-829: descrição', 'CWE-94', 79 → 'CWE-079'.

    Três dígitos com zero à esquerda; quatro quando >= 1000. Devolve None
    quando nada de reconhecível houver — o chamador decide se conta ou falha.
    """
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        numero = valor
    elif isinstance(valor, str):
        achado = _RE_CWE.search(valor)
        if achado:
            numero = int(achado.group(1))
        else:
            achado = _RE_SO_NUMERO.match(valor)
            if not achado:
                return None
            numero = int(achado.group(1))
    else:
        return None
    if numero <= 0:
        return None
    return "CWE-%03d" % numero


def chave_canonica(cwes):
    """Chave de busca na tabela de primário: normalizar, ordenar, juntar.

    Nunca casar por cadeia crua contra a grafia em prosa do CSV.
    """
    return "|".join(sorted(set(cwes)))


# ---------------------------------------------------------------------------
# Caminho (D.5)
#
# As três ferramentas emitem caminho relativo e limpo — propriedade que
# decorre de invocá-las com `.` / --source-root=. de dentro do WORKDIR. Isto
# é salvaguarda, e é deliberadamente conservadora: normalização agressiva que
# come um diretório real é pior que o problema que evita. Toda transformação
# é registrada com valor antes e depois.
# ---------------------------------------------------------------------------
_RE_WORKDIR_CVE = re.compile(r"^/tmp/src-CVE-[0-9]{4}-[0-9]+/")
_PREFIXOS_WORKSPACE = ("/workspace/", "/src/")


def normalizar_caminho(bruto):
    """Devolve (caminho, [motivos]). Lista vazia = nada foi transformado."""
    if not isinstance(bruto, str) or not bruto:
        return bruto, []
    atual = bruto
    motivos = []

    if atual.startswith("file://"):
        resto = atual[len("file://"):]
        # file:///a/b  → /a/b   |   file://host/a/b → host/a/b (deixado como veio)
        from urllib.parse import unquote
        atual = unquote(resto)
        motivos.append("esquema file://")

    if _RE_WORKDIR_CVE.match(atual):
        atual = _RE_WORKDIR_CVE.sub("", atual)
        motivos.append("prefixo do diretorio de trabalho /tmp/src-CVE-*/")
    else:
        for prefixo in _PREFIXOS_WORKSPACE:
            if atual.startswith(prefixo):
                atual = atual[len(prefixo):]
                motivos.append("prefixo %s" % prefixo)
                break

    while atual.startswith("./"):
        atual = atual[2:]
        if "./ inicial" not in motivos:
            motivos.append("./ inicial")

    return atual, motivos


def normalizar_gt_file_path(bruto):
    """Como normalizar_caminho, mais a remoção de barra inicial.

    O ground truth traz UM caminho absoluto: `CVE-2019-12041` declara
    `/index.js`, e vem assim do próprio benchmark da OpenSSF, não do gerador
    de listas. O arquivo é `index.js` na raiz do repositório — a barra é
    defeito do dado.

    A remoção vale SÓ para o ground truth, e por isso não está em
    normalizar_caminho: caminho do benchmark é relativo ao repositório por
    definição, ao passo que um caminho absoluto vindo de uma FERRAMENTA é
    sinal de que a premissa do WORKDIR quebrou, e comê-lo em silêncio
    destruiria a evidência. Lá ele é preservado e reportado; aqui, corrigido
    e reportado.

    Sem isto, `gt_file_path` sai `/index.js`, `gt_file_scanned` dá `false`
    por comparação contra um caminho que ferramenta alguma emite, e o CVE
    vira falso negativo garantido no cruzamento — sem erro visível.
    """
    limpo, motivos = normalizar_caminho(bruto)
    if limpo.startswith("/"):
        limpo = limpo.lstrip("/")
        motivos.append("barra inicial (defeito do ground truth)")
    return limpo, motivos


# ---------------------------------------------------------------------------
# Severidade (D.6)
# ---------------------------------------------------------------------------
TABELA_SEVERIDADE = {
    # CodeQL / Snyk Code (SARIF)          Semgrep
    "error": "high",                      # ERROR
    "warning": "medium",                  # WARNING, MEDIUM
    "note": "low",                        # INFO
    "ERROR": "high",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "INFO": "low",
}

# Quinto valor, deliberado: regra não resolvida pelo ruleId é DEFEITO DE
# JUNÇÃO do normalizador, e colapsá-lo em "unknown" — que é ausência legítima
# de nível numa regra resolvida — esconderia um bug atrás de uma categoria
# prevista. Os dois contadores vão separados ao relatório.
SEVERIDADE_NAO_RESOLVIDA = "unresolved"


# O enum `level` do SARIF é none|note|warning|error. Três estão na tabela do
# D.6; `none` não. Ele NÃO é mapeado de propósito: significa "a ferramenta
# declarou explicitamente que não é problema", ao passo que `unknown` significa
# "a regra não declarou nível". Mapear os dois para o mesmo valor faria a
# categoria significar duas coisas, e a segunda nunca ocorreu na campanha
# anterior. Falha alto, e a mensagem diz que não é lixo.
NIVEIS_SARIF_LEGAIS_NAO_MAPEADOS = {"none"}


def normalizar_severidade(bruta, cve, contexto):
    if bruta is None:
        return "unknown"
    if isinstance(bruta, str) and bruta in NIVEIS_SARIF_LEGAIS_NAO_MAPEADOS:
        raise FalhaCVE(
            "severidade %r em %s (%s): VALOR LEGAL DO ENUM SARIF, nao previsto "
            "na tabela do D.6 — nao e lixo nem corrupcao. O SARIF define "
            "level como none|note|warning|error; 'none' e a ferramenta dizendo "
            "que NAO ha problema, o que difere de 'a regra nao declarou nivel' "
            "(unknown). Mapear os dois para unknown faria a categoria "
            "significar duas coisas. Decidir antes de mapear."
            % (bruta, cve, contexto)
        )
    if not isinstance(bruta, str) or bruta not in TABELA_SEVERIDADE:
        raise FalhaCVE(
            "severidade fora da tabela: %r em %s (%s)" % (bruta, cve, contexto)
        )
    return TABELA_SEVERIDADE[bruta]


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------
_RE_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")
_RE_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")


def carregar_lista(caminho):
    """CVE,URL,PrePatchCommit,CWEs,FilePath,FileLine — seis campos, sem cabeçalho.

    Lido com split(',') e não com csv: a invariante do projeto é que nenhum
    campo contenha vírgula, e um parser que aceitasse aspas mascararia a
    violação em vez de expô-la.
    """
    if not caminho.is_file():
        raise SystemExit("ERRO: lista de ground truth ausente: %s" % caminho)
    gt = {}
    transformacoes = []
    with open(caminho, encoding="utf-8") as arquivo:
        for numero, linha in enumerate(arquivo, 1):
            linha = linha.rstrip("\n").rstrip("\r")
            if not linha.strip() or linha.lstrip().startswith("#"):
                continue
            partes = linha.split(",")
            if len(partes) != 6:
                raise SystemExit(
                    "ERRO: %s linha %d tem %d campos, esperados 6: %r"
                    % (caminho, numero, len(partes), linha)
                )
            cve, url, commit, cwes_bruto, file_path, file_line = partes
            # Os run_*.sh já validam, mas o normalizador lê a lista por conta
            # própria e em momento distinto: lista trocada ou corrompida entre
            # a análise e a normalização passaria sem sinal algum. Linha
            # inválida é falha ruidosa, nunca linha pulada.
            if not _RE_CVE.match(cve):
                raise SystemExit("ERRO: %s linha %d: CVE invalido %r" % (caminho, numero, cve))
            if not _RE_COMMIT.match(commit):
                raise SystemExit(
                    "ERRO: %s linha %d: PrePatchCommit de %s nao e 40 hex: %r"
                    % (caminho, numero, cve, commit)
                )
            if cve in gt:
                raise SystemExit("ERRO: %s linha %d: CVE repetido %s" % (caminho, numero, cve))

            # gt_cwes preserva a ORDEM DECLARADA pelo benchmark (apenas
            # normalizada e deduplicada). A ordenação existe só na chave
            # canônica de busca; o registro é o do ground truth.
            cwes = []
            for bruto in cwes_bruto.split("|"):
                if not bruto.strip():
                    continue
                normalizado = normalizar_cwe(bruto)
                if normalizado is None:
                    raise SystemExit(
                        "ERRO: %s linha %d: CWE irreconhecivel %r" % (caminho, numero, bruto)
                    )
                if normalizado not in cwes:
                    cwes.append(normalizado)

            linhas = []
            for bruto in file_line.split("|"):
                if not bruto.strip():
                    continue
                if not bruto.strip().isdigit():
                    raise SystemExit(
                        "ERRO: %s linha %d: FileLine nao numerico %r" % (caminho, numero, bruto)
                    )
                linhas.append(int(bruto.strip()))

            caminho_limpo, motivos_caminho = normalizar_gt_file_path(file_path)
            if motivos_caminho:
                transformacoes.append({
                    "cve": cve, "antes": file_path, "depois": caminho_limpo,
                    "motivos": motivos_caminho,
                })

            gt[cve] = {
                "cve_id": cve,
                "repository": url,
                "commit": commit,
                "gt_cwes": cwes,
                "gt_file_path": caminho_limpo,
                # Preservado para o tratado quando divergir: o leitor do
                # artefato precisa poder cotejá-lo com o benchmark.
                "gt_file_path_original": file_path if motivos_caminho else None,
                "gt_file_lines": linhas,
            }
    return gt, transformacoes


def carregar_tabela_primario(caminho):
    if not caminho.is_file():
        raise SystemExit("ERRO: tabela de CWE primario ausente: %s" % caminho)
    tabela = {}
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        for registro in csv.DictReader(arquivo):
            conjunto = registro.get("conjunto") or ""
            cwes = [normalizar_cwe(c) for c in conjunto.split("|") if c.strip()]
            if any(c is None for c in cwes):
                raise SystemExit("ERRO: conjunto irreconhecivel em %s: %r" % (caminho, conjunto))
            chave = chave_canonica(cwes)
            primario = (registro.get("primario") or "").strip()
            if primario:
                normalizado = normalizar_cwe(primario)
                if normalizado is None:
                    raise SystemExit("ERRO: primario irreconhecivel em %s: %r" % (caminho, primario))
                # Regra de fechamento: o primário TEM que pertencer ao conjunto.
                if normalizado not in cwes:
                    raise SystemExit(
                        "ERRO: primario %s fora do conjunto %s em %s"
                        % (normalizado, chave, caminho)
                    )
                tabela[chave] = normalizado
            else:
                tabela[chave] = None
    return tabela


def resolver_primario(gt_cwes, tabela, relatorio, cve):
    """Três ramos, não uma busca (D.4).

    A tabela cobre apenas os 17 conjuntos multivalorados; consultá-la fora
    disso produziria falha por um caso previsto.
    """
    distintos = set(gt_cwes)
    if not distintos:
        relatorio["gt_cwe_primary"]["nulo_conjunto_vazio"].append(cve)
        return None
    if len(distintos) == 1:
        return next(iter(distintos))
    chave = chave_canonica(gt_cwes)
    if chave not in tabela:
        relatorio["gt_cwe_primary"]["conjuntos_ausentes_da_tabela"].append(
            {"cve": cve, "conjunto": chave}
        )
        raise FalhaCVE(
            "conjunto de CWE ausente de %s: %s (%s)"
            % (TABELA_PRIMARIO.name, chave, cve)
        )
    primario = tabela[chave]
    if primario is None:
        relatorio["gt_cwe_primary"]["nulo_primario_indefinido"].append(
            {"cve": cve, "conjunto": chave}
        )
    return primario


# ---------------------------------------------------------------------------
# Utilidades de SARIF (CodeQL e Snyk Code)
# ---------------------------------------------------------------------------
def _run_sarif(dados):
    if not isinstance(dados, dict):
        raise RawIlegivel("raw nao e um objeto JSON no topo")
    runs = dados.get("runs")
    if not isinstance(runs, list) or not runs:
        raise RawIlegivel("SARIF sem runs[] utilizavel")
    run = runs[0]
    if not isinstance(run, dict):
        raise RawIlegivel("SARIF com runs[0] que nao e objeto")
    # Simetria com o Semgrep, onde `results` ausente ja era RawIlegivel: sem
    # isto, um SARIF com runs[] e SEM a chave `results` viraria findings: []
    # e exit 0 — "analisou e nao achou" sem base, que e o desfecho que D.8
    # existe para impedir.
    if not isinstance(run.get("results"), list):
        raise RawIlegivel("SARIF com runs[0] sem a lista results[]")
    # So runs[0] e lido, mas os scripts de analise contam achados de TODOS os
    # runs: um SARIF multi-run daria N no log e outro numero no tratado.
    return run


def _contar_runs_extras(dados, cve, relatorio):
    runs = dados.get("runs")
    if isinstance(runs, list) and len(runs) > 1:
        relatorio["sarif_runs_ignorados"].append({"cve": cve, "runs": len(runs)})


def _indice_regras(run):
    """Índice por `id`. A resolução é por ruleId, NUNCA por ruleIndex: custa o
    mesmo e é robusta a reordenação do array de regras."""
    indice = {}
    ferramenta = run.get("tool") or {}
    driver = ferramenta.get("driver") or {}
    for regra in driver.get("rules") or []:
        if isinstance(regra, dict) and isinstance(regra.get("id"), str):
            indice.setdefault(regra["id"], regra)
    # extensions[] é legal em SARIF e alguns emissores põem regras ali. Incluir
    # é superconjunto de busca: reduz falso "nao resolvida" sem esconder nada,
    # porque o contador de não resolvidas continua sendo reportado.
    for extensao in ferramenta.get("extensions") or []:
        for regra in (extensao or {}).get("rules") or []:
            if isinstance(regra, dict) and isinstance(regra.get("id"), str):
                indice.setdefault(regra["id"], regra)
    return indice


NOTIF_EXTRAIDOS = "js/diagnostics/successfully-extracted-files"


def _uris_de_notificacao(run, filtro_id):
    """URIs citadas pelas notificações cujo descriptor.id satisfaz `filtro_id`.

    O caminho vive SÓ em `locations[0].physicalLocation.artifactLocation.uri`:
    medido na Fase E, `message.text` dessas notificações é cadeia vazia.
    """
    uris = []
    invocacoes = run.get("invocations")
    if not isinstance(invocacoes, list):
        return uris
    for invocacao in invocacoes:
        if not isinstance(invocacao, dict):
            continue
        notificacoes = invocacao.get("toolExecutionNotifications")
        if not isinstance(notificacoes, list):
            continue
        for notificacao in notificacoes:
            if not isinstance(notificacao, dict):
                continue
            identificador = (notificacao.get("descriptor") or {}).get("id")
            if not isinstance(identificador, str) or not filtro_id(identificador):
                continue
            for local in notificacao.get("locations") or []:
                uri = (((local or {}).get("physicalLocation") or {})
                       .get("artifactLocation") or {}).get("uri")
                if isinstance(uri, str):
                    uris.append(uri)
    return uris


def derivar_gt_file_scanned_codeql(run, gt_file_path, cve, relatorio):
    """(true|false|None, motivo).

    FONTE ÚNICA: as notificações `js/diagnostics/successfully-extracted-files`,
    uma por arquivo extraído. Medido na Fase E (10/09/2026): enumeram caminho,
    incluem arquivos SEM achado — `js/collapse.js` do CVE-2018-14040 aparece
    com zero resultados —, e o caminho sai relativo e limpo.

    **`runs[0].artifacts[]` foi DESCARTADO como fonte, deliberadamente.** É a
    escolha óbvia e é a errada: o array é superconjunto contaminado por outras
    linguagens. No CVE-2018-14040 traz 176 entradas contra 174 da notificação,
    e as duas a mais — `docs/_plugins/bridge.rb` e `docs/_plugins/bugify.rb` —
    entram por notificação de Ruby (`rb/baseline/...`). Usá-lo reportaria como
    varrido o que o extrator de JavaScript não tocou, o que é PIOR que `null`:
    afirma o contrário do verdadeiro. Não troque a fonte pela mais óbvia.

    `js/baseline/expected-extracted-files` também não serve: é amostra de
    baseline (45 contra 174 no mesmo CVE), não inventário.

    Ausência da notificação → `None`, nunca `False`. Ausência de inventário e
    ausência do arquivo no inventário são coisas distintas, pelo mesmo
    princípio que separa `unknown` de `unresolved` na severidade.
    """
    brutos = _uris_de_notificacao(run, lambda i: i == NOTIF_EXTRAIDOS)
    if not brutos:
        return None, ("SARIF sem notificacao %s: nao ha inventario de arquivos "
                      "extraidos neste raw" % NOTIF_EXTRAIDOS)

    extraidos = set()
    for caminho in brutos:
        limpo, motivos = normalizar_caminho(caminho)
        if motivos:
            # Divergência entre a forma do inventário e a dos achados. Não é
            # esperada — na Fase E nenhum caminho exigiu transformação — e por
            # isso é contada em campo próprio em vez de corrigida em silêncio.
            relatorio["caminho"]["caminhos_scanned_transformados"] += 1
            if len(relatorio["caminho"]["exemplos_scanned"]) < 10:
                relatorio["caminho"]["exemplos_scanned"].append(
                    {"cve": cve, "antes": caminho, "depois": limpo,
                     "motivos": motivos, "fonte": NOTIF_EXTRAIDOS}
                )
        extraidos.add(limpo)

    # Conferência do teto, pedida pela decisão: a notificação enumera TODOS os
    # arquivos extraídos, ou até um limite? `artifacts[]`, depurado das URIs
    # que só aparecem por notificação de outra linguagem, é o segundo
    # observável disponível. Se as duas contagens baterem em todos os CVEs,
    # não há teto na faixa medida. NÃO se compensa nada aqui — conta-se e
    # reporta-se, e a campanha decide com 223 CVEs em vez de 4.
    artefatos = set()
    for artefato in run.get("artifacts") or []:
        uri = ((artefato or {}).get("location") or {}).get("uri")
        if isinstance(uri, str):
            artefatos.add(normalizar_caminho(uri)[0])
    outras_linguagens = {
        normalizar_caminho(u)[0]
        for u in _uris_de_notificacao(run, lambda i: not i.startswith("js/"))
    }
    artefatos_js = artefatos - outras_linguagens
    relatorio["codeql_inventario"].append({
        "cve": cve,
        "notificacao": len(extraidos),
        "artifacts_depurado": len(artefatos_js),
        "bate": len(extraidos) == len(artefatos_js),
    })

    return (gt_file_path in extraidos), (
        "inventario de arquivos EXTRAIDOS, de %s. `false` significa que o "
        "arquivo nao foi extraido para o banco de dados — universo distinto do "
        "`paths.scanned` do Semgrep, que e de arquivos VARRIDOS" % NOTIF_EXTRAIDOS
    )


def _localizacao(resultado):
    """(uri, line_start, line_end, column_start, column_end).

    As colunas entram no schema desde 1.2. Medido na Fase E: as três
    ferramentas as emitem em 100% dos achados — `region.startColumn`/`endColumn`
    no SARIF, `start.col`/`end.col` no Semgrep —, e são o ÚNICO campo que
    distingue achados que empatam na chave de ordenação. No CodeQL a coluna
    vem mesmo quando `endLine` não vem."""
    locais = resultado.get("locations")
    if not isinstance(locais, list) or not locais:
        return None, None, None, None, None
    fisica = (locais[0] or {}).get("physicalLocation") or {}
    artefato = fisica.get("artifactLocation") or {}
    regiao = fisica.get("region") or {}
    return (artefato.get("uri"), regiao.get("startLine"), regiao.get("endLine"),
            regiao.get("startColumn"), regiao.get("endColumn"))


def _texto_mensagem(objeto):
    if not isinstance(objeto, dict):
        return None
    mensagem = objeto.get("message")
    if isinstance(mensagem, dict):
        texto = mensagem.get("text")
        return texto if isinstance(texto, str) else None
    if isinstance(mensagem, str):
        return mensagem
    return None


def _versao_sarif(run):
    driver = (run.get("tool") or {}).get("driver") or {}
    for campo in ("semanticVersion", "version"):
        valor = driver.get(campo)
        if isinstance(valor, str) and valor:
            return valor
    return None


def _notificacoes(run):
    """(quantidade|None, [textos]).

    None significa "o campo não existe neste raw" — ausência NUNCA é falha.
    0 significa "o campo existe e está vazio". A distinção importa: só a
    segunda é evidência de que a ferramenta não teve o que relatar.
    """
    invocacoes = run.get("invocations")
    if not isinstance(invocacoes, list):
        return None, []
    campo_presente = False
    textos = []
    for invocacao in invocacoes:
        if not isinstance(invocacao, dict):
            continue
        notificacoes = invocacao.get("toolExecutionNotifications")
        if notificacoes is None:
            continue
        campo_presente = True
        if not isinstance(notificacoes, list):
            continue
        for notificacao in notificacoes:
            partes = []
            nivel = (notificacao or {}).get("level")
            if isinstance(nivel, str):
                partes.append(nivel)
            texto = _texto_mensagem(notificacao)
            if texto:
                partes.append(texto)
            for local in (notificacao or {}).get("locations") or []:
                uri = (((local or {}).get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
                if isinstance(uri, str):
                    partes.append(uri)
            textos.append(" | ".join(partes) if partes else json.dumps(notificacao)[:LIMITE_TEXTO_DETALHE])
    if not campo_presente:
        return None, []
    return len(textos), textos


def _horario_invocacao(run):
    invocacoes = run.get("invocations")
    if not isinstance(invocacoes, list) or not invocacoes:
        return None
    primeira = invocacoes[0]
    if not isinstance(primeira, dict):
        return None
    for campo in ("endTimeUtc", "startTimeUtc"):
        valor = primeira.get(campo)
        if isinstance(valor, str) and valor:
            return valor
    return None


def _mtime_iso(caminho):
    marca = datetime.fromtimestamp(caminho.stat().st_mtime, tz=timezone.utc)
    return marca.isoformat().replace("+00:00", "Z")


def _truncar(texto):
    if not isinstance(texto, str):
        texto = str(texto)
    return texto if len(texto) <= LIMITE_TEXTO_DETALHE else texto[:LIMITE_TEXTO_DETALHE] + "…"


def montar_diagnosticos(erros, caminhos_descartados, notificacoes, detalhes):
    """O que a ferramenta reporta sobre a própria execução.

    `gt_file_affected` e `gt_file_affected_method` foram REMOVIDOS no schema
    1.2, por três razões medidas na Fase E, em ordem de peso:

    1. **A polaridade invertia entre ferramentas.** No Semgrep `detalhes` vem
       de `errors[]` e `paths.skipped[]` — problemas —, então `true` queria
       dizer "houve problema com o arquivo". No CodeQL vem das
       `toolExecutionNotifications`, que são quase todas de extração
       BEM-SUCEDIDA (174 de 176 num CVE), então `true` queria dizer "o arquivo
       foi extraído" — o oposto. Campo cujo sentido depende da ferramenta é
       pior que campo ausente.
    2. **O registro não sustentava a própria afirmação.** O booleano era
       calculado sobre a lista INTEIRA de detalhes, enquanto `details` guarda
       só as primeiras LIMITE_DETALHES entradas. Num CVE com 224 notificações
       o campo saía `true` por causa de uma entrada que o tratado não grava:
       quem lê não tem como conferir nem refutar.
    3. **No CodeQL a pergunta verdadeira é outra.** "A ferramenta considerou
       este arquivo" é exatamente o que `gt_file_scanned` responde, e o
       inventário para respondê-lo existe no mesmo SARIF. Manter um indício
       por substring ao lado de um inventário direto seria responder mal uma
       pergunta que se pode responder bem.

    O que resta é factual: as três contagens e o texto bruto, cada uma
    dizendo de que fonte veio. `details` segue truncado, e segue sendo indício
    — mas indício não é mais apresentado como conclusão.
    """
    return {
        "errors": erros,
        "skipped_paths": caminhos_descartados,
        "notifications": notificacoes,
        "details": [_truncar(d) for d in detalhes[:LIMITE_DETALHES]],
    }


# ---------------------------------------------------------------------------
# CodeQL
# ---------------------------------------------------------------------------
def processar_codeql(dados, caminho_raw, gt, relatorio):
    run = _run_sarif(dados)
    _contar_runs_extras(dados, gt["cve_id"], relatorio)
    indice = _indice_regras(run)
    versao = _versao_sarif(run)
    if versao and versao != CODEQL_VERSAO_ESPERADA:
        relatorio["codeql_versao_inesperada"].append(
            {"cve": gt["cve_id"], "versao": versao, "esperada": CODEQL_VERSAO_ESPERADA,
             "nota": "rules_total gravado (%d) e o da suite na versao esperada" % CODEQL_RULES_TOTAL}
        )

    horario = _horario_invocacao(run)
    if horario:
        analysis_date, origem = horario, "tool"
    else:
        analysis_date, origem = _mtime_iso(caminho_raw), "file_mtime"
        relatorio["analysis_date_fallback_mtime"].append(gt["cve_id"])

    achados = []
    for resultado in run.get("results") or []:
        if not isinstance(resultado, dict):
            relatorio["resultados_descartados"] += 1
            continue
        rule_id = resultado.get("ruleId")
        regra = indice.get(rule_id) if isinstance(rule_id, str) else None

        if regra is None:
            # Contador (2) de D.6: defeito de JUNÇÃO. Nunca colapsado em unknown.
            relatorio["severidade"]["regra_nao_resolvida"].append(
                {"cve": gt["cve_id"], "rule_id": rule_id}
            )

        cwes = []
        if regra is not None:
            for etiqueta in ((regra.get("properties") or {}).get("tags") or []):
                if isinstance(etiqueta, str) and etiqueta.lower().startswith("external/cwe/"):
                    normalizado = normalizar_cwe(etiqueta)
                    if normalizado and normalizado not in cwes:
                        cwes.append(normalizado)

        # SARIF permite nível no próprio resultado, com precedência sobre o
        # default da regra. O CLAUDE.md registra que o CodeQL não o emite; se
        # emitir, é ele que vale — e o relatório conta de onde veio.
        nivel = resultado.get("level")
        if isinstance(nivel, str):
            relatorio["severidade"]["origem_resultado"] += 1
        elif regra is not None:
            nivel = ((regra.get("defaultConfiguration") or {}).get("level"))
            if isinstance(nivel, str):
                relatorio["severidade"]["origem_regra"] += 1
        else:
            nivel = None

        if nivel is None and regra is None:
            severidade_normalizada = SEVERIDADE_NAO_RESOLVIDA
        else:
            if nivel is None:
                # Contador (1) de D.6: regra resolvida, sem nível declarado.
                relatorio["severidade"]["regra_resolvida_sem_nivel"].append(
                    {"cve": gt["cve_id"], "rule_id": rule_id}
                )
            severidade_normalizada = normalizar_severidade(nivel, gt["cve_id"], rule_id)

        bruto = (regra.get("properties") or {}).get("security-severity") if regra else None
        security_severity = None
        if bruto is not None:
            try:
                # Formato inconsistente ("5" e "5.0"): float, nunca texto.
                security_severity = float(bruto)
            except (TypeError, ValueError):
                relatorio["security_severity_ilegivel"].append(
                    {"cve": gt["cve_id"], "rule_id": rule_id, "valor": _truncar(bruto)}
                )

        uri, inicio, fim, col_inicio, col_fim = _localizacao(resultado)
        achados.append({
            "rule_id": rule_id,
            "cwe": cwes,
            "severity_original": nivel,
            "severity_normalized": severidade_normalizada,
            "security_severity": security_severity,
            "_uri_bruta": uri,
            "line_start": inicio,
            "line_end": fim,
            "column_start": col_inicio,
            "column_end": col_fim,
            "message": _texto_mensagem(resultado),
        })

    quantidade, textos = _notificacoes(run)
    diagnosticos = montar_diagnosticos(None, None, quantidade, textos)
    gt_file_scanned, motivo_scanned = derivar_gt_file_scanned_codeql(
        run, gt["gt_file_path"], gt["cve_id"], relatorio
    )

    return {
        "tool_version": versao,
        # name = referência da suíte; sha256 e obtained_at nulos por não haver
        # o que declarar. rules_applied é NULO por decisão: driver.rules[]
        # registra o que compareceu no resultado, não o que foi aplicado.
        "ruleset": {
            "name": CODEQL_SUITE,
            "sha256": None,
            "rules_id_sha256": None,   # não há pack de arquivo a identificar
            "obtained_at": None,
            "rules_total": CODEQL_RULES_TOTAL,
        },
        "rules_applied": None,
        "analysis_date": analysis_date,
        "analysis_date_source": origem,
        "gt_file_scanned": gt_file_scanned,
        "gt_file_scanned_motivo": motivo_scanned,
        "tool_diagnostics": diagnosticos,
        "achados": achados,
        "extra_metadata": {},
    }


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
def carregar_descritor_semgrep():
    if not DESCRITOR_SEMGREP.is_file():
        raise SystemExit(
            "ERRO: descritor do pack ausente: %s\n"
            "  O bloco ruleset do Semgrep vem dele; sem ele o tratado nao e "
            "reproduzivel." % DESCRITOR_SEMGREP
        )
    with open(DESCRITOR_SEMGREP, encoding="utf-8") as arquivo:
        meta = json.load(arquivo)
    obrigatorios = ("pack", "sha256", "obtained_at", "rules_total", "rules_id_sha256")
    faltando = [c for c in obrigatorios if c not in meta]
    if faltando:
        raise SystemExit(
            "ERRO: %s sem os campos %s" % (DESCRITOR_SEMGREP, ", ".join(faltando))
        )
    # Presença não basta: `rules_total` entra numa COMPARAÇÃO NUMÉRICA por CVE.
    # Com null ou "1074" no descritor, o `>` levantaria TypeError — que não é
    # FalhaCVE, não é capturado pelo laço, e derrubaria a execução INTEIRA sem
    # escrever relatório. Falhar aqui, uma vez e com mensagem, custa o mesmo e
    # perde um arquivo em vez de um lote.
    if isinstance(meta["rules_total"], bool) or not isinstance(meta["rules_total"], int):
        raise SystemExit(
            "ERRO: %s tem rules_total %r (%s); esperado inteiro"
            % (DESCRITOR_SEMGREP, meta["rules_total"], type(meta["rules_total"]).__name__)
        )
    return {
        "name": meta["pack"],
        # DUAS identidades, e por isso duas: o sha256 identifica o ARQUIVO, o
        # rules_id_sha256 identifica o CONJUNTO de regras. O endpoint do
        # registry serve o YAML com ordem não determinística — duas obtenções
        # deram bytes distintos com os mesmos 1074 check_id —, então só a
        # segunda permite a um terceiro verificar identidade de conjunto.
        # Sem ela no tratado, quem lê um treated isolado teria de ir ao
        # descritor para conseguir verificar coisa alguma.
        "sha256": meta["sha256"],
        "rules_id_sha256": meta["rules_id_sha256"],
        "obtained_at": meta["obtained_at"],
        "rules_total": meta["rules_total"],
    }


def _cwes_semgrep(bruto, cve, relatorio):
    """extra.metadata.cwe MUDA DE TIPO: lista na maioria, cadeia nua numa
    minoria. Iterar a cadeia nua percorreria caracteres, produziria zero CWEs
    válidos, e o achado sairia com has_cwe=false — falso negativo
    indistinguível de achado legitimamente sem CWE. Os dois tipos são
    tratados explicitamente, e a ocorrência de cadeia nua é contada."""
    if bruto is None:
        return []
    if isinstance(bruto, str):
        relatorio["cwe"]["semgrep_cadeia_nua"].append({"cve": cve, "valor": _truncar(bruto)})
        itens = [bruto]
    elif isinstance(bruto, list):
        itens = bruto
    else:
        relatorio["cwe"]["semgrep_tipo_inesperado"].append(
            {"cve": cve, "tipo": type(bruto).__name__, "valor": _truncar(bruto)}
        )
        return []
    cwes = []
    for item in itens:
        normalizado = normalizar_cwe(item)
        if normalizado and normalizado not in cwes:
            cwes.append(normalizado)
    return cwes


def _etiqueta_erro_semgrep(valor, cve=None, relatorio=None):
    """errors[].type MUDA DE TIPO, como extra.metadata.cwe: cadeia nua numa
    minoria ("Other syntax error") e união etiquetada na maioria —
    ["PartialParsing", [ {path, start, end}, ... ]]. Medido na Fase E, sobre
    twbs/bootstrap: 20 erros, 1 cadeia e 19 etiquetados.

    Só a etiqueta interessa ao diagnóstico; a carga é a lista de posições, que
    o `message` já resume. Sem este tratamento a forma etiquetada não é uma
    cadeia, o laço a ignora, e o detalhe sai SEM dizer que erro foi —
    silencioso, porque as demais partes continuam preenchidas."""
    if valor is None:
        return None
    if isinstance(valor, str):
        return valor
    if isinstance(valor, list) and valor and isinstance(valor[0], str):
        return valor[0]
    # Terceira forma. Sem contador ela sumiria: `partes` continua não-vazia
    # por causa de level/message/path, então o fallback json.dumps não
    # dispara e o detalhe sai PARECENDO completo, sem dizer que erro foi —
    # o próprio sintoma que esta função existe para eliminar. Simétrico ao
    # `semgrep_tipo_inesperado` do CWE, que trata o mesmo problema no outro
    # campo que muda de tipo.
    if relatorio is not None:
        relatorio["cwe"]["semgrep_tipo_inesperado"].append(
            {"cve": cve, "campo": "errors[].type",
             "tipo": type(valor).__name__, "valor": _truncar(valor)}
        )
    return None


def processar_semgrep(dados, caminho_raw, gt, relatorio, ruleset):
    if not isinstance(dados, dict):
        raise RawIlegivel("raw nao e um objeto JSON no topo")
    resultados = dados.get("results")
    if not isinstance(resultados, list):
        raise RawIlegivel("JSON do semgrep sem results[]")

    # MEDIDO NA FASE E, 10/09/2026: .time.rules[] NÃO lista as 1074 regras
    # carregadas, e sim as aplicadas às linguagens presentes no repositório.
    # Nos quatro CVEs do lote de teste deu 256, 297, 297 e 370, e as 256 do
    # menor são subconjunto próprio das 370 do maior. O console do Semgrep
    # informa as carregadas ("with 1074 Code rules"), mas isso é texto de
    # console: o JSON não traz o número.
    #
    # Daí o nome rules_applied. Campo chamado rules_loaded que significa
    # outra coisa é pior que campo ausente — a consequência estava fechada
    # no CLAUDE.md antes da medição, e é esta.
    #
    # Ausência de .time continua sendo FALHA, não rules_applied null: sem o
    # campo não há sequer o limite superior abaixo, e o --time está no
    # run_semgrep.sh justamente para produzi-lo.
    tempo = dados.get("time")
    if not isinstance(tempo, dict) or not isinstance(tempo.get("rules"), list):
        raise FalhaCVE(
            "JSON do semgrep sem .time.rules[] — o raw foi produzido sem --time? "
            "rules_applied e o inventario de regras efetivamente aplicadas"
        )
    rules_applied = len(tempo["rules"])
    # O valor de CADA CVE é registrado, sempre. A guarda antiga (`!=`) era
    # ruidosa mas mantinha os números à vista; trocá-la por uma condição quase
    # inalcançável, sem registrar nada, deixaria o relatório sem qualquer
    # rastro agregado de rules_applied — e os tratados não são versionados.
    relatorio["semgrep_rules_applied"].append(
        {"cve": gt["cve_id"], "rules_applied": rules_applied,
         "rules_total": ruleset["rules_total"]}
    )
    # DOIS limites, porque a relação verdadeira é 0 < rules_applied <= total.
    #
    # Superior: mais regras aplicadas do que o pack declara só ocorre se o
    # config em uso não for o pack vendorizado. Desigualdade estrita NÃO é
    # sinal — é o caso comum (256, 297, 297 e 370 contra 1074 na Fase E) e
    # reportá-la afogaria o relatório.
    #
    # Inferior: zero regras aplicadas produz `findings: []` indistinguível de
    # "analisou e não achou". A guarda anterior pegava esse caso de graça, por
    # ser `!=`; ao inverter para `>` ele ficaria sem vigia algum. É o modo de
    # falha mais barato de perder e o mais caro de descobrir depois.
    if rules_applied > ruleset["rules_total"]:
        relatorio["semgrep_rules_applied_anomalo"].append(
            {"cve": gt["cve_id"], "rules_applied": rules_applied,
             "rules_total": ruleset["rules_total"],
             "nota": "mais regras aplicadas que o pack declara; o config em uso nao e o pack vendorizado"}
        )
    elif rules_applied == 0:
        relatorio["semgrep_rules_applied_anomalo"].append(
            {"cve": gt["cve_id"], "rules_applied": 0,
             "rules_total": ruleset["rules_total"],
             "nota": "nenhuma regra aplicada; findings vazio nao significa ausencia de achados"}
        )

    achados = []
    for resultado in resultados:
        if not isinstance(resultado, dict):
            relatorio["resultados_descartados"] += 1
            continue
        extra = resultado.get("extra") or {}
        metadados = extra.get("metadata") or {}
        cwes = _cwes_semgrep(metadados.get("cwe"), gt["cve_id"], relatorio)
        bruta = extra.get("severity")
        relatorio["severidade"]["origem_resultado"] += 1
        severidade = normalizar_severidade(bruta, gt["cve_id"], resultado.get("check_id"))
        inicio = (resultado.get("start") or {}).get("line")
        fim = (resultado.get("end") or {}).get("line")
        col_inicio = (resultado.get("start") or {}).get("col")
        col_fim = (resultado.get("end") or {}).get("col")
        mensagem = extra.get("message")
        achados.append({
            "rule_id": resultado.get("check_id"),
            "cwe": cwes,
            "severity_original": bruta,
            "severity_normalized": severidade,
            "security_severity": None,  # exclusivo do CodeQL
            "_uri_bruta": resultado.get("path"),
            "line_start": inicio,
            "line_end": fim,
            "column_start": col_inicio,
            "column_end": col_fim,
            "message": mensagem if isinstance(mensagem, str) else None,
        })

    caminhos = dados.get("paths") if isinstance(dados.get("paths"), dict) else {}

    # gt_file_scanned: paths.scanned contém o gt_file_path. Os caminhos
    # varridos passam pela MESMA normalização dos achados, senão um './'
    # residual daria false onde houve varredura.
    varridos = caminhos.get("scanned")
    if isinstance(varridos, list):
        normalizados = set()
        for caminho in varridos:
            limpo, motivos = normalizar_caminho(caminho)
            if motivos:
                relatorio["caminho"]["caminhos_scanned_transformados"] += 1
                if len(relatorio["caminho"]["exemplos_scanned"]) < 10:
                    relatorio["caminho"]["exemplos_scanned"].append(
                        {"cve": gt["cve_id"], "antes": caminho, "depois": limpo, "motivos": motivos}
                    )
            normalizados.add(limpo)
        gt_file_scanned = gt["gt_file_path"] in normalizados
        motivo_scanned = (
            "inventario de arquivos VARRIDOS, de paths.scanned[]. `false` "
            "significa que o arquivo ficou fora da varredura — universo "
            "distinto do inventario do CodeQL, que e de arquivos EXTRAIDOS"
        )
    else:
        gt_file_scanned = None
        motivo_scanned = "JSON do semgrep sem paths.scanned[]"

    erros = dados.get("errors")
    detalhes = []
    quantidade_erros = None
    if isinstance(erros, list):
        quantidade_erros = len(erros)
        for erro in erros:
            partes = []
            for campo in ("level", "type", "message", "path"):
                valor = (erro or {}).get(campo) if isinstance(erro, dict) else None
                if campo == "type":
                    valor = _etiqueta_erro_semgrep(valor, gt["cve_id"], relatorio)
                if isinstance(valor, str):
                    partes.append(valor)
            detalhes.append(" | ".join(partes) if partes else json.dumps(erro)[:LIMITE_TEXTO_DETALHE])

    descartados = caminhos.get("skipped")
    quantidade_descartados = None
    if isinstance(descartados, list):
        quantidade_descartados = len(descartados)
        for item in descartados:
            if isinstance(item, dict):
                detalhes.append("skipped: %s | %s" % (item.get("path"), item.get("reason")))
            else:
                detalhes.append("skipped: %s" % item)

    diagnosticos = montar_diagnosticos(
        quantidade_erros, quantidade_descartados, None, detalhes
    )

    versao = dados.get("version")
    return {
        "tool_version": versao if isinstance(versao, str) else None,
        "ruleset": dict(ruleset),
        "rules_applied": rules_applied,
        # O JSON do Semgrep não traz carimbo de tempo. O mtime é proveniência
        # mais fraca — não sobrevive a download de artifact nem a git clone —
        # e por isso a origem é declarada em vez de uniformizada por aparência.
        "analysis_date": _mtime_iso(caminho_raw),
        "analysis_date_source": "file_mtime",
        "gt_file_scanned": gt_file_scanned,
        "gt_file_scanned_motivo": motivo_scanned,
        "tool_diagnostics": diagnosticos,
        "achados": achados,
        "extra_metadata": {},
    }


# ---------------------------------------------------------------------------
# Snyk Code
# ---------------------------------------------------------------------------
_RE_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def derivar_gt_file_scanned_snyk(cobertura, gt_file_path):
    """(true|false|None, motivo|None).

    ASSUMIDO, não verificado: o CLAUDE.md diz que a cobertura permite decidir
    se um arquivo foi varrido, mas o formato real de runs[0].properties.
    coverage[] não foi inspecionado — não há raw do Snyk no repositório.

    Se a cobertura trouxer inventário de CAMINHOS, a decisão é por pertinência.
    Se vier agregada por linguagem (files: 12, lang: "JavaScript"), NÃO dá para
    decidir sobre UM arquivo, e o resultado é None com motivo declarado.
    Inferir true a partir de contagem agregada fabricaria justamente o falso
    negativo silencioso que D.7 existe para pegar.
    """
    if not isinstance(cobertura, list) or not cobertura:
        return None, "SARIF do Snyk sem runs[0].properties.coverage[]"
    caminhos = set()
    for entrada in cobertura:
        if not isinstance(entrada, dict):
            continue
        # Entrada NÃO suportada não é "varrida": se o Snyk um dia passar a
        # enumerar caminhos, um arquivo listado sob FAILED_PARSING seria
        # contado como varrido e gt_file_scanned sairia `true` para um arquivo
        # que a ferramenta não conseguiu ler — falso "varrido", silencioso.
        # Hoje `files` é sempre contagem e este ramo não é alcançado; a guarda
        # é para quando for.
        if entrada.get("type") == "FAILED_PARSING" or entrada.get("isSupported") is False:
            continue
        for campo in ("files", "paths", "file", "path"):
            valor = entrada.get(campo)
            if isinstance(valor, str):
                limpo, _ = normalizar_caminho(valor)
                caminhos.add(limpo)
            elif isinstance(valor, list):
                for item in valor:
                    if isinstance(item, str):
                        limpo, _ = normalizar_caminho(item)
                        caminhos.add(limpo)
    if not caminhos:
        return None, "coverage[] agregada, sem inventario de caminhos: nao decide sobre um arquivo"
    return (gt_file_path in caminhos), (
        "inventario de caminhos da coverage[], entradas suportadas. Forma NAO "
        "observada na saida real da Fase E, onde `files` e sempre contagem"
    )


def processar_snyk(dados, caminho_raw, gt, relatorio):
    run = _run_sarif(dados)
    _contar_runs_extras(dados, gt["cve_id"], relatorio)
    indice = _indice_regras(run)
    versao = _versao_sarif(run)

    identificador = ((run.get("automationDetails") or {}).get("id"))
    analysis_date, origem = None, None
    if isinstance(identificador, str):
        achado = _RE_ISO.search(identificador)
        if achado:
            analysis_date, origem = achado.group(0), "tool"
    if analysis_date is None:
        analysis_date, origem = _mtime_iso(caminho_raw), "file_mtime"
        relatorio["analysis_date_fallback_mtime"].append(gt["cve_id"])

    achados = []
    for resultado in run.get("results") or []:
        if not isinstance(resultado, dict):
            relatorio["resultados_descartados"] += 1
            continue
        rule_id = resultado.get("ruleId")
        regra = indice.get(rule_id) if isinstance(rule_id, str) else None
        if regra is None:
            relatorio["severidade"]["regra_nao_resolvida"].append(
                {"cve": gt["cve_id"], "rule_id": rule_id}
            )

        cwes = []
        if regra is not None:
            brutos = (regra.get("properties") or {}).get("cwe")
            if isinstance(brutos, str):
                brutos = [brutos]
            if isinstance(brutos, list):
                for item in brutos:
                    normalizado = normalizar_cwe(item)
                    if normalizado and normalizado not in cwes:
                        cwes.append(normalizado)

        nivel = resultado.get("level")
        if isinstance(nivel, str):
            relatorio["severidade"]["origem_resultado"] += 1
        elif regra is not None:
            nivel = (regra.get("defaultConfiguration") or {}).get("level")
            if isinstance(nivel, str):
                relatorio["severidade"]["origem_regra"] += 1
        else:
            nivel = None

        if nivel is None and regra is None:
            severidade = SEVERIDADE_NAO_RESOLVIDA
        else:
            if nivel is None:
                relatorio["severidade"]["regra_resolvida_sem_nivel"].append(
                    {"cve": gt["cve_id"], "rule_id": rule_id}
                )
            severidade = normalizar_severidade(nivel, gt["cve_id"], rule_id)

        uri, inicio, fim, col_inicio, col_fim = _localizacao(resultado)
        achados.append({
            "rule_id": rule_id,
            "cwe": cwes,
            "severity_original": nivel,
            "severity_normalized": severidade,
            "security_severity": None,  # exclusivo do CodeQL
            "_uri_bruta": uri,
            "line_start": inicio,
            "line_end": fim,
            "column_start": col_inicio,
            "column_end": col_fim,
            "message": _texto_mensagem(resultado),
        })

    cobertura = (run.get("properties") or {}).get("coverage")
    gt_file_scanned, motivo = derivar_gt_file_scanned_snyk(cobertura, gt["gt_file_path"])

    # FAILED_PARSING promovido a tool_diagnostics.errors (schema 1.2).
    # Arquivo cuja análise falhou não produz achado, e o resultado é
    # indistinguível de análise limpa — é exatamente o sinal que o
    # tool_diagnostics existe para capturar. Deixá-lo só em
    # metadata.coverage era preservá-lo onde ninguém procura.
    #
    # Medido na Fase E: a entrada tem QUATRO chaves — files, isSupported,
    # lang, type — e `files` é SEMPRE uma CONTAGEM, nunca lista de caminhos
    # (11 entradas em 4 raws, todas numéricas). Logo a promoção é da
    # contagem, e o detalhe declara que não discrimina caminhos: sem isso,
    # quem lê "errors: 8" suporia saber quais arquivos.
    erros_cobertura = None
    detalhes_cobertura = []
    if isinstance(cobertura, list):
        erros_cobertura = 0
        for entrada in cobertura:
            if not isinstance(entrada, dict):
                continue
            if entrada.get("type") == "FAILED_PARSING" or entrada.get("isSupported") is False:
                # `files` e CONTAGEM na saida real medida (11 entradas em 4
                # raws, todas numericas). Lista de caminhos e o formato que o
                # Snyk NAO emite hoje; tratado aqui para que a promocao nao
                # devolva zero em silencio caso passe a emitir.
                bruto_files = entrada.get("files")
                if isinstance(bruto_files, bool):
                    quantos = 0
                elif isinstance(bruto_files, int):
                    quantos = bruto_files
                elif isinstance(bruto_files, list):
                    quantos = len(bruto_files)
                else:
                    quantos = 0
                erros_cobertura += quantos
                detalhes_cobertura.append(
                    "coverage: %s | %s | %s arquivo(s) — contagem por linguagem; "
                    "nao discrimina caminhos"
                    % (entrada.get("type"), entrada.get("lang"), quantos)
                )

    quantidade, textos = _notificacoes(run)
    diagnosticos = montar_diagnosticos(
        erros_cobertura, None, quantidade, detalhes_cobertura + textos
    )

    return {
        "tool_version": versao,
        "ruleset": None,   # não há conjunto declarável
        "rules_applied": None,
        "analysis_date": analysis_date,
        "analysis_date_source": origem,
        "gt_file_scanned": gt_file_scanned,
        "gt_file_scanned_motivo": motivo,
        "tool_diagnostics": diagnosticos,
        "achados": achados,
        # coverage íntegro, como veio; é o que sustenta a distinção entre
        # "analisou e não achou" e "não havia arquivo analisável".
        "extra_metadata": {"coverage": cobertura if cobertura is not None else None},
    }


# ---------------------------------------------------------------------------
# Ordenação e finding_id (D.9)
# ---------------------------------------------------------------------------
def _chave_ordenacao(achado):
    """Chave TOTAL: (file_path, line_start, line_end, column_start,
    column_end, rule_id, message).

    A estabilidade do sorted() não basta — ela preserva a ordem de ENTRADA nos
    empates, e a ordem de entrada é justamente o que pode variar entre
    execuções. Nulos vão para o fim, explicitamente.

    As colunas entraram no schema 1.2 e nesta chave por medição: na Fase E,
    11 achados do Semgrep empataram em (arquivo, linha, regra, mensagem) e
    diferiam SÓ na coluna — duas chamadas a `path.join` na mesma linha. Sem
    elas a chave não era total contra saída real, e um empate deixava de ser
    informação: passava a significar "idênticos em tudo que o schema grava"
    quando os achados eram distintos no raw.
    """
    def texto(valor):
        return (1, "") if not isinstance(valor, str) else (0, valor)

    def inteiro(valor):
        return (1, 0) if not isinstance(valor, int) or isinstance(valor, bool) else (0, valor)

    return (
        texto(achado.get("file_path")),
        inteiro(achado.get("line_start")),
        inteiro(achado.get("line_end")),
        inteiro(achado.get("column_start")),
        inteiro(achado.get("column_end")),
        texto(achado.get("rule_id")),
        texto(achado.get("message")),
    )


def ordenar_e_numerar(achados, ferramenta, cve, relatorio):
    indexados = list(enumerate(achados))
    # O índice original entra só como desempate FINAL, depois da chave total.
    indexados.sort(key=lambda par: (_chave_ordenacao(par[1]), par[0]))

    vistas = {}
    for _, achado in indexados:
        chave = _chave_ordenacao(achado)
        vistas[chave] = vistas.get(chave, 0) + 1
    colisoes = sum(quantidade - 1 for quantidade in vistas.values() if quantidade > 1)
    if colisoes:
        relatorio["colisoes_chave_ordenacao"]["total"] += colisoes
        relatorio["colisoes_chave_ordenacao"]["por_cve"].append(
            {"cve": cve, "colisoes": colisoes}
        )

    saida = []
    for numero, (_, achado) in enumerate(indexados, 1):
        registro = {"finding_id": "%s:%s:%04d" % (ferramenta, cve, numero)}
        for campo in ("rule_id", "cwe", "has_cwe", "severity_original",
                      "severity_normalized", "security_severity",
                      "file_path", "line_start", "line_end",
                      "column_start", "column_end", "message"):
            registro[campo] = achado.get(campo)
        saida.append(registro)
    return saida


# ---------------------------------------------------------------------------
# Relatório (D.12)
# ---------------------------------------------------------------------------
def relatorio_vazio(ferramenta):
    return {
        "ferramenta": ferramenta,
        "schema_version": SCHEMA_VERSION,
        "gerado_em": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cves": {
            "processados": 0,
            "pulados_por_idempotencia": 0,
            "com_falha": [],
            "linhas_da_lista_sem_raw": 0,
            "raws_sem_linha_na_lista": [],
            "arquivos_inesperados_no_raw_dir": [],
        },
        "achados": {"total": 0, "sem_cwe": 0},
        "caminho": {
            # Duas grandezas distintas, e o nome de cada uma diz qual é:
            # um caminho pode sofrer mais de uma transformação (file:// E
            # prefixo do WORKDIR, por exemplo), então os dois números
            # divergem e confundi-los subestima ou superestima o mexido.
            "achados_com_caminho_transformado": 0,
            "motivos_aplicados": 0,
            "achados_transformados": [],
            "caminhos_scanned_transformados": 0,
            "exemplos_scanned": [],
            "ground_truth_normalizado": [],
            "caminhos_absolutos_nao_reconhecidos": [],
            "nota": None,
        },
        "severidade": {
            "por_valor_normalizado": {},
            "regra_resolvida_sem_nivel": [],   # contador (1) de D.6
            "regra_nao_resolvida": [],         # contador (2) de D.6
            "origem_resultado": 0,
            "origem_regra": 0,
        },
        "cwe": {
            "achados_sem_cwe": 0,
            "semgrep_cadeia_nua": [],
            "semgrep_tipo_inesperado": [],
        },
        "gt_cwe_primary": {
            "nulo_conjunto_vazio": [],
            "nulo_primario_indefinido": [],
            "conjuntos_ausentes_da_tabela": [],
        },
        "gt_file_scanned": {"true": 0, "false": 0, "null": 0, "lista_false": [],
                            "motivos_null": {}, "motivos_por_estado": {}},
        # Conferência do teto da notificação do CodeQL: contagem por CVE, sem
        # compensação. Vazio nas outras duas ferramentas.
        "codeql_inventario": [],
        "tool_diagnostics": {
            "cves_com_erro": [],
            "cves_com_caminho_descartado": [],
            "cves_com_notificacao": [],
        },
        "colisoes_chave_ordenacao": {"total": 0, "por_cve": []},
        "raws_ilegiveis": [],
        "resultados_descartados": 0,
        "sarif_runs_ignorados": [],
        "tratados_obsoletos_apos_falha": [],
        "analysis_date_fallback_mtime": [],
        "semgrep_rules_applied": [],
        "semgrep_rules_applied_anomalo": [],
        "codeql_versao_inesperada": [],
        "security_severity_ilegivel": [],
        "duracao_segundos": {"total": 0.0, "por_cve_mediana": None, "por_cve_maximo": None,
                             "por_cve_maximo_cve": None},
    }


# ---------------------------------------------------------------------------
# Laço principal
# ---------------------------------------------------------------------------
def montar_tratado(ferramenta, gt, parcial, primario, relatorio):
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": gt["cve_id"],
        "repository": gt["repository"],
        # Da LISTA, não do log: a asserção do commit é fatal no script de
        # análise, então raw existente implica HEAD == PrePatchCommit.
        "commit": gt["commit"],
        "tool": ferramenta,
        "tool_version": parcial["tool_version"],
        "ruleset": parcial["ruleset"],
        "rules_applied": parcial["rules_applied"],
        "analysis_date": parcial["analysis_date"],
        "analysis_date_source": parcial["analysis_date_source"],
        "gt_cwes": list(gt["gt_cwes"]),
        "gt_cwe_primary": primario,
        "gt_file_path": gt["gt_file_path"],
        "gt_file_lines": list(gt["gt_file_lines"]),
        "gt_file_scanned": parcial["gt_file_scanned"],
        "tool_diagnostics": parcial["tool_diagnostics"],
    }
    if gt.get("gt_file_path_original"):
        metadata["gt_file_path_original"] = gt["gt_file_path_original"]
    # O motivo acompanha os TRÊS estados desde o schema 1.3, não só o `null`.
    # Com duas ferramentas decidindo por mecanismos distintos — `paths.scanned`
    # do Semgrep é de arquivos VARRIDOS, a notificação do CodeQL é de arquivos
    # EXTRAÍDOS —, um `false` não quer dizer a mesma coisa nas duas, e o
    # booleano sozinho fingiria uniformidade que não existe.
    if parcial.get("gt_file_scanned_motivo"):
        metadata["gt_file_scanned_reason"] = parcial["gt_file_scanned_motivo"]
    # Guarda de colisão: chave de ferramenta jamais sobrescreve chave do
    # schema. Hoje só `coverage` entra por aqui; a guarda custa nada e o
    # sintoma de uma colisão futura seria um campo do schema mudando de
    # significado sem aviso.
    for chave, valor in (parcial.get("extra_metadata") or {}).items():
        if chave in metadata:
            raise FalhaCVE("extra_metadata colidiria com o campo de schema %r" % chave)
        metadata[chave] = valor
    return {"metadata": metadata, "findings": []}


def processar_um(ferramenta, caminho_raw, gt, tabela, relatorio, ruleset_semgrep):
    try:
        with open(caminho_raw, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as erro:
        # D.8: raw ilegível NUNCA vira findings: []. Jamais capturar a exceção
        # e produzir lista vazia — é o que pegaria um SARIF vazio ou malformado
        # do Snyk, a única das três cujo raw o laço de análise não valida.
        raise RawIlegivel("raw ilegivel: %s: %s" % (type(erro).__name__, erro))

    primario = resolver_primario(gt["gt_cwes"], tabela, relatorio, gt["cve_id"])

    if ferramenta == "codeql":
        parcial = processar_codeql(dados, caminho_raw, gt, relatorio)
    elif ferramenta == "semgrep":
        parcial = processar_semgrep(dados, caminho_raw, gt, relatorio, ruleset_semgrep)
    else:
        parcial = processar_snyk(dados, caminho_raw, gt, relatorio)

    for achado in parcial["achados"]:
        bruto = achado.pop("_uri_bruta")
        limpo, motivos = normalizar_caminho(bruto)
        achado["file_path"] = limpo
        if motivos:
            # D.5 pede valor ANTES e DEPOIS, não só a contagem: uma
            # transformação inesperada só é reconhecível vendo o par.
            relatorio["caminho"]["achados_com_caminho_transformado"] += 1
            relatorio["caminho"]["motivos_aplicados"] += len(motivos)
            relatorio["caminho"]["achados_transformados"].append({
                "cve": gt["cve_id"],
                "antes": bruto,
                "depois": limpo,
                "motivos": motivos,
            })
        achado["has_cwe"] = bool(achado["cwe"])
        if not achado["has_cwe"]:
            relatorio["cwe"]["achados_sem_cwe"] += 1
        valor = achado["severity_normalized"]
        relatorio["severidade"]["por_valor_normalizado"][valor] = (
            relatorio["severidade"]["por_valor_normalizado"].get(valor, 0) + 1
        )
        if isinstance(limpo, str) and limpo.startswith("/"):
            relatorio["caminho"]["caminhos_absolutos_nao_reconhecidos"].append(
                {"cve": gt["cve_id"], "caminho": limpo}
            )

    tratado = montar_tratado(ferramenta, gt, parcial, primario, relatorio)
    tratado["findings"] = ordenar_e_numerar(
        parcial["achados"], ferramenta, gt["cve_id"], relatorio
    )
    relatorio["achados"]["total"] += len(tratado["findings"])

    diagnosticos = parcial["tool_diagnostics"]
    if diagnosticos["errors"]:
        relatorio["tool_diagnostics"]["cves_com_erro"].append(gt["cve_id"])
    if diagnosticos["skipped_paths"]:
        relatorio["tool_diagnostics"]["cves_com_caminho_descartado"].append(gt["cve_id"])
    if diagnosticos["notifications"]:
        relatorio["tool_diagnostics"]["cves_com_notificacao"].append(gt["cve_id"])

    varrido = parcial["gt_file_scanned"]
    motivo_estado = parcial.get("gt_file_scanned_motivo")
    if motivo_estado:
        estado = {True: "true", False: "false"}.get(varrido, "null")
        por_estado = relatorio["gt_file_scanned"]["motivos_por_estado"].setdefault(estado, {})
        por_estado[motivo_estado] = por_estado.get(motivo_estado, 0) + 1
    if varrido is True:
        relatorio["gt_file_scanned"]["true"] += 1
    elif varrido is False:
        relatorio["gt_file_scanned"]["false"] += 1
        relatorio["gt_file_scanned"]["lista_false"].append(gt["cve_id"])
    else:
        relatorio["gt_file_scanned"]["null"] += 1
        motivo = parcial.get("gt_file_scanned_motivo") or "sem motivo declarado"
        relatorio["gt_file_scanned"]["motivos_null"][motivo] = (
            relatorio["gt_file_scanned"]["motivos_null"].get(motivo, 0) + 1
        )

    return tratado


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Normaliza a saída bruta das ferramentas SAST para o schema comum.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    analisador.add_argument("--tool", required=True, choices=list(FERRAMENTAS))
    analisador.add_argument("--cve", help="processa um único CVE")
    analisador.add_argument("--overwrite", action="store_true",
                            help="reprocessa CVE cujo tratado já existe")
    analisador.add_argument("--raw-dir", help="padrão: results/<tool>/raw/")
    analisador.add_argument("--treated-dir", help="padrão: results/<tool>/treated/")
    analisador.add_argument("--lista", help="padrão: datasets/listas/cves-sast.txt "
                                            "(existe para exercitar fixtures)")
    analisador.add_argument("--report-path", help="padrão: logs/normalize-report-<tool>.json "
                                                  "(existe para exercitar fixtures)")
    args = analisador.parse_args(argv)

    ferramenta = args.tool
    raw_dir = Path(args.raw_dir) if args.raw_dir else RAIZ / "results" / ferramenta / "raw"
    treated_dir = Path(args.treated_dir) if args.treated_dir else RAIZ / "results" / ferramenta / "treated"
    lista = Path(args.lista) if args.lista else LISTA_PADRAO
    relatorio_path = (Path(args.report_path) if args.report_path
                      else RAIZ / "logs" / ("normalize-report-%s.json" % ferramenta))

    if not raw_dir.is_dir():
        print("ERRO: diretorio de raw ausente: %s" % raw_dir, file=sys.stderr)
        return 2

    gt_todos, caminhos_gt_transformados = carregar_lista(lista)
    tabela = carregar_tabela_primario(TABELA_PRIMARIO)
    ruleset_semgrep = carregar_descritor_semgrep() if ferramenta == "semgrep" else None

    relatorio = relatorio_vazio(ferramenta)
    relatorio["caminho"]["ground_truth_normalizado"] = caminhos_gt_transformados
    for item in caminhos_gt_transformados:
        print("AVISO: gt_file_path de %s normalizado: %r -> %r (%s)"
              % (item["cve"], item["antes"], item["depois"],
                 "; ".join(item["motivos"])), file=sys.stderr)
    relatorio["lista"] = str(lista)
    relatorio["raw_dir"] = str(raw_dir)
    relatorio["treated_dir"] = str(treated_dir)

    extensao = EXTENSAO_RAW[ferramenta]
    raws = sorted(p for p in raw_dir.iterdir() if p.is_file() and p.name.endswith(extensao))
    outros = sorted(
        p.name for p in raw_dir.iterdir()
        if p.is_file() and not p.name.endswith(extensao) and not p.name.startswith(".")
    )
    relatorio["cves"]["arquivos_inesperados_no_raw_dir"] = outros
    if outros:
        print("AVISO: %d arquivo(s) em %s fora do padrao %s: %s"
              % (len(outros), raw_dir, extensao, ", ".join(outros[:10])), file=sys.stderr)

    # Assimetria: raw sem linha na lista é FALHA RUIDOSA. Detectada antes de
    # escrever qualquer tratado, mas sem abortar — abortar na primeira
    # esconderia as demais.
    orfaos = [p.stem for p in raws if p.stem not in gt_todos]
    if orfaos:
        relatorio["cves"]["raws_sem_linha_na_lista"] = orfaos
        print("ERRO: %d raw(s) sem linha correspondente em %s — raw orfao, nome "
              "errado ou lista trocada:" % (len(orfaos), lista), file=sys.stderr)
        for nome in orfaos:
            print("  %s" % nome, file=sys.stderr)

    if args.cve:
        raws = [p for p in raws if p.stem == args.cve]
        if not raws:
            print("ERRO: nenhum raw para %s em %s" % (args.cve, raw_dir), file=sys.stderr)
            return 2

    treated_dir.mkdir(parents=True, exist_ok=True)
    relatorio_path.parent.mkdir(parents=True, exist_ok=True)

    presentes = {p.stem for p in raws}
    # Linha da lista sem raw é NORMAL e silenciosa: os lotes ainda não rodaram
    # todos. Contada no relatório, nunca avisada por CVE.
    if args.cve:
        # Nulo, nao zero: com --cve o numero nao foi apurado, e um campo
        # numerico com valor falso engana mais que um campo nulo.
        relatorio["cves"]["linhas_da_lista_sem_raw"] = None
    else:
        relatorio["cves"]["linhas_da_lista_sem_raw"] = len(
            [c for c in gt_todos if c not in presentes]
        )

    duracoes = []
    inicio_total = time.perf_counter()

    for caminho_raw in raws:
        cve = caminho_raw.stem
        if cve not in gt_todos:
            continue  # órfão: já reportado acima, não produz tratado
        gt = gt_todos[cve]
        destino = treated_dir / ("%s.json" % cve)

        if destino.exists() and not args.overwrite:
            versao_existente = None
            try:
                with open(destino, encoding="utf-8") as arquivo:
                    versao_existente = (json.load(arquivo).get("metadata") or {}).get("schema_version")
            except Exception:
                versao_existente = None
            if versao_existente == SCHEMA_VERSION:
                relatorio["cves"]["pulados_por_idempotencia"] += 1
                continue
            # Idempotência silenciosa sobre schema antigo é exatamente o tipo
            # de divergência que não dá sinal. Sem --overwrite, é falha.
            relatorio["cves"]["com_falha"].append({
                "cve": cve,
                "motivo": "tratado existente com schema_version %r != %r; use --overwrite"
                          % (versao_existente, SCHEMA_VERSION),
            })
            print("ERRO: %s: tratado existente com schema_version %r (corrente %r). "
                  "Use --overwrite." % (cve, versao_existente, SCHEMA_VERSION), file=sys.stderr)
            continue

        inicio = time.perf_counter()
        try:
            tratado = processar_um(ferramenta, caminho_raw, gt, tabela, relatorio, ruleset_semgrep)
        except FalhaCVE as erro:
            # Um raw ilegível interrompe AQUELE CVE, não a execução inteira.
            relatorio["cves"]["com_falha"].append({"cve": cve, "motivo": str(erro)})
            if isinstance(erro, RawIlegivel):
                relatorio["raws_ilegiveis"].append({"cve": cve, "motivo": str(erro)})
            print("ERRO: %s: %s" % (cve, erro), file=sys.stderr)
            # O tratado da execução anterior sobrevive à falha, íntegro e
            # desatualizado. NÃO é apagado — descartar artefato válido por
            # uma falha possivelmente transitória é pior —, mas quem lê
            # results/*/treated/ sem ler o relatório veria artefato válido
            # para um CVE que falhou. Por isso é dito, alto, nos dois canais.
            if destino.exists():
                relatorio["tratados_obsoletos_apos_falha"].append(str(destino))
                print("  AVISO: %s permanece da execucao anterior, agora "
                      "desatualizado" % destino, file=sys.stderr)
            continue

        temporario = destino.with_name(".em-progresso-%s.tmpjson" % cve)
        with open(temporario, "w", encoding="utf-8") as arquivo:
            json.dump(tratado, arquivo, ensure_ascii=False, indent=2, sort_keys=False)
            arquivo.write("\n")
        temporario.replace(destino)

        duracoes.append((time.perf_counter() - inicio, cve))
        relatorio["cves"]["processados"] += 1

    relatorio["duracao_segundos"]["total"] = round(time.perf_counter() - inicio_total, 4)
    if duracoes:
        valores = sorted(d for d, _ in duracoes)
        relatorio["duracao_segundos"]["por_cve_mediana"] = round(statistics.median(valores), 4)
        pior = max(duracoes)
        relatorio["duracao_segundos"]["por_cve_maximo"] = round(pior[0], 4)
        relatorio["duracao_segundos"]["por_cve_maximo_cve"] = pior[1]

    relatorio["achados"]["sem_cwe"] = relatorio["cwe"]["achados_sem_cwe"]
    absolutos = relatorio["caminho"]["caminhos_absolutos_nao_reconhecidos"]
    if relatorio["caminho"]["achados_com_caminho_transformado"] == 0 and not absolutos:
        relatorio["caminho"]["nota"] = (
            "NENHUM caminho de achado foi transformado: as %d saidas ja vieram "
            "relativas e limpas." % relatorio["achados"]["total"]
        )
    elif absolutos:
        # A nota anterior dizia "tudo limpo" quando zero transformacoes
        # ocorreram — inclusive no caso em que ocorreram ZERO porque o
        # caminho veio absoluto sob prefixo nao previsto e foi preservado.
        # Era o console afirmando justamente a invariante que falhou.
        relatorio["caminho"]["nota"] = (
            "%d achado(s) com caminho ABSOLUTO nao reconhecido, preservados "
            "como vieram. A premissa de que as ferramentas emitem caminho "
            "relativo e limpo NAO se sustentou: conferir o WORKDIR e o "
            "--source-root antes de cruzar." % len(absolutos)
        )

    with open(relatorio_path, "w", encoding="utf-8") as arquivo:
        json.dump(relatorio, arquivo, ensure_ascii=False, indent=2)
        arquivo.write("\n")

    resumir(relatorio, relatorio_path)

    houve_falha = bool(
        relatorio["cves"]["com_falha"] or relatorio["cves"]["raws_sem_linha_na_lista"]
    )
    return 1 if houve_falha else 0


def resumir(relatorio, caminho):
    cves = relatorio["cves"]
    print("--- normalizacao: %s ---" % relatorio["ferramenta"])
    print("  processados: %d | pulados: %d | com falha: %d"
          % (cves["processados"], cves["pulados_por_idempotencia"], len(cves["com_falha"])))
    sem_raw = cves["linhas_da_lista_sem_raw"]
    print("  linhas da lista sem raw: %s | raws sem linha na lista: %d"
          % ("nao apurado (--cve)" if sem_raw is None else sem_raw,
             len(cves["raws_sem_linha_na_lista"])))
    print("  achados: %d (sem CWE: %d)"
          % (relatorio["achados"]["total"], relatorio["achados"]["sem_cwe"]))
    severidade = relatorio["severidade"]
    print("  severidade: %s" % (severidade["por_valor_normalizado"] or "{}"))
    print("    regra resolvida sem nivel: %d | regra NAO resolvida: %d"
          % (len(severidade["regra_resolvida_sem_nivel"]), len(severidade["regra_nao_resolvida"])))
    varrido = relatorio["gt_file_scanned"]
    print("  gt_file_scanned: true=%d false=%d null=%d"
          % (varrido["true"], varrido["false"], varrido["null"]))
    if varrido["lista_false"]:
        print("    false em: %s" % ", ".join(varrido["lista_false"][:20]))
    bloco_caminho = relatorio["caminho"]
    print("  achados com caminho transformado: %d (%d motivo(s) aplicado(s))%s"
          % (bloco_caminho["achados_com_caminho_transformado"],
             bloco_caminho["motivos_aplicados"],
             " — %s" % bloco_caminho["nota"] if bloco_caminho["nota"] else ""))
    if bloco_caminho["caminhos_absolutos_nao_reconhecidos"]:
        print("    ATENCAO: %d caminho(s) ABSOLUTO(s) nao reconhecido(s):"
              % len(bloco_caminho["caminhos_absolutos_nao_reconhecidos"]))
        for item in bloco_caminho["caminhos_absolutos_nao_reconhecidos"][:10]:
            print("      %s  %s" % (item["cve"], item["caminho"]))
    if bloco_caminho["ground_truth_normalizado"]:
        print("    gt_file_path normalizado em %d CVE(s): %s"
              % (len(bloco_caminho["ground_truth_normalizado"]),
                 ", ".join(x["cve"] for x in bloco_caminho["ground_truth_normalizado"])))
    if relatorio["tratados_obsoletos_apos_falha"]:
        print("    ATENCAO: %d tratado(s) obsoleto(s) mantidos apos falha"
              % len(relatorio["tratados_obsoletos_apos_falha"]))
    if relatorio["sarif_runs_ignorados"]:
        print("    ATENCAO: %d raw(s) com mais de um run[]; so runs[0] foi lido"
              % len(relatorio["sarif_runs_ignorados"]))
    if relatorio["resultados_descartados"]:
        print("    %d entrada(s) de results[] descartada(s) por nao ser objeto"
              % relatorio["resultados_descartados"])
    # Estas três anomalias existiam apenas no JSON do relatório e não
    # apareciam no console. Anomalia que só a leitura posterior alcança é
    # anomalia que passa: quem acompanha a execução tem de ver na hora.
    if relatorio["semgrep_rules_applied_anomalo"]:
        print("    ATENCAO: %d CVE(s) com rules_applied > rules_total — o config "
              "em uso pode nao ser o pack vendorizado"
              % len(relatorio["semgrep_rules_applied_anomalo"]))
    if relatorio["codeql_versao_inesperada"]:
        print("    ATENCAO: %d CVE(s) com versao do CodeQL diferente da esperada"
              % len(relatorio["codeql_versao_inesperada"]))
    if relatorio["security_severity_ilegivel"]:
        print("    ATENCAO: %d achado(s) com security-severity ilegivel como float"
              % len(relatorio["security_severity_ilegivel"]))
    aplicadas = relatorio["semgrep_rules_applied"]
    if aplicadas:
        valores = sorted(x["rules_applied"] for x in aplicadas)
        print("  rules_applied: min=%d max=%d de rules_total=%d (aplicadas por linguagem "
              "presente, nao carregadas)"
              % (valores[0], valores[-1], aplicadas[0]["rules_total"]))
    inventario = relatorio["codeql_inventario"]
    if inventario:
        divergentes = [x for x in inventario if not x["bate"]]
        print("  inventario do CodeQL (notificacao x artifacts depurado): %d CVE(s), "
              "%d divergente(s)" % (len(inventario), len(divergentes)))
        for item in divergentes[:10]:
            print("    ATENCAO: %s notificacao=%d artifacts_depurado=%d — possivel teto "
                  "na notificacao" % (item["cve"], item["notificacao"], item["artifacts_depurado"]))
    print("  cadeia nua de CWE (semgrep): %d | colisoes de chave: %d"
          % (len(relatorio["cwe"]["semgrep_cadeia_nua"]),
             relatorio["colisoes_chave_ordenacao"]["total"]))
    print("  raws ilegiveis: %d" % len(relatorio["raws_ilegiveis"]))
    duracao = relatorio["duracao_segundos"]
    print("  duracao: total %.3fs | mediana/CVE %s | maximo/CVE %s (%s)"
          % (duracao["total"], duracao["por_cve_mediana"], duracao["por_cve_maximo"],
             duracao["por_cve_maximo_cve"]))
    print("  relatorio: %s" % caminho)


if __name__ == "__main__":
    sys.exit(main())
