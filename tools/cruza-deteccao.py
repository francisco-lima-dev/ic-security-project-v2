#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cruza-deteccao.py — confronta os tratados das tres ferramentas SAST com o
ground truth e apura, por (CVE, ferramenta), os cinco niveis de acerto e as
duas variantes de CWE fixados em docs/criterios-cruzamento.md.

    python3 tools/cruza-deteccao.py [--lista ARQ] [--treated-root DIR]
                                    [--registro ARQ] [--saida-dir DIR]

As quatro opcoes sao CAMINHOS e existem para exercitar fixtures. Nenhuma
seleciona recorte: toda execucao apura os cinco niveis e as duas variantes,
e qual discutir e decisao do texto (criterios, secao 7). O script nao elege
nivel principal nem hierarquiza as variantes.

ENTRADAS — todas versionadas; nada depende de artifact
  datasets/listas/cves-sast.txt          universo dos 223 CVEs e ground truth
  datasets/cwe-primario.csv              primario dos conjuntos multivalorados
  results/<ferramenta>/treated/*.json    os tratados, schema 1.3
  logs/campanha-2026-09-17/campanha-223.json
                                         status de cada (CVE, ferramenta)

O registro da campanha NAO define o denominador: ele e conferido. Serve para
que a ausencia de um tratado nunca seja interpretada sem causa registrada —
ver "sem tratado", adiante.

SAIDAS — em results/cruzamento/, escritas so depois de todas as conferencias
  matriz-deteccao.csv          uma linha por (CVE, ferramenta): 223 x 3
  cruzamento-<ferramenta>.json agregados, achados casados, ressalvas

O GROUND TRUTH vem da lista e da tabela, lidas pelas funcoes do proprio
tools/normalize.py (carregar_lista, carregar_tabela_primario,
resolver_primario, normalizar_cwe). Uma implementacao so de normalizacao de
CWE e de caminho: duas e como CWE-79 e CWE-079 voltam a divergir em silencio.
O gt gravado em cada tratado e CONFERIDO igual ao derivado da lista, e a
divergencia e fatal.

O DENOMINADOR — 220 pares, o mesmo para as tres ferramentas
  - vem da lista, menos tres exclusoes nominadas por identificador;
  - nao emerge da ausencia de arquivo: tratado presente de CVE excluido por
    codigo indisponivel e fatal;
  - CVE do denominador sem tratado so e admitido com status
    SEM_ARQUIVO_ANALISAVEL do Snyk Code no registro, e conta como
    nao-deteccao em todos os niveis. Qualquer outra ausencia e fatal.

O QUE NAO E CALCULADO
  Precisao, falso positivo, ou qualquer grandeza que use os achados fora do
  arquivo do ground truth como denominador (criterios, secao 1): o benchmark
  nao traz rotulo negativo, e esses achados nao sao classificaveis. Pelo
  mesmo motivo nenhuma saida traz contagem total de achados ao lado da
  contagem no arquivo do ground truth.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FERRAMENTAS = ("codeql", "semgrep", "snyk-code")

LISTA_PADRAO = RAIZ / "datasets" / "listas" / "cves-sast.txt"
REGISTRO_PADRAO = RAIZ / "logs" / "campanha-2026-09-17" / "campanha-223.json"
TREATED_ROOT_PADRAO = RAIZ / "results"
SAIDA_PADRAO = RAIZ / "results" / "cruzamento"
CRITERIOS = RAIZ / "docs" / "criterios-cruzamento.md"
NORMALIZE = RAIZ / "tools" / "normalize.py"

VERSAO_CRUZAMENTO = "1"
# Escrito contra o schema 1.3. Tratado de outra versao, ou normalize.py
# gravando outra versao, e parada: os campos lidos aqui podem ter mudado.
SCHEMA_ESPERADO = "1.3"

CVES_NA_LISTA = 223
PARES_NO_DENOMINADOR = 220

# Exclusoes EXPLICITAS, por identificador. Nenhuma delas pode depender de o
# arquivo faltar: denominador que emerge de ausencia muda em silencio quando
# alguem repoe um arquivo.
FORA_POR_CODIGO_INDISPONIVEL = {
    "CVE-2016-1000229": "codigo_indisponivel_repositorio_inexistente",
    "CVE-2018-8035": "codigo_indisponivel_commit_inexistente",
}
# O status que sustenta cada motivo, e so ele: repositorio inexistente falha
# na obtencao; commit inexistente, no checkout (CLAUDE.md, "Cobertura").
STATUS_DA_BAIXA = {"CVE-2016-1000229": "ERRO_FETCH", "CVE-2018-8035": "ERRO_CHECKOUT"}
FORA_SEM_CWE = {"CVE-2018-1000096": "sem_cwe_no_ground_truth"}
FORA_DO_DENOMINADOR = {**FORA_POR_CODIGO_INDISPONIVEL, **FORA_SEM_CWE}

STATUS_CONHECIDOS = {"OK", "SEM_ACHADOS", "PULADO", "ERRO_LINHA", "ERRO_FETCH",
                     "ERRO_CHECKOUT", "ERRO_ANALISE", "SEM_ARQUIVO_ANALISAVEL"}
STATUS_COM_TRATADO = {"OK", "SEM_ACHADOS"}
# Unica ausencia de tratado admitida no denominador, e so no Snyk Code: exit 3
# e causa interna a ferramenta, o CVE permanece e conta como nao-deteccao
# (CLAUDE.md, "Denominador quando SEM_ARQUIVO_ANALISAVEL ocorre").
SEM_TRATADO_ADMITIDO = {"snyk-code": {"SEM_ARQUIVO_ANALISAVEL"}}

NIVEIS = ("nivel_0", "nivel_1", "nivel_2_generosa", "nivel_2_estrita",
          "nivel_3", "nivel_4_generosa", "nivel_4_estrita")
NIVEIS_ESTRITOS = ("nivel_2_estrita", "nivel_4_estrita")
# nivel_0 e satisfeito por qualquer achado do tratado; sua "lista de casados"
# seria o tratado inteiro, e nao e replicada.
NIVEIS_COM_CASADOS = NIVEIS[1:]

CHAVES_ACHADO = {"column_end", "column_start", "cwe", "file_path", "finding_id",
                 "has_cwe", "line_end", "line_start", "message", "rule_id",
                 "security_severity", "severity_normalized", "severity_original"}
# Chaves que normalize.montar_tratado grava sempre.
CHAVES_METADATA = {"schema_version", "cve_id", "repository", "commit", "tool",
                   "tool_version", "ruleset", "rules_applied", "analysis_date",
                   "analysis_date_source", "gt_cwes", "gt_cwe_primary",
                   "gt_file_path", "gt_file_lines", "gt_file_scanned",
                   "tool_diagnostics"}
# extra_metadata: so o Snyk Code grava, e grava sempre.
CHAVES_METADATA_POR_FERRAMENTA = {"snyk-code": {"coverage"}}
CHAVES_METADATA_OPCIONAIS = {"gt_file_path_original", "gt_file_scanned_reason"}
VOCAB_SEV = {"high", "medium", "low", "unknown", "unresolved"}

COLUNAS_CSV = ("cve", "ferramenta", "no_denominador", "motivo_fora_denominador",
               "status_campanha", "tratado_presente", *NIVEIS, "estrita_aplicavel",
               "achados_no_arquivo_gt", "distancia_min_linha",
               "distancia_min_intervalo", "gt_file_scanned", "gt_cwe_primary",
               "gt_cwes")
NOME_CSV = "matriz-deteccao.csv"
PREFIXO_TEMP = ".cruzamento-tmp-"
LIMITE_MOTIVOS_IMPRESSOS = 60

NOTAS = [
    "Nenhuma metrica de precisao nem de falso positivo: achado fora do arquivo "
    "do ground truth nao e classificavel (criterios, secao 1).",
    "achados_no_arquivo_gt e as listas de casados tambem nao formam precisao: "
    "a razao entre casados e achados no arquivo pressuporia que o resto do "
    "arquivo e limpo, o que o benchmark nao afirma.",
    "nivel_0 e satisfeito por qualquer achado do tratado; a lista de "
    "finding_id dele nao e replicada.",
    "Os niveis 2, 3 e 4 exigem que o MESMO achado satisfaca todas as "
    "condicoes; as listas de casados sao por achado.",
    "Casamento de linha por sobreposicao de [line_start, line_end] com alguma "
    "gt_file_lines, sem banda; line_end nulo vale [line_start, line_start]; "
    "achado sem line_start nao casa linha.",
    "distancia_min_linha e |line_start - L| (a grandeza da caracterizacao); "
    "distancia_min_intervalo e a distancia do intervalo a L, e vale 0 "
    "exatamente quando nivel_3 e verdadeiro.",
    "Variante estrita com gt_cwe_primary nulo: nao se aplica, contada em "
    "nao_se_aplica, nunca como nao-acerto. Qual base usar para ela e decisao "
    "do texto; o script nao emite fracao.",
    "CVE do denominador sem tratado so e admitido com status "
    "SEM_ARQUIVO_ANALISAVEL no registro da campanha, e conta como "
    "nao-deteccao em todos os niveis.",
    "O gt usado na apuracao vem da lista e da tabela de primario; o gt "
    "gravado em cada tratado foi conferido igual a ele.",
]


class Parada(Exception):
    """Condicao que impede emitir numero algum. Carrega todos os motivos."""

    def __init__(self, titulo, motivos):
        super().__init__(titulo)
        self.titulo = titulo
        self.motivos = list(motivos)


# ---------------------------------------------------------------------------
# normalize.py como biblioteca
# ---------------------------------------------------------------------------
def carregar_normalize():
    # Sem .pyc em tools/__pycache__: importar nao pode deixar residuo no
    # repositorio.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("normalize", NORMALIZE)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def inteiro(valor):
    return isinstance(valor, int) and not isinstance(valor, bool)


def cwe_canonico(valor, norm):
    """Forma normalizada de tres digitos, pela implementacao do normalize.py."""
    return isinstance(valor, str) and norm.normalizar_cwe(valor) == valor


def caminho_canonico(valor):
    """Relativo e limpo: sem barra inicial, sem ./, sem segmento vazio, . ou ..

    A comparacao de nivel 1 e igualdade exata de cadeia. Caminho fora desta
    forma tornaria a igualdade mal definida, e o erro seria um falso negativo
    silencioso — por isso e anomalia fatal, e nao ajuste.
    """
    if not isinstance(valor, str) or not valor:
        return False
    if valor.startswith("/") or "\\" in valor:
        return False
    return all(segmento not in ("", ".", "..") for segmento in valor.split("/"))


def sha256_arquivo(caminho):
    return hashlib.sha256(Path(caminho).read_bytes()).hexdigest()


def rotulo_caminho(caminho):
    caminho = Path(caminho).resolve()
    try:
        return str(caminho.relative_to(RAIZ))
    except ValueError:
        return str(caminho)


# ---------------------------------------------------------------------------
# Ground truth e denominador
# ---------------------------------------------------------------------------
def carregar_gt(norm, lista):
    """Devolve (gt, denominador, transformacoes). Levanta Parada."""
    try:
        gt, transformacoes = norm.carregar_lista(lista)
        tabela = norm.carregar_tabela_primario(norm.TABELA_PRIMARIO)
    except SystemExit as erro:
        raise Parada("ground truth ilegivel", [str(erro.code)])

    motivos = []
    if len(gt) != CVES_NA_LISTA:
        motivos.append("a lista tem %d CVEs, esperados %d" % (len(gt), CVES_NA_LISTA))
    for cve in FORA_DO_DENOMINADOR:
        if cve not in gt:
            motivos.append("exclusao nominada %s nao esta na lista: a constante "
                           "nao casa com o conjunto" % cve)

    # A premissa do 222: exatamente um CVE sem CWE, e e o nominado.
    sem_cwe = sorted(cve for cve, g in gt.items() if not g["gt_cwes"])
    if sem_cwe != sorted(FORA_SEM_CWE):
        motivos.append("CVEs com gt_cwes vazio na lista: %s; esperado so %s — a "
                       "premissa dos 222 pares esta errada"
                       % (sem_cwe or "nenhum", sorted(FORA_SEM_CWE)))

    relatorio = norm.relatorio_vazio("codeql")
    for cve, g in gt.items():
        try:
            g["gt_cwe_primary"] = norm.resolver_primario(g["gt_cwes"], tabela, relatorio, cve)
        except norm.FalhaCVE as erro:
            motivos.append("%s: %s" % (cve, erro))
            g["gt_cwe_primary"] = None
            continue
        if g["gt_cwe_primary"] is not None and g["gt_cwe_primary"] not in g["gt_cwes"]:
            motivos.append("%s: primario %s fora do conjunto %s (regra de fechamento)"
                           % (cve, g["gt_cwe_primary"], g["gt_cwes"]))
        if not caminho_canonico(g["gt_file_path"]):
            motivos.append("%s: gt_file_path %r fora da forma canonica" % (cve, g["gt_file_path"]))

    denominador = sorted(cve for cve in gt if cve not in FORA_DO_DENOMINADOR)
    if len(denominador) != PARES_NO_DENOMINADOR:
        motivos.append("denominador com %d pares, esperados %d"
                       % (len(denominador), PARES_NO_DENOMINADOR))
    for cve in denominador:
        if not gt[cve]["gt_file_lines"]:
            motivos.append("%s: gt_file_lines vazio num CVE do denominador — o "
                           "criterio de linha fica indefinido" % cve)
    if motivos:
        raise Parada("ground truth nao confere com as premissas do denominador", motivos)
    return gt, denominador, transformacoes


def carregar_registro(caminho, gt):
    """Status de cada (CVE, ferramenta) na campanha. Levanta Parada."""
    try:
        dados = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as erro:
        raise Parada("registro da campanha ilegivel", ["%s: %s" % (caminho, erro)])
    por_cve = dados.get("por_cve") if isinstance(dados, dict) else None
    if not isinstance(por_cve, dict):
        raise Parada("registro da campanha sem por_cve", [str(caminho)])

    motivos, registro = [], {}
    for ferramenta in FERRAMENTAS:
        entradas = por_cve.get(ferramenta)
        if not isinstance(entradas, list):
            motivos.append("registro sem a lista de %s" % ferramenta)
            continue
        registro[ferramenta] = {}
        for entrada in entradas:
            if not (isinstance(entrada, list) and len(entrada) == 3
                    and isinstance(entrada[0], str) and isinstance(entrada[1], str)):
                motivos.append("%s: entrada fora da forma [cve, status, duracao]: %r"
                               % (ferramenta, entrada))
                continue
            cve, status = entrada[0], entrada[1]
            if cve in registro[ferramenta]:
                motivos.append("%s: %s repetido no registro" % (ferramenta, cve))
            if status not in STATUS_CONHECIDOS:
                motivos.append("%s %s: status desconhecido %r" % (ferramenta, cve, status))
            registro[ferramenta][cve] = status
        faltam = sorted(set(gt) - set(registro[ferramenta]))
        sobram = sorted(set(registro[ferramenta]) - set(gt))
        if faltam:
            motivos.append("%s: %d CVEs da lista sem status no registro: %s"
                           % (ferramenta, len(faltam), faltam[:10]))
        if sobram:
            motivos.append("%s: %d CVEs no registro fora da lista: %s"
                           % (ferramenta, len(sobram), sobram[:10]))
    if motivos:
        raise Parada("registro da campanha nao confere com a lista", motivos)
    return registro


# ---------------------------------------------------------------------------
# Validacao estrutural dos tratados
# ---------------------------------------------------------------------------
def validar_tratado(cve, ferramenta, dados, gt, norm):
    """Lista de anomalias. Nao corrige nada; vazia = integro."""
    anomalias = []

    def anomalia(texto):
        anomalias.append("%s %s: %s" % (ferramenta, cve, texto))

    if not isinstance(dados, dict) or set(dados) != {"metadata", "findings"}:
        anomalia("chaves do topo %s, esperadas ['findings', 'metadata']"
                 % (sorted(dados) if isinstance(dados, dict) else type(dados).__name__))
        return anomalias
    meta = dados["metadata"]
    if not isinstance(meta, dict):
        anomalia("metadata nao e objeto")
        return anomalias
    exigidas = CHAVES_METADATA | CHAVES_METADATA_POR_FERRAMENTA.get(ferramenta, set())
    faltam = exigidas - set(meta)
    sobram = set(meta) - exigidas - CHAVES_METADATA_OPCIONAIS
    if faltam:
        anomalia("metadata sem %s" % sorted(faltam))
        return anomalias
    if sobram:
        anomalia("metadata com chave inesperada %s" % sorted(sobram))

    if meta["schema_version"] != SCHEMA_ESPERADO:
        anomalia("schema_version %r, esperado %r" % (meta["schema_version"], SCHEMA_ESPERADO))
    if meta["cve_id"] != cve:
        anomalia("cve_id %r difere do nome do arquivo" % (meta["cve_id"],))
    if meta["tool"] != ferramenta:
        anomalia("tool %r difere do diretorio" % (meta["tool"],))
    if meta["commit"] != gt["commit"]:
        anomalia("commit %r difere do PrePatchCommit da lista %r" % (meta["commit"], gt["commit"]))
    if meta["repository"] != gt["repository"]:
        anomalia("repository %r difere da lista" % (meta["repository"],))

    cwes_gt = meta["gt_cwes"]
    if cve in FORA_SEM_CWE and cwes_gt != []:
        # Nominado a parte da divergencia generica logo abaixo: e a premissa
        # que faz 222 e nao 223.
        anomalia("gt_cwes %r nao vazio num CVE excluido por nao ter CWE — a "
                 "premissa dos 222 pares esta errada" % (cwes_gt,))
    if not isinstance(cwes_gt, list) or not all(cwe_canonico(c, norm) for c in cwes_gt):
        anomalia("gt_cwes fora da forma canonica: %r" % (cwes_gt,))
    elif cwes_gt != gt["gt_cwes"]:
        anomalia("gt_cwes %r difere da lista %r" % (cwes_gt, gt["gt_cwes"]))
    primario = meta["gt_cwe_primary"]
    if primario is not None and not cwe_canonico(primario, norm):
        anomalia("gt_cwe_primary fora da forma canonica: %r" % (primario,))
    elif primario != gt["gt_cwe_primary"]:
        anomalia("gt_cwe_primary %r difere do derivado da tabela %r"
                 % (primario, gt["gt_cwe_primary"]))
    if meta["gt_file_path"] != gt["gt_file_path"]:
        anomalia("gt_file_path %r difere da lista normalizada %r"
                 % (meta["gt_file_path"], gt["gt_file_path"]))
    if meta.get("gt_file_path_original") != gt["gt_file_path_original"]:
        anomalia("gt_file_path_original %r, esperado %r"
                 % (meta.get("gt_file_path_original"), gt["gt_file_path_original"]))
    linhas = meta["gt_file_lines"]
    if not isinstance(linhas, list) or not all(inteiro(x) for x in linhas):
        anomalia("gt_file_lines fora da forma lista de inteiros: %r" % (linhas,))
    elif linhas != gt["gt_file_lines"]:
        anomalia("gt_file_lines %r difere da lista %r" % (linhas, gt["gt_file_lines"]))
    varrido = meta["gt_file_scanned"]
    if not (varrido is None or isinstance(varrido, bool)):
        anomalia("gt_file_scanned fora do tri-estado: %r" % (varrido,))

    achados = dados["findings"]
    if not isinstance(achados, list):
        anomalia("findings nao e lista")
        return anomalias
    padrao_id = re.compile(r"^%s:%s:[0-9]{4,}$" % (re.escape(ferramenta), re.escape(cve)))
    vistos = set()
    for indice, achado in enumerate(achados):
        rotulo = "achado %d" % indice
        if not isinstance(achado, dict) or set(achado) != CHAVES_ACHADO:
            anomalia("%s: chaves divergentes %s" % (
                rotulo, sorted(set(achado) ^ CHAVES_ACHADO) if isinstance(achado, dict)
                else type(achado).__name__))
            continue
        fid = achado["finding_id"]
        if not isinstance(fid, str) or not padrao_id.match(fid):
            anomalia("%s: finding_id %r fora da forma <tool>:<CVE>:<NNNN>" % (rotulo, fid))
        elif fid in vistos:
            anomalia("%s: finding_id %s repetido" % (rotulo, fid))
        else:
            vistos.add(fid)
        cwes = achado["cwe"]
        if not isinstance(cwes, list) or not all(cwe_canonico(c, norm) for c in cwes):
            anomalia("%s: cwe fora da forma canonica: %r" % (rotulo, cwes))
        elif not isinstance(achado["has_cwe"], bool) or achado["has_cwe"] != bool(cwes):
            anomalia("%s: has_cwe %r incoerente com cwe %r" % (rotulo, achado["has_cwe"], cwes))
        if not caminho_canonico(achado["file_path"]):
            anomalia("%s: file_path fora da forma canonica: %r" % (rotulo, achado["file_path"]))
        for campo in ("line_start", "line_end", "column_start", "column_end"):
            if achado[campo] is not None and not inteiro(achado[campo]):
                anomalia("%s: %s nao e inteiro nem nulo: %r" % (rotulo, campo, achado[campo]))
        inicio, fim = achado["line_start"], achado["line_end"]
        if inicio is None and fim is not None:
            anomalia("%s: line_end %r sem line_start" % (rotulo, fim))
        if inteiro(inicio) and inteiro(fim) and fim < inicio:
            anomalia("%s: line_end %d menor que line_start %d" % (rotulo, fim, inicio))
        if achado["severity_normalized"] not in VOCAB_SEV:
            anomalia("%s: severity_normalized fora do vocabulario: %r"
                     % (rotulo, achado["severity_normalized"]))
        for campo in ("rule_id", "message", "severity_original"):
            if achado[campo] is not None and not isinstance(achado[campo], str):
                anomalia("%s: %s nao e texto nem nulo" % (rotulo, campo))
        severidade = achado["security_severity"]
        if severidade is not None and (isinstance(severidade, bool)
                                       or not isinstance(severidade, (int, float))):
            anomalia("%s: security_severity nao e numero nem nulo" % rotulo)
    return anomalias


def carregar_tratados(raiz_tratados, ferramenta, gt, norm):
    """Devolve ({cve: tratado integro}, {cves com arquivo}, anomalias, sha256).

    A presenca e a do ARQUIVO, integro ou nao: tratado que falha a validacao
    ja e anomalia propria, e nao pode reaparecer como "tratado ausente".
    """
    diretorio = Path(raiz_tratados) / ferramenta / "treated"
    if not diretorio.is_dir():
        return ({}, set(), ["%s: diretorio de tratados ausente: %s" % (ferramenta, diretorio)],
                None)
    padrao = re.compile(r"^CVE-[0-9]{4}-[0-9]+\.json$")
    tratados, presentes, anomalias = {}, set(), []
    resumo = hashlib.sha256()
    for caminho in sorted(diretorio.iterdir()):
        if caminho.name == ".gitkeep":
            continue
        if not caminho.is_file() or not padrao.match(caminho.name):
            anomalias.append("%s: arquivo inesperado em %s: %s"
                             % (ferramenta, diretorio, caminho.name))
            continue
        cve = caminho.name[:-len(".json")]
        if cve not in gt:
            anomalias.append("%s: tratado orfao, %s fora da lista" % (ferramenta, cve))
            continue
        presentes.add(cve)
        try:
            bruto = caminho.read_bytes()
        except OSError as erro:
            anomalias.append("%s %s: tratado ilegivel: %s" % (ferramenta, cve, erro))
            continue
        resumo.update(("%s\0%s\n" % (caminho.name, hashlib.sha256(bruto).hexdigest())).encode())
        try:
            dados = json.loads(bruto.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as erro:
            anomalias.append("%s %s: tratado ilegivel: %s" % (ferramenta, cve, erro))
            continue
        encontradas = validar_tratado(cve, ferramenta, dados, gt[cve], norm)
        anomalias.extend(encontradas)
        if not encontradas:
            tratados[cve] = dados
    return tratados, presentes, anomalias, resumo.hexdigest()


def conferir_presenca(ferramenta, presentes, registro, gt, denominador):
    """Presenca de tratado x status do registro x denominador.

    A lista da o universo e o denominador; a ausencia do arquivo diz QUAIS
    CVEs do denominador ficaram sem tratado; o registro so e consultado para
    exigir que cada ausencia tenha causa registrada que a admita. Limite
    declarado: se o proprio registro trouxer SEM_ARQUIVO_ANALISAVEL indevido,
    a ausencia e aceita — nao ha, no repositorio, outra fonte da causa.
    """
    anomalias = []
    no_denominador = set(denominador)
    admitidos = SEM_TRATADO_ADMITIDO.get(ferramenta, set())
    for cve in sorted(gt):
        tem = cve in presentes
        status = registro[ferramenta][cve]
        if cve in FORA_POR_CODIGO_INDISPONIVEL:
            if tem:
                anomalias.append("%s %s: excluido por codigo indisponivel e TEM tratado — "
                                 "o denominador nao pode depender da ausencia do arquivo"
                                 % (ferramenta, cve))
            if status != STATUS_DA_BAIXA[cve]:
                anomalias.append("%s %s: excluido por codigo indisponivel, mas o registro "
                                 "diz %s, e o motivo exige %s"
                                 % (ferramenta, cve, status, STATUS_DA_BAIXA[cve]))
            continue
        if tem and status not in STATUS_COM_TRATADO:
            anomalias.append("%s %s: tratado presente com status %s no registro"
                             % (ferramenta, cve, status))
        elif not tem and status in STATUS_COM_TRATADO:
            anomalias.append("%s %s: status %s no registro e tratado AUSENTE"
                             % (ferramenta, cve, status))
        elif not tem and cve in no_denominador and status not in admitidos:
            anomalias.append("%s %s: CVE do denominador sem tratado, status %s — nao ha "
                             "regra que o admita como nao-deteccao" % (ferramenta, cve, status))
    return anomalias


# ---------------------------------------------------------------------------
# Apuracao
# ---------------------------------------------------------------------------
def casa_linha(achado, linhas):
    inicio = achado["line_start"]
    if inicio is None:
        return False
    fim = achado["line_end"] if achado["line_end"] is not None else inicio
    return any(inicio <= linha <= fim for linha in linhas)


def distancias(achado, linhas):
    """(|line_start - L| minima, distancia minima do intervalo a L)."""
    inicio = achado["line_start"]
    fim = achado["line_end"] if achado["line_end"] is not None else inicio
    return (min(abs(inicio - linha) for linha in linhas),
            min(max(0, inicio - linha, linha - fim) for linha in linhas))


def apurar_cve(gt, achados):
    """Um (CVE, ferramenta). `achados` None = nao ha tratado."""
    estrita_aplicavel = gt["gt_cwe_primary"] is not None

    def valor(nivel, satisfeito):
        if nivel in NIVEIS_ESTRITOS and not estrita_aplicavel:
            return None
        return satisfeito

    casados = {nivel: [] for nivel in NIVEIS_COM_CASADOS}
    if achados is None:
        return {"tratado_presente": False, "estrita_aplicavel": estrita_aplicavel,
                "niveis": {nivel: valor(nivel, False) for nivel in NIVEIS},
                "casados": casados, "achados_no_arquivo_gt": None,
                "distancia_min_linha": None, "distancia_min_intervalo": None,
                "line_end_nulo_no_arquivo_gt": None, "line_start_nulo_no_arquivo_gt": None}

    conjunto = set(gt["gt_cwes"])
    primario = gt["gt_cwe_primary"]
    linhas = gt["gt_file_lines"]
    dist_linha, dist_intervalo = [], []
    fim_nulo = inicio_nulo = 0
    for achado in achados:
        if achado["file_path"] != gt["gt_file_path"]:
            continue
        fid = achado["finding_id"]
        cwes = set(achado["cwe"])
        cwe_generosa = bool(cwes & conjunto)
        cwe_estrita = estrita_aplicavel and primario in cwes
        linha = casa_linha(achado, linhas)
        casados["nivel_1"].append(fid)
        if cwe_generosa:
            casados["nivel_2_generosa"].append(fid)
        if cwe_estrita:
            casados["nivel_2_estrita"].append(fid)
        if linha:
            casados["nivel_3"].append(fid)
        if linha and cwe_generosa:
            casados["nivel_4_generosa"].append(fid)
        if linha and cwe_estrita:
            casados["nivel_4_estrita"].append(fid)
        if achado["line_start"] is None:
            inicio_nulo += 1
            continue
        if achado["line_end"] is None:
            fim_nulo += 1
        d_linha, d_intervalo = distancias(achado, linhas)
        dist_linha.append(d_linha)
        dist_intervalo.append(d_intervalo)

    niveis = {"nivel_0": len(achados) > 0}
    for nivel in NIVEIS_COM_CASADOS:
        niveis[nivel] = valor(nivel, bool(casados[nivel]))
    for nivel in casados:
        casados[nivel].sort()
    return {"tratado_presente": True, "estrita_aplicavel": estrita_aplicavel,
            "niveis": niveis, "casados": casados,
            "achados_no_arquivo_gt": len(casados["nivel_1"]),
            "distancia_min_linha": min(dist_linha) if dist_linha else None,
            "distancia_min_intervalo": min(dist_intervalo) if dist_intervalo else None,
            "line_end_nulo_no_arquivo_gt": fim_nulo,
            "line_start_nulo_no_arquivo_gt": inicio_nulo}


def conferir_coerencia(rotulo, res):
    """Implicacoes que valem por construcao. Violacao e defeito do script."""
    n, c = res["niveis"], {k: set(v) for k, v in res["casados"].items()}
    erros = []

    def exigir(condicao, texto):
        if not condicao:
            erros.append("%s: %s" % (rotulo, texto))

    for nivel in NIVEIS_ESTRITOS:
        exigir((n[nivel] is None) == (not res["estrita_aplicavel"]),
               "%s nulo sse a estrita nao se aplica" % nivel)
    exigir(not n["nivel_1"] or n["nivel_0"], "nivel_1 sem nivel_0")
    exigir(c["nivel_2_generosa"] <= c["nivel_1"] and c["nivel_3"] <= c["nivel_1"],
           "casados de nivel 2 ou 3 fora do arquivo")
    exigir(c["nivel_2_estrita"] <= c["nivel_2_generosa"],
           "estrita sem generosa: primario fora do conjunto")
    # O MESMO achado: o nivel 4 e a intersecao POR ACHADO, nao por CVE.
    exigir(c["nivel_4_generosa"] == c["nivel_2_generosa"] & c["nivel_3"],
           "nivel_4_generosa difere da intersecao por achado de 2 e 3")
    exigir(c["nivel_4_estrita"] == c["nivel_2_estrita"] & c["nivel_3"],
           "nivel_4_estrita difere da intersecao por achado de 2 e 3")
    for nivel in NIVEIS_COM_CASADOS:
        if n[nivel] is not None:
            exigir(n[nivel] == bool(c[nivel]), "%s incoerente com seus casados" % nivel)
    if res["tratado_presente"]:
        exigir(n["nivel_1"] == (res["achados_no_arquivo_gt"] > 0),
               "nivel_1 incoerente com achados_no_arquivo_gt")
        exigir(n["nivel_3"] == (res["distancia_min_intervalo"] == 0),
               "nivel_3 incoerente com distancia_min_intervalo")
    else:
        exigir(not any(n[nivel] for nivel in NIVEIS), "sem tratado com nivel verdadeiro")
    return erros


def agregar(resultados):
    """Contagens sobre os CVEs do denominador. Nenhuma fracao."""
    agregados = {}
    for nivel in NIVEIS:
        valores = [r["niveis"][nivel] for r in resultados.values()]
        item = {"acertos": sum(v is True for v in valores),
                "nao_acertos": sum(v is False for v in valores)}
        if nivel in NIVEIS_ESTRITOS:
            item["nao_se_aplica"] = sum(v is None for v in valores)
        agregados[nivel] = item
    nivel_1 = [cve for cve, r in resultados.items() if r["niveis"]["nivel_1"]]
    com_3 = sum(1 for cve in nivel_1 if resultados[cve]["niveis"]["nivel_3"])
    um_e_tres = {"cves_nivel_1": len(nivel_1), "destes_nivel_3": com_3,
                 "destes_sem_nivel_3": len(nivel_1) - com_3}
    ressalvas = {
        "sem_tratado": sum(1 for r in resultados.values() if not r["tratado_presente"]),
        "line_end_nulo_no_arquivo_gt": sum(r["line_end_nulo_no_arquivo_gt"] or 0
                                           for r in resultados.values()),
        "line_start_nulo_no_arquivo_gt": sum(r["line_start_nulo_no_arquivo_gt"] or 0
                                             for r in resultados.values()),
    }
    return agregados, um_e_tres, ressalvas


# ---------------------------------------------------------------------------
# Autotestes: rodam a cada execucao, antes de qualquer numero
# ---------------------------------------------------------------------------
def autoteste_validacao(norm):
    """Controle positivo do validador: cada mutante tem de ser acusado."""
    cve = "CVE-2000-0001"
    gt = {"cve_id": cve, "repository": "https://example.invalid/r.git", "commit": "a" * 40,
          "gt_cwes": ["CWE-079", "CWE-116"], "gt_cwe_primary": "CWE-079",
          "gt_file_path": "a.js", "gt_file_path_original": None, "gt_file_lines": [10]}
    base = {"metadata": {chave: None for chave in CHAVES_METADATA},
            "findings": [{chave: None for chave in CHAVES_ACHADO}]}
    base["metadata"].update({
        "schema_version": SCHEMA_ESPERADO, "cve_id": cve, "tool": "codeql",
        "repository": gt["repository"], "commit": gt["commit"],
        "gt_cwes": list(gt["gt_cwes"]), "gt_cwe_primary": "CWE-079",
        "gt_file_path": "a.js", "gt_file_lines": [10], "gt_file_scanned": True})
    base["findings"][0].update({
        "finding_id": "codeql:%s:0001" % cve, "cwe": ["CWE-079"], "has_cwe": True,
        "file_path": "a.js", "line_start": 10, "line_end": 12,
        "severity_normalized": "high", "rule_id": "r", "message": "m"})

    def meta(chave, valor):
        return lambda d: d["metadata"].__setitem__(chave, valor)

    def achado(chave, valor):
        return lambda d: d["findings"][0].__setitem__(chave, valor)

    # (nome, trecho que a guarda PRETENDIDA emite, mutacao): acusar por outra
    # guarda qualquer nao prova que a pretendida funciona.
    mutantes = (
        ("topo com chave extra", "chaves do topo", lambda d: d.__setitem__("extra", 1)),
        ("schema_version divergente", "schema_version", meta("schema_version", "1.2")),
        ("metadata sem chave", "metadata sem",
         lambda d: d["metadata"].pop("tool_diagnostics")),
        ("metadata com chave inesperada", "chave inesperada", meta("inesperada", 1)),
        ("tool divergente", "difere do diretorio", meta("tool", "semgrep")),
        ("cve_id divergente", "difere do nome do arquivo", meta("cve_id", "CVE-2000-0002")),
        ("commit divergente", "PrePatchCommit", meta("commit", "b" * 40)),
        ("gt_file_path divergente", "gt_file_path 'b.js'", meta("gt_file_path", "b.js")),
        ("gt_file_path_original inesperado", "gt_file_path_original",
         meta("gt_file_path_original", "/a.js")),
        ("gt_cwes divergente", "difere da lista", meta("gt_cwes", ["CWE-079"])),
        ("gt_cwes fora da forma canonica", "gt_cwes fora da forma canonica",
         meta("gt_cwes", ["CWE-79", "CWE-116"])),
        ("gt_cwe_primary divergente", "gt_cwe_primary 'CWE-116'",
         meta("gt_cwe_primary", "CWE-116")),
        ("gt_file_lines com texto", "gt_file_lines fora da forma",
         meta("gt_file_lines", ["10"])),
        ("gt_file_scanned fora do tri-estado", "tri-estado", meta("gt_file_scanned", "true")),
        ("achado sem chave", "chaves divergentes",
         lambda d: d["findings"][0].pop("message")),
        ("finding_id de outro CVE", "fora da forma <tool>",
         achado("finding_id", "codeql:CVE-2000-0002:0001")),
        ("finding_id repetido", "repetido",
         lambda d: d["findings"].append(copy.deepcopy(d["findings"][0]))),
        ("cwe fora da forma canonica", "cwe fora da forma canonica", achado("cwe", ["CWE-79"])),
        ("has_cwe incoerente", "has_cwe", achado("has_cwe", False)),
        ("file_path absoluto", "file_path fora da forma canonica", achado("file_path", "/a.js")),
        ("file_path com ./", "file_path fora da forma canonica", achado("file_path", "./a.js")),
        ("line_start em texto", "line_start nao e inteiro", achado("line_start", "10")),
        ("line_end menor que line_start", "menor que line_start", achado("line_end", 5)),
        ("line_end sem line_start", "sem line_start", achado("line_start", None)),
        ("severity fora do vocabulario", "severity_normalized fora",
         achado("severity_normalized", "critical")),
    )
    limpo = validar_tratado(cve, "codeql", copy.deepcopy(base), gt, norm)
    casos = []
    for nome, trecho, mutacao in mutantes:
        dados = copy.deepcopy(base)
        mutacao(dados)
        encontradas = validar_tratado(cve, "codeql", dados, gt, norm)
        casos.append({"guarda": "validar_tratado", "mutante": nome,
                      "anomalias": len(encontradas),
                      "guarda_pretendida_disparou": any(trecho in a for a in encontradas)})
    return limpo, casos


def autoteste_presenca():
    """Controle positivo de conferir_presenca, com as regras do denominador."""
    baixa = "CVE-2016-1000229"
    gt = {baixa: {}, "CVE-2000-0001": {}, "CVE-2000-0002": {}}
    denominador = ["CVE-2000-0001", "CVE-2000-0002"]
    registro = {baixa: STATUS_DA_BAIXA[baixa], "CVE-2000-0001": "OK",
                "CVE-2000-0002": "SEM_ARQUIVO_ANALISAVEL"}
    presentes = {"CVE-2000-0001"}

    def rodar(ferramenta="snyk-code", mudar_registro=None, mudar_presentes=None):
        reg = dict(registro, **(mudar_registro or {}))
        pres = mudar_presentes(set(presentes)) if mudar_presentes else set(presentes)
        return conferir_presenca(ferramenta, pres, {ferramenta: reg}, gt, denominador)

    mutantes = (
        ("baixa com tratado", "TEM tratado", {}, lambda p: p | {baixa}, "snyk-code"),
        ("baixa com o status do outro motivo", "o motivo exige",
         {baixa: "ERRO_CHECKOUT"}, None, "snyk-code"),
        ("tratado presente com status sem tratado", "tratado presente com status",
         {}, lambda p: p | {"CVE-2000-0002"}, "snyk-code"),
        ("status OK e tratado ausente", "tratado AUSENTE", {},
         lambda p: p - {"CVE-2000-0001"}, "snyk-code"),
        ("ausencia sem causa admitida", "nao ha regra",
         {"CVE-2000-0002": "ERRO_ANALISE"}, None, "snyk-code"),
        ("SEM_ARQUIVO_ANALISAVEL fora do Snyk Code", "nao ha regra", {}, None, "codeql"),
    )
    limpo = rodar()
    casos = []
    for nome, trecho, mudar_registro, mudar_presentes, ferramenta in mutantes:
        encontradas = rodar(ferramenta, mudar_registro, mudar_presentes)
        casos.append({"guarda": "conferir_presenca", "mutante": nome,
                      "anomalias": len(encontradas),
                      "guarda_pretendida_disparou": any(trecho in a for a in encontradas)})
    return limpo, casos


# Controle positivo da apuracao: conjunto sintetico com resposta conhecida,
# pela MESMA apurar_cve/agregar do conjunto real. Todo contador tem valor
# esperado nao nulo aqui, de modo que um zero no conjunto real vem de um
# caminho de contagem demonstradamente capaz de contar.
def _k(i, caminho, inicio, fim, cwes):
    return {"finding_id": "controle:K:%04d" % i, "file_path": caminho,
            "line_start": inicio, "line_end": fim, "cwe": cwes}


_GT_K = {"gt_file_path": "a.js", "gt_file_lines": [10, 20],
         "gt_cwes": ["CWE-079", "CWE-116"], "gt_cwe_primary": "CWE-079"}
_GT_K_SEM_PRIMARIO = {"gt_file_path": "a.js", "gt_file_lines": [10],
                      "gt_cwes": ["CWE-250", "CWE-400"], "gt_cwe_primary": None}
CONTROLE = {
    "K01": (_GT_K, []),
    "K02": (_GT_K, [_k(1, "b.js", 10, 10, ["CWE-079"])]),
    "K03": (_GT_K, [_k(1, "a.js", 50, 50, ["CWE-020"])]),
    "K04": (_GT_K, [_k(1, "a.js", 10, None, ["CWE-020"])]),
    "K05": (_GT_K, [_k(1, "a.js", 5, 15, ["CWE-116"])]),
    "K06": (_GT_K, [_k(1, "a.js", 20, None, ["CWE-079"])]),
    "K07": (_GT_K_SEM_PRIMARIO, [_k(1, "a.js", 10, None, ["CWE-400"])]),
    "K08": (_GT_K, [_k(1, "a.js", 50, None, ["CWE-079"]), _k(2, "a.js", 10, 10, ["CWE-020"])]),
    "K09": (_GT_K, [_k(1, "a.js", None, None, ["CWE-079"])]),
    "K10": (_GT_K, None),
}
CONTROLE_ESPERADO = {
    "nivel_0": {"acertos": 8, "nao_acertos": 2},
    "nivel_1": {"acertos": 7, "nao_acertos": 3},
    "nivel_2_generosa": {"acertos": 5, "nao_acertos": 5},
    "nivel_2_estrita": {"acertos": 3, "nao_acertos": 6, "nao_se_aplica": 1},
    "nivel_3": {"acertos": 5, "nao_acertos": 5},
    "nivel_4_generosa": {"acertos": 3, "nao_acertos": 7},
    "nivel_4_estrita": {"acertos": 1, "nao_acertos": 8, "nao_se_aplica": 1},
    "nivel_1_e_nivel_3": {"cves_nivel_1": 7, "destes_nivel_3": 5, "destes_sem_nivel_3": 2},
    "ressalvas": {"sem_tratado": 1, "line_end_nulo_no_arquivo_gt": 4,
                  "line_start_nulo_no_arquivo_gt": 1},
}


def controle_positivo():
    resultados, erros = {}, []
    for rotulo, (gt, achados) in CONTROLE.items():
        resultados[rotulo] = apurar_cve(gt, achados)
        erros.extend(conferir_coerencia("controle " + rotulo, resultados[rotulo]))
    agregados, um_e_tres, ressalvas = agregar(resultados)
    obtido = dict(agregados)
    obtido["nivel_1_e_nivel_3"] = um_e_tres
    obtido["ressalvas"] = ressalvas
    for chave, esperado in CONTROLE_ESPERADO.items():
        if obtido[chave] != esperado:
            erros.append("controle %s: esperado %s, obtido %s" % (chave, esperado, obtido[chave]))
    return {"esperado": CONTROLE_ESPERADO, "obtido": obtido, "divergencias": erros}


# ---------------------------------------------------------------------------
# Saidas
# ---------------------------------------------------------------------------
def celula(valor):
    if valor is True:
        return "true"
    if valor is False:
        return "false"
    if valor is None:
        return ""
    return str(valor)


def linha_csv(cve, ferramenta, gt, registro, res, tratado):
    fora = FORA_DO_DENOMINADOR.get(cve)
    linha = {"cve": cve, "ferramenta": ferramenta,
             "no_denominador": celula(fora is None),
             "motivo_fora_denominador": fora or "",
             "status_campanha": registro[ferramenta][cve],
             "tratado_presente": celula(tratado is not None),
             "gt_cwe_primary": gt["gt_cwe_primary"] or "",
             "gt_cwes": "|".join(gt["gt_cwes"])}
    # Fora do denominador nenhuma coluna de apuracao e preenchida: vazio e
    # "nao apurado", e uma soma de coluna nao pode incluir esses pares.
    for coluna in (*NIVEIS, "estrita_aplicavel", "achados_no_arquivo_gt",
                   "distancia_min_linha", "distancia_min_intervalo", "gt_file_scanned"):
        linha[coluna] = ""
    if res is not None:
        for nivel in NIVEIS:
            linha[nivel] = celula(res["niveis"][nivel])
        linha["estrita_aplicavel"] = celula(res["estrita_aplicavel"])
        for coluna in ("achados_no_arquivo_gt", "distancia_min_linha",
                       "distancia_min_intervalo"):
            linha[coluna] = celula(res[coluna])
        if tratado is not None:
            varrido = tratado["metadata"]["gt_file_scanned"]
            linha["gt_file_scanned"] = "null" if varrido is None else celula(varrido)
    return [linha[coluna] for coluna in COLUNAS_CSV]


def texto_csv(linhas):
    motivos = []
    for linha in linhas:
        for campo in linha:
            if any(proibido in campo for proibido in (",", "\n", "\r")):
                motivos.append("campo com virgula ou quebra de linha: %r" % campo)
    if motivos:
        raise Parada("CSV violaria a invariante de nenhum campo com virgula", motivos)
    return "".join(",".join(linha) + "\n" for linha in [list(COLUNAS_CSV), *linhas])


def ler_csv(texto):
    """Leitura por split, como toda lista do projeto. Devolve (linhas, erros)."""
    erros = []
    if not texto.endswith("\n"):
        erros.append("CSV sem quebra de linha final")
    partes = texto.split("\n")
    if partes[-1] == "":
        partes = partes[:-1]
    if not partes or partes[0].split(",") != list(COLUNAS_CSV):
        erros.append("cabecalho do CSV divergente")
        return [], erros
    linhas = []
    for numero, bruta in enumerate(partes[1:], 2):
        campos = bruta.split(",")
        if len(campos) != len(COLUNAS_CSV):
            erros.append("linha %d do CSV com %d campos" % (numero, len(campos)))
            continue
        linhas.append(dict(zip(COLUNAS_CSV, campos)))
    return linhas, erros


def conferir_csv_json(linhas, relatorios):
    """CSV x JSON, por (CVE, ferramenta) e nos agregados. Devolve divergencias."""
    divergencias = []
    for ferramenta in FERRAMENTAS:
        rel = relatorios[ferramenta]
        dentro = [l for l in linhas if l["ferramenta"] == ferramenta
                  and l["no_denominador"] == "true"]
        if len(dentro) != rel["denominador"]["pares"]:
            divergencias.append("%s: %d linhas no denominador do CSV, %d no JSON"
                                % (ferramenta, len(dentro), rel["denominador"]["pares"]))
        if {l["cve"] for l in dentro} != set(rel["por_cve"]):
            divergencias.append("%s: conjuntos de CVE do denominador divergem" % ferramenta)
        for nivel in NIVEIS:
            contagem = {"acertos": sum(l[nivel] == "true" for l in dentro),
                        "nao_acertos": sum(l[nivel] == "false" for l in dentro)}
            if nivel in NIVEIS_ESTRITOS:
                contagem["nao_se_aplica"] = sum(l[nivel] == "" for l in dentro)
            if contagem != rel["agregados"][nivel]:
                divergencias.append("%s %s: CSV %s, JSON %s"
                                    % (ferramenta, nivel, contagem, rel["agregados"][nivel]))
        for linha in dentro:
            entrada = rel["por_cve"].get(linha["cve"])
            if entrada is None:
                continue
            for nivel in NIVEIS:
                if celula(entrada["niveis"][nivel]) != linha[nivel]:
                    divergencias.append("%s %s %s: CSV %r, JSON %r" % (
                        ferramenta, linha["cve"], nivel, linha[nivel], entrada["niveis"][nivel]))
            if celula(entrada["achados_no_arquivo_gt"]) != linha["achados_no_arquivo_gt"]:
                divergencias.append("%s %s: achados_no_arquivo_gt diverge"
                                    % (ferramenta, linha["cve"]))
    return divergencias


def controle_da_conferencia(linhas, relatorios):
    """A conferencia tem de acusar um CSV adulterado, senao seu zero nada diz."""
    adulteradas = copy.deepcopy(linhas)
    alvo = next(l for l in adulteradas if l["no_denominador"] == "true")
    alvo["nivel_0"] = "false" if alvo["nivel_0"] == "true" else "true"
    return len(conferir_csv_json(adulteradas, relatorios))


# ---------------------------------------------------------------------------
# Laco principal
# ---------------------------------------------------------------------------
def executar(args):
    lista = Path(args.lista) if args.lista else LISTA_PADRAO
    raiz_tratados = Path(args.treated_root) if args.treated_root else TREATED_ROOT_PADRAO
    caminho_registro = Path(args.registro) if args.registro else REGISTRO_PADRAO
    saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO

    norm = carregar_normalize()
    if norm.SCHEMA_VERSION != SCHEMA_ESPERADO:
        raise Parada("normalize.py grava schema diferente do que este script le",
                     ["normalize.SCHEMA_VERSION = %r, esperado %r"
                      % (norm.SCHEMA_VERSION, SCHEMA_ESPERADO)])

    # Autotestes antes de ler o conjunto: se falharem, nenhum numero sai.
    if not CRITERIOS.is_file():
        raise Parada("documento de criterios ausente", [str(CRITERIOS)])
    limpo, mutantes = autoteste_validacao(norm)
    limpo_presenca, mutantes_presenca = autoteste_presenca()
    mutantes = mutantes + mutantes_presenca
    controle = controle_positivo()
    falhas = ["registro integro acusado: %s" % a for a in limpo + limpo_presenca]
    falhas += ["mutante sem a guarda pretendida: %s (%s)" % (m["mutante"], m["guarda"])
               for m in mutantes if not m["guarda_pretendida_disparou"]]
    falhas += controle["divergencias"]
    if falhas:
        raise Parada("autoteste do proprio script falhou", falhas)

    gt, denominador, transformacoes = carregar_gt(norm, lista)
    registro = carregar_registro(caminho_registro, gt)

    tratados, presentes, resumos, anomalias = {}, {}, {}, []
    for ferramenta in FERRAMENTAS:
        (tratados[ferramenta], presentes[ferramenta], encontradas,
         resumos[ferramenta]) = carregar_tratados(raiz_tratados, ferramenta, gt, norm)
        anomalias.extend(encontradas)
    for ferramenta in FERRAMENTAS:
        anomalias.extend(conferir_presenca(ferramenta, presentes[ferramenta], registro,
                                           gt, denominador))
    if anomalias:
        raise Parada("validacao estrutural nao passou (%d anomalias)" % len(anomalias),
                     anomalias)

    # Apuracao: todos os (CVE, ferramenta) do denominador, uma passada.
    resultados = {ferramenta: {} for ferramenta in FERRAMENTAS}
    incoerencias = []
    for ferramenta in FERRAMENTAS:
        for cve in denominador:
            tratado = tratados[ferramenta].get(cve)
            res = apurar_cve(gt[cve], tratado["findings"] if tratado is not None else None)
            incoerencias.extend(conferir_coerencia("%s %s" % (ferramenta, cve), res))
            resultados[ferramenta][cve] = res
    if incoerencias:
        raise Parada("implicacoes entre niveis violadas: defeito do script", incoerencias)

    linhas = []
    for cve in sorted(gt):
        for ferramenta in FERRAMENTAS:
            linhas.append(linha_csv(cve, ferramenta, gt[cve], registro,
                                    resultados[ferramenta].get(cve),
                                    tratados[ferramenta].get(cve)))
    csv_texto = texto_csv(linhas)

    agora = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    relatorios = {}
    for ferramenta in FERRAMENTAS:
        res_f = resultados[ferramenta]
        agregados, um_e_tres, contagens = agregar(res_f)
        for nivel, item in agregados.items():
            if sum(item.values()) != len(denominador):
                raise Parada("agregado nao fecha no denominador",
                             ["%s %s: %s" % (ferramenta, nivel, item)])
        estados = {"true": 0, "false": 0, "null": 0, "sem_tratado": 0}
        for cve in denominador:
            tratado = tratados[ferramenta].get(cve)
            if tratado is None:
                estados["sem_tratado"] += 1
            else:
                estados[celula(tratado["metadata"]["gt_file_scanned"]) or "null"] += 1
        relatorios[ferramenta] = {
            "ferramenta": ferramenta,
            "versao_cruzamento": VERSAO_CRUZAMENTO,
            "schema_tratado": SCHEMA_ESPERADO,
            "gerado_em": agora,
            "criterios": {"documento": rotulo_caminho(CRITERIOS),
                          "sha256": sha256_arquivo(CRITERIOS)},
            "fontes": {
                "lista": {"caminho": rotulo_caminho(lista), "sha256": sha256_arquivo(lista)},
                "tabela_primario": {"caminho": rotulo_caminho(norm.TABELA_PRIMARIO),
                                    "sha256": sha256_arquivo(norm.TABELA_PRIMARIO)},
                "registro_campanha": {"caminho": rotulo_caminho(caminho_registro),
                                      "sha256": sha256_arquivo(caminho_registro)},
                "tratados": {"diretorio": rotulo_caminho(raiz_tratados / ferramenta / "treated"),
                             "arquivos": len(tratados[ferramenta]),
                             "sha256_conjunto": resumos[ferramenta]},
                "gt_file_path_normalizado": transformacoes,
            },
            "denominador": {
                "cves_na_lista": len(gt),
                "pares": len(denominador),
                # gt_cwes_no_tratado e a evidencia da conferencia pedida para o
                # CVE sem CWE: [] lido do tratado, nao presumido.
                "fora": [{"cve": cve, "motivo": motivo,
                          "status_campanha": registro[ferramenta][cve],
                          "tratado_presente": cve in tratados[ferramenta],
                          "gt_cwes_no_tratado": (tratados[ferramenta][cve]["metadata"]["gt_cwes"]
                                                 if cve in tratados[ferramenta] else None)}
                         for cve, motivo in sorted(FORA_DO_DENOMINADOR.items())],
            },
            "sem_tratado_no_denominador": [
                {"cve": cve, "status_campanha": registro[ferramenta][cve],
                 "tratamento": "nao-deteccao em todos os niveis"}
                for cve in denominador if not res_f[cve]["tratado_presente"]],
            "agregados": agregados,
            "nivel_1_e_nivel_3": um_e_tres,
            "estrita_nao_se_aplica": [
                {"cve": cve, "gt_cwes": gt[cve]["gt_cwes"],
                 "motivo": "gt_cwe_primary nulo: primario indefinido na tabela"}
                for cve in denominador if not res_f[cve]["estrita_aplicavel"]],
            "ressalvas": {
                "contagens": contagens,
                "gt_file_scanned_no_denominador": estados,
                "notas": NOTAS,
            },
            "por_cve": {
                cve: {"status_campanha": registro[ferramenta][cve],
                      "tratado_presente": res_f[cve]["tratado_presente"],
                      "gt_file_scanned": (tratados[ferramenta][cve]["metadata"]["gt_file_scanned"]
                                          if cve in tratados[ferramenta] else None),
                      "estrita_aplicavel": res_f[cve]["estrita_aplicavel"],
                      "niveis": res_f[cve]["niveis"],
                      "achados_casados": res_f[cve]["casados"],
                      "achados_no_arquivo_gt": res_f[cve]["achados_no_arquivo_gt"],
                      "distancia_min_linha": res_f[cve]["distancia_min_linha"],
                      "distancia_min_intervalo": res_f[cve]["distancia_min_intervalo"]}
                for cve in denominador},
            "validacao": {
                "anomalias": 0,
                "tratados_validados": len(tratados[ferramenta]),
                "autoteste": mutantes,
                "controle_positivo": controle,
            },
        }

    # Conferencia 1: CSV relido do DISCO x JSON em memoria. Vai para o JSON.
    saida.mkdir(parents=True, exist_ok=True)
    for residuo in saida.glob(PREFIXO_TEMP + "*"):
        residuo.unlink()
    temp_csv = saida / (PREFIXO_TEMP + NOME_CSV)
    temp_csv.write_text(csv_texto, encoding="utf-8")
    linhas_lidas, erros_leitura = ler_csv(temp_csv.read_text(encoding="utf-8"))
    divergencias = erros_leitura + conferir_csv_json(linhas_lidas, relatorios)
    acusadas = controle_da_conferencia(linhas_lidas, relatorios) if linhas_lidas else 0
    if divergencias or not acusadas:
        temp_csv.unlink()
        raise Parada("CSV e JSON inconsistentes", divergencias or
                     ["a conferencia nao acusou um CSV adulterado"])
    csv_sha256 = hashlib.sha256(csv_texto.encode("utf-8")).hexdigest()
    for ferramenta in FERRAMENTAS:
        # Liga cada JSON ao CSV da mesma execucao: a promocao final nao e
        # atomica entre arquivos, e CSV e JSON de execucoes distintas passam a
        # ser detectaveis.
        relatorios[ferramenta]["csv_da_mesma_execucao"] = {"arquivo": NOME_CSV,
                                                           "sha256": csv_sha256}
        relatorios[ferramenta]["conferencia_csv"] = {
            "linhas_conferidas": len(linhas_lidas),
            "divergencias": 0,
            "controle_csv_adulterado_divergencias_acusadas": acusadas,
        }

    # Conferencia 2: os dois relidos do disco, depois de escritos.
    temporarios = {ferramenta: saida / ("%scruzamento-%s.json" % (PREFIXO_TEMP, ferramenta))
                   for ferramenta in FERRAMENTAS}
    for ferramenta, caminho in temporarios.items():
        caminho.write_text(json.dumps(relatorios[ferramenta], indent=2, ensure_ascii=False)
                           + "\n", encoding="utf-8")
    relidos = {ferramenta: json.loads(caminho.read_text(encoding="utf-8"))
               for ferramenta, caminho in temporarios.items()}
    divergencias = conferir_csv_json(linhas_lidas, relidos)
    if divergencias:
        temp_csv.unlink()
        for caminho in temporarios.values():
            caminho.unlink()
        raise Parada("CSV e JSON relidos do disco inconsistentes", divergencias)

    os.replace(temp_csv, saida / NOME_CSV)
    for ferramenta, caminho in temporarios.items():
        os.replace(caminho, saida / ("cruzamento-%s.json" % ferramenta))

    imprimir_resumo(relatorios, denominador, len(gt), saida, len(linhas_lidas))
    return 0


def imprimir_resumo(relatorios, denominador, na_lista, saida, linhas_csv):
    primeiro = relatorios[FERRAMENTAS[0]]
    print("===== cruzamento SAST — %s (sha256 %s)"
          % (primeiro["criterios"]["documento"], primeiro["criterios"]["sha256"][:12]))
    print("denominador: %d pares, o mesmo nas tres ferramentas (%d CVEs na lista)"
          % (len(denominador), na_lista))
    for item in primeiro["denominador"]["fora"]:
        print("  fora: %s  %s" % (item["cve"], item["motivo"]))
    validacao = primeiro["validacao"]
    print("validacao: 0 anomalias em %d tratados (%s); autoteste %d de %d mutantes "
          "acusados pela guarda pretendida; controle positivo sem divergencia"
          % (sum(relatorios[f]["validacao"]["tratados_validados"] for f in FERRAMENTAS),
             ", ".join("%s %d" % (f, relatorios[f]["validacao"]["tratados_validados"])
                       for f in FERRAMENTAS),
             sum(1 for m in validacao["autoteste"] if m["guarda_pretendida_disparou"]),
             len(validacao["autoteste"])))
    print("\n%-20s" % "" + "".join("%26s" % f for f in FERRAMENTAS))
    print("%-20s" % "" + "".join("%26s" % "acertos/nao/nao-se-aplica" for _ in FERRAMENTAS))
    for nivel in NIVEIS:
        celulas = []
        for ferramenta in FERRAMENTAS:
            item = relatorios[ferramenta]["agregados"][nivel]
            texto = "%d/%d" % (item["acertos"], item["nao_acertos"])
            if "nao_se_aplica" in item:
                texto += "/%d" % item["nao_se_aplica"]
            celulas.append("%26s" % texto)
        print("%-20s" % nivel + "".join(celulas))
    print("%-20s" % "nivel 1 -> nivel 3" + "".join(
        "%26s" % ("%d de %d" % (relatorios[f]["nivel_1_e_nivel_3"]["destes_nivel_3"],
                                relatorios[f]["nivel_1_e_nivel_3"]["cves_nivel_1"]))
        for f in FERRAMENTAS))
    print("\nsem tratado no denominador (contam como nao-deteccao):")
    for ferramenta in FERRAMENTAS:
        itens = relatorios[ferramenta]["sem_tratado_no_denominador"]
        print("  %-10s %d%s" % (ferramenta, len(itens), (" — " + ", ".join(
            "%s (%s)" % (i["cve"], i["status_campanha"]) for i in itens)) if itens else ""))
    print("estrita nao se aplica: " + "; ".join(
        "%s %s" % (f, [i["cve"] for i in relatorios[f]["estrita_nao_se_aplica"]])
        for f in FERRAMENTAS))
    conferencia = primeiro["conferencia_csv"]
    print("conferencia CSV x JSON: %d linhas, 0 divergencias (CSV adulterado: %d acusadas)"
          % (conferencia["linhas_conferidas"],
             conferencia["controle_csv_adulterado_divergencias_acusadas"]))
    print("saidas em %s: %s, %s" % (rotulo_caminho(saida), NOME_CSV,
                                    ", ".join("cruzamento-%s.json" % f for f in FERRAMENTAS)))


def main(argv=None):
    analisador = argparse.ArgumentParser(
        description="Confronta os tratados com o ground truth: cinco niveis, duas "
                    "variantes de CWE, denominador de 220 pares.")
    analisador.add_argument("--lista", help="padrao: datasets/listas/cves-sast.txt")
    analisador.add_argument("--treated-root",
                            help="diretorio com <ferramenta>/treated/; padrao: results/")
    analisador.add_argument("--registro",
                            help="padrao: logs/campanha-2026-09-17/campanha-223.json")
    analisador.add_argument("--saida-dir", help="padrao: results/cruzamento/")
    args = analisador.parse_args(argv)
    try:
        return executar(args)
    except Parada as parada:
        print("\nPARADO: %s. Nenhum numero emitido, nenhuma saida escrita."
              % parada.titulo, file=sys.stderr)
        for motivo in parada.motivos[:LIMITE_MOTIVOS_IMPRESSOS]:
            print("  - %s" % motivo, file=sys.stderr)
        if len(parada.motivos) > LIMITE_MOTIVOS_IMPRESSOS:
            print("  ... e mais %d" % (len(parada.motivos) - LIMITE_MOTIVOS_IMPRESSOS),
                  file=sys.stderr)
        saida = Path(args.saida_dir) if args.saida_dir else SAIDA_PADRAO
        if (saida / NOME_CSV).exists():
            print("  saidas pre-existentes em %s NAO foram atualizadas" % saida,
                  file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
