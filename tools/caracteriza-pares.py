#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
caracteriza-pares.py — caracteriza, por CVE, o par (PrePatchCommit,
PostPatchCommit) do benchmark: se o commit corrigido existe, como se relaciona
com o vulneravel, e o que a correcao fez com o arquivo e as linhas do ground
truth. Caracterizacao do GROUND TRUTH, e nao analise.

    python3 tools/caracteriza-pares.py --workdir DIR [--cves CVE,CVE,...]
        [--metadata ARQ] [--lista ARQ] [--saida-dir DIR] [--expansoes ARQ]
        [--log-dir DIR] [--timeout-fetch S] [--timeout-clone S] [--git BIN]

O QUE NAO FAZ
  Nenhuma ferramenta SAST roda; nenhum tratado, matriz ou log de analise e
  lido. O PostPatchCommit e obtido — o que a regra critica do CLAUDE.md admite
  so para a campanha da versao corrigida, da qual esta etapa e preparacao —, e
  nenhum codigo e submetido a ferramenta alguma.

ENTRADAS
  datasets/cve-metadata.csv   o benchmark: CVE, Repository, PrePatchCommit,
                              PostPatchCommit, FilePath, FileLine (modulo csv)
  datasets/listas/cves-sast.txt
                              a lista, lida por normalize.carregar_lista(): e
                              dela que saem gt_file_path e gt_file_lines, pela
                              implementacao unica do normalizador (e ela que
                              trata o /index.js do CVE-2019-12041). O
                              metadata e CONFERIDO contra a lista, CVE a CVE:
                              repositorio, PrePatchCommit, caminho (pela
                              normalize.normalizar_gt_file_path) e linhas.
                              Divergencia e parada.
  cruza-deteccao.FORA_DO_DENOMINADOR
                              as tres exclusoes, importadas; os tres CVEs sao
                              caracterizados como os demais, e a exclusao vai
                              numa coluna.

OBTENCAO — por repositorio, nao por CVE
  git clone --filter=blob:none --no-checkout --no-single-branch, anonimo
  (GIT_CONFIG_GLOBAL/SYSTEM=/dev/null, credential.helper vazio, nenhuma GIT_*
  do hospedeiro herdada), limite de TIMEOUT_CLONE. O grafo de commits e as
  arvores vem inteiros; os blobs so sob demanda, no diff.
    - servidor que ignora o filtro so AVISA ("filtering not recognized by
      server") e manda tudo: o clone ja e completo, e isso e registrado.
      A config partialclonefilter e gravada mesmo assim, e NAO serve de sinal
      (medido no git 2.55).
    - clone parcial que falha sem estouro: uma tentativa de clone completo,
      --no-single-branch explicito. Estouro nao tem segunda tentativa: o
      completo seria mais lento.
  Commit ausente do clone (fora de todo ramo e tag: refs/pull, fork, ramo
  removido) e buscado por SHA, com o mesmo filtro, limite TIMEOUT_FETCH.
  "upload-pack: not our ref" => nao existe; estouro ou outra falha =>
  indeterminado.
  Toda inspecao local roda com GIT_NO_LAZY_FETCH=1: num clone parcial, objeto
  ausente dispararia busca na rede, e um teste de ancestralidade viraria uma
  busca por commit. So os diffs que precisam de conteudo buscam, e sob limite.
  Stderr nunca e descartado: todo stderr de git vai ao stderr deste script,
  prefixado pelo CVE, e a ultima linha relevante vai a mensagem do log.
  Clone em diretorio temporario sob --workdir (obrigatorio: /tmp pode ser
  tmpfs), removido ao fim de cada repositorio, inclusive em erro e em sinal.

OS DOIS PostPatchCommit MALFORMADOS (e qualquer valor que nao seja 40 hex)
  Expandidos pelo proprio repositorio so se as quatro condicoes valerem:
    c1 o prefixo casa exatamente um objeto (candidatos listados por
       cat-file --batch-all-objects, que aceita prefixo de qualquer tamanho);
    c2 o objeto e commit;
    c3 o PrePatchCommit e ancestral dele;
    c4 o arquivo do ground truth e alterado entre os dois.
  Os candidatos sao os commits, arvores e tags PRESENTES no clone, listados
  logo apos ele e antes de qualquer fetch — sem isso dependeriam da ordem dos
  CVEs do repositorio. Blobs nunca entram (no clone parcial nao estao la, e o
  criterio mudaria com o servidor), nem commit fora de ramo e tag, que prefixo
  nao permite buscar. Declarado, nao contornado.
  Resultado em datasets/postpatch-expansoes.csv. O cve-metadata.csv, as
  listas e o benchmark nao sao editados.

SAIDAS
  results/pares/pares.csv       uma linha por CVE
  results/pares/pares.txt       contagens e listas nominais
  datasets/postpatch-expansoes.csv
  logs/pares/caracterizacao-pares.csv
                                cve,repo,commit_pre,commit_post,status,
                                mensagem,duracao_segundos
  logs/pares/clones.csv         um por repositorio: modo, rc, duracao, tamanho
  Escrita atomica: nome temporario, o CSV relido com o modulo csv e conferido
  contra a estrutura em memoria, e so entao o nome definitivo. Gravar dentro
  do repositorio exige todas as entradas dentro dele. Com --cves (piloto),
  toda saida tem de ficar FORA do repositorio.
  A classificacao e deterministica; duracao_segundos e tamanho, nao — por isso
  ficam no pares.csv e nos logs, e nunca no pares.txt.

gt_linhas_em_trecho_alterado e gt_linhas_deslocadas sao DESCRICAO, nao
criterio. Como o ponto da falha e localizado na versao corrigida e decisao da
§8 do docs/criterios-cruzamento.md, nao desta etapa.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True

RAIZ = Path(__file__).resolve().parent.parent
NORMALIZE = RAIZ / "tools" / "normalize.py"
CRUZA = RAIZ / "tools" / "cruza-deteccao.py"

METADATA_PADRAO = RAIZ / "datasets" / "cve-metadata.csv"
LISTA_PADRAO = RAIZ / "datasets" / "listas" / "cves-sast.txt"
SAIDA_PADRAO = RAIZ / "results" / "pares"
EXPANSOES_PADRAO = RAIZ / "datasets" / "postpatch-expansoes.csv"
LOG_DIR_PADRAO = RAIZ / "logs" / "pares"

NOME_CSV = "pares.csv"
NOME_TXT = "pares.txt"
NOME_LOG = "caracterizacao-pares.csv"
NOME_CLONES = "clones.csv"
PREFIXO_TEMP = ".caracteriza-tmp-"

# Os mesmos da campanha (TIMEOUT_FETCH, TIMEOUT_CLONE dos run_*.sh).
TIMEOUT_FETCH_PADRAO = 300
TIMEOUT_CLONE_PADRAO = 900

COLUNAS_CSV = [
    "cve", "repositorio", "fora_do_denominador", "pre", "post", "post_malformado",
    "status", "pre_existe", "post_existe", "post_tipo", "relacao", "distancia",
    "pre_e_pai_de_post", "arquivos_alterados", "gt_arquivo", "gt_arquivo_no_pre",
    "gt_arquivo_no_post", "gt_arquivo_alterado", "gt_linhas",
    "gt_linhas_em_trecho_alterado", "gt_linhas_deslocadas", "duracao_segundos",
    # Acrescentadas em 28/09/2026, depois das existentes: as antigas nao mudam.
    "gt_tipo_ponto", "gt_ponto_post",
]
TIPOS_PONTO = {"inalterada", "trecho", "so_remocao"}
COLUNAS_EXPANSOES = [
    "cve", "valor_original", "valor_expandido", "c1_prefixo_unico", "c2_e_commit",
    "c3_pre_ancestral", "c4_arquivo_alterado", "candidatos", "motivo",
]
COLUNAS_LOG = ["cve", "repo", "commit_pre", "commit_post", "status", "mensagem",
               "duracao_segundos"]
COLUNAS_CLONES = ["repositorio", "modo", "rc", "estouro", "duracao_segundos",
                  "tamanho_bytes", "cves", "mensagem"]

# Vocabulario fechado de cada coluna categorica; a releitura o confere.
VOCAB = {
    "post_malformado": {"nao", "expandido", "nao_expandido"},
    "pre_existe": {"sim", "nao", "indeterminado"},
    "post_existe": {"sim", "nao", "indeterminado"},
    "relacao": {"", "post_descende_de_pre", "pre_descende_de_post", "iguais",
                "sem_relacao", "indeterminado"},
    "pre_e_pai_de_post": {"", "sim", "nao"},
    "gt_arquivo_no_pre": {"", "sim", "nao"},
    "gt_arquivo_alterado": {"", "sim", "nao"},
}
# status: OK, ou erro de obtencao do repositorio, com a causa na mensagem.
#   ERRO_CLONE_RECUSA   clone saiu com rc != 0 (parcial e completo)
#   ERRO_CLONE_ESTOURO  clone excedeu TIMEOUT_CLONE
#   ERRO_INSPECAO       a inspecao do par nao terminou: git local com erro
#                       nao previsto (defeito a investigar), ou estouro da
#                       busca de blobs de um diff sob TIMEOUT_FETCH (rede). A
#                       mensagem diz qual — "excedeu" e o segundo. Nenhum dos
#                       dois e caracteristica do par.
STATUS = {"OK", "ERRO_CLONE_RECUSA", "ERRO_CLONE_ESTOURO", "ERRO_INSPECAO"}

_RE_SHA = re.compile(r"[0-9a-f]{40}")
_RE_HEX = re.compile(r"[0-9a-f]+")
_RE_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_RE_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_RE_DIGITOS = re.compile(r"[0-9]+")


class Parada(Exception):
    def __init__(self, titulo, motivos=()):
        super().__init__(titulo)
        self.titulo = titulo
        self.motivos = list(motivos)


class Interrompido(Exception):
    """SIGTERM convertido em excecao, para que os finally limpem os clones."""


def rotulo(caminho):
    caminho = Path(caminho).resolve()
    try:
        return str(caminho.relative_to(RAIZ))
    except ValueError:
        return str(caminho)


def sha256_arquivo(caminho):
    return hashlib.sha256(Path(caminho).read_bytes()).hexdigest()


def importar(nome, caminho):
    spec = importlib.util.spec_from_file_location(nome, caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def dentro_do_repo(caminho):
    return Path(caminho).resolve().is_relative_to(RAIZ)


def limpar_mensagem(texto):
    """O log segue a forma dos da campanha: sem virgula nem quebra de linha."""
    return " ".join(str(texto).replace(",", ";").split())


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------
class Resultado:
    __slots__ = ("rc", "out", "err", "estouro", "segundos", "limite")

    def __init__(self, rc, out, err, estouro, segundos, limite):
        self.rc, self.out, self.err = rc, out, err
        self.estouro, self.segundos, self.limite = estouro, segundos, limite

    def ultima_linha_err(self):
        """A ultima linha fatal:/error:, que e a causa; sem ela, a ultima linha.

        A ultima linha crua nem sempre e a causa: no repositorio inexistente o
        git fecha com 'and the repository exists.', continuacao de outra.
        """
        linhas = [l.strip() for l in self.err.splitlines() if l.strip()
                  and not l.startswith("warning: This repository uses promisor remotes")]
        causas = [l for l in linhas if l.startswith(("fatal:", "error:"))]
        return (causas or linhas or [""])[-1]

    def causa(self, operacao):
        if self.estouro:
            return "%s excedeu %ds" % (operacao, self.limite)
        return "%s saiu com %s: %s" % (operacao, self.rc, self.ultima_linha_err() or "(stderr vazio)")


class Git:
    """Toda invocacao anonima, com stdin em /dev/null e stderr capturado.

    O stderr capturado e repassado ao stderr deste script — nunca descartado.
    """

    def __init__(self, binario, contexto="", home=None):
        self.binario = binario
        self.contexto = contexto
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        for nome in ("SSH_ASKPASS", "CURL_HOME", "XDG_CONFIG_HOME"):
            env.pop(nome, None)
        # HOME vazio: o libcurl le ~/.netrc por conta propria, e credencial
        # ali autenticaria o clone por fora do credential.helper (revisao, 5).
        if home is not None:
            env["HOME"] = str(home)
        env.update({
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        })
        self.env = env

    def __call__(self, args, cwd=None, timeout=None, lazy=False):
        comando = [self.binario, "-c", "credential.helper=", "-c", "gc.auto=0",
                   "-c", "maintenance.auto=false", "-c", "core.quotePath=false",
                   # Acima do limite o git pula a deteccao inexata de
                   # renomeacao e so avisa; o aviso e tratado em nomes().
                   "-c", "diff.renameLimit=100000", *args]
        env = dict(self.env)
        if not lazy:
            env["GIT_NO_LAZY_FETCH"] = "1"
        inicio = time.monotonic()
        # Grupo proprio: o estouro mata git e filhos (git-remote-https), e
        # nao so o processo de topo.
        try:
            processo = subprocess.Popen(comando, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)
        except OSError as erro:
            # E2BIG com pathspec enorme, binario ausente: falha do comando,
            # nunca da execucao inteira (revisao, 3b).
            print("[%s] git %s: nao iniciou: %s" % (self.contexto, args[0], erro), file=sys.stderr)
            return Resultado(None, "", "error: git nao iniciou: %s" % erro, False,
                             time.monotonic() - inicio, timeout)
        estouro = False
        try:
            out, err = processo.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            estouro = True
            self._matar(processo)
            out, err = processo.communicate()
        except BaseException:
            self._matar(processo)
            processo.communicate()
            raise
        # rc guardado antes de qualquer desvio.
        rc = processo.returncode
        segundos = time.monotonic() - inicio
        err_txt = err.decode("utf-8", "replace")
        if err_txt.strip():
            for linha in err_txt.splitlines():
                print("[%s] git %s: %s" % (self.contexto, args[0], linha), file=sys.stderr)
        return Resultado(rc, out.decode("utf-8", "replace"), err_txt, estouro,
                         segundos, timeout)

    @staticmethod
    def _matar(processo):
        try:
            os.killpg(processo.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


# ---------------------------------------------------------------------------
# Entradas
# ---------------------------------------------------------------------------
def carregar_entradas(metadata, lista, norm):
    """{cve: registro}. Metadata conferido contra a lista; divergencia e parada."""
    try:
        gt, _ = norm.carregar_lista(Path(lista))
    except SystemExit as erro:
        raise Parada("lista ilegivel", [str(erro.code)])
    motivos, registros = [], {}
    with open(metadata, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        exigidos = {"CVE", "Repository", "PrePatchCommit", "PostPatchCommit",
                    "FilePath", "FileLine"}
        if not exigidos <= set(leitor.fieldnames or []):
            raise Parada("metadata sem as colunas %s" % sorted(exigidos),
                         [repr(leitor.fieldnames)])
        for numero, r in enumerate(leitor, 2):
            cve = r["CVE"]
            if None in r or None in r.values():
                motivos.append("metadata linha %d: numero de campos diferente do cabecalho" % numero)
                continue
            if cve in registros:
                motivos.append("metadata: %s repetido" % cve)
                continue
            if cve not in gt:
                motivos.append("metadata: %s ausente da lista" % cve)
                continue
            g = gt[cve]
            caminho, _ = norm.normalizar_gt_file_path(r["FilePath"])
            linhas = [int(x) for x in _RE_DIGITOS.findall(r["FileLine"])]
            if r["Repository"] != g["repository"]:
                motivos.append("%s: repositorio %r no metadata, %r na lista"
                               % (cve, r["Repository"], g["repository"]))
            if r["PrePatchCommit"] != g["commit"]:
                motivos.append("%s: PrePatchCommit diverge entre metadata e lista" % cve)
            if caminho != g["gt_file_path"]:
                motivos.append("%s: caminho %r no metadata, %r na lista"
                               % (cve, caminho, g["gt_file_path"]))
            if linhas != g["gt_file_lines"]:
                motivos.append("%s: linhas %r no metadata, %r na lista"
                               % (cve, linhas, g["gt_file_lines"]))
            registros[cve] = {
                "cve": cve,
                "repositorio": g["repository"],
                "pre": g["commit"].lower(),
                "post_bruto": r["PostPatchCommit"].strip(),
                "gt_arquivo": g["gt_file_path"],
                "gt_linhas": list(g["gt_file_lines"]),
            }
    for cve in sorted(set(gt) - set(registros)):
        motivos.append("lista: %s ausente do metadata" % cve)
    if motivos:
        raise Parada("metadata e lista nao conferem", motivos)
    return registros


# ---------------------------------------------------------------------------
# Diff: trechos e linhas
# ---------------------------------------------------------------------------
def trechos_do_diff(texto):
    """[(a, b, c, d)] de cada cabecalho @@ -a,b +c,d @@ (contagem omitida = 1).

    Devolve (trechos, secoes, binario). Mais de uma secao 'diff --git' e
    ambiguidade que o chamador trata como indeterminado.
    """
    trechos, secoes, binario = [], 0, False
    # split("\n"), nao splitlines(): este quebraria tambem em \x0c e afins do
    # conteudo, e um fragmento iniciado por "@@ -" viraria cabecalho.
    for linha in texto.split("\n"):
        if linha.startswith("diff --git "):
            secoes += 1
        elif linha.startswith("Binary files ") or linha.startswith("GIT binary patch"):
            binario = True
        else:
            m = _RE_HUNK.match(linha)
            if m:
                a, b, c, d = m.groups()
                trechos.append((int(a), 1 if b is None else int(b),
                                int(c), 1 if d is None else int(d)))
    return trechos, secoes, binario


def pontos_no_post(linhas, trechos, n_post):
    """Para cada linha do lado pre: (tipo, ponto no post, bloco ou None).

    Descricao, nao criterio: a §8 do docs/criterios-cruzamento.md decide o uso.
    Bloco (a, b, c, d) do -U0: lado pre de a a a+b-1, lado post de c a c+d-1.
      inalterada  a linha nao cai em bloco com b >= 1; ponto = o numero dela
                  no post, pelo deslocamento de classificar_linhas
      trecho      a linha cai em bloco com b >= 1 e d >= 1; ponto = "c-(c+d-1)",
                  o lado post do bloco que a substituiu
      so_remocao  a linha cai em bloco com d = 0. No git, +c,0 quer dizer que as
                  linhas sairam DEPOIS da linha c do post; ponto = "del:N", com
                  N = c+1. Se c+1 passa do fim do post (n_post linhas), N = n_post
                  e a marca e "del:N:fim"; arquivo ausente do post da n_post = 0,
                  logo "del:0:fim".
    n_post e chamado so se houver so_remocao (e uma funcao: contar exige o blob).
    """
    saida = []
    for (alterada, deslocada), linha in zip(classificar_linhas(linhas, trechos), linhas):
        if not alterada:
            saida.append(("inalterada", str(deslocada), None))
            continue
        bloco = next(t for t in trechos if t[1] > 0 and t[0] <= linha <= t[0] + t[1] - 1)
        a, b, c, d = bloco
        if d >= 1:
            saida.append(("trecho", "%d-%d" % (c, c + d - 1), bloco))
            continue
        total = n_post()
        n = c + 1
        saida.append(("so_remocao", "del:%d" % n if n <= total else "del:%d:fim" % total, bloco))
    return saida


def classificar_linhas(linhas, trechos):
    """Para cada linha do lado pre: (alterada, numero no post ou None).

    Alterada = cai num trecho removido ou modificado (b > 0, a <= L <= a+b-1).
    Nao alterada: numero no post = L + soma de (d - b) dos trechos que terminam
    antes dela. Trecho de pura insercao (-a,0) insere DEPOIS da linha a, e
    desloca so as linhas > a.
    """
    saida = []
    for linha in linhas:
        alterada = any(b > 0 and a <= linha <= a + b - 1 for a, b, _, _ in trechos)
        if alterada:
            saida.append((True, None))
            continue
        delta = 0
        for a, b, _, d in trechos:
            fim = a + b - 1 if b > 0 else a
            if linha > fim:
                delta += d - b
        saida.append((False, linha + delta))
    return saida


# ---------------------------------------------------------------------------
# Inspecao de um CVE
# ---------------------------------------------------------------------------
class Inspetor:
    def __init__(self, git, clone, parcial, timeout_fetch):
        self.git, self.clone, self.parcial = git, clone, parcial
        self.timeout_fetch = timeout_fetch
        self.notas = []

    def g(self, args, timeout=None, lazy=False):
        return self.git(args, cwd=self.clone, timeout=timeout, lazy=lazy)

    def tipo(self, objeto):
        """Tipo do objeto, ou None se ausente. Erro do git nao vira ausencia.

        Medido no git 2.55: `cat-file -e` de objeto ausente sai 1 sem stderr;
        `cat-file -t` sai 128 com fatal:, indistinguivel de erro.
        """
        r = self.g(["cat-file", "-e", objeto])
        if r.rc == 1 and not r.err.strip():
            return None
        if r.rc != 0:
            raise ErroInspecao(r.causa("cat-file -e"))
        r = self.g(["cat-file", "-t", objeto])
        if r.rc != 0:
            raise ErroInspecao(r.causa("cat-file -t"))
        return r.out.strip()

    def existe(self, sha, nome):
        """sim / nao / indeterminado. Busca por SHA se ausente do clone."""
        if self.tipo(sha):
            return "sim"
        args = ["fetch", "-q", "--no-tags"]
        if self.parcial:
            args.append("--filter=blob:none")
        r = self.g(args + ["origin", sha], timeout=self.timeout_fetch, lazy=True)
        if r.rc == 0 and not r.estouro:
            if self.tipo(sha):
                self.notas.append("%s obtido por fetch" % nome)
                return "sim"
            self.notas.append("%s: fetch saiu 0 e o objeto segue ausente" % nome)
            return "indeterminado"
        if not r.estouro and "not our ref" in r.err:
            self.notas.append("%s inexistente: %s" % (nome, r.ultima_linha_err()))
            return "nao"
        self.notas.append("%s: %s" % (nome, r.causa("fetch por SHA")))
        return "indeterminado"

    def commit_de(self, objeto):
        r = self.g(["rev-parse", "--verify", "-q", objeto + "^{commit}"])
        return r.out.strip() if r.rc == 0 else None

    def ancestral(self, a, b):
        """True / False / None (indeterminado)."""
        r = self.g(["merge-base", "--is-ancestor", a, b])
        if r.rc == 0:
            return True
        if r.rc == 1:
            return False
        self.notas.append(r.causa("merge-base --is-ancestor"))
        return None

    def blob(self, commit, caminho):
        """Id do blob no caminho, ou None se o caminho nao existe no commit.

        Medido no git 2.55: caminho ausente sai 1 sem stderr. Qualquer outra
        falha e erro, e nao ausencia (revisao, 9).
        """
        r = self.g(["rev-parse", "--verify", "-q", "%s:%s" % (commit, caminho)])
        if r.rc == 0:
            return r.out.strip()
        if r.rc == 1 and not r.err.strip():
            return None
        raise ErroInspecao(r.causa("rev-parse %s:<caminho>" % commit[:12]))

    def nomes(self, pre, post, opcoes, caminhos=()):
        """[(status, caminho[, destino])] de diff --name-status -z."""
        pathspec = ["--", *caminhos] if caminhos else []
        r = self.g(["diff", "--name-status", "-z", "--no-ext-diff", *opcoes, pre, post, *pathspec],
                   timeout=self.timeout_fetch, lazy="-M" in opcoes)
        if r.rc != 0 or r.estouro:
            raise ErroInspecao(r.causa("diff --name-status"))
        if "-M" in opcoes and "renameLimit" in r.err:
            # O git pulou a deteccao inexata e so avisou: "removido" seria
            # classificacao errada sem sinal (revisao, 3a).
            raise ErroInspecao("deteccao de renomeacao pulada pelo git (renameLimit)")
        partes = r.out.split("\0")
        if partes and partes[-1] == "":
            partes.pop()
        entradas, i = [], 0
        while i < len(partes):
            status = partes[i]
            if status[:1] in ("R", "C"):
                entradas.append((status, partes[i + 1], partes[i + 2]))
                i += 3
            else:
                entradas.append((status, partes[i + 1]))
                i += 2
        return entradas

    def situacao_arquivo(self, pre, post, caminho):
        """(no_post, alterado, caminho_no_post). no_post: presente / removido /
        renomeado:<novo>. Levanta ErroInspecao."""
        blob_pre = self.blob(pre, caminho)
        blob_post = self.blob(post, caminho)
        if blob_post is not None:
            return "presente", blob_pre != blob_post, caminho
        # Ausente no post: renomeacao entre o caminho do gt e os adicionados.
        # O pathspec limita a deteccao (e a busca de blobs) a esses caminhos.
        adicionados = [e[1] for e in self.nomes(pre, post, ["--no-renames"])
                       if e[0].startswith("A")]
        if adicionados:
            for entrada in self.nomes(pre, post, ["-M"], [caminho, *adicionados]):
                if entrada[0].startswith("R") and entrada[1] == caminho:
                    novo = entrada[2]
                    return "renomeado:%s" % novo, blob_pre != self.blob(post, novo), novo
        return "removido", True, None

    def linhas_no_post(self, post, caminho_post):
        """Numero de linhas do arquivo no commit dado (post, ou pre na conferencia
        do fim do arquivo); 0 se o caminho e None (arquivo ausente)."""
        if caminho_post is None:
            return 0
        r = self.g(["cat-file", "-p", "%s:%s" % (post, caminho_post)],
                   timeout=self.timeout_fetch, lazy=True)
        if r.rc != 0 or r.estouro:
            raise ErroInspecao(r.causa("cat-file -p <post>:<caminho>"))
        return r.out.count("\n") + (1 if r.out and not r.out.endswith("\n") else 0)

    def linhas(self, pre, post, caminho, caminho_post, linhas):
        """([(alterada, deslocada)], trechos) ou None se indeterminado."""
        caminhos = [caminho] + ([caminho_post] if caminho_post not in (None, caminho) else [])
        r = self.g(["diff", "-U0", "--no-color", "--no-ext-diff", "-M", pre, post, "--", *caminhos],
                   timeout=self.timeout_fetch, lazy=True)
        if r.rc != 0 or r.estouro:
            raise ErroInspecao(r.causa("diff -U0"))
        trechos, secoes, binario = trechos_do_diff(r.out)
        if binario:
            self.notas.append("diff binario: linhas indeterminadas")
            return None
        if secoes != 1:
            self.notas.append("diff com %d secoes: linhas indeterminadas" % secoes)
            return None
        return classificar_linhas(linhas, trechos), trechos


class ErroInspecao(Exception):
    pass


def objetos_do_clone(git, clone):
    """[(sha, tipo)] dos commits, arvores e tags presentes no clone.

    Chamado logo apos o clone, antes de qualquer fetch por SHA ou busca de
    blob: sem isso os candidatos de um prefixo dependeriam da ordem em que os
    CVEs do mesmo repositorio foram inspecionados. Blobs nao entram: no clone
    parcial nao estao la, e no completo estariam — o criterio seria outro
    conforme o servidor aceitasse ou nao o filtro.
    """
    r = git(["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
            cwd=clone)
    if r.rc != 0:
        raise ErroInspecao(r.causa("cat-file --batch-all-objects"))
    saida = []
    for linha in r.out.splitlines():
        sha, _, tipo = linha.partition(" ")
        if tipo != "blob":
            saida.append((sha, tipo))
    return sorted(saida)


def expandir(inspetor, registro, pre_existe, objetos):
    """Linha de postpatch-expansoes.csv. As quatro condicoes, em ordem."""
    valor = registro["post_bruto"]
    linha = {"cve": registro["cve"], "valor_original": valor, "valor_expandido": "",
             "c1_prefixo_unico": "nao_avaliada", "c2_e_commit": "nao_avaliada",
             "c3_pre_ancestral": "nao_avaliada", "c4_arquivo_alterado": "nao_avaliada",
             "candidatos": "", "motivo": ""}
    prefixo = valor.lower()
    if not prefixo or not _RE_HEX.fullmatch(prefixo):
        linha["c1_prefixo_unico"] = "nao"
        linha["motivo"] = "c1: valor nao e hexadecimal"
        return linha
    candidatos = [(sha, tipo) for sha, tipo in objetos if sha.startswith(prefixo)]
    linha["candidatos"] = "|".join("%s:%s" % c for c in candidatos)
    if len(candidatos) != 1:
        linha["c1_prefixo_unico"] = "nao"
        linha["motivo"] = "c1: %d objetos no clone com o prefixo" % len(candidatos)
        return linha
    linha["c1_prefixo_unico"] = "sim"
    sha, tipo = candidatos[0]
    if tipo != "commit":
        linha["c2_e_commit"] = "nao"
        linha["motivo"] = "c2: objeto e %s" % tipo
        return linha
    linha["c2_e_commit"] = "sim"
    if pre_existe != "sim":
        linha["motivo"] = "c3: PrePatchCommit %s no clone" % pre_existe
        return linha
    anc = inspetor.ancestral(registro["pre"], sha)
    if anc is not True:
        linha["c3_pre_ancestral"] = "nao" if anc is False else "indeterminado"
        linha["motivo"] = "c3: PrePatchCommit %s ancestral" % (
            "nao e" if anc is False else "indeterminado se e")
        return linha
    linha["c3_pre_ancestral"] = "sim"
    try:
        # Sem o arquivo no pre, "alterado" sairia verdadeiro por comparacao
        # contra None, e c4 aprovaria correcao que nao tocou arquivo algum
        # (revisao, 2).
        if inspetor.blob(registro["pre"], registro["gt_arquivo"]) is None:
            linha["c4_arquivo_alterado"] = "nao"
            linha["motivo"] = "c4: arquivo do ground truth ausente do PrePatchCommit"
            return linha
        _, alterado, _ = inspetor.situacao_arquivo(registro["pre"], sha, registro["gt_arquivo"])
    except ErroInspecao as erro:
        linha["c4_arquivo_alterado"] = "indeterminado"
        linha["motivo"] = "c4: %s" % erro
        return linha
    if not alterado:
        linha["c4_arquivo_alterado"] = "nao"
        linha["motivo"] = "c4: arquivo do ground truth identico nos dois"
        return linha
    linha["c4_arquivo_alterado"] = "sim"
    linha["valor_expandido"] = sha
    linha["motivo"] = "expandido: as quatro condicoes valem"
    return linha


def linha_vazia(registro, fora):
    post = registro["post_bruto"]
    return {
        "cve": registro["cve"], "repositorio": registro["repositorio"],
        "fora_do_denominador": fora.get(registro["cve"], ""),
        "pre": registro["pre"], "post": post,
        "post_malformado": "nao" if _RE_SHA.fullmatch(post.lower()) else "nao_expandido",
        "status": "", "pre_existe": "indeterminado", "post_existe": "indeterminado",
        "post_tipo": "", "relacao": "", "distancia": "", "pre_e_pai_de_post": "",
        "arquivos_alterados": "", "gt_arquivo": registro["gt_arquivo"],
        "gt_arquivo_no_pre": "", "gt_arquivo_no_post": "", "gt_arquivo_alterado": "",
        "gt_linhas": "|".join(map(str, registro["gt_linhas"])),
        "gt_linhas_em_trecho_alterado": "", "gt_linhas_deslocadas": "",
        "duracao_segundos": "", "gt_tipo_ponto": "", "gt_ponto_post": "",
        "_blocos": [], "_alem_do_pre": None,
    }


def caracterizar(inspetor, registro, linha, objetos, estado):
    """Preenche `linha`. Devolve a linha de expansao, ou None.

    A expansao vai tambem para estado["expansao"] assim que existe: um
    ErroInspecao posterior nao pode perde-la (revisao, 1).
    """
    pre = registro["pre"]
    linha["pre_existe"] = inspetor.existe(pre, "pre")
    tipo_pre = inspetor.tipo(pre) if linha["pre_existe"] == "sim" else None
    if tipo_pre not in (None, "commit"):
        inspetor.notas.append("pre e objeto %s, nao commit" % tipo_pre)

    expansao = None
    post = registro["post_bruto"].lower()
    if not _RE_SHA.fullmatch(post):
        expansao = expandir(inspetor, registro, linha["pre_existe"], objetos)
        estado["expansao"] = expansao
        if not expansao["valor_expandido"]:
            linha["post_malformado"] = "nao_expandido"
            inspetor.notas.append("post malformado nao expandido: " + expansao["motivo"])
            return expansao
        linha["post_malformado"] = "expandido"
        post = expansao["valor_expandido"]
        linha["post"] = post
    linha["post_existe"] = inspetor.existe(post, "post")
    if linha["post_existe"] != "sim":
        return expansao
    linha["post_tipo"] = inspetor.tipo(post) or ""
    post_c = inspetor.commit_de(post)
    if post_c is None:
        inspetor.notas.append("post (%s) nao descasca para commit" % linha["post_tipo"])
        return expansao
    if post_c != post:
        inspetor.notas.append("post descascado para o commit %s" % post_c)
    if linha["pre_existe"] != "sim":
        return expansao
    pre_c = inspetor.commit_de(pre)
    if pre_c is None:
        return expansao

    if pre_c == post_c:
        linha["relacao"] = "iguais"
    else:
        anc = inspetor.ancestral(pre_c, post_c)
        if anc is True:
            linha["relacao"] = "post_descende_de_pre"
        elif anc is False:
            anc2 = inspetor.ancestral(post_c, pre_c)
            linha["relacao"] = {True: "pre_descende_de_post", False: "sem_relacao",
                                None: "indeterminado"}[anc2]
        else:
            linha["relacao"] = "indeterminado"
    if linha["relacao"] == "post_descende_de_pre":
        r = inspetor.g(["rev-list", "--count", "%s..%s" % (pre_c, post_c)])
        if r.rc != 0:
            raise ErroInspecao(r.causa("rev-list --count"))
        linha["distancia"] = r.out.strip()
    r = inspetor.g(["rev-parse", post_c + "^@"])
    if r.rc != 0:
        raise ErroInspecao(r.causa("rev-parse ^@"))
    linha["pre_e_pai_de_post"] = "sim" if pre_c in r.out.split() else "nao"

    linha["arquivos_alterados"] = str(len(inspetor.nomes(pre_c, post_c, ["--no-renames"])))

    caminho = registro["gt_arquivo"]
    if inspetor.blob(pre_c, caminho) is None:
        linha["gt_arquivo_no_pre"] = "nao"
        inspetor.notas.append("arquivo do ground truth ausente do pre")
        return expansao
    linha["gt_arquivo_no_pre"] = "sim"
    no_post, alterado, caminho_post = inspetor.situacao_arquivo(pre_c, post_c, caminho)
    linha["gt_arquivo_no_post"] = no_post
    linha["gt_arquivo_alterado"] = "sim" if alterado else "nao"

    linhas = registro["gt_linhas"]
    if not linhas:
        return expansao
    if not alterado:
        classes, trechos = [(False, l) for l in linhas], []
    else:
        resultado = inspetor.linhas(pre_c, post_c, caminho, caminho_post, linhas)
        if resultado is None:
            return expansao
        classes, trechos = resultado
    contagem = []

    def n_post():
        if not contagem:
            contagem.append(inspetor.linhas_no_post(post_c, caminho_post))
        return contagem[0]
    # Os pontos saem ANTES de qualquer coluna de linha ser preenchida: um
    # ErroInspecao aqui (cat-file do post) deixa as quatro vazias, e nao duas
    # preenchidas e duas vazias (revisao 2, risco 3).
    pontos = pontos_no_post(linhas, trechos, n_post)
    # Linha do gt alem do fim do arquivo no pre nao cai em bloco algum e sairia
    # "inalterada" sem sustentacao (revisao 2, risco 4). Registrada, sem mudar
    # classificacao: a falha na contagem vira nota, nunca ERRO_INSPECAO.
    try:
        n_pre = inspetor.linhas_no_post(pre_c, caminho)
        alem = [l for l in linhas if l > n_pre]
        if alem:
            inspetor.notas.append("linha do gt alem do fim do pre (%d linhas): %s"
                                  % (n_pre, "|".join(map(str, alem))))
        linha["_alem_do_pre"] = (alem, n_pre)
    except ErroInspecao as erro:
        inspetor.notas.append("tamanho do arquivo no pre indeterminado: %s" % erro)
        linha["_alem_do_pre"] = None
    linha["gt_linhas_em_trecho_alterado"] = "|".join("sim" if a else "nao" for a, _ in classes)
    # Posicional, alinhado a gt_linhas: vazio na posicao das alteradas.
    linha["gt_linhas_deslocadas"] = "|".join("" if a else str(n) for a, n in classes)
    linha["gt_tipo_ponto"] = "|".join(t for t, _, _ in pontos)
    linha["gt_ponto_post"] = "|".join(p for _, p, _ in pontos)
    # Fora do CSV (chave com _): blocos para o pares.txt (dez maiores trechos).
    linha["_blocos"] = [(l, t, bl) for l, (t, _, bl) in zip(linhas, pontos)]
    return expansao


# ---------------------------------------------------------------------------
# Um repositorio
# ---------------------------------------------------------------------------
def tamanho(diretorio):
    total = 0
    for raiz, _, arquivos in os.walk(diretorio):
        for nome in arquivos:
            try:
                total += os.lstat(os.path.join(raiz, nome)).st_size
            except OSError:
                pass
    return total


def clonar(git, url, destino, timeout_clone):
    """(ok, parcial, status, registro de clones.csv)."""
    base = ["clone", "--no-checkout", "--no-single-branch"]
    r = git(base[:1] + ["--filter=blob:none"] + base[1:] + [url, str(destino)],
            timeout=timeout_clone, lazy=True)
    reg = {"repositorio": url, "rc": "" if r.rc is None else str(r.rc),
           "estouro": "sim" if r.estouro else "nao",
           "duracao_segundos": "%.1f" % r.segundos, "tamanho_bytes": "", "mensagem": ""}
    if r.estouro:
        reg["modo"] = "parcial"
        reg["mensagem"] = r.causa("clone parcial")
        return False, True, "ERRO_CLONE_ESTOURO", reg
    if r.rc == 0:
        if "filtering not recognized by server" in r.err:
            reg["modo"] = "completo_filtro_ignorado"
            reg["mensagem"] = "servidor ignorou o filtro; o clone e completo"
            parcial = False
        else:
            reg["modo"] = "parcial"
            parcial = True
        reg["tamanho_bytes"] = str(tamanho(destino))
        return True, parcial, "OK", reg
    primeira = r.causa("clone parcial")
    shutil.rmtree(destino, ignore_errors=True)
    r2 = git(base + [url, str(destino)], timeout=timeout_clone, lazy=True)
    reg["modo"] = "completo_apos_falha_do_parcial"
    reg["rc"] = "%s;%s" % (reg["rc"], "" if r2.rc is None else r2.rc)
    reg["estouro"] = "nao;%s" % ("sim" if r2.estouro else "nao")
    reg["duracao_segundos"] = "%.1f" % (r.segundos + r2.segundos)
    if r2.rc == 0 and not r2.estouro:
        reg["mensagem"] = primeira + "; clone completo OK"
        reg["tamanho_bytes"] = str(tamanho(destino))
        return True, False, "OK", reg
    reg["mensagem"] = primeira + "; " + r2.causa("clone completo")
    return False, False, ("ERRO_CLONE_ESTOURO" if r2.estouro else "ERRO_CLONE_RECUSA"), reg


def expansao_nao_avaliada(registro, motivo):
    return {"cve": registro["cve"], "valor_original": registro["post_bruto"],
            "valor_expandido": "", "c1_prefixo_unico": "nao_avaliada",
            "c2_e_commit": "nao_avaliada", "c3_pre_ancestral": "nao_avaliada",
            "c4_arquivo_alterado": "nao_avaliada", "candidatos": "", "motivo": motivo}


def ocultador(*diretorios):
    """Troca diretorios da maquina do operador por marcadores: as linhas
    fatal: do git citam o destino do clone, e o log pode ser versionado
    (revisao, 6)."""
    pares = sorted(((str(Path(d)), m) for d, m in diretorios), key=lambda i: -len(i[0]))

    def ocultar(texto):
        for d, m in pares:
            texto = texto.replace(d, m)
        return texto
    return ocultar


def processar_repositorio(url, registros, fora, args, workdir):
    """[(linha, expansao, log)] e o registro de clones.csv."""
    saida = []
    with tempfile.TemporaryDirectory(prefix="par-", dir=workdir) as tmp:
        destino = Path(tmp) / "clone"
        ocultar = ocultador((destino, "<clone>"), (tmp, "<tmp-do-clone>"),
                            (Path(workdir).resolve(), "<workdir>"), (workdir, "<workdir>"))
        git = Git(args.git, contexto=url, home=args.home)
        ok, parcial, status_clone, reg = clonar(git, url, destino, args.timeout_clone)
        reg["mensagem"] = ocultar(reg["mensagem"])
        reg["cves"] = "|".join(r["cve"] for r in registros)
        print("[%s] clone %s: %s em %ss, %s bytes"
              % (url, reg["modo"], status_clone, reg["duracao_segundos"],
                 reg["tamanho_bytes"] or "-"), file=sys.stderr)
        objetos, erro_objetos = None, None
        if ok and any(not _RE_SHA.fullmatch(r["post_bruto"].lower()) for r in registros):
            try:
                objetos = objetos_do_clone(git, destino)
            except ErroInspecao as erro:
                erro_objetos = str(erro)
        for registro in registros:
            inicio = time.monotonic()
            linha = linha_vazia(registro, fora)
            expansao = None
            notas = []
            if not ok:
                linha["status"] = status_clone
                notas.append(reg["mensagem"])
                if linha["post_malformado"] == "nao_expandido":
                    expansao = expansao_nao_avaliada(
                        registro, "repositorio nao obtido: " + reg["mensagem"])
            else:
                inspetor = Inspetor(Git(args.git, contexto=registro["cve"], home=args.home),
                                    destino, parcial, args.timeout_fetch)
                estado = {}
                try:
                    if erro_objetos and not _RE_SHA.fullmatch(registro["post_bruto"].lower()):
                        raise ErroInspecao(erro_objetos)
                    expansao = caracterizar(inspetor, registro, linha, objetos, estado)
                    linha["status"] = "OK"
                except ErroInspecao as erro:
                    linha["status"] = "ERRO_INSPECAO"
                    inspetor.notas.append(str(erro))
                    # A expansao ja feita e mantida; a que nao chegou a ser
                    # feita vira linha nao avaliada — o malformado nunca some
                    # e a execucao nao para por um CVE (revisao, 1).
                    expansao = estado.get("expansao")
                    if expansao is None and linha["post_malformado"] != "nao":
                        expansao = expansao_nao_avaliada(
                            registro, "inspecao interrompida antes da expansao: %s" % erro)
                notas = ["clone %s" % reg["modo"]] + inspetor.notas
            if expansao is not None:
                expansao["motivo"] = ocultar(expansao["motivo"])
            duracao = int(round(time.monotonic() - inicio))
            linha["duracao_segundos"] = str(duracao)
            log = {"cve": registro["cve"], "repo": url, "commit_pre": registro["pre"],
                   "commit_post": linha["post"], "status": linha["status"],
                   "mensagem": limpar_mensagem(ocultar("; ".join(n for n in notas if n))),
                   "duracao_segundos": str(duracao)}
            print("[%s] %s %s" % (registro["cve"], linha["status"], log["mensagem"]),
                  file=sys.stderr)
            saida.append((linha, expansao, log))
    return saida, reg


# ---------------------------------------------------------------------------
# Escrita e releitura
# ---------------------------------------------------------------------------
def csv_texto(colunas, linhas):
    buf = io.StringIO()
    escritor = csv.DictWriter(buf, fieldnames=colunas, lineterminator="\n")
    escritor.writeheader()
    for linha in linhas:
        escritor.writerow({c: linha[c] for c in colunas})
    return buf.getvalue()


def conferir_csv(caminho, colunas, esperado, chave="cve", ignorar=()):
    """Rele com o modulo csv: cabecalho, campos, chave unica e cada celula
    igual a da memoria. `ignorar`: colunas nao comparadas (duracao)."""
    motivos = []
    with open(caminho, newline="", encoding="utf-8") as arquivo:
        leitor = csv.DictReader(arquivo)
        if leitor.fieldnames != colunas:
            return ["cabecalho %r, esperado %r" % (leitor.fieldnames, colunas)]
        lidos = {}
        for numero, r in enumerate(leitor, 2):
            if None in r or None in r.values():
                motivos.append("linha %d: numero de campos diferente do cabecalho" % numero)
                continue
            if r[chave] in lidos:
                motivos.append("linha %d: %s repetido" % (numero, r[chave]))
            lidos[r[chave]] = r
    memoria = {l[chave]: l for l in esperado}
    for k in sorted(set(memoria) - set(lidos)):
        motivos.append("%s na memoria e ausente do arquivo" % k)
    for k in sorted(set(lidos) - set(memoria)):
        motivos.append("%s no arquivo e ausente da memoria" % k)
    for k in sorted(set(lidos) & set(memoria)):
        for c in colunas:
            if c in ignorar:
                continue
            if lidos[k][c] != str(memoria[k][c]):
                motivos.append("%s coluna %s: arquivo %r, memoria %r"
                               % (k, c, lidos[k][c], memoria[k][c]))
    return motivos


# Colunas que toda referencia tem de trazer: as da primeira versao, 28/09/2026.
COLUNAS_ANTIGAS = [c for c in COLUNAS_CSV if c not in ("gt_tipo_ponto", "gt_ponto_post")]


def carregar_referencia(referencia, esperados):
    """(colunas, {cve: linha}) de um pares.csv anterior, validado ANTES dos
    clones: caminho errado ou referencia defeituosa nao pode custar a
    execucao inteira (revisao 2, risco 1). Levanta Parada.

    Exige as colunas antigas todas (uma referencia so com `cve` passaria
    vazia; risco 2), nenhuma coluna desconhecida, nenhum CVE repetido, e o
    conjunto de CVEs igual ao selecionado.
    """
    try:
        with open(referencia, newline="", encoding="utf-8") as arquivo:
            leitor = csv.DictReader(arquivo)
            cabecalho = list(leitor.fieldnames or [])
            registros = list(leitor)
    except (OSError, UnicodeDecodeError, csv.Error) as erro:
        raise Parada("referencia da regressao ilegivel", ["%s: %s" % (type(erro).__name__, erro)])
    motivos = []
    faltam = [c for c in COLUNAS_ANTIGAS if c not in cabecalho]
    if faltam:
        motivos.append("referencia sem as colunas antigas %s" % faltam)
    desconhecidas = [c for c in cabecalho if c not in COLUNAS_CSV]
    if desconhecidas:
        motivos.append("colunas da referencia ausentes da saida: %s" % desconhecidas)
    ref, repetidos = {}, []
    for r in registros:
        if None in r or None in r.values():
            motivos.append("referencia: linha com numero de campos diferente do cabecalho")
            continue
        if r.get("cve") in ref:
            repetidos.append(r.get("cve"))
        ref[r.get("cve")] = r
    if repetidos:
        motivos.append("CVE repetido na referencia: %s" % sorted(set(repetidos)))
    if set(ref) != set(esperados):
        motivos.append("CVEs diferem: so na referencia %s; so na selecao %s" % (
            sorted(set(ref) - set(esperados))[:10], sorted(set(esperados) - set(ref))[:10]))
    if motivos:
        raise Parada("referencia da regressao recusada, antes de qualquer clone", motivos)
    return [c for c in cabecalho if c != "duracao_segundos"], ref


def regressao(carregada, linhas):
    """Toda coluna da referencia, fora duracao_segundos, igual em todo CVE."""
    colunas, ref = carregada
    motivos = []
    atual = {l["cve"]: l for l in linhas}
    if set(ref) != set(atual):
        motivos.append("CVEs diferem: so na referencia %s; so na saida %s" % (
            sorted(set(ref) - set(atual)), sorted(set(atual) - set(ref))))
    for cve in sorted(set(ref) & set(atual)):
        for c in colunas:
            if ref[cve][c] != str(atual[cve][c]):
                motivos.append("%s %s: referencia %r, agora %r" % (cve, c, ref[cve][c], atual[cve][c]))
    return motivos


def conferir_vocabulario(linhas):
    motivos = []
    for l in linhas:
        for coluna, vocab in VOCAB.items():
            if l[coluna] not in vocab:
                motivos.append("%s: %s = %r fora do vocabulario" % (l["cve"], coluna, l[coluna]))
        if l["status"] not in STATUS:
            motivos.append("%s: status %r fora do vocabulario" % (l["cve"], l["status"]))
        if not _RE_CVE.fullmatch(l["cve"]):
            motivos.append("ID malformado %r" % l["cve"])
        no_post = l["gt_arquivo_no_post"]
        if no_post not in ("", "presente", "removido") and not no_post.startswith("renomeado:"):
            motivos.append("%s: gt_arquivo_no_post %r" % (l["cve"], no_post))
        n = len(l["gt_linhas"].split("|")) if l["gt_linhas"] else 0
        for coluna in ("gt_linhas_em_trecho_alterado", "gt_linhas_deslocadas",
                       "gt_tipo_ponto", "gt_ponto_post"):
            if l[coluna] and len(l[coluna].split("|")) != n:
                motivos.append("%s: %s nao alinhada a gt_linhas" % (l["cve"], coluna))
        # As quatro colunas de linha saem juntas ou nenhuma (revisao 2, risco 3).
        if bool(l["gt_linhas_em_trecho_alterado"]) != bool(l["gt_tipo_ponto"]):
            motivos.append("%s: colunas de linha preenchidas pela metade" % l["cve"])
        if l["gt_tipo_ponto"] and not set(l["gt_tipo_ponto"].split("|")) <= TIPOS_PONTO:
            motivos.append("%s: gt_tipo_ponto %r" % (l["cve"], l["gt_tipo_ponto"]))
        # O ponto das inalteradas e o numero deslocado: as duas colunas tem de
        # concordar posicao a posicao.
        if l["gt_tipo_ponto"]:
            for tipo, ponto, desl in zip(l["gt_tipo_ponto"].split("|"),
                                         l["gt_ponto_post"].split("|"),
                                         l["gt_linhas_deslocadas"].split("|")):
                if (tipo == "inalterada") != (desl != "") or (tipo == "inalterada" and ponto != desl):
                    motivos.append("%s: gt_ponto_post discorda de gt_linhas_deslocadas" % l["cve"])
                    break
        if l["distancia"] and l["relacao"] != "post_descende_de_pre":
            motivos.append("%s: distancia sem post_descende_de_pre" % l["cve"])
    return motivos


# Nomes definitivos ja promovidos nesta execucao: main() os cita quando algo
# interrompe a execucao depois do primeiro replace (revisao, 7).
PROMOVIDOS = []


def gravar(destinos):
    """destinos: [(caminho, texto, conferencia ou None)]. Temporario, releitura,
    e so entao o nome definitivo. Reprovado: nada definitivo e tocado.

    Os replace sao sequenciais, e o conjunto NAO e atomico. SIGINT e SIGTERM
    ficam bloqueados durante eles, de modo que so SIGKILL ou erro de E/S deixam
    promocao parcial — e o erro de E/S nomeia o que ja foi promovido. SIGKILL
    na escrita deixa .caracteriza-tmp-* ao lado do definitivo; a execucao
    seguinte o remove antes de escrever.
    """
    temporarios = []
    try:
        for caminho, texto, _ in destinos:
            caminho.parent.mkdir(parents=True, exist_ok=True)
            tmp = caminho.with_name(PREFIXO_TEMP + caminho.name)
            tmp.unlink(missing_ok=True)
            tmp.write_text(texto, encoding="utf-8")
            temporarios.append(tmp)
        for (caminho, _, conferencia), tmp in zip(destinos, temporarios):
            if conferencia:
                motivos = conferencia(tmp)
                if motivos:
                    raise Parada("releitura de %s reprovada" % caminho.name, motivos)
        bloqueados = {signal.SIGINT, signal.SIGTERM}
        anterior = signal.pthread_sigmask(signal.SIG_BLOCK, bloqueados)
        try:
            for (caminho, _, _), tmp in zip(destinos, temporarios):
                try:
                    tmp.replace(caminho)
                except OSError as erro:
                    raise Parada("promocao incompleta: ja promovidos %s" % (
                        [str(c) for c in PROMOVIDOS] or "nenhum"),
                        ["%s: %s: %s" % (caminho, type(erro).__name__, erro)])
                PROMOVIDOS.append(caminho)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, anterior)
    finally:
        for tmp in temporarios:
            try:
                tmp.unlink(missing_ok=True)
            except OSError as erro:
                print("AVISO: temporario nao removido: %s: %s" % (tmp, erro), file=sys.stderr)


# ---------------------------------------------------------------------------
# Relatorio legivel
# ---------------------------------------------------------------------------
def faixa_distancia(valor):
    n = int(valor)
    if n == 1:
        return "1"
    if n <= 5:
        return "2 a 5"
    if n <= 20:
        return "6 a 20"
    return "mais de 20"


def contar(linhas, coluna, transformar=lambda v: v):
    contagem = {}
    for l in linhas:
        chave = transformar(l[coluna])
        contagem[chave] = contagem.get(chave, 0) + 1
    return sorted(contagem.items(), key=lambda i: (-i[1], i[0]))


def gerar_txt(linhas, expansoes, fontes, sha_csv, subconjunto):
    out = []
    w = out.append
    w("Caracterizacao dos pares (PrePatchCommit, PostPatchCommit)")
    w("Propriedade do ground truth. Nenhuma ferramenta SAST rodou; nenhum")
    w("resultado de ferramenta foi lido.")
    if subconjunto:
        w("SUBCONJUNTO (--cves): %d CVEs, nao o conjunto." % len(linhas))
    w("")
    w("  csv desta execucao (sha256): %s" % sha_csv)
    w("")
    w("Fontes (sha256):")
    for nome, caminho, digest in fontes:
        w("  %-9s %s  %s" % (nome, caminho, digest))
    w("")

    def bloco(titulo, pares):
        w(titulo)
        for valor, n in pares:
            w("  %-40s %4d" % (valor if valor != "" else "(vazio)", n))
        w("")

    w("CVEs: %d" % len(linhas))
    w("")
    bloco("status:", contar(linhas, "status"))
    bloco("post_existe:", contar(linhas, "post_existe"))
    w("Malformados:")
    for e in expansoes:
        w("  %s  %r -> %s" % (e["cve"], e["valor_original"], e["valor_expandido"] or "(nao expandido)"))
        w("    c1 %s | c2 %s | c3 %s | c4 %s" % (e["c1_prefixo_unico"], e["c2_e_commit"],
                                                e["c3_pre_ancestral"], e["c4_arquivo_alterado"]))
        w("    candidatos: %s" % (e["candidatos"] or "nenhum"))
        w("    motivo: %s" % e["motivo"])
    w("")
    bloco("relacao:", contar(linhas, "relacao"))
    com_dist = [l for l in linhas if l["distancia"]]
    ordem = {"1": 0, "2 a 5": 1, "6 a 20": 2, "mais de 20": 3}
    faixas = contar(com_dist, "distancia", faixa_distancia)
    bloco("distancia (so post_descende_de_pre, %d):" % len(com_dist),
          sorted(faixas, key=lambda i: ordem[i[0]]))
    bloco("pre_e_pai_de_post:", contar(linhas, "pre_e_pai_de_post"))
    bloco("gt_arquivo_no_pre:", contar(linhas, "gt_arquivo_no_pre"))
    bloco("gt_arquivo_no_post:", contar(linhas, "gt_arquivo_no_post",
                                        lambda v: "renomeado" if v.startswith("renomeado:") else v))
    bloco("gt_arquivo_alterado:", contar(linhas, "gt_arquivo_alterado"))

    def grupo(l):
        v = l["gt_linhas_em_trecho_alterado"]
        if not v:
            return "(nao computado)"
        marcas = v.split("|")
        if all(m == "sim" for m in marcas):
            return "todas"
        if any(m == "sim" for m in marcas):
            return "algumas"
        return "nenhuma"
    contagem = {}
    for l in linhas:
        contagem[grupo(l)] = contagem.get(grupo(l), 0) + 1
    bloco("linhas do ground truth em trecho alterado, por CVE:",
          sorted(contagem.items(), key=lambda i: (-i[1], i[0])))

    # Pontos na versao corrigida (descricao para a §8, nao criterio).
    por_tipo, combinacoes, tamanhos, blocos, remocoes = {}, {}, [], {}, []
    for l in linhas:
        if not l["gt_tipo_ponto"]:
            continue
        tipos = l["gt_tipo_ponto"].split("|")
        for t in tipos:
            por_tipo[t] = por_tipo.get(t, 0) + 1
        chave = "+".join(sorted(set(tipos)))
        combinacoes[chave] = combinacoes.get(chave, 0) + 1
        # `blk`, e nao `bloco`: o nome e da funcao auxiliar deste gerar_txt.
        for (lin, tipo, blk), ponto in zip(l["_blocos"], l["gt_ponto_post"].split("|")):
            if tipo == "trecho":
                a, b, c, d = blk
                tamanhos.append(d)
                blocos[(l["cve"], blk)] = (l["cve"], l["gt_arquivo"], a, a + b - 1, c, c + d - 1, d)
            elif tipo == "so_remocao":
                remocoes.append((l["cve"], l["gt_arquivo"], lin, ponto, blk))
    bloco("linhas do ground truth por gt_tipo_ponto:",
          sorted(por_tipo.items(), key=lambda i: (-i[1], i[0])))
    bloco("CVEs por combinacao de gt_tipo_ponto:",
          sorted(combinacoes.items(), key=lambda i: (-i[1], i[0])))
    faixas_t = [("1", lambda n: n == 1), ("2 a 5", lambda n: 2 <= n <= 5),
                ("6 a 20", lambda n: 6 <= n <= 20), ("21 a 100", lambda n: 21 <= n <= 100),
                ("mais de 100", lambda n: n > 100)]
    bloco("tamanho do trecho (fim - inicio + 1), por linha do tipo trecho (%d):" % len(tamanhos),
          [(nome, sum(1 for n in tamanhos if f(n))) for nome, f in faixas_t])
    w("dez maiores trechos (um por bloco; empate por CVE):")
    maiores = sorted(blocos.values(), key=lambda b: (-b[6], b[0], b[2]))[:10]
    for cve, arquivo, pa, pb, pc, pd, n in maiores:
        w("  %-17s %4d linhas  pre %d-%d  post %d-%d  %s" % (cve, n, pa, pb, pc, pd, arquivo))
    w("")
    alem = [(l["cve"], l["_alem_do_pre"]) for l in linhas
            if l["_alem_do_pre"] and l["_alem_do_pre"][0]]
    sem_tamanho = [l["cve"] for l in linhas if l["gt_tipo_ponto"] and l["_alem_do_pre"] is None]
    w("linhas do ground truth alem do fim do arquivo no pre (%d CVEs; o tipo sai "
      "inalterada sem sustentacao):" % len(alem))
    for cve, (fora_do_fim, n_pre) in alem:
        w("  %-17s linhas %s  (pre com %d linhas)" % (cve, "|".join(map(str, fora_do_fim)), n_pre))
    w("  tamanho do pre indeterminado: %s" % (", ".join(sem_tamanho) or "nenhum"))
    w("")
    w("CVEs com alguma linha so_remocao (%d):" % len({r[0] for r in remocoes}))
    for cve, arquivo, lin, ponto, (a, b, c, d) in remocoes:
        w("  %-17s linha %d  %s  (bloco -%d,%d +%d,0)  %s" % (cve, lin, ponto, a, b, c, arquivo))
    w("")

    w("Listas nominais:")
    criterios = [
        ("post ausente ou indeterminado", lambda l: l["post_existe"] != "sim"),
        ("relacao diferente de post_descende_de_pre",
         lambda l: l["relacao"] != "post_descende_de_pre"),
        ("arquivo do ground truth nao alterado", lambda l: l["gt_arquivo_alterado"] == "nao"),
        ("arquivo do ground truth removido", lambda l: l["gt_arquivo_no_post"] == "removido"),
        ("arquivo do ground truth renomeado",
         lambda l: l["gt_arquivo_no_post"].startswith("renomeado:")),
        ("arquivo do ground truth fora do pre", lambda l: l["gt_arquivo_no_pre"] == "nao"),
        ("nenhuma linha em trecho alterado", lambda l: grupo(l) == "nenhuma"),
        ("linhas nao computadas", lambda l: grupo(l) == "(nao computado)"),
    ]
    for titulo, criterio in criterios:
        nomes = [l for l in linhas if criterio(l)]
        w("  %s (%d):" % (titulo, len(nomes)))
        for l in nomes:
            w("    %s  %s  relacao=%s post=%s arquivo=%s linhas=%s" % (
                l["cve"], l["status"], l["relacao"] or "-", l["post_existe"],
                l["gt_arquivo_no_post"] or "-", l["gt_linhas_em_trecho_alterado"] or "-"))
    w("")
    w("gt_linhas_em_trecho_alterado e gt_linhas_deslocadas sao descricao, nao")
    w("criterio: como o ponto da falha e localizado na versao corrigida e")
    w("decisao da §8 do docs/criterios-cruzamento.md.")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
def executar(args):
    for nome in ("timeout_fetch", "timeout_clone"):
        if getattr(args, nome) <= 0:
            raise Parada("--%s tem de ser inteiro positivo" % nome.replace("_", "-"))
    metadata = Path(args.metadata)
    lista = Path(args.lista)
    saida = Path(args.saida_dir)
    expansoes_arq = Path(args.expansoes)
    log_dir = Path(args.log_dir)
    workdir = Path(args.workdir)
    if not workdir.is_dir():
        raise Parada("--workdir inexistente", [str(workdir)])

    saidas = [saida, expansoes_arq, log_dir]
    if args.cves:
        dentro = [str(s) for s in saidas if dentro_do_repo(s)]
        if dentro:
            raise Parada("com --cves (subconjunto), toda saida tem de ficar fora do "
                         "repositorio", dentro)
    if any(dentro_do_repo(s) for s in saidas):
        entradas = [metadata, lista] + ([Path(args.regressao_contra)] if args.regressao_contra else [])
        fora = [str(e) for e in entradas if not dentro_do_repo(e)]
        if fora:
            raise Parada("saida dentro do repositorio exige entradas dentro dele", fora)
    if dentro_do_repo(workdir):
        raise Parada("--workdir dentro do repositorio: clones nao entram na arvore",
                     [str(workdir)])

    # GIT_NO_LAZY_FETCH e o que impede busca sem limite nas inspecoes locais;
    # git que nao o conheca o ignora em silencio (revisao, 4). O minimo e o do
    # recurso mais recente usado, conferido no historico do git.git em
    # 28/09/2026:
    #   GIT_NO_LAZY_FETCH   e6d5479e7 (27/02/2024, "git: extend --no-lazy-fetch
    #                       to work across subprocesses"); primeira tag que o
    #                       contem: v2.45.0. Ausente de e6d5479e7^ (git grep).
    #   GIT_CONFIG_GLOBAL   RelNotes/2.32.0
    #   clone --filter      548719fbd ("clone: partial clone"), v2.17.0
    #   cat-file --batch-all-objects   RelNotes/2.6.0
    #   merge-base --is-ancestor       RelNotes/1.8.0
    r = Git(args.git)(["version"])
    m = re.search(r"git version (\d+)\.(\d+)", r.out)
    if r.rc != 0 or not m or (int(m.group(1)), int(m.group(2))) < (2, 45):
        raise Parada("git 2.45 ou posterior exigido (GIT_NO_LAZY_FETCH, v2.45.0)",
                     [r.out.strip() or r.causa("git version")])
    args.git_versao = r.out.strip()
    print("caracteriza-pares: %s" % args.git_versao, file=sys.stderr)

    args.home = Path(tempfile.mkdtemp(prefix="home-vazio-", dir=workdir))
    try:
        return _executar(args, metadata, lista, saida, expansoes_arq, log_dir, workdir)
    finally:
        shutil.rmtree(args.home, ignore_errors=True)


def _executar(args, metadata, lista, saida, expansoes_arq, log_dir, workdir):
    cruza = importar("cruza_deteccao", CRUZA)
    norm = cruza.importar("normalize", NORMALIZE)
    fora = dict(cruza.FORA_DO_DENOMINADOR)
    registros = carregar_entradas(metadata, lista, norm)

    selecionados = sorted(registros)
    referencia = None
    if args.cves:
        pedidos = [c.strip() for c in args.cves.split(",") if c.strip()]
        desconhecidos = [c for c in pedidos if c not in registros]
        if desconhecidos:
            raise Parada("--cves com CVE fora do conjunto", desconhecidos)
        selecionados = sorted(set(pedidos))

    if args.regressao_contra:
        referencia = carregar_referencia(Path(args.regressao_contra), selecionados)

    por_repo = {}
    for cve in selecionados:
        por_repo.setdefault(registros[cve]["repositorio"], []).append(registros[cve])

    print("caracteriza-pares: %d CVEs, %d repositorios; git anonimo; limites "
          "TIMEOUT_FETCH=%d; TIMEOUT_CLONE=%d" % (len(selecionados), len(por_repo),
                                                  args.timeout_fetch, args.timeout_clone),
          file=sys.stderr)

    linhas, expansoes, logs, clones = [], [], [], []
    for url in sorted(por_repo):
        resultado, reg = processar_repositorio(url, por_repo[url], fora, args, workdir)
        clones.append(reg)
        for linha, expansao, log in resultado:
            linhas.append(linha)
            logs.append(log)
            if expansao is not None:
                expansoes.append(expansao)
    linhas.sort(key=lambda l: l["cve"])
    logs.sort(key=lambda l: l["cve"])
    expansoes.sort(key=lambda e: e["cve"])
    # Todo malformado tem linha de expansao, e so eles.
    malformados = sorted(l["cve"] for l in linhas if l["post_malformado"] != "nao")
    if malformados != [e["cve"] for e in expansoes]:
        raise Parada("expansoes nao correspondem aos malformados",
                     [str(malformados), str([e["cve"] for e in expansoes])])

    motivos = conferir_vocabulario(linhas)
    if motivos:
        raise Parada("vocabulario", motivos)
    if referencia is not None:
        motivos = regressao(referencia, linhas)
        if motivos:
            raise Parada("regressao contra %s: colunas antigas divergem" % args.regressao_contra,
                         motivos)
        print("regressao contra %s: todas as colunas da referencia identicas, fora "
              "duracao_segundos (%d CVEs)" % (args.regressao_contra, len(linhas)), file=sys.stderr)

    texto_csv = csv_texto(COLUNAS_CSV, linhas)
    fontes = [("metadata", rotulo(metadata), sha256_arquivo(metadata)),
              ("lista", rotulo(lista), sha256_arquivo(lista)),
              ("codigo", rotulo(__file__), sha256_arquivo(__file__)),
              ("codigo", rotulo(NORMALIZE), sha256_arquivo(NORMALIZE)),
              ("codigo", rotulo(CRUZA), sha256_arquivo(CRUZA))]
    fontes.append(("git", args.git_versao, ""))
    if args.regressao_contra:
        # Registra no artefato que a garantia foi conferida, e contra o que
        # (revisao 2, observacao 6). Caminho coberto pela guarda de entrada.
        fontes.append(("regressao", rotulo(args.regressao_contra) + " (colunas antigas "
                       "identicas)", sha256_arquivo(args.regressao_contra)))
    texto_txt = gerar_txt(linhas, expansoes, fontes,
                          hashlib.sha256(texto_csv.encode("utf-8")).hexdigest(),
                          bool(args.cves))
    gravar([
        (saida / NOME_CSV, texto_csv,
         lambda p: conferir_csv(p, COLUNAS_CSV, linhas)),
        (saida / NOME_TXT, texto_txt, None),
        (expansoes_arq, csv_texto(COLUNAS_EXPANSOES, expansoes),
         lambda p: conferir_csv(p, COLUNAS_EXPANSOES, expansoes)),
        (log_dir / NOME_LOG, csv_texto(COLUNAS_LOG, logs),
         lambda p: conferir_csv(p, COLUNAS_LOG, logs)),
        (log_dir / NOME_CLONES, csv_texto(COLUNAS_CLONES, clones),
         lambda p: conferir_csv(p, COLUNAS_CLONES, clones, chave="repositorio")),
    ])
    sys.stdout.write(texto_txt)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Caracterizacao dos pares pre/post do benchmark.")
    p.add_argument("--workdir", required=True,
                   help="onde os clones temporarios sao criados (fora do repositorio; "
                        "evite tmpfs)")
    p.add_argument("--cves", help="subconjunto, separado por virgula (piloto)")
    p.add_argument("--metadata", default=str(METADATA_PADRAO))
    p.add_argument("--lista", default=str(LISTA_PADRAO))
    p.add_argument("--saida-dir", default=str(SAIDA_PADRAO))
    p.add_argument("--expansoes", default=str(EXPANSOES_PADRAO))
    p.add_argument("--log-dir", default=str(LOG_DIR_PADRAO))
    p.add_argument("--timeout-fetch", type=int, default=TIMEOUT_FETCH_PADRAO)
    p.add_argument("--timeout-clone", type=int, default=TIMEOUT_CLONE_PADRAO)
    p.add_argument("--git", default="git", help="binario do git (fixtures)")
    p.add_argument("--regressao-contra",
                   help="pares.csv anterior: toda coluna dele, fora duracao_segundos, tem de "
                        "sair identica, ou nada e gravado")
    args = p.parse_args(argv)

    def ao_sinal(numero, _quadro):
        raise Interrompido("sinal %d" % numero)
    signal.signal(signal.SIGTERM, ao_sinal)
    try:
        return executar(args)
    except Parada as parada:
        print("\nPARADO: %s. %s" % (parada.titulo, _estado_saidas()), file=sys.stderr)
        for motivo in parada.motivos:
            print("  - %s" % motivo, file=sys.stderr)
        return 2
    except (Interrompido, KeyboardInterrupt) as erro:
        # Nao afirma limpeza sem conferir: sinal dentro do rmtree deixa resto.
        restos = sorted(str(q) for q in Path(args.workdir).glob("par-*")) + sorted(
            str(q) for q in Path(args.workdir).glob("home-vazio-*"))
        print("\nINTERROMPIDO (%s). %s %s" % (
            erro or "SIGINT", _estado_saidas(),
            "Resto no workdir: %s" % restos if restos else "Workdir sem resto de clone."),
            file=sys.stderr)
        return 130


def _estado_saidas():
    if PROMOVIDOS:
        return "Saidas JA PROMOVIDAS: %s." % [str(c) for c in PROMOVIDOS]
    return "Nenhuma saida escrita."


if __name__ == "__main__":
    sys.exit(main())
