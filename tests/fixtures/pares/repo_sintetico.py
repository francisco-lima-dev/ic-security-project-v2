# -*- coding: utf-8 -*-
"""
Repositorio git sintetico para tools/caracteriza-pares.py, criado pelo teste
num diretorio temporario, com o valor esperado de cada coluna por caso.

Datas e identidade fixas: os SHA saem os mesmos a cada construcao, mas nenhum
valor esperado depende de SHA literal — todos sao lidos do repositorio
construido, pelo nome do commit.

    construir(tmp) -> Fixture

Historia (main, linear):
  C0  f.js f1..f10, g.js g1..g5, h.js h1..h5, r.js r1..r20, k.js k1..k3
  C1  g.js: g1 -> G1
  C2  f.js: f5 -> F5
  C3  g.js: g2 -> G2
  C4  k.js: k1 -> K1
  C5  remove h.js
  C6  r.js -> lib/r2.js, com duas linhas inseridas no topo
  C7  k.js: k2 -> K2
  C8  f.js: tres linhas inseridas no topo, e f9 -> F9
Fora de main:
  outro        D1, filho de C0: f.js f1 -> F1
  enchimento   20 commits vazios a partir de C0 (garantem prefixo de 1
               caractere comum a dois commits, por casa dos pombos)
  refs/pull/1/head  P1, filho de C1, fora de todo ramo: f.js f7 -> F7
  tag anotada  v-tag -> C2
O servidor aceita filtro (uploadpack.allowFilter) e SHA alcancavel fora de
ramo (uploadpack.allowReachableSHA1InWant), como o GitHub. Uma copia nua sem
essas configuracoes faz o papel de servidor que ignora o filtro.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

CWES = "CWE-079"


def _env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@exemplo",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@exemplo",
        "GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00Z",
        "LC_ALL": "C",
    })
    return env


class Repo:
    def __init__(self, caminho):
        self.caminho = Path(caminho)
        self.env = _env()

    def git(self, *args):
        r = subprocess.run(["git", *args], cwd=self.caminho, env=self.env,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if r.returncode != 0:
            raise RuntimeError("git %s: %s" % (" ".join(args), r.stderr))
        return r.stdout.strip()

    def escrever(self, nome, linhas):
        caminho = self.caminho / nome
        caminho.parent.mkdir(parents=True, exist_ok=True)
        caminho.write_text("".join("%s\n" % l for l in linhas), encoding="utf-8")

    def commit(self, mensagem):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", mensagem)
        return self.git("rev-parse", "HEAD")


class Fixture:
    pass


def _prefixo_unico(objetos, sha):
    for n in range(1, 41):
        if sum(1 for o in objetos if o.startswith(sha[:n])) == 1:
            return sha[:n]
    raise RuntimeError("sem prefixo unico para %s" % sha)


def construir(tmp):
    tmp = Path(tmp)
    r = Repo(tmp / "origem")
    r.caminho.mkdir(parents=True)
    r.git("init", "-q", "-b", "main")
    f = ["f%d" % i for i in range(1, 11)]
    g = ["g%d" % i for i in range(1, 6)]
    k = ["k1", "k2", "k3"]
    r.escrever("f.js", f)
    r.escrever("g.js", g)
    r.escrever("h.js", ["h%d" % i for i in range(1, 6)])
    r.escrever("r.js", ["r%d" % i for i in range(1, 21)])
    r.escrever("k.js", k)
    c = {"C0": r.commit("C0")}
    g[0] = "G1"; r.escrever("g.js", g); c["C1"] = r.commit("C1")
    f[4] = "F5"; r.escrever("f.js", f); c["C2"] = r.commit("C2")
    g[1] = "G2"; r.escrever("g.js", g); c["C3"] = r.commit("C3")
    k[0] = "K1"; r.escrever("k.js", k); c["C4"] = r.commit("C4")
    (r.caminho / "h.js").unlink(); c["C5"] = r.commit("C5")
    (r.caminho / "r.js").unlink()
    r.escrever("lib/r2.js", ["n1", "n2"] + ["r%d" % i for i in range(1, 21)])
    c["C6"] = r.commit("C6")
    k[1] = "K2"; r.escrever("k.js", k); c["C7"] = r.commit("C7")
    f8 = ["a", "b", "c"] + f[:8] + ["F9"] + f[9:]
    r.escrever("f.js", f8); c["C8"] = r.commit("C8")

    r.git("checkout", "-q", "-b", "outro", c["C0"])
    r.escrever("f.js", ["F1"] + ["f%d" % i for i in range(2, 11)])
    c["D1"] = r.commit("D1")
    r.git("checkout", "-q", "-b", "enchimento", c["C0"])
    for i in range(20):
        r.commit("E%d" % i)
    r.git("checkout", "-q", "--detach", c["C1"])
    fp = list(["f%d" % i for i in range(1, 11)]); fp[6] = "F7"
    r.escrever("f.js", fp)
    c["P1"] = r.commit("P1")
    r.git("update-ref", "refs/pull/1/head", c["P1"])
    r.git("checkout", "-q", "main")
    r.git("tag", "-a", "v-tag", "-m", "tag anotada", c["C2"])
    c["T"] = r.git("rev-parse", "v-tag")
    r.git("config", "uploadpack.allowFilter", "true")
    r.git("config", "uploadpack.allowReachableSHA1InWant", "true")

    # Copia nua sem allowFilter: servidor que ignora o filtro.
    sem_filtro = tmp / "sem-filtro.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(r.caminho), str(sem_filtro)],
                   env=r.env, check=True, capture_output=True, stdin=subprocess.DEVNULL)

    # Objetos nao-blob da origem: superconjunto dos do clone (P1 incluso).
    todos = [l.split() for l in r.git("cat-file", "--batch-all-objects",
                                      "--batch-check=%(objectname) %(objecttype)").splitlines()]
    nao_blob = [sha for sha, tipo in todos if tipo != "blob"]
    commits_clone = [c[n] for n in ("C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "D1")]
    commits_clone += r.git("rev-list", "enchimento", "^main").split()
    ambiguo = next(ch for ch in "0123456789abcdef"
                   if sum(1 for s in commits_clone if s.startswith(ch)) >= 2)

    url = "file://" + str(r.caminho)
    url_sem_filtro = "file://" + str(sem_filtro)
    url_inexistente = "file://" + str(tmp / "nao-existe")
    inexistente_post = "d" * 40
    inexistente_pre = "e" * 40

    fx = Fixture()
    fx.commits, fx.url, fx.url_sem_filtro, fx.url_inexistente = c, url, url_sem_filtro, url_inexistente
    fx.ambiguo = ambiguo

    # (cve, url, pre, post_bruto, arquivo, linhas, esperado)
    V = "post_descende_de_pre"
    casos = []

    # Parametros posicionais-apenas: `post` e `pre` tambem sao colunas esperadas.
    def caso(cve, descricao, url_, pre_, post_, arquivo, linhas, /, **esperado):
        casos.append((cve, descricao, url_, pre_, post_, arquivo, linhas, esperado))

    base = dict(status="OK", pre_existe="sim", post_existe="sim", post_tipo="commit",
                post_malformado="nao", fora_do_denominador="", gt_arquivo_no_pre="sim")
    caso("CVE-2099-0001", "post filho direto de pre, alterando a linha do gt",
         url, c["C1"], c["C2"], "f.js", [5],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="1",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    caso("CVE-2099-0002", "post a tres commits de pre",
         url, c["C1"], c["C4"], "f.js", [5],
         **base, relacao=V, distancia="3", pre_e_pai_de_post="nao", arquivos_alterados="3",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    caso("CVE-2099-0003", "post sem relacao com pre (outro ramo)",
         url, c["C1"], c["D1"], "f.js", [1],
         **base, relacao="sem_relacao", distancia="", pre_e_pai_de_post="nao",
         arquivos_alterados="2", gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    # Id real de exclusao: exercita a coluna fora_do_denominador.
    caso("CVE-2018-1000096", "post igual a pre",
         url, c["C1"], c["C1"], "f.js", [5],
         **dict(base, fora_do_denominador="sem_cwe_no_ground_truth"),
         relacao="iguais", distancia="", pre_e_pai_de_post="nao", arquivos_alterados="0",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="nao",
         gt_linhas_em_trecho_alterado="nao", gt_linhas_deslocadas="5")
    caso("CVE-2099-0005", "arquivo removido no post",
         url, c["C4"], c["C5"], "h.js", [2],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="1",
         gt_arquivo_no_post="removido", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    caso("CVE-2099-0006", "arquivo renomeado, linha do gt deslocada por insercao no topo",
         url, c["C5"], c["C6"], "r.js", [10],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="2",
         gt_arquivo_no_post="renomeado:lib/r2.js", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="nao", gt_linhas_deslocadas="12")
    caso("CVE-2099-0007", "correcao que nao toca o arquivo do gt",
         url, c["C6"], c["C7"], "f.js", [3],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="1",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="nao",
         gt_linhas_em_trecho_alterado="nao", gt_linhas_deslocadas="3")
    caso("CVE-2099-0008", "linha fora de trecho alterado, deslocada +3; outra alterada",
         url, c["C7"], c["C8"], "f.js", [2, 9],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="1",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="nao|sim", gt_linhas_deslocadas="5|")
    caso("CVE-2099-0009", "objeto de tag anotada no lugar do post",
         url, c["C1"], c["T"], "f.js", [5],
         **dict(base, post_tipo="tag"), relacao=V, distancia="1", pre_e_pai_de_post="sim",
         arquivos_alterados="1", gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    nada = dict(post_existe="indeterminado", post_tipo="", relacao="", distancia="",
                pre_e_pai_de_post="", arquivos_alterados="", gt_arquivo_no_pre="",
                gt_arquivo_no_post="", gt_arquivo_alterado="",
                gt_linhas_em_trecho_alterado="", gt_linhas_deslocadas="")
    caso("CVE-2099-0010", "prefixo ambiguo (1 caractere, dois commits)",
         url, c["C1"], ambiguo, "f.js", [5],
         **dict(base, **nada, post_malformado="nao_expandido"))
    caso("CVE-2099-0011", "prefixo unico de commit que nao descende de pre",
         url, c["C1"], _prefixo_unico(nao_blob, c["D1"]), "f.js", [1],
         **dict(base, **nada, post_malformado="nao_expandido"))
    caso("CVE-2099-0012", "prefixo unico que expande (quatro condicoes)",
         url, c["C1"], _prefixo_unico(nao_blob, c["C2"]), "f.js", [5],
         **dict(base, post_malformado="expandido", post=c["C2"]), relacao=V, distancia="1",
         pre_e_pai_de_post="sim", arquivos_alterados="1", gt_arquivo_no_post="presente",
         gt_arquivo_alterado="sim", gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    caso("CVE-2099-0013", "prefixo de descendente que nao altera o arquivo do gt",
         url, c["C6"], _prefixo_unico(nao_blob, c["C7"]), "f.js", [3],
         **dict(base, **nada, post_malformado="nao_expandido"))
    caso("CVE-2099-0014", "prefixo de objeto de tag",
         url, c["C1"], _prefixo_unico(nao_blob, c["T"]), "f.js", [5],
         **dict(base, **nada, post_malformado="nao_expandido"))
    caso("CVE-2099-0015", "pre descende de post",
         url, c["C4"], c["C2"], "f.js", [5],
         **base, relacao="pre_descende_de_post", distancia="", pre_e_pai_de_post="nao",
         arquivos_alterados="2", gt_arquivo_no_post="presente", gt_arquivo_alterado="nao",
         gt_linhas_em_trecho_alterado="nao", gt_linhas_deslocadas="5")
    caso("CVE-2099-0016", "post inexistente (not our ref)",
         url, c["C1"], inexistente_post, "f.js", [5],
         **dict(base, **dict(nada, post_existe="nao")))
    caso("CVE-2099-0017", "pre inexistente",
         url, inexistente_pre, c["C2"], "f.js", [5],
         **dict(base, **dict(nada, post_existe="sim", post_tipo="commit"), pre_existe="nao"))
    caso("CVE-2099-0018", "post so em refs/pull, obtido por fetch",
         url, c["C1"], c["P1"], "f.js", [7],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="1",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    caso("CVE-2099-0019", "arquivo do gt ausente do pre",
         url, c["C1"], c["C2"], "nao/existe.js", [5],
         **dict(base, gt_arquivo_no_pre="nao"), relacao=V, distancia="1",
         pre_e_pai_de_post="sim", arquivos_alterados="1", gt_arquivo_no_post="",
         gt_arquivo_alterado="", gt_linhas_em_trecho_alterado="", gt_linhas_deslocadas="")
    caso("CVE-2099-0020", "servidor que ignora o filtro: mesmo resultado do caso 1",
         url_sem_filtro, c["C1"], c["C2"], "f.js", [5],
         **base, relacao=V, distancia="1", pre_e_pai_de_post="sim", arquivos_alterados="1",
         gt_arquivo_no_post="presente", gt_arquivo_alterado="sim",
         gt_linhas_em_trecho_alterado="sim", gt_linhas_deslocadas="")
    falha = dict(nada, pre_existe="indeterminado", post_existe="indeterminado",
                 status="ERRO_CLONE_RECUSA", fora_do_denominador="", post_malformado="nao")
    caso("CVE-2099-0021", "repositorio inexistente", url_inexistente, c["C1"], c["C2"],
         "f.js", [5], **falha)
    caso("CVE-2099-0022", "repositorio inexistente, post malformado", url_inexistente,
         c["C1"], "abc1234", "f.js", [5], **dict(falha, post_malformado="nao_expandido"))

    caso("CVE-2099-0023", "prefixo que passaria c1-c3, com o arquivo do gt ausente do pre",
         url, c["C1"], _prefixo_unico(nao_blob, c["C2"]), "nao/existe.js", [5],
         **dict(base, **nada, post_malformado="nao_expandido"))
    # Ordenado DEPOIS do 0018, que busca P1 por SHA: se os candidatos fossem
    # listados por CVE, e nao logo apos o clone, P1 casaria e c1 sairia sim.
    caso("CVE-2099-0024", "prefixo de commit so obtido por fetch de outro CVE",
         url, c["C1"], _prefixo_unico(nao_blob, c["P1"]), "f.js", [7],
         **dict(base, **nada, post_malformado="nao_expandido"))

    fx.casos = casos
    # Expansoes esperadas: (valor_expandido, c1, c2, c3, c4)
    fx.expansoes = {
        "CVE-2099-0010": ("", "nao", "nao_avaliada", "nao_avaliada", "nao_avaliada"),
        "CVE-2099-0011": ("", "sim", "sim", "nao", "nao_avaliada"),
        "CVE-2099-0012": (c["C2"], "sim", "sim", "sim", "sim"),
        "CVE-2099-0013": ("", "sim", "sim", "sim", "nao"),
        "CVE-2099-0014": ("", "sim", "nao", "nao_avaliada", "nao_avaliada"),
        "CVE-2099-0022": ("", "nao_avaliada", "nao_avaliada", "nao_avaliada", "nao_avaliada"),
        "CVE-2099-0023": ("", "sim", "sim", "sim", "nao"),
        "CVE-2099-0024": ("", "nao", "nao_avaliada", "nao_avaliada", "nao_avaliada"),
    }

    lista = tmp / "lista.txt"
    metadata = tmp / "metadata.csv"
    with open(lista, "w", encoding="utf-8") as l_arq, open(metadata, "w", encoding="utf-8") as m_arq:
        m_arq.write("CVE,Repository,PrePatchCommit,PostPatchCommit,CWEs,Explanation,FilePath,FileLine\n")
        for cve, _, url_, pre, post, arquivo, linhas, _ in casos:
            linhas_txt = "|".join(map(str, linhas))
            l_arq.write("%s,%s,%s,%s,%s,%s\n" % (cve, url_, pre, CWES, arquivo, linhas_txt))
            m_arq.write('%s,%s,%s,%s,"%s","x","%s",%s\n'
                        % (cve, url_, pre, post, CWES, arquivo, linhas_txt))
    fx.lista, fx.metadata = lista, metadata
    return fx
