#!/usr/bin/env bash
# confere-campanha.sh — guarda entre a campanha pedida e o lote.
#
#   tools/confere-campanha.sh <campanha> <lote>
#
# <campanha> e `deteccao` ou `corrigida`; <lote> e o nome do arquivo em
# datasets/listas/, sem diretorio — as mesmas entradas do workflow_dispatch do
# analise-lote.yml, que chama este script ANTES de qualquer pull de imagem.
#
# Regra:
#   corrigida  exige lote cujo nome contenha "-corrigida-";
#   deteccao   exige lote cujo nome NAO contenha "corrigida" — mais estrito que
#              "-corrigida-", para que nem a lista completa corrigida
#              (cves-sast-corrigida.txt) passe por lote de deteccao.
#
# Os scripts de analise nao sabem qual commit recebem: fazem checkout do que a
# lista traz. Quem decide se a campanha analisa o PrePatchCommit ou o
# PostPatchCommit e a LISTA; esta guarda impede que a entrada `campanha` e a
# lista digam coisas diferentes, o que publicaria resultado de uma campanha com
# o rotulo da outra.
#
# Saida: em sucesso, UMA linha no stdout, `lista_completa=<caminho>`, a lista
# completa da campanha, relativa a raiz do repositorio — a que o normalize.py
# recebe em --lista. Em falha, a razao no stderr, nomeando a entrada e o lote,
# e codigo 1. Uso incorreto sai 2.
#
# Sem `set -e`: cada caminho confere e sai explicitamente.
set -uo pipefail

if [ "$#" -ne 2 ]; then
    echo "uso: tools/confere-campanha.sh <campanha> <lote>" >&2
    exit 2
fi

CAMPANHA="$1"
LOTE="$2"

if [ -z "$CAMPANHA" ]; then
    echo "ERRO: entrada 'campanha' vazia (lote '$LOTE'); valores aceitos: deteccao, corrigida" >&2
    exit 1
fi
if [ -z "$LOTE" ]; then
    echo "ERRO: entrada 'lote' vazia (campanha '$CAMPANHA')" >&2
    exit 1
fi

case "$CAMPANHA" in
    deteccao)
        case "$LOTE" in
            *corrigida*)
                echo "ERRO: campanha=deteccao com lote '$LOTE', que e lista da versao corrigida" >&2
                echo "  A campanha de deteccao roda sobre o PrePatchCommit: lotes cves-sast-batch-<xx>, cves-sast-fumaca, cves-sast-teste." >&2
                exit 1
                ;;
        esac
        COMPLETA="datasets/listas/cves-sast.txt"
        ;;
    corrigida)
        case "$LOTE" in
            *-corrigida-*) ;;
            *)
                echo "ERRO: campanha=corrigida com lote '$LOTE', cujo nome nao contem '-corrigida-'" >&2
                echo "  A campanha da versao corrigida roda sobre o PostPatchCommit: lotes cves-sast-corrigida-batch-<xx>, cves-sast-corrigida-fumaca." >&2
                exit 1
                ;;
        esac
        COMPLETA="datasets/listas/cves-sast-corrigida.txt"
        ;;
    *)
        echo "ERRO: entrada 'campanha' desconhecida: '$CAMPANHA' (lote '$LOTE'); valores aceitos: deteccao, corrigida" >&2
        exit 1
        ;;
esac

printf 'lista_completa=%s\n' "$COMPLETA"
exit 0
