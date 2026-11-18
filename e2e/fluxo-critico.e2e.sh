#!/usr/bin/env bash
# E2E do fluxo crítico de keyfence (repositório sem tela).
# Roda o fluxo que o usuário depende, de ponta a ponta, com dado sintético, e para no primeiro passo que quebra.
# Cada passo grava a saída em e2e/saida/<passo>.txt, que é a prova do passo que falhou.
# Fluxo real: colar um valor sintético no chat, o hook guardar com nome, usar pelo nome, e o literal e a leitura do cofre serem barrados.
# Config, cofre, registro e repo ficam em pasta temporária; o cofre real nunca é tocado.
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
SAIDA="$RAIZ/e2e/saida"
mkdir -p "$SAIDA"

passo() {
  local nome="$1"; shift
  if "$@" >"$SAIDA/$nome.txt" 2>&1; then
    echo "ok: $nome"
  else
    echo "falhou: $nome (saída em e2e/saida/$nome.txt)"
    tail -20 "$SAIDA/$nome.txt"
    exit 1
  fi
}

passo captura-sintetica node "$RAIZ/scripts/verificacao/e2e-captura.js" --smoke
passo colar-guardar-usar-pelo-nome node "$RAIZ/scripts/verificacao/e2e-captura.js"

echo "fluxo crítico: todos os passos ok"
