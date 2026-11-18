#!/usr/bin/env bash
# verificar.sh: smoke de um comando só de keyfence. Roda as provas em ordem barata primeiro e imprime a linha `Verificado:` do commit.
# Gerado pelo kit-verificacao (js/npm) e preenchido com as provas reais do keyfence.
# Exit 0 só se tudo passou, 1 na primeira prova que falha, 2 erro de uso.
set -u

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="origin/main"
COMPLETO=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      cat <<'AJUDA'
verificar.sh [--completo] [--base <ref>]
Roda as provas em ordem barata primeiro e para na primeira que falha.
--completo  acrescenta a suíte inteira (`npm test`, ROUNDS=100 como no CI).
--base      ref de comparação para achar os arquivos tocados (padrão origin/main).
No fim imprime `Verificado: <o que rodou>`, a linha que vai no corpo do commit e do PR.
Exemplos (examples):
  bash scripts/verificar.sh
  bash scripts/verificar.sh --completo
AJUDA
      exit 0 ;;
    --completo) COMPLETO=1 ;;
    --base)
      [ $# -ge 2 ] || { printf 'error: --base pede um ref\ncode: USO\nhelp: verificar.sh --base origin/main\n'; exit 2; }
      BASE="$2"; shift ;;
    *) printf 'error: argumento desconhecido: %s\ncode: USO\nhelp: verificar.sh --help\n' "$1"; exit 2 ;;
  esac
  shift
done

cd "$RAIZ" || exit 1
RODOU=()

rodar() {
  nome="$1"; shift
  printf '\n== %s ==\n' "$nome"
  "$@" || { printf '\nverificar: FALHOU em %s\n' "$nome"; exit 1; }
  RODOU+=("$nome")
}

rodar_tocados() {
  nome="$1"; shift
  LISTA=()
  for f in $( { git diff --name-only "$BASE"...HEAD; git diff --name-only; git diff --name-only --cached; } 2>/dev/null | sort -u | grep -E '\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte)$' ); do
    [ -f "$f" ] && LISTA+=("$f")
  done
  if [ "${#LISTA[@]}" -eq 0 ]; then
    printf '\n== %s ==\n(nenhum arquivo de código tocado)\n' "$nome"
    return
  fi
  rodar "$nome (${#LISTA[@]} arquivo(s))" "$@" "${LISTA[@]}"
}

rodar "E2E do fluxo crítico (colar, guardar, usar pelo nome)" bash e2e/fluxo-critico.e2e.sh

if [ "$COMPLETO" -eq 1 ]; then
  rodar "suíte inteira (ROUNDS=100)" env ROUNDS=100 npm test
fi

if [ "${#RODOU[@]}" -eq 0 ]; then
  printf '\nVerificado: nenhum (verificar.sh sem passos para esta stack, edite o arquivo)\n'
  exit 0
fi
SAIDA=""
for item in "${RODOU[@]}"; do SAIDA="${SAIDA:+$SAIDA, }$item"; done
printf '\nVerificado: %s\n' "$SAIDA"
