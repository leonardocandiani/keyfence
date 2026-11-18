#!/usr/bin/env bash
# conferir-carimbo.sh: em PR, exige a linha `Verificado:` no corpo ou na mensagem do último commit.
# Entrada por ambiente: PR_BODY (corpo do PR) e ULTIMO_COMMIT (mensagem; na falta, lê `git log -1`).
# Exit 0 se achou o carimbo, 1 se não achou ou se `nenhum` veio sem motivo.
set -u

CORPO="${PR_BODY:-}"
if [ -z "${ULTIMO_COMMIT+x}" ]; then
  ULTIMO_COMMIT="$(git log -1 --format=%B 2>/dev/null || true)"
fi

achar() {
  printf '%s\n' "$1" | grep -iE '^[[:space:]]*Verificado:[[:space:]]*[^[:space:]]' | head -1
}

linha="$(achar "$CORPO")"
origem="corpo do PR"
if [ -z "$linha" ]; then
  linha="$(achar "$ULTIMO_COMMIT")"
  origem="último commit"
fi

if [ -z "$linha" ]; then
  printf 'error: nenhuma linha `Verificado:` no corpo do PR nem no último commit\n'
  printf 'code: SEM_CARIMBO\n'
  printf 'help: acrescente `Verificado: <o que rodou>` (saída de `bash scripts/verificar.sh`) ou `Verificado: nenhum (<motivo de 10 caracteres ou mais>)`\n'
  exit 1
fi

valor="$(printf '%s' "$linha" | sed -E 's/^[[:space:]]*[Vv][Ee][Rr][Ii][Ff][Ii][Cc][Aa][Dd][Oo]:[[:space:]]*//')"
case "$(printf '%s' "$valor" | tr '[:upper:]' '[:lower:]')" in
  nenhum*)
    motivo="$(printf '%s' "$valor" | sed -nE 's/^[Nn][Ee][Nn][Hh][Uu][Mm][[:space:]]*\((.*)\)[[:space:]]*$/\1/p')"
    if [ "${#motivo}" -lt 10 ]; then
      printf 'error: `Verificado: nenhum` precisa do motivo, com 10 caracteres ou mais\n'
      printf 'code: CARIMBO_SEM_MOTIVO\n'
      printf 'help: use `Verificado: nenhum (<motivo>)`, por exemplo `Verificado: nenhum (mudança só de documentação)`\n'
      exit 1
    fi ;;
esac

printf 'carimbo: ok (%s)\nverificado: %s\n' "$origem" "$valor"
exit 0
