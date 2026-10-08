#!/bin/bash
# bash-firewall — PreToolUse hook. Rede de seguranca ATIVA antes de cada comando.
# Complementa permissions.deny (estatico) com analise de padrao perigoso.
# Protocolo: stdin = JSON do tool call. exit 0 libera. exit 2 bloqueia e
# devolve stderr pro modelo. Nunca trava o fluxo normal de trabalho.

input=$(cat)
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)

[ -z "$cmd" ] && exit 0

block() {
  echo "BLOQUEADO pelo bash-firewall: $1" >&2
  echo "Comando: $cmd" >&2
  echo "Se for intencional e seguro, peca ao usuario pra rodar manualmente com '! <comando>'." >&2
  exit 2
}

# normaliza espacos pra casar padroes com espacamento variado
norm=$(printf '%s' "$cmd" | tr -s '[:space:]' ' ')

# --- Destruicao de disco / sistema ---
case "$norm" in
  *"dd "*" of=/dev/"*)            block "dd escrevendo em device de bloco" ;;
  *mkfs*|*mkfs.*)                 block "formatacao de filesystem (mkfs)" ;;
  *" of=/dev/sd"*|*" of=/dev/disk"*|*" of=/dev/nvme"*) block "escrita direta em disco" ;;
  *">/dev/sd"*|*"> /dev/sd"*|*">/dev/disk"*|*"> /dev/disk"*) block "redirecionamento pra device de disco" ;;
  *shutdown\ *|*"halt"*|*"reboot"*|*"poweroff"*) block "comando de desligamento/reboot do sistema" ;;
  *"diskutil eraseDisk"*|*"diskutil reformat"*) block "diskutil apagando disco" ;;
esac

# --- Fork bomb ---
case "$norm" in
  *':(){'*|*':()'*'{ :|:'*|*'(){ '*'|'*'& };'*) block "fork bomb" ;;
esac

# --- chmod / chown recursivo perigoso ---
case "$norm" in
  *"chmod -R 777 /"*|*"chmod 777 /"*|*"chmod -R 777 ~"*|*"chmod -R 777 \$HOME"*) block "chmod 777 recursivo em raiz/home" ;;
  *"chown -R "*" /"|*"chown -R "*" / "*) block "chown recursivo em raiz" ;;
esac

# --- Pipe de download direto pra shell (RCE classico) ---
case "$norm" in
  *"bash <("*curl*|*"sh <("*curl*)                   block "process substitution baixando e executando" ;;
esac

# curl/wget canalizado pra shell: o shell tem que ser o comando logo depois do
# pipe. O padrao antigo casava a palavra e " sh" em qualquer ponto ("echo shot",
# "| head -1; ... sh") e travava comando legitimo.
if [[ "$norm" =~ (curl|wget)[^|\;\&]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh([[:space:]]|$) ]]; then
  block "download canalizado pra shell (exec de codigo remoto)"
fi

# --- Leitura/exfiltracao de credenciais ---
# leitura local de segredo via utilitarios de texto
# .env tratado a parte: como substring, "mensagens.enviados" ou "process.env"
# viravam falso positivo e travavam comando legitimo. Aqui so conta o arquivo
# de verdade: .env como caminho (depois de espaco, barra, aspas ou =).
if [[ "$norm" =~ (cat|less|more|head|tail|strings|xxd|od|base64|nl)[[:space:]] ]] && \
   [[ "$norm" =~ (^|[[:space:]/\'\"=])\.env([[:space:].\'\"]|$) ]]; then
  block "leitura de arquivo sensivel (.env)"
fi
for secret in 'id_rsa' 'id_ed25519' 'id_ecdsa' '.aws/credentials' \
              'auth-profiles.json' '.claude.json' '.npmrc' '.pgpass' \
              '.ssh/config' 'Keychains' 'login.keychain'; do
  case "$norm" in
    *"cat "*"$secret"*|*"less "*"$secret"*|*"more "*"$secret"*|*"head "*"$secret"*|\
    *"tail "*"$secret"*|*"strings "*"$secret"*|*"xxd "*"$secret"*|*"od "*"$secret"*|\
    *"base64 "*"$secret"*|*"nl "*"$secret"*)
      block "leitura de arquivo sensivel ($secret)" ;;
  esac
done

# exfiltracao: enviar arquivo sensivel via rede
case "$norm" in
  *curl*"@"*".env"*|*curl*"@"*"id_rsa"*|*curl*"@"*"credentials"*|*curl*"@"*".claude.json"*) \
    block "upload de arquivo sensivel via curl" ;;
  *curl*"-d @"*|*curl*"--data @"*"/.ssh/"*) block "exfiltracao de dados via curl --data @arquivo" ;;
esac

# --- git destrutivo em branch protegida ---
case "$norm" in
  *"git push"*"--force"*"main"*|*"git push"*"-f "*"main"*|\
  *"git push"*"--force"*"GoLive"*|*"git push"*"-f "*"GoLive"*) \
    block "git push --force em branch protegida (main/GoLive)" ;;
  *"git push --force origin"*|*"git push -f origin"*) \
    block "git push --force sem branch explicito (perigoso). Use --force-with-lease em branch nomeada." ;;
  *"git reset --hard origin"*) ;;  # permitido, comum e recuperavel
  *"git clean -fdx /"*|*"git clean -ffdx"*) block "git clean destrutivo amplo" ;;
esac

# --- Limpeza ampla fora de rm (rm ja esta no deny) ---
case "$norm" in
  *"find / -delete"*|*"find ~ -delete"*|*"find \$HOME -delete"*) block "find -delete em raiz/home" ;;
  *">/dev/null 2>&1 &"*) ;;  # padrao comum e inofensivo, ignora
esac

exit 0
