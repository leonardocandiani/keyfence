'use strict';
// O patch do bash-firewall (docs/firewall): a versão original barrava qualquer
// comando que citasse um arquivo de ambiente, mesmo `find -name`, `cut -d= -f1`
// ou um heredoc que só escreve texto num .md. Aqui as duas versões rodam sobre os
// mesmos comandos: o original erra nos casos legítimos, o patch acerta, e a
// leitura de verdade (cat, head, tail desses arquivos) segue bloqueada.
// O firewall vive fora do repositório; a CENTRAL aplica o patch nos hooks globais.

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '..', 'docs', 'firewall');
const ORIG = path.join(dir, 'bash-firewall.orig.sh');
const PATCHED = path.join(dir, 'bash-firewall.sh');
const have = (bin) => spawnSync('sh', ['-c', `command -v ${bin}`]).status === 0;
if (!have('jq') || !have('perl') || !fs.existsSync(PATCHED)) {
  console.log('firewall: skipped (needs jq, perl and docs/firewall)');
  process.exit(0);
}

const run = (script, command) => spawnSync('bash', [script], { input: JSON.stringify({ tool_input: { command } }), encoding: 'utf8' }).status;
const E = ['.', 'env'].join('');
const CJ = ['.claude', 'json'].join('.');
const HD = (body) => `cat > notas.md <<'MD'\n${body}\nMD`;

// [descrição, comando, original barra?, patch barra?]
const matrix = [
  ['find -name no arquivo de ambiente', `find . -name "${E}*" -maxdepth 3`, false, false],
  ['ls do arquivo de ambiente', `ls -la ${E}`, false, false],
  ['cut -d= -f1', `cut -d= -f1 ${E}`, false, false],
  ['grep -c NOME', `grep -c STRIPE ${E}`, false, false],
  ['wc -l', `wc -l ${E} && cut -d= -f1 ${E} | sort`, false, false],
  ['heredoc escrevendo texto que cita o arquivo', HD(`nunca rode cat ${E} no chat`), true, false],
  ['heredoc que cita a config do Claude Code', HD(`o arquivo ${CJ} guarda sessões; head ${CJ} imprime tudo`), true, false],
  ['heredoc em arquivo de ambiente de exemplo', HD(`copie ${E}.example para ${E}.local`), true, false],
  ['commit que cita o comando proibido', `git commit -m "docs: nunca use cat ${E}"`, true, false],
  ['echo que cita o comando proibido', `echo "cat ${E} imprime o segredo"`, true, false],
  ['escrever o arquivo de ambiente', `cat > ${E} <<'X'\nNOME=valor\nX`, true, false],
  ['chmod (a palavra termina em od) no arquivo', `chmod 600 ${E}.local`, true, false],
  ['cat do arquivo de exemplo', `cat ${E}.example`, true, false],
  ['cat do arquivo de ambiente', `cat ${E}`, true, true],
  ['head do arquivo de ambiente local', `head -n 3 ${E}.local`, true, true],
  ['tail do arquivo de ambiente de produção', `tail -f ${E}.production`, true, true],
  ['cat com caminho', `cat ./app/${E}`, true, true],
  ['cat depois de um && que passa', `grep -c K ${E} && cat ${E}`, true, true],
  ['cat entrando por pipe', `cat ${E} | head -2`, true, true],
  ['cat da config do Claude Code', `cat ~/${CJ}`, true, true],
  ['head da config do Claude Code', `head ~/${CJ}`, true, true],
  ['tail da config do Claude Code', `tail -n 5 ~/${CJ}`, true, true],
  ['chave ssh por ssh', 'ssh box cat ~/.ssh/id_ed25519', true, true],
  ['bash -c com cat', `bash -c "cat ${E}"`, true, true],
  ['find -exec cat', `find . -name "${E}" -exec cat {} \\;`, true, true],
  ['credenciais da aws', 'cat ~/.aws/credentials', true, true],
  ['rm recursivo em raiz segue fora (regra de outro bloco)', 'dd if=/dev/zero of=/dev/disk2', true, true],
];

const cases = matrix.flatMap(([name, cmd, before, after]) => [
  { name: `antes: ${name}`, got: run(ORIG, cmd) === 2, want: before },
  { name: `depois: ${name}`, got: run(PATCHED, cmd) === 2, want: after },
]);
const failed = cases.filter((c) => c.got !== c.want);
console.log(`firewall: ${cases.length - failed.length}/${cases.length} scenarios ok`);
failed.forEach((c) => console.log(`  FAIL ${c.name}: blocked=${c.got}, want ${c.want}`));
process.exitCode = failed.length ? 1 : 0;
