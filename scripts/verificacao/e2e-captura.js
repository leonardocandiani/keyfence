'use strict';
// E2E do fluxo crítico do keyfence: colar um valor sintético no chat, o hook guardar com nome, e
// o uso pelo nome passar enquanto o valor literal e a leitura do cofre são barrados.
// Roda isolado (config, cofre, registro e repo em pasta temporária); nunca toca o cofre real.
// `--smoke` roda só a captura (passo 1), a prova barata do verificar.sh.
// Exit 0 se tudo passou, 1 na primeira falha (imprime o passo e a evidência, nunca o valor), 2 erro de uso.
const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { positives } = require('../../test/gen');

const args = process.argv.slice(2);
const desconhecido = args.filter((a) => a !== '--smoke');
if (desconhecido.length) {
  console.log(`error: argumento desconhecido: ${desconhecido[0]}\ncode: USO\nhelp: node scripts/verificacao/e2e-captura.js [--smoke]`);
  process.exit(2);
}
const SMOKE = args.includes('--smoke');

const HOOK = path.join(__dirname, '..', '..', 'bin', 'keyfence-hook.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-e2e-'));
const repo = path.join(tmp, 'repo');
fs.mkdirSync(repo);
execFileSync('git', ['init', '-q'], { cwd: repo });
fs.writeFileSync(path.join(repo, '.gitignore'), '.env\n');
const cfg = path.join(tmp, 'config.json');
fs.writeFileSync(cfg, JSON.stringify({ jev: { enabled: false }, capture: { globalFile: path.join(tmp, 'global', 'secrets.env') } }));
const env = {
  ...process.env,
  KEYFENCE_CONFIG: cfg,
  KEYFENCE_VAULT_DIR: path.join(tmp, 'vault'),
  KEYFENCE_VAULT_KEY_FILE: path.join(tmp, 'vault-key'),
  KEYFENCE_REGISTRY: path.join(tmp, 'registry.json'),
};
const SID = `e2e-${process.pid}-${Date.now()}`;
const valor = positives.find((p) => p[0] === 'meta')[1]();

function hook(payload) {
  const r = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ session_id: SID, cwd: repo, ...payload }), env, encoding: 'utf8' });
  let out = null;
  try { out = r.stdout ? JSON.parse(r.stdout) : null; } catch { out = { ilegivel: true }; }
  return out;
}
const decisao = (o) => (o && o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || (o && o.decision) || 'pass';
const bash = (command) => decisao(hook({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } }));

function falhou(passo, evidencia) {
  console.log(`e2e-captura: FALHOU em ${passo}\n  ${evidencia}`);
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exit(1);
}
function passou(passo) { console.log(`ok: ${passo}`); }

const colado = hook({ hook_event_name: 'UserPromptSubmit', prompt: `segue o token da meta: ${valor}` });
const textoColado = JSON.stringify(colado);
const arquivo = path.join(repo, '.env');
const conteudo = fs.existsSync(arquivo) ? fs.readFileSync(arquivo, 'utf8') : '';
const nome = (conteudo.match(/^([A-Z][A-Z0-9_]*)=/m) || [])[1];

if (!nome || !conteudo.includes(`${nome}=${valor}`)) falhou('1 colar e guardar', `o valor sintético não foi guardado no .env do repo (nome achado: ${nome || 'nenhum'})`);
if (textoColado.includes(valor)) falhou('1 colar e guardar', 'o contexto devolvido ao agente repete o valor');
if (!textoColado.includes(`$${nome}`)) falhou('1 colar e guardar', `o agente não recebeu o nome $${nome}`);
if ((fs.statSync(arquivo).mode & 0o077) !== 0) falhou('1 colar e guardar', '.env guardado sem modo privado (0600)');
passou(`1 colar e guardar: valor sintético em .env com o nome ${nome}, modo privado, valor fora do contexto`);

if (!SMOKE) {
  const d2 = bash(`curl -s -H "Authorization: Bearer ${valor}" https://api.example.com/v1/me`);
  if (d2 !== 'deny') falhou('2 valor literal na rede', `comando com o valor literal saiu com decisão ${d2}, esperado deny`);
  passou('2 valor literal na rede: barrado');

  const d3 = bash(`curl -s -H "Authorization: Bearer $${nome}" https://api.example.com/v1/me`);
  if (d3 === 'deny') falhou('3 uso pelo nome', `comando que usa $${nome} foi barrado`);
  passou(`3 uso pelo nome: $${nome} passa`);

  const d4 = bash('cat .env');
  if (d4 !== 'deny') falhou('4 leitura do cofre', `leitura direta do .env saiu com decisão ${d4}, esperado deny`);
  passou('4 leitura do cofre: barrada');
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log(SMOKE ? 'e2e-captura (smoke): ok' : 'e2e-captura: ok (4 passos)');
