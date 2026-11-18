# REVIEW.md: o que o revisor olha em keyfence

Este arquivo diz ao revisor (humano, Codex ou subagente) o que conferir neste repositório. O revisor lê a versão da branch base (`origin/main`), nunca a do PR: a mudança não altera o próprio check. A rodada seguinte de review recebe os achados da anterior e confere se cada um foi corrigido, em vez de recomeçar do zero.

## Severidade

- **Important**: bloqueia o merge. Bug, segredo, prova ausente, item do checklist abaixo violado pelo diff.
- **Nit**: não bloqueia. Estilo, nome, comentário, simplificação. O revisor lista o Nit em bloco separado no fim; o autor decide.
- **Pre-existing**: problema que já existia antes do diff. Não é cobrado do autor; vira tarefa à parte, nunca bloqueio.

Formato do review: cada achado com severidade, `arquivo:linha`, por que está errado e como provar que falha. O review fecha com a linha `Bloqueantes: N`.

## Checklist disparado pelo diff

O revisor confere só os itens cujo gatilho casa com o diff. Cada item traz a origem na última coluna.

| Gatilho no diff | O que conferir | Severidade | Origem |
|---|---|---|---|
| todo PR | A linha `Verificado:` bate com o que realmente rodou? O comando está no corpo e a saída foi lida? | Important | carimbo (`scripts/verificacao/conferir-carimbo.sh`) |
| lockfile, `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml` | Dependência nova tem motivo no PR e a existente não resolvia? O lockfile mudou só pelo que o PR declara? | Important | regra do kit |
| `.env*`, chave, token, senha, credencial (fixture real) | Há segredo no diff? Valor entra só por variável de ambiente, nunca literal em código, log ou teste. | Important | regra do kit |
| teste novo, alterado ou removido; `.skip`, `.only`, `sleep`, retry | O teste passa sem relógio real? Teste removido ou pulado tem o motivo no PR? Instável não ganha retry: acha a causa. | Important | regra do kit |
| `.github/workflows/`, `scripts/verificacao/`, `REVIEW.md` junto com código | O PR muda o check e o código que o check julga? Diz por quê no corpo, com a linha `Check alterado: <motivo>`. | Important | regra do kit |
| `src/detect.js`, `src/forms.js`, `src/jev.js`, `src/lines.js` | O ajuste que tira um falso positivo derruba a captura de uma senha real? O PR traz, no mesmo diff, o caso que deixou de ser segredo E o caso vizinho que continua sendo, com valor sintético de `test/gen.js`? | Important | falsos positivos em série: #38 a #42, #52, #53; e o inverso, falso negativo que deixou senha sem proteção: #47, #48, #54, #55, #56 |
| teste que gera valores (`test/gen.js`, `ROUNDS`, `SEED`, `test/whole-value.test.js`) | A semente é impressa na falha e `SEED=<n>` reproduz? O gerador evita colisão entre campos (dígitos distintos, sem valor que por acaso case com palavra comum)? Teste que falha em 1 de N rodadas é bug do gerador ou do código, nunca retry. | Important | tidy.test falhava em 0,28% das rodadas (#50); whole-value com semente fixa (#57) |
| `src/maintain.js`, `src/capture.js`, `src/naming.js`, `src/tidy.js`, `src/cli.js` (maintain) | Falha de leitura ou escrita vira aviso (`maintain.onFailure`) e linha em `unreadable[n]`, ou some em silêncio? Arquivo grande ou evictado do iCloud derruba a rodada inteira? | Important | maintain calado: transcript acima de 512 MB (#44), arquivo iCloud evictado com erro -11 (#58) |
| `bin/keyfence-hook.js`, `src/hook*.js`, regras de bloqueio | Valor literal continua barrado em rede, commit, MCP e código? Texto que só cita a leitura do cofre (`--mensagem`, heredoc) não é barrado por engano? Latência do hook segue medida em `test/hook.test.js`. | Important | #41, #43; o hook roda em toda sessão, então erro aqui para todas |
| `src/capture.js`, `src/naming.js` (gravação no `.env` ou `secrets.env`) | O valor volta idêntico ao ler o arquivo? Valor com `|`, espaço ou `~` entra entre aspas? Nome gerado é ASCII e nunca começa com dígito? | Important | #36, #51; valor com `|` no secrets.env executava o valor no `source` |

## Como esta lista cresce e encolhe

Item novo entra quando o mesmo padrão aparece em 2 ou mais PRs ou reverts e dá para identificar no diff. Item cujo gatilho nunca casou em 6 meses sai (poda). Lacuna que um review deixou passar num diff pequeno vira linha aqui no mesmo PR da correção.
