# Testes instáveis

Teste que falha e passa sem mudança de código entra aqui com a data, até ter causa raiz. Re-rodar até ficar verde não é conserto. Linha fechada fica como registro da causa.

| Teste | Aberto | Fechado | Causa raiz | Conserto |
|---|---|---|---|---|
| `test/whole-value.test.js` | 17/11/2026 | 17/11/2026 | O teste sorteava com `crypto.randomInt`, então a falha (1 em 1260, valor de forma `$(]aaaaaa~aa*!9-a*^a9a))` no layout json) não reproduzia. Investigado por semente, 11 de 300 sementes falhavam, em quatro classes: (1) valor inteiro `$(comando)`, `<nome>`, `nome.ext` em prosa ou `NOME_X=resto` em `.env` e json são recusados por desenho (`PLACEHOLDER` em `src/detect.js`, `NOT_A_VALUE` em `src/jev.js`, atribuição de variável) e o gerador não os excluía; (2) regressão minha dos PRs 54 e 55: o casamento do rótulo leva junto a quebra de linha da linha de cima e as regras de "valor na linha de baixo" a liam como a quebra entre rótulo e valor, então senha com forma de e-mail em `Senha:` deixava de ser capturada; (3) `scanContextual` aceitava `>` e um par de crases como borda de palavra, então senha com `->` ou crase saía em pedaço e o resto ficava à mostra. | PRs 56 (regressão, gerador com semente fixa e sementes fixas) e o deste arquivo (`scanContextual`, filtros do gerador por layout, tabela de casos fixos). De 11 em 300 sementes que falham para 0 em 300. |

Reproduzir uma falha: `SEED=<n> ROUNDS=<n> node test/whole-value.test.js` (a semente só reproduz com o mesmo número de rodadas, e a mensagem de falha imprime os dois).
