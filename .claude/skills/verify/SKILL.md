---
name: verify
description: Roda as provas de keyfence num comando, em ordem barata primeiro, e devolve a linha `Verificado:` do commit e do PR. Use antes de commitar e antes de abrir PR.
---

# verify

Chame antes de cada commit e antes de `gh pr create`.

```
bash scripts/verificar.sh              # antes do commit: E2E do fluxo crítico, com smoke da captura (segundos)
bash scripts/verificar.sh --completo   # antes do PR: acrescenta a suíte inteira (npm test, ROUNDS=100)
```

Sai com 0 só se tudo passou e para na primeira prova que falha, dizendo qual foi. No fim imprime `Verificado: <o que rodou>`: cole essa linha no corpo do commit e na descrição do PR. Commit que não rodou nada leva `Verificado: nenhum (<motivo de 10 caracteres ou mais>)`. O CI (`.github/workflows/verificado.yml`) reprova o PR sem a linha.

Regras que valem junto:

- Três falhas seguidas do mesmo passo: pare, junte o erro e escale. Não tente uma quarta vez às cegas.
- Teste instável não se repete até passar: ache a causa raiz ou remova o teste dizendo o motivo no PR.
- O script não substitui rodar o sistema real. O keyfence não tem tela: a prova do fluxo crítico é `e2e/fluxo-critico.e2e.sh` (guarda a saída do passo que quebra em `e2e/saida/`), que roda `scripts/verificacao/e2e-captura.js`: cola um valor sintético, confere que foi guardado com nome e que o valor literal e a leitura do cofre são barrados.
- Bug de detecção corrigido ganha teste de regressão no arquivo que já cobre o módulo (`test/detect.test.js`, `test/whole-value.test.js`, `test/jev.test.js`); valor de teste é sempre sintético, vindo de `test/gen.js`.
- `REVIEW.md` diz o que o revisor olha por gatilho do diff; a mudança não altera o check que a julga.
