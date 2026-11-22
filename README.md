# git-secret-guard

Hook de `pre-commit` que bloqueia credencial antes dela entrar no Git, um
sanitizador de histórico para repositórios que **já** vazaram e uma varredura de
resíduo para provar que não sobrou nada.

Nasci de um incidente real: um repositório público continha `.env` com credenciais
de produção e o histórico guardava cópias mesmo depois de `git rm`. Apagar o
arquivo não apaga o segredo — e segredo em histórico público é acesso concedido a
quem clonar. A ordem que resolveu o problema foi: **conter → rotacionar →
sanear → impedir**. Este repositório é a parte de "impedir" e "sanear", aberta.

> Nenhum dado, nome ou credencial do caso original está aqui. Os valores de
> exemplo são sintéticos e os tokens de identificação usados pelo sanitizador
> vêm de um arquivo local ignorado pelo Git (`ident.txt`).

## Por que isto existe

| o que parece resolver | o que resolve de fato |
|---|---|
| `git rm secret.txt` + commit | nada: o blob continua alcançável pelo SHA antigo |
| trocar o remote para privado | reduz superfície, não revoga acesso de quem já clonou |
| confiar em revisão de código | humano não lembra de todo literal em todo diff |
| **revogar a credencial** | é a única ação que encerra o acesso |
| **hook com padrão de segredo** | impede o próximo incidente |

## Instalação

```bash
# 1. hook no repositório alvo
cp -r .githooks /caminho/para/seu/repo/.githooks
git -C /caminho/para/seu/repo config core.hooksPath .githooks

# 2. teste local: 12 casos, esperados e obtidos
cp testa-hook.sh /caminho/para/seu/repo/ && bash testa-hook.sh
```

O hook lê `hook-patterns.tsv` (também versionado aqui) e faz três coisas:
nega commit de arquivo de credencial, nega literal que se parece com token de
provedor e nega dado de identificação (CNPJ, IP interno, hostname de homologação)
em documento. A saída diz **qual regra** bateu e em **qual linha** — sem a linha,
o desenvolvedor discutiu comigo; com a linha, ele conserta.

## Sanear um histórico que já vazou

```bash
cp ident.txt.example ident.txt      # edite com os tokens DO SEU caso, não os meus
python3 sanitizar_repo.py --repo /caminho/para/seu/repo \
  --ident-txt ident.txt --apply --out relatorio.json
```

O que ele faz, nesta ordem:

1. varre **todo** o histórico (não só o `HEAD`), coletando valores de chave de
   configuração e literais que parecem credencial;
2. reescreve commits substituindo valor por `<REDIGIDO-<TIPO>>`, preservando
   estrutura do arquivo para o diff continuar legível;
3. remove caminho de arquivo que só existe para conter segredo;
4. emite `relatorio.json` com antes/depois por arquivo, para a decisão de
   rotação ter lastro;
5. exige confirmação explícita (`--apply`) porque reescrever histórico é
   irreversível para quem tem clone antigo.

`gitleaks.toml` é a regra para o scanner do GitHub/GitLab, com allowlist
deliberada para os fixtures deste repositório (`GH_PREFIX`+`GH_FAKE_SUFFIX` são
montados em runtime justamente para o push protection não confundir teste com
vazamento).

## O que este projeto **não** faz

- Não revoga credencial: rotação é no provedor (nuvem, banco, IdP, SaaS).
- Não torna público seguro o que era privado sem histórico limpo: `git push
  --force` num repo que alguém clonou continua sendo cópia em circulação.
- Não substitui secret manager. Ele é a cerca, não o cofre.

## Prova de funcionamento

```
$ bash testa-hook.sh
ok    1   arquivo .env                         BLOCK
ok    2   arquivo env.txt                      BLOCK
ok    3   arquivo CREDENCIAIS.md               BLOCK
ok    4   senha literal em codigo              BLOCK
ok    5   IP interno em doc                    BLOCK
ok    6   CNPJ real em doc                     BLOCK
ok    7   hostname interno                     BLOCK
ok    8   chave de provedor                    BLOCK
ok    9   codigo limpo (segredo via ambiente)  PASS
ok    10  exemplo com placeholder              PASS
ok    11  SECRET_KEY literal em modulo         BLOCK
ok    12  .gitignore cita .env.local           PASS
resultados: 12 corretos, 0 incorretos
```

Caso 4 e caso 11 existem porque as duas primeiras versões do hook só olhavam
arquivo de configuração — e o vazamento verdadeiro estava em `core/security.py`,
um lugar que ninguém procura quando pensa em "segredo".

## Perfil

[github.com/jraalves](https://github.com/jraalves) ·
[portfólio](https://jraalves.github.io/portfolio/) ·
[LinkedIn](https://www.linkedin.com/in/joaorenatoalves-sre)
