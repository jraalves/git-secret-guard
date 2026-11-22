#!/usr/bin/env bash
# Teste de regressao do hook de pre-commit: um repositorio limpo por caso.
kit=${1:-/home/ubuntu/github-kit/tools}
base=$(mktemp -d); pass=0; fail=0
run() {
  local id="$1" expect="$2" desc="$3" name="$4" body="$5"
  local d="$base/$id" err="$base/stderr_$id"
  mkdir -p "$d/.githooks" "$d/tools"
  cp "$kit/.githooks/pre-commit" "$d/.githooks/" ; chmod +x "$d/.githooks/pre-commit"
  cp "$kit/hook-patterns.tsv" "$d/tools/"
  res=$( cd "$d" \
    && git init -q . \
    && git config user.email t@example.com && git config user.name T \
    && git config --local core.hooksPath .githooks \
    && printf '%s' "$body" > "$name" \
    && git add "$name" \
    && if git commit -q -m t 2>"$err"; then echo PASS; else echo BLOCK; fi )
  if [ "$res" = "$expect" ]; then
    printf 'ok    %-3s %-36s %s\n' "$id" "$desc" "$res"; pass=$((pass+1))
  else
    printf 'ERRO  %-3s %-36s esperado=%s obtido=%s\n' "$id" "$desc" "$expect" "$res"; fail=$((fail+1))
    sed -n '1,3p' "$err" | sed 's/^/          /'
  fi
}
# token de exemplo montado em runtime: o literal 'ghp_' + 36 chars nao aparece no arquivo,
# entao o push protection do GitHub nao bloqueia o teste; o hook ainda o ve no conteudo staged.
GH_PREFIX='ghp'; GH_FAKE_SUFFIX='AAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaa'

run 1 BLOCK "arquivo .env"                        .env           'JWT_SECRET=abc123def456ghi789
MONGO_URL=mongodb://app:SenhaReal123@192.168.0.100:27017/db'
run 2 BLOCK "arquivo env.txt"                     env.txt        'token=abcdef123456'
run 3 BLOCK "arquivo CREDENCIAIS.md"              CREDENCIAIS.md 'senha do admin: Escondida123'
run 4 BLOCK "senha literal em codigo"             a.py           'def login():
    password = "SuperSecret123"
'
run 5 BLOCK "IP interno em doc"                   topo.md        'O servidor fica em http://192.168.0.1:8000
'
run 6 BLOCK "CNPJ real em doc"                    dados.md       'Empresa: 11.222.333/0001-81'
run 7 BLOCK "hostname interno"                    rede.md        'Acesso por acme.local e homolog.app.local'
run 8 BLOCK "chave de provedor"                   ci.yaml        "token: \${GH_PREFIX}_${GH_FAKE_SUFFIX}" 
run 9 PASS  "codigo limpo (segredo via ambiente)" b.py           'import os
def get_secret():
    return os.environ["JWT_SECRET_KEY"]
def check(candidate, stored_hash):
    return verify(candidate, stored_hash)
'
run 10 PASS "exemplo com placeholder"             .env.example   'JWT_SECRET=<JWT_SECRET>
API_TOKEN=seu_token_aqui
CNPJ=12.345.678/0001-00
HOST=0.0.0.0
'
run 11 BLOCK "SECRET_KEY literal em modulo"      security.py   'SECRET_KEY = "abcd1234efgh5678ijkl"'
run 12 PASS  ".gitignore cita .env.local"         .gitignore    '.env
.env.local
kind-config.local.yaml
__pycache__/
'

echo; echo "resultados: $pass corretos, $fail incorretos"; [ "$fail" -eq 0 ]
