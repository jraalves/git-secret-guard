#!/usr/bin/env python3
"""Sanitizador de repositorio para republicacao anonima.

Uso: python3 sanitizar_repo.py <origem> <destino> [--secrets-file <arquivo>]

Faz duas coisas, nesta ordem:
 1) elimina arquivos por classe (credencial, ambiente, artefato, dump, codigo de terceiro);
 2) substitui em todo texto restante valores reais por placeholder, usando como fonte de
    segredos o proprio .env/config local + padroes (IP interno, CNPJ, CPF, dominio, marca).
No final roda o scan de verificacao: se algo sobreviver, exit code 1 e nada e publicado.
"""
import argparse, base64, hashlib, json, pathlib, re, shutil, sys

DROP_DIR = {"venv", ".venv", "env", "node_modules", "__pycache__", ".git", ".idea", ".vscode",
            "dist", "build", "analysis", "site-packages", "vendor", "coverage", ".pytest_cache",
            "logs", "log", "tmp", "storage", "uploads", "media", "backup", "backups"}
DROP_NAME_RE = re.compile(
    r"(^|/)(\.env(\..*)?|env\.txt|CREDENCIAIS?\.md|.*CREDENCIAL.*\.(md|txt|json)|"
    r"GUIA_ACESSO.*|.*ACESSO_COMPLETO.*|CONFIGURACAO_.*OFICIAL.*|MICROSOFT_ENTRA.*|VERIFICACAO_IDENTIDADE.*|"
    r"PACOTE_GOLD.*|RELATORIO_TECNICO.*|ENTREGA_FINAL.*|AUDITORIA.*|.*SEGURANCA.*\.md|"
    r"id_rsa.*|.*\.pem|.*\.key|.*\.p12|.*\.pfx|.*\.kdbx|google-service-account.*|.*service-account.*\.json|"
    r".*\.(sqlite3?|db|bak|dump|sql\.gz|tar|tar\.gz|zip|7z|png|jpg|jpeg|gif|webp|pdf|docx?|xlsx?|pptx?)$)",
    re.I)
DROP_PATH_RE = re.compile(r"(^|/)(.*(backup|dump|seed_real|producao|produccao).*|test_empresa_api_output\.txt|test_result\.md)$", re.I)
SQL_INSERT_RE = re.compile(r"^\s*(INSERT|COPY)\b", re.I)

# padroes genericos de substituicao (ordem importa)
PATTERNS = [
    ("IP_INTERNO",  r"\b(?:192\.168|10)\.\d{1,3}\.\d{1,3}(?::\d+)?\b"),
    ("IP_CG_NAT",   r"\b100\.64\.\d{1,3}\.\d{1,3}\b|\b200\.123\.\d{1,3}\.\d{1,3}\b"),
    ("HOST_INTERNO", r"\b[a-z0-9.-]*\.(?:local|internal|corp|lan|ddns\.net|home\.network)\b"),
    ("CAMINHO_WIN", r"\b[A-Za-z]:\\\\?[^\s\"'|<>]*"),
    ("CNPJ",        r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b|\b\d{14}\b"),
    ("CPF",         r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    ("TELEFONE_BR", r"(?<![\d])(?:\+?55[\s-]?)?(?:\(\d{2}\)\s*)?(?:9?\d{4}-?\d{4})(?![\d])"),
    ("EMAIL",       r"\b[\w.%+-]+@[\w.-]+\.(?:com\.br|br|com|net|io|org)\b"),
    ("CHAVE_FORMAT", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("URL_DIC",     r"https?://[^\s'\"<>)\]]+"),
]
# tokens de identificacao (marca, razao social, nomes proprios de cliente)
URL_KEEP = re.compile(r"github\.com|docs\.github|pypi|npmjs|wikipedia|schema\.org|w3\.org|opentelemetry\.io|prometheus\.io|grafana\.com|kubernetes\.io|registry\.npmjs|localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|example\.org", re.I)
# Tokens de marcador de cliente/entidade. NAO sao os do meu ex-cliente: sao
# exemplos da forma correta. Os reais ficam em ident.txt (gitignored), porque
# lista de marca propria dentro de ferramenta publica tambem e vazamento.
IDENT_TOKENS = ["ACME", "acme-corp", "contoso", "exemplo consultoria", "cliente-x"]

def load_secret_values(base: pathlib.Path):
    """Le coletorios locais e devolve [(valor, rotulo)] ordenado do maior para o menor."""
    vals = {}
    def add(v, label):
        v = (v or "").strip().strip("'\"").strip()
        if len(v) >= 6 and not v.lower().startswith(("your", "seu", "<", "placeholder", "changeme")):
            vals[v] = label
    for cand in ["backend/.env", ".env", "env.txt", "core/settings.py", "config/settings.py",
                 "backend/core/settings.py", "settings.py", "docker-compose.yml", "deploy_v2.sh",
                 "CREDENCIAIS.md", "GUIA_ACESSO_COMPLETO.md"]:
        p = base / cand
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"(?m)^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*['\"]?([^'\"\n#]{6,})", txt):
            add(m.group(2), m.group(1))
        for m in re.finditer(r"(?i)password\s*=\s*['\"]([^'\"]{6,})['\"]", txt):
            add(m.group(1), "PASSWORD")
        for m in re.finditer(r"(?i)(senha|password|secret|token)\D{0,20}[:=]\s*[\"']?([^\s\"';]{8,})", txt):
            add(m.group(2), m.group(1).upper())
    return sorted(vals.items(), key=lambda kv: -len(kv[0]))

HARVEST_ANY = [
    ("SECRET",  re.compile(r"(?i)\b([A-Z0-9_]*(?:secret|token|api[_-]?key|senha|password|passwd|pwd)[A-Z0-9_]*)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
    ("KWARG",   re.compile(r"(?i)\b([a-z0-9_]*(?:secret|token|senha|password|passwd|pwd))[a-z0-9_]*\s*=\s*['\"]([^'\"]{8,})['\"]")),
]
HARVEST_LABELS = re.compile(r"(?i)(secret|token|api[_-]?key|senha|password|passwd|pwd)")
SKIP_HARVEST = re.compile(r"(?i)^(<[A-Z_]+>|\$\{|\{\{|your_|seu_|changeme|example|placeholder|x{6,}|\*{6,})")

def harvest_all(base: pathlib.Path, ident):
    """Segunda passada: varre TODOS os arquivos de texto atrás de literal de credencial.

    A primeira versão colhia valores só de um whitelist de caminhos de config
    (.env, settings.py, CREDENCIAIS.md...). Funcionou nos dois repositórios reais,
    mas deixou passar `SECRET_KEY = "..."` dentro de core/security.py e o default
    `new_password=<literal>` de um script manual, porque aquele literal nunca tinha
    aparecido no arquivo de origem. Coletar só de config é coletar do que eu lembrei.
    """
    vals = {}
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(base))
        if set(rel.split("/")) & DROP_DIR or DROP_NAME_RE.search(rel) or DROP_PATH_RE.search(rel):
            continue
        try:
            if p.stat().st_size > 1_500_000:
                continue
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "\x00" in txt[:4096]:
            continue
        for _, rx in HARVEST_ANY:
            for m in rx.finditer(txt):
                nome, valor = m.group(1), m.group(2).strip()
                if not HARVEST_LABELS.search(nome):
                    continue
                if len(valor) < 8 or SKIP_HARVEST.match(valor):
                    continue
                if any(t.lower() in valor.lower() for t in ident):
                    continue
                vals.setdefault(valor, nome.upper())
    return vals

def scan(text, secrets, ident):
    """Retorna dict contagem de ocorrencia por classe, ainda presente no texto."""
    out = {}
    probe = re.sub(r"<[A-Z][A-Z0-9_:]*>", " ", text)   # placeholder != dado real
    for name, pat in PATTERNS:
        if name == "URL_DIC":
            # o relatorio de residuo nao pode denunciar as URLs que a propria
            # redacao decidiu preservar (documentacao, schemas, projetos abertos)
            restantes = [m.group(0) for m in re.finditer(pat, probe, re.I)
                         if not URL_KEEP.search(m.group(0))]
            n = len(restantes)
        else:
            n = len(re.findall(pat, probe, re.I))
        if n:
            out[name] = out.get(name, 0) + n
    for v in secrets:
        n = probe.count(v)
        if n:
            out["SEGREDO_" + (secrets[v] if isinstance(secrets, dict) else "VAL")] = n
    for t in ident:
        n = len(re.findall(re.escape(t), probe, re.I))
        if n:
            out["IDENT:" + t] = n
    return out

def redact(text, secrets, ident, log):
    # 1. valores conhecidos primeiro (substring exata, mais longo primeiro)
    for v in secrets:
        if v in text:
            label = secrets[v] if isinstance(secrets, dict) else "VAL"
            text = text.replace(v, "<%s>" % label)
            log["sub_secret"] += 1
    # 2. tokens de identificacao
    for t in ident:
        rx = re.compile(re.escape(t), re.I)
        if rx.search(text):
            text = rx.sub("<ENTIDADE>", text)
            log["sub_ident"] += 1
    # 3. padroes genericos
    def mk(name):
        def rep(m):
            s = m.group(0)
            if name == "URL_DIC" and URL_KEEP.search(s):
                return s
            return "<%s>" % name
        return rep
    for name, pat in PATTERNS:
        new = re.sub(pat, mk(name), text, flags=re.I)
        if new != text:
            log["sub_" + name] = log.get("sub_" + name, 0) + 1
            text = new
    return text

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src"); ap.add_argument("dst")
    ap.add_argument("--ident", default=None,
                    help="tokens separados por virgula; padrao le de ident.txt (um por linha)")
    ap.add_argument("--ident-txt", default="ident.txt",
                    help="arquivo com tokens reais; nunca commitar")
    args = ap.parse_args()
    src, dst = pathlib.Path(args.src), pathlib.Path(args.dst)
    if args.ident:
        ident = [t.strip() for t in args.ident.split(",") if t.strip()]
    else:
        it = pathlib.Path(args.ident_txt)
        if it.is_file():
            ident = [ln.strip() for ln in it.read_text(encoding="utf-8", errors="ignore").splitlines()
                     if ln.strip() and not ln.strip().startswith("#")]
            print(f"tokens de identificacao lidos de {it}: {len(ident)}", file=sys.stderr)
        else:
            ident = list(IDENT_TOKENS)
            print("aviso: usando tokens de EXEMPLO (crie ident.txt com as marcas reais)", file=sys.stderr)
    secrets = dict(load_secret_values(src))
    secrets.update(harvest_all(src, ident))          # colhe o que a lista de cima não sabia
    secrets = dict(sorted(secrets.items(), key=lambda kv: -len(kv[0])))
    if not secrets:
        print("aviso: nenhum valor de credencial colhido (repos sem .env?)", file=sys.stderr)
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)

    log = {"drop_dir": 0, "drop_file": 0, "kept": 0, "sub_secret": 0, "sub_ident": 0}
    for p in sorted(src.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(src).as_posix()
        parts = set(rel.split("/"))
        if parts & DROP_DIR or any(d in rel for d in DROP_DIR):
            log["drop_dir"] += 1; continue
        if DROP_NAME_RE.search(rel) or DROP_PATH_RE.search(rel):
            log["drop_file"] += 1; continue
        if p.stat().st_size > 1_500_000:
            log["drop_file"] += 1; continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, ValueError):
            log["drop_file"] += 1; continue          # binario nao e publicavel aqui
        # .sql: manter esquema, jogar fora linhas de dados
        if rel.endswith(".sql"):
            keep = [l for l in text.splitlines() if not SQL_INSERT_RE.match(l)]
            log.setdefault("sql_rows_dropped", 0)
            log["sql_rows_dropped"] = log.get("sql_rows_dropped", 0) + (len(text.splitlines()) - len(keep))
            text = "\n".join(keep)
        out = redact(text, secrets, ident, log)
        # teste final por arquivo: se ainda houver padrao sensivel e nao-ignorado, descarta arquivo
        resid = scan(out, secrets, ident)
        fatal = {k: v for k, v in resid.items()
                 if k.startswith(("SEGREDO_", "IDENT:")) or k in
                 ("CNPJ", "CPF", "IP_INTERNO", "IP_CG_NAT", "HOST_INTERNO", "CHAVE_FORMAT")}
        aviso = {k: v for k, v in resid.items() if k in ("TELEFONE_BR", "EMAIL", "CAMINHO_WIN")}
        if aviso:
            log.setdefault("avisos", {})[rel] = aviso
        if fatal:
            log["drop_file"] += 1
            print("  descartado por residuo sensivel:", rel, fatal, file=sys.stderr)
            continue
        t = dst / rel
        t.parent.mkdir(parents=True, exist_ok=True)
        t.write_text(out, encoding="utf-8")
        log["kept"] += 1

    # verificacion global
    blob = "\n".join(f.read_text(encoding="utf-8", errors="ignore") for f in dst.rglob("*") if f.is_file())
    final = scan(blob, secrets, ident)
    report = {"resumo": log, "residuo_final": final,
              "secretos_fonte": [{"len": len(v), "sha1": hashlib.sha1(v.encode()).hexdigest()[:10], "label": lbl}
                                 for v, lbl in secrets.items()]}
    (dst / "SANITIZATION_REPORT.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"origem": str(src), "mantidos": log["kept"], "descartados": log["drop_file"] + log["drop_dir"],
                      "substituicoes": {k: v for k, v in log.items() if k.startswith("sub_") or k == "sql_rows_dropped"},
                      "residuo_final": final}, indent=2, ensure_ascii=False))
    sys.exit(1 if final else 0)

main()
