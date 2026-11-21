#!/usr/bin/env bash
# Functional test for scripts/check-secrets.sh and scripts/check_secrets.py (the git hooks). Every
# "secret" here is random or assembled at run time, so this file itself holds none.
#   bash tests/func/check_secrets_test.sh        (from the repo root; needs git, python3)
set -uo pipefail
SRC_REPO="$(cd "${1:-$(dirname "$0")/../..}" && pwd -P)"
T="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/cs.XXXXXX")" && pwd -P)"
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
# A private HOME: the user's ~/.config/git/ignore (or any other per-user git file) can't change results.
export HOME="$T/home" XDG_CONFIG_HOME="$T/home/.config"
unset SECSTACK_NO_RUNTIME SECSTACK_GH NO_COLOR
mkdir -p "$HOME" "$T/repo/scripts" "$T/sec/configs"
cp "$SRC_REPO/scripts/check-secrets.sh" "$SRC_REPO/scripts/check_secrets.py" "$T/repo/scripts/"
cp "$SRC_REPO/.gitignore" "$T/repo/" 2>/dev/null || printf 'env/\nlogs/\n' > "$T/repo/.gitignore"
SC="$T/sec/configs/scope.cidrs"; DN="$T/sec/configs/never-commit.txt"
printf '203.0.113.0/24 # client\n172.30.0.8/29 lab\n' > "$SC"
printf '# client names\n  acme-widgets  \n' > "$DN"
export SECOPS="$T/sec"
printf 'clean line\n' > "$T/repo/q.txt"; printf 'notes\n' > "$T/repo/r1.txt"
cd "$T/repo" && git init -q && git symbolic-ref HEAD refs/heads/main && git add -A && git commit -qm base --no-verify
H=scripts/check-secrets.sh
pass=0; fail=0
ok(){ echo "PASS $*"; pass=$((pass+1)); }
bad(){ echo "FAIL $*"; fail=$((fail+1)); }
rnd(){ python3 -c 'import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))' "$1"; }
alnum(){ python3 -c 'import secrets,string,sys; print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(int(sys.argv[1]))))' "$1"; }
b64(){ python3 -c 'import base64,sys; print(base64.b64encode(sys.argv[1].encode()).decode())' "$1"; }
hook(){ bash "$H" "$@" 2>&1; }
show(){ printf '%s\n' "$1" | sed 's/^/    /'; }
# has <text> <substring>: no pipe, so nothing like `printf | grep -q` under pipefail (where grep
# exiting early makes printf die of SIGPIPE and the pipeline fail although the text matched).
has(){ case "$1" in *"$2"*) return 0 ;; esac; return 1; }

stage(){ mkdir -p "$(dirname -- "$1")"; printf '%s\n' "$2" > "./$1"; git add -f -- "./$1"; }
unstage(){ git rm -q --cached -f -- "./$1" >/dev/null 2>&1; rm -f -- "./$1"; }
expect_block(){ # expect_block <name> <file> <content> <message-substring>
  stage "$2" "$3"; out=$(hook); rc=$?
  if [ $rc -eq 1 ] && has "$out" "$4"; then ok "$1"; else bad "$1 (rc=$rc)"; show "$out"; fi
  unstage "$2"
}
expect_pass(){ # expect_pass <name> <file> <content>
  stage "$2" "$3"; out=$(hook); rc=$?
  if [ $rc -eq 0 ]; then ok "$1"; else bad "$1 (rc=$rc)"; show "$out"; fi
  unstage "$2"
}
refuses(){ # refuses <name> <message-substring> <command...>: exit 1 and the reason on stderr
  local name="$1" msg="$2"; shift 2
  out=$("$@" 2>&1); rc=$?
  if [ $rc -eq 1 ] && has "$out" "$msg"; then ok "$name"; else bad "$name (rc=$rc)"; show "$out"; fi
}

GHTOK="ghp_$(alnum 36)"
HEX32=$(rnd 16)
P="$(alnum 14)7q"     # letters and a digit, like a real password
expect_block "GitHub token"           a.txt "token is $GHTOK" "credential pattern"
expect_block "export NAME=secret"     b.sh  "export API_TOKEN=$(alnum 24)" "secret-looking assignment"
expect_block "32-hex setup token"     c.txt "setup $HEX32" "bare hex token"
expect_block "64-hex generated secret" d.txt "value $(rnd 32)" "bare hex token"
expect_block "uppercase hex"          c2.txt "ntlm $(rnd 16 | tr a-f A-F)" "bare hex token"
expect_block "password in URL"        e.yml "url: postgres://admin:$(alnum 12)@db/x" "credentials in a URL"
expect_block "yaml password (quoted)" f.yml "password: \"$(alnum 16)\"" "secret-looking key/value"
expect_block "yaml password (bare)"   f2.yaml "db_password: $(alnum 16)" "secret-looking key/value"
expect_block "bearer header"          f3.md "curl -H 'Authorization: Bearer $(alnum 30)'" "credential pattern"
expect_block "live scope address"     g.md  "found 203.0.113.45 open" "live scope"
expect_block "deny-list entry"        g2.md "report for Acme-Widgets inc" "never-commit.txt"
expect_block "home folder path"       g3.md "see /Us""ers/jdoe/Desktop/x" "/Users/<name>/"
expect_block "env path"               env/x "anything" "never committed"
expect_block ".env.local"             app/.env.local "X=1" "never committed"
expect_block "OPERATIONS.md"          OPERATIONS.md "notes" "never committed"
expect_block "Operations.md (case)"   docs/Operations.md "notes" "never committed"
expect_block "api token file"         pentagi-api-token "x" "never committed"
expect_block "pem file"               certs/server.PEM "x" "never committed"
expect_block "ssh key file"           id_ed25519 "x" "never committed"
expect_block "private key header"     k.txt "-----BEGIN OPENSSH PRIV""ATE KEY-----" "credential pattern"
expect_block "file name with spaces"  "my notes.txt" "$GHTOK" "credential pattern"
printf 'a\000b\n' > blob.dat; git add blob.dat
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" 'binary file' && ok "binary file" || { bad "binary file (rc=$rc)"; show "$out"; }
git rm -q --cached -f blob.dat; rm -f blob.dat

expect_pass "generators are fine"     h.env.example "COOKIE_SIGNING_SALT=@hex32
PASSWORD=\${PW}"
expect_pass "digests are fine"        i.json "\"sha256\": \"$(rnd 32)\""
expect_pass "image pins are fine"     j.lock "X=img@sha256:$(rnd 32)"
expect_pass "lab addresses are fine"  l.md "DVWA at 172.30.0.10"
expect_pass "other addresses are fine" m.md "docs use 198.51.100.7"
expect_pass "token file paths are fine" m2.yml "token_file: /run/secrets/token-value-here"
expect_pass "shared folder is fine"   m3.md "/Users/Shared/secstack and \$HOME/GitHub"

# ---- 1. secrets under obvious names, in the shapes this repo actually holds ----
expect_block "compose list-form env"  compose.yml "services:
  db:
    environment:
      - POSTGRES_PASSWORD=$P" "POSTGRES_PASSWORD = ****"
expect_block "Dockerfile ENV"         Dockerfile "ENV DB_PASSWORD=$P" "DB_PASSWORD = ****"
expect_block "Dockerfile ENV (legacy)" Dockerfile "ENV DB_PASSWORD $P" "DB_PASSWORD = ****"
expect_block "markdown password: x"   tpl.md "Login with password: $P" "secret-looking"
expect_block "markdown at line start" tpl2.md "password: $P" "password = ****"
expect_block "lowercase shell var"    run.sh "password=$P" "password = ****"
expect_block "DB_PASS (short name)"   app-settings.txt "DB_PASS=$P" "DB_PASS = ****"
expect_block "nxc -p"                 n1.sh "nxc smb 10.0.0.5 -u administrator -p '$P'" "password on a command line"
expect_block "curl -u user:pass"      n2.sh "curl -u admin:$P http://portal.local/" "password on a command line"
expect_block "mysql -pPASS"           n3.sh "mysql -uroot -p$P app" "password on a command line"
expect_block "--password=PASS"        n4.md "tool --password=$P --verbose" "password on a command line"
expect_block "impacket target"        n5.md "secretsdump.py corp.local/administrator:$P@10.0.0.5" "password on a command line"
expect_block "exclusion is per match" o.json "{\"client_secret\": \"$P\", \"redirect_url\": \"https://x/cb\"}" "client_secret = ****"
expect_block "comment says example"   k.yml "api_key: $P  # see https://example.com/docs" "api_key = ****"
expect_block "escaped JSON quotes"    nb.ipynb "{\"source\": [\"password = \\\"$P\\\"\\n\"]}" "password = ****"
expect_block "hex with commit later"  hx.txt "setup token $HEX32 (paste it before the first commit)" "bare hex token"
expect_block "a hash labeled hash"    hx2.md "Administrator NT hash: $(rnd 16)" "bare hex token"
expect_pass  "digest labels are fine" hx3.md "sha256sum: $(rnd 32)
- \"digest\": \"sha256:$(rnd 32)\"
pip install x --hash=sha256:$(rnd 32)"
expect_block "YAML block scalar"      bs.yml "db:
  password: |
    $P" "password = ****"
expect_block "connection string"      cs.json "{\"Db\": \"Server=x;Database=y;User Id=sa;Password=$P;\"}" "Password = ****"
expect_block "URL query token"        u.md "https://api.example.net/v1/items?api_key=$P$P" "api_key = ****"
expect_pass "code reads a variable"   n6.md "password = os.environ[\"PW\"]"
expect_pass "placeholders are fine"   n7.yml "password: changeme
api_key: YOUR_API_KEY_HERE
token: \${TOKEN}
secret: <set me>"
expect_pass "ports and paths aren't passwords" n8.sh "ssh -p 2222 host
mkdir -p /usr/local/share/secstack
docker run -p 8080:80 img"
expect_pass "image refs aren't impacket targets" n9.lock "PG=library/postgres:16-alpine-x@sha256:$(rnd 32)"
expect_pass "model settings aren't secrets" n10.yml "max_tokens: 8192
tokenizer: some-model-name-here"
expect_pass "words ending in sk- aren't keys" n11.md "see risk-assessment-template-for-clients"
expect_pass "test values in code"      n12.py "TOKEN = \"0123456789abcdef\" * 4
OTHER = \"placeholder-test-token\""
expect_pass "file names aren't secrets" n13.sh "echo \"check-secrets: scripts/check-secrets.sh not found\"
secrets: see docs/REBUILD.md and config.yaml
password_file: /run/secrets/db
token: /var/run/secrets/serviceaccount/token"
expect_block "base64 secret with slashes" n14.ini "aws_secret_access_key = $(alnum 12)/$(alnum 7)/$(alnum 19)" "aws_secret_access_key = ****"

# ---- 2. deny-list: names however they're written, past targets as networks, paths, messages ----
printf '# client names\n  acme-widgets  \nSoci\303\251t\303\251 G\303\251n\303\251rale\n198.51.100.0/24\n192.0.2.7\n' > "$DN"
expect_block "deny: space instead of -" d1.md "report for Acme Widgets" "never-commit.txt"
expect_block "deny: no-break space"     d2.md "$(printf 'report for Acme\302\240Widgets')" "never-commit.txt"
expect_block "deny: underscores"        d3.md "acme_widgets_portal" "never-commit.txt"
expect_block "deny: NFD accents"        d4.md "$(printf 'client: Socie\314\201te\314\201 Ge\314\201ne\314\201rale')" "never-commit.txt"
expect_block "deny: unaccented"         d5.md "client: SOCIETE GENERALE" "never-commit.txt"
expect_block "deny: CIDR entry"         d6.md "past target 198.51.100.77 had SMB signing off" "never-commit.txt"
expect_pass  "deny: address entry is exact" d7.md "192.0.2.70 is someone else"
expect_block "deny: address entry"      d8.md "past target 192.0.2.7" "never-commit.txt"
expect_block "deny: name wrapped across lines" d9.md "report for Acme
Widgets team" "never-commit.txt"
expect_block "deny: in a folder name"   "Acme Widgets/notes.md" "nothing here" "path matches"
expect_block "deny: in a file name"     "notes-acme-widgets.md" "nothing here" "path matches"
printf 'Fix scope for the Acme Widgets engagement\n\n# Please enter the commit message\n' > "$T/msg1"
refuses "deny: commit message" "commit message: matches" bash "$H" --commit-msg "$T/msg1"
printf 'Fix the scope parser\n\n# Please enter the commit message for your changes. Lines starting\n# with %s will be ignored, and an empty message aborts the commit.\n# acme-widgets/notes.md (a comment git drops)\n# ------------------------ >8 ------------------------\nacme-widgets diff below the scissors\n' "'#'" > "$T/msg2"
bash "$H" --commit-msg "$T/msg2" >/dev/null 2>&1 && ok "message: comments and scissors ignored" || bad "message comments checked"
printf 'Add token %s\n' "$GHTOK" > "$T/msg3"
refuses "message: credential" "credential pattern" bash "$H" --commit-msg "$T/msg3"
printf '# client names\n  acme-widgets  \n' > "$DN"

# ---- 3. live scope: client ranges in 172.30/16, leading zeros, defanged and hostname forms ----
printf '203.0.113.0/24 # client\n172.30.0.8/29 lab\n172.30.5.0/24 # client B\n' > "$SC"
expect_block "scope: client range in 172.30/16" s1.md "found 172.30.5.20 open" "live scope"
expect_pass  "scope: the lab stays fine"   s2.md "DVWA at 172.30.0.10, Juice Shop 172.30.0.11"
expect_block "scope: leading zeros"        s3.md "found 203.000.113.045 open" "live scope"
expect_block "scope: defanged"             s4.md "IOC 203.0.113[.]45 and hxxp://203[.]0[.]113[.]46/" "live scope"
expect_block "scope: dashed hostname"      s5.md "host ip-203-0-113-45.ec2.internal" "live scope"
expect_block "scope: in a hostname"        s6.md "app.203.0.113.45.nip.io" "live scope"
expect_block "scope: in a path"            scans/203.0.113.45.nmap "nothing" "path holds a live scope address"
expect_pass  "scope: not inside longer numbers" s7.md "v1203.0.113.45 and 203.0.113.45.6 and 1.3.6.1.203.0.113.45"
printf '203.0.113.0/24 # client\n172.30.0.0/16 # client C\n' > "$SC"
expect_pass  "scope: hexstrike-net and the lab on it stay fine" s8.md "HexStrike at 172.30.1.5, DVWA also at 172.30.1.10"
expect_block "scope: next to the reserved networks"           s9.md "found 172.30.2.7 open" "live scope"
printf '203.0.113.0/24 # client\n172.30.0.8/29 lab\n' > "$SC"

# ---- 4. fails closed ----
stage f4.md "found 203.0.113.45 open"
refuses "no runtime root: refuses" "runtime root" env SECOPS="$T/nowhere" bash "$H"
refuses "no runtime root (default ~/GitHub/.sec-ops): refuses" "runtime root" env -u SECOPS bash "$H"
git config secstack.secops "$T/sec"
refuses "root recorded in git config is used" "live scope" env -u SECOPS bash "$H"
git config secstack.secops "$T/gone"
refuses "recorded root that can't be read: refuses" "runtime root" env -u SECOPS bash "$H"
git config --unset secstack.secops
mv "$DN" "$DN.real"; ln -s "$T/nowhere/list" "$DN"
refuses "unreadable deny-list: refuses" "can't read" bash "$H"
rm "$DN"; mv "$DN.real" "$DN"
mv "$SC" "$SC.real"; mkdir "$SC"
refuses "unreadable scope file: refuses" "can't read" bash "$H"
rmdir "$SC"; mv "$SC.real" "$SC"
mkdir -p "$T/nopy"; for t in git bash dirname basename readlink env; do ln -sf "$(command -v "$t")" "$T/nopy/$t"; done
refuses "python3 missing: refuses" "python3 not found" env PATH="$T/nopy" bash "$H"
refuses "git failing: refuses" "git diff failed" env GIT_INDEX_FILE="$T/sec/configs/scope.cidrs" bash "$H"
unstage f4.md
stage f5.txt "token $GHTOK"
refuses "TMPDIR unusable: still checks" "credential pattern" env TMPDIR="$T/nowhere" bash "$H"
refuses "SECSTACK_NO_RUNTIME=1 still checks credentials" "credential pattern" env SECOPS="$T/nowhere" SECSTACK_NO_RUNTIME=1 bash "$H"
unstage f5.txt
stage f6.txt "nothing to see"
SECOPS="$T/nowhere" SECSTACK_NO_RUNTIME=1 bash "$H" >/dev/null 2>&1 && ok "SECSTACK_NO_RUNTIME=1 passes a clean file" || bad "NO_RUNTIME clean file"
unstage f6.txt

# ---- 5. names git would read as index stages or pathspec magic ----
expect_block "root file named 1:1"    "1:1 notes.md" "token $GHTOK" "credential pattern"
expect_block "root file named 0:x"    "0:x.txt" "found 203.0.113.45 open" "live scope"
ln -s /etc ':evil'; git add -- ./:evil
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" 'outside the repo' && ok "symlink named :evil" || { bad "symlink :evil (rc=$rc)"; show "$out"; }
git rm -q --cached -- ./:evil; rm ./:evil
printf 'x\n' > a1; git add a1; git commit -qm a1 --no-verify; ln -s /etc 'a[1]'; git add -- './a[1]'
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" 'outside the repo' && ok "symlink with glob characters" || { bad "symlink a[1] (rc=$rc)"; show "$out"; }
git rm -q --cached -- './a[1]'; rm './a[1]'

# ---- 6. filters (git-lfs): the hook can't see the real content ----
git config filter.fake.clean cat; git config filter.fake.smudge cat; printf '*.pdf filter=fake\n' > .gitattributes; git add .gitattributes
expect_block "filter attribute"       report.pdf "token $GHTOK" "stored through a filter"
git rm -q --cached .gitattributes; rm .gitattributes
expect_block "LFS pointer"            r2.pdf "version https://git-lfs.github.com/spec/v1
oid sha256:$(rnd 32)
size 12" "stored through a filter"
if command -v git-lfs >/dev/null 2>&1; then
  git lfs install --local >/dev/null 2>&1; git lfs track '*.zip' >/dev/null; git add .gitattributes
  expect_block "git-lfs tracked file"  loot.zip "token $GHTOK" "stored through a filter"
  git rm -q --cached .gitattributes; rm .gitattributes; git lfs uninstall --local >/dev/null 2>&1
fi

# ---- 7. masking: only paths, line numbers and key names are ever printed ----
V=$(alnum 24); HASH=$(rnd 16); AKID="AKIA$(python3 -c 'import secrets,string; print("".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(16)))')"
printf 'token %s\nexport API_TOKEN=%s\nsetup %s\n' "$GHTOK" "$V" "$HEX32" > o.txt
printf '%s:Winter2024!\n%s:x-oauth-basic\n%s:%s\n' "$HASH" "$GHTOK" "$AKID" "$(alnum 40)" > cracked.txt
printf 'export ACME_WIDGETS_TOKEN=%s\nfound 203.0.113.77 open\nreport for Acme Widgets\nsee /Us''ers/jdoe/x\n' "$V" > m.txt
mkdir -p "Acme Widgets"; printf 'x\n' > "Acme Widgets/n.md"; printf 'x\n' > "scans-203.0.113.78.txt"
git add o.txt cracked.txt m.txt "Acme Widgets/n.md" "scans-203.0.113.78.txt"
out=$(hook)
if grep -iF -e "$GHTOK" -e "$V" -e "$HEX32" -e "$HASH" -e "$AKID" -e "${GHTOK:4:12}" -e "${V:3:12}" \
     -e "203.0.113.7" -e "acme" -e "widgets" -e "jdoe" -e "$T" >/dev/null <<EOF
$out
EOF
then
  bad "a value was printed"; show "$out"
else ok "values, names, addresses and users masked in output"; fi
has "$out" 'API_TOKEN = ****' && ok "masked output still names the key" || bad "key not shown"
has "$out" 'BLOCKED ****/n.md' && ok "client name in a path masked" || { bad "path not masked"; show "$out"; }
git rm -q --cached o.txt cracked.txt m.txt "Acme Widgets/n.md" "scans-203.0.113.78.txt"; rm -rf o.txt cracked.txt m.txt "Acme Widgets" scans-203.0.113.78.txt

# ---- 8. never-commit paths (case, variants, trailing spaces) and .gitignore ----
for f in .env-prod .env_local env.prod "prod.env.json" ".env " "OPERATIONS.md " backup/configs/scope.cidrs .envrc \
         hashes.pot .netrc .git-credentials .pgpass key.ppk session.har id_dsa "server.key."; do
  expect_block "never-commit path [$f]" "$f" "harmless" "never committed"
done
expect_pass "env.overrides is fine"   upstream/x/env.overrides "OLLAMA_SERVER_URL=http://host.docker.internal:11434"
expect_pass "env.py is fine"          scripts/env.py "import os"
for f in .env-prod env.prod prod.env.json backup/configs/scope.cidrs .netrc hashes.pot; do
  git check-ignore -q --no-index -- "$f" && ok ".gitignore covers $f" || bad ".gitignore misses $f"
done
for f in upstream/pentagi/env.overrides scripts/env.py x.env.example; do
  git check-ignore -q --no-index -- "$f" && bad ".gitignore wrongly ignores $f" || ok ".gitignore keeps $f"
done

# Modified and renamed files are scanned too.
printf 'clean line\ntoken %s\n' "$GHTOK" > q.txt; git add q.txt
hook >/dev/null && bad "modified file not scanned" || ok "modified file scanned"
git checkout -q HEAD -- q.txt
git mv r1.txt r2.txt; printf 'notes\npassword = "%s"\n' "$(alnum 14)" > r2.txt; git add r2.txt
hook >/dev/null && bad "renamed file not scanned" || ok "renamed file scanned"
git mv -f r2.txt r1.txt; git checkout -q HEAD -- r1.txt
# A rename or a copy to a deny-listed name is a new path (git status R and C, not only A).
git mv r1.txt acme-widgets-report.txt
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" "path matches" && ok "a rename to a deny-listed name is refused" || { bad "rename to a client name (rc=$rc)"; show "$out"; }
git mv -f acme-widgets-report.txt r1.txt
printf '# local\n' >> .gitignore; cp .gitignore acme-widgets-ignore.txt; git add .gitignore acme-widgets-ignore.txt
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" "path matches" && has "$(git diff --cached -M -C --name-only --diff-filter=C)" "acme-widgets-ignore.txt" \
  && ok "a copy to a deny-listed name is refused" || { bad "copy to a client name (rc=$rc)"; show "$out"; }
git rm -q --cached -f acme-widgets-ignore.txt; rm -f acme-widgets-ignore.txt; git checkout -q HEAD -- .gitignore

# Symlinks: checked by path and target, never followed.
printf 'token %s\n' "$GHTOK" > "$T/outside.txt"
ln -s "$T/outside.txt" lnk; git add lnk
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" 'outside the repo' && ! has "$out" 'credential pattern' \
  && ok "symlink out of the repo blocked, target not read" || { bad "symlink handling (rc=$rc)"; show "$out"; }
out=$(hook --all); rc=$?
[ $rc -eq 1 ] && has "$out" 'outside the repo' && ! has "$out" 'credential pattern' \
  && ok "--all doesn't follow symlinks" || { bad "--all symlink (rc=$rc)"; show "$out"; }
git rm -q --cached -f lnk; rm -f lnk
ln -s ../../.sec-ops/env/pentagi-api-token rel; git add rel
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" 'outside the repo' && ok "relative symlink escape blocked" || { bad "relative escape (rc=$rc)"; show "$out"; }
git rm -q --cached -f rel; rm -f rel
ln -s q.txt inside; git add inside
hook >/dev/null && ok "symlink inside the repo is fine" || bad "symlink inside the repo blocked"
git rm -q --cached -f inside; rm -f inside

# The staged content is what counts: cleaning the working tree after `git add` doesn't hide it.
printf 'token %s\n' "$GHTOK" > n.txt; git add n.txt; printf 'clean\n' > n.txt
hook >/dev/null && bad "staged secret hidden by a clean working tree" || ok "scans the index, not the working tree"
git rm -q --cached -f n.txt; rm -f n.txt

# ---- 9. every hook: commit, merge, am, commit-msg and push (commits made with --no-verify) ----
for name in pre-commit pre-merge-commit pre-applypatch commit-msg applypatch-msg pre-push; do
  printf '#!/bin/sh\nexec bash "$(git rev-parse --show-toplevel)/scripts/check-secrets.sh" --hook "${0##*/}" "$@"\n' > ".git/hooks/$name"
  chmod +x ".git/hooks/$name"
done
printf 'token %s\n' "$GHTOK" > t9.txt; git add t9.txt
git commit -qm t9 >/dev/null 2>&1 && bad "pre-commit let a token through" || ok "pre-commit blocks"
git rm -q --cached -f t9.txt; rm -f t9.txt
printf 'x\n' > c9.txt; git add c9.txt
git commit -qm "notes for the Acme Widgets job" >/dev/null 2>&1 && bad "commit-msg let a client name through" || ok "commit-msg blocks"
git commit -qm "c9" >/dev/null 2>&1 && ok "a clean commit goes through" || bad "clean commit blocked"
git checkout -qb side; printf 'token %s\n' "$GHTOK" > s9.txt; git add s9.txt; git commit -qm s9 --no-verify; git checkout -q main
git merge -q --no-ff --no-edit side >/dev/null 2>&1 && bad "pre-merge-commit let a token through" || ok "pre-merge-commit blocks"
git merge --abort >/dev/null 2>&1; git reset -q --hard
git format-patch -q -1 -o "$T/p" side
git am -q "$T/p"/*.patch >/dev/null 2>&1 && bad "pre-applypatch let a token through" || ok "pre-applypatch blocks"
git am --abort >/dev/null 2>&1; git reset -q --hard
git init -q --bare "$T/remote.git"; git -C "$T/remote.git" symbolic-ref HEAD refs/heads/main; git remote add origin "$T/remote.git"
git push -q origin main >/dev/null 2>&1 && ok "pre-push: clean push goes through" || bad "clean push blocked"
printf 'token %s\n' "$GHTOK" > p9.txt; git add p9.txt; git commit -qm p9 --no-verify
git push -q origin main >/dev/null 2>&1 && bad "pre-push let a --no-verify commit through" || ok "pre-push blocks a --no-verify commit"
git reset -q --hard HEAD~1
printf 'y\n' > p10.txt; git add p10.txt; git commit -qm "scope for Acme Widgets" --no-verify
git push -q origin main >/dev/null 2>&1 && bad "pre-push let a client name in a message through" || ok "pre-push checks messages"
git reset -q --hard HEAD~1
git push -q origin side >/dev/null 2>&1 && bad "pre-push let a new branch through" || ok "pre-push checks new branches"
git push -q origin main:refs/heads/acme-widgets-q3 >/dev/null 2>&1 && bad "pre-push let a client-named branch through" || ok "pre-push checks ref names"
printf 'z\n' > p11.txt; git add p11.txt; GIT_AUTHOR_EMAIL=me@acme-widgets.example git commit -qm p11 --no-verify
git push -q origin main >/dev/null 2>&1 && bad "pre-push let a client address in the author through" || ok "pre-push checks author and committer"
git reset -q --hard HEAD~1
git push -q --no-verify origin side >/dev/null 2>&1; git push -q origin --delete side >/dev/null 2>&1 \
  && ok "pre-push: deleting a branch is fine" || bad "branch delete blocked"
# ---- 10. added lines only, whole words, placeholders, code files, messages, tags ----
has_ci(){ grep -iF -- "$2" >/dev/null <<EOF2
$1
EOF2
}
# Scope and the deny-list are checked on the lines a change adds (already-public lines don't block an
# unrelated edit, a push or a pull); --all still checks whole files.
printf 'allow 10.9.0.0/24 and 10.9.0.6\nnotes from Zentro Labs\n' > fw.txt; git add fw.txt
git commit -qm fw --no-verify; git push -q --no-verify origin main
printf '10.9.0.0/24 # client D\n' >> "$SC"; printf 'Zentro Labs\n' >> "$DN"
printf 'more notes\n' >> fw.txt; git add fw.txt
out=$(hook); rc=$?
[ $rc -eq 0 ] && ok "added lines: old in-scope lines don't block an edit" || { bad "old lines rechecked (rc=$rc)"; show "$out"; }
git commit -qm notes >/dev/null 2>&1 && git push -q origin main >/dev/null 2>&1 && ok "added lines: the commit and push go through" || bad "unrelated edit blocked at commit or push"
printf 'new target 10.9.0.20\n' >> fw.txt; git add fw.txt
out=$(hook); rc=$?; [ $rc -eq 1 ] && has "$out" "live scope" && ok "added lines: a new in-scope line is caught" || { bad "new scope line (rc=$rc)"; show "$out"; }
git reset -q --hard; printf 'call with zentro labs\n' >> fw.txt; git add fw.txt
out=$(hook); rc=$?; [ $rc -eq 1 ] && has "$out" "never-commit.txt" && ok "added lines: a new deny-list line is caught" || { bad "new deny line (rc=$rc)"; show "$out"; }
git reset -q --hard
out=$(hook --all); rc=$?; [ $rc -eq 1 ] && has "$out" "fw.txt: live scope" && ok "added lines: --all still checks whole files" || { bad "--all whole file (rc=$rc)"; show "$out"; }
git clone -q -b main "$T/remote.git" "$T/other"
(cd "$T/other" && printf 'reject 10.9.0.0/24 for Zentro Labs\n' > up.txt && git add up.txt && git commit -qm up --no-verify && git push -q --no-verify origin main)
printf 'local\n' > loc.txt; git add loc.txt; git commit -qm loc >/dev/null 2>&1
git pull -q --no-rebase --no-edit origin main >/dev/null 2>&1 && [ -f up.txt ] && ok "added lines: pulling public content isn't blocked" || { bad "pull blocked"; git merge --abort >/dev/null 2>&1; }
git checkout -qb s12; printf 'x\n' > m12.txt; git add m12.txt; git commit -qm s12 --no-verify; git checkout -q main
git merge -q --no-ff --no-commit s12 >/dev/null 2>&1; printf 'target 10.9.0.30\n' >> m12.txt; git add m12.txt
git commit -qm merge >/dev/null 2>&1 && bad "a merge's own in-scope line got through" || ok "added lines: a merge's own new lines are checked"
git merge --abort >/dev/null 2>&1; git reset -q --hard; git branch -q -D s12
printf '203.0.113.0/24 # client\n172.30.0.8/29 lab\n' > "$SC"

# Deny-list entries match whole words (or the words run together), never inside other words.
printf 'Qvx\nQ&Z\nZentro Labs\n' > "$DN"
expect_pass  "deny: not inside a longer word"     w1.md "see GitHub/aqvxz/secstack and zentrolabsy"
expect_block "deny: a whole word"                 w2.md "notes on qvx systems" "never-commit.txt"
expect_pass  "deny: one-letter words alone"       w3.md "\"created_q\": z.get(\"x\")"
expect_block "deny: one-letter words as written"  w4.md "the Q&Z contract" "never-commit.txt"
expect_block "deny: words run together"           w5.md "ZentroLabs portal" "never-commit.txt"
expect_pass  "deny: joined forms don't split other words" w6.md "subQvxs, AqvxZ, Qvxs2, zentrolabsy2, LabsZentro
grep -q -z, x = q+z, seq z, getQz, qz1"
# ... and joined to another word at a capital or a digit, or spaced differently (real names assembled
# at run time, so this file never holds them)
DOTS="J.P. Mor""gan"; AMP="A""T&T"
printf 'Zentro Labs\nacme-widgets\n%s\n%s\n' "$DOTS" "$AMP" > "$DN"
expect_block "deny: joined to a capitalized word"  w7.md "see AcmeWidgetsReport.docx" "never-commit.txt"
expect_block "deny: joined to digits"              w8.md "host acmewidgets01.corp.local" "never-commit.txt"
expect_block "deny: digits after the last word"    w9.md "host acme-widgets2024" "never-commit.txt"
expect_block "deny: joined to Q3"                  w10.md "ZentroLabsQ3 kickoff" "never-commit.txt"
expect_block "deny: in a camelCase name"           w11.md "zentroLabsClient = 1" "never-commit.txt"
expect_block "deny: joined, in a file name"        "AcmeWidgetsReport.docx" "nothing here" "path matches"
expect_block "deny: one-letter words spaced"       w12.md "jp mor""gan" "never-commit.txt"
expect_block "deny: one-letter words around &"     w13.md "A""T & T contract" "never-commit.txt"
printf '3X\n' > "$DN"
expect_pass  "deny: digits stay whole numbers"     w14.md "python3 -x and Q3X"
expect_block "deny: a digit entry joined to a word" w15.md "see 3XReport.docx" "never-commit.txt"
printf 'Soci\303\251t\303\251 G\303\251n\303\251rale\nAcme Widgets\n' > "$DN"
printf 'Soci\351t\351 G\351n\351rale,AD tiering weak\n' > clients.csv; git add clients.csv
out=$(hook); rc=$?; [ $rc -eq 1 ] && has "$out" "never-commit.txt" && ok "deny: a cp1252 file" || { bad "cp1252 name (rc=$rc)"; show "$out"; }
git rm -q --cached clients.csv; rm -f clients.csv
printf 'Notes: Soci\351t\351 G\351n\351rale\n' > "$T/msg6"
refuses "deny: a Latin-1 commit message" "commit message: matches" bash "$H" --commit-msg "$T/msg6"
expect_block "deny: URL-encoded"   link.md "https://contoso.sharepoint.com/sites/eng/Acme%20Widgets/Report.docx" "never-commit.txt"
expect_block "deny: HTML entities" link2.html "<p>Acme&#32;Widgets</p>" "never-commit.txt"

# Placeholders and well-known values aren't secrets; the same shapes with real values are.
expect_pass "URL whose password is the user name" u1.md 'DATABASE_URL=postgres://postgres:postgres@db:5432/app'
expect_pass "URL with a placeholder password"     u2.md 'format: scheme://user:password@host'
expect_pass "placeholder key"                     u3.md 'export OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
expect_pass "documentation key"                   u4.md 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE'
expect_pass "the empty NT hash"                   u5.md 'empty NT hash 31d6cfe0d16ae931b73c59d7e0c089c0'
expect_pass "an md5 checksum"                     u6.md 'md5: 5d41402abc4b2a76b9719d911017c592'
expect_pass "a Terraform lock hash"               .terraform.lock.hcl "    \"zh:$(rnd 32)\","

# Code files: assignments in strings, comments and getenv defaults count; references don't.
expect_block "code: assignment in a string"  tests/test_env.py "ENV = \"PENTAGI_PASSWORD=$P\\n\"" "PENTAGI_PASSWORD = ****"
expect_block "code: assignment in a comment" t2.py "# debug: PENTAGI_PASSWORD=$P" "PENTAGI_PASSWORD = ****"
expect_block "code: getenv default"          app.py "pw = os.getenv(\"DB_PASS\", \"$P\")" "DB_PASS = ****"
expect_pass  "code: references aren't literals" c1.py "password = get_password()
token = self._token
api_key=api_key
secret = sorted(set(keys) & other)
_TOKEN = _token.encode(\"ascii\")"

# More credential shapes.
expect_block "Groq key (gsk_)"          g1.md "groq gsk_$(alnum 52)" "credential pattern"
expect_block "*_KEY name"               upstream/y/env.overrides "LLM_SERVER_KEY=$(alnum 38)7q" "LLM_SERVER_KEY = ****"
expect_block "password with brackets"   g3.env.example "ADMIN_PASSWORD=$(alnum 3)7#$(alnum 3)($(alnum 5)" "ADMIN_PASSWORD = ****"
expect_block "recon key list"           p.yaml "shodan:
  - $(alnum 30)7q" "shodan = ****"
expect_block "XML element"              s.xml "<config><password>$P</password></config>" "password = ****"
expect_block "YAML flow map"            fm.yml "db: {user: admin, password: $P}" "password = ****"
expect_block "long --*-password option" lo.md "docker exec pentagi ./setup --admin-password $P" "password on a command line"
expect_pass  "--password-file and flags" lo2.md "tool --password-file /run/secrets/db --no-password --verbose"
expect_pass  "slugs and ids under *_key"  k1.yml "cache_key: user-profile-settings-v2
sort_key: created_at"
printf 'fix: admin NT hash was %s\n' "$(rnd 16)" > "$T/msg7"
refuses "message: hex" "bare hex token" bash "$H" --commit-msg "$T/msg7"

# Lab tool shapes: an impacket target with no domain, Metasploit set, registry logins, openssl, redis,
# Docker's config.json and .netrc lines. The same shapes with placeholders pass.
expect_block "impacket target, no domain" lt1.md "impacket-psexec administrator:$P@192.0.2.10" "password on a command line"
expect_block "Metasploit set PASSWORD"    lt2.rc "set PASSWORD $P" "PASSWORD = ****"
expect_block "Metasploit setg SMBPass"    lt3.rc "setg SMBPass $P" "SMBPass = ****"
expect_block "msfconsole -x set"          lt4.sh "msfconsole -q -x \"use exploit/windows/smb/psexec; set SMBUser admin; set SMBPass $P; run\"" "SMBPass = ****"
expect_block "Metasploit console prompt"  lt12.md "msf6 exploit(windows/smb/psexec) > set SMBPass $P" "SMBPass = ****"
expect_block "Metasploit in \`code\`"      lt13.md "Run \`setg PASSWORD $P\` first" "PASSWORD = ****"
expect_block "redis-cli -a in \`code\`"    lt14.md "Run \`redis-cli -a $P\` first" "password on a command line"
expect_block "docker login -p"            lt5.md "docker login -u robot -p $P ghcr.io" "password on a command line"
expect_block "docker login --password"    lt6.md "docker login -u robot --password $P ghcr.io" "password on a command line"
expect_block "openssl pass:"              lt7.md "openssl pkcs12 -export -in c.pem -passout pass:$P -out c.p12" "password on a command line"
expect_block "redis-cli -a"               lt8.md "redis-cli -h 127.0.0.1 -a $P ping" "password on a command line"
expect_block "Docker config.json auth"    lt9.json "{\"auths\":{\"ghcr.io\":{\"auth\":\"$(b64 "robot:$P")\"}}}" "auth = ****"
expect_block "netrc line in a heredoc"    lt10.sh "cat > ~/.netrc <<EOF
machine git.corp.example login robot password $P
EOF" "password = ****"
expect_pass  "lab tool shapes with placeholders" lt11.md "impacket-psexec administrator:\$ADMIN_PASS@192.0.2.10
psexec.py administrator:changeme@192.0.2.11
set PASSWORD <password>
setg SMBPass changeme
set PASSWORD x
msf6 exploit(windows/smb/psexec) > set SMBPass <password>
msfconsole -q -x \"use exploit/windows/smb/psexec; set SMBPass \${SMB_PASS}; run\"
Run \`redis-cli -a \$REDIS_PASSWORD\` first
docker login -u robot -p \$REGISTRY_TOKEN ghcr.io
docker login -u robot --password \${REGISTRY_TOKEN} ghcr.io
docker run -p 8080:80 -p 443:443 img
openssl pkcs12 -export -in c.pem -passout pass:\$PW -out c.p12
openssl pkcs12 -export -in c.pem -passout pass:example -out c.p12
redis-cli -a xxx ping
redis-cli -a \"\$REDIS_PASSWORD\" ping
{\"auths\":{\"ghcr.io\":{\"auth\":\"<base64>\"}}}
\"auth\": \"$(b64 robot:changeme)\"
machine git.corp.example login robot password \${GIT_TOKEN}
machine git.corp.example login robot password <token>"

# Messages: '#' lines are dropped only under git's editor template; only the exact scissors line cuts.
printf 'acme-widgets\n' > "$DN"
printf '#12 notes for the acme-widgets job\n' > "$T/msg8"
refuses "message: # lines from -m are checked" "commit message: matches" bash "$H" --commit-msg "$T/msg8"
printf 'Fix it\n\n# Please enter the commit message for your changes. Lines starting\n# with %s will be ignored, and an empty message aborts the commit.\nretry >8 times\nacme-widgets below\n' "'#'" > "$T/msg9"
refuses "message: '>8' in a line isn't the scissors" "commit message: matches" bash "$H" --commit-msg "$T/msg9"
git checkout -qb s13; printf 'hi\n' > b13.txt; git add b13.txt; git commit -qm "acme-widgets findings" --no-verify
git format-patch -q -1 -o "$T/p13"; git checkout -q main
git am -q "$T/p13"/*.patch >/dev/null 2>&1 && bad "applypatch-msg let a client name through" || ok "applypatch-msg checks git am messages"
git am --abort >/dev/null 2>&1; git reset -q --hard; git branch -q -D s13

# .pre-commit-config.yaml isn't an install backup; *.pre-repo-* is.
expect_pass  ".pre-commit-config.yaml is fine" .pre-commit-config.yaml "repos: []"
git check-ignore -q --no-index -- .pre-commit-config.yaml && bad ".gitignore ignores .pre-commit-config.yaml" || ok ".gitignore keeps .pre-commit-config.yaml"
expect_block "install backups are never committed" "bin.pre-repo-20251121-101010/x" "x" "never committed"

# Masking: git's errors, a name split across folder and file, the runtime path.
mkdir acme-widgets; printf 'hi\n' > acme-widgets/n.md; git add acme-widgets/n.md; rm -f acme-widgets/n.md; rmdir acme-widgets; ln -s "$T" acme-widgets
out=$(hook); rc=$?
[ $rc -eq 1 ] && ! has_ci "$out" "acme" && ok "masking: git's error text isn't echoed" || { bad "git stderr echoed (rc=$rc)"; show "$out"; }
git rm -q --cached acme-widgets/n.md; rm -f acme-widgets
printf 'Zentro Labs\n' > "$DN"; mkdir zentro; printf 'hi\n' > zentro/labs.md; git add zentro/labs.md
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" "BLOCKED ****: path matches \$SECOPS/configs/never-commit.txt" && ! has_ci "$out" "zentro" && ! has "$out" "$T" \
  && ok "masking: a name split across folder and file, and the runtime path" || { bad "split name or runtime path shown (rc=$rc)"; show "$out"; }
git rm -q --cached zentro/labs.md; rm -f zentro/labs.md; rmdir zentro

# Long lines stay fast (the URL pattern was quadratic).
python3 -c 'print("a" * 400000)' > long.txt; git add long.txt
t0=$(date +%s); hook >/dev/null; t1=$(date +%s)
[ $((t1 - t0)) -lt 30 ] && ok "a 400k-character line is checked in $((t1 - t0))s" || bad "a 400k-character line took $((t1 - t0))s"
git rm -q --cached long.txt; rm -f long.txt
# ... and long values: trailing \n escapes and closers were stripped one by one (an 80 KB line took 27s).
python3 -c 'import sys; sys.stdout.write("cfg=" + "\\n" * 100000 + "end\ncfg: x" + ")" * 200000 + "\n")' > long2.md; git add long2.md
t0=$(date +%s); hook >/dev/null; t1=$(date +%s)
[ $((t1 - t0)) -lt 5 ] && ok "two 200 KB values are checked in $((t1 - t0))s" || bad "two 200 KB values took $((t1 - t0))s"
git rm -q --cached long2.md; rm -f long2.md

# Tags: every message down a nested tag, and tags of trees or blobs refused.
printf 'acme-widgets\n' > "$DN"
BL=$(printf 'token %s\n' "$GHTOK" | git hash-object -w --stdin); TR=$(printf '100644 blob %s\tloot.txt\n' "$BL" | git mktree)
git tag t1 "$TR"; git tag t2 "$BL"; git tag -a inner -m "acme-widgets notes" HEAD; git tag -a outer -m clean inner 2>/dev/null
for t in t1 t2 outer; do git push -q origin "$t" >/dev/null 2>&1 && bad "pre-push let tag $t through" || ok "pre-push checks tag $t"; done
git tag -a ok12 -m fine HEAD; git push -q origin ok12 >/dev/null 2>&1 && ok "a clean annotated tag goes through" || bad "clean tag blocked"

# Gitlinks (`git add -A` over a nested clone adds one, with no .gitmodules): the path is checked at
# commit and push; the commit it points to is another repo's and isn't read.
git init -q "$T/client"; (cd "$T/client" && printf 'x\n' > x && git add x && git commit -qm x --no-verify)
git clone -q "$T/client" acme-widgets-webapp; mkdir -p scans; git clone -q "$T/client" scans/203.0.113.5
git clone -q "$T/client" vendored-lib
git -c advice.addEmbeddedRepo=false add vendored-lib
out=$(hook); rc=$?
[ $rc -eq 0 ] && ok "a gitlink with a harmless path passes" || { bad "gitlink with a harmless path (rc=$rc)"; show "$out"; }
git rm -q --cached vendored-lib
git -c advice.addEmbeddedRepo=false add acme-widgets-webapp scans/203.0.113.5
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" "path matches" && has "$out" "path holds a live scope address" && ! has "$out" "couldn't read" \
  && ok "gitlink paths are checked at commit" || { bad "gitlink paths at commit (rc=$rc)"; show "$out"; }
git commit -qm gitlinks --no-verify
out=$(git push origin HEAD:refs/heads/gl 2>&1); rc=$?
[ $rc -ne 0 ] && has "$out" "path matches" && has "$out" "path holds a live scope address" \
  && ok "pre-push checks gitlink paths" || { bad "gitlink paths at push (rc=$rc)"; show "$out"; }
git push -q --no-verify origin --delete gl >/dev/null 2>&1; git reset -q --hard HEAD~1 2>/dev/null; rm -rf acme-widgets-webapp scans vendored-lib

# Replace refs: pre-push reads the real commits, the ones the push sends, not a `git replace` stand-in.
printf 'token %s\n' "$GHTOK" > rp.txt; git add rp.txt; git commit -qm rp --no-verify
git replace HEAD "$(git commit-tree -p HEAD~1 -m rp 'HEAD~1^{tree}')"
out=$(git push origin HEAD:refs/heads/rp 2>&1); rc=$?
[ $rc -ne 0 ] && has "$out" "rp.txt" && ok "pre-push: a replace ref doesn't hide a commit" || { bad "a replace ref hid a commit (rc=$rc)"; show "$out"; }
git push -q --no-verify origin --delete rp >/dev/null 2>&1; git replace -d "$(git rev-parse HEAD)" >/dev/null; git reset -q --hard HEAD~1

# Fail closed on an internal error; symlink targets; control characters in names.
stage ie.txt "clean"
out=$(python3 -c 'import sys; sys.path.insert(0, "scripts"); import check_secrets as c; c.scan_text = lambda *a, **k: 1 / 0; sys.exit(c.main([]))' 2>&1); rc=$?
[ $rc -eq 1 ] && has "$out" "internal error" && ok "an internal error refuses (exit 1)" || { bad "internal error rc=$rc"; show "$out"; }
unstage ie.txt
ln -s clients/acme-widgets/notes x12; git add x12
out=$(hook); rc=$?; [ $rc -eq 1 ] && has "$out" "never-commit.txt" && ok "a symlink target naming a client" || { bad "symlink target (rc=$rc)"; show "$out"; }
git rm -q --cached x12; rm -f x12
ln -s scans/203.0.113.9.txt y12; git add y12
out=$(hook); rc=$?; [ $rc -eq 1 ] && has "$out" "live scope" && ok "a symlink target holding a scope address" || { bad "symlink scope (rc=$rc)"; show "$out"; }
git rm -q --cached y12; rm -f y12
ESCNAME="$(printf 'esc\033[31mred.txt')"; printf 'token %s\n' "$GHTOK" > "./$ESCNAME"; git add -- "./$ESCNAME"
out=$(hook); rc=$?
[ $rc -eq 1 ] && has "$out" 'esc\x1b[31mred.txt' && ! has "$out" "$(printf '\033')" && ok "control characters in names are escaped" || { bad "control characters printed (rc=$rc)"; show "$out"; }
git rm -q --cached -- "./$ESCNAME"; rm -f -- "./$ESCNAME"
printf '# client names\n  acme-widgets  \n' > "$DN"
for name in pre-commit pre-merge-commit pre-applypatch commit-msg applypatch-msg pre-push; do rm -f ".git/hooks/$name"; done

# ---- 11. more credential formats ----
JWT="eyJ$(alnum 30).eyJ$(alnum 40).$(alnum 30)"
expect_block "JWT"                    f10a.txt "token: Bearer-less $JWT" "credential pattern"
expect_block "PGP private key block"  f10b.asc "-----BEGIN PGP PRIV""ATE KEY BLOCK-----" "credential pattern"
expect_block "base64 PEM (kubeconfig)" f10c.yaml "    client-key-data: $(b64 "-----BEGIN RSA PRIV""ATE KEY-----
MIIE$(alnum 40)")" "credential pattern"
expect_pass  "base64 certificate is fine" f10d.yaml "    client-certificate-data: $(b64 "-----BEGIN CERTIFICATE-----
MIIC$(alnum 40)")"
expect_block "Authorization: Basic"   f10e.http "Authorization: Basic $(b64 "admin:$P")" "credential pattern"
expect_block "Azure storage key"      f10f.txt "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=$(b64 "$(alnum 48)")" "credential pattern"
expect_block "Azure SAS signature"    f10g.md "https://a.blob.core.windows.net/c?sv=2022-11-02&sig=$(alnum 40)" "credential pattern"
expect_block "Stripe live key"        f10h.js "stripe('sk_""live_$(alnum 24)')" "credential pattern"
expect_block "SendGrid key"           f10i.txt "SG.$(alnum 22).$(alnum 43)" "credential pattern"
expect_block "npm token"              f10j.txt "npm_$(alnum 36)" "credential pattern"
expect_block "PyPI token"             f10k.txt "pypi-AgE$(alnum 40)" "credential pattern"
expect_block "Docker Hub token"       f10l.txt "dckr_pat_$(alnum 27)" "credential pattern"
expect_block "Google OAuth secret"    f10m.txt "GOCSPX-$(alnum 28)" "credential pattern"
expect_block "Slack app token"        f10n.txt "xapp-1-A0$(alnum 9)-$(alnum 13)" "credential pattern"
expect_block "sha512crypt hash"       f10o.txt "root:\$6\$$(alnum 8)\$$(alnum 86):19000:0:99999:7:::" "credential pattern"
expect_block "bcrypt hash"            f10p.txt "admin:\$2y\$10\$$(alnum 53)" "credential pattern"
expect_block "PuTTY key"              f10q.txt "PuTTY-User-Key-""File-3: ssh-ed25519" "credential pattern"

# ---- 12. --all, the guard's own files, any locale ----
printf 'harmless\n' > ./-; printf 'token %s\n' "$GHTOK" > zz.txt
out=$(hook --all); rc=$?
[ $rc -eq 1 ] && has "$out" 'zz.txt: credential pattern' && ok "--all: a file named - doesn't hide later files" || { bad "--all with - (rc=$rc)"; show "$out"; }
rm -f ./- zz.txt
printf 'token %s\n' "$GHTOK" > ./-v.txt
out=$(hook --all); rc=$?
[ $rc -eq 1 ] && has "$out" '-v.txt: credential pattern' && ok "--all: leading-dash names" || { bad "--all leading dash (rc=$rc)"; show "$out"; }
rm -f ./-v.txt
for f in scripts/check-secrets.sh scripts/check_secrets.py; do
  cp "$f" "$T/saved"; printf '# test %s\n' "$GHTOK" >> "$f"; git add "$f"
  hook >/dev/null && bad "$f is exempt from its own checks" || ok "$f is checked like any file"
  cp "$T/saved" "$f"; git add "$f"
done
printf 'Caf\351 notes token %s\n' "$GHTOK" > latin1.txt; git add latin1.txt
locales=" $(locale -a 2>/dev/null | tr 'A-Z\n' 'a-z ' | tr -d '-') "   # c.utf8 en_us.utf8 ...
for loc in C C.UTF-8 en_US.UTF-8; do
  want=$(printf '%s' "$loc" | tr 'A-Z' 'a-z' | tr -d '-')
  if [ "$loc" != C ] && ! has "$locales" " $want "; then
    echo "SKIP Latin-1 line, LC_ALL=$loc: that locale isn't installed here"; continue
  fi
  out=$(LC_ALL=$loc LANG=$loc bash "$H" 2>&1); rc=$?
  [ $rc -eq 1 ] && has "$out" 'credential pattern' && ok "Latin-1 line, LC_ALL=$loc" || { bad "Latin-1 line LC_ALL=$loc (rc=$rc)"; show "$out"; }
done
git rm -q --cached -f latin1.txt; rm -f latin1.txt
printf 'a\r\nb\rAPI_TOKEN=%s\r' "$(alnum 20)" > cr.env.example; git add cr.env.example
hook >/dev/null && bad "CR-only line endings hide an assignment" || ok "CR-only line endings"
git rm -q --cached -f cr.env.example; rm -f cr.env.example

# --all scans tracked + untracked (not ignored) files on disk
printf 'x %s\n' "$GHTOK" > p.txt
hook --all >/dev/null && bad "--all missed an untracked file" || ok "--all covers untracked files"
rm -f p.txt
out=$(hook --all); rc=$?
[ $rc -eq 0 ] && has "$out" 'files clean' && ok "--all clean repo passes" || { bad "--all false positive (rc=$rc)"; show "$out"; }

# The repo's own files (these tests included) pass the guard.
mkdir -p "$T/self" "$T/emptysec/configs"
(cd "$SRC_REPO" && tar cf - --exclude .git --exclude __pycache__ .) | (cd "$T/self" && tar xf -)
(cd "$T/self" && git init -q && SECOPS="$T/emptysec" bash scripts/check-secrets.sh --all > "$T/self.out" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "the repo itself passes --all" || { bad "the repo itself is flagged (rc=$rc)"; show "$(cat "$T/self.out")"; }

echo "check-secrets: $pass passed, $fail failed"
[ $fail -eq 0 ]
