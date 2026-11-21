# Rebuild and recovery

`./setup.sh` does everything below in order and can be resumed with `./setup.sh --from STEP`.
This page explains each step for when you need to run or repair one by hand.

## Prerequisites

| Install | Notes |
|---|---|
| Command Line Tools | `xcode-select --install` (git, python3 3.9+) |
| `uv` | `brew install uv` |
| Docker Desktop | Turn off "Start Docker Desktop when you sign in". Resources are set in step `docker`. |
| Ollama.app | Current release. Its CLI is at `/Applications/Ollama.app/Contents/Resources/ollama` (secstack and setup add that to PATH). Turn off launch at login. Its own Settings win over the plan: keep Expose Ollama to the network off, don't set Context length or Model location there (use `OLLAMA_MODELS` for another models folder), and don't let websites or browser extensions use it. If one of these differs, `secstack llm start` stops Ollama and names the setting. |
| Hugging Face CLI (`hf`) | When a chosen model is a GGUF download (the 48/64 GB primary is): `brew install hf` (or `uv tool install huggingface_hub`). The old `huggingface-cli` isn't used. |
| 5ire (optional) | Official notarized DMG from the nanbingxyz/5ire GitHub releases |

Use a native arm64 terminal; setup stops under Rosetta.

## Steps

| Step | What it does | By hand |
|---|---|---|
| `preflight` | macOS + Apple Silicon + >= 16 GB, native terminal, not root, tools present, runtime root and its folders not inside the repo (no symlinks into it; compared by identity, as APFS ignores case) | |
| `plan` | Detects hardware, sizes memory/CPU, lets you pick models. Writes `$SECOPS/configs/stack.conf` (last), `models.selected.json`, `pentagi-providers/*.json`, `generated/*` (600 in 700 dirs), each in full before any is put in place. Refuses a models or GGUF folder on a drive that isn't mounted. Stops if a pick needs `hf` and it's missing. With `--yes` on a re-run it keeps the current models and stops if it can't. | `scripts/plan.py select --write` |
| `upstream` | Clones pentagi, ARTEX, hexstrike-ai, kali-mcp, 5ire and checks out the commits in `upstream/repos.lock`, with git hooks and fsmonitor off. On every run it vets each clone (origin exactly the lock's URL; no replace refs, grafts, alternates, local git config outside an allowlist or index flags hiding edits; `git fsck` finds no damaged or forged objects; tracked files match the commit, compared through a fresh index; no untracked compose file in pentagi or ARTEX, and in ARTEX no untracked file outside `.env`, `data/`, `keys/` and `backups/`; the pin tracks no `.env`, `secstack.*` or, for pentagi, compose override, in any letter case) and prints the fix for anything it refuses. Applies patches (one that fails stops the run), writes `pentagi/secstack.*.provider.yml` (600) and the compose override that stops pentagi restarting with Docker (an existing one that differs from `upstream/pentagi/docker-compose.override.yml` is refused, with the `mv` that moves it aside), renders the `.env` files (new secrets the first time; after that the other override keys are rewritten and missing secrets added; an existing secret is kept when it is in its generator's format or strong, 16+ characters with 8+ different, and a weak one stops the run, except pentagi's scraper login, which is renewed), and syncs the host MCP venv (`$SECOPS/venv`) to the hash-locked requirements. | `scripts/bootstrap-upstream.sh` |
| `install` | Links the repo into `~/GitHub/.sec-ops`, seeds an empty scope, adds `secstack` to PATH (and a non-default runtime root) in `~/.zshrc`, installs the six check-secrets hooks (a hook of your own is kept with a note; with `core.hooksPath` set in the global or system git config it sets a repo-local one, `.git/hooks`, pointing at the repo's own hooks folder, and with a repo-local one of yours it tells you what to add), records `git config secstack.secops`, and points the HexStrike entry in the Claude Desktop stash at the token wrapper. A real directory that differs from the repo is listed and only replaced after you agree, or with `--force`/`--yes` (it's kept as `*.pre-repo-<time>`). setup adds install's notes to the list at the end. | `./install.sh --check`, then `./install.sh` (or `--force`) |
| `docker` | Starts Docker Desktop and checks its VM against the plan. If you need to change Settings > Resources, it asks before stopping the tool containers. Then it applies the scope firewall in strict mode (a Docker restart wipes it). With `--yes` the resize is listed at the end; the firewall is applied either way. | `scripts/plan.py docker-check`, then `secstack scope strict` |
| `loopback` | Puts 127.0.0.2 on lo0 now and installs `/Library/LaunchDaemons/com.secstack.lo0-alias.plist`, which adds it at every boot: pentagi's terminal ports and `secstack lab up --ui` publish there. Asks before sudo; with `--yes` it is listed at the end. | `sudo ifconfig lo0 alias 127.0.0.2 up` (until the next reboot) |
| `images` | Builds `hexstrike-kali` (20-40 min; it fails if `apt-get update` fails or no tool installs) and `kali-tools-mcp-server`; pulls the images in `upstream/images.lock` that are missing. Present images are never upgraded. | `scripts/build-images.sh` (`--pull` to upgrade on purpose) |
| `models` | Starts Ollama with the planned context/parallel/KV settings and no `OLLAMA_ORIGINS` (if an Ollama.app setting overrides them, it stops Ollama and names it), pulls or imports the chosen models (GGUF: commit-pinned and sha256-verified), builds each alias under a temporary name, checks its weights against the catalog pin and its tool calling, and only then puts it in place and reads it back. Pulls and checks the embedding model, and records the manifest digest each model passed its checks with. | `secstack llm start && scripts/models.sh` |
| `pentagi` | Starts pentagi and its restart guard (asks first if ARTEX or a pentagi flow is running; skipped with a to-do while 127.0.0.2 isn't on lo0; refuses an unsafe `.env`), asks you to change the default password and create an API token (pasted hidden, saved 600; the clipboard is cleared if it still holds the token), then creates the plan's providers and templates that don't exist yet | see below |
| `artex` | Starts ARTEX (asks first if a pentagi flow is running; an idle pentagi is stopped); if it isn't claimed yet, copies the one-time setup token to the clipboard and clears it however setup ends | see below |
| `5ire` | Writes 5ire's `mcp.json` only on a 5ire that has never been opened: 5ire imports that file into its own database on its first launch and never reads it again. Before that launch, a HexStrike entry in `mcp.json` without the token wrapper is flagged; after it, setup points you to 5ire > Tools, which it can't read. Offers to add the missing IPv4/IPv6 `/etc/hosts` lines that block 5ire's log shipping (asks before sudo). | see below |
| `audit` | `secstack audit` (exit 0 passed, 1 issues, 2 something wasn't checked): listeners, pentagi's `.env`, containers and their networks, the restart guard, scope firewall, Docker VM vs plan, permissions, model digests, Ollama origins, the Ollama login item, 5ire hosts, memory, model budget. setup then exits 3 for issues and 2 when something wasn't checked. | |

### pentagi by hand

1. `secstack pentagi` (it needs 127.0.0.2 on lo0: step `loopback`), open https://127.0.0.1:8443 once it
   loads, log in with the upstream default `admin@pentagi.com` / `admin`, **change the password**.
2. Settings > API Tokens > create one and copy it. Save it without echoing and clear the clipboard:
   `(umask 077; pbpaste > ~/GitHub/.sec-ops/env/pentagi-api-token) && pbcopy </dev/null`
3. `secstack providers --create-only && secstack templates --create-only` (pentagi must be running).

`secstack providers` without `--create-only` also updates providers that already exist (after writing a
backup of them to `$SECOPS/logs/pentagi-providers-backup-<time>.json`); use it after re-planning.

`secstack pentagi` also starts the restart guard, which clears the restart policy pentagi gives each new
Kali terminal (log: `$SECOPS/logs/restart-guard.log`). It stops with pentagi (`secstack stop`, `down` or
`artex`); the audit fails while pentagi runs without it, and `secstack pentagi` starts it again.

### ARTEX by hand

`secstack artex`, then `cd ~/GitHub/ARTEX && docker compose logs artex | grep "Setup token"`. Open
http://127.0.0.1:8787/setup, paste it, set the admin password, then set System > Settings > concurrent
workers to the plan's `OLLAMA_NUM_PARALLEL` (`grep NUM_PARALLEL ~/GitHub/.sec-ops/configs/stack.conf`).
**Back up `ARTEX/.env`**: `ARTEX_SECRET_KEY` decrypts credential columns in ARTEX's database. After its
pin moves in `upstream/repos.lock`, rebuild its images once with `secstack artex --build`.

### 5ire by hand

On a 5ire that has never been opened:

```bash
mkdir -p ~/Library/Application\ Support/5ire
cp ~/GitHub/.sec-ops/configs/generated/5ire-mcp.json ~/Library/Application\ Support/5ire/mcp.json
```

On a 5ire that has been opened, `mcp.json` no longer counts (5ire imports it once, on its first launch):
add or edit the three servers in 5ire > Tools using the commands in that file. HexStrike and the
pentagi bridge run `~/GitHub/.sec-ops/venv/bin/python3` (HexStrike through
`~/GitHub/.sec-ops/mcp/hexstrike-client/hexstrike_client.py`, which adds its API token), Kali docs runs
`docker`. Then block the log shipping (the audit wants both lines; leave out one `/etc/hosts` already has):

```bash
printf '\n0.0.0.0 api.axiom.co\n:: api.axiom.co\n' | sudo tee -a /etc/hosts
```

In 5ire, add the Ollama provider `http://127.0.0.1:11434` and pick the primary model (`secstack status`).
The pentagi bridge reads the default pentagi provider from the plan each time it starts a flow, so it
follows a re-plan without config changes.

### Lab in a browser

With 127.0.0.2 on lo0 (step `loopback`), `secstack lab up --ui` publishes DVWA on http://127.0.0.2:8081
(`admin` / `password`) and Juice Shop on http://127.0.0.2:8082. Not 127.0.0.1: Ollama trusts every page there,
and the lab serves planted XSS. The lab runs on pentest-net (172.30.0.10/.11) and hexstrike-net
(172.30.1.10/.11), without NET_RAW (DVWA's ping page may not work); a lab container that doesn't match
what secstack creates (networks, addresses, ports, image) is recreated, losing its data.

## Changing models later

```bash
./setup.sh --only plan          # pick again (current models preselected)
./setup.sh --only upstream      # refresh .env model keys + pentagi provider YAML (secrets kept)
./setup.sh --only models        # install new picks
secstack pentagi                # restart pentagi with the new .env (secstack artex for ARTEX)
                                # wait until https://127.0.0.1:8443 loads, then:
secstack providers --prune      # update the plan's providers in pentagi, remove ones for dropped models
```

Every catalog model already installed is credited toward the budget, but models still to download
must fit the free disk ([ARCHITECTURE.md](ARCHITECTURE.md#hardware-plan) has the rule). Remove models you dropped with
`ollama rm <alias>`, and pick the new primary in 5ire if it changed.

## Upgrading an install made by an earlier secstack

```bash
cd ~/GitHub/secstack && git pull
./install.sh                     # links, git hooks, Claude stash entry (--force if it lists differences)
open -a Docker                   # wait until it runs: everything below needs it
secstack stop                    # stops watchers, frameworks, hexstrike, the lab; clears restart policies
./setup.sh --yes --only plan     # same models, plan files rewritten (drop --yes to choose again)
./setup.sh --only upstream       # vets the clones; provider files, compose override, .env, host venv
./setup.sh --only images         # rebuilds hexstrike-kali (token entry point), kali-tools-mcp-server
./setup.sh --only loopback       # 127.0.0.2 on lo0, now and at every boot (asks before sudo)
secstack scope rm 172.30.0.8/29  # only if scope.cidrs has this old lab line (the lab needs none)
secstack scope apply             # creates hexstrike-net; firewall on both networks
secstack mcp on                  # HexStrike on hexstrike-net (172.30.1.5) with a new token
secstack pentagi                 # recreates pentagi (terminal ports on 127.0.0.2) + restart guard
                                 # wait until https://127.0.0.1:8443 loads, then:
secstack providers --create-only && secstack templates --create-only
./setup.sh --only 5ire           # what to fix for 5ire; the missing hosts lines
secstack claude off && secstack claude on   # only if Claude Desktop has the entries on; restart it after
rm -rf ~/GitHub/hexstrike-ai/hexstrike-env  # the old MCP venv, if it's there
secstack audit                   # 0 passed, 1 issues, 2 something wasn't checked
```

- `install.sh` adds an applypatch-msg hook (six hooks in all). If `core.hooksPath` is set in your
  global or system git config, which would skip this repo's hooks, it sets a repo-local
  `core.hooksPath` to this repo's own hooks folder (`.git/hooks`, relative, so it still works after
  you move the clone) and says so: your global hooks then don't run in this repo (undo:
  `git config --local --unset core.hooksPath`). An absolute one left by an earlier install that no
  longer exists (the clone moved) is reset.
- If `upstream` refuses a clone, keep anything you added, run the fix it prints and re-run. After an
  upgrade, expect:
  - pentagi's `docker-compose.override.yml`, when it isn't byte for byte the one secstack ships (you
    or an older version edited it): move it aside with the `mv` it prints; the re-run writes the right
    one.
  - files in ARTEX that its pinned commit doesn't have, outside `.env`, `data/`, `keys/` and
    `backups/` (skills you added, say): its image build copies them and `./skills` is mounted, so move
    them out of `~/GitHub/ARTEX`.
  - for pentagi, "tracked files differ" listing `example.*.provider.yml`: an earlier version wrote over
    those files; restore them with the `git checkout` it prints.
  - a weak secret in a `.env`: put a strong one in the `.env` and in what stores data under it, as the
    message says.
- `scope apply` creates hexstrike-net and adds the new rules; it removes nothing by itself. It refuses
  a `scope.cidrs` that still has the old lab line (`secstack scope show` lists it), hence the
  `scope rm` before it. The previous version's IPv6 rule stays in the Docker VM until Docker restarts;
  it does no harm. If it says pentest-net isn't the network secstack creates (an older install), run
  the command it prints.
- `secstack mcp on` starts HexStrike on hexstrike-net and restarts one it finds on another network.
  MCP clients pick up the new token without a reconnect.
- The lab now sits on both networks: the next `secstack lab up` recreates it, losing its data.
- `secstack pentagi` refuses until the `loopback` step has put 127.0.0.2 on lo0 and `upstream` has set
  `DOCKER_PUBLIC_IP=127.0.0.2` in pentagi's `.env`. If it stops Ollama and names an Ollama.app setting,
  change that setting and run `secstack pentagi` again.
- Claude Desktop: `claude off` and `claude on` replace an old HexStrike entry (one that runs
  `hexstrike_mcp.py` directly) with the one that goes through `mcp/hexstrike-client`; restart Claude after.
  Skip them if the entries are off: `claude on` would turn them on.
- 5ire keeps the MCP servers it imported in its own database: if HexStrike (or pentagi-bridge) in
  5ire > Tools doesn't run the commands in `~/GitHub/.sec-ops/configs/generated/5ire-mcp.json`, edit it
  there.
- If you chose other models at the `plan` step, also run `./setup.sh --only models` after the images, and
  `secstack providers --prune` in place of the `--create-only` sync (see "Changing models later").
- If the audit says no model digests are recorded, or a recorded model is missing:
  `./setup.sh --only models` (it verifies the installed models and records them).
- `~/GitHub/.sec-ops/hexstrike-data` is no longer mounted; move out anything you saved there. Folders
  `install.sh --force` replaced are kept as `*.pre-repo-<time>`; delete them once everything works.

## Pinning (run on a Mac where everything works, then commit)

| What | Command | Effect |
|---|---|---|
| Runtime images | `scripts/pin-images.sh --check`, then `scripts/pin-images.sh` | Replaces tag entries in `upstream/images.lock` with the digests of the images this Mac has (an image without exactly one registry digest keeps its tag, with the reason) |
| Ollama hub weights | `scripts/plan.py pin-weights`, then `--write` | Adds `weights_sha256` to catalog entries (the embedding model too) whose installed alias holds exactly the weights its source serves; other Macs then refuse different weights |
| Chat templates | `scripts/export-modelfiles.sh` | Saves the Modelfile of each model in the plan to `models/exported/`, rewritten in a normal form (template, RENDERER/PARSER, stop tokens; no `FROM`, `CAPABILITY` or local paths). Read `SYSTEM`/`MESSAGE` lines before committing. |
| Upstream projects | `scripts/bootstrap-upstream.sh --latest` | Fetches the lock URL's HEAD (into `FETCH_HEAD` only) and reports what it has past each pin; changes nothing. To move a pin: review the commits, put the full hash in `upstream/repos.lock`, re-run without `--latest`, re-test. |

Review with `git diff`, run `~/GitHub/.sec-ops/venv/bin/python3 -m unittest discover -s tests`, then
commit (the hooks scan what is staged and pushed).

## What is not in the repo

| Item | Where it lives | How to get it back |
|---|---|---|
| Hardware plan | `$SECOPS/configs/stack.conf` + generated files | `./setup.sh --only plan` |
| `pentagi/.env`, `ARTEX/.env` | upstream clones, 600 | Regenerated with new secrets by `upstream` (move the old one aside first; an existing database then needs its data reset or the old password put back), or restore from backup |
| pentagi API token, HexStrike token, NVD key, SearXNG secret | `$SECOPS/env/` (`pentagi-api-token`, `hexstrike-token`, `nvd-api-key`, `searxng.env`) | Recreate (every new HexStrike container gets a new token from `secstack mcp on`; SearXNG's auto-generates) |
| Live scope, deny-list | `$SECOPS/configs/scope.cidrs`, `never-commit.txt` | `secstack scope add`; rewrite the list |
| 127.0.0.2 at every boot | `/Library/LaunchDaemons/com.secstack.lo0-alias.plist` (root) | `./setup.sh --only loopback` |
| Host MCP venv | `$SECOPS/venv` | `./setup.sh --only upstream` |
| Provider/template backups | `$SECOPS/logs/pentagi-*-backup-*.json` | Written before every sync that changes something |
| Flow history, ARTEX projects | Docker volumes | Back up the pentagi/ARTEX volumes if you need them |
| Reports and evidence | `$SECOPS/reports/` | Copy to encrypted storage; never into git |
| Model weights | Ollama's models folder (`OLLAMA_MODELS`, default `~/.ollama/models`) | `./setup.sh --only models` |
