# secstack

A hardware-aware installer and control plane for a local-only offensive-security workstation on Apple
Silicon. It sets up pentagi, ARTEX, HexStrike (Kali container), kali-mcp and 5ire, driven by local
abliterated models in Ollama. Every listener is on loopback. The tool containers (pentagi's Kali
terminals, HexStrike) can open connections only to the lab and an explicit scope, and the lab opens none.

**For authorized testing only.** Scope is enforced at the network layer; authorization is your job.

## Install

```bash
git clone https://github.com/rmerck/secstack.git ~/GitHub/secstack && cd ~/GitHub/secstack
./setup.sh --plan        # see what this Mac gets; changes nothing
./setup.sh               # install (interactive)
./setup.sh --help        # all options
```

`setup.sh` reads the Mac's chip, memory, cores and free disk, splits memory between macOS, the Docker
VM and one loaded model, and recommends models from a 15-entry catalog. You can change the pick.
Then it clones the pinned upstream projects, builds the images, installs and verifies the models, and
walks you through the steps that need a browser (pentagi password and API token, ARTEX claim). It
finishes with a security audit. Every step can be resumed (`--from STEP`) or run alone (`--only STEP`);
both run preflight first. setup asks before it uses sudo (to put 127.0.0.2 on lo0 at every boot, and
for the `/etc/hosts` lines that block 5ire's log shipping).

`./setup.sh --yes` runs unattended: the recommended models on a first install, the current plan's models
on a re-run (it stops if it can't keep them). Runtime folders that differ from the repo are replaced
and kept as `*.pre-repo-<time>`. It never uses sudo: steps that need a browser, sudo or a decision are
listed at the end.

setup exits 0 when the steps ran and the audit (if it ran) passed, 3 when the audit found issues, and 2
when the audit couldn't check everything. Any other non-zero exit means a step stopped; setup says
where and how to resume.

Prerequisites (setup checks them and prints the install command for anything missing): Apple Silicon
Mac with at least 16 GB, a native (not Rosetta) terminal, Command Line Tools (`git`, `python3`), `uv`,
Docker Desktop, Ollama.app, and 5ire (optional). The Hugging Face CLI (`brew install hf`) is needed when
a chosen model is a GGUF download; the 48 and 64 GB primary is one, and setup stops early if it's missing.

| This Mac has | Recommended (you can change it) |
|---|---|
| 16 GB | Qwen3 4B, 16K context; run one framework at a time |
| 18 GB | Qwen3.5 4B, 32K context; run one framework at a time |
| 24-32 GB | Qwen3.5 9B + Gemma-4 12B (vision), plus Qwen3 14B at 32 GB |
| 36 GB | gpt-oss 20B + Qwen3 14B + Gemma-4 12B |
| 48 GB | Qwen3.6 35B MoE + Qwen3.8 27B + Gemma-4 26B (the reference build) |
| 64 GB | Same, with Gemma-4 31B as the vision model |
| 96 GB | Qwen3-Next 80B MoE + Qwen3.8 27B + Gemma-4 31B, 4 parallel requests |
| 128 GB+ | Qwen3.5 122B + Qwen3.8 27B + Gemma-4 31B (gpt-oss 120B selectable at 192 GB) |

Exact numbers: `./setup.sh --plan` or `scripts/plan.py recommend --ram-gb 32 --disk-gb 2000`.

## Daily use

```
secstack prep                      Docker + scope firewall + Ollama (chat :11434, embed :11435) + hexstrike
secstack pentagi | artex [--build]
                                   start one framework (stops the other; artex also stops flow watchers);
                                   --build after ARTEX's pin moved
secstack lab up [--ui] | down | reset [--ui]
                                   DVWA + Juice Shop on pentest-net and hexstrike-net
                                   (--ui: also on 127.0.0.2:8081/8082)
secstack scope show | add CIDR [note] | rm CIDR | apply | strict | install | test | off
secstack report FLOW [--expect vendor[,product]]  evidence + NVD check of the CVE IDs (first 100)
secstack watch FLOW [--down] | watch stop [FLOW]  notify on finish or stall, report automatically
secstack verify-cve FILE... [--expect vendor[,product]]
secstack providers [--create-only] [--prune]      sync the plan's pentagi providers (pentagi running)
secstack templates [--create-only]                sync flow templates (pentagi running)
secstack plan | status | audit | models | bench
secstack stop                      stop flow watchers, frameworks, hexstrike and lab; keep Docker + Ollama
secstack down                      stop everything, release Docker VM memory
```

`secstack` with no arguments prints the full list. pentagi's Kali terminals publish their ports on
127.0.0.2, and so does `lab up --ui`: Ollama trusts any page on 127.0.0.1, and what those ports serve is
agent-made (the lab serves XSS). `./setup.sh --only loopback` adds 127.0.0.2 to lo0 now and at every
boot (`/Library/LaunchDaemons/com.secstack.lo0-alias.plist`; it asks before sudo). Without it,
`secstack pentagi` and `secstack lab up --ui` refuse to start.

While pentagi runs, a restart guard runs in the background (log: `$SECOPS/logs/restart-guard.log`):
it clears the restart policy pentagi gives each new Kali terminal, so none comes back with Docker before
the scope firewall. `secstack pentagi` starts it; it stops with pentagi (`stop`, `down`, `artex`) and
ends by itself when Docker stops.

## Layout

```
setup.sh             one-command, resumable installer (--plan, --yes, --models, --from, --only, --help)
install.sh           links the repo into the runtime root (~/GitHub/.sec-ops), installs the git hooks;
                     --check shows changes first
bin/                 secstack, secops-flow.py, toolcall-test.py, bench-run.sh, hexstrike-ctl
mcp/                 pentagi-bridge (5ire -> pentagi REST API), hexstrike-client (adds HexStrike's API
                     token); stdio MCP servers, loopback only
models/catalog.json  the model catalog (<= 15); see models/README.md
scripts/
  plan.py            hardware detection, sizing, recommendation, selection, model install, weight pins
  bootstrap-upstream.sh, render-env.py   vetted pinned clones, patches, provider files, .env rendering, host venv
  build-images.sh, pin-images.sh         local images; pin runtime images to digests
  models.sh, export-modelfiles.sh, check-secrets.sh (checks in check_secrets.py)
configs/             hexstrike-kali image, SearXNG, flow templates, MCP client templates, scope example,
                     host-venv.lock.txt (hash-locked Python deps for the MCP clients)
upstream/            repos.lock (commits), images.lock (image digests), patches, .env overrides (no secrets)
tests/               ~/GitHub/.sec-ops/venv/bin/python3 -m unittest discover -s tests
                     (unit + functional; no network, no Docker; without requests, the secops-flow, bridge
                     and HexStrike client tests are skipped)
docs/                ARCHITECTURE.md (design, ports, security), REBUILD.md (manual steps, upgrades, recovery)
```

## How it fits together

The repo is code and config only. The runtime root `~/GitHub/.sec-ops` (700) holds per-machine state:
the hardware plan (`configs/stack.conf`, generated pentagi providers, 5ire config), secrets and tokens,
logs, reports, live scope and the host MCP venv (`venv/`). `install.sh` makes its `bin/`, `mcp/` and
static `configs/*` symlinks into this repo. Upstream projects stay as plain clones next to it (`pentagi/`
and `ARTEX/` are 700: they hold `.env` secrets), pinned by `upstream/repos.lock`. Their `.env` files are
rendered once with fresh random secrets; `./setup.sh --only upstream` later rewrites the other override
keys (model names after a re-plan, security settings) and keeps the secrets. A weak existing secret stops
that step, except pentagi's scraper login, which is simply renewed.

**Pinned:** upstream commits (vetted and checked with `git fsck` on every run), `hexstrike-kali`'s base
images, the host MCP venv (hashes), Hugging Face downloads (commit + sha256), the lab, SearXNG, Kali and
alpine images (digests). **Floats until you pin it on a working Mac:** the pentagi, pgvector and scraper
images (`scripts/pin-images.sh`) and Ollama hub models (`scripts/plan.py pin-weights --write`).
**Floats by design:** what the local image builds fetch at build time. For `hexstrike-kali`: Kali
packages, Go tools at `@latest` and its pip packages. For `kali-tools-mcp-server`, built from kali-mcp's
own Dockerfile at the pinned commit: its `python:3.11-slim` base (a tag, no digest), `git` from apt, pip
packages without hashes (most by version range), and the kali-tools docs it serves, cloned from GitLab
at HEAD. Also ARTEX's own dependencies. The 5ire clone is only cloned, pinned and vetted (nothing uses
it); the 5ire app is the DMG you installed. See [docs/REBUILD.md](docs/REBUILD.md).

**The scope firewall covers** pentest-net (pentagi's Kali terminals) and hexstrike-net (HexStrike
alone): their containers open connections only to the lab and `scope.cidrs`, not to each other and not
across the two networks, and the lab, on both, opens none. **It does not cover** ARTEX, pentagi itself,
its scraper and SearXNG (they need the internet), or DNS: names still resolve through Docker's resolver,
so data can leave in DNS queries. pentagi's browser tool goes through its scraper, so an agent can browse
LAN and private addresses outside `scope.cidrs`. Run every framework only against targets you are
authorized to test.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) lists the known limits (terminals on pentest-net can spoof each other and the lab,
floating build inputs, the HexStrike token in its container's memory, and more).

## Never commit

`.env` files, `$SECOPS/env/*`, `logs/`, `reports/`, live `scope.cidrs`, the generated plan. `.gitignore`
excludes them and `scripts/check-secrets.sh` runs as six git hooks (pre-commit, pre-merge-commit,
pre-applypatch, commit-msg, applypatch-msg and pre-push) on everything a commit or push would add. Put
client names, domains and past targets in `$SECOPS/configs/never-commit.txt` (one per line; an address
or CIDR matches every address in it) and the hooks block them too. A name matches as whole words,
whatever the case, accents or punctuation between its words, and also run together or joined to other
words and digits (`ExampleCorp`, `ExampleCorpReport`, `examplecorp2024`); a name with a one-letter word
(`J.P. Morgan`, `AT&T`) must keep its words apart. In a commit or push, live scope
addresses and deny-list entries count only on lines new to a file, so an old line doesn't block an
unrelated edit; credentials count everywhere, and `scripts/check-secrets.sh --all` checks every file
whole.

## License

MIT, see [LICENSE](LICENSE). The projects secstack installs (pentagi, ARTEX, hexstrike-ai,
kali-mcp, 5ire), the container images it builds or pulls and the models it downloads keep their own
licenses.
