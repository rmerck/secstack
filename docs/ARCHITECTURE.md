# Architecture (v10, 2026-11-21)

Hardened, local-only offensive-security workstation for Apple Silicon Macs (16 GB and up), sized per
machine by `scripts/plan.py`. The reference build is a MacBook Pro M5 Pro (18 cores, 48 GB).
Local abliterated models only. Every listener on loopback. Nothing starts at login.
Tool containers on `pentest-net` and `hexstrike-net` can open connections only to the lab and the CIDRs
in `scope.cidrs`.

## Components

| Component | Upstream | Role here |
|---|---|---|
| Ollama | ollama.com (Ollama.app) | Model runtime on Metal. Two instances: chat :11434, embeddings :11435. |
| pentagi | vxcontrol/pentagi | Autonomous multi-agent pentest flows; spawns Kali terminal containers on pentest-net |
| ARTEX | BaaRai/ARTEX | Agentic web-app testing with a MITM recording proxy, driven from its own UI |
| hexstrike-ai | 0x4m4/hexstrike-ai | ~45 tools behind a token-protected API, rebuilt into a Kali arm64 image (`hexstrike-kali`), alone on hexstrike-net |
| kali-mcp | evilbotnet/kali-mcp | Offline Kali tool-docs MCP server (823 tools), no network |
| 5ire | nanbingxyz/5ire | Desktop chat client with MCP tools, pointed at local Ollama |
| SearXNG | searxng/searxng | Self-hosted search for pentagi agents (on pentagi's network) |
| DVWA + Juice Shop | vulnerables/web-dvwa, bkimminich/juice-shop | Local benchmark lab: 172.30.0.10/.11 on pentest-net, 172.30.1.10/.11 on hexstrike-net |
| `secstack` | this repo | Single control script for all of the above |
| pentagi-bridge, hexstrike-client | this repo | Stdio MCP servers: 5ire starts and watches pentagi flows; HexStrike's client with its token |
| secops-flow | this repo | Flow reports, watcher, NVD CVE verification, benchmarks, template/provider sync |
| plan.py | this repo | Hardware detection, memory/CPU sizing, model catalog, recommendation, model install |

ARTEX and pentagi never run together (`secstack` stops one before starting the other).

## Hardware plan

`scripts/plan.py` writes `$SECOPS/configs/stack.conf` (plain KEY=VALUE, validated, never sourced) and
the files generated with it. Each is written in full under a temporary name first, then they are renamed
into place, `stack.conf` last: until then everything that reads the plan sees the previous one whole.

| Slice | Rule | 48 GB reference |
|---|---|---|
| macOS + apps | ~17% of RAM, 5-12 GB | 8 GB |
| Docker Desktop VM | ~33% of RAM, 6-20 GB; CPUs = half the cores, 4-8; 1 GB swap | 16 GB, 8 CPUs |
| Model fence (one model loaded) | the rest, capped 1 GB under the GPU working-set limit | 24 GB |
| Context x parallel | fence >= 48: 32K x 4; >= 20: 32K x 2; >= 10: 32K x 1; else 16K x 1 | 32K x 2 |
| hexstrike container | half the Docker CPUs (2-4); 4 GB if the VM is 12 GB or more, else 2 | 4 CPUs, 4 GB |
| Model storage | see below | 75 GB |

**Model storage.** Models still to download must fit the free space where Ollama keeps models
(`OLLAMA_MODELS`, from launchd when the shell doesn't set it), less 20 GB of headroom and, while the
Docker images aren't built and share that space, 35 GB for them (APFS volumes of one container share
it; a live check for the `hexstrike-kali` image beats the install record). A Hugging Face GGUF in
`SECSTACK_MODELS_DIR` (default `~/models/gguf`) needs room until it is imported: the largest one counts
twice on the same space, or must fit its own volume less 20 GB (and 35 GB if that is the home volume
and the images aren't built). The whole selection must fit the budget: the cap (75 GB up to 64 GB of
RAM, 1.2 x RAM above, or `SECSTACK_MODEL_BUDGET_GB`, 5-4000) or, if smaller, the room for downloads
plus every catalog chat model already installed, selected or not. A models folder or GGUF folder on a
drive that isn't mounted (a path under `/Volumes/<name>` with nothing mounted there) is refused:
measured anyway, it would be the internal disk.

After the models are chosen, the plan uses the largest context every one of them fits (it can raise a
16K plan to 32K; it never lowers the tier and never raises parallel above it).

Models come from `models/catalog.json` (15 entries max; see `models/README.md`). `secstack`, the bench
and tool-call tests, the pentagi/ARTEX `.env` model keys, the pentagi providers and the 5ire config all
read the plan. Without a plan, `secstack` falls back to the 48 GB reference values.

Recommendations by memory (`scripts/plan.py recommend --ram-gb N --disk-gb 2000` shows any size):

| RAM | Docker VM | Model fence | Context | Primary (workhorse) | Deep | Alt (vision) |
|---|---|---|---|---|---|---|
| 16 GB | 6 GB | 5 GB | 16K x 1 | qwen3-4b-abliterated | - | - |
| 18 GB | 6 GB | 7 GB | 32K x 1 | qwen3.5-4b-abliterated | - | - |
| 24 GB | 8 GB | 11 GB | 32K x 1 | qwen3.5-9b-abliterated | - | gemma4-12b-abliterated |
| 32 GB | 11 GB | 16 GB | 32K x 1 | qwen3.5-9b-abliterated | qwen3-14b-abliterated | gemma4-12b-abliterated |
| 36 GB | 12 GB | 18 GB | 32K x 1 | gpt-oss-20b-abliterated | qwen3-14b-abliterated | gemma4-12b-abliterated |
| 48 GB | 16 GB | 24 GB | 32K x 2 | qwen3.6-35b-a3b-abliterated | qwen3.8-27b-abliterated | gemma4-26b-abliterated |
| 64 GB | 20 GB | 33 GB | 32K x 2 | qwen3.6-35b-a3b-abliterated | qwen3.8-27b-abliterated | gemma4-31b-abliterated |
| 96 GB | 20 GB | 64 GB | 32K x 4 | qwen3-next-80b-abliterated | qwen3.8-27b-abliterated | gemma4-31b-abliterated |
| 128 GB | 20 GB | 95 GB | 32K x 4 | qwen3.5-122b-abliterated | qwen3.8-27b-abliterated | gemma4-31b-abliterated |
| 192 GB | 20 GB | 143 GB | 32K x 4 | qwen3.5-122b-abliterated | qwen3.8-27b-abliterated | gemma4-31b-abliterated |

Docker Desktop keeps RAM it grabbed during builds. `secstack down` stops Docker fully to release it.
The audit warns when swap passes 1 GB: close browser tabs. Set Docker Desktop > Settings > Resources to
the plan's CPUs, memory and 1 GB swap: other CPUs or memory are a mismatch in the `docker` step and a
warning in the audit (a re-plan gives the same size: it follows from this Mac's memory and cores).

## Networks and ports

| Network | Who | Egress |
|---|---|---|
| `pentest-net` (bridge `br-pentest`, 172.30.0.0/24) | pentagi's Kali terminals, lab (.10, .11) | scope firewall: the lab and `scope.cidrs` only |
| `hexstrike-net` (bridge `br-hexstrike`, 172.30.1.0/24) | hexstrike (.5), lab (.10, .11) | scope firewall: the lab and `scope.cidrs` only |
| pentagi's compose network | pentagi, pgvector, scraper, SearXNG | normal (they need the internet) |
| ARTEX's compose network | ARTEX and its proxy | normal |

`secstack scope apply` creates both bridges without IPv6, and the firewall also turns IPv6 off on them.
On each, the gateway is .1, Docker hands out addresses from the upper half (.128/25), and the lower half
holds the fixed ones. Nothing crosses between the two: pentagi's terminals can't reach HexStrike, and
HexStrike reaches the lab at its hexstrike-net addresses.

Published ports, on 127.0.0.1: pentagi 8443, scraper 9443, pgvector 5432, hexstrike 8888, ARTEX 8787
(UI) and 8788 (proxy). On 127.0.0.2: the two ports pentagi publishes for each flow's Kali terminal, and
the lab with `secstack lab up --ui` (8081, 8082). Not 127.0.0.1: Ollama trusts every page on 127.0.0.1
and localhost, and what these ports serve is agent-made (the lab serves planted XSS). macOS has no
127.0.0.2 until it's added to lo0: `./setup.sh --only loopback` adds it now and at every boot
(`/Library/LaunchDaemons/com.secstack.lo0-alias.plist`; it asks before sudo). Ollama: 11434 (chat) and
11435 (embeddings).

## Security notes

- **Scope firewall.** A `SECOPS-SCOPE` chain in the Docker VM, jumped to first from `DOCKER-USER` (one
  hook per bridge, exactly these two first, in order) for traffic entering from `br-pentest` or
  `br-hexstrike`; `FORWARD` must start with its jump to `DOCKER-USER`. The chain first drops anything
  entering a bridge with a source outside that bridge's subnet (forged replies can't cross to the other
  network). A container may open a connection only to the lab on its own bridge
  (172.30.0.8/29 on pentest-net, 172.30.1.8/29 on hexstrike-net) or a CIDR in `scope.cidrs` (IPv4, /16
  or narrower, normalized, never overlapping a reserved range); replies to connections made to it pass.
  Everything else is rejected: other containers on its bridge, the other bridge, Docker Desktop's subnet
  (192.168.65.0/24) and the VM's own uplink network, loopback, link-local, multicast and the Mac's
  services behind `host.docker.internal`. The lab may answer but sends nothing else, so even a
  connection it opened while the firewall was off is cut. Every packet of a connection a container
  opened is checked, so narrowing the scope (`scope rm`, or a hand edit then `scope apply`) cuts it. An
  `INPUT` rule per bridge refuses new connections from the bridges to the VM itself, IPv6 is off on both
  bridges (the `disable_ipv6` sysctl, read back; skipped when the VM has no IPv6), and bridge netfilter
  is switched on so traffic inside a bridge meets the rules. `secstack scope install` also opens public
  TCP 80/443 for package installs until `secstack scope strict`.
- **It fails closed.** One apply runs at a time (a lock in `$SECOPS/run/scope.lock`; a dead owner's is
  taken over). Apply first checks both networks, the VM's uplink and `scope.cidrs`; a failure
  there changes nothing. Then it puts a guard rule that blocks each bridge first in `DOCKER-USER`, sets
  up bridge netfilter, the `INPUT` rules, IPv6 and the chain (final REJECT first), hooks the chain in
  for each bridge and removes the guards last: a failure in between leaves the bridges blocked. On a VM
  that Docker just restarted (no `SECOPS-SCOPE` chain yet), it pauses while the guards are in and kills
  the containers on either network that came back on their own. Last it reads everything back (every
  rule, in order, hooks first, no leftover guard, IPv6 off) and fails on any difference. The VM needs
  `ip` and `sysctl`. `scope rm` and leaving install mode also flush tracked connections of both subnets
  (a warning if the VM has no `conntrack`). `strict` is saved before its apply runs, so a failed
  `scope strict` can't leave install mode for a later apply. `scope off` removes only the hooks.
  `secstack scope test` probes from each network (internet, LAN, `host.docker.internal` at the address
  the container resolves, HexStrike) and exits non-zero on a leak.
- **A Docker restart wipes the firewall.** `secstack prep`, `pentagi`, `lab up` and `mcp on` re-apply
  it, and `secstack audit` checks it. Every container on either network gets restart policy `no` after
  each apply and before `stop` and `down`, and pentagi gets a compose override (`restart: "no"`), so
  nothing comes back with Docker before the firewall. pentagi gives each new Kali terminal a restart
  policy, so while pentagi runs a restart guard (started by `secstack pentagi`, log
  `$SECOPS/logs/restart-guard.log`) follows `docker events` and clears it as soon as a container is
  created or joins a network. It stops with pentagi (`stop`, `down`, `artex`) and ends by itself when
  Docker stops; the audit fails when pentagi runs without it. When secstack starts Docker itself, it
  kills any container on either network that came back anyway (a terminal ignores SIGTERM, so a stop
  would leave it running for 10 seconds). `secstack` refuses a `pentest-net` or `hexstrike-net` it
  didn't create (another driver, bridge name, subnet, dynamic range or IPv6), and prints how to recreate
  it: `secstack stop && docker network rm pentest-net && secstack scope apply && secstack lab reset`
  (the same with `hexstrike-net`).
- **Not covered by the scope firewall.** ARTEX, pentagi itself, its scraper and SearXNG need the
  internet, and an agent can reach it through their tools (a scrape, a search). pentagi's browser tool
  sends private, loopback, `.local` and `.lan` URLs to its own scraper, which sits on pentagi's network
  with no secstack rule: an agent (or a page steering it) can browse LAN and client hosts outside
  `scope.cidrs`, the Docker VM, and the Mac's loopback services through `host.docker.internal`. DNS from
  both networks goes to Docker's resolver, which forwards it, so data can leave in DNS queries. Scope is
  a guard rail for terminal and HexStrike traffic, not a sandbox for the models. See "Known limits" below.
- **pentagi's terminals get neither the Docker socket nor NET_ADMIN** (`DOCKER_INSIDE=false`,
  `DOCKER_NET_ADMIN=false` in pentagi's `.env`): with the socket a terminal could start a container on
  any network, with NET_ADMIN change their own addresses and routes (NET_RAW, which scans need, already
  allows ARP forgery on pentest-net; see "Known limits"). They publish their ports on
  127.0.0.2 (`DOCKER_PUBLIC_IP`). `secstack pentagi` refuses an unsafe `.env` (read the way Compose reads
  it), a missing override or no 127.0.0.2 on lo0, before it stops ARTEX, and runs Compose with explicit
  `-f` files and those keys unset in its environment. pentagi adds SYS_PTRACE to its terminals, which
  the audit allows for them only. pentagi itself mounts `/var/run/docker.sock` to launch terminals:
  root-equivalent control of the Docker VM, and through Docker Desktop's file sharing (all of `/Users`
  by default) of your files too. Limit Docker Desktop > Settings > Resources > File sharing to the
  folders secstack mounts (`$SECSTACK_GH`, by default `~/GitHub`, which holds the clones and `$SECOPS`).
- **Images.** pentagi runs in `DOCKER_IMAGE_SELECTION_MODE=fixed` with the Kali image from
  `upstream/images.lock`, so an agent can't pick an arbitrary image. Images are pulled only when
  missing. The alpine image that programs the firewall (privileged, in the VM) must be digest-pinned;
  `secstack` refuses a tag.
- **No proxies.** secstack, plan.py, secops-flow, the pentagi bridge and the HexStrike client bypass
  HTTP proxies for loopback, so the tokens can't travel through one (NVD lookups too, unless
  `SECSTACK_NVD_PROXY` names one). secops-flow and the bridge refuse a `PENTAGI_URL` that isn't a plain
  loopback URL, and a token file that isn't a single-line token (without echoing it).
- **hexstrike** upstream hard-codes `app.run(host="0.0.0.0")` with no auth: arbitrary command execution
  on the LAN if run natively on macOS. Here it runs only in the container, alone on hexstrike-net
  (172.30.1.5), published on 127.0.0.1:8888, behind a Host-header allowlist (DNS rebinding) and a token:
  every request but `GET`/`HEAD /health` needs the header `X-Secstack-Token` holding
  `$SECOPS/env/hexstrike-token` (600). Every new HexStrike container gets a new token (`secstack mcp on`
  or `prep`; a running one that holds the current token is kept). A malformed token file is replaced; a
  symlink in its place is refused. The container's entry point passes the token over a pipe to a fresh
  copy of itself (same PID, started with an environment that never held it), so it is in neither
  `/proc/1/environ` nor a command line. MCP clients add it through `mcp/hexstrike-client`, which reads
  the file again when it changes: no reconnect after a new token, HTTP 401 while there is none.
  `secstack mcp on` applies the scope firewall first, then refuses an image built before the token
  check: a HexStrike that answers without asking for the token, or doesn't answer `/health` within a
  minute, is removed. The client sends the token only to 127.0.0.1. There is no data mount.
- **Ollama** starts with the planned settings and without `OLLAMA_ORIGINS` (a website could otherwise
  pull, replace or delete models). `secstack llm start` restarts an instance that answers a foreign
  Origin or whose server log lacks the planned settings. Ollama.app's own Settings win over what
  secstack passes (Expose Ollama to the network, Context length, Model location, browser access), so
  when the server it started still lacks them, it stops Ollama and names the setting to change. The
  audit fails when either instance accepts a website or browser extension, tested with a request and
  read from its server log. `llm stop` stops only Ollama.app and secstack's embedding server.
- **Flow reports** go to a new folder, `$SECOPS/reports/flow<id>-<time>-<random>`. The terminal's
  `/workspace` (the agent's) is copied as plain files only: links, special files, paths outside it,
  name collisions and files over 256 MiB are skipped and listed in `skipped-links.txt`; the copy stops
  at 2 GiB, 20,000 entries or 15 minutes, marked INCOMPLETE. It goes into a hidden `.copying` folder,
  is quarantined there and only then moved into view; if Docker doesn't answer within 60 seconds the
  workspace isn't copied, and `SUMMARY.md` says so. File and folder names with control, bidi or invisible
  characters are renamed (each such character becomes `_`) and listed in `SUMMARY.md`; contents are kept.
  Up to 64 MiB of each of the flow's message and
  terminal logs is kept (TRUNCATED beyond that); the JSON files can be larger, since non-ASCII text is
  written escaped. `SUMMARY.md` opens with the CVE check and shows agent text
  escaped in code blocks, every line behind a gutter, long texts shortened. On macOS the folder is
  quarantined; files 600, folders 700.
- **5ire** packaged builds ship app logs to Axiom (`api.axiom.co`). setup offers to add the missing
  IPv4 and IPv6 `/etc/hosts` lines; the audit wants both. 5ire imports `mcp.json` into its own database
  on its first launch and never reads the file again: after that, its MCP servers are changed in
  5ire > Tools.
- **pentagi provider sync** (`secstack providers`, pentagi running) creates the plan's providers; it
  updates existing ones only without `--create-only`, after a 600 backup in `$SECOPS/logs`. `--prune`
  deletes only names the plan generates, and not at all when a provider file failed to load.
- **Models.** Weights are checked against catalog pins before a temporary build replaces an alias, the
  alias is read back after the copy, and only the manifest digest that passed is recorded. Exported
  Modelfiles are re-parsed as Ollama reads them, never copied (see `models/README.md`).
- **Git hooks** (`scripts/check-secrets.sh`, six of them): pre-commit, pre-merge-commit and
  pre-applypatch check what is staged, commit-msg and applypatch-msg the message, pre-push every commit,
  tag and message a push sends (`--no-verify` ones too; nested tags are followed, and a tag of a tree or
  blob is refused). They block never-commit paths, force-added ignored files, binary and git-lfs files,
  symlinks out of the repo, credential formats, secret-looking values, passwords on command lines,
  credentials in URLs, bare hex tokens, `/Users/<name>/` paths, live scope addresses (also defanged,
  dashed or zero-padded) and `never-commit.txt` entries, in content, paths, messages, authors, ref names
  and tags. In a commit or push, scope addresses and deny-list entries count only on lines new to a
  file (for a merge, lines in none of its parents); credentials count on every line, and `--all` checks
  whole files. A deny-list entry matches as whole words or with its words run together, ignoring case,
  accents and punctuation, also %-encoded, HTML-escaped or in cp1252/MacRoman text; one with a
  one-letter word (X&Y) must appear as written or as one word (XY). 172.30.0.0/24 and 172.30.1.0/24
  never count as live scope. The output never shows a matched value or git's own messages; a path
  that matches only as a whole prints as `****`. The hooks refuse when `python3` is missing, the runtime
  root has no readable `configs/` folder, or a list that exists can't be read (`SECSTACK_NO_RUNTIME=1`
  skips only those lists). With a global or system `core.hooksPath`, which would skip this repo's
  hooks, `install.sh` sets a repo-local one pointing at the repo's own hooks folder. A safety net: a
  secret with no telltale name or format still needs your eyes.
- **Secrets** live only in `ARTEX/.env`, `pentagi/.env`, `pentagi/secstack.*.provider.yml` and `$SECOPS/env/*`,
  all 600, inside 700 directories. `secstack audit` checks listeners (`netstat`, every user's), pentagi's
  `.env`, containers on either network or named like secstack's (HexStrike on hexstrike-net only, the
  lab on both, the rest on pentest-net only; no privileges, host namespaces, added capabilities,
  unconfined profiles, devices, device cgroup rules, Docker socket mounts or restart policy), published
  ports (loopback only; pentest-net containers on 127.0.0.2 only), the restart guard while pentagi
  runs, the firewall, Docker VM vs plan, permissions, model digests (changed or missing models), Ollama
  origins, the Ollama login item, 5ire hosts, mutual exclusion, memory and model budget. Exit 0 passed,
  1 issues, 2 something wasn't checked (Docker or Ollama down, no recorded model digests, an Ollama
  server log without its settings, `netstat` unreadable); it never reports passed then.
- **CVE IDs** from agents are checked against NVD (`secstack verify-cve`, also run by `secstack report`).
  IDs are read as a reader sees them (fullwidth forms and lookalike dashes folded, invisible characters
  dropped); IDs written with lookalike letters or digits are flagged LOOKALIKE. The first 1,000 distinct
  IDs are listed (the rest counted), and at most 100 of them are checked per run (`REPORT.md` and
  pentagi's report messages first) within 15 minutes; the rest are NOT CHECKED. Not in NVD, rejected,
  unverified and unchecked IDs are flagged, and with `--expect vendor[,product]` (exact CPE names) IDs
  for another product too; only the CPEs NVD marks vulnerable count (UNCONFIRMED when NVD lists no
  vulnerable product yet). Answers are cached 30 days once NVD has analyzed, modified, rejected or
  deferred a CVE, 1 day otherwise. The optional NVD key is `$SECOPS/env/nvd-api-key`. Local models
  invent CVE IDs.

## Known limits

These are accepted, not fixed:

- **pentest-net is shared.** pentagi's Kali terminals all sit on it and keep NET_RAW (scans need it).
  One can forge ARP replies or source addresses to take over another terminal's address, or the lab's,
  toward the other terminals and toward the Docker VM: a page on 127.0.0.2:8081/8082 may come from a
  terminal posing as the lab. The firewall still limits where any of them can open connections, and
  HexStrike, on its own network, is out of their reach.
- **DNS.** Names resolve through Docker's embedded resolver on both networks, which forwards them: data
  can leave in DNS queries (`secstack scope test` shows that DNS resolves).
- **Floating inputs.** The pentagi, pgvector and scraper images float until `scripts/pin-images.sh`
  pins them, Ollama hub weights until `scripts/plan.py pin-weights --write`. Some build inputs float by
  design: `kali-tools-mcp-server`'s `python:3.11-slim` base (by tag), `git` from apt, pip packages
  without hashes and the kali-tools docs cloned at HEAD; `hexstrike-kali`'s Kali packages, Go tools and
  pip packages. A rebuild can bring in different code.
- **The HexStrike token in memory.** HexStrike runs every command as root in its container, and root
  there can read the token from the server's memory (`/proc/1/mem`, or `gdb`, which the image has). A new
  container gets a new token, so a captured one stops working once the container is replaced.
- **An interrupted report.** A report stopped by SIGTERM (which `secstack watch stop`, `stop`, `down` and
  `artex` send to a running watcher) finishes its cleanup and quarantine first. One killed outright
  (SIGKILL, a crash) during its workspace copy can leave a hidden `.copying` folder in the report folder,
  holding agent-made files without the quarantine mark. Delete it rather than open anything in it.
- **Outside the scope firewall.** ARTEX, pentagi itself, its scraper and SearXNG reach the internet,
  and an agent can too, through their tools. pentagi's browser tool goes through its scraper to private
  and LAN addresses and to the Mac's loopback services (`host.docker.internal`), whatever `scope.cidrs`
  says. pentagi holds the Docker socket (root-equivalent in the Docker VM, and your files through Docker
  Desktop's file sharing: limit it, see "Security notes").
- **pentagi remembers across flows.** Its guide store is global: a guide an agent saved in one flow
  (possibly shaped by a hostile target) is offered to every later flow, across restarts.
- **The lab is a relay.** It sits on both networks, so a terminal that takes over DVWA or Juice Shop can
  plant content that HexStrike later reads and hands to 5ire or Claude Desktop. With `lab up --ui`, a
  website in your browser can drive the lab on 127.0.0.2 (CSRF, DNS rebinding). Run `lab down` when
  you're done.
- **The CVE check is a helper.** It reads plain IDs (with lookalike dashes folded); IDs written with
  Markdown escapes, HTML entities or comments inside them are neither checked nor flagged. Read the
  report, not only the verdict.
- **Weights are trusted on first use** until pinned: most catalog entries ship without `weights_sha256`.
  The first install records each alias's manifest digest; a later change fails the next install and the
  audit. Pin them with `scripts/plan.py pin-weights --write` on a Mac where they work.
- **Another account on the Mac** could listen on 127.0.0.1:8443 while pentagi is down and receive the
  pentagi API token from secops-flow or the MCP bridge, which don't pin pentagi's self-signed
  certificate. secstack assumes a single-user Mac.
