# Models

`catalog.json` lists at most 15 models: chat models in three roles plus one embedding model. All chat
models are abliterated (refusal-removed) builds from established publishers, so agents don't refuse
authorized test steps. `scripts/plan.py` reads the Mac's hardware, recommends one model per role that
fits, and lets you change the pick.

| Role | Job | Used by |
|---|---|---|
| `workhorse` | Fast, reliable tool calling. Normally the **primary** model | pentagi (default provider), ARTEX, 5ire |
| `deep` | Slower, more careful reasoning | pentagi `local-hybrid` adviser, its own pentagi provider |
| `alt` | A second model family, usually with vision | screenshots, cross-checking findings |
| `embed` | Embeddings for pentagi memory (always installed) | pentagi on the second Ollama (:11435) |

## How a recommendation is made

1. **Memory split.** `plan.py recommend` shows it. macOS + apps get about 17% of RAM (5-12 GB) and the
   Docker VM about 33% (6-20 GB). One model at a time gets the rest, capped 1 GB under the GPU's
   working-set limit (about 2/3 of RAM up to 36 GB, about 3/4 above, or `iogpu.wired_limit_mb` if set).
   That cap is the **fence**.
2. **Context.** Fence of 48 GB or more: 32K context x 4 parallel requests. 20-47 GB: 32K x 2. 10-19 GB:
   32K x 1. Under 10 GB: 16K x 1. Once the models are chosen, the plan takes the largest context all of
   them fit (a 16K plan can become 32K; parallel never goes above the tier).
3. **Fit.** The estimated loaded size must be at most the fence. It is the weights, plus the KV cache
   (`kv_gb_32k` x context/32K x parallel, q8_0), plus 1 GB, plus 0.5 GB per 64K tokens of compute
   buffers, plus 0.5 GB for a vision projector.
4. **Disk.** Models still to download must fit the free disk where Ollama keeps models, less 20 GB of
   headroom and, while the Docker images aren't built and share that free space, 35 GB for them. A
   Hugging Face GGUF needs its size twice while it is imported (on another volume, it must fit there).
   All selected chat models together must fit the budget: the cap (75 GB up to 64 GB of RAM, 1.2 x RAM
   above, or `SECSTACK_MODEL_BUDGET_GB`) or, if smaller, the room for downloads plus every catalog chat
   model already installed, selected or not. A models or GGUF folder on a drive that isn't mounted is
   refused. [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) has the exact rule.
5. **Pick.** Every combination of one model per role (or none) that fits is scored. The primary decides
   first: a workhorse beats a deep model, then the higher `rank` wins. Then more roles filled, then the
   other roles' ranks, then the smaller total size. The recommender only pairs an alt model from a
   different family than the primary, so it can cross-check it (a manual pick may break that rule).
   At most 3 chat models. `p N` in the picker (or `--primary`, with the picker or `--yes`) makes another
   tool-calling model the primary, in place of the pick in its role. With `--models`, `--primary` must
   name one of the listed models.

Estimates are deliberately conservative. Ollama sizes the KV cache as `num_ctx x OLLAMA_NUM_PARALLEL`,
and if a model still doesn't fit the GPU limit it offloads layers to the CPU (slower, not a crash):
`ollama ps` shows the CPU/GPU split. After install, `secstack bench` measures real speed, tool calling
and refusals. Recent Ollama releases run some architectures on their MLX engine on Apple Silicon; check
`ollama ps` after the first load to confirm the context and memory you expect.

## Catalog fields

| Field | Meaning |
|---|---|
| `id` | Short name for `--models` (e.g. `qwen3.6-35b-moe`) |
| `alias` | The Ollama name secstack creates (`ollama create alias`), lowercase |
| `role` | `workhorse`, `deep`, `alt` or `embed` (exactly one embedding model) |
| `source` | `{"type":"ollama","ref":"publisher/model:tag"}` (no `:cloud`, `:local` or `-cloud` tag, not another catalog alias) or `{"type":"hf","repo":..., "file":..., "revision":<40-hex commit>, "sha256":<64-hex>}` |
| `size_gb` | Download / weights size (decimal GB, as Ollama shows it) |
| `kv_gb_32k` | q8_0 KV cache for 32K tokens of one sequence (from the model's layer/head counts) |
| `rank` | Preference within a role when several fit (higher wins) |
| `provider` | pentagi provider name generated for this model |
| `tools` / `vision` / `abliterated` | Capabilities. A primary model must have `tools: true` |
| `reasoning_off` | Optional; `false` for models whose thinking can't be disabled (gpt-oss). pentagi then gets `effort: low` instead of `mode: off` |
| `weights_sha256` | Optional weights pin (set by `plan.py pin-weights --write`, the embedding model's too); checked on every install |
| `family`, `name`, `notes` | Family (the recommender pairs the alt with another family), display name, short notes |
| `verified` | Benchmark result on real hardware, when one exists |

`scripts/plan.py` validates the catalog on every run: at most 15 entries, unique ids/aliases/providers,
strict name patterns (no option-like or path-like values, no name Ollama reads as a blob digest), and
exactly one embedding model. A saved selection whose ids, aliases or sources no longer match the
catalog is refused.

## Supply chain

- **Hugging Face GGUF** sources must be pinned to a commit (`revision`); without one the download is
  refused. They should also carry a `sha256`: `plan.py install-models` verifies it before importing
  and deletes the file on a mismatch. An entry without a `sha256` is refused unless you pass
  `--allow-unpinned`, which prints the digest so you can pin it.
- **Ollama hub** tags are mutable and Ollama can't pull by digest. `install-models` records in
  `models.selected.json` the manifest digest each alias passed its checks with; the next install fails
  and `secstack audit` fails when one changes (new weights, template or system prompt alike), or when a
  recorded model is missing. Only `install-models --force`, which re-creates the alias from its catalog
  source, records a new digest. A model that fails a
  check keeps the record of its last good install, and so does one that changed after its check in the
  same run (something else reached Ollama's API meanwhile): the install then fails.
- **Weights fingerprint.** secstack reads a model's manifest the way Ollama resolves it (the
  `manifests-v2` store of Ollama 0.40+ or the older tree; for a manifest list, the child Ollama runs on
  Apple Silicon), checked against the digest Ollama lists, rather than text Ollama prints. A model with
  one weights layer is identified by that layer's sha256, which for a GGUF import is the file's sha256.
  A model with more (a vision projector, an adapter, shards) is identified by a sha256 over the sorted
  list of those layers, tensor names included, so adding or swapping any of them changes it. Template,
  system prompt, parameters, messages and license don't count. A model that runs on a remote host, or
  whose manifest can't be read, is refused, pinned or not.
- **Weight pins.** `scripts/plan.py pin-weights --write`, run on a Mac where the models work, stores the
  fingerprint as `weights_sha256` for each alias (the embedding model too) that holds exactly the
  weights its catalog source serves (an alias that differs is reported, not pinned). With a pin,
  `install-models` checks the pulled source before building, builds the alias under a temporary name,
  checks it again, and only then copies it into place. The alias is read back after the copy: it must
  hold the very build that passed, or it is removed. A failed check leaves any existing alias untouched
  and fails the install. An alias that is already installed is verified, never replaced; `--force`
  rebuilds it from the source, still under the same checks. The embedding model is pulled in place, so
  the installed copy is kept under a temporary name and put back if the new pull fails a check. A copy
  an earlier run left under that name is never overwritten: rather than pull again, the install stops
  and says how to put it back (`ollama cp`) or remove it (`ollama rm`).
- Treat third-party abliterated weights as untrusted input: they run only inside Ollama on loopback,
  and tool calls go through MCP servers that ask for approval.

## Exact templates from a working machine

Tool calling depends on the chat template or the `RENDERER`/`PARSER` lines Ollama attaches to a model. Hub
models carry them; an imported GGUF (the Qwen3.6 entry) gets them from Ollama's architecture mapping at
import time. After every install, `install-models` asks Ollama (`/api/show`) whether each tool-calling
model really reports `tools`, and refuses to install a primary model that doesn't.

`scripts/export-modelfiles.sh` captures the Modelfile of each model in the plan (or the aliases you
name) into `models/exported/<alias>.Modelfile`. It is parsed the way Ollama parses it and written out
in a normal form, never copied: comments dropped, `TEMPLATE`, `SYSTEM`, `LICENSE` and `MESSAGE` values
in `"""` blocks, `FROM` (a local blob path) and `CAPABILITY` dropped. `install-models` reads those files
the same way and keeps `TEMPLATE`, `SYSTEM`, `PARAMETER`, `MESSAGE`, `LICENSE`, `RENDERER` and `PARSER`
only. Refused: `FROM`, `ADAPTER`, `DRAFT`, `REQUIRES` and `CAPABILITY` (also as a `PARAMETER` name, like
`PARAMETER model`), unknown commands, anywhere a character Ollama's parser drops (control, format such
as zero-width or bidi, private-use, surrogate and noncharacter code points, and every space but U+0020;
tab and newline are fine), a bare CR, and a value containing `"""`. `num_ctx` and `num_predict` come
from the plan instead. Run the export on a Mac where tool calling already passes, read any `SYSTEM` and
`MESSAGE` lines (they can hold your own prompts), then commit `models/exported/*.Modelfile` so other
Macs get the same format.

## Commands

```bash
./setup.sh --plan                          # this Mac: plan + recommendation, changes nothing
scripts/plan.py recommend --ram-gb 32      # what a 32 GB Mac would get (add --disk-gb to set free disk)
./setup.sh --only plan                     # choose again (interactive)
./setup.sh --only models                   # install the chosen models
scripts/plan.py install-models --force     # rebuild aliases (e.g. after exporting Modelfiles)
scripts/plan.py pin-weights [--write]      # pin the weights of installed models in catalog.json
```
