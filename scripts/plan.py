#!/usr/bin/env python3
"""plan.py: hardware-aware resource and model planner for secstack.

  plan.py detect [--json]
      Print this Mac's hardware.
  plan.py recommend [--ram-gb N] [--cpus N] [--disk-gb N]
      Print the resource plan and the recommended models. Writes nothing.
      --ram-gb / --cpus / --disk-gb simulate another machine.
  plan.py select [--yes | --models ID,ID,...] [--primary ID] [--write]
      Choose models (interactive unless --yes or --models). With --write, save the
      stack config and generated files under $SECOPS/configs.
  plan.py install-models [--keep-gguf] [--force] [--allow-unpinned]
      Pull or import the selected models into Ollama, create the aliases, verify them.
  plan.py pin-weights [--write]
      Read the weight digests of installed catalog models and pin them in models/catalog.json.
  plan.py modelfile-filter RAW OUT
      Keep only the allowed commands of an `ollama show --modelfile` dump
      (used by export-modelfiles.sh).
  plan.py docker-check
      Compare the running Docker Desktop VM with the plan (exit 1 on mismatch, 2 if Docker is down).
  plan.py show
      Print the saved stack config.

Standard library only: runs on the Python 3.9 that ships with Apple's Command Line Tools.
Writes under $SECOPS (default ~/GitHub/.sec-ops), files 600 and directories 700. The exceptions:
`pin-weights --write` updates the repo's catalog on purpose, `modelfile-filter` writes the OUT file
it is given (models/exported/ in the repo, 644), and `install-models` downloads GGUF files into
$SECSTACK_MODELS_DIR (default ~/models/gguf; deleted after import unless --keep-gguf) for Ollama.
Model sizes are decimal GB as Ollama reports them; RAM is GiB as macOS reports it.
The difference (~7%) errs on the safe side.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import itertools
import json
import math
import os
import platform
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from xml.parsers.expat import ExpatError

REPO = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO / "models" / "catalog.json"
EXPORTED_DIR = REPO / "models" / "exported"
TEMPLATE_5IRE = REPO / "configs" / "5ire" / "mcp.json"
HOME = Path.home()
GH = Path(os.environ.get("SECSTACK_GH") or (HOME / "GitHub"))
SECOPS = Path(os.environ.get("SECOPS") or (GH / ".sec-ops"))
CFG = SECOPS / "configs"
GEN = CFG / "generated"
STACK_CONF = CFG / "stack.conf"
SELECTED = CFG / "models.selected.json"
PROVIDERS_DIR = CFG / "pentagi-providers"
MODELS_DIR = Path(os.environ.get("SECSTACK_MODELS_DIR") or (HOME / "models" / "gguf"))   # GGUF downloads
LAUNCHCTL = "/bin/launchctl"


def _launchd_env(name: str) -> str:
    """A variable set for apps with `launchctl setenv` ("" when unset, or not on macOS). Ollama.app
    takes its settings from there, not from a shell."""
    if platform.system() != "Darwin":
        return ""
    try:
        p = subprocess.run([LAUNCHCTL, "getenv", name], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    return p.stdout.strip() if p.returncode == 0 else ""


def _ollama_models_dir() -> Path:
    """Ollama's model store: OLLAMA_MODELS from this environment, else (macOS) the value Ollama.app
    gets from launchd, else ~/.ollama/models."""
    return Path(os.environ.get("OLLAMA_MODELS") or _launchd_env("OLLAMA_MODELS") or (HOME / ".ollama" / "models"))


OLLAMA_MODELS = _ollama_models_dir()
OLLAMA_URL = "http://127.0.0.1:11434"
# Loopback calls never go through an HTTP proxy (urllib would otherwise use the macOS system proxy).
_LOCAL_HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
OLLAMA_APP_CLI = "/Applications/Ollama.app/Contents/Resources/ollama"
SYSCTL = "/usr/sbin/sysctl"
DF = "/bin/df"
DISKUTIL = "/usr/sbin/diskutil"
DOCKER_FALLBACK = "/Applications/Docker.app/Contents/Resources/bin/docker"

GIB = 1024 ** 3
MIN_RAM_GB = 16
MAX_CHAT_MODELS = 3
MODEL_BUDGET_CAP_GB = 75   # up to 64 GB of RAM; bigger Macs get 1.2 x RAM so their big models fit
DOCKER_IMAGES_GB = 35      # hexstrike-kali, kali-linux, pentagi, ARTEX, lab, searxng (approximate)
DISK_SAFETY_GB = 20
CATALOG_MAX = 15
ROLES = ("workhorse", "deep", "alt")
PENTAGI_ROLES = ("simple", "simple_json", "primary_agent", "assistant", "generator", "refiner", "adviser",
                 "reflector", "searcher", "enricher", "coder", "installer", "pentester")
GEN_MARK = "scripts/plan.py"

# All patterns are used with fullmatch (a "$" anchor alone would also accept a trailing newline).
SAFE_VALUE = re.compile(r"(?:[A-Za-z0-9._:/,][A-Za-z0-9._:/,-]*)?")     # every stack.conf value
ALIAS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")                     # Ollama alias we create
ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,47}")
# Ollama hub reference: optional lowercase namespace (no dots, so no registry host), name, optional tag.
# A tag Ollama reads as a source suffix is refused: ":cloud" and "...-cloud" make a remote model, and
# ":local" names another model (internal/modelref.parseSourceSuffix).
REF_RE = re.compile(r"(?:[a-z0-9][a-z0-9_-]{0,63}/)?[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
                    r"(?::(?!(?i:cloud|local|[a-z0-9._-]*-cloud)\Z)[A-Za-z0-9][A-Za-z0-9._-]{0,63})?")
SOURCE_TAG_RE = re.compile(r"(?i:cloud|local|.*-cloud)")
# A digest Ollama resolves as a local blob instead of a model name (manifest.ResolveDigestReference): as
# library/<digest>:latest, as the whole name, or after a runner, "mlx:<digest>" (server.digestModelName).
DIGEST_NAME_RE = re.compile(r"(?i:(?:sha256[-:])?[0-9a-f]{12,64})")
DIGEST_RUNNERS = ("mlx", "mlxrunner", "ggml", "llamacpp", "llama.cpp", "llama-cpp", "llama_cpp")
HF_REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
HF_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.gguf")
PROVIDER_RE = re.compile(r"local-[a-z0-9][a-z0-9.-]{0,40}")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
MODELS_DIR_RE = re.compile(r"/[A-Za-z0-9._/+@ -]+")
OLLAMA_HOST_DIR = "registry.ollama.ai"   # legacy store: manifests/<host>/<ns>/<model>/<tag> files
OLLAMA_V2_HOST_DIR = "ollama.com"        # Ollama 0.40+: manifests-v2/<host>/... links to the manifest blob
MT_MODEL = "application/vnd.ollama.image.model"
MT_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
MT_MANIFEST_LIST = "application/vnd.ollama.manifest.list.v2+json"
RUNNER_PREFERENCES = ("mlx", "llamacpp", "ggml")   # the manifest-list child Ollama runs on Apple Silicon
MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*")
# Manifest layers that are metadata, not weights; every other layer (model, projector, adapter, draft,
# tensors...) counts toward a model's weights fingerprint.
META_LAYERS = {"application/vnd.ollama.image." + t for t in ("template", "system", "params", "license", "messages")}
TMP_ALIAS_PREFIX = "secstack-tmp-"
# Modelfile commands an exported Modelfile may carry. FROM comes from the catalog; num_ctx/num_predict
# from the plan; anything else (ADAPTER, DRAFT, CAPABILITY, REQUIRES, ...) is refused.
MF_ALLOWED = ("TEMPLATE", "SYSTEM", "PARAMETER", "MESSAGE", "LICENSE", "RENDERER", "PARSER")
MF_DROPPED_PARAMS = ("num_ctx", "num_predict")
# Ollama's Modelfile command words (parser.isValidCommand, v0.40) and MESSAGE roles. Its parser names a
# PARAMETER command after the parameter, and CreateRequest then switches on that name, so "PARAMETER model
# x" is a FROM: commands are classified by the parsed name, never by the first word of a line.
MF_COMMANDS = ("from", "license", "template", "system", "adapter", "draft", "renderer", "parser", "parameter",
               "message", "requires", "capability")
MF_KEPT = ("template", "system", "license", "renderer", "parser", "message")
MF_REFUSED = ("model", "adapter", "draft", "requires", "capability")
MF_ROLES = ("system", "user", "assistant")
CTX_RANGE = (2048, 262144)


class PlanError(Exception):
    pass


def _digits(s) -> bool:
    s = str(s)
    return s.isascii() and s.isdigit()


def _printable(s, limit=60) -> str:
    return "".join(ch for ch in str(s) if 32 <= ord(ch) < 127)[:limit]


def _round(x: float) -> int:
    """Round half up (Python's round() is banker's rounding: round(16.5) == 16)."""
    return int(x + 0.5)


# --------------------------------------------------------------------------- hardware
@dataclass
class Hardware:
    os: str
    arm64: bool
    translated: bool
    chip: str
    ram_gb: float
    cpus: int
    p_cores: int = 0          # perflevel0 cores (fastest cluster)
    e_cores: int = 0          # perflevel1 cores
    core_levels: str = ""     # e.g. "6 Super + 12 Performance" (M5) or "10 Performance + 4 Efficiency"
    gpu_cores: int = 0
    macos: str = ""
    free_disk_gb: float = 0.0       # on the volume that holds the models (OLLAMA_MODELS)
    wired_limit_mb: int = 0
    simulated: bool = False
    images_free_gb: float = 0.0     # on the home volume (Docker Desktop's disk image)
    same_volume: bool = True        # models and Docker draw on the same free space
    wired_limit_key: str = ""       # the sysctl wired_limit_mb was read from
    staging_free_gb: float = 0.0    # where Hugging Face GGUF files are downloaded (MODELS_DIR)
    staging_same_volume: bool = True    # ... sharing the models' free space
    staging_home_volume: bool = True    # ... sharing the home volume's free space (Docker images)

    def summary(self) -> str:
        cores = f"{self.cpus} CPU cores"
        if self.core_levels:
            cores += f" ({self.core_levels})"
        elif self.p_cores:
            cores += f" ({self.p_cores}+{self.e_cores})"
        parts = [self.chip, cores]
        if self.gpu_cores:
            parts.append(f"{self.gpu_cores}-core GPU")
        parts.append(f"{self.ram_gb:.0f} GB unified memory")
        if self.macos:
            parts.append(f"macOS {self.macos}")
        parts.append(f"{self.free_disk_gb:.0f} GB free" + ("" if self.same_volume else
                     f" for models ({self.images_free_gb:.0f} GB on the system volume)"))
        if not self.staging_same_volume:
            parts.append(f"{self.staging_free_gb:.0f} GB free for GGUF downloads")
        s = " | ".join(parts)
        return s + (" [simulated]" if self.simulated else "")


def _run(cmd, timeout=10) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return p.stdout.strip() if p.returncode == 0 else ""


def _int(s, default=0) -> int:
    s = str(s).strip()
    return int(s) if _digits(s) else default


def _existing(path) -> Path:
    """path, or its nearest existing parent."""
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    return p


def _free_gb(path: Path) -> tuple:
    """(free GiB, device id) of the volume holding path (or its nearest existing parent)."""
    p = _existing(path)
    try:
        return shutil.disk_usage(str(p)).free / GIB, os.stat(p).st_dev
    except OSError:
        return 0.0, -1


SAME_FREE_GB = 0.1   # two volumes reporting the same free space (to 0.1 GB) are taken to share it


def _apfs_container(path) -> str:
    """APFS container (e.g. "disk3") of the volume holding path; "" when unknown or not APFS."""
    if platform.system() != "Darwin":
        return ""
    lines = _run([DF, "-P", str(_existing(path))]).splitlines()
    dev = lines[1].split()[0] if len(lines) > 1 and lines[1].split() else ""
    if not dev.startswith("/dev/"):
        return ""
    try:
        ref = plistlib.loads(_run([DISKUTIL, "info", "-plist", dev], timeout=20).encode()).get("APFSContainerReference")
    except (ValueError, AttributeError, ExpatError):
        return ""
    return ref if isinstance(ref, str) else ""


def _same_pool(a: tuple, b: tuple, containers: dict) -> bool:
    """Whether two (path, free GiB, device id) draw on the same free space: one volume, two APFS
    volumes of one container (each has its own device id, but they share the container's free
    space), or, when neither can be told, the same free space reported on both."""
    (pa, free_a, dev_a), (pb, free_b, dev_b) = a, b
    if dev_a == dev_b:
        return True
    for p in (pa, pb):
        if p not in containers:
            containers[p] = _apfs_container(p)
    if containers[pa] and containers[pa] == containers[pb]:
        return True
    return abs(free_a - free_b) < SAME_FREE_GB


VOLUMES = "/Volumes"   # where macOS mounts other drives, disk images and network shares


def _unmounted_volume(path) -> str:
    """The /Volumes/<name> that path resolves under (through any symlink, a dangling one too) when no
    volume is mounted there; "" otherwise, and off macOS. A folder left behind there isn't the drive.
    ("/Volumes/Macintosh HD" is a link to /, so the boot volume never counts.)"""
    if platform.system() != "Darwin":
        return ""
    real = os.path.realpath(path)
    # /Volumes is a firmlink to /System/Volumes/Data/Volumes, which realpath doesn't resolve: both spellings.
    for root in (VOLUMES.rstrip("/"), "/System/Volumes/Data" + VOLUMES.rstrip("/")):
        if real.lower().startswith(root.lower() + "/"):   # APFS ignores case: /volumes/T7 is /Volumes/T7
            mount = real[:len(root) + 1] + real[len(root) + 1:].split("/", 1)[0]
            return "" if os.path.ismount(mount) else mount
    return ""


def _volumes() -> dict:
    """Free space where the models (OLLAMA_MODELS), Docker's images (home) and GGUF downloads
    (MODELS_DIR) go, and which of them share it. A folder on a drive that isn't mounted is refused:
    measured anyway, it falls back to its nearest existing parent, /Volumes on the internal disk, with
    other free space and none of the drive's models."""
    for what, p in (("Ollama's model store", OLLAMA_MODELS), ("The GGUF download folder", MODELS_DIR)):
        mount = _unmounted_volume(p)
        if mount:
            real = os.path.realpath(p)
            link = f" (a link to {_printable(real, 300)})" if real != os.path.abspath(p) else ""
            raise PlanError(f"{what} {_printable(p, 300)}{link} is on {_printable(mount, 300)}, which isn't "
                            "mounted: the plan would measure the internal disk instead. Connect that drive "
                            "and re-run.")
    models, home, staging = ((p,) + _free_gb(p) for p in (OLLAMA_MODELS, HOME, MODELS_DIR))
    seen = {}
    return {"free_disk_gb": models[1], "images_free_gb": home[1], "staging_free_gb": staging[1],
            "same_volume": _same_pool(models, home, seen),
            "staging_same_volume": _same_pool(staging, models, seen),
            "staging_home_volume": _same_pool(staging, home, seen)}


def detect(volumes: bool = True) -> Hardware:
    """This Mac's hardware. volumes=False leaves out the free disk, for a simulation given its own."""
    system = platform.system()
    vols = _volumes() if volumes else {}
    if system != "Darwin":
        try:
            ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / GIB
        except (ValueError, OSError, AttributeError):
            ram = 0.0
        return Hardware(os=system, arm64=False, translated=False, chip=_printable(platform.machine()),
                        ram_gb=ram, cpus=os.cpu_count() or 1, **vols)
    sysctl = lambda key: _run([SYSCTL, "-n", key])  # noqa: E731
    gpu = 0
    sp = _run(["/usr/sbin/system_profiler", "SPDisplaysDataType", "-json"], timeout=30)
    if sp:
        try:
            for item in json.loads(sp).get("SPDisplaysDataType", []):
                gpu = max(gpu, _int(item.get("sppci_cores")))
        except (ValueError, AttributeError, TypeError):
            gpu = 0
    # Core clusters: perflevel0 is the fastest; names differ by chip (M5: "Super"/"Performance").
    levels = []
    for i in range(min(_int(sysctl("hw.nperflevels")), 4)):
        n = _int(sysctl(f"hw.perflevel{i}.physicalcpu"))
        if n:
            levels.append(f"{n} {_printable(sysctl(f'hw.perflevel{i}.name') or f'level{i}', 20)}")
    wired, wired_key = _int(sysctl("iogpu.wired_limit_mb")), "iogpu.wired_limit_mb"
    if not wired:                                   # macOS 13 used debug.iogpu.wired_limit (bytes)
        wired, wired_key = _int(sysctl("debug.iogpu.wired_limit")) // (1024 * 1024), "debug.iogpu.wired_limit"
    return Hardware(
        os=system,
        arm64=sysctl("hw.optional.arm64") == "1",
        translated=sysctl("sysctl.proc_translated") == "1",
        chip=_printable(sysctl("machdep.cpu.brand_string") or "unknown"),
        ram_gb=_int(sysctl("hw.memsize")) / GIB,
        cpus=_int(sysctl("hw.ncpu"), os.cpu_count() or 1),
        p_cores=_int(sysctl("hw.perflevel0.physicalcpu")),
        e_cores=_int(sysctl("hw.perflevel1.physicalcpu")),
        core_levels=" + ".join(levels),
        gpu_cores=gpu,
        macos=_printable(_run(["/usr/bin/sw_vers", "-productVersion"]), 20),
        wired_limit_mb=wired,
        wired_limit_key=wired_key if wired else "",
        **vols,
    )


def simulate(ram_gb, cpus=None, disk_gb=None, base: Hardware | None = None) -> Hardware:
    disk = float(disk_gb if disk_gb is not None else (base.free_disk_gb if base else 500))
    return Hardware(os="Darwin", arm64=True, translated=False, chip="Apple Silicon",
                    ram_gb=float(ram_gb), cpus=int(cpus or (base.cpus if base and base.cpus else 10)),
                    free_disk_gb=disk, images_free_gb=disk, same_volume=True, staging_free_gb=disk,
                    simulated=True)


# --------------------------------------------------------------------------- local state
@dataclass
class LocalState:
    """What is already on this Mac, so a re-plan doesn't charge the disk for it twice."""
    installed: set = field(default_factory=set)   # catalog aliases with an Ollama manifest
    installed_gb: float = 0.0
    images_present: bool = False


def _alias_installed(alias: str) -> bool:
    # The alias's manifest, in whichever layout this Ollama keeps it (manifests-v2 or the legacy tree).
    return _manifest_file(alias) is not None


def _images_built():
    """Whether Docker holds the locally built images (hexstrike-kali stands for all of them): True or
    False when Docker answers, None when it doesn't (not installed, or not running)."""
    docker = shutil.which("docker") or DOCKER_FALLBACK
    if not os.access(docker, os.X_OK):
        return None
    if _run([docker, "image", "inspect", "--format", "{{.Id}}", "hexstrike-kali"], timeout=15):
        return True
    return False if _run([docker, "version", "--format", "{{.Server.Version}}"], timeout=15) else None


def local_state(catalog: list) -> LocalState:
    st = LocalState()
    for m in chat_models(catalog):
        if _alias_installed(m["alias"]):
            st.installed.add(m["alias"])
            st.installed_gb += float(m["size_gb"])
    live = _images_built()
    if live is not None:   # what Docker has wins: images can be pruned or purged after an install
        st.images_present = live
        return st
    try:  # Docker is down: the models step runs after the images step, so a recorded install means images exist
        st.images_present = bool(json.loads(SELECTED.read_text(errors="replace")).get("installed"))
    except (OSError, ValueError, AttributeError):
        st.images_present = False
    return st


# --------------------------------------------------------------------------- resource plan
@dataclass
class Plan:
    ram_gb: int
    os_reserve_gb: int
    docker_vm_gb: int
    docker_cpus: int
    docker_swap_gb: int
    metal_limit_gb: float
    fence_gb: int
    ctx: int
    parallel: int
    kv_type: str
    max_tokens: int
    model_budget_gb: int
    max_chat_models: int
    hexstrike_cpus: int
    hexstrike_mem_gb: int
    new_disk_gb: int = 0                                 # free disk for models not installed yet
    installed: list = field(default_factory=list)        # catalog aliases already in Ollama
    warnings: list = field(default_factory=list)
    images_reserve_gb: int = 0         # held back from new_disk_gb for Docker images not built yet
    staging_shared: bool = True        # GGUF downloads share new_disk_gb with the models
    staging_disk_gb: int = 0           # otherwise: free for a GGUF download on its own volume
    staging_reserve_gb: int = 0        # ... after this much for Docker images (when it's the home volume)


CTX_WARNING = ("16K context: pentagi's long agent prompts may be truncated. "
               "Use 5ire + HexStrike for most work on this machine.")


def metal_limit_gb(ram_gb: float, wired_limit_mb: int = 0) -> float:
    """GPU-usable unified memory (Metal recommendedMaxWorkingSetSize). Apple doesn't publish the default;
    ~2/3 of RAM up to 36 GB and ~3/4 above is the commonly measured split (recent 16-24 GB Macs report
    ~74%, so this errs low). Below 64 GB the RAM split, not this limit, sets the fence anyway."""
    if wired_limit_mb and wired_limit_mb > 0:
        return wired_limit_mb / 1024
    return ram_gb * (2 / 3 if ram_gb <= 36 else 3 / 4)


def default_budget_cap(ram_gb: int) -> int:
    env = os.environ.get("SECSTACK_MODEL_BUDGET_GB", "").strip()
    if _digits(env) and 5 <= int(env) <= 4000:
        return int(env)
    return MODEL_BUDGET_CAP_GB if ram_gb <= 64 else int(ram_gb * 1.2)


def compute_plan(hw: Hardware, max_models: int = MAX_CHAT_MODELS, budget_cap: int | None = None,
                 state: LocalState | None = None) -> Plan:
    if hw.os != "Darwin" or not hw.arm64:
        raise PlanError(f"secstack needs an Apple Silicon Mac (detected {hw.os} / {hw.chip or 'unknown'}).")
    ram = _round(hw.ram_gb)
    if ram < MIN_RAM_GB:
        raise PlanError(f"{ram} GB of memory is below the {MIN_RAM_GB} GB minimum.")
    state = state or LocalState()
    warnings = []
    docker_vm = min(20, max(6, _round(ram * 0.33)))
    os_reserve = min(12, max(5, _round(ram * 0.17)))
    metal = metal_limit_gb(ram, hw.wired_limit_mb)
    fence = max(0, int(min(ram - docker_vm - os_reserve, metal - 1)))
    if fence >= 48:
        ctx, parallel = 32768, 4
    elif fence >= 20:
        ctx, parallel = 32768, 2
    elif fence >= 10:
        ctx, parallel = 32768, 1
    else:
        ctx, parallel = 16384, 1
        warnings.append(CTX_WARNING)
    if ram <= 18:
        warnings.append("16-18 GB: run one framework at a time and expect small (4-8B) models.")
    if hw.translated:
        warnings.append("This shell runs under Rosetta. Use a native arm64 terminal for builds.")
    if hw.wired_limit_mb and hw.wired_limit_mb > 0:
        if hw.wired_limit_key == "debug.iogpu.wired_limit":   # macOS 13: bytes, under another name
            warnings.append(f"debug.iogpu.wired_limit is set (about {hw.wired_limit_mb} MB); the plan uses it as "
                            "the GPU limit (sudo sysctl debug.iogpu.wired_limit=0 restores the default).")
        else:
            warnings.append(f"iogpu.wired_limit_mb is set to {hw.wired_limit_mb}; the plan uses it as the GPU limit "
                            "(sudo sysctl iogpu.wired_limit_mb=0 restores the default).")
    cpus = max(1, int(hw.cpus))
    docker_cpus = min(cpus, 8, max(4, cpus // 2))
    # Docker's images go on the home volume; they only compete with models when both share it.
    reserve = 0 if state.images_present or not hw.same_volume else DOCKER_IMAGES_GB
    if budget_cap is None:
        budget_cap = default_budget_cap(ram)
    # Models still to download must fit the free disk, less the image reserve and the headroom.
    # Installed models are on disk already (free space excludes them) and need no headroom of their
    # own: every installed catalog chat model, selected or not, is credited on top for the total.
    new_disk = max(0, math.floor(hw.free_disk_gb - reserve - DISK_SAFETY_GB))
    budget = min(budget_cap, new_disk + math.ceil(round(state.installed_gb, 1)))
    # A Hugging Face model is downloaded as a GGUF file into MODELS_DIR, then copied into Ollama's
    # store: until the file is deleted it needs its size twice. On the models' own free space that is
    # counted against new_disk; on another volume, against that volume (less the image reserve when
    # Docker's images go there too).
    staging_reserve, staging_disk = 0, 0
    if not hw.staging_same_volume:
        staging_reserve = DOCKER_IMAGES_GB if hw.staging_home_volume and not state.images_present else 0
        staging_disk = max(0, math.floor(hw.staging_free_gb - staging_reserve - DISK_SAFETY_GB))
    if reserve and hw.free_disk_gb < reserve + DISK_SAFETY_GB:
        # The images still to build don't fit with the headroom, whatever is installed (installed models
        # raise the budget, so it can't tell). Shown rounded down: never as much as they need.
        warnings.append(f"Only {math.floor(hw.free_disk_gb * 10) / 10:.1f} GB free: Docker images need ~{reserve} GB, "
                        f"and {DISK_SAFETY_GB} GB stays free as headroom. Free up disk space.")
    elif budget < 5:
        need = f"Docker images need ~{DOCKER_IMAGES_GB} GB plus models" if reserve else "models need room"
        warnings.append(f"Only {hw.free_disk_gb:.0f} GB free: {need}, and {DISK_SAFETY_GB} GB stays free as "
                        "headroom. Free up disk space.")
    if not hw.same_volume and not state.images_present and hw.images_free_gb < DOCKER_IMAGES_GB + DISK_SAFETY_GB:
        warnings.append(f"Only {hw.images_free_gb:.0f} GB free on the system volume: Docker images need "
                        f"~{DOCKER_IMAGES_GB} GB there.")
    return Plan(
        ram_gb=ram, os_reserve_gb=os_reserve, docker_vm_gb=docker_vm, docker_cpus=docker_cpus,
        docker_swap_gb=1, metal_limit_gb=round(metal, 1), fence_gb=fence, ctx=ctx, parallel=parallel,
        kv_type="q8_0", max_tokens=min(16384, ctx // 2), model_budget_gb=max(0, budget),
        max_chat_models=max(1, min(max_models, MAX_CHAT_MODELS)),
        hexstrike_cpus=max(1, min(4, docker_cpus // 2)), hexstrike_mem_gb=4 if docker_vm >= 12 else 2,
        new_disk_gb=new_disk, installed=sorted(state.installed), warnings=warnings,
        images_reserve_gb=reserve, staging_shared=hw.staging_same_volume, staging_disk_gb=staging_disk,
        staging_reserve_gb=staging_reserve)


def resident_gb(m: dict, ctx: int, parallel: int) -> float:
    """Estimated memory with the model loaded: weights + KV cache (num_ctx x parallel) + compute buffers."""
    tokens = ctx * parallel
    kv = float(m.get("kv_gb_32k", 0.0)) * tokens / 32768
    overhead = 1.0 + 0.5 * tokens / 65536 + (0.5 if m.get("vision") else 0.0)
    return round(float(m["size_gb"]) + kv + overhead, 1)


def fits(m: dict, plan: Plan) -> bool:
    return m["role"] == "embed" or resident_gb(m, plan.ctx, plan.parallel) <= plan.fence_gb


def finalize_context(plan: Plan, models: list) -> Plan:
    """After the models are chosen, raise a 16K plan to 32K when every chosen model fits there at the
    plan's parallel count. Nothing is ever lowered: validate_selection already holds the tier."""
    chat = [m for m in models if m["role"] != "embed"]
    if plan.ctx >= 32768 or not chat:
        return plan
    if all(resident_gb(m, 32768, plan.parallel) <= plan.fence_gb for m in chat):
        warnings = [w for w in plan.warnings if w != CTX_WARNING]
        return dataclasses.replace(plan, ctx=32768, max_tokens=16384, warnings=warnings)
    return plan


# --------------------------------------------------------------------------- catalog
REQUIRED = ("id", "alias", "name", "family", "role", "tools", "vision", "abliterated", "source",
            "size_gb", "kv_gb_32k", "rank", "provider", "notes")


def validate_catalog(models) -> list:
    errs = []
    if not isinstance(models, list) or not models:
        return ["catalog has no models"]
    if len(models) > CATALOG_MAX:
        errs.append(f"catalog has {len(models)} models; the limit is {CATALOG_MAX}")
    seen = {"id": set(), "alias": set(), "provider": set()}
    embeds = 0
    for m in models:
        if not isinstance(m, dict):
            errs.append("catalog entry is not an object")
            continue
        mid = _printable(m.get("id", "?"), 48)
        missing = [k for k in REQUIRED if k not in m]
        if missing:
            errs.append(f"{mid}: missing {', '.join(missing)}")
            continue
        for k in ("id", "alias", "name", "family", "role", "provider", "notes"):
            if not isinstance(m[k], str):
                errs.append(f"{mid}: {k} must be a string")
        if errs and errs[-1].startswith(f"{mid}: ") and "must be a string" in errs[-1]:
            continue
        if not ID_RE.fullmatch(m["id"]):
            errs.append(f"{mid}: bad id")
        if not ALIAS_RE.fullmatch(m["alias"]):
            errs.append(f"{mid}: bad alias {_printable(m['alias'])!r}")
        if m["role"] not in ROLES + ("embed",):
            errs.append(f"{mid}: role must be one of {ROLES + ('embed',)}")
        if m["role"] == "embed":
            embeds += 1
        elif not PROVIDER_RE.fullmatch(m["provider"]):
            errs.append(f"{mid}: bad provider name {_printable(m['provider'])!r}")
        for k in ("tools", "vision", "abliterated"):
            if not isinstance(m[k], bool):
                errs.append(f"{mid}: {k} must be true/false")
        if "reasoning_off" in m and not isinstance(m["reasoning_off"], bool):
            errs.append(f"{mid}: reasoning_off must be true/false")
        if m.get("weights_sha256") is not None and not HEX64.fullmatch(str(m["weights_sha256"])):
            errs.append(f"{mid}: weights_sha256 must be 64 lowercase hex or null")
        for k in ("size_gb", "kv_gb_32k"):
            if not isinstance(m[k], (int, float)) or isinstance(m[k], bool) or not 0 <= m[k] <= 400:
                errs.append(f"{mid}: {k} out of range")
        if not isinstance(m["rank"], int) or isinstance(m["rank"], bool):
            errs.append(f"{mid}: rank must be an integer")
        src = m["source"] if isinstance(m["source"], dict) else {}
        if ((ALIAS_RE.fullmatch(m["alias"]) and _name_parts(m["alias"]) is None)
                or m["alias"].startswith(TMP_ALIAS_PREFIX)):
            errs.append(f"{mid}: alias {_printable(m['alias'])!r} is a name Ollama reads as a blob digest, "
                        "or secstack's temporary build name")
        if src.get("type") == "ollama":
            if not REF_RE.fullmatch(str(src.get("ref", ""))):
                errs.append(f"{mid}: bad ollama ref (namespace/name:tag on the default registry only, "
                            "no :cloud, :local or -cloud tag)")
            elif _name_parts(src["ref"]) is None:
                errs.append(f"{mid}: ollama ref {_printable(src['ref'])!r} is a name Ollama reads as a blob digest")
            if m["role"] == "embed" and src.get("ref") != m["alias"]:
                errs.append(f"{mid}: the embedding model's alias must equal its ref")
        elif src.get("type") == "hf":
            if not HF_REPO_RE.fullmatch(str(src.get("repo", ""))):
                errs.append(f"{mid}: bad hf repo")
            if not HF_FILE_RE.fullmatch(str(src.get("file", ""))):
                errs.append(f"{mid}: bad hf file (plain *.gguf name, no paths)")
            if src.get("revision") is not None and not HEX40.fullmatch(str(src["revision"])):
                errs.append(f"{mid}: revision must be a 40-hex commit")
            if src.get("sha256") is not None and not HEX64.fullmatch(str(src["sha256"])):
                errs.append(f"{mid}: sha256 must be 64 lowercase hex")
            if m["role"] == "embed":
                errs.append(f"{mid}: embedding model must come from the Ollama library")
        else:
            errs.append(f"{mid}: source.type must be ollama or hf")
        for k in seen:
            v = m[k]
            if k == "provider" and m["role"] == "embed":
                continue
            if v in seen[k]:
                errs.append(f"{mid}: duplicate {k} {_printable(v)!r}")
            seen[k].add(v)
    # A chat model's source may not be any catalog alias: `ollama pull` would write straight into that
    # alias before any check ran. (The embedding model's alias is its source on purpose.)
    aliases = {_canon_name(m["alias"]) for m in models if isinstance(m, dict) and isinstance(m.get("alias"), str)}
    for m in models:
        src = m.get("source") if isinstance(m, dict) else None
        if (isinstance(src, dict) and m.get("role") != "embed" and src.get("type") == "ollama"
                and isinstance(src.get("ref"), str) and _canon_name(src["ref"]) in aliases):
            errs.append(f"{_printable(m.get('id', '?'), 48)}: source {_printable(src['ref'])!r} is a catalog alias; "
                        "pulling it would replace that alias unchecked")
    if embeds != 1:
        errs.append(f"catalog needs exactly one embedding model (found {embeds})")
    return errs


def load_catalog(path: Path = CATALOG_PATH) -> list:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise PlanError(f"cannot read {path}: {e}")
    models = data.get("models") if isinstance(data, dict) else None
    errs = validate_catalog(models)
    if errs:
        raise PlanError("catalog invalid:\n  " + "\n  ".join(errs))
    return models


def embed_model(catalog: list) -> dict:
    return next(m for m in catalog if m["role"] == "embed")


def chat_models(catalog: list) -> list:
    return [m for m in catalog if m["role"] != "embed"]


def find_model(catalog: list, key: str) -> dict:
    for m in catalog:
        if key in (m["id"], m["alias"]):
            return m
    raise PlanError(f"unknown model {_printable(key)!r}. Known: {', '.join(m['id'] for m in chat_models(catalog))}")


def weights_digest(m: dict):
    """Expected sha256 of the weights blob: the GGUF's sha256 for HF imports, else the pinned value."""
    if m["source"].get("type") == "hf" and m["source"].get("sha256"):
        return m["source"]["sha256"]
    return m.get("weights_sha256")


# --------------------------------------------------------------------------- recommendation / selection
def _primary(models: list):
    """Highest-ranked tool-calling model, workhorse role first, then deep, then alt."""
    for role in ROLES:
        cands = [m for m in models if m["role"] == role and m["tools"]]
        if cands:
            return max(cands, key=lambda m: (m["rank"], -m["size_gb"]))
    return None


def _new_download_gb(models: list, plan: Plan) -> float:
    return sum(float(m["size_gb"]) for m in models if m["alias"] not in plan.installed)


def _staging_gb(models: list, plan: Plan) -> float:
    """The largest Hugging Face model still to download: its GGUF file stays next to Ollama's copy
    until the import finishes (models are imported one at a time, and the file is deleted after)."""
    return max((float(m["size_gb"]) for m in models
                if m["alias"] not in plan.installed and (m.get("source") or {}).get("type") == "hf"), default=0.0)


def disk_errors(models: list, plan: Plan) -> list:
    """Why these chat models don't fit the disk; empty when they do."""
    errs = []
    total = sum(float(m["size_gb"]) for m in models)
    if total > plan.model_budget_gb:
        errs.append(f"selection needs {total:.1f} GB of disk; the model budget is {plan.model_budget_gb} GB")
    new, gguf = _new_download_gb(models, plan), _staging_gb(models, plan)
    after = (f"after ~{plan.images_reserve_gb} GB for Docker images and " if plan.images_reserve_gb else "after ")
    if new + (gguf if plan.staging_shared else 0) > plan.new_disk_gb:
        extra = f" (plus {gguf:.1f} GB while the Hugging Face download is imported)" if gguf and plan.staging_shared else ""
        errs.append(f"the models not installed yet need {new:.1f} GB{extra}; {plan.new_disk_gb} GB of disk is free "
                    f"for them ({after}{DISK_SAFETY_GB} GB headroom)")
    if not plan.staging_shared and gguf > plan.staging_disk_gb:
        after = (f"after ~{plan.staging_reserve_gb} GB for Docker images and " if plan.staging_reserve_gb else "after ")
        errs.append(f"the Hugging Face download needs {gguf:.1f} GB in {_printable(MODELS_DIR, 80)} until it is "
                    f"imported; {plan.staging_disk_gb} GB is free there ({after}{DISK_SAFETY_GB} GB headroom)")
    return errs


def recommend(plan: Plan, catalog: list) -> list:
    """Best combination of one model per role (workhorse, deep, alt) that fits the fence, the disk
    budget and the model count. Preference: the best primary (a workhorse when one fits, then the
    highest rank), then the most roles filled, then the other roles' ranks, then the smaller total
    download. The alt (vision) model must be a different family than the primary, so it can
    cross-check it."""
    pools = []
    for role in ROLES:
        pools.append([m for m in chat_models(catalog) if m["role"] == role and fits(m, plan)] + [None])
    best, best_key = [], None
    for combo in itertools.product(*pools):
        models = [m for m in combo if m]
        if not models or len(models) > plan.max_chat_models:
            continue
        primary = _primary(models)
        if primary is None:
            continue
        if disk_errors(models, plan):
            continue
        w, d, a = combo
        if a is not None and a is not primary and a["family"] == primary["family"]:
            continue
        key = (-ROLES.index(primary["role"]), primary["rank"], len(models), w["rank"] if w else -1,
               d["rank"] if d else -1, a["rank"] if a else -1, -sum(m["size_gb"] for m in models))
        if best_key is None or key > best_key:
            best, best_key = models, key
    return best


def validate_selection(sel: list, plan: Plan) -> list:
    errs = []
    chat = [m for m in sel if m["role"] != "embed"]
    if not chat:
        errs.append("select at least one chat model")
    if len(chat) > plan.max_chat_models:
        errs.append(f"{len(chat)} chat models selected; the limit is {plan.max_chat_models}")
    if len({m["id"] for m in chat}) != len(chat):
        errs.append("a model is selected twice")
    for m in chat:
        need = resident_gb(m, plan.ctx, plan.parallel)
        if need > plan.fence_gb:
            errs.append(f"{m['id']} needs ~{need} GB loaded; this Mac's model fence is {plan.fence_gb} GB")
    errs += disk_errors(chat, plan)
    if chat and not any(m["tools"] for m in chat):
        errs.append("at least one selected model must support tool calling (agents need it)")
    return errs


def assign_roles(sel: list, primary: str | None = None) -> dict:
    chat = [m for m in sel if m["role"] != "embed"]
    if primary:
        p = next((m for m in chat if primary in (m["id"], m["alias"])), None)
        if p is None:
            raise PlanError(f"--primary {_printable(primary)!r} is not in the selection")
        if not p["tools"]:
            raise PlanError(f"{p['id']} does not support tool calling and can't be the primary model")
    else:
        p = _primary(chat)
        if p is None:
            raise PlanError("no tool-calling model in the selection")
    rest = [m for m in chat if m is not p]
    deep = max((m for m in rest if m["role"] == "deep"), key=lambda m: m["rank"], default=None)
    alt = max((m for m in rest if m["role"] == "alt"), key=lambda m: m["rank"], default=None)
    return {"chat": p, "deep": deep, "alt": alt, "all": chat}


def with_primary(catalog: list, ids: list, key: str, plan: Plan) -> tuple:
    """(ids, primary id) with the model `key` (id or alias) as the primary. A model that isn't selected
    yet takes the place of the pick(s) in its role; one that is selected stays where it is. Used by
    select --yes --primary, the interactive --primary and 'p N'."""
    m = find_model(catalog, key)
    if m["role"] == "embed" or not m["tools"]:
        raise PlanError(f"{m['id']} doesn't support tool calling, so it can't be the primary model")
    if m["id"] in ids:
        return list(ids), m["id"]
    rest = [i for i in ids if find_model(catalog, i)["role"] != m["role"]]
    return rest[: plan.max_chat_models - 1] + [m["id"]], m["id"]


# --------------------------------------------------------------------------- generated files
def _safe(v) -> str:
    s = str(v)
    if not SAFE_VALUE.fullmatch(s):
        raise PlanError(f"refusing to write unsafe config value {_printable(s)!r}")
    return s


def stack_conf_text(hw: Hardware, plan: Plan, roles: dict, embed: dict) -> str:
    vals = [
        ("STACK_VERSION", 1),
        ("CHAT_MODEL", roles["chat"]["alias"]),
        ("DEEP_MODEL", roles["deep"]["alias"] if roles["deep"] else "none"),
        ("ALT_MODEL", roles["alt"]["alias"] if roles["alt"] else "none"),
        ("MODELS", ",".join(m["alias"] for m in roles["all"])),
        ("EMBED_MODEL", embed["alias"]),
        ("PENTAGI_DEFAULT_PROVIDER", roles["chat"]["provider"]),
        ("OLLAMA_CONTEXT_LENGTH", plan.ctx),
        ("OLLAMA_NUM_PARALLEL", plan.parallel),
        ("OLLAMA_KV_CACHE_TYPE", plan.kv_type),
        ("MAX_TOKENS", plan.max_tokens),
        ("INFERENCE_FENCE_GB", plan.fence_gb),
        ("MODEL_BUDGET_GB", plan.model_budget_gb),
        ("MAX_CHAT_MODELS", plan.max_chat_models),
        ("RAM_GB", plan.ram_gb),
        ("OS_RESERVE_GB", plan.os_reserve_gb),
        ("DOCKER_VM_GB", plan.docker_vm_gb),
        ("DOCKER_VM_CPUS", plan.docker_cpus),
        ("DOCKER_SWAP_GB", plan.docker_swap_gb),
        ("HEXSTRIKE_CPUS", plan.hexstrike_cpus),
        ("HEXSTRIKE_MEM_GB", plan.hexstrike_mem_gb),
    ]
    head = [f"# secstack stack config, generated by {GEN_MARK} on {dt.datetime.now().isoformat(timespec='seconds')}",
            f"# for: {_printable(hw.summary(), 160)}",
            "# Re-run ./setup.sh --only plan (or scripts/plan.py select --write) to change it. Plain KEY=VALUE; not sourced."]
    return "\n".join(head + [f"{k}={_safe(v)}" for k, v in vals]) + "\n"


def read_conf(path: Path = STACK_CONF) -> dict:
    """Same rules as bin/secstack conf(): split on LF, strip one trailing CR, last occurrence wins,
    empty or unsafe values count as absent."""
    out = {}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return out
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        mt = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(.*)", line)
        if not mt:
            continue
        k, v = mt.group(1), mt.group(2)
        if v and SAFE_VALUE.fullmatch(v):
            out[k] = v
        else:
            out.pop(k, None)
    return out


def _reasoning(m: dict) -> dict:
    # pentagi refuses reasoning "off" for models that can't disable it (gpt-oss); use low effort there.
    return {"mode": "off"} if m.get("reasoning_off", True) else {"effort": "low"}


def provider_doc(name: str, model: dict, adviser: dict | None, plan: Plan, note: str) -> dict:
    return {"name": name, "type": "ollama", "_generated_by": GEN_MARK, "_note": note,
            "default": {"model": model["alias"], "n": 1, "max_tokens": plan.max_tokens, "reasoning": _reasoning(model)},
            "roles": {"adviser": {"model": (adviser or model)["alias"], "reasoning": None}}}


def providers(roles: dict, plan: Plan) -> list:
    chat, deep = roles["chat"], roles["deep"]
    out = [(chat["provider"], provider_doc(chat["provider"], chat, None, plan,
                                           f"DEFAULT for new flows. {chat['name']} on every role; thinking off except adviser."))]
    if deep:
        out.append(("local-hybrid", provider_doc("local-hybrid", chat, deep, plan,
                                                 f"{chat['name']} everywhere, {deep['name']} as adviser with thinking on "
                                                 "(model swap each time the adviser runs).")))
    for m in roles["all"]:
        if m is not chat:
            out.append((m["provider"], provider_doc(m["provider"], m, None, plan,
                                                    f"{m['name']} on every role ({m['role']}).")))
    return [(f"{(i + 1) * 10:02d}-{name}.json", doc) for i, (name, doc) in enumerate(out)]


def ollama_provider_yml(model: dict, plan: Plan) -> str:
    alias = _safe(model["alias"])
    if model.get("reasoning_off", True):
        reasoning = ["  reasoning:", '    mode: "off"']
        head = "thinking off except adviser"
    else:
        reasoning = ["  reasoning:", '    effort: "low"']
        head = "low reasoning effort except adviser (this model can't turn thinking off)"
    out = [f"# Generated by {GEN_MARK}: {alias} on every role, {head}.", ""]
    for r in PENTAGI_ROLES:
        out += [f"{r}:", f'  model: "{alias}"', "  n: 1", f"  max_tokens: {plan.max_tokens}"]
        if r != "adviser":
            out += reasoning
        out.append("")
    return "\n".join(out)


def fiveire_config() -> str:
    data = json.loads(TEMPLATE_5IRE.read_text())
    subst = {"__SECOPS__": str(SECOPS), "__GH__": str(GH), "__HOME__": str(HOME)}

    def walk(x):
        if isinstance(x, str):
            for k, v in subst.items():
                x = x.replace(k, v)
            return x
        if isinstance(x, list):
            return [walk(i) for i in x]
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        return x
    data = walk(data)
    bridge = data.get("mcpServers", {}).get("pentagi-bridge")
    if bridge is not None:
        # The bridge reads PENTAGI_DEFAULT_PROVIDER from $SECOPS/configs/stack.conf at call time,
        # so a re-plan takes effect without editing 5ire's config.
        env = bridge.setdefault("env", {})
        env.pop("PENTAGI_PROVIDER", None)
        env["SECOPS"] = str(SECOPS)
    return json.dumps(data, indent=2) + "\n"


def _identity(p: str):
    """(st_dev, st_ino) of p, or None when it doesn't exist (yet)."""
    try:
        st = os.stat(p)
    except OSError:
        return None
    return st.st_dev, st.st_ino


def _lineage(p: str) -> set:
    """Identities of p and every folder above it that exists."""
    out, cur = set(), os.path.realpath(p)
    while True:
        ident = _identity(cur)
        if ident:
            out.add(ident)
        up = os.path.dirname(cur)
        if up == cur:
            return out
        cur = up


def _overlaps(a: Path, b: Path) -> bool:
    # By identity as well as by path: on APFS, ~/github/x and ~/GitHub/x are one folder under two
    # spellings, so string comparison alone would miss it (setup.sh and install.sh check the same way).
    ra, rb = os.path.realpath(a), os.path.realpath(b)
    if ra == rb or ra.startswith(rb + os.sep) or rb.startswith(ra + os.sep):
        return True
    ia, ib = _identity(ra), _identity(rb)
    return bool((ia and ia in _lineage(rb)) or (ib and ib in _lineage(ra)))


def _ensure_private_dir(p: Path) -> None:
    """Create p (700) or tighten it to 700 if we own it. Never follows a symlink."""
    if p.is_symlink():
        raise PlanError(f"{p} is a symlink; refusing to write generated files through it")
    if not p.exists():
        p.mkdir(parents=True, mode=0o700, exist_ok=True)
    st = p.stat()
    if st.st_uid == os.getuid() and st.st_mode & 0o077:
        os.chmod(p, 0o700)


def write_private(path: Path, text: str) -> None:
    _ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _prepare_providers_dir() -> None:
    """Earlier installs linked configs/pentagi-providers into the repo; generated files must not land there."""
    if PROVIDERS_DIR.is_symlink():
        target = Path(os.path.realpath(PROVIDERS_DIR))
        repo = Path(os.path.realpath(REPO))
        if repo in target.parents or target == repo:
            PROVIDERS_DIR.unlink()
        else:
            raise PlanError(f"{PROVIDERS_DIR} is a symlink to {target}; move it aside and re-run")
    _ensure_private_dir(PROVIDERS_DIR)


def _drop_stale_providers(keep: set) -> None:
    """Delete the generated provider files whose names aren't in keep; hand-made files stay."""
    for old in PROVIDERS_DIR.glob("*.json"):
        if old.name in keep:
            continue
        try:
            if json.loads(old.read_text()).get("_generated_by") == GEN_MARK:
                old.unlink()
        except (OSError, ValueError, AttributeError):
            continue


def _temp_beside(path: Path, text: str) -> str:
    """text in a new private (600) file in path's folder, for os.replace to put in place. The name doesn't
    end in .json, so nothing that reads the folder picks it up half-written."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return tmp


def write_outputs(hw: Hardware, plan: Plan, roles: dict, embed: dict) -> list:
    if _overlaps(SECOPS, REPO):
        raise PlanError(f"the runtime root {SECOPS} and the repo {REPO} overlap; clone the repo somewhere else")
    # Every file's text is built first, so a bad value changes nothing.
    conf_text = stack_conf_text(hw, plan, roles, embed)
    sel = {"generated": dt.datetime.now().isoformat(timespec="seconds"), "generated_by": GEN_MARK,
           "hardware": asdict(hw), "plan": asdict(plan), "primary": roles["chat"]["alias"],
           "models": roles["all"] + [embed]}
    try:  # keep the digest record of models that are still selected (see cmd_install_models)
        prev = json.loads(SELECTED.read_text(errors="replace")).get("installed", {})
        keep = {m["alias"] for m in sel["models"]}
        if isinstance(prev, dict):
            sel["installed"] = {k: v for k, v in prev.items() if k in keep}
    except (OSError, ValueError, AttributeError):
        pass
    files = [(SELECTED, json.dumps(sel, indent=1) + "\n")]
    files += [(PROVIDERS_DIR / fname, json.dumps(doc, indent=2) + "\n") for fname, doc in providers(roles, plan)]
    files += [(GEN / "ollama.provider.yml", ollama_provider_yml(roles["chat"], plan)),
              (GEN / "5ire-mcp.json", fiveire_config()),
              (STACK_CONF, conf_text)]
    # Then every file is written under a temporary name in its own folder, where a full disk or a folder
    # that can't be written shows up while nothing has changed. Only then are they renamed into place,
    # stack.conf last (secstack, setup.sh and the .env rendering read it), and the generated providers the
    # new plan doesn't have are deleted after that: until stack.conf is replaced, every reader sees the
    # previous plan whole, providers included.
    temps, placing = [], False
    try:
        for d in (SECOPS, CFG, GEN):
            _ensure_private_dir(d)
        _prepare_providers_dir()
        for path, text in files:
            temps.append((_temp_beside(path, text), path))
        placing = True
        while temps:
            os.replace(*temps[0])
            del temps[0]
    except BaseException as e:
        for tmp, _ in temps:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if not isinstance(e, OSError):
            raise
        if placing:   # a rename within its folder writes no data: this takes an I/O error or the like
            raise PlanError(f"couldn't put the new plan in place ({e}); some of its files may be new, but "
                            f"{STACK_CONF} still has the previous plan. Fix that and re-run.")
        raise PlanError(f"couldn't write the plan ({e}); the previous plan is unchanged. Fix that and re-run.")
    _drop_stale_providers({path.name for path, _ in files if path.parent == PROVIDERS_DIR})
    return [path for path, _ in files]


# --------------------------------------------------------------------------- output
def print_plan(hw: Hardware, plan: Plan, state: LocalState | None = None, final: Plan | None = None) -> None:
    shown = final or plan
    print(f"Hardware  {hw.summary()}")
    print(f"Plan      macOS + apps {plan.os_reserve_gb} GB | Docker VM {plan.docker_vm_gb} GB, "
          f"{plan.docker_cpus} CPUs, {plan.docker_swap_gb} GB swap | one model loaded, up to {plan.fence_gb} GB "
          f"(GPU limit ~{plan.metal_limit_gb:.0f} GB)")
    ctx = f"context {shown.ctx // 1024}K x {shown.parallel} parallel"
    if final is not None and (final.ctx, final.parallel) != (plan.ctx, plan.parallel):
        ctx += f" with these models ({plan.ctx // 1024}K x {plan.parallel} for this memory)"
    print(f"          {ctx}, KV {plan.kv_type}, max output {shown.max_tokens} tokens | "
          f"model storage up to {plan.model_budget_gb} GB, up to {plan.max_chat_models} chat models")
    if state and state.installed:
        print(f"          already installed: {', '.join(sorted(state.installed))} (counted as available disk)")
    for w in shown.warnings:
        print(f"  ! {w}")


def print_table(catalog: list, plan: Plan, selected_ids: list, primary_id: str | None) -> list:
    rows = chat_models(catalog)
    rows.sort(key=lambda m: (ROLES.index(m["role"]), -m["rank"]))
    print()
    print(f"  # sel  {'model':32s} {'role':9s} {'disk':>6s} {'loaded':>7s}  fit      notes")
    for i, m in enumerate(rows, 1):
        need = resident_gb(m, plan.ctx, plan.parallel)
        fit = "ok" if need <= plan.fence_gb else "too big"
        if fit == "ok" and disk_errors([m], plan):
            fit = "no disk"
        mark = "[x]" if m["id"] in selected_ids else ("[-]" if fit != "ok" else "[ ]")
        star = "*" if m["id"] == primary_id else " "
        tags = []
        if m["vision"]:
            tags.append("vision")
        if not m["tools"]:
            tags.append("no tools")
        if m.get("verified"):
            tags.append("benchmarked")
        if m["alias"] in plan.installed:
            tags.append("installed")
        note = _printable(", ".join(tags + [m["notes"]]), 200)
        note = note if len(note) <= 60 else note[:57].rstrip() + "..."
        print(f" {i:2d} {mark}{star} {_printable(m['alias'], 32):32s} {m['role']:9s} {m['size_gb']:5.1f}G {need:6.1f}G  "
              f"{fit:8s} {note}")
    emb = embed_model(catalog)
    print(f"      Embeddings: {_printable(emb['alias'])} ({emb['size_gb']} GB, always installed)")
    print("      * = primary (pentagi/ARTEX/5ire default)   [-] = doesn't fit this Mac")
    return rows


def _default_primary(catalog: list, ids: list) -> str | None:
    p = _primary([find_model(catalog, i) for i in ids])
    return p["id"] if p else None


def interactive_select(catalog: list, plan: Plan, preselect: list, primary: str | None = None) -> tuple:
    rec_ids = [m["id"] for m in recommend(plan, catalog)]
    sel = list(preselect) if preselect else list(rec_ids)
    if primary is not None and primary not in sel:
        primary = None
    while True:
        rows = print_table(catalog, plan, sel, primary or _default_primary(catalog, sel))
        print("\n  Toggle models by number (e.g. '2 5'), 'p N' = make N the primary (it replaces the pick in")
        print("  its role), 'r' = recommended, Enter = accept, 'q' = quit.")
        try:
            ans = input("  > ").strip().lower()
        except EOFError:
            raise PlanError("no answer (stdin closed); re-run with --yes or --models")
        if ans in ("q", "quit", "exit"):
            raise PlanError("cancelled")
        if ans == "r":
            sel, primary = list(rec_ids), None
            continue
        if ans == "":
            models = [find_model(catalog, i) for i in sel]
            errs = validate_selection(models, plan)
            if errs:
                print("\n  Can't accept this selection:")
                for e in errs:
                    print(f"    - {e}")
                continue
            return models, (primary or _default_primary(catalog, sel))
        toks = ans.replace(",", " ").split()
        if toks and toks[0] == "p":
            if len(toks) == 2 and _digits(toks[1]) and 1 <= int(toks[1]) <= len(rows):
                try:
                    sel, primary = with_primary(catalog, sel, rows[int(toks[1]) - 1]["id"], plan)
                except PlanError as e:
                    print(f"  {e}")
            else:
                print("  usage: p N")
            continue
        bad = next((t for t in toks if not (_digits(t) and 1 <= int(t) <= len(rows))), None)
        if bad is not None:
            print(f"  '{_printable(bad, 20)}' is not a model number")
            continue
        for t in toks:
            mid = rows[int(t) - 1]["id"]
            if mid in sel:
                sel.remove(mid)
                if primary == mid:
                    primary = None
            else:
                sel.append(mid)


# --------------------------------------------------------------------------- install
def ollama_bin() -> str:
    for c in (shutil.which("ollama"), OLLAMA_APP_CLI, "/usr/local/bin/ollama", "/opt/homebrew/bin/ollama"):
        if c and os.access(c, os.X_OK):
            return c
    raise PlanError("ollama CLI not found (install Ollama.app from https://ollama.com/download)")


def ollama_up() -> bool:
    try:
        with _LOCAL_HTTP.open(OLLAMA_URL + "/api/version", timeout=3) as r:
            return r.status == 200
    except OSError:
        return False


def ollama_tags() -> dict:
    """name -> manifest digest (hex, "" if odd) of every model Ollama lists in /api/tags. A name listed
    with several digests (Ollama 0.40.0 lists each local child of a manifest list) maps to the frozenset
    of them. Raises PlanError when Ollama doesn't answer or answers nonsense, so a failure never looks
    like "nothing installed"."""
    try:
        with _LOCAL_HTTP.open(OLLAMA_URL + "/api/tags", timeout=15) as r:
            data = json.load(r)
    except (OSError, ValueError) as e:
        raise PlanError(f"couldn't list Ollama's models ({e}); is it running? secstack llm start")
    models = data.get("models") if isinstance(data, dict) else None
    if not isinstance(models, list):
        raise PlanError("Ollama's model list (/api/tags) is malformed; is something else on 127.0.0.1:11434?")
    out = {}
    for m in models:
        name = m.get("name") if isinstance(m, dict) else None
        if not isinstance(name, str) or not name:
            continue
        digest = m.get("digest")
        d = digest if isinstance(digest, str) and HEX64.fullmatch(digest) else ""
        for key in (name, name[: -len(":latest")]) if name.endswith(":latest") else (name,):
            prev = out.get(key)
            if prev is None or prev == d:
                out[key] = d
            else:
                out[key] = (prev if isinstance(prev, frozenset) else frozenset((prev,))) | {d}
    return out


def ollama_tags_quiet() -> dict:
    try:
        return ollama_tags()
    except PlanError:
        return {}


def _name_parts(name: str):
    """(namespace, model, tag) of a model name on Ollama's default registry (ns/model:tag, model:tag or an
    alias), or None for anything Ollama would read as something else: another host, a path trick, a
    source suffix (:cloud, :local, -cloud), or a local blob digest: library/<hex>:latest, and in Ollama
    0.40 also sha256:<hex>, <hex> and <runner>:<hex> as the whole name (mlx:0123456789ab)."""
    runner, colon, rest = name.partition(":")
    if DIGEST_NAME_RE.fullmatch(name.strip()) or (
            colon and runner.strip().lower() in DIGEST_RUNNERS and DIGEST_NAME_RE.fullmatch(rest.strip())):
        return None
    n, tag = name, "latest"
    if ":" in n.rsplit("/", 1)[-1]:
        n, tag = n.rsplit(":", 1)
    parts = n.split("/")
    if len(parts) == 1:
        parts = ["library"] + parts
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", x) for x in parts + [tag]):
        return None
    if SOURCE_TAG_RE.fullmatch(tag):
        return None
    if parts[0].lower() == "library" and tag.lower() == "latest" and DIGEST_NAME_RE.fullmatch(parts[1]):
        return None
    return parts[0], parts[1], tag


def _canon_name(name: str) -> str:
    """ns/model:tag in lowercase, the defaults filled in (Ollama's names don't depend on case on APFS)."""
    n, tag = name, "latest"
    if ":" in n.rsplit("/", 1)[-1]:
        n, tag = n.rsplit(":", 1)
    return (n if "/" in n else "library/" + n).lower() + ":" + tag.lower()


def _manifest_file(name: str):
    """(entry, tree) of the named manifest Ollama resolves for a model name, as manifest.resolveManifestPath
    does in Ollama 0.40: manifests-v2/ollama.com/<ns>/<model>/<tag> (a link to the manifest blob) first,
    then the legacy manifests/registry.ollama.ai/... and manifests/ollama.com/... files. A dangling v2 link
    falls through to the legacy tree, as Ollama's os.Stat does. None when there is none."""
    parts = _name_parts(name)
    if parts is None:
        return None
    v2 = OLLAMA_MODELS / "manifests-v2"
    entry = v2.joinpath(OLLAMA_V2_HOST_DIR, *parts)
    if os.path.exists(entry):
        return entry, v2
    legacy = OLLAMA_MODELS / "manifests"
    for host in (OLLAMA_HOST_DIR, OLLAMA_V2_HOST_DIR):
        entry = legacy.joinpath(host, *parts)
        if os.path.lexists(entry):
            return entry, legacy
    return None


def _read_blob(hexdigest: str):
    """Bytes of <OLLAMA_MODELS>/blobs/sha256-<hex>, only if they hash to hex. None when missing or wrong."""
    try:
        raw = (OLLAMA_MODELS / "blobs" / ("sha256-" + hexdigest)).read_bytes()
    except OSError:
        return None
    return raw if hashlib.sha256(raw).hexdigest() == hexdigest else None


def _read_named_manifest(entry: Path, tree: Path):
    """(bytes, sha256 hex) of a named manifest entry, checked the way Ollama checks it before use: a link
    must resolve to <OLLAMA_MODELS>/blobs/sha256-<hex> and nowhere else, holding bytes that hash to that
    name; a plain file must stay inside its manifests tree. None otherwise."""
    try:
        if os.path.islink(entry):
            target = os.path.realpath(entry)
            blob_name = os.path.basename(target)
            hexdigest = blob_name[len("sha256-"):]
            if (not blob_name.startswith("sha256-") or not HEX64.fullmatch(hexdigest)
                    or os.path.dirname(target) != os.path.realpath(OLLAMA_MODELS / "blobs")):
                return None
            raw = _read_blob(hexdigest)
            return None if raw is None else (raw, hexdigest)
        real, root = os.path.realpath(entry), os.path.realpath(tree)
        if not real.startswith(root + os.sep) or not os.path.isfile(real):
            return None
        raw = Path(real).read_bytes()
    except OSError:
        return None
    return raw, hashlib.sha256(raw).hexdigest()


def _strict_json(raw: bytes):
    """JSON decoded the way Go's encoding/json fills Ollama's structs, or ValueError wherever the two
    could disagree: Go matches object keys to fields case-insensitively (the last one wins), so a key that
    isn't ASCII or repeats another up to case is refused, and so are NaN and Infinity (Go rejects them)."""
    def obj(pairs):
        seen = set()
        for k, _ in pairs:
            if not k.isascii() or k.lower() in seen:
                raise ValueError(f"ambiguous JSON key {_printable(k)!r}")
            seen.add(k.lower())
        return dict(pairs)

    def constant(c):
        raise ValueError(f"{c} is not JSON")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=obj, parse_constant=constant)


def _field(obj, key: str):
    """obj[key] found the way Go finds a struct field, case-insensitively (see _strict_json)."""
    if not isinstance(obj, dict):
        return None
    return next((v for k, v in obj.items() if k.lower() == key.lower()), None)


def _select_manifest(man: dict, digest: str):
    """(manifest, digest) that Ollama on Apple Silicon runs for a named manifest: the manifest itself, or,
    for a manifest list, the first child by runner preference (mlx, llamacpp, ggml) whose manifest blob
    is local, as manifest.selectManifestWithPreferences does. None for anything else, including a child
    written inline instead of by digest (Ollama names those by a digest of Go's own re-encoding)."""
    if _field(man, "mediaType") != MT_MANIFEST_LIST:
        return man, digest
    children = _field(man, "manifests")
    if not isinstance(children, list) or not all(isinstance(c, dict) for c in children):
        return None
    for runner in RUNNER_PREFERENCES:
        child = next((c for c in children if _field(c, "mediaType") in (None, "", MT_MANIFEST)
                      and isinstance(_field(c, "runner"), str) and _field(c, "runner").strip().lower() == runner),
                     None)
        if child is None:
            continue
        ref = _field(child, "digest")
        if _field(child, "config") or _field(child, "layers") or not isinstance(ref, str):
            return None
        if not (ref.startswith("sha256:") and HEX64.fullmatch(ref[7:])):
            return None
        if not (OLLAMA_MODELS / "blobs" / ("sha256-" + ref[7:])).exists():
            continue                                  # not pulled here: Ollama tries the next runner
        raw = _read_blob(ref[7:])
        try:
            sub = _strict_json(raw) if raw is not None else None
        except ValueError:
            return None
        if not isinstance(sub, dict) or _field(sub, "mediaType") == MT_MANIFEST_LIST:
            return None
        return sub, ref[7:]
    return None


def _listed_digests(tags: dict, name: str) -> set:
    """Digests /api/tags lists for a name: an exact match, else the single entry equal up to case (Ollama
    lists a model in the case it was pulled with; APFS finds it either way). Empty when there is none."""
    full = name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"
    keys = [full] if full in tags else [k for k in tags if ":" in k.rsplit("/", 1)[-1] and k.lower() == full.lower()]
    if len(keys) != 1:
        return set()
    v = tags[keys[0]]
    return {d for d in (v if isinstance(v, frozenset) else (v,)) if isinstance(d, str) and HEX64.fullmatch(d)}


def _show(name: str) -> dict:
    req = urllib.request.Request(OLLAMA_URL + "/api/show", data=json.dumps({"model": name}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with _LOCAL_HTTP.open(req, timeout=30) as r:
            data = json.load(r)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def model_capabilities(name: str):
    """Capabilities Ollama reports for an installed model (e.g. {'completion','tools','vision'}),
    or None when this Ollama doesn't report them."""
    caps = _show(name).get("capabilities")
    return {str(c) for c in caps} if isinstance(caps, list) else None


def weights_fingerprint(layers: list) -> str:
    """layers: [(mediaType, hex digest[, tensor name])] of a model's weight layers. A single unnamed model
    layer gives its own digest (for a GGUF import, the file's sha256); several (projector, adapter, draft,
    shards, tensors) give a sha256 of the sorted list, so adding, dropping or swapping any of them changes
    it. A tensor name (safetensors/MLX layers) is part of a layer: the same blobs under swapped names are
    another model. Layers without names keep the earlier "mediaType digest" lines, so old pins hold."""
    rows = sorted((x[0], x[1], x[2] if len(x) > 2 and x[2] else "") for x in layers)
    if len(rows) == 1 and rows[0][0] == MT_MODEL and not rows[0][2]:
        return rows[0][1]
    if not any(n for _, _, n in rows):
        return hashlib.sha256("\n".join(f"{mt} {d}" for mt, d, _ in rows).encode()).hexdigest()
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def installed_weights(name: str, tags: dict | None = None):
    """Weights fingerprint of an installed model, from its manifest as Ollama resolves and checks it
    (manifests-v2 link or legacy file; for a manifest list, the child Ollama on Apple Silicon runs), never
    from text Ollama prints. "remote" for a model that runs on another host: its config says so (keys
    matched as Go matches them), and Ollama gives such a model no weight layers, so the config is read
    first. None when the manifest or its config can't be read or trusted, or, given /api/tags, when it
    isn't the manifest Ollama lists under that name."""
    return _weights_and_digest(name, tags)[0]


def _weights_and_digest(name: str, tags: dict | None = None) -> tuple:
    """(installed_weights(name, tags), the manifest digest they were read from; None with None). The
    install keeps the digest that passed its checks, to confirm what it put in place and record exactly
    that."""
    found = _manifest_file(name)
    read = _read_named_manifest(*found) if found else None
    try:
        man = _strict_json(read[0]) if read else None
    except ValueError:
        return None, None
    picked = _select_manifest(man, read[1]) if isinstance(man, dict) else None
    if picked is None:
        return None, None
    man, digest = picked
    if tags is not None and digest not in _listed_digests(tags, name):
        return None, None
    config = _field(man, "config")
    if config is not None and not isinstance(config, dict):
        return None, None
    cfg = _field(config, "digest")
    if cfg:                                            # Ollama reads the config when the manifest names one
        ok = isinstance(cfg, str) and cfg[:7] == "sha256:" and HEX64.fullmatch(cfg[7:])
        raw = _read_blob(cfg[7:]) if ok else None
        try:
            conf = _strict_json(raw) if raw is not None else None
        except ValueError:
            return None, None
        if not isinstance(conf, dict):
            return None, None
        if _field(conf, "remote_host") or _field(conf, "remote_model"):
            return "remote", digest
    entries = _field(man, "layers")
    if not isinstance(entries, (list, type(None))):
        return None, None
    layers = []
    for layer in entries or []:
        mt, dg, nm = (_field(layer, k) for k in ("mediaType", "digest", "name"))
        if not isinstance(layer, dict) or not isinstance(mt, str) or not isinstance(dg, str) \
                or not isinstance(nm, (str, type(None))):
            return None, None
        if mt in META_LAYERS:
            continue
        if not MEDIA_TYPE_RE.fullmatch(mt) or not (dg[:7] == "sha256:" and HEX64.fullmatch(dg[7:])):
            return None, None
        layers.append((mt, dg[7:], nm or ""))
    return (weights_fingerprint(layers), digest) if layers else (None, None)


def run_cmd(cmd: list) -> None:
    print("  $ " + " ".join(shlex.quote(c) for c in cmd), flush=True)
    try:
        subprocess.run(cmd, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        raise PlanError(f"command failed: {cmd[0]} {cmd[1] if len(cmd) > 1 else ''}: {e}")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hf_fetch(m: dict, allow_unpinned: bool) -> Path:
    src = m["source"]
    if not src.get("revision"):
        raise PlanError(f"{m['id']}: Hugging Face downloads need a pinned commit (source.revision) in the catalog")
    if not src.get("sha256") and not allow_unpinned:
        raise PlanError(f"{m['id']}: the catalog has no sha256 for this download. Add it to models/catalog.json, "
                        "or pass --allow-unpinned (the digest is printed so you can pin it).")
    # Only the current `hf` CLI: the old huggingface-cli could leave symlinks into its cache in --local-dir.
    exe = shutil.which("hf")
    if not exe:
        raise PlanError("Hugging Face CLI (hf) not found: brew install hf   (or: uv tool install huggingface_hub)")
    if not MODELS_DIR_RE.fullmatch(str(MODELS_DIR)):
        raise PlanError(f"{_printable(MODELS_DIR)} has characters Ollama's Modelfile can't take; "
                        "set SECSTACK_MODELS_DIR to a simple absolute path")
    dest = MODELS_DIR / m["alias"]
    for p in (MODELS_DIR, dest):
        if p.is_symlink():
            raise PlanError(f"{p} is a symlink; refusing to download through it")
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    real = os.path.realpath(dest)
    run_cmd([exe, "download", src["repo"], src["file"], "--revision", src["revision"], "--local-dir", str(dest)])
    # The file must be a plain file in the folder that was checked above (not a link, and not in a folder
    # that was swapped for a link meanwhile).
    path = dest / src["file"]
    if dest.is_symlink() or path.is_symlink() or not path.is_file() or os.path.dirname(os.path.realpath(path)) != real:
        raise PlanError(f"download did not produce {path} as a plain file in {dest}")
    digest = sha256_file(path)
    if src.get("sha256"):
        if digest != src["sha256"]:
            path.unlink()
            raise PlanError(f"{m['id']}: sha256 mismatch (got {digest}); the file was deleted")
        print(f"  sha256 verified {digest[:16]}...")
    else:
        print(f"  WARNING: unpinned download, sha256 {digest}. Add it to the catalog after checking it.")
    return path


def _bad_char(ch: str) -> bool:
    """A character refused anywhere in a Modelfile: one that Ollama's parser drops (strconv.IsPrint rejects
    it) in every Unicode version, so it could join two quotes into a delimiter no reviewer sees. That is
    controls, format characters (zero-width, bidi), private use, surrogates, every space but U+0020, and
    the 66 noncharacters; tab and newline are separators. A code point this Python's Unicode tables don't
    know (Cn) is allowed, so the answer doesn't depend on which Python runs: Ollama may drop one, and
    _mf_value writes values so that a dropped non-ASCII character can't change how the file reads."""
    if ch in "\t\n":
        return False
    o = ord(ch)
    if 0xFDD0 <= o <= 0xFDEF or o & 0xFFFE == 0xFFFE:
        return True
    cat = unicodedata.category(ch)
    return cat in ("Cc", "Cf", "Co", "Cs") or (cat[0] == "Z" and ch != " ")


def _read_modelfile(path) -> str:
    """A Modelfile's text exactly as stored: UTF-8, line ends not translated (Python's universal newlines
    would turn a bare CR into a line break and hide it)."""
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return f.read()
    except (OSError, UnicodeError) as e:
        raise PlanError(f"cannot read {path}: {e}")


def _mf_unquote(s: str) -> tuple:
    """parser.unquote: strip one level of \"\"\" or " quotes; (value, False) when they don't balance."""
    if s[:3] == '"""':
        return (s[3:-3], True) if len(s) >= 6 and s[-3:] == '"""' else ("", False)
    if s[:1] == '"':
        return (s[1:-1], True) if len(s) >= 2 and s[-1:] == '"' else ("", False)
    return s, True


def _ollama_parse(text: str, need_from: bool = True) -> list:
    """Ollama's Modelfile parser (parser.ParseFile, v0.40), rune for rune: [(name, args)], where name is
    "model" for FROM, the lowercase command word otherwise, the parameter name for PARAMETER, and MESSAGE
    args are "role: content". Values are unquoted the same way after every command word, so PARAMETER and
    MESSAGE values may be quoted and span lines too. Raises PlanError wherever Ollama fails. The caller
    has already refused CR and the characters Ollama drops (see _mf_check). Linear in the text: where Ollama
    re-reads the whole value at every space and line break, this keeps the first and last non-blank
    positions of the value, so whether its quotes close is known without re-reading it."""
    NIL, NAME, VALUE, PARAM, MSG, COMMENT = range(6)

    def letter(c):
        return "a" <= c <= "z" or "A" <= c <= "Z"

    def closed():
        """_mf_unquote(value.strip())[1] for the value in buf, in constant time."""
        if first < 0:
            return True
        size = last - first + 1
        if buf[first:first + 3] == ['"', '"', '"']:
            return size >= 6 and buf[last - 2:last + 1] == ['"', '"', '"']
        if buf[first] == '"':
            return size >= 2 and buf[last] == '"'
        return True

    def value():
        return _mf_unquote("".join(buf[first:last + 1]) if first >= 0 else "")[0]
    out, buf, curr, name, role, first, last = [], [], NIL, "", "", -1, -1
    for r in text:
        if curr == NIL:                       # parseRuneForState; "" stands for Go's rune 0
            nxt, r = (COMMENT, "") if r == "#" else (NIL, "") if r in " \t\n" else (NAME, r)
        elif curr == NAME:
            if not letter(r) and r not in " \t":
                raise PlanError("unknown Modelfile command (a command word is letters only)")
            nxt, r = (NAME, r) if letter(r) else (VALUE, "")
        elif curr == VALUE:
            nxt = NIL if r in " \t\n" else VALUE
        elif curr in (PARAM, MSG):
            if letter(r) or (curr == PARAM and ("0" <= r <= "9" or r == "_")):
                nxt = curr
            elif r in " \t":
                nxt, r = VALUE, ""
            else:
                raise PlanError("malformed PARAMETER or MESSAGE line in the Modelfile")
        else:
            nxt, r = (NIL, "") if r == "\n" else (COMMENT, "")
        if nxt != curr:
            if curr == NAME:
                word = "".join(buf)
                low = word.lower()
                if low not in MF_COMMANDS:
                    raise PlanError(f"unknown Modelfile command {_printable(word, 20)!r}")
                if low == "parameter":
                    nxt = PARAM
                elif low == "message":
                    nxt, name = MSG, low
                else:
                    name = "model" if low == "from" else low
            elif curr == PARAM:
                name = "".join(buf)
            elif curr == MSG:
                role = "".join(buf)
                if role not in MF_ROLES:
                    raise PlanError(f"MESSAGE role must be one of {', '.join(MF_ROLES)}")
            elif curr == VALUE:
                if r in " \t" or not closed():     # a space never ends a value; a line break only a closed one
                    buf.append(r)
                    continue
                s = value()
                if role:
                    s, role = f"{role}: {s}", ""
                out.append((name, s))
            buf, curr, first, last = [], nxt, -1, -1
        if r and r not in "\t\n":             # Go appends what strconv.IsPrint accepts (see _bad_char)
            if r != " ":
                first, last = (len(buf) if first < 0 else first), len(buf)
            buf.append(r)
    if curr == VALUE:
        if not closed():
            raise PlanError("unterminated quoted value in the Modelfile")
        s = value()
        out.append((name, f"{role}: {s}" if role else s))
    elif curr not in (NIL, COMMENT):
        raise PlanError("the Modelfile ends in the middle of a command")
    if need_from and not any(n == "model" for n, _ in out):
        raise PlanError("the Modelfile has no FROM")
    return out


def _mf_check(text: str, source: str) -> str:
    """CRLF line ends become LF; a bare CR (a line break to Ollama, not to an editor or git diff) and
    any character Ollama drops (see _bad_char) are refused, anywhere, quoted values and comments included."""
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise PlanError(f"{source}: bare carriage return (Ollama reads it as a line break)")
    bad = next((ch for ch in text if _bad_char(ch)), None)
    if bad is not None:
        raise PlanError(f"{source}: invisible or control character U+{ord(bad):04X} (Ollama drops it, "
                        "which can change how the file reads)")
    return text


def _mf_value(s: str, block: bool = False) -> str:
    """s written so that Ollama reads exactly s back: bare when it is plain ASCII on one line, else in a
    \"\"\" block. A value with \"\"\" in it can't be written safely; the check ignores non-ASCII characters
    in case Ollama's Unicode tables drop one that Python's keep."""
    if '"""' in re.sub(r"[^\x00-\x7f]", "", s):
        raise PlanError('a Modelfile value containing """ can\'t be written back safely')
    if not block and s and s.isascii() and "\n" not in s and s == s.strip(" \t") and not s.startswith('"'):
        return s
    return '"""' + s + '"""'


def _mf_render(commands: list, need_from: bool) -> str:
    """Modelfile text for parsed commands (the format of Command.String), read back with _ollama_parse to
    confirm Ollama will see exactly these commands and nothing else."""
    lines = []
    for name, args in commands:
        if name == "model":
            lines.append("FROM " + _mf_value(args))
        elif name in ("template", "system", "license"):
            lines.append(f"{name.upper()} " + _mf_value(args, block=True))
        elif name in ("renderer", "parser"):
            lines.append(f"{name.upper()} " + _mf_value(args))
        elif name == "message":
            role, _, content = args.partition(": ")
            lines.append(f"MESSAGE {role} " + _mf_value(content, block=True))
        else:
            lines.append(f"PARAMETER {name} " + _mf_value(args))
    text = "".join(line + "\n" for line in lines)
    if _ollama_parse(_mf_check(text, "rebuilt Modelfile"), need_from) != [tuple(c) for c in commands]:
        raise PlanError("the rebuilt Modelfile doesn't read back as the same commands; refusing it")
    return text


def _mf_commands(text: str, source: str, allow_from: bool) -> list:
    """The commands of a Modelfile that describe how to talk to the model: TEMPLATE, SYSTEM, LICENSE,
    RENDERER, PARSER, MESSAGE and parameters other than num_ctx/num_predict (the plan sets those). FROM
    is dropped from `ollama show --modelfile` output (allow_from; there it names local blobs) and refused
    in an exported file, as is everything that changes the model itself (ADAPTER, DRAFT, REQUIRES,
    CAPABILITY), whether written as a command or as a PARAMETER of that name. CAPABILITY is also dropped
    from show output: the rebuilt alias inherits it from the catalog source."""
    kept = []
    for name, args in _ollama_parse(_mf_check(text, source), need_from=False):
        if allow_from and name in ("model", "capability"):
            continue
        if name in MF_REFUSED:
            word = "FROM" if name == "model" else name.upper()
            raise PlanError(f"{source}: {word} isn't allowed in an exported Modelfile (only {', '.join(MF_ALLOWED)})")
        if name not in MF_KEPT and name.lower() in MF_DROPPED_PARAMS:
            continue
        kept.append((name, args))
    return kept


def filter_modelfile(text: str, source: str, allow_from: bool) -> str:
    """The allowed commands of a Modelfile (see _mf_commands), rebuilt from what Ollama's parser reads
    rather than copied, so nothing hides between what this function checks and what Ollama sees."""
    return _mf_render(_mf_commands(text, source, allow_from), need_from=False)


def modelfile_text(m: dict, from_ref: str, ctx: int, max_tokens: int) -> str:
    """FROM + the allowed commands of an exported Modelfile (models/exported/, if any) + context caps,
    rebuilt and read back the way Ollama will read it."""
    commands = [("model", from_ref)]
    exported = EXPORTED_DIR / f"{m['alias']}.Modelfile"
    if exported.is_file():
        commands += _mf_commands(_read_modelfile(exported), str(exported), allow_from=False)
    commands += [("num_ctx", str(int(ctx))), ("num_predict", str(int(max_tokens)))]
    return _mf_render(commands, need_from=True)


def _check_against_catalog(selected: list) -> None:
    """The selection file lives in $SECOPS; the catalog in the repo is the source of truth. Refuse
    anything that drifted (e.g. a pin rotated in the catalog after the plan was written)."""
    catalog = {m["id"]: m for m in load_catalog()}
    for m in selected:
        cat = catalog.get(m.get("id"))
        if cat is None or cat["alias"] != m.get("alias") or cat["source"] != m.get("source"):
            raise PlanError(f"{_printable(m.get('id', '?'))}: the saved selection no longer matches models/catalog.json. "
                            "Re-run ./setup.sh --only plan.")


def _short(d) -> str:
    return d[:12] if isinstance(d, str) and HEX64.fullmatch(d) else str(d if d else "unreadable")[:12]


def _tmp_alias(alias: str) -> str:
    return TMP_ALIAS_PREFIX + hashlib.sha256(alias.encode()).hexdigest()[:12]


def _selection_bounds(sel: dict) -> tuple:
    plan = sel.get("plan") if isinstance(sel.get("plan"), dict) else {}
    ctx, max_tokens = plan.get("ctx"), plan.get("max_tokens")
    if not (isinstance(ctx, int) and not isinstance(ctx, bool) and CTX_RANGE[0] <= ctx <= CTX_RANGE[1]):
        raise PlanError(f"{SELECTED}: context {ctx!r} is outside {CTX_RANGE}; re-run ./setup.sh --only plan")
    if not (isinstance(max_tokens, int) and not isinstance(max_tokens, bool) and 1 <= max_tokens <= ctx):
        raise PlanError(f"{SELECTED}: max output {max_tokens!r} is invalid; re-run ./setup.sh --only plan")
    return ctx, max_tokens


def _weights_problem(got, want) -> str:
    """Why a model whose weights read back as got (installed_weights) can't be used, given the catalog
    pin want; "" when it can."""
    if got == "remote":
        return "it runs on a remote host"
    if got is None:
        return "its manifest can't be read as Ollama serves it"
    if want and got != want:
        return f"its weights {_short(got)} are not the catalog's pinned {want[:12]}"
    return ""


def cmd_install_models(args) -> int:
    try:
        sel = json.loads(SELECTED.read_text())
    except (OSError, ValueError):
        raise PlanError(f"no model selection at {SELECTED}: run ./setup.sh --only plan first")
    if not isinstance(sel, dict):
        raise PlanError(f"{SELECTED} is not a selection file: run ./setup.sh --only plan")
    errs = validate_catalog(sel.get("models"))
    if errs:
        raise PlanError("selection file invalid:\n  " + "\n  ".join(errs))
    _check_against_catalog(sel["models"])
    catalog = {m["id"]: m for m in load_catalog()}
    ctx, max_tokens = _selection_bounds(sel)
    primary = sel.get("primary")
    ollama = ollama_bin()
    if not ollama_up():
        raise PlanError("Ollama is not running: secstack llm start")
    tags = ollama_tags()
    problems, no_tools, failed = [], [], set()
    verified = {}                     # alias -> the manifest digest that passed its checks in this run
    # The digests recorded by the last good install. An unpinned model is trusted on first use, so a later
    # change to it (weights, template or system prompt) must fail here, not quietly become the new record.
    previous = sel.get("installed") if isinstance(sel.get("installed"), dict) else {}

    def refuse(alias: str, why: str) -> None:
        problems.append(why)
        failed.add(alias)

    for m in sel["models"]:
        alias, src = m["alias"], m["source"]
        want = weights_digest(catalog.get(m["id"], m))
        print(f"\n== {alias}")
        # The embedding model's backup from an earlier run may be the only good copy left: never reuse it.
        backup = _tmp_alias(alias) if m["role"] == "embed" and _tmp_alias(alias) in tags else None
        if alias in tags and not args.force:
            # Installed earlier: check it, never replace it here.
            got, digest = _weights_and_digest(alias, tags)
            why = _weights_problem(got, want)
            if why:
                refuse(alias, f"{alias}: installed, but {why}. " + (
                    f"An earlier run kept the previous one as {backup}: put it back (ollama cp {backup} {alias}) "
                    f"or remove it (ollama rm {backup}), then re-run" if backup else
                    "Re-create it from the catalog source: scripts/plan.py install-models --force"))
                continue
            rec = previous.get(alias) if isinstance(previous.get(alias), dict) else {}
            old = rec.get("digest") if isinstance(rec.get("digest"), str) and HEX64.fullmatch(rec["digest"]) else None
            if old and old != digest:      # changed since the last recorded install (audit reports it too)
                refuse(alias, f"{alias}: installed, but its manifest changed since the last recorded install "
                              f"({old[:12]} -> {_short(digest)}): something re-created or edited it (weights, "
                              f"template or system prompt). Check it (ollama show --modelfile {alias}), then "
                              "re-create it from the catalog source: scripts/plan.py install-models --force")
                continue
            verified[alias] = digest
            print("  already installed" + (" (weights verified)" if want else ""))
            if m["role"] == "embed":
                continue
            caps = model_capabilities(alias)
            if m.get("tools") and caps is not None and "tools" not in caps:
                no_tools.append(alias)
                print(f"  ! Ollama does not list tool calling for {alias} ({', '.join(sorted(caps))})")
            continue

        if m["role"] == "embed":
            # Its alias is its library tag, so `ollama pull` replaces it in place: keep the installed copy
            # under the temporary name and put it back if the new pull fails its checks.
            tmp, had, keep = _tmp_alias(alias), alias in tags, False
            if backup:
                refuse(alias, f"{alias}: an earlier run kept a copy of it as {tmp}; put it back (ollama cp {tmp} "
                              f"{alias}) or remove it (ollama rm {tmp}), then re-run. It is not overwritten.")
                continue
            try:
                if had:
                    run_cmd([ollama, "cp", alias, tmp])
                run_cmd([ollama, "pull", src["ref"]])
                keep = had                            # the copy stays until the pull checks out or it is back
                got, digest = _weights_and_digest(alias, ollama_tags())
                why = _weights_problem(got, want)
                if why:
                    if had:
                        run_cmd([ollama, "cp", tmp, alias])
                        keep = False
                        refuse(alias, f"{alias}: refused the pulled model: {why}; the previous one was put back")
                    else:
                        _run([ollama, "rm", alias], timeout=60)
                        gone = alias not in ollama_tags_quiet()
                        refuse(alias, f"{alias}: refused the pulled model: {why}; " +
                               ("it was removed" if gone else f"remove it: ollama rm {alias}"))
                    continue
                keep = False
                verified[alias] = digest
                print(f"  installed {alias}" + (f" (weights verified {want[:12]})" if want else ""))
            finally:
                if keep:
                    print(f"  ! the previous {alias} is kept as {tmp}: ollama cp {tmp} {alias}")
                elif had and _run([ollama, "rm", tmp], timeout=60) == "" and tmp in ollama_tags_quiet():
                    print(f"  ! couldn't remove the temporary copy {tmp}: ollama rm {tmp}")
            continue

        gguf = None
        if src["type"] == "ollama":
            run_cmd([ollama, "pull", src["ref"]])
            if want:
                got = installed_weights(src["ref"], ollama_tags())
                if got != want:
                    refuse(alias, f"{alias}: {src['ref']} now serves weights {_short(got)}, not the pinned "
                                  f"{want[:12]}; {alias} left as it was")
                    continue
            ref = src["ref"]
        else:
            gguf = hf_fetch(m, args.allow_unpinned)
            ref = str(gguf)

        # Build under a temporary name, check it, and only then put it in place, so a model that fails
        # its checks never replaces a working alias.
        tmp = _tmp_alias(alias)
        try:
            with tempfile.TemporaryDirectory(prefix="secstack-mf-") as d:
                mf = Path(d) / "Modelfile"
                mf.write_text(modelfile_text(m, ref, ctx, max_tokens), encoding="utf-8")
                run_cmd([ollama, "create", tmp, "-f", str(mf)])
            got, digest = _weights_and_digest(tmp, ollama_tags())
            why = _weights_problem(got, want)
            if why:
                refuse(alias, f"{alias}: refused the new build: {why}; {alias} left as it was")
                continue
            if not want:
                print(f"  (no weights pin in the catalog; fingerprint {_short(got)})")
            caps = model_capabilities(tmp)
            if m.get("tools") and caps is not None and "tools" not in caps:
                if alias == primary:
                    refuse(alias, f"the primary model {alias} has no tool calling in this Ollama, so agents can't "
                                  "use it. Update Ollama, or capture its Modelfile on a Mac where it works "
                                  "(scripts/export-modelfiles.sh) and re-run with --force, or pick another "
                                  "primary (./setup.sh --only plan).")
                    continue
                no_tools.append(alias)
                print(f"  ! Ollama does not list tool calling for {alias} ({', '.join(sorted(caps))})")
            elif caps is None and m.get("tools"):
                print("  ? this Ollama doesn't report capabilities; run secstack bench to check tool calling")
            run_cmd([ollama, "cp", tmp, alias])
            # Read the alias back: it must hold the very manifest that passed (anything that reaches
            # Ollama's API could swap the build between the check and the copy).
            placed, placed_digest = _weights_and_digest(alias, ollama_tags())
            if (placed, placed_digest) != (got, digest):
                _run([ollama, "rm", alias], timeout=60)
                gone = alias not in ollama_tags_quiet()
                refuse(alias, f"{alias}: what was copied into place ({_short(placed)}) isn't the build that passed "
                              f"its checks; " + ("it was removed" if gone else f"remove it: ollama rm {alias}") +
                              ". Re-run scripts/plan.py install-models --force")
                continue
            verified[alias] = placed_digest
            print(f"  installed {alias}" + (f" (weights verified {want[:12]})" if want else ""))
        finally:
            if _run([ollama, "rm", tmp], timeout=60) == "" and tmp in ollama_tags_quiet():
                print(f"  ! couldn't remove the temporary model {tmp}: ollama rm {tmp}")
        if gguf is not None and not args.keep_gguf:
            gguf.unlink()
            print("  removed the downloaded GGUF (Ollama keeps its own copy)")

    # Provenance: Ollama tags are mutable and can't be pulled by digest, so record the digest each alias
    # passed its checks with, and warn when it differs from the last install. An alias Ollama now lists
    # with another digest changed after its check (something else reached Ollama's API meanwhile): it is
    # not recorded and the run fails, so `secstack audit` keeps reporting it.
    try:
        tags = ollama_tags()
    except PlanError as e:
        tags = None
        problems.append(f"nothing recorded: {e}")
    record = {}
    for m in sel["models"]:
        alias, d = m["alias"], verified.get(m["alias"])
        if tags is not None and alias not in failed and d not in _listed_digests(tags, alias):
            failed.add(alias)
            now = ", ".join(sorted(x[:12] for x in _listed_digests(tags, alias))) or "nothing"
            problems.append(f"{alias}: changed after its check in this run (Ollama lists {now}, the check passed "
                            f"{_short(d)}); not recorded. Re-run scripts/plan.py install-models --force")
        if tags is None or alias in failed:
            # A failed check keeps the record of the last good install, so `secstack audit` keeps
            # reporting the change instead of taking what failed as the new normal.
            if isinstance(previous.get(alias), dict):
                record[alias] = previous[alias]
            continue
        old = previous.get(alias, {}).get("digest") if isinstance(previous.get(alias), dict) else None
        if isinstance(old, str) and HEX64.fullmatch(old) and old != d:
            print(f"  ! {alias}: manifest digest changed since the last install ({old[:12]} -> {d[:12]})")
        record[alias] = {"digest": d, "recorded": dt.datetime.now().isoformat(timespec="seconds")}
    if record:
        sel["installed"] = record
        write_private(SELECTED, json.dumps(sel, indent=1) + "\n")
        print(f"  recorded manifest digests for {len(record)} models in {SELECTED}")
    print()
    print(_run([ollama, "list"], timeout=60))
    if problems:
        raise PlanError("model install problems:\n  " + "\n  ".join(problems))
    if primary in no_tools:
        raise PlanError(f"the primary model {primary} has no tool calling in this Ollama, so agents can't use it. "
                        "Update Ollama, or capture its Modelfile on a Mac where it works "
                        "(scripts/export-modelfiles.sh) and re-run with --force, or pick another primary "
                        "(./setup.sh --only plan).")
    if no_tools:
        print("  note: models above lack tool calling here; use them for chat/vision only, or fix as described in models/README.md")
    return 0


def cmd_pin_weights(args) -> int:
    """Pin the weights fingerprint of each installed catalog model (run on a Mac where they work).
    A model is pinned only when its alias holds exactly the weights its catalog source serves."""
    if not ollama_up():
        raise PlanError("Ollama is not running: secstack llm start")
    tags = ollama_tags()
    data = json.loads(CATALOG_PATH.read_text())
    changed = 0
    for m in data["models"]:          # the embedding model too: its alias is its source
        alias, src = m["alias"], m["source"]
        got = installed_weights(alias, tags)
        if got is None:
            print(f"  ?    {alias}: not installed here, or its manifest can't be read")
            continue
        if got == "remote":
            print(f"  !    {alias}: runs on a remote host; not pinned")
            continue
        if src["type"] == "hf":
            ok = got == src.get("sha256")
            print(f"  {'ok  ' if ok else '!   '} {alias}: " + ("matches the pinned GGUF" if ok else
                  f"weights {got[:12]} differ from the pinned GGUF sha256; re-create it: install-models --force"))
            continue
        ref_w = installed_weights(src["ref"], tags)
        if ref_w is None:
            print(f"  ?    {alias}: pull {src['ref']} first so the alias can be compared with its source")
            continue
        if ref_w != got:
            print(f"  !    {alias}: the alias's weights differ from {src['ref']}; re-create it (install-models --force) before pinning")
            continue
        want = m.get("weights_sha256")
        if want and want != got:
            print(f"  !    {alias}: installed {got[:12]} differs from the pin {want[:12]} (not changed)")
        elif not want:
            print(f"  pin  {alias}: {got}")
            m["weights_sha256"] = got
            changed += 1
        else:
            print(f"  ok   {alias}")
    errs = validate_catalog(data["models"])
    if errs:
        raise PlanError("refusing to write an invalid catalog:\n  " + "\n  ".join(errs))
    if changed and args.write:
        fd, tmp = tempfile.mkstemp(dir=str(CATALOG_PATH.parent), prefix=".catalog-")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(data, indent=1) + "\n")
            os.chmod(tmp, 0o644)
            os.replace(tmp, CATALOG_PATH)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        print(f"Pinned {changed} models in {CATALOG_PATH}. Review with git diff, then commit.")
    elif changed:
        print("(not written: add --write)")
    return 0


def cmd_modelfile_filter(args) -> int:
    """`ollama show --modelfile` output -> the allowed commands only (scripts/export-modelfiles.sh),
    rebuilt from what Ollama's parser reads (see filter_modelfile)."""
    body = filter_modelfile(_read_modelfile(args.raw), args.raw, allow_from=True)
    out = Path(args.out)
    if out.is_symlink():
        raise PlanError(f"{out} is a symlink; refusing to write through it")
    fd, tmp = tempfile.mkstemp(dir=str(out.parent), prefix=".mf-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(tmp, 0o644)
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return 0


# --------------------------------------------------------------------------- commands
def _hardware(args) -> Hardware:
    ram, cpus, disk = (getattr(args, k, None) for k in ("ram_gb", "cpus", "disk_gb"))
    if ram is None:
        if cpus is not None or disk is not None:
            raise PlanError("--cpus/--disk-gb need --ram-gb")
        return detect()
    # A simulation takes the core count from this Mac, and the free disk too unless --disk-gb sets it.
    return simulate(ram, cpus, disk, detect(volumes=disk is None))


def _no_fit_hint(catalog: list, plan: Plan) -> str:
    chat = [m for m in chat_models(catalog) if m["tools"]]
    if not chat:
        return "The catalog has no chat model with tool calling."
    fitting = [m for m in chat if resident_gb(m, plan.ctx, plan.parallel) <= plan.fence_gb]
    if not fitting:
        smallest = min(resident_gb(m, plan.ctx, plan.parallel) for m in chat)
        return f"No catalog model fits in memory: the smallest needs ~{smallest} GB loaded; the fence is {plan.fence_gb} GB."
    m = min(fitting, key=lambda x: (_new_download_gb([x], plan) + _staging_gb([x], plan), x["size_gb"]))
    errs = disk_errors([m], plan)
    if not errs:
        return "No catalog model fits this Mac."
    errs = [e for e in errs if not e.startswith("selection needs")] or errs   # the free-disk reason says more
    return f"No catalog model fits on disk. The one that needs the least, {m['id']}: {'; '.join(errs)}. Free up disk space."


def cmd_detect(args) -> int:
    hw = detect()
    print(json.dumps(asdict(hw), indent=1) if args.json else hw.summary())
    return 0


def cmd_recommend(args) -> int:
    hw = _hardware(args)
    catalog = load_catalog()
    state = LocalState() if hw.simulated else local_state(catalog)
    plan = compute_plan(hw, state=state)
    rec = recommend(plan, catalog)
    final = finalize_context(plan, rec) if rec else None
    print_plan(hw, plan, state, final)
    roles = assign_roles(rec) if rec else None
    print_table(catalog, plan, [m["id"] for m in rec], roles["chat"]["id"] if roles else None)
    if not rec:
        print(f"\n  {_no_fit_hint(catalog, plan)}")
        return 1
    return 0


def cmd_select(args) -> int:
    hw = _hardware(args)
    if args.write and hw.simulated:
        raise PlanError("--write uses the real hardware; drop --ram-gb/--cpus/--disk-gb")
    catalog = load_catalog()
    state = LocalState() if hw.simulated else local_state(catalog)
    plan = compute_plan(hw, state=state)
    print_plan(hw, plan, state)
    primary = args.primary
    if args.models:
        models = [find_model(catalog, k.strip()) for k in args.models.split(",") if k.strip()]
        if any(m["role"] == "embed" for m in models):
            print(f"  note: {embed_model(catalog)['alias']} is always installed; no need to list it")
            models = [m for m in models if m["role"] != "embed"]
    elif args.yes:
        ids = [m["id"] for m in recommend(plan, catalog)]
        if primary:   # the recommendation, with this model in place of the pick in its role
            ids, primary = with_primary(catalog, ids, primary, plan)
        if not ids:
            raise PlanError(_no_fit_hint(catalog, plan))
        models = [find_model(catalog, i) for i in ids]
    else:
        if not sys.stdin.isatty():
            raise PlanError("not a terminal: pass --yes (recommended models) or --models ID,ID")
        conf = read_conf()
        pre = []
        for a in conf.get("MODELS", "").split(","):
            if not a:
                continue
            try:
                m = find_model(catalog, a)
            except PlanError:
                continue
            if fits(m, plan) and m["id"] not in pre:
                pre.append(m["id"])
        seed_id = None
        if primary:   # asked for explicitly: must exist, fit and call tools
            m = find_model(catalog, primary)
            if m["role"] == "embed" or not m["tools"]:
                raise PlanError(f"--primary {m['id']}: it doesn't support tool calling")
            if not fits(m, plan):
                raise PlanError(f"--primary {m['id']}: it doesn't fit this Mac's model fence")
            pre, seed_id = with_primary(catalog, pre or [x["id"] for x in recommend(plan, catalog)], m["id"], plan)
        elif conf.get("CHAT_MODEL"):   # the current plan's primary, when it is still usable
            try:
                m = find_model(catalog, conf["CHAT_MODEL"])
                if m["role"] != "embed" and m["tools"] and fits(m, plan):
                    seed_id = m["id"]
            except PlanError:
                seed_id = None
        models, primary = interactive_select(catalog, plan, pre, seed_id)
    errs = validate_selection(models, plan)
    if errs:
        raise PlanError("selection rejected:\n  " + "\n  ".join(errs))
    roles = assign_roles(models, primary)
    plan = finalize_context(plan, models)
    embed = embed_model(catalog)
    print(f"\nSelected: {', '.join(m['alias'] for m in roles['all'])} + {embed['alias']}")
    print(f"Primary:  {roles['chat']['alias']} (pentagi provider {roles['chat']['provider']})")
    print(f"Context:  {plan.ctx // 1024}K x {plan.parallel} parallel")
    if not args.write:
        print("(not saved: add --write)")
        return 0
    for p in write_outputs(hw, plan, roles, embed):
        print(f"  wrote {p}")
    return 0


def cmd_install(args) -> int:
    return cmd_install_models(args)


def cmd_docker_check(args) -> int:
    conf = read_conf()
    want_gb, want_cpus = conf.get("DOCKER_VM_GB", ""), conf.get("DOCKER_VM_CPUS", "")
    if not (_digits(want_gb) and _digits(want_cpus)) or int(want_gb) < 1 or int(want_cpus) < 1:
        raise PlanError(f"no valid Docker plan in {STACK_CONF}: run ./setup.sh --only plan")
    want_gb, want_cpus = int(want_gb), int(want_cpus)
    docker = shutil.which("docker") or DOCKER_FALLBACK
    out = _run([docker, "info", "--format", "{{.NCPU}} {{.MemTotal}}"], timeout=30).split()
    if len(out) != 2 or not all(_digits(x) for x in out):
        print("Docker is not running.")
        return 2
    ncpu, mem_gb = int(out[0]), int(out[1]) / GIB
    ok_cpu = ncpu == want_cpus
    # Docker Desktop reports a little less than its setting, never more: a larger VM would eat into
    # the model's memory, so only the small shortfall is tolerated.
    ok_mem = want_gb - max(1.0, 0.06 * want_gb) <= mem_gb <= want_gb + 0.25
    print(f"Docker VM: {ncpu} CPUs, {mem_gb:.1f} GiB  (plan: {want_cpus} CPUs, {want_gb} GB)"
          f"  {'OK' if ok_cpu and ok_mem else 'MISMATCH'}")
    return 0 if ok_cpu and ok_mem else 1


def cmd_show(args) -> int:
    if not STACK_CONF.is_file():
        print(f"No stack config yet ({STACK_CONF}). Run ./setup.sh --only plan.")
        return 1
    print(STACK_CONF.read_text(errors="replace"), end="")
    return 0


def _positive(s: str) -> int:
    if not _digits(s) or int(s) < 1:
        raise argparse.ArgumentTypeError("must be a positive whole number")
    return int(s)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")
    s = sub.add_parser("detect")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_detect)
    for name, fn in (("recommend", cmd_recommend), ("select", cmd_select)):
        s = sub.add_parser(name)
        s.add_argument("--ram-gb", type=_positive, help="simulate a Mac with this much memory")
        s.add_argument("--cpus", type=_positive, help="simulated CPU cores (with --ram-gb)")
        s.add_argument("--disk-gb", type=_positive, help="simulated free disk (with --ram-gb)")
        s.set_defaults(fn=fn)
        if name == "select":
            g = s.add_mutually_exclusive_group()
            g.add_argument("--yes", action="store_true", help="accept the recommended models")
            g.add_argument("--models", help="comma-separated catalog ids or aliases")
            s.add_argument("--primary", help="catalog id/alias of the default (tool-calling) model")
            s.add_argument("--write", action="store_true", help="save the stack config and generated files")
    s = sub.add_parser("install-models")
    s.add_argument("--keep-gguf", action="store_true", help="keep downloaded GGUF files after import")
    s.add_argument("--force", action="store_true", help="re-create aliases that already exist")
    s.add_argument("--allow-unpinned", action="store_true",
                   help="allow a Hugging Face download whose sha256 isn't in the catalog (a commit is still required)")
    s.set_defaults(fn=cmd_install)
    s = sub.add_parser("pin-weights")
    s.add_argument("--write", action="store_true", help="write the pins into models/catalog.json")
    s.set_defaults(fn=cmd_pin_weights)
    s = sub.add_parser("modelfile-filter")
    s.add_argument("raw")
    s.add_argument("out")
    s.set_defaults(fn=cmd_modelfile_filter)
    sub.add_parser("docker-check").set_defaults(fn=cmd_docker_check)
    sub.add_parser("show").set_defaults(fn=cmd_show)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except PlanError as e:
        print(f"plan: {e}", file=sys.stderr)
        return 2
    except OSError as e:   # a full disk, a folder that can't be written: a clear message, not a traceback
        print(f"plan: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nplan: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
