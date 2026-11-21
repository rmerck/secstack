"""Unit tests for scripts/plan.py and scripts/render-env.py.

Run from the repo root:  python3 -m unittest discover -s tests -v
Standard library only; no network, no Ollama, no Docker. Writes only to a temp directory that is
removed at exit (the repo itself is never written).
"""
import argparse
import atexit
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True   # don't leave __pycache__ in scripts/, bin/, mcp/
_TMP = Path(tempfile.mkdtemp(prefix="secstack-test-")).resolve()   # macOS: /var -> /private/var
atexit.register(shutil.rmtree, _TMP, True)
# plan.py reads these at import time, so they must be set first.
os.environ["SECOPS"] = str(_TMP / "sec-ops")
os.environ["SECSTACK_GH"] = str(_TMP / "GitHub")
os.environ["SECSTACK_MODELS_DIR"] = str(_TMP / "models")
os.environ["OLLAMA_MODELS"] = str(_TMP / "ollama-models")
os.environ.pop("SECSTACK_MODEL_BUDGET_GB", None)

_spec = importlib.util.spec_from_file_location("plan", REPO / "scripts" / "plan.py")
plan = importlib.util.module_from_spec(_spec)
sys.modules["plan"] = plan
_spec.loader.exec_module(plan)

RENDER = REPO / "scripts" / "render-env.py"
TIERS = (16, 18, 24, 32, 36, 48, 64, 96, 128, 192)


def quiet():
    return contextlib.redirect_stdout(io.StringIO())


def mac(ram, cpus=12, disk=600, wired=0):
    hw = plan.simulate(ram, cpus, disk)
    hw.wired_limit_mb = wired
    return hw


def m(id_, role, size, kv=1.0, family="fam", tools=True, vision=False, rank=50, source=None, **extra):
    d = {"id": id_, "alias": f"{id_}-abliterated", "name": id_, "family": family, "role": role,
         "tools": tools, "vision": vision, "abliterated": True,
         "source": source or {"type": "ollama", "ref": f"pub/{id_}:latest"},
         "size_gb": size, "kv_gb_32k": kv, "rank": rank,
         "provider": "" if role == "embed" else f"local-{id_}", "notes": ""}
    d.update(extra)
    return d


def embed():
    e = m("embed", "embed", 0.3, 0.0, "nomic", tools=False, rank=0, source={"type": "ollama", "ref": "nomic-embed-text"})
    e["alias"] = "nomic-embed-text"
    return e


def synthetic():
    return [
        m("w-big", "workhorse", 19, 0.3, "qwen", rank=90),
        m("w-mid", "workhorse", 13, 0.4, "gpt", rank=70),
        m("w-small", "workhorse", 5, 1.2, "qwen", rank=50),
        m("w-tiny", "workhorse", 2.5, 1.2, "qwen", rank=30),
        m("d-big", "deep", 17, 2.0, "qwen", rank=90),
        m("d-mid", "deep", 9, 2.6, "qwen", rank=60),
        m("a-big", "alt", 17, 0.5, "gemma", vision=True, rank=90),
        m("a-mid", "alt", 8, 0.4, "gemma", vision=True, rank=60),
        m("a-qwen", "alt", 6, 0.4, "qwen", vision=True, rank=99),
        embed(),
    ]


def reset_secops():
    shutil.rmtree(_TMP / "sec-ops", ignore_errors=True)


# --------------------------------------------------------------------------- resource plan
class TestComputePlan(unittest.TestCase):
    def test_48gb_reference_profile(self):
        p = plan.compute_plan(mac(48, cpus=18))
        self.assertEqual((p.docker_vm_gb, p.os_reserve_gb, p.fence_gb), (16, 8, 24))
        self.assertEqual((p.ctx, p.parallel, p.kv_type, p.max_tokens), (32768, 2, "q8_0", 16384))
        self.assertEqual((p.docker_cpus, p.hexstrike_cpus, p.hexstrike_mem_gb), (8, 4, 4))
        self.assertEqual(p.model_budget_gb, 75)

    def test_every_tier_is_consistent(self):
        for ram in TIERS:
            p = plan.compute_plan(mac(ram))
            with self.subTest(ram=ram):
                self.assertGreater(p.fence_gb, 0)
                self.assertLessEqual(p.fence_gb + p.docker_vm_gb + p.os_reserve_gb, ram)
                self.assertLessEqual(p.fence_gb, plan.metal_limit_gb(ram))
                self.assertTrue(6 <= p.docker_vm_gb <= 20)
                self.assertTrue(5 <= p.os_reserve_gb <= 12)
                self.assertLessEqual(p.max_tokens, p.ctx // 2)
                self.assertIn(p.parallel, (1, 2, 4))

    def test_context_tiers(self):
        # fence >= 48 -> 32K x4, >= 20 -> 32K x2, >= 10 -> 32K x1, else 16K x1
        p96 = plan.compute_plan(mac(96))
        self.assertEqual((p96.ctx, p96.parallel), (32768, 4))
        self.assertEqual(plan.compute_plan(mac(48)).parallel, 2)
        p24 = plan.compute_plan(mac(24))
        self.assertEqual((p24.ctx, p24.parallel), (32768, 1))
        p16 = plan.compute_plan(mac(16, cpus=8))
        self.assertEqual((p16.ctx, p16.parallel, p16.max_tokens), (16384, 1, 8192))
        self.assertIn(plan.CTX_WARNING, p16.warnings)

    def test_small_machine(self):
        p = plan.compute_plan(mac(16, cpus=8))
        self.assertEqual(p.docker_cpus, 4)
        self.assertEqual(p.hexstrike_mem_gb, 2)
        self.assertTrue(any("16-18 GB" in w for w in p.warnings))

    def test_rejects_unsupported(self):
        with self.assertRaises(plan.PlanError):
            plan.compute_plan(mac(8))
        intel = mac(32)
        intel.arm64 = False
        with self.assertRaises(plan.PlanError):
            plan.compute_plan(intel)
        linux = mac(32)
        linux.os = "Linux"
        with self.assertRaises(plan.PlanError):
            plan.compute_plan(linux)

    def test_rounding_is_half_up(self):
        self.assertEqual(plan._round(16.5), 17)
        self.assertEqual(plan._round(15.84), 16)   # 48 GB x 0.33

    def test_budget_scales_on_big_macs(self):
        self.assertEqual(plan.compute_plan(mac(64, disk=2000)).model_budget_gb, 75)
        self.assertEqual(plan.compute_plan(mac(128, disk=2000)).model_budget_gb, 153)
        with mock.patch.dict(os.environ, {"SECSTACK_MODEL_BUDGET_GB": "40"}):
            self.assertEqual(plan.compute_plan(mac(48, disk=2000)).model_budget_gb, 40)
        with mock.patch.dict(os.environ, {"SECSTACK_MODEL_BUDGET_GB": "4"}):   # out of range: ignored
            self.assertEqual(plan.compute_plan(mac(48, disk=2000)).model_budget_gb, 75)
        with mock.patch.dict(os.environ, {"SECSTACK_MODEL_BUDGET_GB": "\uff14\uff10"}):  # fullwidth digits: ignored
            self.assertEqual(plan.compute_plan(mac(48, disk=2000)).model_budget_gb, 75)

    def test_low_disk(self):
        self.assertEqual(plan.compute_plan(mac(48, disk=60)).model_budget_gb, 5)    # 60 - 35 - 20
        p = plan.compute_plan(mac(48, disk=40))
        self.assertEqual(p.model_budget_gb, 0)
        self.assertTrue(any("free" in w for w in p.warnings))

    def test_installed_models_and_images_are_credited(self):
        st = plan.LocalState(installed={"x"}, installed_gb=40.0, images_present=True)
        # 60 free + 40 already installed - 0 images (present) - 20 safety = 80, capped at 75
        self.assertEqual(plan.compute_plan(mac(48, disk=60), state=st).model_budget_gb, 75)
        st = plan.LocalState(installed={"x"}, installed_gb=10.0, images_present=False)
        self.assertEqual(plan.compute_plan(mac(48, disk=60), state=st).model_budget_gb, 15)

    def test_wired_limit_override(self):
        p = plan.compute_plan(mac(64, wired=20480))
        self.assertLessEqual(p.fence_gb, 19)
        self.assertTrue(any("wired_limit" in w for w in p.warnings))

    def test_resident_estimate(self):
        x = m("x", "workhorse", 10, kv=2.0)
        self.assertEqual(plan.resident_gb(x, 32768, 1), 13.2)    # 10 + 2 + 1.0 + 0.25
        self.assertEqual(plan.resident_gb(x, 32768, 2), 15.5)    # 10 + 4 + 1.0 + 0.5
        x["vision"] = True
        self.assertEqual(plan.resident_gb(x, 32768, 2), 16.0)

    HF = {"type": "hf", "repo": "org/w-GGUF", "file": "w.gguf", "revision": "a" * 40, "sha256": "b" * 64}

    def test_installed_models_need_no_headroom(self):
        # Installed models are on disk already: keeping them needs no free space at all, so a re-plan
        # on a nearly full disk still accepts (and recommends) them; new downloads still can't fit.
        cat = {x["id"]: x for x in synthetic()}
        keep = [cat["w-big"], cat["d-big"], cat["a-big"]]                    # 19 + 17 + 17 GB
        st = plan.LocalState(installed={x["alias"] for x in keep}, installed_gb=53.0, images_present=True)
        for free in (5, 15, 20):
            p = plan.compute_plan(mac(48, disk=free), state=st)
            with self.subTest(free=free):
                self.assertEqual((p.new_disk_gb, p.model_budget_gb), (0, 53))
                self.assertEqual(plan.validate_selection(keep, p), [])
                self.assertEqual([x["id"] for x in plan.recommend(p, synthetic())], ["w-big", "d-big", "a-big"])
                errs = plan.validate_selection([cat["w-big"], cat["d-big"], cat["a-mid"]], p)
                self.assertTrue(any("not installed yet need 8.0 GB" in e for e in errs), errs)
        # The real reference set (55.7 GB) at exactly 20 GB free: the budget is rounded up, not truncated.
        real = {x["id"]: x for x in plan.load_catalog()}
        ref = [real["qwen3.6-35b-moe"], real["qwen3.8-27b"], real["gemma4-26b"]]
        st = plan.LocalState(installed={x["alias"] for x in ref}, installed_gb=sum(x["size_gb"] for x in ref),
                             images_present=True)
        self.assertEqual(plan.validate_selection(ref, plan.compute_plan(mac(48, disk=20.0), state=st)), [])

    def test_gguf_download_needs_its_size_twice(self):
        # A Hugging Face model is downloaded as a GGUF file and then copied into Ollama's store.
        hf = m("w-hf", "workhorse", 19, 0.3, "qwen", source=dict(self.HF))
        p = plan.compute_plan(mac(48, disk=95))                    # 95 - 35 images - 20 headroom = 40
        self.assertEqual(p.new_disk_gb, 40)
        self.assertEqual(plan.validate_selection([hf], p), [])     # 19 + 19 <= 40
        big = dict(hf, size_gb=21)
        errs = plan.validate_selection([big], p)                   # 21 + 21 > 40
        self.assertTrue(any("Hugging Face" in e for e in errs), errs)
        self.assertEqual(plan.validate_selection([dict(big, source={"type": "ollama", "ref": "pub/w:latest"})], p), [])
        st = plan.LocalState(installed={big["alias"]}, installed_gb=21.0)
        self.assertEqual(plan.validate_selection([big], plan.compute_plan(mac(48, disk=95), state=st)), [])

    def test_gguf_staged_on_another_volume(self):
        # Models on another volume; GGUF files still go to ~/models/gguf on the home volume, where the
        # Docker images go too.
        hf = m("w-hf", "workhorse", 19, 0.3, "qwen", source=dict(self.HF))
        hw = mac(48, disk=500)
        hw.same_volume, hw.images_free_gb = False, 30
        hw.staging_same_volume, hw.staging_home_volume, hw.staging_free_gb = False, True, 30
        self.assertIn("GGUF downloads", hw.summary())
        p = plan.compute_plan(hw)                                  # 30 - 35 images - 20 headroom
        self.assertEqual((p.new_disk_gb, p.staging_disk_gb), (480, 0))
        errs = plan.validate_selection([hf], p)
        self.assertTrue(any("Hugging Face download needs 19.0 GB" in e for e in errs), errs)
        built = plan.LocalState(images_present=True)
        self.assertEqual(plan.compute_plan(hw, state=built).staging_disk_gb, 10)
        self.assertTrue(plan.validate_selection([hf], plan.compute_plan(hw, state=built)))
        hw.staging_free_gb = 60
        self.assertEqual(plan.validate_selection([hf], plan.compute_plan(hw, state=built)), [])
        self.assertEqual(plan.validate_selection([dict(hf, source={"type": "ollama", "ref": "pub/w:latest"})], p), [])

    def test_wired_limit_warning_names_the_sysctl_read(self):
        hw = mac(64, wired=20480)
        hw.wired_limit_key = "debug.iogpu.wired_limit"            # macOS 13
        text = " ".join(plan.compute_plan(hw).warnings)
        self.assertIn("sudo sysctl debug.iogpu.wired_limit=0", text)
        self.assertNotIn("wired_limit_mb", text)

    def test_disk_messages_keep_a_decimal(self):
        p = plan.compute_plan(mac(18, disk=58))                    # 3 GB free for new downloads
        errs = plan.validate_selection([m("w", "workhorse", 3.3, 0.3)], p)
        self.assertTrue(any("need 3.3 GB" in e for e in errs), errs)
        self.assertTrue(any("needs 3.3 GB of disk" in e for e in errs), errs)

    def test_images_warning_whenever_they_dont_fit(self):
        # Docker's images still to be built here share the models' free space. Installed models raise the
        # budget, so it can't tell whether the images fit: the warning goes by the free space itself.
        def warnings(free, installed_gb=0.0, images=False):
            st = plan.LocalState(installed={"x"} if installed_gb else set(), installed_gb=installed_gb,
                                 images_present=images)
            return " | ".join(plan.compute_plan(mac(48, disk=free), state=st).warnings)
        self.assertIn("Only 40.0 GB free: Docker images need ~35 GB", warnings(40, 9.0))   # qwen3-14b installed
        self.assertIn("Docker images need ~35 GB", warnings(30, 55.7))     # the reference set installed
        self.assertIn("Only 54.9 GB free", warnings(54.99, 55.7))          # never rounded up to what is needed
        self.assertEqual(warnings(55, 9.0), "")                            # images + headroom fit
        self.assertEqual(warnings(30, 55.7, images=True), "")              # images built: nothing to warn about
        self.assertIn("Only 22 GB free: models need room", warnings(22, images=True))     # budget 2: the fallback
        self.assertIn("Docker images need ~35 GB plus models", warnings(58))              # images fit, models don't


class TestFinalizeContext(unittest.TestCase):
    def test_small_models_raise_16k_to_32k(self):
        p = plan.compute_plan(mac(16, cpus=8))
        self.assertEqual(p.ctx, 16384)
        tiny = m("t", "workhorse", 2.0, kv=0.5)
        f = plan.finalize_context(p, [tiny])
        self.assertEqual((f.ctx, f.parallel, f.max_tokens), (32768, 1, 16384))
        self.assertNotIn(plan.CTX_WARNING, f.warnings)

    def test_never_raises_parallel(self):
        p = plan.compute_plan(mac(24))
        f = plan.finalize_context(p, [m("t", "workhorse", 1.0, kv=0.1)])
        self.assertEqual(f.parallel, 1)

    def test_never_lowers(self):
        p = plan.compute_plan(mac(48))            # fence 24, 32K x 2
        big = m("b", "workhorse", 20, kv=2.0)     # wouldn't fit at x2, but selection validation stops that
        self.assertEqual(plan.finalize_context(p, [big]), p)
        p16 = plan.compute_plan(mac(16, cpus=8))
        self.assertEqual(plan.finalize_context(p16, [m("x", "workhorse", 4.0, kv=1.0)]).ctx, 16384)

    def test_embed_ignored(self):
        p = plan.compute_plan(mac(48))
        self.assertEqual(plan.finalize_context(p, [embed()]).parallel, p.parallel)


# --------------------------------------------------------------------------- recommendation
class TestRecommendSynthetic(unittest.TestCase):
    def setUp(self):
        self.cat = synthetic()
        self.assertEqual(plan.validate_catalog(self.cat), [])

    def test_constraints_hold_everywhere(self):
        for ram in TIERS:
            for disk in (60, 120, 600):
                p = plan.compute_plan(mac(ram, disk=disk))
                rec = plan.recommend(p, self.cat)
                with self.subTest(ram=ram, disk=disk):
                    self.assertLessEqual(len(rec), p.max_chat_models)
                    self.assertLessEqual(sum(x["size_gb"] for x in rec), p.model_budget_gb)
                    for x in rec:
                        self.assertLessEqual(plan.resident_gb(x, p.ctx, p.parallel), p.fence_gb)
                    if rec:
                        primary = plan._primary(rec)
                        self.assertTrue(primary["tools"])
                        self.assertEqual(plan.validate_selection(rec, p), [])
                        for a in (x for x in rec if x["role"] == "alt" and x is not primary):
                            self.assertNotEqual(a["family"], primary["family"])

    def test_alt_must_differ_in_family(self):
        rec = plan.recommend(plan.compute_plan(mac(48)), self.cat)
        self.assertEqual([x["id"] for x in rec], ["w-big", "d-big", "a-big"])  # a-qwen ranks higher, same family

    def test_best_primary_beats_more_roles(self):
        # Filling all three roles with a weak primary loses to the best workhorse alone.
        cat = [m("w-big", "workhorse", 19, 0.3, "qwen", rank=90), m("w-small", "workhorse", 5, 0.3, "qwen", rank=50),
               m("d-mid", "deep", 9, 0.3, "qwen", rank=60), m("a-mid", "alt", 8, 0.3, "gemma", rank=60), embed()]
        p = plan.compute_plan(mac(48, disk=78))      # budget 23
        self.assertEqual([x["id"] for x in plan.recommend(p, cat)], ["w-big"])

    def test_roles_filled_around_the_best_primary(self):
        cat = [m("w-big", "workhorse", 12, 0.3, "qwen", rank=90), m("d-mid", "deep", 9, 0.3, "qwen", rank=60),
               m("d-big", "deep", 15, 0.3, "qwen", rank=90), m("a-mid", "alt", 8, 0.3, "gemma", rank=60), embed()]
        p = plan.compute_plan(mac(48, disk=84))      # budget 29: w-big + d-mid + a-mid (29) beats w-big + d-big (27)
        self.assertEqual([x["id"] for x in plan.recommend(p, cat)], ["w-big", "d-mid", "a-mid"])

    def test_workhorse_primary_preferred_over_higher_ranked_deep(self):
        cat = [m("w", "workhorse", 5, 0.3, rank=30), m("d", "deep", 5, 0.3, rank=95), embed()]
        p = plan.compute_plan(mac(48), max_models=1)
        self.assertEqual([x["id"] for x in plan.recommend(p, cat)], ["w"])

    def test_dropped_installed_models_dont_count_as_free(self):
        cat = {x["id"]: x for x in self.cat}
        st = plan.LocalState(installed={"w-big-abliterated"}, installed_gb=19.0, images_present=True)
        p = plan.compute_plan(mac(48, disk=40), state=st)    # total budget 39, new downloads 20
        self.assertEqual((p.model_budget_gb, p.new_disk_gb), (39, 20))
        self.assertEqual(plan.validate_selection([cat["w-big"], cat["d-big"]], p), [])
        errs = plan.validate_selection([cat["d-big"], cat["a-big"]], p)
        self.assertTrue(any("not installed yet" in e for e in errs), errs)
        rec = plan.recommend(p, self.cat)
        self.assertLessEqual(sum(x["size_gb"] for x in rec if x["alias"] not in p.installed), 20)

    def test_budget_limits_selection(self):
        rec = plan.recommend(plan.compute_plan(mac(48, disk=95)), self.cat)   # budget 40
        self.assertLessEqual(sum(x["size_gb"] for x in rec), 40)

    def test_max_models(self):
        p = plan.compute_plan(mac(48), max_models=1)
        self.assertEqual(len(plan.recommend(p, self.cat)), 1)

    def test_nothing_fits(self):
        cat = [m("huge", "workhorse", 90), embed()]
        self.assertEqual(plan.recommend(plan.compute_plan(mac(16)), cat), [])

    def test_no_tool_model_means_no_recommendation(self):
        cat = [m("a", "alt", 3, tools=False), embed()]
        self.assertEqual(plan.recommend(plan.compute_plan(mac(48)), cat), [])

    def test_validate_selection_errors(self):
        p = plan.compute_plan(mac(24))
        cat = {x["id"]: x for x in self.cat}
        self.assertTrue(any("needs" in e for e in plan.validate_selection([cat["w-big"]], p)))
        errs = plan.validate_selection([cat["w-tiny"], cat["w-small"], cat["d-mid"], cat["a-mid"]], p)
        self.assertTrue(any("limit" in e for e in errs))
        notools = dict(cat["a-mid"], tools=False)
        self.assertTrue(any("tool calling" in e for e in plan.validate_selection([notools], p)))
        self.assertTrue(any("at least one" in e for e in plan.validate_selection([], p)))
        self.assertTrue(any("twice" in e for e in plan.validate_selection([cat["w-tiny"], cat["w-tiny"]], p)))
        small = plan.compute_plan(mac(48, disk=70))    # budget 15
        self.assertTrue(any("disk" in e for e in plan.validate_selection([cat["w-mid"], cat["w-small"]], small)))

    def test_assign_roles(self):
        cat = {x["id"]: x for x in self.cat}
        r = plan.assign_roles([cat["a-mid"], cat["d-mid"], cat["w-small"]])
        self.assertEqual((r["chat"]["id"], r["deep"]["id"], r["alt"]["id"]), ("w-small", "d-mid", "a-mid"))
        r = plan.assign_roles([cat["w-small"], cat["d-mid"]], primary="d-mid")
        self.assertEqual(r["chat"]["id"], "d-mid")
        self.assertIsNone(r["deep"])
        with self.assertRaises(plan.PlanError):
            plan.assign_roles([dict(cat["a-mid"], tools=False), cat["w-small"]], primary="a-mid")
        with self.assertRaises(plan.PlanError):
            plan.assign_roles([cat["w-small"]], primary="nope")
        with self.assertRaises(plan.PlanError):
            plan.assign_roles([dict(cat["a-mid"], tools=False)])

    def test_installed_model_recommended_on_a_full_disk(self):
        # Nothing new fits, but the model already installed does: it is still the recommendation.
        st = plan.LocalState(installed={"w-big-abliterated"}, installed_gb=19.0, images_present=True)
        p = plan.compute_plan(mac(48, disk=10), state=st)
        self.assertEqual([x["id"] for x in plan.recommend(p, self.cat)], ["w-big"])

    def test_gguf_staging_steers_the_recommendation(self):
        hf = m("w-hf", "workhorse", 19, 0.3, "qwen", rank=90, source=dict(TestComputePlan.HF))
        cat = [hf, m("w-hub", "workhorse", 13, 0.4, "gpt", rank=70), embed()]
        p = plan.compute_plan(mac(48, disk=90))        # 35 GB for new downloads: 19 fits once, not twice
        self.assertEqual([x["id"] for x in plan.recommend(p, cat)], ["w-hub"])
        p = plan.compute_plan(mac(48, disk=95))        # 40 GB: room for the file and Ollama's copy
        self.assertEqual([x["id"] for x in plan.recommend(p, cat)], ["w-hf"])

    def test_with_primary_replaces_the_pick_in_its_role(self):
        p = plan.compute_plan(mac(48))
        ids, primary = plan.with_primary(self.cat, ["w-big", "d-big", "a-big"], "w-mid-abliterated", p)
        self.assertEqual((ids, primary), (["d-big", "a-big", "w-mid"], "w-mid"))
        ids, primary = plan.with_primary(self.cat, ["w-big", "d-big", "a-big"], "a-big", p)
        self.assertEqual((ids, primary), (["w-big", "d-big", "a-big"], "a-big"))   # selected already: stays
        self.assertEqual(plan.with_primary(self.cat, [], "d-mid", p), (["d-mid"], "d-mid"))
        notools = [dict(x, tools=False) if x["id"] == "a-mid" else x for x in self.cat]
        for bad in ("a-mid", "embed"):
            with self.assertRaises(plan.PlanError):
                plan.with_primary(notools, ["w-big"], bad, p)


# --------------------------------------------------------------------------- catalog
class TestCatalogValidation(unittest.TestCase):
    def test_rejects_bad_entries(self):
        base = synthetic()
        hf = {"type": "hf", "repo": "a/b", "file": "x.gguf", "revision": "a" * 40, "sha256": None}
        cases = {
            "duplicate alias": lambda c: c[1].update(alias=c[0]["alias"]),
            "duplicate id": lambda c: c[1].update(id=c[0]["id"]),
            "duplicate provider": lambda c: c[1].update(provider=c[0]["provider"]),
            "option-like ref": lambda c: c[0].update(source={"type": "ollama", "ref": "-rf"}),
            "registry host in ref": lambda c: c[0].update(source={"type": "ollama", "ref": "evil.com/x/y:1"}),
            "ghcr ref": lambda c: c[0].update(source={"type": "ollama", "ref": "ghcr.io/x:1"}),
            "newline in ref": lambda c: c[0].update(source={"type": "ollama", "ref": "pub/x:1\n"}),
            "path traversal file": lambda c: c[0].update(source=dict(hf, file="../x.gguf")),
            "short revision": lambda c: c[0].update(source=dict(hf, revision="abc123")),
            "bad sha": lambda c: c[0].update(source=dict(hf, sha256="XYZ")),
            "unknown source": lambda c: c[0].update(source={"type": "http", "url": "x"}),
            "bad role": lambda c: c[0].update(role="boss"),
            "uppercase alias": lambda c: c[0].update(alias="Qwen"),
            "two embeds": lambda c: c.append(dict(c[-1], id="embed2", alias="embed2",
                                                  source={"type": "ollama", "ref": "embed2"})),
            "no embed": lambda c: c.pop(),
            "embed alias != ref": lambda c: c[-1].update(alias="other-embed"),
            "hf embed": lambda c: c[-1].update(source=hf),
            "string size": lambda c: c[0].update(size_gb="19"),
            "nan size": lambda c: c[0].update(size_gb=float("nan")),
            "bool rank": lambda c: c[0].update(rank=True),
            "negative kv": lambda c: c[0].update(kv_gb_32k=-1),
            "non-string notes": lambda c: c[0].update(notes=5),
            "non-string id": lambda c: c[0].update(id=7),
            "bad provider": lambda c: c[0].update(provider="remote; rm -rf"),
            "reasoning_off not bool": lambda c: c[0].update(reasoning_off="no"),
            "bad weights pin": lambda c: c[0].update(weights_sha256="abc"),
            "missing key": lambda c: c[0].pop("family"),
            "tools not bool": lambda c: c[0].update(tools="yes"),
        }
        for name, mutate in cases.items():
            cat = copy.deepcopy(base)
            mutate(cat)
            with self.subTest(name):
                self.assertNotEqual(plan.validate_catalog(cat), [])

    def test_accepts_optional_fields(self):
        cat = synthetic()
        cat[0]["reasoning_off"] = False
        cat[0]["weights_sha256"] = "a" * 64
        cat[1]["weights_sha256"] = None
        self.assertEqual(plan.validate_catalog(cat), [])

    def test_limit_15(self):
        cat = synthetic()
        for i in range(10):
            cat.insert(0, m(f"extra{i}", "workhorse", 5))
        self.assertTrue(any("limit" in e for e in plan.validate_catalog(cat)))

    def test_not_a_list(self):
        self.assertTrue(plan.validate_catalog(None))
        self.assertTrue(plan.validate_catalog([]))
        self.assertTrue(plan.validate_catalog(["x"]))

    def test_weights_digest(self):
        x = m("x", "workhorse", 1, source={"type": "hf", "repo": "a/b", "file": "x.gguf", "revision": "a" * 40,
                                            "sha256": "b" * 64}, weights_sha256="c" * 64)
        self.assertEqual(plan.weights_digest(x), "b" * 64)       # the GGUF hash wins for HF imports
        y = m("y", "workhorse", 1, weights_sha256="c" * 64)
        self.assertEqual(plan.weights_digest(y), "c" * 64)
        self.assertIsNone(plan.weights_digest(m("z", "workhorse", 1)))


class TestRealCatalog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = plan.load_catalog()

    def test_valid_and_small(self):
        self.assertEqual(plan.validate_catalog(self.cat), [])
        self.assertLessEqual(len(self.cat), 15)

    def test_chat_models_are_abliterated(self):
        for x in plan.chat_models(self.cat):
            self.assertTrue(x["abliterated"], x["id"])

    def test_gpt_oss_cannot_turn_reasoning_off(self):
        for x in self.cat:
            if x["family"] == "gpt-oss":
                self.assertIs(x.get("reasoning_off"), False, x["id"])

    def test_reference_mac_gets_current_stack(self):
        p = plan.compute_plan(mac(48, cpus=18, disk=600))
        rec = plan.recommend(p, self.cat)
        self.assertEqual([x["alias"] for x in rec],
                         ["qwen3.6-35b-a3b-abliterated", "qwen3.8-27b-abliterated", "gemma4-26b-abliterated"])
        roles = plan.assign_roles(rec)
        self.assertEqual(roles["chat"]["provider"], "local-qwen36-moe")

    def test_every_tier_gets_a_valid_tool_model(self):
        for ram in TIERS:
            p = plan.compute_plan(mac(ram, disk=800))
            rec = plan.recommend(p, self.cat)
            with self.subTest(ram=ram):
                self.assertTrue(rec, f"nothing recommended at {ram} GB")
                self.assertTrue(plan._primary(rec)["tools"])
                self.assertEqual(plan.validate_selection(rec, p), [])

    def test_larger_machines_never_get_smaller_primary(self):
        prev = 0
        for ram in TIERS:
            rec = plan.recommend(plan.compute_plan(mac(ram, disk=800)), self.cat)
            size = plan._primary(rec)["size_gb"]
            with self.subTest(ram=ram):
                self.assertGreaterEqual(size, prev)
            prev = size


# --------------------------------------------------------------------------- config files
class TestConf(unittest.TestCase):
    def setUp(self):
        self.cat = synthetic()
        self.p = plan.compute_plan(mac(48))
        self.roles = plan.assign_roles(plan.recommend(self.p, self.cat))
        self.embed = plan.embed_model(self.cat)
        self.tmp = tempfile.TemporaryDirectory()
        self.f = Path(self.tmp.name) / "stack.conf"

    def tearDown(self):
        self.tmp.cleanup()

    def test_stack_conf_round_trip(self):
        self.f.write_text(plan.stack_conf_text(mac(48), self.p, self.roles, self.embed))
        conf = plan.read_conf(self.f)
        self.assertEqual(conf["CHAT_MODEL"], "w-big-abliterated")
        self.assertEqual(conf["MODELS"], "w-big-abliterated,d-big-abliterated,a-big-abliterated")
        self.assertEqual(conf["PENTAGI_DEFAULT_PROVIDER"], "local-w-big")
        self.assertEqual(conf["OLLAMA_CONTEXT_LENGTH"], "32768")
        self.assertEqual(conf["INFERENCE_FENCE_GB"], "24")
        for k, v in conf.items():
            self.assertRegex(v, r"^[A-Za-z0-9._:/,-]*$", k)

    def test_none_slots(self):
        roles = dict(self.roles, deep=None, alt=None, all=[self.roles["chat"]])
        self.f.write_text(plan.stack_conf_text(mac(48), self.p, roles, self.embed))
        conf = plan.read_conf(self.f)
        self.assertEqual((conf["DEEP_MODEL"], conf["ALT_MODEL"]), ("none", "none"))

    def test_unsafe_value_refused(self):
        bad = dict(self.roles, chat=dict(self.roles["chat"], alias="x;touch /tmp/pwn"))
        with self.assertRaises(plan.PlanError):
            plan.stack_conf_text(mac(48), self.p, bad, self.embed)
        bad = dict(self.roles, chat=dict(self.roles["chat"], alias="x\nEVIL=1"))
        with self.assertRaises(plan.PlanError):
            plan.stack_conf_text(mac(48), self.p, bad, self.embed)

    def test_read_conf_rules(self):
        self.f.write_bytes(b"CHAT_MODEL=$(reboot)\nOK=fine\r\n# X=y\nA=1\nA=2\nB=keep\nB=\nC=x\nC=bad value\n"
                           b" D=indented\nlower=x\nE=-dash\n")
        # E: a leading dash could pass as an option to a command, so it counts as unsafe
        self.assertEqual(plan.read_conf(self.f), {"OK": "fine", "A": "2"})

    def test_read_conf_missing(self):
        self.assertEqual(plan.read_conf(Path(self.tmp.name) / "nope"), {})


class TestGenerated(unittest.TestCase):
    def setUp(self):
        self.cat = synthetic()
        self.p = plan.compute_plan(mac(48))
        self.roles = plan.assign_roles(plan.recommend(self.p, self.cat))
        self.embed = plan.embed_model(self.cat)

    def test_providers(self):
        files = dict(plan.providers(self.roles, self.p))
        names = [d["name"] for d in files.values()]
        self.assertEqual(names[0], "local-w-big")
        self.assertIn("local-hybrid", names)
        self.assertEqual(list(files), sorted(files))
        hybrid = next(d for d in files.values() if d["name"] == "local-hybrid")
        self.assertEqual(hybrid["roles"]["adviser"]["model"], "d-big-abliterated")
        self.assertIsNone(hybrid["roles"]["adviser"]["reasoning"])
        self.assertEqual(hybrid["default"]["reasoning"], {"mode": "off"})
        self.assertEqual(hybrid["default"]["max_tokens"], self.p.max_tokens)
        no_deep = dict(self.roles, deep=None, all=[self.roles["chat"]])
        self.assertNotIn("local-hybrid", [d["name"] for _, d in plan.providers(no_deep, self.p)])

    def test_reasoning_effort_for_models_that_always_think(self):
        gpt = m("gpt", "workhorse", 13, family="gpt-oss", reasoning_off=False)
        roles = plan.assign_roles([gpt])
        doc = dict(plan.providers(roles, self.p))["10-local-gpt.json"]
        self.assertEqual(doc["default"]["reasoning"], {"effort": "low"})
        y = plan.ollama_provider_yml(gpt, self.p)
        self.assertEqual(y.count('effort: "low"'), 12)
        self.assertNotIn('mode: "off"', y)

    def test_ollama_provider_yml(self):
        y = plan.ollama_provider_yml(self.roles["chat"], self.p)
        for r in plan.PENTAGI_ROLES:
            self.assertIn(f"\n{r}:\n", "\n" + y)
        adviser = y.split("adviser:")[1].split("\n\n")[0]
        self.assertNotIn("reasoning", adviser)
        self.assertEqual(y.count('mode: "off"'), 12)
        self.assertIn(f"max_tokens: {self.p.max_tokens}", y)

    def test_fiveire_config(self):
        five = json.loads(plan.fiveire_config())
        bridge = five["mcpServers"]["pentagi-bridge"]
        self.assertEqual(bridge["env"]["SECOPS"], str(plan.SECOPS))
        self.assertNotIn("PENTAGI_PROVIDER", bridge["env"])
        self.assertNotIn("__", json.dumps(five))


class TestWriteOutputs(unittest.TestCase):
    def setUp(self):
        reset_secops()
        self.cat = synthetic()
        self.p = plan.compute_plan(mac(48))
        self.roles = plan.assign_roles(plan.recommend(self.p, self.cat))
        self.embed = plan.embed_model(self.cat)
        self.provdir = plan.PROVIDERS_DIR

    def tearDown(self):
        reset_secops()

    def write(self):
        return plan.write_outputs(mac(48), self.p, self.roles, self.embed)

    def test_permissions(self):
        written = self.write()
        for f in written:
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600, f)
        for d in (plan.SECOPS, plan.CFG, plan.GEN, self.provdir):
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700, d)
        sel = json.loads(plan.SELECTED.read_text())
        self.assertEqual(sel["primary"], "w-big-abliterated")
        self.assertEqual(sel["models"][-1]["alias"], "nomic-embed-text")

    def test_loose_dir_is_tightened(self):
        plan.CFG.mkdir(parents=True)
        os.chmod(plan.CFG, 0o755)
        self.write()
        self.assertEqual(stat.S_IMODE(plan.CFG.stat().st_mode), 0o700)

    def test_old_repo_link_replaced(self):
        fake_repo = _TMP / "fake-repo"
        (fake_repo / "configs").mkdir(parents=True, exist_ok=True)
        self.provdir.parent.mkdir(parents=True)
        self.provdir.symlink_to(fake_repo / "configs")
        with mock.patch.object(plan, "REPO", fake_repo):
            self.write()
        self.assertFalse(self.provdir.is_symlink())
        self.assertEqual(list((fake_repo / "configs").iterdir()), [], "nothing may be written into the repo")

    def test_foreign_symlink_refused(self):
        other = _TMP / "elsewhere"
        other.mkdir(exist_ok=True)
        self.provdir.parent.mkdir(parents=True)
        self.provdir.symlink_to(other)
        with self.assertRaises(plan.PlanError):
            self.write()
        self.assertEqual(list(other.iterdir()), [])

    def test_symlinked_generated_dir_refused(self):
        other = _TMP / "elsewhere2"
        other.mkdir(exist_ok=True)
        plan.CFG.mkdir(parents=True)
        plan.GEN.symlink_to(other)
        with self.assertRaises(plan.PlanError):
            self.write()

    def test_replan_keeps_hand_made_files_and_drops_stale_generated(self):
        self.write()
        keep = self.provdir / "99-hand-made.json"
        keep.write_text('{"name": "mine"}')
        roles = dict(self.roles, deep=None, all=[self.roles["chat"], self.roles["alt"]])
        plan.write_outputs(mac(48), self.p, roles, self.embed)
        names = sorted(p.name for p in self.provdir.glob("*.json"))
        self.assertIn("99-hand-made.json", names)
        self.assertFalse(any("hybrid" in n for n in names), names)

    def test_installed_record_kept_for_selected_models_only(self):
        self.write()
        sel = json.loads(plan.SELECTED.read_text())
        sel["installed"] = {"w-big-abliterated": {"digest": "a" * 64}, "gone-abliterated": {"digest": "b" * 64}}
        plan.SELECTED.write_text(json.dumps(sel))
        self.write()
        self.assertEqual(list(json.loads(plan.SELECTED.read_text())["installed"]), ["w-big-abliterated"])


    def test_overlap_found_by_identity(self):
        # APFS ignores case: ~/github/x and ~/GitHub/x are one folder, yet realpath keeps either spelling.
        # Two distinct folder names stand in for the two spellings (on a Mac, the real ones would overlap).
        with tempfile.TemporaryDirectory() as t:
            repo = os.path.join(t, "one", "repo")
            runtime = os.path.join(t, "two", "repo", ".sec-ops")
            os.makedirs(repo)
            os.makedirs(runtime)
            self.assertFalse(plan._overlaps(Path(runtime), Path(repo)), "distinct folders on this disk")
            real = plan._identity

            def same_folder(p):         # "two" names the same folder as "one", as two spellings do on APFS
                return real(p.replace(os.sep + "two" + os.sep, os.sep + "one" + os.sep))
            with mock.patch.object(plan, "_identity", same_folder):
                self.assertTrue(plan._overlaps(Path(runtime), Path(repo)))
                self.assertTrue(plan._overlaps(Path(repo), Path(runtime)))


class TestLocalState(unittest.TestCase):
    def setUp(self):
        reset_secops()
        self.store = Path(os.environ["OLLAMA_MODELS"])
        shutil.rmtree(self.store, ignore_errors=True)

    def tearDown(self):
        reset_secops()
        shutil.rmtree(self.store, ignore_errors=True)

    def test_counts_installed_aliases(self):
        man = self.store / "manifests" / "registry.ollama.ai" / "library" / "w-big-abliterated"
        man.mkdir(parents=True)
        (man / "latest").write_text("{}")
        with mock.patch.object(plan, "_run", return_value=""):
            st = plan.local_state(synthetic())
        self.assertEqual(st.installed, {"w-big-abliterated"})
        self.assertEqual(st.installed_gb, 19.0)
        self.assertFalse(st.images_present)

    def test_install_record_means_images_present(self):
        plan.CFG.mkdir(parents=True)
        plan.SELECTED.write_text(json.dumps({"installed": {"x": {}}}))
        with mock.patch.object(plan, "_run", return_value=""):
            self.assertTrue(plan.local_state(synthetic()).images_present)


# --------------------------------------------------------------------------- install
def ollama_reads(text):
    """What Ollama's Modelfile parser (parser.ParseFile, ollama v0.40.17) reads from text: [(name, args)],
    FROM as "model", PARAMETER as the parameter's name, MESSAGE args as "role: content"; None where Ollama
    fails. An independent transliteration of the Go code (CR and LF both end a line, runes that
    strconv.IsPrint rejects are dropped from the buffer, every command's value is unquoted the same way),
    kept apart from plan.py's reader so a test can check what Ollama itself would see."""
    import unicodedata
    NIL, NAME, VALUE, PARAM, MSG, COMMENT = range(6)
    valid = ("from", "license", "template", "system", "adapter", "draft", "renderer", "parser", "parameter",
             "message", "requires", "capability")

    def printable(r):
        return r == " " or (r != "" and unicodedata.category(r)[0] in "LMNPS")

    def alpha(r):
        return "a" <= r <= "z" or "A" <= r <= "Z"

    def trim(s):        # strings.TrimSpace
        sp = lambda c: c in "\t\n\v\f\r \x85\xa0" or unicodedata.category(c) in ("Zs", "Zl", "Zp")  # noqa: E731
        i, j = 0, len(s)
        while i < j and sp(s[i]):
            i += 1
        while j > i and sp(s[j - 1]):
            j -= 1
        return s[i:j]

    def unquote(s):
        if s[:3] == '"""':
            return (s[3:-3], True) if len(s) >= 6 and s[-3:] == '"""' else ("", False)
        if s[:1] == '"':
            return (s[1:-1], True) if len(s) >= 2 and s[-1:] == '"' else ("", False)
        return s, True
    text = text[1:] if text.startswith("\ufeff") else text        # unicode.BOMOverride
    cmds, b, curr, name, role = [], [], NIL, "", ""
    for r in text:
        if curr == NIL:
            nxt, r = (COMMENT, "") if r == "#" else (NIL, "") if r in " \t\r\n" else (NAME, r)
        elif curr == NAME:
            if alpha(r):
                nxt = NAME
            elif r in " \t":
                nxt, r = VALUE, ""
            else:
                return None
        elif curr == VALUE:
            nxt = NIL if r in " \t\r\n" else VALUE
        elif curr in (PARAM, MSG):
            if alpha(r) or (curr == PARAM and ("0" <= r <= "9" or r == "_")):
                nxt = curr
            elif r in " \t":
                nxt, r = VALUE, ""
            else:
                return None
        else:
            nxt, r = (NIL, "") if r in "\r\n" else (COMMENT, "")
        if nxt != curr:
            word = "".join(b)
            if curr == NAME:
                if word.lower() not in valid:
                    return None
                low = word.lower()
                if low == "parameter":
                    nxt = PARAM
                elif low == "message":
                    nxt, name = MSG, low
                else:
                    name = "model" if low == "from" else low
            elif curr == PARAM:
                name = word
            elif curr == MSG:
                if word not in ("system", "user", "assistant"):
                    return None
                role = word
            elif curr == VALUE:
                s, ok = unquote(trim(word))
                if not ok or r in " \t":
                    b.append(r)
                    continue
                if role:
                    s, role = role + ": " + s, ""
                cmds.append((name, s))
            b, curr = [], nxt
        if printable(r):
            b.append(r)
    if curr == VALUE:
        s, ok = unquote(trim("".join(b)))
        if not ok:
            return None
        cmds.append((name, role + ": " + s if role else s))
    elif curr not in (NIL, COMMENT):
        return None
    return cmds


EVIL = "evil.example.com/ns/backdoor:latest"


class TestModelfile(unittest.TestCase):
    """The Modelfile allowlist: what plan.py accepts must read, in Ollama, as exactly the commands it
    meant, and nothing that changes the model itself may get through, however it is quoted."""

    def export(self, text):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        with open(Path(d.name) / "w-big-abliterated.Modelfile", "w", encoding="utf-8", newline="") as f:
            f.write(text)                                  # exactly these characters, line ends included
        pt = mock.patch.object(plan, "EXPORTED_DIR", Path(d.name))
        pt.start()
        self.addCleanup(pt.stop)
        return plan.modelfile_text(m("w-big", "workhorse", 19), "pub/w:1", 32768, 16384)

    def test_allowed_commands_kept(self):
        mf = self.export('TEMPLATE """{{ .Prompt }}\nFROM inside a template is just text\n"""\n'
                         "PARAMETER num_ctx 4096\nparameter NUM_PREDICT 10\nPARAMETER stop <|im_end|>\n"
                         'SYSTEM "be brief"\nRENDERER qwen3\nPARSER qwen3\n# a comment\n'
                         'MESSAGE user """hi\nthere"""\nPARAMETER stop """\n\nUser:"""\n')
        self.assertEqual(ollama_reads(mf), [
            ("model", "pub/w:1"), ("template", "{{ .Prompt }}\nFROM inside a template is just text\n"),
            ("stop", "<|im_end|>"), ("system", "be brief"), ("renderer", "qwen3"), ("parser", "qwen3"),
            ("message", "user: hi\nthere"), ("stop", "\n\nUser:"), ("num_ctx", "32768"), ("num_predict", "16384")])

    def test_refused(self):
        cases = (
            ("FROM /Users/someone/.ollama/blob\n", "FROM isn't allowed"),
            ("ADAPTER /x/lora\n", "ADAPTER isn't allowed"),
            ("DRAFT pub/small\n", "DRAFT isn't allowed"),
            ("CAPABILITY tools\n", "CAPABILITY isn't allowed"),
            ("REQUIRES 0.9\n", "REQUIRES isn't allowed"),
            # Ollama names a PARAMETER after the parameter, then acts on that name: these are FROM, ADAPTER
            (f"PARAMETER model {EVIL}\n", "FROM isn't allowed"),
            ("PARAMETER adapter /x/lora\n", "ADAPTER isn't allowed"),
            # a quoted PARAMETER or MESSAGE value may span lines in Ollama: it hides the FROM from a line reader
            (f'PARAMETER stop """a\nLICENSE """"\nFROM {EVIL}\n#"""\n', "FROM isn't allowed"),
            (f'MESSAGE user """a\nSYSTEM """"\nFROM {EVIL}\n#"""\n', "FROM isn't allowed"),
            # Ollama drops invisible characters: these join three quotes, or hide a FROM, out of sight
            (f'TEMPLATE """x""\u200b"\nFROM {EVIL}\n#"""\n', r"U\+200B"),
            (f"\u200bFROM {EVIL}\n", r"U\+200B"),
            ("PARAMETER stop \x01x\n", r"U\+0001"),
            ('SYSTEM "a\u0085b"\n', r"U\+0085"),                       # C1 control
            ('SYSTEM """a\u202eb"""\n', r"U\+202E"),                   # bidi override
            ('TEMPLATE """a\u00a0b"""\n', r"U\+00A0"),                 # a space other than U+0020
            ('SYSTEM """\ue000"""\n', r"U\+E000"),                     # private use
            ("\ufeffSYSTEM x\n", r"U\+FEFF"),                          # byte order mark
            ("# comment \u2028 inside\nSYSTEM x\n", r"U\+2028"),       # comments too
            # a bare CR ends a line for Ollama but not for an editor or git diff
            (f"PARAMETER stop x\rFROM {EVIL}\n", "carriage return"),
            (f"# note\rFROM {EVIL}\n", "carriage return"),
            (f'TEMPLATE """{{ .Prompt }}"""\nFROM {EVIL}\n', "FROM isn't allowed"),
            ('TEMPLATE """x""" FROM y\n', "unterminated"),
            ('TEMPLATE """never closed\n', "unterminated"),
            ('SYSTEM "unterminated\n', "unterminated"),
            ('SYSTEM "say """ now"\n', 'containing """'),             # can't be written back unambiguously
            ("garbage line\n", "unknown Modelfile command"),
            ("MESSAGE robot hi\n", "MESSAGE role"),
            ("PARAMETER num-ctx 5\n", "malformed PARAMETER"),
            ("SYSTEM\n", "unknown Modelfile command"),
        )
        for bad, why in cases:
            with self.subTest(bad=bad), self.assertRaisesRegex(plan.PlanError, why):
                self.export(bad)

    def test_refused_characters_dont_depend_on_the_unicode_version(self):
        # Refused: what Ollama drops in every Unicode version. Allowed: code points this Python may not
        # know yet (U+0378 is unassigned; U+1FAE0 is unassigned before Unicode 14, so in Python 3.9).
        for ch in ("\x00", "\x85", "\u200b", "\u202e", "\ufeff", "\ue000", "\U000f0000", "\ud800", "\u00a0",
                   "\u2028", "\u2029", "\u3000", "\ufdd0", "\ufdef", "\ufffe", "\uffff", "\U0001fffe", "\U0010ffff"):
            with self.subTest(ch=f"U+{ord(ch):04X}"):
                self.assertTrue(plan._bad_char(ch))
        for ch in ("a", " ", "\t", "\n", "\u0378", "\U0001fae0", "\u00e9", "\u4e2d", "\U000e0100"):
            with self.subTest(ch=f"U+{ord(ch):04X}"):
                self.assertFalse(plan._bad_char(ch))
        mf = self.export('TEMPLATE """{{ .Prompt }} \U0001fae0 \u0378"""\nSYSTEM \u0378\n')
        self.assertEqual(plan._ollama_parse(mf)[1:3], [("template", "{{ .Prompt }} \U0001fae0 \u0378"),
                                                       ("system", "\u0378")])
        self.assertEqual([n for n, _ in ollama_reads(mf)], ["model", "template", "system", "num_ctx", "num_predict"])

    def test_unknown_character_between_quotes_cant_hide_a_command(self):
        # Ollama drops a code point its Unicode tables don't know: ""<U+0378>" becomes a closing """.
        with self.assertRaisesRegex(plan.PlanError, 'containing """'):
            self.export(f'TEMPLATE """x""\u0378"\nFROM {EVIL}\n#"""\n')

    def test_long_quoted_values_are_read_in_linear_time(self):
        import time
        line = "Licensed under terms that run on and on, " * 4 + '"quoted"\n'
        text = 'LICENSE """' + line * 4000 + '"""\nPARAMETER stop x\n'     # ~760 kB, 4000 line breaks
        calls = []
        real = plan._mf_unquote
        with mock.patch.object(plan, "_mf_unquote", lambda s: calls.append(1) or real(s)):
            self.assertEqual([n for n, _ in plan._ollama_parse(text, need_from=False)], ["license", "stop"])
        self.assertLessEqual(len(calls), 2, "the value is not re-read at each space or line break")
        start = time.monotonic()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(plan, "EXPORTED_DIR", Path(d)):
            (Path(d) / "w-big-abliterated.Modelfile").write_text(text * 2)
            plan.modelfile_text(m("w-big", "workhorse", 19), "pub/w:1", 32768, 16384)
        self.assertLess(time.monotonic() - start, 30)

    def test_round_trip_catches_a_writer_mistake(self):
        # A safety net for the writer itself: had it written a multi-line value bare, Ollama would read
        # its second line as a command. The read-back must refuse the file.
        with mock.patch.object(plan, "_mf_value", lambda s, block=False: s), \
                self.assertRaisesRegex(plan.PlanError, "doesn't read back as the same commands"):
            self.export('TEMPLATE """{{ .Prompt }}\nADAPTER /x/lora"""\n')

    def test_crlf_line_ends_are_fine(self):
        mf = self.export("SYSTEM be brief\r\nPARAMETER stop <|im_end|>\r\n")
        self.assertEqual(ollama_reads(mf)[1:3], [("system", "be brief"), ("stop", "<|im_end|>")])

    def test_line_ends_are_read_untranslated(self):
        # Universal newlines would turn the bare CR into a line break and report the FROM instead.
        with self.assertRaisesRegex(plan.PlanError, "carriage return"):
            self.export(f"SYSTEM hi\rFROM {EVIL}\n")

    def test_accepted_files_read_the_same_in_ollama(self):
        """Fuzz: every file plan.py accepts must read, in Ollama, as the catalog's FROM plus only allowed
        commands, and as the same commands plan.py meant."""
        import random
        rnd = random.Random(20261121)
        atoms = ('"', '"""', '""', "\n", " ", "\t", "#", "a", "\u200b", "\r", "\\", "FROM ", "ADAPTER /x\n",
                 "PARAMETER stop ", "PARAMETER model ", "MESSAGE user ", "TEMPLATE ", "SYSTEM ", "LICENSE ",
                 "PARSER ", EVIL, "\n#", "x")
        accepted = 0
        with tempfile.TemporaryDirectory() as d, mock.patch.object(plan, "EXPORTED_DIR", Path(d)):
            for _ in range(3000):
                text = "".join(rnd.choice(atoms) for _ in range(rnd.randint(1, 14)))
                with open(Path(d) / "w-big-abliterated.Modelfile", "w", encoding="utf-8", newline="") as f:
                    f.write(text)
                try:
                    mf = plan.modelfile_text(m("w-big", "workhorse", 19), "pub/w:1", 32768, 16384)
                except plan.PlanError:
                    continue
                accepted += 1
                seen = ollama_reads(mf)
                with self.subTest(text=text):
                    self.assertIsNotNone(seen)
                    self.assertEqual([a for n, a in seen if n == "model"], ["pub/w:1"])
                    self.assertFalse({n for n, _ in seen} & {"adapter", "draft", "requires", "capability"})
                    self.assertEqual(seen, plan._ollama_parse(mf))
                    if "\r" not in text:      # the reader itself agrees with Ollama on the file as written
                        self.assertEqual(plan._ollama_parse(text, need_from=False), ollama_reads(text))
        self.assertGreater(accepted, 100)

    def test_without_export(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(plan, "EXPORTED_DIR", Path(d)):
            mf = plan.modelfile_text(m("q", "workhorse", 1), "pub/q:1", 16384, 8192)
        self.assertEqual(mf, "FROM pub/q:1\nPARAMETER num_ctx 16384\nPARAMETER num_predict 8192\n")

    def test_from_path_with_spaces_reads_back(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(plan, "EXPORTED_DIR", Path(d)):
            mf = plan.modelfile_text(m("q", "workhorse", 1), "/Users/a b/models/q/q.gguf", 16384, 8192)
        self.assertEqual(ollama_reads(mf)[0], ("model", "/Users/a b/models/q/q.gguf"))

    def test_filter_subcommand_drops_from(self):
        with tempfile.TemporaryDirectory() as d:
            raw, out = Path(d) / "x.raw", Path(d) / "x.Modelfile"
            raw.write_text("# Modelfile generated by \"ollama show\"\nFROM /Users/someone/.ollama/models/blobs/sha256-ab\n"
                           'TEMPLATE """{{ .Prompt }}"""\nPARAMETER num_ctx 8192\nPARAMETER temperature 0.6\n'
                           "CAPABILITY tools\n")
            with quiet():
                self.assertEqual(plan.main(["modelfile-filter", str(raw), str(out)]), 0)
            self.assertEqual(out.read_text(), 'TEMPLATE """{{ .Prompt }}"""\nPARAMETER temperature 0.6\n')
            for bad, why in (("FROM /x\nADAPTER /y\n", "ADAPTER isn't allowed"),
                             (f"SYSTEM hi\rFROM {EVIL}\n", "carriage return"),
                             ('PARAMETER stop """a\nLICENSE """"\nADAPTER /x\n#"""\n', "ADAPTER isn't allowed")):
                with open(raw, "w", encoding="utf-8", newline="") as f:
                    f.write(bad)
                err = io.StringIO()
                with self.subTest(bad=bad), contextlib.redirect_stderr(err):
                    self.assertEqual(plan.main(["modelfile-filter", str(raw), str(out)]), 2)
                    self.assertRegex(err.getvalue(), why)

    def test_filter_output_of_a_hidden_from_is_harmless(self):
        # In `ollama show` output the hidden FROM is a FROM to Ollama too: it is dropped, and what is
        # written reads back as the same single parameter.
        with tempfile.TemporaryDirectory() as d:
            raw, out = Path(d) / "x.raw", Path(d) / "x.Modelfile"
            raw.write_text(f'PARAMETER stop """a\nLICENSE """"\nFROM {EVIL}\n#"""\n')
            with quiet():
                self.assertEqual(plan.main(["modelfile-filter", str(raw), str(out)]), 0)
            self.assertEqual(ollama_reads(out.read_text()), [("stop", 'a\nLICENSE "')])
            (Path(d) / "link").symlink_to(out)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(plan.main(["modelfile-filter", str(raw), str(Path(d) / "link")]), 2)


FAKE_HF = """#!/bin/sh
# fake hf: hf download REPO FILE --revision R --local-dir D
# FAKE_HF_MODE: file (default), link (the file is a symlink), swapdir (D is replaced by a symlink), none
[ "$1" = download ] || exit 9
file="$3"; shift 3
while [ $# -gt 0 ]; do case "$1" in --local-dir) dir="$2"; shift ;; esac; shift; done
case "${FAKE_HF_MODE:-file}" in
  file) mkdir -p "$dir" && printf 'GGUF-test-weights' > "$dir/$file" ;;
  link) mkdir -p "$dir.other" && printf 'GGUF-test-weights' > "$dir.other/$file" && ln -s "$dir.other/$file" "$dir/$file" ;;
  swapdir) mkdir -p "$dir.other" && printf 'GGUF-test-weights' > "$dir.other/$file" && rm -rf "$dir" && ln -s "$dir.other" "$dir" ;;
  none) ;;
esac
"""


class TestHfFetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        hf = t / "bin" / "hf"
        hf.write_text(FAKE_HF)
        hf.chmod(0o755)
        self.models = t / "models"
        self.patches = [mock.patch.dict(os.environ, {"PATH": f"{t / 'bin'}:/usr/bin:/bin"}),
                        mock.patch.object(plan, "MODELS_DIR", self.models)]
        for pt in self.patches:
            pt.start()
        self.digest = hashlib.sha256(b"GGUF-test-weights").hexdigest()

    def tearDown(self):
        for pt in reversed(self.patches):
            pt.stop()
        self.tmp.cleanup()

    def model(self, **src):
        s = {"type": "hf", "repo": "org/repo", "file": "m.gguf", "revision": "a" * 40, "sha256": self.digest}
        s.update(src)
        return m("hfm", "workhorse", 1, source=s)

    def fetch(self, mode="file", **src):
        with quiet(), mock.patch.dict(os.environ, {"FAKE_HF_MODE": mode}):
            return plan.hf_fetch(self.model(**src), allow_unpinned=src.get("sha256", 1) is None)

    def test_verified_download(self):
        p = self.fetch()
        self.assertEqual(p, self.models / "hfm-abliterated" / "m.gguf")
        self.assertTrue(p.is_file())

    def test_models_dir_with_a_space(self):
        with mock.patch.object(plan, "MODELS_DIR", Path(self.tmp.name) / "my models"):
            self.assertTrue(self.fetch().is_file())

    def test_mismatch_deletes_file(self):
        with self.assertRaisesRegex(plan.PlanError, "sha256 mismatch"):
            self.fetch(sha256="0" * 64)
        self.assertFalse((self.models / "hfm-abliterated" / "m.gguf").exists())

    def test_revision_required(self):
        with self.assertRaisesRegex(plan.PlanError, "pinned commit"):
            plan.hf_fetch(self.model(revision=None), allow_unpinned=True)

    def test_unpinned_needs_flag(self):
        with self.assertRaisesRegex(plan.PlanError, "no sha256"):
            plan.hf_fetch(self.model(sha256=None), allow_unpinned=False)
        self.assertTrue(self.fetch(sha256=None).is_file())

    def test_needs_hf_cli(self):
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}), \
                self.assertRaisesRegex(plan.PlanError, r"\(hf\) not found"):
            plan.hf_fetch(self.model(), allow_unpinned=False)

    def test_symlinked_destination_refused(self):
        self.models.mkdir()
        target = Path(self.tmp.name) / "elsewhere"
        target.mkdir()
        (self.models / "hfm-abliterated").symlink_to(target)
        with self.assertRaisesRegex(plan.PlanError, "hfm-abliterated is a symlink; refusing"):
            self.fetch()
        self.assertEqual(list(target.iterdir()), [])

    def test_symlinked_models_dir_refused(self):
        target = Path(self.tmp.name) / "elsewhere"
        target.mkdir()
        self.models.symlink_to(target)
        with self.assertRaisesRegex(plan.PlanError, "models is a symlink; refusing"):
            self.fetch()
        self.assertEqual(list(target.iterdir()), [])

    def test_download_must_be_a_plain_file_in_place(self):
        for mode in ("link", "swapdir", "none"):
            shutil.rmtree(self.models, ignore_errors=True)
            with self.subTest(mode=mode), self.assertRaisesRegex(plan.PlanError, "did not produce .* as a plain file"):
                self.fetch(mode)

    def test_odd_models_dir_refused(self):
        with mock.patch.object(plan, "MODELS_DIR", Path(self.tmp.name) / 'my"models'), \
                self.assertRaisesRegex(plan.PlanError, "characters Ollama's Modelfile can't take"):
            plan.hf_fetch(self.model(), allow_unpinned=False)


class FakeOllama:
    """Ollama's model store faked on disk, so the real verification code (manifest resolution and
    checks, /api/tags digests, fingerprints) runs unchanged. layout "legacy": manifests/registry.ollama.ai/
    <ns>/<model>/<tag> files (Ollama before 0.40). "v2": manifests-v2/ollama.com/... links to the manifest
    blob, the legacy file removed (Ollama 0.40 and later). Like Ollama's create, create reads its Modelfile
    with Ollama's parser (the last FROM wins), pulls a base it doesn't have, and builds a ':cloud' FROM as a
    remote model with no weight layers; a remote base gives a build without weights (create.go copies
    the layers, never remote_host)."""
    TEMPLATE = ("application/vnd.ollama.image.template", "sha256:" + "7" * 64)

    def __init__(self, root, layout="legacy"):
        self.root, self.layout, self.calls, self.hub, self.remote = Path(root), layout, [], {}, set()
        self.list_fails = False
        self.before_create = None        # callback(base): runs as create starts (a tag moving meanwhile)
        self.remote_builds = set()       # names whose create comes out remote (an Ollama that does that)

    @staticmethod
    def split(name):
        n, tag = (name.rsplit(":", 1) if ":" in name.rsplit("/", 1)[-1] else (name, "latest"))
        return (n.split("/") if "/" in n else ["library", n]) + [tag]

    def legacy_path(self, name):
        return self.root.joinpath("manifests", "registry.ollama.ai", *self.split(name))

    def v2_path(self, name):
        return self.root.joinpath("manifests-v2", "ollama.com", *self.split(name))

    def path(self, name):
        return self.v2_path(name) if self.layout == "v2" else self.legacy_path(name)

    def blob(self, data):
        d = hashlib.sha256(data).hexdigest()
        (self.root / "blobs").mkdir(parents=True, exist_ok=True)
        (self.root / "blobs" / ("sha256-" + d)).write_bytes(data)
        return d

    def store(self, name, data):
        """Manifest bytes under name, the way this layout keeps them."""
        if self.layout == "v2":
            link = self.v2_path(name)
            link.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(link):
                link.unlink()
            link.symlink_to(os.path.relpath(self.root / "blobs" / ("sha256-" + self.blob(data)), link.parent))
            if os.path.lexists(self.legacy_path(name)):
                self.legacy_path(name).unlink()
        else:
            p = self.legacy_path(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    def write(self, name, layers, remote=False, names=None):
        cfg = json.dumps({"remote_host": "https://ollama.com:443", "remote_model": name} if remote
                         else {"model_format": "gguf", "model_family": "fake"}).encode()
        man = {"schemaVersion": 2, "mediaType": plan.MT_MANIFEST,
               "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
                          "digest": "sha256:" + self.blob(cfg), "size": len(cfg)},
               "layers": [dict({"mediaType": mt, "digest": d, "size": 1}, **({"name": names[i]} if names else {}))
                          for i, (mt, d) in enumerate(layers)]}
        self.store(name, json.dumps(man).encode())

    def layers(self, name):
        man = json.loads(self.path(name).read_bytes())
        return [(x["mediaType"], x["digest"]) for x in man["layers"]]

    def tags(self):
        """/api/tags: every entry of manifests-v2, then of manifests not listed already (a v2 entry
        shadows the legacy one even when it can't be read, as in manifest.namedManifestRefs)."""
        if self.list_fails:
            raise plan.PlanError("couldn't list Ollama's models")
        out, seen = {}, set()
        for tree in ("manifests-v2", "manifests"):
            for f in sorted((self.root / tree).glob("*/*/*/*")):
                ns, model, tag = f.parts[-3:]
                name = (model if ns == "library" else f"{ns}/{model}") + ":" + tag
                if name in seen or f.is_dir():
                    continue
                seen.add(name)
                try:
                    out[name] = hashlib.sha256(f.read_bytes()).hexdigest()
                except OSError:
                    continue
        for name in [k for k in out if k.endswith(":latest")]:
            out[name[:-7]] = out[name]
        return out

    def pull(self, name):
        if name in self.remote:
            self.write(name, [self.TEMPLATE], remote=True)
        else:
            self.write(name, self.hub[name] + [self.TEMPLATE])

    def run_cmd(self, cmd):
        self.calls.append(cmd)
        if os.path.basename(cmd[0]) == "hf":
            subprocess.run(cmd, check=True)
        elif cmd[1] == "pull":
            self.pull(cmd[2])
        elif cmd[1] == "create":
            read = ollama_reads(Path(cmd[4]).read_text(encoding="utf-8"))
            if read is None:
                raise plan.PlanError("command failed: ollama create: Ollama can't parse the Modelfile")
            base = [a for n, a in read if n == "model"][-1]       # CreateRequest: the last FROM wins
            if self.before_create:
                self.before_create(base)
            if base.rsplit(":", 1)[-1].lower() == "cloud" or base.lower().endswith("-cloud") \
                    or cmd[2] in self.remote_builds:
                self.write(cmd[2], [self.TEMPLATE], remote=True)
                return
            if base.startswith("/"):
                layers = [(plan.MT_MODEL, "sha256:" + hashlib.sha256(Path(base).read_bytes()).hexdigest())]
            else:
                if not self.path(base).exists():
                    self.pull(base)
                layers = [x for x in self.layers(base) if x[0] not in plan.META_LAYERS]
            self.write(cmd[2], layers + [self.TEMPLATE])
        elif cmd[1] == "cp":
            self.store(cmd[3], self.path(cmd[2]).read_bytes())

    def run(self, cmd, timeout=10):
        if cmd[1:2] == ["rm"]:
            self.calls.append(cmd)
            for p in (self.v2_path(cmd[2]), self.legacy_path(cmd[2])):
                if os.path.lexists(p):
                    p.unlink()
            return "deleted"
        return ""


class TestInstallModels(unittest.TestCase):
    """cmd_install_models against a fake Ollama store: pins, temp alias + swap, tools, drift.
    TestInstallModelsV2 runs the same tests against Ollama 0.40's manifests-v2 layout."""
    W, A = "gpt-oss-20b", "gemma4-26b"           # Ollama-library sources
    WA, AA = "gpt-oss-20b-abliterated", "gemma4-26b-abliterated"
    LAYOUT = "legacy"

    def setUp(self):
        reset_secops()
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.catalog = copy.deepcopy(plan.load_catalog())
        self.by_id = {x["id"]: x for x in self.catalog}
        self.ol = FakeOllama(t / "ollama", self.LAYOUT)
        self.wref, self.aref = self.by_id[self.W]["source"]["ref"], self.by_id[self.A]["source"]["ref"]
        self.ol.hub = {self.wref: [(plan.MT_MODEL, "sha256:" + "1" * 64)],
                       self.aref: [(plan.MT_MODEL, "sha256:" + "2" * 64),
                                   ("application/vnd.ollama.image.projector", "sha256:" + "3" * 64)],
                       "nomic-embed-text": [(plan.MT_MODEL, "sha256:" + "4" * 64)]}
        self.caps = {}
        self.patches = [
            mock.patch.object(plan, "OLLAMA_MODELS", t / "ollama"),
            mock.patch.object(plan, "load_catalog", lambda path=None: copy.deepcopy(self.catalog)),
            mock.patch.object(plan, "ollama_bin", lambda: "ollama"),
            mock.patch.object(plan, "ollama_up", lambda: True),
            mock.patch.object(plan, "ollama_tags", self.ol.tags),
            mock.patch.object(plan, "run_cmd", self.ol.run_cmd),
            mock.patch.object(plan, "_run", self.ol.run),
            mock.patch.object(plan, "model_capabilities", lambda a: self.caps.get(a, {"completion", "tools"})),
            mock.patch.object(plan, "MODELS_DIR", t / "models"),
        ]
        for pt in self.patches:
            pt.start()

    def tearDown(self):
        for pt in reversed(self.patches):
            pt.stop()
        self.tmp.cleanup()
        reset_secops()

    def select(self, *ids):
        p = plan.compute_plan(mac(48, disk=600))
        roles = plan.assign_roles([self.by_id[i] for i in (ids or (self.W, self.A))])
        with quiet():
            plan.write_outputs(mac(48), p, roles, plan.embed_model(self.catalog))

    def install(self, force=False):
        args = argparse.Namespace(force=force, keep_gguf=False, allow_unpinned=False)
        with quiet():
            return plan.cmd_install_models(args)

    def fingerprint(self, ref):
        return plan.weights_fingerprint([(mt, d[7:]) for mt, d in self.ol.hub[ref]])

    def verbs(self):
        return [c[1] if c[0] == "ollama" else os.path.basename(c[0]) for c in self.ol.calls]

    def test_fresh_install_uses_a_temp_alias(self):
        self.select()
        self.assertEqual(self.install(), 0)
        tmp = plan._tmp_alias(self.WA)
        self.assertIn(["ollama", "pull", self.wref], self.ol.calls)
        self.assertIn(["ollama", "cp", tmp, self.WA], self.ol.calls)
        self.assertIn(["ollama", "rm", tmp], self.ol.calls)
        self.assertFalse(self.ol.path(tmp).exists())
        self.assertEqual(plan.installed_weights(self.AA), self.fingerprint(self.aref))   # model + projector
        sel = json.loads(plan.SELECTED.read_text())
        self.assertEqual(sel["installed"][self.WA]["digest"], self.ol.tags()[self.WA])

    def test_pinned_weights_verified(self):
        self.by_id[self.W]["weights_sha256"] = self.fingerprint(self.wref)
        self.by_id[self.A]["weights_sha256"] = self.fingerprint(self.aref)
        self.select()
        self.assertEqual(self.install(), 0)

    def test_hub_serving_other_weights_is_refused_before_create(self):
        self.by_id[self.W]["weights_sha256"] = "a" * 64
        self.select()
        with self.assertRaisesRegex(plan.PlanError, f"{self.wref} now serves weights"):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())
        self.assertNotIn(["ollama", "create", plan._tmp_alias(self.WA), "-f"],
                         [c[:4] for c in self.ol.calls], "nothing is built from weights that failed the check")

    def test_extra_layer_breaks_the_pin(self):
        self.by_id[self.W]["weights_sha256"] = self.fingerprint(self.wref)
        self.select()
        self.ol.hub[self.wref] = self.ol.hub[self.wref] + [("application/vnd.ollama.image.adapter", "sha256:" + "9" * 64)]
        with self.assertRaises(plan.PlanError):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())

    def test_force_never_replaces_a_working_alias_with_unverified_weights(self):
        good = self.fingerprint(self.wref)
        self.by_id[self.W]["weights_sha256"] = good
        self.select()
        self.ol.write(self.WA, self.ol.hub[self.wref] + [FakeOllama.TEMPLATE])
        before = self.ol.path(self.WA).read_bytes()
        self.ol.hub[self.wref] = [(plan.MT_MODEL, "sha256:" + "8" * 64)]        # the tag was re-pushed
        with self.assertRaises(plan.PlanError):
            self.install(force=True)
        self.assertEqual(self.ol.path(self.WA).read_bytes(), before)

    def test_existing_alias_with_other_weights_fails_without_touching_it(self):
        self.by_id[self.W]["weights_sha256"] = "a" * 64
        self.select()
        self.ol.write(self.WA, self.ol.hub[self.wref])
        self.ol.write(self.AA, self.ol.hub[self.aref])
        self.ol.write("nomic-embed-text", self.ol.hub["nomic-embed-text"])
        with self.assertRaises(plan.PlanError):
            self.install()
        self.assertEqual(self.verbs(), [])

    def test_existing_aliases_verified_and_left_alone(self):
        self.by_id[self.W]["weights_sha256"] = self.fingerprint(self.wref)
        self.select()
        for name, ref in ((self.WA, self.wref), (self.AA, self.aref), ("nomic-embed-text", "nomic-embed-text")):
            self.ol.write(name, self.ol.hub[ref])
        self.assertEqual(self.install(), 0)
        self.assertEqual(self.verbs(), [])

    def test_unreadable_manifest_fails_a_pinned_model(self):
        self.by_id[self.W]["weights_sha256"] = self.fingerprint(self.wref)
        self.select()
        self.ol.write(self.WA, self.ol.hub[self.wref])
        listed = {**self.ol.tags(), self.WA + ":latest": "f" * 64, self.WA: "f" * 64}   # not what's on disk
        with mock.patch.object(plan, "ollama_tags", lambda: listed):
            with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: installed, but its manifest can't be read"):
                self.install()

    def test_remote_hub_model_refused(self):
        # A remote model has a remote_host config and no weight layers; a build from it has no weights.
        self.select()
        self.ol.remote.add(self.wref)
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: refused the new build: its manifest can't be read"):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())
        self.assertNotIn(["ollama", "cp", plan._tmp_alias(self.WA), self.WA], self.ol.calls)

    def test_build_that_comes_out_remote_is_refused_unpinned(self):
        self.select()
        self.ol.remote_builds.add(plan._tmp_alias(self.WA))
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: refused the new build: it runs on a remote host"):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())
        self.assertNotIn(["ollama", "cp", plan._tmp_alias(self.WA), self.WA], self.ol.calls)

    def test_installed_remote_alias_refused(self):
        self.select()
        self.ol.write(self.WA, [FakeOllama.TEMPLATE], remote=True)
        before = self.ol.path(self.WA).read_bytes()
        self.ol.write(self.AA, self.ol.hub[self.aref])
        self.ol.write("nomic-embed-text", self.ol.hub["nomic-embed-text"])
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: installed, but it runs on a remote host"):
            self.install()
        self.assertEqual(self.ol.path(self.WA).read_bytes(), before)
        self.assertEqual(self.verbs(), [])

    def test_tag_moving_between_pull_and_create_is_caught(self):
        good = self.fingerprint(self.wref)
        self.by_id[self.W]["weights_sha256"] = good
        self.select()

        def moved(base):          # another pull lands after the pre-create check passed
            if base == self.wref:
                self.ol.write(self.wref, [(plan.MT_MODEL, "sha256:" + "6" * 64), FakeOllama.TEMPLATE])
        self.ol.before_create = moved
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: refused the new build: its weights 666666666666"):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())
        self.assertNotIn(["ollama", "cp", plan._tmp_alias(self.WA), self.WA], self.ol.calls)

    def test_exported_modelfile_cannot_redirect_the_build(self):
        exported = Path(self.tmp.name) / "exported"
        exported.mkdir()
        (exported / f"{self.WA}.Modelfile").write_text(f'PARAMETER stop """a\nLICENSE """"\nFROM {EVIL}\n#"""\n')
        self.ol.hub[EVIL] = [(plan.MT_MODEL, "sha256:" + "e" * 64)]
        self.select()
        with mock.patch.object(plan, "EXPORTED_DIR", exported), \
                self.assertRaisesRegex(plan.PlanError, "FROM isn't allowed"):
            self.install()
        self.assertFalse(self.ol.path(EVIL).exists(), "the attacker's model was never fetched")
        self.assertFalse(self.ol.path(self.WA).exists())

    def test_embed_model_is_verified_and_restored(self):
        emb = self.by_id["nomic-embed"]
        good = self.fingerprint("nomic-embed-text")
        emb["weights_sha256"] = good
        self.select()
        self.ol.write("nomic-embed-text", self.ol.hub["nomic-embed-text"])
        before = self.ol.path("nomic-embed-text").read_bytes()
        self.ol.hub["nomic-embed-text"] = [(plan.MT_MODEL, "sha256:" + "5" * 64)]     # the tag moved
        with self.assertRaisesRegex(plan.PlanError, "nomic-embed-text: refused the pulled model: its weights "
                                                    "555555555555 are not the catalog's pinned .*; the previous one "
                                                    "was put back"):
            self.install(force=True)
        self.assertEqual(self.ol.path("nomic-embed-text").read_bytes(), before)
        self.assertFalse(os.path.lexists(self.ol.path(plan._tmp_alias("nomic-embed-text"))))

    def test_embed_copy_kept_when_the_check_cannot_run(self):
        self.select()
        self.ol.write("nomic-embed-text", self.ol.hub["nomic-embed-text"])
        real = plan._weights_and_digest

        def flaky(name, tags=None):     # Ollama stops answering right after the embedding model's pull
            if name == "nomic-embed-text":
                raise plan.PlanError("couldn't list Ollama's models")
            return real(name, tags)
        with mock.patch.object(plan, "_weights_and_digest", flaky), \
                self.assertRaisesRegex(plan.PlanError, "couldn't list"):
            self.install(force=True)
        self.assertTrue(self.ol.path(plan._tmp_alias("nomic-embed-text")).exists(), "the previous copy is kept")

    def test_embed_model_failing_its_check_is_not_left_installed(self):
        self.by_id["nomic-embed"]["weights_sha256"] = "a" * 64
        self.select()
        with self.assertRaisesRegex(plan.PlanError, "nomic-embed-text: refused the pulled model: .*; it was removed"):
            self.install()
        self.assertFalse(self.ol.path("nomic-embed-text").exists())
        self.ol.remote.add("nomic-embed-text")
        del self.by_id["nomic-embed"]["weights_sha256"]
        self.select()
        with self.assertRaisesRegex(plan.PlanError, "nomic-embed-text: refused the pulled model: it runs on a remote"):
            self.install()

    def test_embed_model_pin_verified_when_installed(self):
        self.by_id["nomic-embed"]["weights_sha256"] = "a" * 64
        self.select()
        self.ol.write("nomic-embed-text", self.ol.hub["nomic-embed-text"])
        with self.assertRaisesRegex(plan.PlanError, "nomic-embed-text: installed, but its weights"):
            self.install()

    def test_build_swapped_between_its_check_and_the_copy_is_refused(self):
        self.by_id[self.W]["weights_sha256"] = self.fingerprint(self.wref)
        self.select()
        tmp = plan._tmp_alias(self.WA)

        def caps(name):           # runs after the check, before `ollama cp`: something swaps the build
            if name == tmp:
                self.ol.write(tmp, [(plan.MT_MODEL, "sha256:" + "e" * 64), FakeOllama.TEMPLATE])
            return {"completion", "tools"}
        with mock.patch.object(plan, "model_capabilities", caps), \
                self.assertRaisesRegex(plan.PlanError, f"{self.WA}: what was copied into place \\(eeeeeeeeeeee\\) "
                                                       "isn't the build that passed its checks; it was removed"):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())
        self.assertNotIn(self.WA, json.loads(plan.SELECTED.read_text()).get("installed", {}))

    def test_alias_changed_later_in_the_run_is_reported_not_recorded(self):
        self.select()

        def swap(base):           # while the next model builds, something replaces the verified alias
            if base == self.aref:
                self.ol.write(self.WA, [(plan.MT_MODEL, "sha256:" + "e" * 64), FakeOllama.TEMPLATE])
        self.ol.before_create = swap
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: changed after its check in this run"):
            self.install()
        installed = json.loads(plan.SELECTED.read_text())["installed"]
        self.assertNotIn(self.WA, installed)
        self.assertEqual(installed[self.AA]["digest"], self.ol.tags()[self.AA])   # the others are recorded

    def test_nothing_recorded_when_ollama_stops_answering(self):
        self.select()
        for name, ref in ((self.WA, self.wref), (self.AA, self.aref), ("nomic-embed-text", "nomic-embed-text")):
            self.ol.write(name, self.ol.hub[ref])
        first = [True]

        def tags():
            if first.pop() if first else False:
                return self.ol.tags()
            raise plan.PlanError("couldn't list Ollama's models")
        with mock.patch.object(plan, "ollama_tags", tags), \
                self.assertRaisesRegex(plan.PlanError, "nothing recorded: couldn't list"):
            self.install()
        self.assertNotIn("installed", json.loads(plan.SELECTED.read_text()))

    def test_embed_backup_from_an_earlier_run_is_never_overwritten(self):
        self.by_id["nomic-embed"]["weights_sha256"] = self.fingerprint("nomic-embed-text")
        self.select()
        tmp = plan._tmp_alias("nomic-embed-text")
        self.ol.write(tmp, self.ol.hub["nomic-embed-text"])                       # the good copy, kept earlier
        self.ol.write("nomic-embed-text", [(plan.MT_MODEL, "sha256:" + "5" * 64)])   # a bad pull in place
        kept = self.ol.path(tmp).read_bytes()
        with self.assertRaisesRegex(plan.PlanError, f"An earlier run kept the previous one as {tmp}: put it back "
                                                    f"\\(ollama cp {tmp} nomic-embed-text\\)"):
            self.install()
        self.ol.calls.clear()
        with self.assertRaisesRegex(plan.PlanError, f"kept a copy of it as {tmp}; put it back .* It is not overwritten"):
            self.install(force=True)
        self.assertEqual(self.ol.path(tmp).read_bytes(), kept)
        self.assertFalse([c for c in self.ol.calls if "nomic-embed-text" in c], "nothing touched the embedding model")

    def test_failed_check_keeps_the_previous_record(self):
        self.by_id[self.W]["weights_sha256"] = self.fingerprint(self.wref)
        self.select()
        self.assertEqual(self.install(), 0)
        recorded = json.loads(plan.SELECTED.read_text())["installed"][self.WA]
        self.ol.write(self.WA, [(plan.MT_MODEL, "sha256:" + "9" * 64), FakeOllama.TEMPLATE])   # replaced later
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: installed, but its weights 999999999999"):
            self.install()
        self.assertEqual(json.loads(plan.SELECTED.read_text())["installed"][self.WA], recorded)
        self.assertNotEqual(self.ol.tags()[self.WA], recorded["digest"], "secstack audit still sees the change")

    def test_unpinned_model_changed_since_the_last_install_is_refused(self):
        # Trust on first use: an unpinned alias whose manifest changed after the recorded install (here only its
        # system prompt; the weights are the same) fails its check, and the record keeps the last good digest
        # so `secstack audit` keeps reporting it. Only --force (re-create from the catalog) records a new one.
        self.select()
        self.assertEqual(self.install(), 0)
        recorded = json.loads(plan.SELECTED.read_text())["installed"][self.WA]
        swapped = list(self.ol.hub[self.wref]) + [("application/vnd.ollama.image.system", "sha256:" + "8" * 64)]
        self.ol.write(self.WA, swapped)
        self.assertEqual(plan.installed_weights(self.WA), self.fingerprint(self.wref), "same weights")
        with self.assertRaisesRegex(plan.PlanError, f"{self.WA}: installed, but its manifest changed since the last "
                                                    f"recorded install \\({recorded['digest'][:12]} -> "):
            self.install()
        self.assertEqual(json.loads(plan.SELECTED.read_text())["installed"][self.WA], recorded)
        self.assertEqual(self.install(force=True), 0)                              # re-created and recorded anew
        self.assertEqual(json.loads(plan.SELECTED.read_text())["installed"][self.WA]["digest"], self.ol.tags()[self.WA])

    def test_hf_import_verified_end_to_end(self):
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        (t / "bin" / "hf").write_text(FAKE_HF)
        (t / "bin" / "hf").chmod(0o755)
        q = self.by_id["qwen3.6-35b-moe"]
        q["source"]["sha256"] = hashlib.sha256(b"GGUF-test-weights").hexdigest()
        self.select("qwen3.6-35b-moe")
        with mock.patch.dict(os.environ, {"PATH": f"{t / 'bin'}:/usr/bin:/bin"}):
            self.assertEqual(self.install(), 0)
        self.assertEqual(plan.installed_weights(q["alias"]), q["source"]["sha256"])
        self.assertFalse((t / "models" / q["alias"] / q["source"]["file"]).exists(), "GGUF removed after import")

    def test_primary_without_tools_is_not_installed(self):
        self.select()
        self.caps[plan._tmp_alias(self.WA)] = {"completion"}
        with self.assertRaises(plan.PlanError):
            self.install()
        self.assertFalse(self.ol.path(self.WA).exists())

    def test_ollama_list_failure_stops_before_anything(self):
        self.select()
        self.ol.list_fails = True
        with self.assertRaises(plan.PlanError):
            self.install()
        self.assertEqual(self.ol.calls, [])

    def test_stale_selection_refused(self):
        self.select()
        self.by_id[self.W]["source"] = {"type": "ollama", "ref": "someone/else:1"}
        with self.assertRaises(plan.PlanError):
            self.install()
        self.assertEqual(self.ol.calls, [])

    def test_tampered_selection_refused(self):
        self.select()
        sel = json.loads(plan.SELECTED.read_text())
        sel["models"][0]["source"]["ref"] = "-rf"
        plan.SELECTED.write_text(json.dumps(sel))
        with self.assertRaises(plan.PlanError):
            self.install()
        self.assertEqual(self.ol.calls, [])

    def test_context_bounds_from_the_selection_file(self):
        self.select()
        sel = json.loads(plan.SELECTED.read_text())
        for ctx, mt in ((10 ** 9, 16384), (32768, -5), (32768, 99999), ("32768", 16384)):
            sel["plan"]["ctx"], sel["plan"]["max_tokens"] = ctx, mt
            plan.SELECTED.write_text(json.dumps(sel))
            with self.subTest(ctx=ctx, max_tokens=mt), self.assertRaises(plan.PlanError):
                self.install()
        self.assertEqual(self.ol.calls, [])

    def test_no_selection(self):
        with self.assertRaises(plan.PlanError):
            self.install()


class TestInstallModelsV2(TestInstallModels):
    LAYOUT = "v2"


class TestPinWeights(unittest.TestCase):
    LAYOUT = "legacy"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        shutil.copy(plan.CATALOG_PATH, t / "catalog.json")
        self.ol = FakeOllama(t / "ollama", self.LAYOUT)
        cat = {x["id"]: x for x in plan.load_catalog()}
        self.alias, self.ref = cat["gpt-oss-20b"]["alias"], cat["gpt-oss-20b"]["source"]["ref"]
        self.layers = [(plan.MT_MODEL, "sha256:" + "1" * 64)]
        self.patches = [mock.patch.object(plan, "OLLAMA_MODELS", t / "ollama"),
                        mock.patch.object(plan, "CATALOG_PATH", t / "catalog.json"),
                        mock.patch.object(plan, "ollama_up", lambda: True),
                        mock.patch.object(plan, "ollama_tags", self.ol.tags)]
        for pt in self.patches:
            pt.start()

    def tearDown(self):
        for pt in reversed(self.patches):
            pt.stop()
        self.tmp.cleanup()

    def pins(self):
        return {x["alias"]: x.get("weights_sha256") for x in json.loads(plan.CATALOG_PATH.read_text())["models"]}

    def test_pins_only_aliases_matching_their_source(self):
        self.ol.write(self.ref, self.layers)
        self.ol.write(self.alias, self.layers)
        with quiet():
            plan.cmd_pin_weights(argparse.Namespace(write=True))
        self.assertEqual(self.pins()[self.alias], "1" * 64)
        self.assertEqual(plan.validate_catalog(json.loads(plan.CATALOG_PATH.read_text())["models"]), [])

    def test_alias_differing_from_source_is_not_pinned(self):
        self.ol.write(self.ref, self.layers)
        self.ol.write(self.alias, [(plan.MT_MODEL, "sha256:" + "5" * 64)])
        with quiet() as out:
            plan.cmd_pin_weights(argparse.Namespace(write=True))
        self.assertIsNone(self.pins()[self.alias])
        self.assertIn("differ from", out.getvalue())

    def test_without_write_nothing_changes(self):
        before = plan.CATALOG_PATH.read_bytes()
        self.ol.write(self.ref, self.layers)
        self.ol.write(self.alias, self.layers)
        with quiet():
            plan.cmd_pin_weights(argparse.Namespace(write=False))
        self.assertEqual(plan.CATALOG_PATH.read_bytes(), before)

    def test_embedding_model_is_pinned(self):
        self.ol.write("nomic-embed-text", self.layers)
        with quiet():
            plan.cmd_pin_weights(argparse.Namespace(write=True))
        self.assertEqual(self.pins()["nomic-embed-text"], "1" * 64)

    def test_remote_alias_not_pinned(self):
        self.ol.write(self.ref, [FakeOllama.TEMPLATE], remote=True)
        self.ol.write(self.alias, [FakeOllama.TEMPLATE], remote=True)
        with quiet() as out:
            plan.cmd_pin_weights(argparse.Namespace(write=True))
        self.assertIsNone(self.pins()[self.alias])
        self.assertIn(f"{self.alias}: runs on a remote host", out.getvalue())


class TestPinWeightsV2(TestPinWeights):
    LAYOUT = "v2"


class TestManifestStore(unittest.TestCase):
    """installed_weights reads a manifest the way Ollama resolves and checks it (TestManifestStoreV2: the
    Ollama 0.40 manifests-v2 layout), never trusting what Python and Go would read differently."""
    LAYOUT = "legacy"
    W = [(plan.MT_MODEL, "sha256:" + "1" * 64)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ol = FakeOllama(Path(self.tmp.name) / "ollama", self.LAYOUT)
        pt = mock.patch.object(plan, "OLLAMA_MODELS", self.ol.root)
        pt.start()
        self.addCleanup(pt.stop)

    def weights(self, name="m", tags=True):
        return plan.installed_weights(name, self.ol.tags() if tags else None)

    def manifest(self, man, name="m", config=b'{"model_format":"gguf"}'):
        """Store a manifest (a dict, with a config blob added, or raw bytes) under name."""
        if isinstance(man, dict):
            man = dict(man, config={"digest": "sha256:" + self.ol.blob(config)}) if config is not None else man
            man = json.dumps(man).encode()
        self.ol.store(name, man)

    def test_reads_this_layout(self):
        self.ol.write("m", self.W + [FakeOllama.TEMPLATE])
        self.ol.write("pub/x:tag", self.W + [("application/vnd.ollama.image.projector", "sha256:" + "3" * 64)])
        self.assertEqual(self.weights(), "1" * 64)
        self.assertEqual(self.weights("pub/x:tag"), plan.weights_fingerprint(
            [(plan.MT_MODEL, "1" * 64), ("application/vnd.ollama.image.projector", "3" * 64)]))
        legacy_com = self.ol.root.joinpath("manifests", "ollama.com", "library", "c", "latest")
        legacy_com.parent.mkdir(parents=True)
        legacy_com.write_bytes(self.ol.path("m").read_bytes())       # Ollama 0.40's second legacy host
        self.assertEqual(plan.installed_weights("c"), "1" * 64)

    def test_must_be_the_manifest_ollama_lists(self):
        self.ol.write("m", self.W)
        d = self.ol.tags()["m:latest"]
        self.assertIsNone(plan.installed_weights("m", {}))
        self.assertIsNone(plan.installed_weights("m", {"m:latest": "f" * 64}))
        self.assertEqual(plan.installed_weights("m", {"M:latest": d}), "1" * 64)              # case: APFS
        self.assertIsNone(plan.installed_weights("m", {"M:latest": d, "M:Latest": d}))         # ambiguous
        self.assertEqual(plan.installed_weights("m", {"m:latest": frozenset((d, "f" * 64))}), "1" * 64)

    def test_remote_config_is_read_before_the_layers(self):
        self.ol.write("m", [FakeOllama.TEMPLATE], remote=True)
        self.assertEqual(self.weights(), "remote")
        for cfg in (b'{"Remote_Host": "https://x.example"}', b'{"REMOTE_MODEL": "x"}'):
            with self.subTest(cfg=cfg):
                self.manifest({"layers": [{"mediaType": plan.MT_MODEL, "digest": self.W[0][1]}]}, config=cfg)
                self.assertEqual(self.weights(), "remote")

    def test_config_must_be_readable(self):
        layers = {"layers": [{"mediaType": plan.MT_MODEL, "digest": self.W[0][1]}]}
        for cfg in (b'{"remote_host": "https://x"} trailing', b'{"remote_host": "", "Remote_Host": "https://x"}',
                    b"not json", b'["a list"]'):
            with self.subTest(cfg=cfg):
                self.manifest(layers, config=cfg)
                self.assertIsNone(self.weights())
        self.manifest(dict(layers, config={"digest": "sha256:" + "9" * 64}), config=None)     # missing blob
        self.assertIsNone(self.weights())
        cfg = self.ol.blob(b"{}")
        (self.ol.root / "blobs" / ("sha256-" + cfg)).write_bytes(b'{"remote_host": "https://x"}')  # swapped
        self.manifest(dict(layers, config={"digest": "sha256:" + cfg}), config=None)
        self.assertIsNone(self.weights())

    def test_json_go_reads_differently_is_refused(self):
        evil = "sha256:" + "e" * 64
        template = "application/vnd.ollama.image.template"
        for layer in ({"mediaType": template, "MediaType": plan.MT_MODEL, "digest": evil},
                      {"mediaType": plan.MT_MODEL, "digest": self.W[0][1], "dige\u017ft": evil},
                      {"mediaType": "application/vnd.ollama.image.model x", "digest": evil},
                      {"mediaType": plan.MT_MODEL, "digest": evil.upper()}):
            with self.subTest(layer=layer):
                self.manifest({"layers": [{"mediaType": plan.MT_MODEL, "digest": self.W[0][1]}, layer]})
                self.assertIsNone(self.weights())
        self.manifest(b'{"layers": [{"mediaType": "%s", "digest": "%s", "size": NaN}]}'
                      % (plan.MT_MODEL.encode(), self.W[0][1].encode()))
        self.assertIsNone(self.weights())
        self.manifest({"layers": {"not": "a list"}})
        self.assertIsNone(self.weights())

    def test_tensor_names_are_part_of_the_weights(self):
        t = "application/vnd.ollama.image.tensor"
        self.ol.write("a", [(t, "sha256:" + "1" * 64), (t, "sha256:" + "2" * 64)], names=["q_proj", "k_proj"])
        self.ol.write("b", [(t, "sha256:" + "1" * 64), (t, "sha256:" + "2" * 64)], names=["k_proj", "q_proj"])
        self.assertNotEqual(self.weights("a"), self.weights("b"))
        # layers without names keep the earlier fingerprint, so existing pins still hold
        rows = [(plan.MT_MODEL, "1" * 64), ("application/vnd.ollama.image.projector", "3" * 64)]
        self.assertEqual(plan.weights_fingerprint(rows), hashlib.sha256(
            "\n".join(f"{mt} {d}" for mt, d in sorted(rows)).encode()).hexdigest())

    def child(self, ch):
        cfg = self.ol.blob(b'{"model_format":"gguf"}')
        man = {"schemaVersion": 2, "mediaType": plan.MT_MANIFEST, "config": {"digest": "sha256:" + cfg},
               "layers": [{"mediaType": plan.MT_MODEL, "digest": "sha256:" + ch * 64, "size": 1}]}
        return self.ol.blob(json.dumps(man).encode())

    def test_manifest_list_child_ollama_runs(self):
        mlx, ggml = self.child("a"), self.child("b")
        entries = [{"mediaType": plan.MT_MANIFEST, "digest": "sha256:" + mlx, "runner": " MLX"},
                   {"mediaType": plan.MT_MANIFEST, "digest": "sha256:" + ggml, "runner": "ggml"}]
        self.manifest({"schemaVersion": 2, "mediaType": plan.MT_MANIFEST_LIST, "manifests": entries}, config=None)
        self.assertEqual(plan.installed_weights("m", {"m:latest": mlx}), "a" * 64)    # Apple Silicon: mlx first
        self.assertIsNone(plan.installed_weights("m", {"m:latest": ggml}))           # not the child it lists
        (self.ol.root / "blobs" / ("sha256-" + mlx)).unlink()                          # mlx child not pulled
        self.assertEqual(plan.installed_weights("m", {"m:latest": frozenset((ggml, mlx))}), "b" * 64)
        for bad in ([dict(entries[1], layers=[{"mediaType": plan.MT_MODEL, "digest": "sha256:" + "c" * 64}])],
                    [dict(entries[1], mediaType=plan.MT_MANIFEST_LIST)],
                    [dict(entries[1], runner="cuda")]):
            with self.subTest(bad=bad):
                self.manifest({"mediaType": plan.MT_MANIFEST_LIST, "manifests": bad}, config=None)
                self.assertIsNone(plan.installed_weights("m"))

    def test_names_ollama_reads_as_something_else(self):
        # Even with a manifest stored under the name: Ollama reads these as a cloud model, another
        # model (:local) or a local blob digest, so this manifest isn't what it would use.
        for name in ("m:cloud", "m:20b-cloud", "m:LOCAL", "deadbeef0123", "sha256-deadbeef0123", "m",
                     "pub/deadbeef0123", "mlx:0123456789abcdef", "ggml:" + "a" * 64, "sha256:" + "b" * 64):
            self.ol.write(name, self.W)
        for name in ("m:cloud", "m:20b-cloud", "m:LOCAL", "deadbeef0123", "sha256-deadbeef0123", "../m",
                     "a/b/m", "m:", "/m", "library/m:..", "m:latest/x", "mlx:0123456789abcdef",
                     "ggml:" + "a" * 64, "sha256:" + "b" * 64, "library/deadbeef0123", "library/DeadBeef0123:latest"):
            with self.subTest(name=name):
                self.assertIsNone(plan._manifest_file(name))
        self.assertIsNotNone(plan._manifest_file("library/m:latest"))
        self.assertIsNotNone(plan._manifest_file("pub/deadbeef0123"))


class TestManifestStoreV2(TestManifestStore):
    LAYOUT = "v2"

    def test_v2_entry_first_and_a_dangling_link_falls_back(self):
        self.ol.write("m", [(plan.MT_MODEL, "sha256:" + "2" * 64)])                     # v2
        legacy = self.ol.legacy_path("m")
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(json.dumps({"layers": [{"mediaType": plan.MT_MODEL, "digest": self.W[0][1]}]}))
        self.assertEqual(self.weights(tags=False), "2" * 64)
        os.unlink(os.path.realpath(self.ol.v2_path("m")))                               # blob gone: dangling
        self.assertEqual(self.weights(tags=False), "1" * 64)                            # as Ollama's os.Stat
        self.assertIsNone(self.weights())                                               # but Ollama lists neither

    def test_link_must_hold_the_blob_it_names(self):
        self.ol.write("m", self.W)
        link = self.ol.v2_path("m")
        blob = Path(os.path.realpath(link))
        outside = Path(self.tmp.name) / "elsewhere" / blob.name
        outside.parent.mkdir()
        outside.write_bytes(blob.read_bytes())
        link.unlink()
        link.symlink_to(outside)                                                        # right name, wrong place
        self.assertIsNone(self.weights(tags=False))
        link.unlink()
        link.symlink_to(blob)
        blob.write_bytes(blob.read_bytes().replace(b"1111", b"2222", 1))               # content no longer its name
        self.assertIsNone(self.weights(tags=False))

    def test_plain_file_entry_must_stay_in_its_tree(self):
        self.ol.write("m", self.W)
        link = self.ol.v2_path("m")
        data = link.read_bytes()
        link.unlink()
        link.write_bytes(data)                                                          # Ollama's copy fallback
        self.assertEqual(self.weights(), "1" * 64)
        away = Path(self.tmp.name) / "away"
        away.mkdir()
        (away / "latest").write_bytes(data)
        shutil.rmtree(link.parent)
        link.parent.symlink_to(away)                                                    # the folder is a link out
        self.assertIsNone(self.weights(tags=False))


class TestOllamaTags(unittest.TestCase):
    """The real ollama_tags against canned /api/tags answers (the install tests fake the whole function)."""

    def answer(self, body=None, exc=None):
        class Opener:
            def open(self, url, timeout=None):
                if exc is not None:
                    raise exc
                return contextlib.closing(io.BytesIO(body if isinstance(body, bytes) else json.dumps(body).encode()))
        return mock.patch.object(plan, "_LOCAL_HTTP", Opener())

    def test_listing(self):
        d1, d2 = "1" * 64, "2" * 64
        body = {"models": [{"name": "a:latest", "digest": d1}, {"name": "ns/b:7b", "digest": "Z" * 64},
                           {"name": "u:1", "digest": "A" * 64}, {"name": "c:latest", "digest": d1},
                           {"name": "c:latest", "digest": d2}, {"name": "e:1", "digest": d1},
                           {"name": "e:1", "digest": d1}, {"name": 5, "digest": d1}, "junk", {"digest": d1}]}
        with self.answer(body):
            tags = plan.ollama_tags()
        self.assertEqual(tags, {"a:latest": d1, "a": d1, "ns/b:7b": "", "u:1": "", "e:1": d1,
                                "c:latest": frozenset((d1, d2)), "c": frozenset((d1, d2))})

    def test_failures_are_errors_never_an_empty_list(self):
        for kw, why in ((dict(exc=OSError("refused")), "couldn't list Ollama's models"),
                        (dict(body=b"<html>"), "couldn't list Ollama's models"),
                        (dict(body={"models": None}), "malformed"),
                        (dict(body={"error": "busy"}), "malformed"),
                        (dict(body=[1, 2]), "malformed")):
            with self.subTest(answer=str(kw)), self.answer(**kw):
                with self.assertRaisesRegex(plan.PlanError, why):
                    plan.ollama_tags()
                self.assertEqual(plan.ollama_tags_quiet(), {})
        with self.answer({"models": []}):
            self.assertEqual(plan.ollama_tags(), {})


class TestCatalogSources(unittest.TestCase):
    """validate_catalog's source rules: no remote or otherwise-resolved Ollama names, no source that is
    an alias (a pull would overwrite it before any check)."""

    def errs(self, mutate):
        cat = synthetic()
        mutate({x["id"]: x for x in cat})
        return plan.validate_catalog(cat)

    def assertRefused(self, mutate, why):
        errs = self.errs(mutate)
        self.assertTrue(any(why in e for e in errs), errs)

    def test_source_suffix_tags_refused(self):
        for ref in ("pub/w:cloud", "pub/w:Cloud", "pub/w:120b-cloud", "pub/w:20B-CLOUD", "pub/w:local", "w:LOCAL"):
            with self.subTest(ref=ref):
                self.assertRefused(lambda b: b["w-big"]["source"].update(ref=ref), "no :cloud, :local or -cloud")
        self.assertEqual(self.errs(lambda b: b["w-big"]["source"].update(ref="pub/w:cloudy")), [])

    def test_names_ollama_reads_as_blob_digests_refused(self):
        for ref in ("deadbeef0123", "library/DEADBEEF0123:latest", "sha256-" + "a" * 20):
            with self.subTest(ref=ref):
                self.assertRefused(lambda b: b["w-big"]["source"].update(ref=ref), "reads as a blob digest")
        for ref in ("pub/deadbeef0123", "deadbeef0123:1b"):
            with self.subTest(ref=ref):
                self.assertEqual(self.errs(lambda b: b["w-big"]["source"].update(ref=ref)), [])
        self.assertRefused(lambda b: b["w-big"].update(alias="deadbeef0123"), "reads as a blob digest")
        self.assertRefused(lambda b: b["w-big"].update(alias="secstack-tmp-x"), "temporary build name")

    def test_ollama_040_digest_references_refused(self):
        # server.digestModelName: <runner>:<digest> and the bare digest forms name a local blob.
        for ref in ("mlx:0123456789abcdef", "MLXrunner:0123456789AB", "ggml:" + "a" * 64, "llamacpp:" + "c" * 12,
                    "llama.cpp:sha256-" + "b" * 20, "llama_cpp:" + "c" * 12, "llama-cpp:" + "d" * 40,
                    "sha256:" + "d" * 64, "SHA256:" + "e" * 12):
            with self.subTest(ref=ref):
                self.assertRefused(lambda b: b["w-big"]["source"].update(ref=ref), "reads as a blob digest")
        for ref in ("mlx:7b", "pub/mlx:0123456789ab", "mlx-community:0123456789ab", "ggml:0123456789a"):
            with self.subTest(ref=ref):
                self.assertEqual(self.errs(lambda b: b["w-big"]["source"].update(ref=ref)), [])

    def test_source_may_not_be_a_catalog_alias(self):
        for ref in ("w-big-abliterated", "w-mid-abliterated:latest", "library/W-Mid-Abliterated:LATEST",
                    "nomic-embed-text"):
            with self.subTest(ref=ref):
                self.assertRefused(lambda b: b["w-big"]["source"].update(ref=ref), "is a catalog alias")
        self.assertEqual(plan.validate_catalog(synthetic()), [])      # the embedding model's alias is its source


class TestInteractiveSelect(unittest.TestCase):
    def setUp(self):
        self.cat = synthetic()
        self.p = plan.compute_plan(mac(48))
        rows = plan.chat_models(self.cat)
        rows.sort(key=lambda x: (plan.ROLES.index(x["role"]), -x["rank"]))
        self.num = {x["id"]: str(i) for i, x in enumerate(rows, 1)}

    def pick(self, answers, cat=None):
        with mock.patch("builtins.input", side_effect=answers), quiet():
            return plan.interactive_select(cat or self.cat, self.p, [], None)

    def test_accept_recommendation(self):
        models, primary = self.pick([""])
        self.assertEqual([x["id"] for x in models], ["w-big", "d-big", "a-big"])
        self.assertEqual(primary, "w-big")

    def test_toggle_and_primary(self):
        n = self.num
        models, primary = self.pick([f"{n['d-big']} {n['a-big']}", f"p {n['w-mid']}", "99", "x", ""])
        self.assertEqual([x["id"] for x in models], ["w-mid"])          # 'p N' takes the place of w-big
        self.assertEqual(primary, "w-mid")
        models, primary = self.pick([n["w-mid"], f"p {n['w-mid']}", n["a-big"], ""])   # selected first: both kept
        self.assertEqual(sorted(x["id"] for x in models), ["d-big", "w-big", "w-mid"])
        self.assertEqual(primary, "w-mid")

    def test_p_replaces_the_pick_in_its_role(self):
        # Three models selected: making a fourth the primary used to leave four (refused on Enter).
        models, primary = self.pick([f"p {self.num['w-mid']}", ""])
        self.assertEqual(sorted(x["id"] for x in models), ["a-big", "d-big", "w-mid"])
        self.assertEqual(primary, "w-mid")

    def test_invalid_selection_is_not_accepted(self):
        # a fourth model is over the limit; 'r' resets to the recommendation
        models, _ = self.pick([self.num["w-small"], "", "r", ""])
        self.assertEqual(len(models), 3)

    def test_no_tools_cannot_be_primary(self):
        cat = synthetic()
        cat[6]["tools"] = False      # a-big
        _, primary = self.pick([f"p {self.num['a-big']}", ""], cat)
        self.assertEqual(primary, "w-big")

    def test_quit_and_eof(self):
        with self.assertRaises(plan.PlanError):
            self.pick(["q"])
        with self.assertRaises(plan.PlanError):
            self.pick(EOFError())


class TestCommands(unittest.TestCase):
    def setUp(self):
        reset_secops()

    def tearDown(self):
        reset_secops()

    def test_docker_check(self):
        plan.CFG.mkdir(parents=True)
        plan.STACK_CONF.write_text("DOCKER_VM_GB=16\nDOCKER_VM_CPUS=8\n")
        with mock.patch.object(plan, "_run", return_value=f"8 {16 * plan.GIB - 300 * 2**20}"), quiet():
            self.assertEqual(plan.cmd_docker_check(None), 0)
        with mock.patch.object(plan, "_run", return_value=f"8 {24 * plan.GIB}"), quiet():
            self.assertEqual(plan.cmd_docker_check(None), 1)
        with mock.patch.object(plan, "_run", return_value=f"8 {int(16.5 * plan.GIB)}"), quiet():
            self.assertEqual(plan.cmd_docker_check(None), 1)        # bigger than planned eats the model's memory
        with mock.patch.object(plan, "_run", return_value=f"8 {int(14.8 * plan.GIB)}"), quiet():
            self.assertEqual(plan.cmd_docker_check(None), 1)
        with mock.patch.object(plan, "_run", return_value=f"7 {16 * plan.GIB}"), quiet():
            self.assertEqual(plan.cmd_docker_check(None), 1)
        with mock.patch.object(plan, "_run", return_value=""), quiet():
            self.assertEqual(plan.cmd_docker_check(None), 2)
        plan.STACK_CONF.write_text("DOCKER_VM_GB=sixteen\nDOCKER_VM_CPUS=8\n")
        with self.assertRaises(plan.PlanError):
            plan.cmd_docker_check(None)

    def test_main_maps_errors_to_exit_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), quiet():
            self.assertEqual(plan.main(["docker-check"]), 2)
        self.assertIn("no valid Docker plan", err.getvalue())

    def test_recommend_simulated(self):
        with quiet() as out:
            self.assertEqual(plan.main(["recommend", "--ram-gb", "48", "--cpus", "14", "--disk-gb", "900"]), 0)
        self.assertIn("qwen3.6-35b-a3b-abliterated", out.getvalue())

    def test_recommend_output_is_consistent(self):
        with quiet() as out:
            plan.main(["recommend", "--ram-gb", "18", "--disk-gb", "900"])
        text = out.getvalue()
        self.assertIn("32K x 1 parallel with these models", text)
        self.assertNotIn("16K context", text)
        with quiet() as out:
            self.assertEqual(plan.main(["recommend", "--ram-gb", "48", "--disk-gb", "45"]), 1)
        self.assertIn("fits on disk", out.getvalue())

    def test_interactive_primary_must_be_real(self):
        hw = mac(48, disk=600)
        hw.simulated = False
        stdin = types.SimpleNamespace(isatty=lambda: True)
        for bad in ("nope", "nomic-embed", "gpt-oss-120b"):     # typo, no tools, too big
            with mock.patch.object(plan, "detect", lambda: hw), mock.patch.object(plan, "_run", return_value=""), \
                    mock.patch.object(plan.sys, "stdin", stdin), contextlib.redirect_stderr(io.StringIO()), quiet():
                self.assertEqual(plan.main(["select", "--primary", bad]), 2, bad)
        with mock.patch.object(plan, "detect", lambda: hw), mock.patch.object(plan, "_run", return_value=""), \
                mock.patch.object(plan.sys, "stdin", stdin), mock.patch("builtins.input", side_effect=[""]), quiet() as out:
            self.assertEqual(plan.main(["select", "--primary", "gpt-oss-20b"]), 0)
        self.assertIn("Primary:  gpt-oss-20b-abliterated", out.getvalue())

    def test_runtime_root_inside_repo_refused(self):
        p = plan.compute_plan(mac(48))
        roles = plan.assign_roles(plan.recommend(p, synthetic()))
        with mock.patch.object(plan, "REPO", _TMP), self.assertRaises(plan.PlanError):
            plan.write_outputs(mac(48), p, roles, embed())

    def test_free_disk_of_a_missing_path_uses_its_parent(self):
        free, dev = plan._free_gb(_TMP / "does" / "not" / "exist")
        self.assertGreater(free, 0)
        self.assertEqual(dev, os.stat(_TMP).st_dev)

    def test_separate_model_volume(self):
        hw = mac(48, disk=200)
        hw.same_volume, hw.images_free_gb = False, 30
        p = plan.compute_plan(hw)
        self.assertEqual(p.new_disk_gb, 180)          # no image reserve on the models volume
        self.assertTrue(any("system volume" in w for w in p.warnings))
        self.assertIn("system volume", hw.summary())

    def test_select_write_refuses_simulation(self):
        with contextlib.redirect_stderr(io.StringIO()), quiet():
            self.assertEqual(plan.main(["select", "--yes", "--write", "--ram-gb", "48"]), 2)

    def test_select_models_and_primary(self):
        hw = mac(48, disk=600)
        hw.simulated = False
        with mock.patch.object(plan, "detect", lambda: hw), mock.patch.object(plan, "_run", return_value=""), quiet():
            rc = plan.main(["select", "--write", "--models", "gemma4-26b,qwen3.6-35b-moe,nomic-embed",
                            "--primary", "qwen3.6-35b-a3b-abliterated"])
        self.assertEqual(rc, 0)
        conf = plan.read_conf()
        self.assertEqual(conf["CHAT_MODEL"], "qwen3.6-35b-a3b-abliterated")
        self.assertEqual(conf["MODELS"], "gemma4-26b-abliterated,qwen3.6-35b-a3b-abliterated")

    def test_positive_ints_only(self):
        for bad in ("0", "-5", "4.5", "\uff14\uff18"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                plan.main(["recommend", "--ram-gb", bad])

    def test_ollama_models_from_launchd(self):
        # Ollama.app takes OLLAMA_MODELS from launchd (launchctl setenv), not from a shell.
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="/Volumes/T7/ollama\n", stderr="")
        env = {k: v for k, v in os.environ.items() if k != "OLLAMA_MODELS"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(plan.platform, "system", return_value="Darwin"), \
                mock.patch.object(plan.subprocess, "run", fake_run):
            self.assertEqual(plan._ollama_models_dir(), Path("/Volumes/T7/ollama"))
            self.assertEqual(calls, [[plan.LAUNCHCTL, "getenv", "OLLAMA_MODELS"]])
            with mock.patch.dict(os.environ, {"OLLAMA_MODELS": "/srv/models"}):
                self.assertEqual(plan._ollama_models_dir(), Path("/srv/models"))   # this shell's own value wins
            self.assertEqual(len(calls), 1)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(plan.platform, "system", return_value="Linux"):
            self.assertEqual(plan._ollama_models_dir(), plan.HOME / ".ollama" / "models")

    def test_apfs_volumes_of_one_container_share_free_space(self):
        import plistlib
        df = {"/a": "/dev/disk3s5", "/b": "/dev/disk3s7", "/c": "/dev/disk5s1"}
        refs = {"/dev/disk3s5": "disk3", "/dev/disk3s7": "disk3", "/dev/disk5s1": "disk5"}

        def fake_run(cmd, timeout=10):
            if cmd[0] == plan.DF:
                return f"Filesystem 512-blocks Used Available Capacity Mounted on\n{df[cmd[2]]} 9 9 9 9% /x"
            if cmd[0] == plan.DISKUTIL:
                return plistlib.dumps({"APFSContainerReference": refs[cmd[3]]}).decode()
            return ""
        with mock.patch.object(plan.platform, "system", return_value="Darwin"), mock.patch.object(plan, "_run", fake_run), \
                mock.patch.object(plan, "_existing", Path):
            self.assertEqual(plan._apfs_container("/a"), "disk3")
            self.assertTrue(plan._same_pool(("/a", 100.0, 1), ("/b", 80.0, 2), {}))      # one container
            self.assertFalse(plan._same_pool(("/a", 100.0, 1), ("/c", 80.0, 3), {}))     # another disk
            self.assertTrue(plan._same_pool(("/a", 100.0, 1), ("/c", 100.02, 3), {}))    # same free space
        def diskutil_says(out):
            return lambda cmd, timeout=10: "Filesystem\n/dev/disk3s5 9 9 9 9% /x" if cmd[0] == plan.DF else out
        for out in ("", '<?xml version="1.0"?><plist version="1.0"><dict>', "not a plist",
                    plistlib.dumps([1]).decode(), plistlib.dumps({"APFSContainerReference": 3}).decode()):
            with mock.patch.object(plan.platform, "system", return_value="Darwin"), \
                    mock.patch.object(plan, "_run", diskutil_says(out)), mock.patch.object(plan, "_existing", Path):
                self.assertEqual(plan._apfs_container("/a"), "", out)
        with mock.patch.object(plan.platform, "system", return_value="Darwin"), mock.patch.object(plan, "_run", return_value=""):
            self.assertEqual(plan._apfs_container("/a"), "")                            # df answered nothing
        with mock.patch.object(plan.platform, "system", return_value="Linux"), \
                mock.patch.object(plan, "_run", side_effect=AssertionError("ran a command off macOS")):
            self.assertEqual(plan._apfs_container("/a"), "")                            # not macOS
        # detect(): models on their own APFS volume of the home volume's container share its free space,
        # so the plan keeps the Docker image reserve; GGUF downloads stay with the home volume.
        frees = {plan.OLLAMA_MODELS: (80.0, 1), plan.HOME: (79.0, 2), plan.MODELS_DIR: (79.0, 2)}
        with mock.patch.object(plan, "_free_gb", frees.get), mock.patch.object(plan, "_apfs_container", lambda p: "disk3"):
            v = plan._volumes()
        self.assertEqual((v["same_volume"], v["staging_same_volume"], v["staging_home_volume"]), (True, True, True))
        with mock.patch.object(plan, "_free_gb", frees.get), mock.patch.object(plan, "_apfs_container", lambda p: ""):
            v = plan._volumes()
        self.assertEqual((v["same_volume"], v["staging_same_volume"], v["staging_home_volume"]), (False, False, True))
        self.assertEqual((v["free_disk_gb"], v["images_free_gb"], v["staging_free_gb"]), (80.0, 79.0, 79.0))

    def test_detect_names_the_wired_limit_sysctl(self):
        vals = {"hw.memsize": str(48 * plan.GIB), "hw.ncpu": "18", "hw.optional.arm64": "1",
                "debug.iogpu.wired_limit": str(40 * plan.GIB)}
        with mock.patch.object(plan.platform, "system", return_value="Darwin"), \
                mock.patch.object(plan, "_run", lambda cmd, timeout=10: vals.get(cmd[-1], "") if cmd[0] == plan.SYSCTL else ""):
            hw = plan.detect()
        self.assertEqual((hw.wired_limit_mb, hw.wired_limit_key), (40960, "debug.iogpu.wired_limit"))
        vals["iogpu.wired_limit_mb"] = "30000"
        with mock.patch.object(plan.platform, "system", return_value="Darwin"), \
                mock.patch.object(plan, "_run", lambda cmd, timeout=10: vals.get(cmd[-1], "") if cmd[0] == plan.SYSCTL else ""):
            hw = plan.detect()
        self.assertEqual((hw.wired_limit_mb, hw.wired_limit_key), (30000, "iogpu.wired_limit_mb"))

    def test_live_docker_beats_the_install_record(self):
        plan.CFG.mkdir(parents=True)
        plan.SELECTED.write_text(json.dumps({"installed": {"x": {}}}))

        def docker(image_id, server):
            return lambda cmd, timeout=10: image_id if "inspect" in cmd else (server if "version" in cmd else "")
        with mock.patch.object(plan.os, "access", return_value=True):
            with mock.patch.object(plan, "_run", docker("", "27.3.1")):          # Docker up, images pruned
                self.assertFalse(plan.local_state(synthetic()).images_present)
            with mock.patch.object(plan, "_run", docker("", "")):                # Docker down: the record decides
                self.assertTrue(plan.local_state(synthetic()).images_present)
            plan.SELECTED.unlink()
            with mock.patch.object(plan, "_run", docker("sha256:" + "1" * 64, "27.3.1")):
                self.assertTrue(plan.local_state(synthetic()).images_present)

    def test_installed_aliases_found_in_either_manifest_layout(self):
        # Ollama 0.40+ keeps a created alias as a manifests-v2 link to the manifest blob; older ones as a
        # file under manifests/registry.ollama.ai. Both count as installed (and credited on the disk).
        with tempfile.TemporaryDirectory() as d, mock.patch.object(plan, "OLLAMA_MODELS", Path(d)), \
                mock.patch.object(plan, "_images_built", return_value=False):
            legacy = Path(d) / "manifests" / "registry.ollama.ai" / "library" / "w-big-abliterated"
            legacy.mkdir(parents=True)
            (legacy / "latest").write_text("{}")
            blob = Path(d) / "blobs" / ("sha256-" + hashlib.sha256(b"{}").hexdigest())
            blob.parent.mkdir()
            blob.write_bytes(b"{}")
            v2 = Path(d) / "manifests-v2" / "ollama.com" / "library" / "d-big-abliterated"
            v2.mkdir(parents=True)
            (v2 / "latest").symlink_to(blob)
            st = plan.local_state(synthetic())
        self.assertEqual(st.installed, {"w-big-abliterated", "d-big-abliterated"})
        self.assertEqual(st.installed_gb, 36.0)

    def test_yes_with_primary_takes_its_roles_place(self):
        with quiet() as out:
            self.assertEqual(plan.main(["select", "--yes", "--primary", "gpt-oss-20b", "--ram-gb", "48",
                                        "--disk-gb", "900"]), 0)
        self.assertIn("Selected: qwen3.8-27b-abliterated, gemma4-26b-abliterated, gpt-oss-20b-abliterated",
                      out.getvalue())
        self.assertIn("Primary:  gpt-oss-20b-abliterated", out.getvalue())

    def test_failed_write_leaves_the_previous_plan_whole(self):
        # Every file is written under a temporary name first (where a full disk or a folder that can't be
        # written shows up), then renamed into place, stack.conf last; the generated providers the new plan
        # doesn't have are deleted after that. A failure leaves the previous plan exactly as it was.
        hw = mac(48, disk=600)
        hw.simulated = False
        real_mkstemp, real_replace, real_fdopen = tempfile.mkstemp, os.replace, os.fdopen

        def select(models, *patches):
            with contextlib.ExitStack() as stack:
                for p in (mock.patch.object(plan, "detect", lambda: hw), mock.patch.object(plan, "_run", return_value=""),
                          *patches):
                    stack.enter_context(p)
                err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                stack.enter_context(quiet())
                return plan.main(["select", "--write", "--models", models]), err.getvalue()

        def files():   # everything under the runtime root, temporary files included
            return {str(p.relative_to(plan.SECOPS)): p.read_bytes() for p in plan.SECOPS.rglob("*") if p.is_file()}
        self.assertEqual(select("qwen3.6-35b-moe,qwen3.8-27b,gemma4-26b")[0], 0)
        before = files()
        default = plan.PROVIDERS_DIR / "10-local-qwen36-moe.json"
        self.assertIn(str(default.relative_to(plan.SECOPS)), before)

        def refused_in(folder, error):    # no file can be created there
            def mkstemp(*a, **kw):
                if Path(kw.get("dir") or ".") == folder:
                    raise error
                return real_mkstemp(*a, **kw)
            return mock.patch.object(plan.tempfile, "mkstemp", mkstemp)

        class FillsUp:                    # the disk fills up while the 5ire config is being written
            def __init__(self, f):
                self.f = f

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.f.close()

            def write(self, text):
                if '"mcpServers"' in text:
                    raise OSError(28, "No space left on device")
                return self.f.write(text)
        full = "No space left on device"
        fills_up = mock.patch.object(plan.os, "fdopen", lambda fd, *a, **kw: FillsUp(real_fdopen(fd, *a, **kw)))
        for label, patch, strerror in (
                ("full while writing", fills_up, full),
                ("full", refused_in(plan.GEN, OSError(28, full)), full),
                ("unwritable", refused_in(plan.PROVIDERS_DIR, PermissionError(13, "Permission denied")), "Permission denied")):
            rc, err = select("gpt-oss-20b,qwen3-14b", patch)
            with self.subTest(label):
                self.assertEqual(rc, 2)
                self.assertIn(strerror, err)
                self.assertIn("the previous plan is unchanged", err)
                self.assertNotIn("Traceback", err)
                self.assertEqual(files(), before)      # stack.conf, models.selected.json, every provider, no temp file
        events = []

        def temp(*a, **kw):
            events.append("temp")
            return real_mkstemp(*a, **kw)

        def rename(src, dst):
            events.append(("replace", Path(dst), default.exists()))
            real_replace(src, dst)
        rc, _ = select("gpt-oss-20b,qwen3-14b", mock.patch.object(plan.tempfile, "mkstemp", temp),
                       mock.patch.object(plan.os, "replace", rename))
        self.assertEqual(rc, 0)
        first = next(i for i, e in enumerate(events) if e != "temp")
        self.assertNotIn("temp", events[first:])                         # every temporary file before any rename
        self.assertEqual(events[-1], ("replace", plan.STACK_CONF, True))  # stack.conf last; the old default still there
        self.assertFalse(default.exists())                               # ... and deleted only after it
        self.assertIn("CHAT_MODEL=gpt-oss-20b-abliterated", plan.STACK_CONF.read_text())
        with mock.patch.object(plan, "cmd_show", side_effect=OSError(5, "Input/output error")), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(plan.main(["show"]), 2)
        self.assertIn("plan: [Errno 5] Input/output error", err.getvalue())

    def test_unmounted_drive_spelled_through_the_data_volume(self):
        # /System/Volumes/Data/Volumes/T7 is /Volumes/T7 by another name: a firmlink realpath doesn't resolve.
        with mock.patch.object(plan.platform, "system", return_value="Darwin"), \
                mock.patch.object(plan, "VOLUMES", "/Volumes"), mock.patch.object(plan.os.path, "ismount", lambda p: False):
            self.assertEqual(plan._unmounted_volume("/System/Volumes/Data/Volumes/T7/ollama"),
                             "/System/Volumes/Data/Volumes/T7")
            self.assertEqual(plan._unmounted_volume("/system/volumes/data/volumes/T7/x"),
                             "/system/volumes/data/volumes/T7")
            self.assertEqual(plan._unmounted_volume("/System/Volumes/Data/Users/me/models"), "")
        with mock.patch.object(plan.platform, "system", return_value="Darwin"), mock.patch.object(plan, "VOLUMES", "/Volumes"), \
                mock.patch.object(plan.os.path, "ismount", lambda p: p == "/System/Volumes/Data/Volumes/T7"):
            self.assertEqual(plan._unmounted_volume("/System/Volumes/Data/Volumes/T7/ollama"), "")

    def test_model_folders_on_an_unmounted_drive_are_refused(self):
        # Ollama's store (OLLAMA_MODELS from the shell or launchd, or a symlinked ~/.ollama/models) or the GGUF
        # folder on a drive that isn't mounted: measured anyway, the path falls back to /Volumes on the
        # internal disk, with other free space and none of the drive's models. The plan refuses instead.
        root = _TMP / "unmounted"
        shutil.rmtree(root, ignore_errors=True)
        vols = root / "Volumes"                                     # stands in for /Volumes
        (root / "boot").mkdir(parents=True)
        vols.mkdir()
        (vols / "Macintosh HD").symlink_to(root / "boot")           # the boot volume's own link
        link = root / "home" / ".ollama" / "models"
        link.parent.mkdir(parents=True)
        link.symlink_to(vols / "T7" / "ollama")                     # dangling while T7 is unplugged
        sysctl = {"hw.memsize": str(48 * plan.GIB), "hw.ncpu": "18", "hw.optional.arm64": "1"}

        def fake_run(cmd, timeout=10):        # a 48 GB Apple Silicon Mac; every other command answers nothing
            return sysctl.get(cmd[-1], "") if cmd[0] == plan.SYSCTL else ""

        @contextlib.contextmanager
        def this_mac(store, staging=root / "home" / "models" / "gguf", mounted=(), system="Darwin"):
            with mock.patch.object(plan, "VOLUMES", str(vols)), mock.patch.object(plan, "OLLAMA_MODELS", Path(store)), \
                    mock.patch.object(plan, "MODELS_DIR", Path(staging)), \
                    mock.patch.object(plan.platform, "system", return_value=system), \
                    mock.patch.object(plan.os.path, "ismount", lambda p: p in [str(vols / n) for n in mounted]), \
                    mock.patch.object(plan, "_run", fake_run):
                yield

        def run(argv, store, **kw):
            with this_mac(store, **kw), contextlib.redirect_stderr(io.StringIO()) as err, quiet():
                return plan.main(argv), err.getvalue()
        t7 = f"is on {vols / 'T7'}, which isn't mounted"
        rc, err = run(["select", "--write", "--yes"], vols / "T7" / "ollama")      # launchctl setenv OLLAMA_MODELS
        self.assertEqual(rc, 2)
        self.assertIn(f"Ollama's model store {vols / 'T7' / 'ollama'} {t7}", err)
        self.assertIn("Connect that drive", err)
        self.assertFalse(plan.STACK_CONF.exists())
        rc, err = run(["recommend"], link)                                           # ~/.ollama/models -> T7
        self.assertEqual(rc, 2)
        self.assertIn(f"{link} (a link to {vols / 'T7' / 'ollama'}) {t7}", err)
        (vols / "T7" / "ollama").mkdir(parents=True)        # a folder left behind in /Volumes isn't the drive
        self.assertIn(t7, run(["recommend"], link)[1])
        rc, err = run(["recommend"], root / "home" / "store", staging=vols / "T7" / "gguf")   # SECSTACK_MODELS_DIR
        self.assertIn(f"GGUF download folder {vols / 'T7' / 'gguf'} {t7}", err)
        spelled = str(vols)[:-len("Volumes")] + "volumes/T7/ollama"                  # APFS ignores case
        self.assertIn("isn't mounted", run(["recommend"], spelled)[1])
        # A simulation given its own free disk doesn't measure this Mac's; one without --disk-gb does.
        self.assertEqual(run(["recommend", "--ram-gb", "48", "--disk-gb", "900"], link)[0], 0)
        self.assertIn(t7, run(["recommend", "--ram-gb", "48"], link)[1])
        # The drive mounted, the boot volume's own link, or not macOS: measured as before.
        for store, kw in ((link, {"mounted": ("T7",)}), (vols / "Macintosh HD" / "Users" / "x", {}),
                          (link, {"system": "Linux"})):
            with self.subTest(store=str(store), **kw), this_mac(store, **kw):
                self.assertGreater(plan.detect().free_disk_gb, 0)


# --------------------------------------------------------------------------- render-env
class TestRenderEnv(unittest.TestCase):
    def run_render(self, *extra, vars_=True):
        d = self.d
        cmd = [sys.executable, str(RENDER), "--example", str(d / "ex"), "--overrides", str(d / "ov"),
               "--out", str(d / "out")]
        if vars_:
            cmd += ["--vars", str(d / "vars")]
        return subprocess.run(cmd + list(extra), capture_output=True, text=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = Path(self.tmp.name)
        (d / "ex").write_text("A=1\nSECRET=changeme # upstream\nMODEL=\nURL=x\n# MODEL=commented\n")
        (d / "ov").write_text("SECRET=@hex24\nMODEL=${CHAT_MODEL}\nUSER=@alnum12\nURL=https://${USER}:${SECRET}@h/\n"
                              "IMAGE=${PENTAGI_IMAGE}\n")
        (d / "vars").write_text("# plan\nCHAT_MODEL=model-a\nPENTAGI_IMAGE=vx/p@sha256:" + "a" * 64 + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def out(self):
        return (self.d / "out").read_text()

    def test_render_and_update(self):
        r = self.run_render()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.out()
        self.assertEqual(stat.S_IMODE((self.d / "out").stat().st_mode), 0o600)
        self.assertIn("MODEL=model-a\n", out)
        self.assertIn("IMAGE=vx/p@sha256:", out)
        self.assertIn("# MODEL=commented\n", out)
        secret = [x for x in out.splitlines() if x.startswith("SECRET=")][0]
        self.assertNotIn("changeme", secret)
        url = [x for x in out.splitlines() if x.startswith("URL=")][0]
        self.assertIn(secret.split("=", 1)[1], url)
        (self.d / "vars").write_text("CHAT_MODEL=model-b\nPENTAGI_IMAGE=vx/p:2\n")
        r = self.run_render("--update-keys", "MODEL,IMAGE")
        self.assertEqual(r.returncode, 0, r.stderr)
        out2 = self.out()
        self.assertIn("MODEL=model-b\n", out2)
        self.assertIn("IMAGE=vx/p:2\n", out2)
        self.assertIn(secret + "\n", out2, "secrets must survive a model update")

    def test_update_refuses_generated_secrets(self):
        self.assertEqual(self.run_render().returncode, 0)
        before = self.out()
        for keys in ("SECRET", "URL"):          # URL is derived from generated secrets
            self.assertEqual(self.run_render("--update-keys", keys).returncode, 2, keys)
        self.assertEqual(self.out(), before)

    def test_update_preserves_crlf_and_adds_missing(self):
        (self.d / "out").write_bytes(b"MODEL=old\r\nOTHER=1")
        r = self.run_render("--update-keys", "MODEL,IMAGE")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = (self.d / "out").read_bytes()
        self.assertTrue(out.startswith(b"OTHER=1\r\n\r\n# ---- secstack overrides"), out)
        self.assertTrue(out.endswith(b"\r\nMODEL=model-a\r\nIMAGE=vx/p@sha256:" + b"a" * 64 + b"\r\n"), out)
        self.assertNotIn(b"\n", out.replace(b"\r\n", b""), "line endings stay CRLF")

    def test_existing_kept_without_flags(self):
        (self.d / "out").write_text("SECRET=keep\n")
        r = self.run_render()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out(), "SECRET=keep\n")

    def test_unresolved_variable_fails_closed(self):
        r = self.run_render(vars_=False)
        self.assertEqual(r.returncode, 2)
        self.assertFalse((self.d / "out").exists())

    def test_unsafe_vars_count_as_missing(self):
        (self.d / "vars").write_text("CHAT_MODEL=a b\nPENTAGI_IMAGE=x\n")
        self.assertEqual(self.run_render().returncode, 2)
        (self.d / "vars").write_text("CHAT_MODEL=$(id)\nPENTAGI_IMAGE=x\n")
        self.assertEqual(self.run_render().returncode, 2)

    def test_bad_overrides_fail(self):
        (self.d / "ov").write_text("MODEL=@nope\n")
        self.assertEqual(self.run_render().returncode, 2)
        (self.d / "ov").write_text("this is not a key value line\n")
        self.assertEqual(self.run_render().returncode, 2)
        (self.d / "ov").write_text("A=${B}\nB=${A}\n")
        self.assertEqual(self.run_render().returncode, 2)

    def test_update_keys_must_exist_in_overrides(self):
        self.assertEqual(self.run_render().returncode, 0)
        self.assertEqual(self.run_render("--update-keys", "NOPE").returncode, 2)

    # ---- the file as Docker Compose reads it (values checked against docker compose 5.7) ----
    def get(self, key, path=None, env=None):
        r = subprocess.run([sys.executable, str(RENDER), "--get", key, "--file", str(path or self.d / "out")],
                           capture_output=True, text=True, env=dict(os.environ, **(env or {})))
        return r.returncode, r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout

    def test_get_reads_like_compose(self):
        (self.d / "env").write_bytes((
            "A=1\nexport B=2\n  C = 3 # c\nD: 4\nE=\"x\ny\" F=5\nG=$A-${Z:-dz}\n"
            "# see docs\u2028COMPOSE_FILE=evil.yml\n"          # one comment line: Compose splits at \n only
            "# old\x0cDOCKER_NETWORK=bridge\n"
            "X=\"a\nDOCKER_INSIDE=true\n\"\n"                  # inside a quoted value, not an assignment
            "H=\"a\\\"b\\nc\\\\d\\$e\"\nI='s\\'q'\n"
            "J=${SECSTACK_T_ENV:-none}\nK=k\r\nL=x #c\nM=x#c\n"
            "N=first\n\tN=last\n"
            "SECSTACK_T_ENV\n").encode())
        want = {"A": "1", "B": "2", "C": "3", "D": "4", "E": "x\ny", "F": "5", "G": "1-dz",
                "X": "a\nDOCKER_INSIDE=true\n", "H": 'a"b\nc\\d$e', "I": "s'q", "J": "fromenv", "K": "k",
                "L": "x", "M": "x#c", "N": "last", "SECSTACK_T_ENV": "fromenv",
                "COMPOSE_FILE": "", "DOCKER_NETWORK": "", "DOCKER_INSIDE": "", "Z": ""}
        for key, value in want.items():
            self.assertEqual(self.get(key, self.d / "env", {"SECSTACK_T_ENV": "fromenv"}), (0, value), key)

    def test_get_unreadable_or_unparseable(self):
        self.assertEqual(self.get("A", self.d / "missing")[0], 2)
        (self.d / "env").write_text('A=1\nB="unterminated\n')
        self.assertEqual(self.get("A", self.d / "env")[0], 2)
        (self.d / "env").write_text("A=1\n")
        self.assertEqual(self.get("B", self.d / "env"), (0, ""))

    def test_render_drops_every_upstream_assignment_of_an_override(self):
        (self.d / "ex").write_text(
            "A=1\nMODEL=from-example\n# note\u2028COMPOSE_FILE=evil.yml\n  MODEL=indented\nexport SECRET=changeme\n"
            "X='a' URL=evil\nY=\"multi\nMODEL=inside-quotes\n\"\nMODEL: yaml\nIMAGE = spaced\n")
        r = self.run_render()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.out()
        self.assertEqual(self.get("MODEL"), (0, "model-a"))
        self.assertEqual(self.get("IMAGE"), (0, "vx/p@sha256:" + "a" * 64))
        rc, secret = self.get("SECRET")
        self.assertRegex(secret, r"^[0-9a-f]{48}$")
        rc, user = self.get("USER")
        self.assertEqual(self.get("URL"), (0, f"https://{user}:{secret}@h/"))
        self.assertEqual(self.get("COMPOSE_FILE"), (0, ""), "a comment must stay a comment")
        self.assertIn("# note\u2028COMPOSE_FILE=evil.yml\n", out)
        self.assertEqual(self.get("Y"), (0, "multi\nMODEL=inside-quotes\n"), "other values stay intact")
        self.assertEqual(self.get("X"), (0, "a"))
        self.assertTrue(out.splitlines()[-1].startswith("IMAGE="), "the overrides are the last block")
        self.assertNotIn("from-example", out)
        self.assertNotIn("changeme", out)

    def test_refresh_repairs_alternate_assignments_and_keeps_secrets(self):
        self.assertEqual(self.run_render().returncode, 0)
        secret = self.get("SECRET")[1]
        with open(self.d / "out", "a") as f:
            f.write("export MODEL=evil\n  IMAGE=evil\nZ='z' URL=evil\n")
        self.assertEqual(self.get("MODEL"), (0, "evil"))
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.get("MODEL"), (0, "model-a"))
        self.assertEqual(self.get("IMAGE"), (0, "vx/p@sha256:" + "a" * 64))
        self.assertEqual(self.get("SECRET"), (0, secret))
        self.assertEqual(self.get("URL"), (0, f"https://{self.get('USER')[1]}:{secret}@h/"))
        before = self.out()
        self.assertEqual(self.run_render("--refresh").returncode, 0)
        self.assertEqual(self.out(), before, "a second refresh changes nothing")

    def test_refresh_checks_secret_format(self):
        user = "Ab3dEf6hIj9k"
        for value, why in (("password1234", "is shorter than 16 characters"),
                           ("0" * 48, "fewer than 8 different characters"),
                           ("abcd" * 5, "fewer than 8 different characters"), ("", "is empty")):
            (self.d / "out").write_text(f"SECRET={value}\nUSER={user}\n")
            r = self.run_render("--refresh")
            self.assertEqual(r.returncode, 2, value)
            self.assertIn(why, r.stderr, value)
            self.assertIn("change the user's password there too", r.stderr)

    def test_refresh_keeps_strong_secrets_made_elsewhere(self):
        # What the upstream installers write: pentagi an 18-character DB password and a 32-hex salt,
        # ARTEX a 24-character password and (also accepted by ARTEX) a 64-hex key.
        (self.d / "ov").write_text("DBPASS=@hex24\nHEXSEED=@hex32\nAPW=@hex24\nKEY=@b64_32\nODD=@hex16\n")
        (self.d / "ex").write_text("DBPASS=postgres\nHEXSEED=example\n")
        have = {"DBPASS": "Kq3vT8wZp2LmN5xR7y", "HEXSEED": "fedcba9876543210" + "0123456789abcdef",
                "APW": "aZ8kQ2mX5nB7vC1pL4rT9wYe", "KEY": "9c" + "0123456789abcdef" * 3 + "f1e2d3c4b5a69788",
                "ODD": "p@ss w0rd$#\"q'!xyz"}   # odd characters: kept and written back quoted
        (self.d / "out").write_text("".join(f"{k}={v}\n" for k, v in have.items() if k != "ODD")
                                    + "ODD='p@ss w0rd$#\"q\\'!xyz'\n")
        self.assertEqual(self.get("ODD")[1], "p@ss w0rd$#\"q'!xyz", "test setup")
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 0, r.stderr)
        for k, v in have.items():
            self.assertEqual(self.get(k), (0, v), k)
        self.assertEqual(self.run_render("--refresh").returncode, 0, "the quoted value reads back the same")
        self.assertEqual(self.get("ODD"), (0, have["ODD"]))

    def test_refresh_renews_weak_renewable_secrets(self):
        (self.d / "ov").write_text("SECRET=@hex24\nUSER=@alnum12 renewable\nURL=https://${USER}:${SECRET}@h/\n")
        secret = "0123456789abcdef" * 3
        (self.d / "out").write_text(f"SECRET={secret}\nUSER=abc\nURL=old\n")
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("renewed USER", r.stdout)
        user = self.get("USER")[1]
        self.assertRegex(user, r"^[A-Za-z0-9]{12}$")
        self.assertEqual(self.get("SECRET"), (0, secret))
        self.assertEqual(self.get("URL"), (0, f"https://{user}:{secret}@h/"))
        (self.d / "out").write_text(f"SECRET=abc\nUSER={user}\n")      # not renewable: still refused
        self.assertEqual(self.run_render("--refresh").returncode, 2)

    def test_renewable_secret_is_kept_only_in_its_generator_format(self):
        # Long and varied, but not what @alnum12 makes: a renewable value is rebuilt into other values
        # (here URL), so a planted "x@evil.example/" must be replaced, never kept.
        (self.d / "ov").write_text("SECRET=@hex24\nUSER=@alnum12 renewable\nURL=https://${USER}:${SECRET}@h/\n")
        secret = "0123456789abcdef" * 3
        for planted in ("x@scrape.attacker.example/", "password12345678"):
            (self.d / "out").write_text(f"SECRET={secret}\nUSER={planted}\nURL=old\n")
            r = self.run_render("--refresh")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("renewed USER", r.stdout, planted)
            user = self.get("USER")[1]
            self.assertRegex(user, r"^[A-Za-z0-9]{12}$")
            self.assertEqual(self.get("URL"), (0, f"https://{user}:{secret}@h/"))

    def test_strong_secret_with_a_newer_unicode_character_is_kept_on_any_python(self):
        # U+1FAE0 is Unicode 14: unassigned (Cn) in the Mac's Python 3.9 tables, a symbol in newer ones.
        value = "Kq3vT8wZp2LmN5xR" + chr(0x1FAE0)
        (self.d / "ov").write_text("SECRET=@hex24\nUSER=@alnum12\n")
        (self.d / "out").write_text(f"SECRET={value}\nUSER=Ab3dEf6hIj9k\n")
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.get("SECRET"), (0, value))
        (self.d / "out").write_text(f"SECRET={value}\ufffe\nUSER=Ab3dEf6hIj9k\n")   # a noncharacter: refused
        self.assertEqual(self.run_render("--refresh").returncode, 2)

    def test_refresh_refuses_the_example_value(self):
        upstream = "0123456789abcdef" * 3                     # well-formed, but published upstream
        (self.d / "ex").write_text(f"SECRET={upstream}\n")
        (self.d / "out").write_text(f"SECRET={upstream}\nUSER=Ab3dEf6hIj9k\n")
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 2)
        self.assertIn("SECRET is still the upstream example value", r.stderr)

    def test_refresh_adds_missing_generated_key(self):
        secret = "0123456789abcdef" * 3
        (self.d / "out").write_text(f"SECRET={secret}\nMODEL=old\n")
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("added", r.stdout)
        self.assertIn("USER", r.stdout)
        self.assertEqual(self.get("SECRET"), (0, secret))
        user = self.get("USER")[1]
        self.assertRegex(user, r"^[A-Za-z0-9]{12}$")
        self.assertEqual(self.get("URL"), (0, f"https://{user}:{secret}@h/"))

    def test_render_refuses_a_value_compose_would_change(self):
        (self.d / "ov").write_text("LITERAL=a$HOME\n")
        r = self.run_render()
        self.assertEqual(r.returncode, 2)
        self.assertIn("LITERAL wouldn't read back as rendered", r.stderr)
        self.assertFalse((self.d / "out").exists())

    def test_out_must_be_a_regular_file(self):
        (self.d / "out").mkdir()
        r = self.run_render("--refresh")
        self.assertEqual(r.returncode, 2)
        self.assertIn("isn't a regular file", r.stderr)


if __name__ == "__main__":
    unittest.main()
