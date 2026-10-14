"""Every shipped recipe is valid, lint-clean, uniquely named, and refers to products Pulse recognises."""
import json
import unittest
from pathlib import Path

import catalog
import recipes

DIR = Path(__file__).resolve().parent.parent / "recipes"


class BuiltinRecipeTests(unittest.TestCase):
    def files(self):
        fs = sorted(DIR.glob("*.json"))
        self.assertGreaterEqual(len(fs), 9)
        return fs

    def test_all_valid_and_lint_clean(self):
        for f in self.files() + [DIR / "example-local-recipe.json.disabled"]:
            r = recipes.validate(json.loads(f.read_text()))
            self.assertEqual(recipes.lint(r), [], f.name)

    def test_ids_match_file_names_and_are_unique(self):
        ids = [json.loads(f.read_text())["id"] for f in self.files()]
        self.assertEqual(ids, [f.stem for f in self.files()])
        self.assertEqual(len(ids), len(set(ids)))

    def test_products_are_ones_pulse_recognises(self):
        known = {r[1] for r in catalog.RULES} | {"DNS + ad blocking"}
        for f in self.files():
            for p in json.loads(f.read_text())["when"].get("product", []):
                self.assertIn(p, known, f"{f.name}: product {p!r} is never produced by discovery")

    def test_every_recipe_has_a_description(self):
        for f in self.files():
            self.assertGreater(len(json.loads(f.read_text()).get("description", "")), 20, f.name)

    def test_gate_check_mode_accepts_them(self):
        import subprocess
        import sys
        gate = DIR.parent / "heal" / "pulse-heal-gate"
        p = subprocess.run([sys.executable, str(gate), "--check", *map(str, self.files())], capture_output=True, text=True,
                           env={"PULSE_HEAL_LIB": str(DIR.parent / "pulse"), "PATH": "/usr/bin:/bin"})
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
