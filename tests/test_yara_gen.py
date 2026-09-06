#!/usr/bin/env python3
"""Tests for m4-yara-gen."""
import json
import os
import subprocess
import sys
import unittest
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "firmware"))
import yara_gen as yg

SCRIPT = os.path.join(ROOT, "firmware", "yara_gen.py")


class TestFeatureExtraction(unittest.TestCase):
    def setUp(self):
        self.fe = yg.FeatureExtractor()

    def test_string_extraction(self):
        data = b"\x00prefix http://x.example/stage.exe suffix\x00"
        strings = self.fe.extract_strings(data)
        joined = "|".join(s.value for s in strings)
        self.assertIn("http://x.example/stage.exe", joined)

    def test_ngram_extraction(self):
        data = (b"A9EA8951234D" * 32) + b"payload.."  # high-frequency repeated
        ngrams = self.fe.extract_ngrams(data, n=4, top=8)
        self.assertTrue(ngrams)
        top = ngrams[0]
        self.assertGreaterEqual(top.occurrences, 8)


class TestYaraEvaluator(unittest.TestCase):
    def setUp(self):
        self.rs = yg.RuleSet()
        r = yg.YaraRule(name="t1", meta={},
                        strings=[("$a", "text", '"hello_bad"'),
                                 ("$b", "text", '"exfil_url"')],
                        condition="any of them", confidence=0.5,
                        raw_rule="rule t1 {}")
        self.rs.add_rule(r)

    def test_match_content(self):
        self.assertEqual(self.rs.match_bytes(b"xx hello_bad yy"),
                         ["t1"])
        self.assertEqual(self.rs.match_bytes(b"xx exfil_url yy"),
                         ["t1"])

    def test_no_match(self):
        self.assertEqual(self.rs.match_bytes(b"xx clean yy"), [])

    def test_byte_pattern(self):
        rs = yg.RuleSet()
        r = yg.YaraRule(name="t2", meta={},
                        strings=[("$a", "byte", "4D 5A 90 00")],
                        condition="any of them", confidence=0.5,
                        raw_rule="rule t2 {}")
        rs.add_rule(r)
        self.assertEqual(rs.match_bytes(b"\x4d\x5a\x90\x00de"),
                         ["t2"])
        self.assertEqual(rs.match_bytes(b"abcd"), [])


class TestRuleGeneration(unittest.TestCase):
    def test_generate_roundtrip(self):
        gen = yg.RuleGenerator()
        data = b"MZ" + b"\x90" * 4 + b"DownloadAndExec http://m.example/stage " \
               b"CreateThread VirtualAlloc exfil_xor_beacon"
        rules = gen.generate(data, "sample.bin")
        self.assertTrue(rules)
        # every rule must self-match its own raw bytes
        for r in rules:
            rs = yg.RuleSet()
            rs.add_rule(r)
            self.assertIn(r.name, rs.match_bytes(data))

    def test_yar_file_parses_back(self):
        gen = yg.RuleGenerator()
        data = b"evil dropper http://b.example/drop VirtualAlloc exfil_n"
        rules = gen.generate(data, "s.bin")
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.yar")
            with open(path, "w") as f:
                f.write(rules[0].raw_rule)
            parsed = yg.parse_yar(path)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0].name, rules[0].name)


class TestCorpusEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp()
        yg.seed_corpus(os.path.join(cls.td, "corpus"))

    def test_precision_recall(self):
        corpus = os.path.join(self.td, "corpus")
        gen = yg.RuleGenerator()
        ruleset = yg.RuleSet()
        for name, data in yg.load_corpus(corpus)["malware"]:
            for r in gen.generate(data, name):
                ruleset.add_rule(r)
        ev = yg.evaluate_corpus(corpus, ruleset)
        self.assertGreaterEqual(ev.true_positives, 1)
        self.assertEqual(ev.false_negatives, 0)
        self.assertGreaterEqual(ev.malware_total, 3)
        self.assertLess(ev.false_positives, ev.clean_total)
        self.assertTrue(0 <= ev.precision <= 1)
        self.assertTrue(0 <= ev.recall <= 1)


class TestCLI(unittest.TestCase):
    def test_help(self):
        r = subprocess.run([sys.executable, SCRIPT, "--help"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)

    def test_demo_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run([sys.executable, SCRIPT, "demo",
                                "--workdir", td],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("precision", r.stdout.lower())
            self.assertIn("exit=0", r.stdout)

    def test_generate_cli(self):
        with tempfile.TemporaryDirectory() as td:
            sample = os.path.join(td, "s.bin")
            with open(sample, "wb") as f:
                f.write(b"MZexfil DownloadAndExec http://m.example/stage CreateThread")
            out = os.path.join(td, "out")
            r = subprocess.run([sys.executable, SCRIPT, "generate",
                                sample, "-o", out],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("rule(s)", r.stdout)
            self.assertTrue(os.path.exists(os.path.join(out, "all_rules.yar")))


if __name__ == "__main__":
    unittest.main()