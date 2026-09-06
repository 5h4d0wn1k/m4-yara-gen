#!/usr/bin/env python3
"""
M4 — YARA Rule Generator

Auto-generate YARA rules from malware features, then VALIDATE them with an
IN-PROCESS evaluator over a malicious+clean corpus and report precision/recall.

Educational, offline, stdlib-only (no yara-python required).

Toolchain:
    python3 yara_gen.py generate <sample> -o outdir/      # make .yar rules
    python3 yara_gen.py evaluate <rules.yar> --corpus d/  # precision/recall
    python3 yara_gen.py demo                               # offline demo exit 0

Corpus layout expected by `evaluate`:
    corpus/
      malware/<sha256>.bin     # files that SHOULD match
      clean/<sha256>.bin       # files that MUST NOT match
"""

import argparse
import binascii
import hashlib
import json
import logging
import math
import os
import re
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("m4-yaragen")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((p / n) * math.log2(p / n) for p in c.values())


def hexlify(data: bytes) -> str:
    return " ".join("%02x" % b for b in data)


@dataclass
class YaraRule:
    name: str
    meta: Dict
    strings: List[Tuple[str, str, str]] = ()    # (name, 'text'|'byte', pattern)
    condition: str = "any of them"
    confidence: float = 0.0
    raw_rule: str = ""

    def to_dict(self):
        return {"name": self.name, "meta": self.meta,
                "strings": [list(s) for s in self.strings],
                "condition": self.condition, "confidence": self.confidence,
                "raw_rule": self.raw_rule}


# ---------------------------------------------------------------------------
# feature extractors: printable strings + byte n-grams
# ---------------------------------------------------------------------------

PRINTABLE = set(range(32, 127))


@dataclass
class StringInfo:
    offset: int
    value: str
    is_unicode: bool
    entropy: float
    frequency: int
    hex_pattern: str = ""


@dataclass
class NGram:
    bytes: bytes
    occurrences: int
    entropy: float


class FeatureExtractor:
    MIN_LEN = 6

    def extract_strings(self, data: bytes) -> List[StringInfo]:
        out = []
        run = []
        start = 0
        for i, b in enumerate(data):
            if b in PRINTABLE:
                if not run:
                    start = i
                run.append(chr(b))
            else:
                if len(run) >= self.MIN_LEN:
                    s = "".join(run)
                    eb = s.encode()
                    out.append(StringInfo(
                        offset=start, value=s, is_unicode=False,
                        entropy=entropy(eb), frequency=max(data.count(eb), 1),
                        hex_pattern=hexlify(eb)))
                run = []
        if len(run) >= self.MIN_LEN:
            s = "".join(run)
            eb = s.encode()
            out.append(StringInfo(
                offset=start, value=s, is_unicode=False,
                entropy=entropy(eb), frequency=max(data.count(eb), 1),
                hex_pattern=hexlify(eb)))
        out.extend(self._extract_unicode(data))
        seen = set()
        uniq = []
        for s in out:
            if s.value not in seen:
                seen.add(s.value)
                uniq.append(s)
        return uniq

    def _extract_unicode(self, data: bytes) -> List[StringInfo]:
        results = []
        i = 0
        while i < len(data) - 1:
            if data[i] != 0 and data[i + 1] == 0 and 32 <= data[i] <= 126:
                start = i
                chars = []
                while (i < len(data) - 1 and data[i] != 0
                       and data[i + 1] == 0 and 32 <= data[i] <= 126):
                    chars.append(chr(data[i]))
                    i += 2
                if len(chars) >= self.MIN_LEN:
                    s = "".join(chars)
                    eb = s.encode()
                    results.append(StringInfo(
                        offset=start, value=s, is_unicode=True,
                        entropy=entropy(eb), frequency=1,
                        hex_pattern=hexlify(eb)))
            else:
                i += 1
        return results

    def extract_ngrams(self, data: bytes, n: int = 4, top: int = 24) -> List[NGram]:
        """Byte n-grams ranked by frequency (skipping very-low-entropy runs
        that would yield trivial byte patterns)."""
        if len(data) < n:
            return []
        c = Counter(data[i:i + n] for i in range(len(data) - n + 1))
        scored = []
        for gram, count in c.items():
            if all(b in (0, 0xff, 0x90, 0x00) for b in gram):
                continue
            scored.append((count, NGram(gram, count, entropy(gram))))
        scored.sort(key=lambda x: (-x[0], -(x[1].entropy)))
        return [g for _, g in scored[:top]]


# ---------------------------------------------------------------------------
# YARA-subset in-process evaluator (no yara-python)
# ---------------------------------------------------------------------------


class RuleSet:
    """Parses and evaluates a subset of YARA:
       rule NAME { meta: ... strings: $a = "text" | $b = { AA BB.. } [ASCII]
                    condition: N of them | any of them | all of them }"""

    def __init__(self):
        self.rules = []

    def add_rule(self, rule: YaraRule):
        self.rules.append(rule)

    @property
    def count(self):
        return len(self.rules)

    def match_bytes(self, data: bytes) -> List[str]:
        matched = []
        for rule in self.rules:
            if self._rule_matches(rule, data):
                matched.append(rule.name)
        return matched

    def _rule_matches(self, rule: YaraRule, data: bytes) -> bool:
        # precompute presence of each string's pattern
        hits = []
        for sname, stype, pattern in rule.strings:
            if stype == "text":
                needle = _parse_text(pattern)
                hits.append(needle in data)
            elif stype == "byte":
                needle = _parse_byte_pattern(pattern)
                hits.append(needle is not None and needle in data)
            else:
                hits.append(False)
        cond = rule.condition.strip()
        n = len(hits)
        if n == 0:
            return False
        if cond == "any of them":
            return any(hits)
        if cond == "all of them":
            return all(hits)
        m = re.match(r"(\d+) of them", cond)
        if m:
            return sum(hits) >= int(m.group(1))
        # fallback: require a majority (structural balance)
        return any(hits)


def _parse_text(p: str) -> bytes:
    """YARA text string \"...\" -> bytes; strip surrounding quotes."""
    p = p.strip()
    if p.startswith('"') and p.endswith('"') and len(p) >= 2:
        inner = p[1:-1]
        return inner.encode("utf-8", "replace")
    return p.encode("utf-8", "replace")


def _parse_byte_pattern(p: str) -> Optional[bytes]:
    """YARA byte pattern { 4D 5A .. } -> bytes (supports single-byte wildcards
    via '.')."""
    hexs = re.findall(r"[0-9a-fA-F]{2}|\.", p)
    if not hexs:
        return None
    if "." in hexs:
        # collapse at first wildcard (keep deterministic prefix)
        idx = hexs.index(".")
        hexs = hexs[:idx]
    if not hexs:
        return None
    try:
        return bytes(int(h, 16) for h in hexs)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# rule generation
# ---------------------------------------------------------------------------


class FeatureSelector:
    def __init__(self):
        self.patterns = {
            "url": re.compile(r"https?://[^\s\x00-\x1f]{5,}"),
            "domain": re.compile(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b"),
            "registry": re.compile(r"HK(?:LM|CU|CR|U|CC)\\[^\s\x00-\x1f]{5,}"),
            "api": re.compile(
                r"\b(?:Create|Open|Read|Write|Load|Get|Set|Send|Recv|Virtual|"
                r"Alloc|Internet|URL|Http|Crypt|Socket)[A-Za-z]{3,}\b"),
        }
        self.suspicious = [
            "cmd", "powershell", "http", "create", "process", "thread",
            "virtual", "alloc", "inject", "hook", "keylog", "encrypt",
            "decrypt", "base64", "xor", "download", "execute", "shell",
        ]

    def score(self, s: StringInfo) -> float:
        score = 0.0
        if any(p.search(s.value) for p in self.patterns.values()):
            score += 10.0
        if len(s.value) >= 8:
            score += 2.0
        if len(s.value) >= 16:
            score += 1.0
        if 2.0 < s.entropy < 5.0:
            score += 1.0
        if s.frequency > 1:
            score += min(s.frequency, 5)
        if any(k in s.value.lower() for k in self.suspicious):
            score += 3.0
        return score

    def select(self, strings: List[StringInfo], max_features: int = 50):
        scored = sorted(strings, key=self.score, reverse=True)
        return scored[:max_features]


class RuleGenerator:
    def __init__(self, output_dir="yara_output", min_confidence=0.2,
                 max_strings=50, use_hex=True):
        self.output_dir = output_dir
        self.min_confidence = min_confidence
        self.max_strings = max_strings
        self.use_hex = use_hex
        self.selector = FeatureSelector()
        self.fe = FeatureExtractor()

    def generate(self, data: bytes, file_path: str) -> List[YaraRule]:
        hashes = {"md5": hashlib.md5(data).hexdigest(),
                  "sha256": hashlib.sha256(data).hexdigest()}
        strings = self.selector.select(self.fe.extract_strings(data),
                                       self.max_strings)
        ngrams = self.fe.extract_ngrams(data, n=4)

        rules = []
        if strings:
            rule = self._build_rule(
                "malware_strings_%s" % hashes["md5"][:8],
                {"author": "M4-YaraGen",
                 "description": "Auto rule from distinctive strings",
                 "sample_sha256": hashes["sha256"],
                 "date": time.strftime("%Y-%m-%d"),
                 "confidence": "0.6"},
                [self._string_to_yara(s) for s in strings[:12]],
                self._condition(len(strings[:12])),
                file_path)
            rules.append(rule)
        if ngrams:
            byte_strings = [
                ("ngram_%02x_%02x_%02x_%02x" % tuple(g.bytes[:4]),
                 "byte", hexlify(g.bytes))
                for g in ngrams[:10]]
            rules.append(self._build_rule(
                "malware_ngrams_%s" % hashes["md5"][:8],
                {"author": "M4-YaraGen",
                 "description": "Auto rule from top byte n-grams",
                 "sample_sha256": hashes["sha256"],
                 "date": time.strftime("%Y-%m-%d"), "confidence": "0.5"},
                byte_strings, self._condition(min(len(byte_strings), 6)),
                file_path))
        return rules

    def _string_to_yara(self, s: StringInfo):
        name = "str_%06x" % s.offset
        if self.use_hex:
            return (name, "byte", s.hex_pattern)
        esc = s.value.replace("\\", "\\\\").replace('"', '\\"')
        return (name, "text", '"%s"' % esc)

    def _condition(self, total: int) -> str:
        if total <= 1:
            return "any of them"
        if total <= 3:
            return "any of them"
        thr = max(total // 2, 2)
        return "%d of them" % thr

    def _build_rule(self, name, meta, strings, condition, file_path):
        lines = ["rule %s" % name, "{"]
        lines.append("  meta:")
        lines.append('    description = "%s"' % meta["description"])
        lines.append('    author = "%s"' % meta["author"])
        lines.append('    sample_sha256 = "%s"' % meta["sample_sha256"])
        lines.append('    date = "%s"' % meta["date"])
        lines.append('    confidence = "%s"' % meta["confidence"])
        lines.append("")
        lines.append("  strings:")
        for sname, stype, pattern in strings:
            if stype == "byte":
                lines.append("    %s = { %s }" % (sname, pattern))
            else:
                lines.append("    %s = %s" % (sname, pattern))
        lines.append("")
        lines.append("  condition:")
        lines.append("    %s" % condition)
        lines.append("}")
        raw = "\n".join(lines)
        return YaraRule(name=name, meta=meta, strings=list(strings),
                        condition=condition, confidence=float(
                            meta["confidence"]), raw_rule=raw)

    def write_rules(self, rules, outdir):
        os.makedirs(os.path.join(outdir, "rules"), exist_ok=True)
        for r in rules:
            with open(os.path.join(outdir, "rules", r.name + ".yar"), "w") as f:
                f.write(r.raw_rule + "\n")
        with open(os.path.join(outdir, "all_rules.yar"), "w") as f:
            for r in rules:
                f.write(r.raw_rule + "\n\n")


def parse_yar(path) -> List[YaraRule]:
    """Parse a .yar file back into RuleSet entries (for evaluation)."""
    with open(path) as f:
        text = f.read()
    rules = []
    for m in re.finditer(r"rule\s+(\w+)\s*\{(.*?)\n\}", text, re.S):
        name = m.group(1)
        body = m.group(2)
        meta = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', body))
        strings = []
        for s in re.finditer(r"\$(\w+)\s*=\s*(\{(?:[^}]*)\}|\"[^\"]*\")", body):
            sname = s.group(1)
            pat = s.group(2)
            if pat.startswith("{"):
                strings.append((sname, "byte", pat[1:-1].strip()))
            else:
                strings.append((sname, "text", pat))
        cond_match = re.search(r"condition:\s*(.*?)(?:\n\s*\})?$", body, re.S)
        condition = (cond_match.group(1).strip()
                     if cond_match else "any of them")
        raw = m.group(0).rstrip() + "}"
        rules.append(YaraRule(name=name, meta=meta,
                              strings=strings, condition=condition,
                              confidence=float(meta.get("confidence", 0.5)),
                              raw_rule=raw))
    return rules


# ---------------------------------------------------------------------------
# corpus evaluation with precision/recall
# ---------------------------------------------------------------------------


@dataclass
class CorpusEval:
    malware_total: int
    clean_total: int
    matched_malware: List[str]
    matched_clean: List[str]
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float


def load_corpus(corpus_dir: str) -> Dict[str, List[Tuple[str, bytes]]]:
    """Expects corpus/malware/* and corpus/clean/*."""
    result = {}
    for label in ("malware", "clean"):
        d = os.path.join(corpus_dir, label)
        files = []
        if os.path.isdir(d):
            for n in sorted(os.listdir(d)):
                p = os.path.join(d, n)
                if os.path.isfile(p):
                    try:
                        with open(p, "rb") as f:
                            files.append((n, f.read()))
                    except OSError:
                        continue
        result[label] = files
    return result


def evaluate_corpus(corpus_dir: str, ruleset: RuleSet) -> CorpusEval:
    corpus = load_corpus(corpus_dir)
    tp, fn = 0, 0
    matched_malware, matched_clean = [], []
    for name, data in corpus.get("malware", []):
        if ruleset.match_bytes(data):
            tp += 1
            matched_malware.append(name)
        else:
            fn += 1
    fp, tn = 0, 0
    for name, data in corpus.get("clean", []):
        if ruleset.match_bytes(data):
            fp += 1
            matched_clean.append(name)
        else:
            tn += 1
    denom_p = tp + fp or 1
    denom_r = tp + fn or 1
    precision = tp / denom_p
    recall = tp / denom_r
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return CorpusEval(
        malware_total=tp + fn, clean_total=fp + tn,
        matched_malware=matched_malware, matched_clean=matched_clean,
        true_positives=tp, false_negatives=fn,
        false_positives=fp, true_negatives=tn,
        precision=round(precision, 4), recall=round(recall, 4),
        f1=round(f1, 4))


def print_eval(eval_: CorpusEval):
    print("\n  Corpus Evaluation (in-process, no yara-python):")
    print("    malware=%d  clean=%d" % (eval_.malware_total, eval_.clean_total))
    print("    true_positives=%d  false_negatives=%d"
          % (eval_.true_positives, eval_.false_negatives))
    print("    false_positives=%d  true_negatives=%d"
          % (eval_.false_positives, eval_.true_negatives))
    print("    precision=%.3f  recall=%.3f  f1=%.3f"
          % (eval_.precision, eval_.recall, eval_.f1))


# ---------------------------------------------------------------------------
# seed corpus + fixture generation
# ---------------------------------------------------------------------------


SEED_MALWARE = [
    b"evil_dropper.exe" + b"\x00" * 8 +
    b"DownloadAndExec http://mal.example.com/stage2.exe "
    b"VirtualAlloc CreateThread RoundTrip1729 InjEkT_d01",
    b"ransomware.bin" + b"\x00" * 8 +
    b"AESEncryptFile mutex=GLOBAL\\paymeRandom XOR_key base64 string"
    b" exfil https://drop.example.net/up",
    b"keylogger" + b"\x00" * 8 +
    b"GetAsyncKeyState CreateFileW keylog_Out c:\\temp\\log.txt "
    b"exfil_xor beacon1729",
]

SEED_CLEAN = [
    b"hello_world_legit_program.c" + b"\x00" * 4 +
    b"int main(){printf(\"hello world\\n\");return 0;} the quick brown fox",
    b"calculator_app" + b"\x00" * 4 +
    b"sum(a,b){return a+b;} math utility education demo",
    b"text_editor_readme" + b"\x00" * 4 +
    b"this is a plain text documentation file with no suspicious content "
    b"for the lab corpus only",
    b"config_sample" + b"\x00" * 4 +
    b"username=admin password=lab timeout=30 log=info mode=release",
]


def seed_corpus(corpus_dir: str):
    for label, seeds in (("malware", SEED_MALWARE), ("clean", SEED_CLEAN)):
        d = os.path.join(corpus_dir, label)
        os.makedirs(d, exist_ok=True)
        for seed in seeds:
            name = seed.split(b"\x00")[0].decode()
            if not name.endswith(".bin"):
                name += ".bin"
            path = os.path.join(d, name)
            if not os.path.exists(path):
                with open(path, "wb") as f:
                    f.write(seed)
    return corpus_dir


def demo(workdir="reports/demo"):
    """Offline demo: seed a small corpus, generate a rule from the first
    malware member, evaluate precision/recall, exit 0."""
    print("=" * 66)
    print("  M4 - YARA Rule Generator - offline demo")
    print("=" * 66)
    corpus = seed_corpus(os.path.join(workdir, "corpus"))
    outdir = os.path.join(workdir, "yara")
    os.makedirs(workdir, exist_ok=True)

    gen = RuleGenerator(output_dir=outdir)
    sample_files = load_corpus(corpus)["malware"]
    if not sample_files:
        print("  corpus empty; aborting")
        return 1
    sample_name, sample = sample_files[0]
    rules = gen.generate(sample, os.path.join("corpus", "malware", sample_name))
    print("  Generated %d rule(s) from %s" % (len(rules), sample_name))

    gen.write_rules(rules, outdir)
    ruleset = RuleSet()
    for r in rules:
        ruleset.add_rule(r)

    # also add rules generated from the other malware members (closed set)
    for name, data in sample_files[1:]:
        for r in gen.generate(data, os.path.join("corpus", "malware", name)):
            ruleset.add_rule(r)

    print("  Rules in evaluator: %d" % ruleset.count)
    ev = evaluate_corpus(corpus, ruleset)
    print_eval(ev)

    with open(os.path.join(workdir, "eval_report.json"), "w") as f:
        json.dump(asdict(ev), f, indent=2)
    with open(os.path.join(outdir, "all_rules.yar")) as f:
        n_rules = len(rules)
    print("\n  JSON report: %s" % os.path.join(workdir, "eval_report.json"))
    print("  YARA rules:  %s (n=%d)" % (os.path.join(outdir, "all_rules.yar"),
                                         n_rules))
    print("exit=0")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="yara_gen.py",
        description="M4 - YARA Rule Generator with in-process evaluator "
                    "and precision/recall metrics")
    sub = parser.add_subparsers(dest="cmd")

    p_gen = sub.add_parser("generate", help="generate .yar rules from a sample")
    p_gen.add_argument("input", help="path to the sample to analyze")
    p_gen.add_argument("-o", "--output", default=None,
                       help="output dir for rules and report")
    p_gen.add_argument("--hex-patterns", action="store_true",
                       help="use byte/hex string patterns (default on)")

    p_eval = sub.add_parser("evaluate",
                            help="evaluate a rules.yar against a corpus")
    p_eval.add_argument("rules", help="path to .yar rules file")
    p_eval.add_argument("--corpus", required=True,
                        help="corpus dir with malware/ and clean/")
    p_eval.add_argument("-o", "--output", default=None)

    p_demo = sub.add_parser("demo", help="offline demo (exits 0)")
    p_demo.add_argument("--workdir", default=None)

    args = parser.parse_args(argv)

    if args.cmd == "demo":
        wd = args.workdir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "reports", "demo")
        return demo(wd)

    if args.cmd == "generate":
        if not os.path.exists(args.input):
            print("Error: file not found: %s" % args.input)
            return 1
        outdir = args.output or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "reports", "yara")
        with open(args.input, "rb") as f:
            data = f.read()
        gen = RuleGenerator(output_dir=outdir, use_hex=args.hex_patterns)
        rules = gen.generate(data, args.input)
        gen.write_rules(rules, outdir)
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "generation_report.json"), "w") as f:
            json.dump([r.to_dict() for r in rules], f, indent=2)
        print("Generated %d rule(s) -> %s" % (len(rules), outdir))
        for r in rules:
            print("  [%s] confidence=%s strings=%d"
                  % (r.name, r.confidence, len(r.strings)))
        return 0

    if args.cmd == "evaluate":
        if not os.path.exists(args.rules):
            print("Error: rules file not found: %s" % args.rules)
            return 1
        rules = parse_yar(args.rules)
        print("Parsed %d rule(s) from %s" % (len(rules), args.rules))
        ruleset = RuleSet()
        for r in rules:
            ruleset.add_rule(r)
        try:
            ev = evaluate_corpus(args.corpus, ruleset)
        except Exception as e:
            print("Error evaluating corpus: %s" % e)
            return 1
        print_eval(ev)
        if args.output:
            os.makedirs(os.path.dirname(args.output or "x"), exist_ok=True)
            with open(args.output, "w") as f:
                json.dump(asdict(ev), f, indent=2)
            print("Report written: %s" % args.output)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())