# M4 — YARA Rule Generator

Auto-generate real YARA rules from malware features (**printable strings** and
**byte n-grams**), then **validate them in-process** over a malicious + clean
corpus and report **precision / recall / f1**. Fully offline, **stdlib-only —
no yara-python required**.

## What genuinely works

- **Feature extraction** — printable ASCII + UTF-16LE string extraction with
  offset/length/entropy/frequency, plus byte **n-gram** extraction ranked by
  frequency (skipping trivial all-zero/0xff/0x90 runs).
- **Rule generation** — emits valid, self-contained `.yar` files with two rule
  families per sample: a *string* rule (top distinctive strings, hex patterns
  by default) and an *n-gram* rule (top byte bigrams/4-grams as `{ 4D 5A .. }`
  patterns). Rules are written individually and to `all_rules.yar`.
- **In-process evaluator** — a YARA-subset engine that matches rules against
  bytes directly in Python (text substrings and byte patterns with single-byte
  wildcards), supporting `any of them` / `N of them` / `all of them`
  conditions. No external `yara` dependency.
- **Corpus evaluation with precision/recall** — point `evaluate` at a
  `corpus/<malware|clean>/` tree and get true/false positives & negatives plus
  precision, recall and F1, written to a gitignored report.
- **Seeded corpus** — `demo` builds a small synthetic `malware/` + `clean/`
  corpus and reports closed-set precision/recall.

Dependencies: **Python 3 stdlib only** (`re`, `hashlib`, `json`, `collections`,
`math`, `argparse`, `dataclasses`).

## Usage

```bash
python3 firmware/yara_gen.py --help

# Offline demo (exits 0): seed corpus, generate rules, evaluate precision/recall
python3 firmware/yara_gen.py demo

# Generate rules + .yar files from one sample
python3 firmware/yara_gen.py generate sample.bin -o reports/yara

# Evaluate a rules.yar against a corpus (corpus/malware/*, corpus/clean/*)
python3 firmware/yara_gen.py evaluate reports/yara/all_rules.yar \
    --corpus reports/demo/corpus -o reports/eval.json
```

### Offline demo exit codes

```bash
python3 firmware/yara_gen.py demo --workdir reports/demo   # exits 0
python3 firmware/yara_gen.py generate <sample> -o out      # exits 0
python3 firmware/yara_gen.py evaluate <rules> --corpus c/  # exits 0
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

11 stdlib `unittest` cases covering string and n-gram extraction, the in-process
YARA-subset evaluator (text + byte patterns, match/no-match), rule-generation
round-trips, corpus precision/recall over the seeded fixture set, and CLI exit
codes.

## Live Lab Test Plan

1. In an offline lab VM run `python3 firmware/yara_gen.py demo` and confirm it
   exits 0 with a precision/recall report.
2. Generate rules from a sample you crafted (`generate sample.bin`) and
   confirm each produced `.yar` file parses back (`evaluate`) and matches its
   own sample.
3. Build a larger labelled corpus of your own and confirm precision/recall
   degrade predictably as you add near-duplicate clean files.
4. Only ever analyze samples you own or are authorized to hold.

## Metrics

- Extractors: printable strings (ASCII + UTF-16LE) and byte n-grams.
- Rule families: `malware_strings_*`, `malware_ngrams_*`; output as individual
  `.yar` files plus `all_rules.yar`.
- Evaluator: in-process YARA subset (no yara-python).
- Corpus metrics: true/false positives, true/false negatives, precision,
  recall, F1.
- Test count: 11 stdlib unittest cases.
- Dependencies: Python 3 stdlib only.

## IMPORTANT: Read before use.

This tool is for **educational and authorized analysis only** — it reads files
you own or are authorized to examine and generates signature rules from their
content. The bundled corpus is entirely synthetic and inert. Do not scan
third-party binaries or networks without authorization. Do not rely on the
generated rules for production detection without validation on a larger,
representative corpus. The author is not responsible for misuse.

## License

MIT — see `LICENSE`.