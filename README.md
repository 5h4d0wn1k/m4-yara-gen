# M4 — YARA Rule Generator

Auto-generate YARA rules from malware features with string extraction and entropy analysis.

## Overview

This project implements a YARA rule generator that:
- Extracts and categorizes strings from malware samples
- Selects high-value features (URLs, API calls, registry keys, etc.)
- Clusters related strings by category
- Generates optimized YARA rules with confidence scoring
- Validates rules with yara-python
- Performs entropy analysis on the sample
- Generates both individual and combined rule files

## Features

- **String Extraction**: ASCII and Unicode string extraction with offset tracking
- **Feature Selection**: Score and rank strings by malware relevance
- **String Clustering**: Group related strings by category (network, API, crypto, etc.)
- **Rule Generation**: Create valid YARA rules with proper conditions
- **Confidence Scoring**: Rate rule quality based on feature indicators
- **Rule Validation**: Verify rules compile with yara-python
- **Entropy Analysis**: Detect encrypted/compressed regions
- **Export**: Individual .yar files and combined rule set

## Installation

```bash
pip install yara-python
```

## Usage

```bash
# Basic rule generation
python3 yara_gen.py malware_sample.exe

# Custom output and confidence
python3 yara_gen.py malware.exe -o ./rules --min-confidence 0.3

# With hex patterns
python3 yara_gen.py sample.bin --hex-patterns

# Limit strings per rule
python3 yara_gen.py sample.exe --max-strings 30
```

## Example Output

```
============================================================
  M4 — YARA Rule Generator — Report
============================================================
  File:         malware.exe
  Size:         245760 bytes
  MD5:          abc123...
  SHA256:       def456...
  Entropy:      6.42
  Rules:        3
------------------------------------------------------------
  Generated Rules:
    [malware_cluster_000] confidence=0.85
      Auto-generated rule from cluster 0
      Strings: 8
    [malware_cluster_001] confidence=0.62
      Auto-generated rule from cluster 1
      Strings: 5
============================================================
```

## Architecture

```
m4-yara-gen/
├── firmware/
│   ├── yara_gen.py       # Main YARA rule generator
│   ├── yara_output/      # Generated rules directory
│   │   ├── rules/        # Individual .yar files
│   │   └── all_rules.yar # Combined rule file
├── README.md
└── requirements.txt
```

## How It Works

1. **File Analysis**: Compute hashes and entropy for the sample
2. **String Extraction**: Extract ASCII and Unicode strings with metadata
3. **Feature Selection**: Score strings by relevance (URLs, APIs, crypto, etc.)
4. **Clustering**: Group related strings by category
5. **Rule Generation**: Create YARA rules with optimized conditions
6. **Validation**: Verify rules compile with yara-python
7. **Export**: Save individual and combined rule files

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before generating detection rules
- YARA rules should only be created for malware analysis purposes
- This tool should ONLY be used on samples you own or have authorization to analyze

### Legal Framework
- **CFAA**: Unauthorized access to computer systems is a federal crime
- **DMCA**: Reverse engineering may have legal implications
- **Export Controls**: Security tools may be subject to export restrictions

### Acceptable Use
- Creating detection rules for known malware samples
- Academic research in controlled environments
- Authorized malware analysis with written scope
- Security education and training

### Prohibited Use
- Generating rules to evade existing detection
- Analyzing samples without proper authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

## License

MIT
