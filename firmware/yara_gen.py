#!/usr/bin/env python3
"""
M4 — YARA Rule Generator: Auto-generate YARA rules from malware features

Educational tool for creating YARA rules from malware samples.
"""

import os
import sys
import re
import json
import math
import hashlib
import argparse
import binascii
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import Counter

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraRule:
    name: str
    meta: Dict
    strings: List[Tuple[str, str, str]]
    condition: str
    raw_rule: str
    confidence: float


@dataclass
class StringInfo:
    offset: int
    value: str
    hex_pattern: Optional[str]
    is_unicode: bool
    entropy: float
    frequency: int


@dataclass
class AnalysisReport:
    file_path: str
    file_size: int
    md5: str
    sha256: str
    total_entropy: float
    rules_generated: int
    rules: List[Dict]
    warnings: List[str]


class EntropyAnalyzer:
    @staticmethod
    def calculate(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def calculate_window(data: bytes, window_size: int = 256) -> List[float]:
        entropies = []
        for i in range(0, len(data), window_size):
            window = data[i:i + window_size]
            entropies.append(EntropyAnalyzer.calculate(window))
        return entropies


class StringExtractor:
    MIN_LENGTH = 6
    MAX_LENGTH = 256

    def extract(self, data: bytes) -> List[StringInfo]:
        strings = []
        current = []
        offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if self.MIN_LENGTH <= len(current) <= self.MAX_LENGTH:
                    s = ''.join(current)
                    freq = data.count(s.encode())
                    strings.append(StringInfo(
                        offset=offset, value=s,
                        hex_pattern=self._to_hex_pattern(s),
                        is_unicode=False,
                        entropy=self._calc_string_entropy(s),
                        frequency=max(freq, 1)
                    ))
                current = []
                offset = i + 1

        if self.MIN_LENGTH <= len(current) <= self.MAX_LENGTH:
            s = ''.join(current)
            strings.append(StringInfo(
                offset=offset, value=s,
                hex_pattern=self._to_hex_pattern(s),
                is_unicode=False, entropy=self._calc_string_entropy(s), frequency=1
            ))

        unicode_strings = self._extract_unicode(data)
        strings.extend(unicode_strings)

        return self._deduplicate(strings)

    def _extract_unicode(self, data: bytes) -> List[StringInfo]:
        results = []
        i = 0
        while i < len(data) - 1:
            if data[i] != 0 and data[i + 1] == 0 and 32 <= data[i] <= 126:
                start = i
                chars = []
                while i < len(data) - 1 and data[i] != 0 and data[i + 1] == 0 and 32 <= data[i] <= 126:
                    chars.append(chr(data[i]))
                    i += 2
                if len(chars) >= self.MIN_LENGTH:
                    s = ''.join(chars)
                    results.append(StringInfo(
                        offset=start, value=s,
                        hex_pattern=self._to_hex_pattern(s),
                        is_unicode=True,
                        entropy=self._calc_string_entropy(s),
                        frequency=1
                    ))
            else:
                i += 1
        return results

    def _to_hex_pattern(self, s: str) -> str:
        return ' '.join(f'{ord(c):02X}' for c in s)

    def _calc_string_entropy(self, s: str) -> float:
        counter = Counter(s)
        length = len(s)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _deduplicate(self, strings: List[StringInfo]) -> List[StringInfo]:
        seen = set()
        unique = []
        for s in strings:
            if s.value not in seen:
                seen.add(s.value)
                unique.append(s)
        return unique


class FeatureSelector:
    def __init__(self):
        self.high_value_categories = {
            'urls': re.compile(r'https?://[^\s\x00-\x1f]{6,}'),
            'domains': re.compile(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b'),
            'file_paths': re.compile(r'[A-Z]:\\[^\s\x00-\x1f]{6,}|/(?:usr|etc|var|tmp|home)/[^\s\x00-\x1f]{6,}'),
            'registry_keys': re.compile(r'HK(?:LM|CU|CR|U|CC)\\[^\s\x00-\x1f]{6,}'),
            'api_calls': re.compile(r'\b(?:Create|Open|Read|Write|Load|Get|Set|Send|Recv|Virtual|Alloc|Internet|URL|Http|Crypt)[A-Za-z]{4,}\b'),
            'crypto_constants': re.compile(r'(?:AES|RSA|DES|RC4|MD5|SHA1|SHA256|HMAC)[A-Z][a-z]+[A-Z][a-zA-Z]*'),
            'mutex_names': re.compile(r'[A-Za-z0-9_]{8,32}'),
        }

    def select_features(self, strings: List[StringInfo], max_features: int = 50) -> List[StringInfo]:
        scored = []
        for s in strings:
            score = self._score_string(s)
            scored.append((score, s))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:max_features]]

    def _score_string(self, s: StringInfo) -> float:
        score = 0.0
        for cat, pattern in self.high_value_categories.items():
            if pattern.search(s.value):
                score += 10.0
                break

        if len(s.value) >= 8:
            score += 2.0
        if len(s.value) >= 16:
            score += 1.0

        if 2.0 < s.entropy < 5.0:
            score += 1.0

        if s.frequency > 1:
            score += min(s.frequency, 5)

        suspicious = ['cmd', 'powershell', 'http', 'create', 'process', 'thread',
                      'virtual', 'alloc', 'inject', 'hook', 'keylog', 'encrypt',
                      'decrypt', 'base64', 'xor', 'download', 'execute', 'shell']
        for sus in suspicious:
            if sus.lower() in s.value.lower():
                score += 3.0
                break

        return score


class YaraRuleGenerator:
    def __init__(self, args):
        self.input_path = args.input
        self.output_dir = args.output or os.path.join(
            os.path.dirname(self.input_path) or '.', 'yara_output'
        )
        self.min_confidence = args.min_confidence
        self.max_strings_per_rule = args.max_strings
        self.use_hex_patterns = args.hex_patterns

        os.makedirs(self.output_dir, exist_ok=True)

        self.string_extractor = StringExtractor()
        self.feature_selector = FeatureSelector()
        self.entropy_analyzer = EntropyAnalyzer()

    def _compute_hashes(self, data: bytes) -> Dict[str, str]:
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }

    def _sanitize_rule_name(self, name: str) -> str:
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        if sanitized[0].isdigit():
            sanitized = 'rule_' + sanitized
        return sanitized

    def _string_to_yara(self, s: StringInfo) -> Tuple[str, str, str]:
        name = f'str_{s.offset:06x}'
        if self.use_hex_patterns and s.hex_pattern:
            pattern = s.hex_pattern
            return name, 'hex', pattern
        escaped = s.value.replace('\\', '\\\\').replace('"', '\\"')
        return name, 'text', f'"{escaped}"'

    def _generate_condition(self, num_strings: int) -> str:
        if num_strings <= 3:
            return 'any of them'
        elif num_strings <= 6:
            return '3 of them'
        elif num_strings <= 12:
            return f'math.min(5, {num_strings // 2}) of them'
        else:
            threshold = max(num_strings // 3, 4)
            return f'{threshold} of them'

    def _validate_yara_rule(self, rule_str: str) -> Tuple[bool, str]:
        if not YARA_AVAILABLE:
            return True, "yara-python not installed, skipping validation"
        try:
            yara.compile(source=rule_str)
            return True, "Valid"
        except yara.SyntaxError as e:
            return False, str(e)

    def _build_rule(self, name: str, meta: Dict, strings: List[Tuple[str, str, str]],
                    condition: str) -> str:
        lines = [f'rule {name}']
        if meta:
            lines.append('{')
            lines.append('  meta:')
            for k, v in meta.items():
                val = str(v).replace('"', '\\"')
                lines.append(f'    {k} = "{val}"')
            lines.append('')
            lines.append('  strings:')
            for sname, stype, spattern in strings:
                lines.append(f'    {sname} = {spattern}')
            lines.append('')
            lines.append(f'  condition:')
            lines.append(f'    {condition}')
            lines.append('}')
        else:
            lines[0] += ' {'
            lines.append('  strings:')
            for sname, stype, spattern in strings:
                lines.append(f'    {sname} = {spattern}')
            lines.append('')
            lines.append(f'  condition:')
            lines.append(f'    {condition}')
            lines.append('}')
        return '\n'.join(lines)

    def _generate_rules_from_clusters(self, selected_strings: List[StringInfo],
                                       data: bytes, hashes: Dict[str, str]) -> List[YaraRule]:
        rules = []

        string_clusters = self._cluster_strings(selected_strings)

        for i, cluster in enumerate(string_clusters):
            if not cluster:
                continue

            rule_name = f'malware_cluster_{i:03d}'
            meta = {
                'author': 'M4-YaraGen',
                'description': f'Auto-generated rule from cluster {i}',
                'sample_md5': hashes['md5'],
                'sample_sha256': hashes['sha256'],
                'date': __import__('datetime').datetime.now().strftime('%Y-%m-%d'),
                'confidence': str(self._calc_cluster_confidence(cluster))
            }

            yara_strings = []
            for s in cluster:
                yara_strings.append(self._string_to_yara(s))

            condition = self._generate_condition(len(yara_strings))

            raw_rule = self._build_rule(rule_name, meta, yara_strings, condition)

            is_valid, msg = self._validate_yara_rule(raw_rule)
            if not is_valid:
                continue

            confidence = self._calc_cluster_confidence(cluster)
            if confidence >= self.min_confidence:
                rules.append(YaraRule(
                    name=rule_name, meta=meta, strings=yara_strings,
                    condition=condition, raw_rule=raw_rule, confidence=confidence
                ))

        return rules

    def _cluster_strings(self, strings: List[StringInfo]) -> List[List[StringInfo]]:
        clusters = []
        current_cluster = []
        last_category = None

        categories = {
            'network': ['url', 'domain', 'http'],
            'filesystem': ['file', 'path', 'directory'],
            'registry': ['registry', 'hk', 'key'],
            'api': ['create', 'process', 'thread', 'virtual', 'alloc', 'load'],
            'crypto': ['crypt', 'encrypt', 'decrypt', 'hash', 'aes', 'rsa'],
            'persistence': ['run', 'startup', 'service', 'scheduled'],
        }

        def categorize(s: StringInfo) -> str:
            for cat, keywords in categories.items():
                for kw in keywords:
                    if kw.lower() in s.value.lower():
                        return cat
            return 'generic'

        for s in strings:
            cat = categorize(s)
            if cat != last_category and current_cluster:
                clusters.append(current_cluster)
                current_cluster = []
            current_cluster.append(s)
            last_category = cat

        if current_cluster:
            clusters.append(current_cluster)

        if len(clusters) == 1 and len(strings) > 10:
            mid = len(strings) // 2
            clusters = [strings[:mid], strings[mid:]]

        return clusters

    def _calc_cluster_confidence(self, cluster: List[StringInfo]) -> float:
        if not cluster:
            return 0.0

        score = 0.0
        total = len(cluster)

        network_indicators = sum(1 for s in cluster if 'http' in s.value.lower() or '://' in s.value)
        api_indicators = sum(1 for s in cluster if any(
            api in s.value.lower() for api in ['createprocess', 'virtualalloc', 'loadlibrary']
        ))

        score += min(network_indicators * 0.15, 0.4)
        score += min(api_indicators * 0.1, 0.3)
        score += min(total * 0.05, 0.3)

        avg_entropy = sum(s.entropy for s in cluster) / total
        if 2.0 < avg_entropy < 5.0:
            score += 0.1

        return min(score, 1.0)

    def run(self) -> AnalysisReport:
        logger.info(f"Analyzing: {self.input_path}")

        with open(self.input_path, 'rb') as f:
            data = f.read()

        hashes = self._compute_hashes(data)
        entropy = self.entropy_analyzer.calculate(data)
        logger.info(f"Entropy: {entropy:.2f}")
        logger.info(f"SHA256: {hashes['sha256']}")

        strings = self.string_extractor.extract(data)
        logger.info(f"Extracted {len(strings)} strings")

        selected = self.feature_selector.select_features(strings, self.max_strings_per_rule)
        logger.info(f"Selected {len(selected)} feature strings")

        rules = self._generate_rules_from_clusters(selected, data, hashes)
        logger.info(f"Generated {len(rules)} YARA rules")

        warnings = []
        if not rules:
            warnings.append("No rules generated - sample may lack distinctive features")
        if entropy > 7.0:
            warnings.append("High entropy detected - sample may be encrypted/compressed")
        if len(selected) < 5:
            warnings.append("Few distinctive strings found")

        rule_dir = os.path.join(self.output_dir, 'rules')
        os.makedirs(rule_dir, exist_ok=True)

        for rule in rules:
            rule_path = os.path.join(rule_dir, f'{rule.name}.yar')
            with open(rule_path, 'w') as f:
                f.write(rule.raw_rule)

        combined_path = os.path.join(self.output_dir, 'all_rules.yar')
        with open(combined_path, 'w') as f:
            for rule in rules:
                f.write(rule.raw_rule + '\n\n')

        report = AnalysisReport(
            file_path=self.input_path,
            file_size=len(data),
            md5=hashes['md5'],
            sha256=hashes['sha256'],
            total_entropy=entropy,
            rules_generated=len(rules),
            rules=[asdict(r) for r in rules],
            warnings=warnings
        )

        report_path = os.path.join(self.output_dir, 'generation_report.json')
        with open(report_path, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        logger.info(f"Report saved to: {report_path}")
        logger.info(f"Rules saved to: {rule_dir}")

        return report


def print_report(report: AnalysisReport):
    print("\n" + "=" * 60)
    print("  M4 — YARA Rule Generator — Report")
    print("=" * 60)
    print(f"  File:         {report.file_path}")
    print(f"  Size:         {report.file_size} bytes")
    print(f"  MD5:          {report.md5}")
    print(f"  SHA256:       {report.sha256}")
    print(f"  Entropy:      {report.total_entropy:.2f}")
    print(f"  Rules:        {report.rules_generated}")
    print("-" * 60)

    if report.rules:
        print("  Generated Rules:")
        for rule in report.rules:
            print(f"    [{rule['name']}] confidence={rule.get('confidence', 'N/A')}")
            if rule.get('meta', {}).get('description'):
                print(f"      {rule['meta']['description']}")
            print(f"      Strings: {len(rule.get('strings', []))}")

    if report.warnings:
        print("\n  Warnings:")
        for w in report.warnings:
            print(f"    [!] {w}")

    print("=" * 60)


logger = None


def main():
    global logger
    logging = __import__('logging')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(
        description='M4 — YARA Rule Generator'
    )
    parser.add_argument(
        'input', help='Path to malware sample'
    )
    parser.add_argument(
        '-o', '--output', help='Output directory for rules'
    )
    parser.add_argument(
        '--min-confidence', type=float, default=0.2,
        help='Minimum confidence threshold (0.0-1.0, default: 0.2)'
    )
    parser.add_argument(
        '--max-strings', type=int, default=50,
        help='Maximum strings per rule (default: 50)'
    )
    parser.add_argument(
        '--hex-patterns', action='store_true',
        help='Use hex patterns instead of text strings'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable verbose output'
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: File not found: {args.input}")
        sys.exit(1)

    generator = YaraRuleGenerator(args)
    report = generator.run()
    print_report(report)


if __name__ == '__main__':
    main()
