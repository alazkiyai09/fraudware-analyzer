# YARA Rules for Fraudware Analyzer

This directory contains YARA rules for detecting known malware families.

## Rule Files

| File | Description | Families Covered |
|------|-------------|------------------|
| `banking_trojans.yar` | Banking trojan signatures | Zeus, SpyEye, Carberp, Citadel, Dyre, Dridex |
| `info_stealers.yar` | Information stealer signatures | Pony, Fareit, LokiBot, Azorult, RedLine, Raccoon |
| `ransomware.yar` | Ransomware signatures | WannaCry, Petya, Locky, Cerber, GandCrab, Ryuk, Maze |
| `rats.yar` | Remote Access Trojan signatures | PoisonIvy, Gh0st, DarkComet, njRAT, XtremeRAT |

## Usage

### Using with Fraudware Analyzer CLI

```bash
fraudware-analyzer yara-scan suspicious.exe --rules ./rules
```

### Using with Python API

```python
from fraudware_analyzer.yara_scanner import YARAScanner

# Initialize scanner with rules
scanner = YARAScanner(rules_path="./rules")

# Scan a file
matches = scanner.scan("suspicious.exe")

for match in matches:
    print(f"Rule: {match['rule']}")
    print(f"Tags: {match['tags']}")
```

## Adding Custom Rules

To add custom YARA rules:

1. Create a new `.yar` file in this directory
2. Follow the YARA rule syntax: https://yara.readthedocs.io/

Example rule:

```yara
rule MyCustomRule {
    meta:
        description = "My custom detection rule"
        author = "Your Name"
    strings:
        $suspicious = "suspicious_string" nocase
        $api = "VirtualAlloc" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}
```

## License

These rules are provided as-is for educational and research purposes.
