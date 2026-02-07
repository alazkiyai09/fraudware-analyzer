# Fraudware Analyzer - Architecture

## Overview

Fraudware Analyzer is a static analysis framework for detecting and classifying banking trojans and other malware through API call sequence analysis, string extraction, and YARA rule matching.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Fraudware Analyzer System                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                            INPUT LAYER                                 │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐      │  │
│  │  │ PE Files   │  │ Memory     │  │ Strings    │  │ YARA       │      │  │
│  │  │ (.exe)     │  │ Dumps      │  │ Dump       │  │ Rules      │      │  │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘      │  │
│  └────────┼─────────────┼─────────────┼─────────────┼────────────┘       │  │
│           │             │             │             │                      │
│           ▼             ▼             ▼             ▼                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                          EXTRACTION LAYER                             │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐     │  │
│  │  │ PE Parser  │  │ API        │  │ String     │  │ Resource   │     │  │
│  │  │            │  │ Extractor  │  │ Extractor  │  │ Extractor  │     │  │
│  │  │ - Headers  │  │ - IAT      │  │ - ASCII    │  │ - Icons    │     │  │
│  │  │ - Sections │  │ - EAT      │  │ - Unicode  │  │ - Bitmaps  │     │  │
│  │  │ - Imports  │  │ - Delay    │  │ - URLs    │  │ - Menus    │     │  │
│  │  │ - Exports  │  │ - Ordinal  │  │ - IPs     │  │ - Version  │     │  │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘     │  │
│  └────────┼─────────────┼─────────────┼─────────────┼────────────┘       │  │
│           │             │             │             │                      │
│           ▼             ▼             ▼             ▼                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                           ANALYSIS LAYER                              │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐     │  │
│  │  │ Sequence   │  │ Pattern    │  │ ML         │  │ Behavior   │     │  │
│  │  │ Analysis   │  │ Matching   │  │ Classifier │  │ Profiler   │     │  │
│  │  │            │  │            │  │            │  │            │     │  │
│  │  │ - n-grams  │  │ - Known    │  │ - Random   │  │ - Network  │     │  │
│  │  │ - Frequenc │  │   Signatur │  │   Forest   │  │ - File     │     │  │
│  │  │ - Ordering │  │ - Familie  │  │ - XGBoost  │  │ - Registry │     │  │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘     │  │
│  └────────┼─────────────┼─────────────┼─────────────┼────────────┘       │  │
│           │             │             │             │                      │
│           ▼             ▼             ▼             ▼                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                          REPORTING LAYER                             │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐     │  │
│  │  │ JSON       │  │ HTML       │  │ PDF        │  │ STIX       │     │  │
│  │  │ Report     │  │ Report     │  │ Report     │  │ Format     │     │  │
│  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### PE Parser Module

```
┌─────────────────────────────────────────────────────────────────┐
│                         PE Parser                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input: PE File (.exe, .dll)                                    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    DOS Header                            │   │
│  │  - e_magic: "MZ"                                         │   │
│  │  - e_lfanew: Offset to PE Header                         │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    PE Header                             │   │
│  │  - Signature: "PE\0\0"                                   │   │
│  │  - Machine: CPU type (e.g., 0x14c for i386)             │   │
│  │  - NumberOfSections: Number of sections                 │   │
│  │  - TimeDateStamp: Compilation timestamp                 │   │
│  │  - Characteristics: EXE flags                            │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Optional Header                         │   │
│  │  ┌──────────────────┐  ┌──────────────────┐             │   │
│  │  │    Standard      │  │   Windows        │             │   │
│  │  │    Fields        │  │   Specific       │             │   │
│  │  │  - EntryPoint    │  │  - ImageBase     │             │   │
│  │  │  - ImageSize     │  │  - StackReserve  │             │   │
│  │  └──────────────────┘  └──────────────────┘             │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Section Headers                         │   │
│  │  .text: Code section                                      │   │
│  │  .data: Initialized data                                  │   │
│  │  .rdata: Read-only data                                   │   │
│  │  .rsrc: Resources                                         │   │
│  │  .imports: Import tables                                  │   │
│  │  .exports: Export tables                                  │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  Output: Parsed structures, imports, exports, sections           │
└─────────────────────────────────────────────────────────────────┘
```

### API Extractor Module

```
┌─────────────────────────────────────────────────────────────────┐
│                       API Extractor                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input: Parsed PE File with Import Address Table                │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Import Directory Table                   │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │   │
│  │  | DLL 1    │  │ DLL 2    │  │ DLL N    │              │   │
│  │  | kernel32 │  │ wininet  │  │ ws2_32   │              │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘              │   │
│  └───────┼────────────┼────────────┼────────────────────────┘   │
│          ▼            ▼            ▼                             │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Import Lookup Table                      │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │   │
│  │  │ Create  │  │ Internet│  │ socket  │  │ connect │   │   │
│  │  │ File    │  │ Open    │  │         │  │         │   │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   API Categorization                      │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐│   │
│  │  │ Process  │  │ Network  │  │ Registry │  │ File     ││   │
│  │  │ APIs     │  │ APIs     │  │ APIs     │  │ APIs     ││   │
│  │  │ CreateP  │  │ Internet │  │ RegCreat │  │ CreateF  ││   │
│  │  │ WriteP   │  │ socket   │  │ RegSet   │  │ WriteF   ││   │
│  │  │ VirtualA │  │ connect  │  │ RegOpen  │  │ DeleteF  ││   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘│   │
│  │  ┌──────────┐  ┌──────────┐                             │   │
│  │  │ Crypto   │  │ GUI      │                             │   │
│  │  │ APIs     │  │ APIs     │                             │   │
│  │  │ CryptE   │  │ GetMessage│                             │   │
│  │  │ CryptD   │  │ SetWinH  │                             │   │
│  │  └──────────┘  └──────────┘                             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Sequence Building                         │   │
│  │  - Preserve call order from IAT                           │   │
│  │  - Build n-grams (bigrams, trigrams)                      │   │
│  │  - Count frequencies                                      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│  Output: API list, sequences, categories, frequencies             │
└─────────────────────────────────────────────────────────────────┘
```

### ML Classifier Module

```
┌─────────────────────────────────────────────────────────────────┐
│                       ML Classifier                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input: API sequences, strings, metadata                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Feature Extraction                       │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │ API-based Features                               │    │   │
│  │  │ - Total API count                                │    │   │
│  │  │ - Unique API count                               │    │   │
│  │  │ - Process API count                              │    │   │
│  │  │ - Network API count                              │    │   │
│  │  │ - Registry API count                             │    │   │
│  │  │ - File API count                                 │    │   │
│  │  │ - Crypto API count                               │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │ String-based Features                            │    │   │
│  │  │ - String count                                   │    │   │
│  │  │ - Average string length                          │    │   │
│  │  │ - Contains HTTP URL                              │    │   │
│  │  │ - Contains .exe                                   │    │   │
│  │  │ - Contains password                              │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Classification Models                    │   │
│  │  ┌────────────────┐  ┌────────────────┐                 │   │
│  │  │  Random Forest │  │  XGBoost       │                 │   │
│  │  │  - 100 trees   │  │  - 50 estimat  │                 │   │
│  │  │  - Max depth:  │  │  - Max depth:  │                 │   │
│  │  │    None        │  │    6          │                 │   │
│  │  └────────────────┘  └────────────────┘                 │   │
│  │  ┌────────────────────────────────────────────┐         │   │
│  │  │  Heuristic Classifier (fallback)           │         │   │
│  │  │  - Zeus detection patterns               │         │   │
│  │  │  - Ransomware indicators                 │         │   │
│  │  │  - Banking trojan signatures             │         │   │
│  │  └────────────────────────────────────────────┘         │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Output                                   │   │
│  │  - Predicted family (Zeus, SpyEye, Pony, etc.)            │   │
│  │  - Confidence score (0-1)                                 │   │
│  │  - Probability distribution                              │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### YARA Scanner Module

```
┌─────────────────────────────────────────────────────────────────┐
│                       YARA Scanner                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Input: PE File, YARA Rules                                      │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Rule Compilation                         │   │
│  │  ┌────────────────┐  ┌────────────────┐                  │   │
│  │  │ banking_       │  │ info_stealers_│                  │   │
│  │  │ trojans.yar    │  │ .yar          │                  │   │
│  │  └────────┬───────┘  └────────┬───────┘                  │   │
│  │           ▼                    ▼                          │   │
│  │  ┌────────────────┐  ┌────────────────┐                  │   │
│  │  │ ransomware.yar │  │ rats.yar       │                  │   │
│  │  └────────┬───────┘  └────────┬───────┘                  │   │
│  └───────────┼──────────────────┼──────────────────────────┘   │
│              ▼                  ▼                              │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Compiled Rules                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Pattern Matching                          │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │ String Matching                                   │    │   │
│  │  │ - Hex strings                                     │    │   │
│  │  │ - Text strings                                    │    │   │
│  │  │ - Wildcard patterns                               │    │   │
│  │  │ - Alternatives                                    │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  │  ┌─────────────────────────────────────────────────┐    │   │
│  │  │ Condition Evaluation                            │    │   │
│  │  │ - Boolean logic (and, or, not)                   │    │   │
│  │  │ - Comparison operators                            │    │   │
│  │  │ - Arithmetic expressions                          │    │   │
│  │  │ - String count checks                             │    │   │
│  │  └─────────────────────────────────────────────────┘    │   │
│  └────────────────────┬────────────────────────────────────┘   │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Matches                                 │   │
│  │  - Matched rule names                                     │   │
│  │  - Matched strings (offset, identifier, data)             │   │
│  │  - Rule metadata                                          │   │
│  │  - Tags                                                   │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Analysis Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    Complete Analysis Pipeline                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. FILE INPUT                                                  │
│     ┌───────────┐                                              │
│     │ suspicious│                                              │
│     │   .exe    │                                              │
│     └─────┬─────┘                                              │
│           │                                                    │
│  2. PE PARSING          ▼                                        │
│     ┌───────────────────────────────┐                          │
│     │ Parse PE headers and sections │                          │
│     │ Extract Import Address Table  │                          │
│     │ Identify packer/obfuscator    │                          │
│     └───────────────┬───────────────┘                          │
│                     │                                          │
│  3. EXTRACTION       ▼                                          │
│     ┌───────────────────────────────┐                          │
│     │ • API calls (IAT)             │                          │
│     │ • Strings (ASCII/Unicode)     │                          │
│     │ • Resources (icons, etc.)     │                          │
│     │ • Section information         │                          │
│     └───────────────┬───────────────┘                          │
│                     │                                          │
│  4. FEATURE         ▼                                          │
│     EXTRACTION                                                  │
│     ┌───────────────────────────────┐                          │
│     │ • API categories              │                          │
│     │ • String patterns             │                          │
│     │ • n-gram sequences            │                          │
│     │ • Metadata                    │                          │
│     └───────┬───────────────────────┘                          │
│             │                                                 │
│             ├───────────────┬───────────────┐                  │
│             ▼               ▼               ▼                  │
│     ┌───────────┐   ┌───────────┐   ┌───────────┐             │
│     │  ML       │   │  YARA     │   │ Heuristic│             │
│     │Classifier │   │ Scanner   │   │ Analysis │             │
│     └─────┬─────┘   └─────┬─────┘   └─────┬─────┘             │
│           │               │               │                     │
│           └───────────────┴───────────────┘                     │
│                           ▼                                     │
│  5. CLASSIFICATION                                                  │
│     ┌───────────────────────────────┐                          │
│     │ Combine evidence from all     │                          │
│     │ analysis sources              │                          │
│     │ Determine final family        │                          │
│     │ Calculate confidence          │                          │
│     └───────────────┬───────────────┘                          │
│                     │                                          │
│  6. REPORTING        ▼                                          │
│     ┌───────────────────────────────┐                          │
│     │ Generate detailed report      │                          │
│     │ • Family identification       │                          │
│     │ • Confidence score            │                          │
│     │ • Matched YARA rules          │                          │
│     │ • API call summary            │                          │
│     │ • String analysis             │                          │
│     │ • Behavioral indicators       │                          │
│     └───────────────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Detection Families

| Category | Families | Key Indicators |
|----------|----------|----------------|
| **Banking Trojans** | Zeus, SpyEye, Carberp, Citadel, Dyre, Dridex | `InternetOpen`, `HttpSendRequest`, `GetAsyncKeyState` |
| **Info Stealers** | Pony, Fareit, LokiBot, Azorult, RedLine | `GetClipboardData`, `CredEnumerate`, `CryptUnprotect` |
| **Ransomware** | WannaCry, Petya, Locky, Cerber, GandCrab | `CryptEncrypt`, `CryptDecrypt`, file modification patterns |
| **RATs** | PoisonIvy, Gh0st, DarkComet, njRAT | `InternetOpen`, `CreateRemoteThread`, keylogging APIs |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| **PE Parsing** | pefile |
| **ML** | scikit-learn, XGBoost |
| **Rule Matching** | YARA |
| **CLI** | argparse, click |
| **Reporting** | Jinja2, ReportLab |
| **Logging** | loguru |
