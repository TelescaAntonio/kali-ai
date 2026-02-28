# Kali-AI v14.0

[![Version](https://img.shields.io/badge/version-14.0-blue.svg)]()
[![AI Engine](https://img.shields.io/badge/AI-Claude%20Opus%204.6-purple.svg)]()
[![Lines](https://img.shields.io/badge/lines-6954-green.svg)]()
[![Modules](https://img.shields.io/badge/modules-32-orange.svg)]()

## Overview

Kali-AI is an autonomous AI framework for penetration testing,
OSINT, criminal network investigation, crypto forensics, threat
intelligence, and forensic reporting. Built on Claude Opus 4.6
with the OTPAVL cognitive cycle. 6954 lines, 32 modules, 45+ tools.

## Capabilities

1. Cognitive AI Engine - Claude Opus 4.6, OTPAVL cycle, multi-agent
2. Penetration Testing - MITRE ATT&CK v14, CVE lookup, risk scoring
3. OSINT Engine - email, phone, social, WHOIS, DNS, subdomain
4. Criminal Network Intelligence - graph analysis, entity tracking
5. Crypto Forensics - ETH/BTC tracing, 40+ exchanges, mixer detection
6. Threat Intelligence - AbuseIPDB, VirusTotal, AlienVault, Shodan
7. Forensic Reports - law enforcement format, SHA-256 chain of custody
8. Real-Time Monitoring - IP/domain/wallet surveillance daemon

## Installation

git clone https://github.com/TelescaAntonio/kali-ai.git cd kali-ai chmod +x kali-ai.sh ./kali-ai.sh

Requirements: Kali Linux, Bash 5+, jq, curl, Anthropic API key.

## API Keys

Create api_keys.json in the project folder with your keys for
AbuseIPDB, VirusTotal, AlienVault OTX, and Shodan.

## Usage Examples

Start: ./kali-ai.sh
Scan: scansiona 192.168.1.0/24
OSINT: osint example.com
Email investigation: investiga hacker@suspect.com
CNI: cni suspect@email.com indagine frode
Crypto: crypto_trace 0x742d35Cc... ETH 3
Threat intel: threat_intel 185.220.101.45
Forensic report: forensic_report "Caso" "Descrizione"
Monitor: monitor_start 300

## Research

- DOI: 10.13140/RG.2.2.15729.34401
- Patent: PCT WO2024018409
- Horizon: HORIZON-CL3-2026-02-CS-ECCC-02

## Version History

- v14.0 Forensic Reports, Real-Time Monitoring
- v13.0 Threat Intelligence Aggregator
- v12.0 Criminal Network Intelligence, Crypto Forensics
- v10.0 Email Forensics Investigation
- v9.0 OSINT Engine, Web Vulnerability Scanner
- v8.0 Auto-Install, Topology Mapper, Risk Scoring
- v7.0 MITRE ATT&CK, CVE Lookup, Memory Engine
- v6.0 Core framework, Claude Opus 4.6, OTPAVL

## Author

Antonio Telesca - AI Systems Engineer
Email: antonio.telesca@irst-institute.eu
GitHub: https://github.com/TelescaAntonio
ORCID: https://orcid.org/0009-0003-3048-1044
EU Expert ID: EX2026D1365471

## License

All Rights Reserved. For licensing: antonio.telesca@irst-institute.eu
