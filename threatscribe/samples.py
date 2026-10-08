"""A synthetic threat report for the demo and the tests (defanged, like the real ones)."""

from __future__ import annotations

SAMPLE_REPORT = """\
The threat actor known as FIN-Example launched a spear-phishing campaign against
financial institutions in March. Victims received a malicious attachment that, when
opened, ran an obfuscated PowerShell command (encoded with base64) to download a
payload from hxxps://cdn.evil-example[.]com/stage2.bin. The loader established a
scheduled task for persistence and beaconed to its command and control server at
185.220.101[.]47 over HTTPS. Analysts recovered the second-stage ransomware, which
encrypts files and drops a ransom note demanding payment to the Bitcoin address
1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2. Indicators include the SHA256 hash
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and the sender
address payments@evil-example[.]com. The activity exploits CVE-2024-3400 on
public-facing VPN gateways.
"""
