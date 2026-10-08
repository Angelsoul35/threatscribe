"""Tag a report with MITRE ATT&CK techniques by keyword.

A small, curated map from phrases that commonly appear in threat reports to the
ATT&CK technique they describe. It is intentionally a lookup, not a classifier:
the mapping is auditable, every tag points to a specific phrase in the text, and
analysts can extend it. It is a first-pass aid, not a replacement for mapping by a
human analyst.
"""

from __future__ import annotations

from dataclasses import dataclass

# technique id -> (name, keyword phrases)
_TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1566": ("Phishing", ("phishing", "spear-phishing", "spear phishing", "malicious attachment")),
    "T1059.001": ("PowerShell", ("powershell", "encoded command", "-enc ")),
    "T1059.003": ("Windows Command Shell", ("cmd.exe", "command shell", "batch script")),
    "T1053": ("Scheduled Task/Job", ("scheduled task", "schtasks", "cron job")),
    "T1547": ("Boot/Logon Autostart", ("registry run key", "autostart", "startup folder")),
    "T1055": ("Process Injection", ("process injection", "process hollowing", "dll injection")),
    "T1486": ("Data Encrypted for Impact", ("ransomware", "encrypts files", "ransom note")),
    "T1071": ("Application Layer Protocol", ("command and control", "c2 server", "beacon")),
    "T1105": ("Ingress Tool Transfer", ("download a payload", "downloads a payload",
                                        "downloaded a payload", "drops a file", "stage a payload")),
    "T1003": ("Credential Dumping", ("mimikatz", "lsass", "credential dumping",
                                     "dump credentials")),
    "T1027": ("Obfuscated Files", ("base64", "obfuscated", "packed executable")),
    "T1190": ("Exploit Public-Facing App", ("exploits a vulnerability", "exploited cve",
                                            "public-facing", "web shell")),
}


@dataclass(frozen=True)
class TechniqueTag:
    technique_id: str
    name: str
    evidence: str


def tag(text: str) -> list[TechniqueTag]:
    low = text.lower()
    tags: list[TechniqueTag] = []
    for tid, (name, phrases) in _TECHNIQUES.items():
        for phrase in phrases:
            if phrase in low:
                tags.append(TechniqueTag(tid, name, phrase))
                break
    return sorted(tags, key=lambda t: t.technique_id)
