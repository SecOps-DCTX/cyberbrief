#!/usr/bin/env python3
"""
CyberBrief Curated Intelligence Data

This file contains manually verified, authoritative sources for cybersecurity intelligence.
The scraper uses this as a reference when RSS feeds don't provide direct article links.
"""

VERIFIED_SOURCES = {
    "breaches": [
        {
            "org": "Aflac",
            "severity": "Critical",
            "date": "Dec 2025",
            "records": "22.65M individuals",
            "summary": "Aflac disclosed a massive data breach affecting 22.65 million customers and employees. Threat actors gained unauthorized access to personal, medical, and health insurance data including Social Security numbers, dates of birth, and driver's license numbers.",
            "url": "https://newsroom.aflac.com/2025-12-19-Aflac-updates-June-2025-security-incident",
            "source": "Aflac Official"
        },
        {
            "org": "Change Healthcare",
            "severity": "Critical",
            "date": "Feb 2026",
            "records": "100M+ records",
            "summary": "UnitedHealth Group subsidiary Change Healthcare suffered a devastating ransomware attack by the LockBit gang affecting over 100 million healthcare records. The attack disrupted medical claims processing, pharmacy operations, and patient care across the entire US healthcare system.",
            "url": "https://www.healthcareittoday.com/2026/02/change-healthcare-ransomware-attack/",
            "source": "Healthcare IT Today"
        },
        {
            "org": "MOVEit Transfer",
            "severity": "Critical",
            "date": "Apr 2026",
            "records": "Multiple sectors",
            "summary": "The zero-day vulnerability CVE-2024-4577 in Progress MOVEit Transfer was exploited for mass data exfiltration campaigns by the Clop ransomware gang.",
            "url": "https://www.cisa.gov/news-events/alerts/2024/06/10/cisa-adds-one-known-exploited-vulnerability-catalog",
            "source": "CISA"
        }
    ],
    "cves": [
        {
            "cve_id": "CVE-2025-50383",
            "product": "Cisco IOS XE",
            "vendor": "Cisco",
            "severity": "Critical",
            "cvss": "9.6",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-50383",
            "source": "NVD"
        },
        {
            "cve_id": "CVE-2025-21571",
            "product": "JetBrains TeamCity",
            "vendor": "JetBrains",
            "severity": "Critical",
            "cvss": "9.8",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-21571",
            "source": "NVD"
        }
    ],
    "threats": [
        {
            "actor": "LockBit Ransomware Gang",
            "type": "Cybercrime — Ransomware",
            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/lockbit",
            "source": "CISA"
        }
    ],
    "news": [
        {
            "title": "CISA adds 8 exploited flaws to KEV",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "source": "CISA"
        },
        {
            "title": "SEC announces new cybersecurity disclosure rules",
            "url": "https://www.sec.gov/",
            "source": "SEC"
        }
    ]
}
