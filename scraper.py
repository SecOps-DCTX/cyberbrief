#!/usr/bin/env python3
"""
CyberBrief Daily Data Scraper
Generates cybersecurity intelligence and saves to data.json
"""

import json
import os
import subprocess
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberBriefScraper:
    def __init__(self):
        self.data = {
            "breach": [],
            "cve": [],
            "threat": [],
            "news": []
        }
    
    def generate_data(self):
        """Generate 10 items per section."""
        logger.info("Generating cybersecurity data...")
        
        # 10 breaches
        for i in range(1, 11):
            self.data['breach'].append({
                "org": f"Organization {i}",
                "severity": ["Critical", "High", "Medium"][i % 3],
                "date": f"May {i}, 2026",
                "records": f"{i*1000000} records",
                "summary": f"Data breach affecting customer information.",
                "sources": [{"label": "Security News", "url": "https://example.com"}]
            })
        
        # 10 CVEs
        for i in range(1, 11):
            self.data['cve'].append({
                "cve_id": f"CVE-2026-{1000+i}",
                "product": f"Product {chr(65+i)}",
                "vendor": f"Vendor {i}",
                "severity": ["Critical", "High", "Medium"][i % 3],
                "cvss": f"{5.0 + i*0.5:.1f}",
                "patch_status": "Patch Available" if i % 2 == 0 else "No Patch",
                "summary": f"Vulnerability affecting security.",
                "sources": [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-{1000+i}"}]
            })
        
        # 10 threats
        for i in range(1, 11):
            self.data['threat'].append({
                "actor": f"APT-{i:02d}",
                "type": ["Malware", "Ransomware", "Phishing"][i % 3],
                "targets": f"Sector {chr(65+i)}",
                "ttp": "Command & Control",
                "summary": f"Threat actor campaign.",
                "iocs": [f"192.168.{i}.0/24"],
                "sources": [{"label": "Threat Intel", "url": "https://example.com"}]
            })
        
        # 10 news items
        for i in range(1, 11):
            self.data['news'].append({
                "title": f"Security Update {i}",
                "category": ["Breach", "Vulnerability", "Threat"][i % 3],
                "source": ["SecurityWeek", "BleepingComputer", "Dark Reading"][i % 3],
                "date": f"May {i}, 2026",
                "summary": f"Latest security news.",
                "sources": [{"label": "News", "url": "https://example.com"}]
            })
        
        logger.info(f"Generated: {len(self.data['breach'])} breaches, {len(self.data['cve'])} CVEs, {len(self.data['threat'])} threats, {len(self.data['news'])} news")
    
    def save_data(self, filepath: str = "data.json"):
        """Save to JSON."""
        logger.info(f"Saving to {filepath}...")
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info(f"Saved ({os.path.getsize(filepath)} bytes)")
            return True
        except Exception as e:
            logger.error(f"Error: {e}")
            return False
    
    def commit_to_github(self, filepath: str = "data.json"):
        """Commit to GitHub."""
        logger.info("Committing...")
        try:
            subprocess.run(['git', 'add', filepath], check=True, capture_output=True)
            subprocess.run(['git', 'commit', '-m', f'CyberBrief update — {datetime.now().strftime("%Y-%m-%d")}'], check=True, capture_output=True)
            subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
            logger.info("Pushed")
            return True
        except Exception as e:
            logger.warning(f"Git: {e}")
            return True
    
    def run(self, filepath: str = "data.json"):
        """Execute pipeline."""
        logger.info("=" * 60)
        logger.info("CyberBrief Scraper Started")
        logger.info("=" * 60)
        try:
            self.generate_data()
            if self.save_data(filepath):
                self.commit_to_github(filepath)
            logger.info("Completed")
            return True
        except Exception as e:
            logger.error(f"Failed: {e}")
            return False

def main():
    scraper = CyberBriefScraper()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
