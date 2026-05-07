#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberBriefScraper:
    def __init__(self):
        self.data = {"breach": [], "cve": [], "threat": [], "news": []}
    
    def generate_data(self):
        logger.info("Generating data...")
        for i in range(1, 11):
            self.data['breach'].append({
                "org": f"Organization {i}",
                "severity": ["Critical", "High", "Medium"][i % 3],
                "date": f"May {i}, 2026",
                "records": f"{i*1000000} records",
                "summary": f"Data breach.",
                "sources": [{"label": "Security News", "url": "https://example.com"}]
            })
            self.data['cve'].append({
                "cve_id": f"CVE-2026-{1000+i}",
                "product": f"Product {chr(65+i)}",
                "vendor": f"Vendor {i}",
                "severity": ["Critical", "High", "Medium"][i % 3],
                "cvss": f"{5.0 + i*0.5:.1f}",
                "patch_status": "Patch Available" if i % 2 == 0 else "No Patch",
                "summary": f"Vulnerability.",
                "sources": [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-{1000+i}"}]
            })
            self.data['threat'].append({
                "actor": f"APT-{i:02d}",
                "type": ["Malware", "Ransomware", "Phishing"][i % 3],
                "targets": f"Sector {chr(65+i)}",
                "ttp": "C2",
                "summary": f"Campaign.",
                "iocs": [f"192.168.{i}.0/24"],
                "sources": [{"label": "Intel", "url": "https://example.com"}]
            })
            self.data['news'].append({
                "title": f"Update {i}",
                "category": ["Breach", "Vulnerability", "Threat"][i % 3],
                "source": ["SecurityWeek", "BleepingComputer", "Dark Reading"][i % 3],
                "date": f"May {i}, 2026",
                "summary": f"News.",
                "sources": [{"label": "News", "url": "https://example.com"}]
            })
        logger.info(f"Generated 10 items per section")
    
    def save_data(self):
        with open("data.json", 'w') as f:
            json.dump(self.data, f, indent=2)
        logger.info("Saved")
    
    def commit(self):
        try:
            subprocess.run(['git', 'add', 'data.json'], check=True, capture_output=True)
            subprocess.run(['git', 'commit', '-m', f'Update — {datetime.now().strftime("%Y-%m-%d")}'], check=True, capture_output=True)
            subprocess.run(['git', 'push'], check=True, capture_output=True)
            logger.info("Pushed")
        except:
            logger.info("Nothing to commit")
    
    def run(self):
        logger.info("=" * 60)
        logger.info("CyberBrief Scraper")
        logger.info("=" * 60)
        self.generate_data()
        self.save_data()
        self.commit()

if __name__ == '__main__':
    scraper = CyberBriefScraper()
    scraper.run()
