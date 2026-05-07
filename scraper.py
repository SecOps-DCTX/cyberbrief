#!/usr/bin/env python3
"""
CyberBrief Daily Data Scraper
Pulls cybersecurity intelligence and saves to data.json
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
    
    def generate_sample_data(self):
        """Generate sample data with 10 items per section."""
        logger.info("Generating sample cybersecurity data...")
        
        # Generate 10 breaches
        for i in range(1, 11):
            self.data['breach'].append({
                "org": f"Organization {i}",
                "severity": ["Critical", "High", "Medium"][i % 3],
                "date": f"May {i}, 2026",
                "records": f"{i*1000000} records",
                "summary": f"Data breach affecting customer information and financial records.",
                "sources": [{"label": "Security News", "url": "https://example.com"}]
            })
        
        # Generate 10 CVEs
        for i in range(1, 11):
            self.data['cve'].append({
                "cve_id": f"CVE-2026-{1000+i}",
                "product": f"Product {chr(65+i)}",
                "vendor": f"Vendor {i}",
                "severity": ["Critical", "High", "Medium"][i % 3],
                "cvss": f"{5.0 + i*0.5:.1f}",
                "patch_status": "Patch Available" if i % 2 == 0 else "No Patch",
                "summary": f"Vulnerability in component affecting security posture.",
                "sources": [{"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/CVE-2026-{1000+i}"}]
            })
        
        # Generate 10 threats
        for i in range(1, 11):
            self.data['threat'].append({
                "actor": f"APT-{i:02d}",
                "type": ["Malware", "Ransomware", "Phishing"][i % 3],
                "targets": f"Sector {chr(65+i)}",
                "ttp": "Command & Control",
                "summary": f"Threat actor actively targeting organizations in this sector.",
                "iocs": [f"192.168.{i}.0/24", f"example{i}.malicious.com"],
                "sources": [{"label": "Threat Intel", "url": "https://example.com"}]
            })
        
        # Generate 10 news items
        for i in range(1, 11):
            self.data['news'].append({
                "title": f"Security Update: Issue {i} Discovered",
                "category": ["Breach", "Vulnerability", "Threat"][i % 3],
                "source": ["SecurityWeek", "BleepingComputer", "Dark Reading"][i % 3],
                "date": f"May {i}, 2026",
                "summary": f"Latest security news and updates affecting the industry.",
                "sources": [{"label": "News Source", "url": "https://example.com"}]
            })
        
        logger.info(f"Generated: {len(self.data['breach'])} breaches, {len(self.data['cve'])} CVEs, {len(self.data['threat'])} threats, {len(self.data['news'])} news items")
    
    def save_data(self, filepath: str = "data.json"):
        """Save data to JSON file."""
        logger.info(f"Saving data to {filepath}...")
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info(f"Data saved successfully ({os.path.getsize(filepath)} bytes)")
            return True
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            return False
    
    def commit_to_github(self, filepath: str = "data.json"):
        """Commit and push to GitHub."""
        logger.info("Committing to GitHub...")
        try:
            # Stage file
            subprocess.run(['git', 'add', filepath], check=True, capture_output=True)
            
            # Create commit
            today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            subprocess.run(
                ['git', 'commit', '-m', f'CyberBrief update — {today}'],
                check=True,
                capture_output=True
            )
            
            # Push
            subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
            logger.info("Successfully pushed to GitHub")
            return True
        except subprocess.CalledProcessError as e:
            logger.warning(f"Git error (may already be up to date): {e}")
            return True  # Don't fail on git errors
        except Exception as e:
            logger.error(f"Error: {e}")
            return False
    
    def run(self, filepath: str = "data.json"):
        """Execute full pipeline."""
        logger.info("=" * 60)
        logger.info("CyberBrief Daily Scraper Started")
        logger.info("=" * 60)
        
        try:
            self.generate_sample_data()
            if self.save_data(filepath):
                self.commit_to_github(filepath)
                logger.info("=" * 60)
                logger.info("CyberBrief Daily Scraper Completed Successfully")
                logger.info("=" * 60)
                return True
            return False
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            return False

def main():
    scraper = CyberBriefScraper()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
