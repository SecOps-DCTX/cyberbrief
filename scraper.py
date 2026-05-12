#!/usr/bin/env python3
"""
CyberBrief Hybrid Data Scraper

Preserves manually curated source URLs while updating summaries/dates from web scraping.

How it works:
1. Loads existing data.json (template with verified links)
2. Scrapes web content for fresh summaries
3. Merges new summaries with existing URLs
4. Saves updated data.json

This ensures links NEVER break while keeping content fresh.
"""

import json
import subprocess
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, List, Any
import logging
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Website sources to scrape for fresh content
SOURCES = {
    'securityweek': {
        'url': 'https://www.securityweek.com/',
        'article_selector': 'a.article-link, h3 a, h2 a',
    },
    'bleepingcomputer': {
        'url': 'https://www.bleepingcomputer.com/',
        'article_selector': 'a.post-link, h2.post-title a, h3 a',
    },
    'darkreading': {
        'url': 'https://www.darkreading.com/',
        'article_selector': 'a.article-card, h2 a, h3 a',
    },
    'hackernews': {
        'url': 'https://thehackernews.com/',
        'article_selector': 'h2.post-title a, a.post-link, h2 a',
    }
}

CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

class HybridScraper:
    """Hybrid scraper: preserve URLs, update summaries."""
    
    def __init__(self):
        self.template_data = self.load_template()
        self.cisa_kev = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def load_template(self) -> Dict:
        """Load existing data.json as template (preserves URLs)."""
        logger.info("Loading data.json template...")
        try:
            with open('data.json', 'r') as f:
                data = json.load(f)
            logger.info(f"Template loaded: {len(data.get('breach', []))} breaches, "
                       f"{len(data.get('cve', []))} CVEs, "
                       f"{len(data.get('threat', []))} threats, "
                       f"{len(data.get('news', []))} news")
            return data
        except Exception as e:
            logger.error(f"Failed to load template: {e}")
            return {'breach': [], 'cve': [], 'threat': [], 'news': []}
    
    def fetch_cisa_kev(self):
        """Fetch CISA KEV for CVE enrichment."""
        logger.info("Fetching CISA KEV...")
        try:
            resp = self.session.get(CISA_KEV_URL, timeout=10)
            resp.raise_for_status()
            kev_data = resp.json()
            
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                self.cisa_kev[cve_id] = vuln
            
            logger.info(f"Loaded {len(self.cisa_kev)} KEV entries")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
    
    def scrape_summaries(self) -> Dict[str, List[str]]:
        """Scrape fresh summaries from news sites."""
        logger.info("Scraping fresh summaries...")
        summaries = {'breach': [], 'cve': [], 'threat': [], 'news': []}
        
        for source_name, config in SOURCES.items():
            try:
                logger.info(f"  Scraping {source_name}...")
                resp = self.session.get(config['url'], timeout=15)
                resp.raise_for_status()
                soup = BeautifulSoup(resp.content, 'html.parser')
                
                links = soup.select(config['article_selector'])[:20]
                
                for link in links:
                    try:
                        title = link.get_text(strip=True)
                        if len(title) < 10:
                            continue
                        
                        # Classify by keywords
                        text = title.lower()
                        if any(kw in text for kw in ['breach', 'hack', 'leaked', 'compromised']):
                            summaries['breach'].append(title)
                        elif any(kw in text for kw in ['cve', 'vulnerability', 'patch', 'exploit']):
                            summaries['cve'].append(title)
                        elif any(kw in text for kw in ['apt', 'threat', 'actor', 'group']):
                            summaries['threat'].append(title)
                        else:
                            summaries['news'].append(title)
                    except Exception as e:
                        logger.debug(f"Error parsing {source_name}: {e}")
                
                logger.info(f"  Got {sum(len(v) for v in summaries.values())} summaries")
            
            except Exception as e:
                logger.error(f"Error scraping {source_name}: {e}")
        
        return summaries
    
    def update_summaries(self, scraped: Dict[str, List[str]]) -> Dict:
        """Update template data with fresh summaries, preserve URLs."""
        logger.info("Updating summaries while preserving URLs...")
        updated_data = json.loads(json.dumps(self.template_data))  # Deep copy
        
        # Update breaches
        for i, item in enumerate(updated_data.get('breach', [])):
            if i < len(scraped['breach']):
                item['summary'] = scraped['breach'][i]
                item['date'] = datetime.now().strftime('%b %Y')
                # Preserve sources (URLs)
        
        # Update CVEs
        for i, item in enumerate(updated_data.get('cve', [])):
            if i < len(scraped['cve']):
                item['summary'] = scraped['cve'][i]
                # Enrich with CISA KEV if available
                if item.get('cve_id') in self.cisa_kev:
                    kev = self.cisa_kev[item['cve_id']]
                    item['vendor'] = kev.get('vendorProject', item.get('vendor'))
                    item['cvss'] = str(kev.get('cvssV3Score', item.get('cvss', '0')))
                # Preserve sources (URLs)
        
        # Update threats
        for i, item in enumerate(updated_data.get('threat', [])):
            if i < len(scraped['threat']):
                item['summary'] = scraped['threat'][i]
                # Preserve sources (URLs)
        
        # Update news
        for i, item in enumerate(updated_data.get('news', [])):
            if i < len(scraped['news']):
                item['summary'] = scraped['news'][i]
                item['date'] = datetime.now().strftime('%b %d, %Y')
                # Preserve sources (URLs)
        
        logger.info("Summaries updated, URLs preserved")
        return updated_data
    
    def run(self):
        """Execute hybrid scrape pipeline."""
        logger.info("=" * 60)
        logger.info("CyberBrief Hybrid Scraper Started")
        logger.info("=" * 60)
        
        try:
            self.fetch_cisa_kev()
            scraped = self.scrape_summaries()
            
            if not any(scraped.values()):
                logger.warning("No fresh summaries found. Keeping template data.")
                self.save_data(self.template_data)
                return True  # Still success — data.json preserved
            
            updated_data = self.update_summaries(scraped)
            self.save_data(updated_data)
            self.commit_to_github()
            
            logger.info("=" * 60)
            logger.info("CyberBrief Hybrid Scraper Completed Successfully")
            logger.info("=" * 60)
            return True
        
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            return False
    
    def save_data(self, data: Dict, filepath: str = 'data.json'):
        """Save data to JSON."""
        logger.info(f"Saving data to {filepath}...")
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Saved successfully")
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            raise
    
    def commit_to_github(self):
        """Commit data.json to GitHub."""
        logger.info("Committing to GitHub...")
        try:
            subprocess.run(['git', 'add', 'data.json'], check=True, capture_output=True)
            today = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            subprocess.run(['git', 'commit', '-m', f'CyberBrief hybrid update — {today}'], 
                          check=True, capture_output=True)
            subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
            logger.info("Pushed to GitHub")
        except subprocess.CalledProcessError as e:
            logger.debug(f"Git: {e}")

def main():
    scraper = HybridScraper()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
