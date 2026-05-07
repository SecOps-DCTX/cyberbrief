#!/usr/bin/env python3
"""
CyberBrief Daily Data Scraper — Production Implementation

Fetches cybersecurity intelligence from multiple sources daily:
- SecurityWeek RSS
- BleepingComputer RSS
- Dark Reading RSS
- CISA KEV JSON API
- The Hacker News RSS

Scores items by severity/impact and stores 10 per section in data.json.
"""

import json
import os
import subprocess
import requests
import feedparser
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# RSS Feed URLs
FEEDS = {
    'securityweek': 'https://www.securityweek.com/feed/',
    'bleepingcomputer': 'https://www.bleepingcomputer.com/feed/',
    'darkreading': 'https://www.darkreading.com/rss.xml',
    'hackernews': 'https://thehackernews.com/feeds/posts/default'
}

# CISA KEV API
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

class CyberBriefScraper:
    """Production scraper for daily cybersecurity intelligence."""
    
    def __init__(self):
        self.data = {'breach': [], 'cve': [], 'threat': [], 'news': []}
        self.cisa_kev = {}
    
    def fetch_cisa_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities catalog."""
        logger.info("Fetching CISA KEV...")
        try:
            resp = requests.get(CISA_KEV_URL, timeout=10)
            resp.raise_for_status()
            kev_data = resp.json()
            
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                self.cisa_kev[cve_id] = vuln
            
            logger.info(f"Loaded {len(self.cisa_kev)} KEV entries")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
    
    def validate_url(self, url: str, timeout: int = 5) -> bool:
        """Check if URL is alive and valid."""
        if not url or not url.startswith('http'):
            return False
        
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, stream=True)
            return 200 <= resp.status_code < 400
        except requests.exceptions.RequestException as e:
            logger.debug(f"URL validation failed for {url}: {e}")
            return False
    
    def fetch_rss_feeds(self):
        """Fetch and parse RSS feeds from security news sources."""
        logger.info("Fetching RSS feeds...")
        
        articles = []
        cutoff = datetime.now() - timedelta(hours=24)
        
        for source_name, feed_url in FEEDS.items():
            try:
                logger.info(f"  Fetching {source_name}...")
                feed = feedparser.parse(feed_url)
                
                for entry in feed.entries[:50]:
                    try:
                        published = datetime(*entry.published_parsed[:6]) if hasattr(entry, 'published_parsed') else datetime.now()
                        if published < cutoff:
                            continue
                        
                        link = entry.get('link', '')
                        if not self.validate_url(link):
                            logger.debug(f"URL validation failed for {source_name}: {link}")
                            continue
                        
                        article = {
                            'source': source_name,
                            'title': entry.get('title', ''),
                            'summary': entry.get('summary', '')[:500],
                            'link': link,
                            'published': published.isoformat(),
                            'tags': [tag.get('term', '') for tag in entry.get('tags', [])]
                        }
                        articles.append(article)
                    except Exception as e:
                        logger.debug(f"Error parsing entry from {source_name}: {e}")
                
                logger.info(f"  Got {len([a for a in articles if a['source'] == source_name])} recent articles from {source_name}")
            
            except Exception as e:
                logger.error(f"Error fetching {source_name}: {e}")
        
        return articles
    
    def classify_article(self, article: Dict) -> Dict[str, Any]:
        """Classify article as breach/CVE/threat/news based on content."""
        title = (article['title'] or '').lower()
        summary = (article['summary'] or '').lower()
        text = f"{title} {summary}"
        
        score = 0
        section = 'news'
        severity = 'Info'
        
        breach_keywords = ['breach', 'data breach', 'leaked', 'compromised', 'ransomware', 'hack']
        if any(kw in text for kw in breach_keywords):
            section = 'breach'
            score += 50
            severity = 'Critical' if any(org in text for org in ['bank', 'financial', 'healthcare', 'government']) else 'High'
        
        cve_keywords = ['cve-', 'vulnerability', 'zero-day', 'patch', 'exploit', 'rce']
        if any(kw in text for kw in cve_keywords):
            section = 'cve'
            score += 60
            severity = 'Critical' if any(kw in text for kw in ['exploit', 'zero-day']) else 'High'
        
        threat_keywords = ['apt', 'threat actor', 'group', 'campaign', 'ransomware gang']
        if any(kw in text for kw in threat_keywords):
            section = 'threat'
            score += 55
            severity = 'High'
        
        news_keywords = ['regulation', 'fbi', 'cisa', 'policy']
        if any(kw in text for kw in news_keywords):
            section = 'news'
            score += 30
        
        authority_boost = {'securityweek': 15, 'bleepingcomputer': 15, 'darkreading': 12, 'hackernews': 10}
        score += authority_boost.get(article['source'], 5)
        
        return {'section': section, 'severity': severity, 'score': min(score, 100), 'article': article}
    
    def parse_breach(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured breach data from article."""
        article = classified['article']
        title = article['title']
        org = title.split(' ')[0] if title else 'Unknown'
        url = article['link'] if self.validate_url(article['link']) else f"https://www.cisa.gov/"
        
        return {
            'org': org,
            'severity': classified['severity'],
            'date': datetime.now().strftime('%b %Y'),
            'records': 'Unknown',
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': url}]
        }
    
    def parse_cve(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured CVE data from article."""
        import re
        article = classified['article']
        text = f"{article['title']} {article['summary']}"
        
        cve_match = re.search(r'(cve-\d{4}-\d+)', text, re.I)
        cve_id = cve_match.group(0).upper() if cve_match else 'CVE-2026-00000'
        
        url = article['link'] if self.validate_url(article['link']) else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        return {
            'cve_id': cve_id,
            'product': 'Unknown',
            'vendor': 'Unknown',
            'severity': classified['severity'],
            'cvss': '0',
            'patch_status': 'Unknown',
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': url}]
        }
    
    def parse_threat(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured threat actor data from article."""
        article = classified['article']
        url = article['link'] if self.validate_url(article['link']) else "https://www.cisa.gov/"
        
        return {
            'actor': 'Unknown Actor',
            'type': 'Cybercrime',
            'targets': 'Multiple',
            'ttp': 'See source',
            'iocs': [],
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': url}]
        }
    
    def parse_news(self, classified: Dict) -> Dict[str, Any]:
        """Extract structured news data from article."""
        article = classified['article']
        url = article['link'] if self.validate_url(article['link']) else "https://www.cisa.gov/"
        
        return {
            'title': article['title'],
            'category': 'News',
            'source': article['source'].replace('_', ' ').title(),
            'date': datetime.now().strftime('%b %d, %Y'),
            'summary': article['summary'],
            'sources': [{'label': article['source'].replace('_', ' ').title(), 'url': url}]
        }
    
    def run(self, max_per_section: int = 10):
        """Execute full scrape → classify → parse → save pipeline."""
        logger.info("=" * 60)
        logger.info("CyberBrief Daily Scraper Started")
        logger.info("=" * 60)
        
        try:
            self.fetch_cisa_kev()
            articles = self.fetch_rss_feeds()
            logger.info(f"Fetched {len(articles)} articles total")
            
            if not articles:
                logger.warning("No articles found. Using existing data.")
                return False
            
            classified = [self.classify_article(a) for a in articles]
            classified.sort(key=lambda x: x['score'], reverse=True)
            
            for item in classified[:max_per_section * 2]:
                section = item['section']
                
                if section == 'breach' and len(self.data['breach']) < max_per_section:
                    self.data['breach'].append(self.parse_breach(item))
                elif section == 'cve' and len(self.data['cve']) < max_per_section:
                    self.data['cve'].append(self.parse_cve(item))
                elif section == 'threat' and len(self.data['threat']) < max_per_section:
                    self.data['threat'].append(self.parse_threat(item))
                elif section == 'news' and len(self.data['news']) < max_per_section:
                    self.data['news'].append(self.parse_news(item))
            
            self.save_data()
            self.commit_to_github()
            
            logger.info("=" * 60)
            logger.info("CyberBrief Daily Scraper Completed Successfully")
            logger.info("=" * 60)
            return True
        
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            return False
    
    def save_data(self, filepath: str = 'data.json'):
        """Save compiled data to JSON."""
        logger.info(f"Saving data to {filepath}...")
        try:
            with open(filepath, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info(f"Saved: {len(self.data['breach'])} breaches, {len(self.data['cve'])} CVEs, {len(self.data['threat'])} threats, {len(self.data['news'])} news")
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            raise
    
    def commit_to_github(self):
        """Commit data.json to GitHub."""
        logger.info("Committing to GitHub...")
        try:
            result = subprocess.run(['git', 'diff', '--quiet', 'data.json'], capture_output=True, check=False)
            if result.returncode != 0:
                subprocess.run(['git', 'add', 'data.json'], check=True)
                today = datetime.now().strftime('%Y-%m-%d')
                subprocess.run(['git', 'commit', '-m', f'CyberBrief daily update — {today}'], check=True, capture_output=True)
                subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
                logger.info(f"Pushed update for {today}")
            else:
                logger.info("No changes to commit")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git error: {e}")

def main():
    scraper = CyberBriefScraper()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
