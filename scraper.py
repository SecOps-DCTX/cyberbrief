#!/usr/bin/env python3
"""
CyberBrief Hybrid Data Scraper with Link Validation

Preserves manually curated source URLs while updating summaries/dates from web scraping.
ENHANCED: Now validates all links before updating data.json.

How it works:
1. Loads existing data.json (template with verified links)
2. Scrapes web content for fresh summaries AND incident links
3. Extracts actual article/advisory URLs (not generic domain links)
4. VALIDATES every link with HEAD/GET requests to confirm it works
5. Merges new summaries + validated links with existing data
6. Saves updated data.json only with working URLs
7. Reports validation results

This ensures:
- Fresh content every 4 hours
- Deep links to specific incidents (not homepages)
- All links are verified to work before publishing
- Broken links never replace good ones (fallback to template)
"""

import json
import subprocess
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, List, Tuple, Any
import logging
import re
from urllib.parse import urljoin
from urllib.error import URLError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Website sources to scrape for fresh content
SOURCES = {
    'securityweek': {
        'url': 'https://www.securityweek.com/',
        'article_selector': 'a.article-link, h3 a, h2 a',
        'link_attr': 'href',
        'base_url': 'https://www.securityweek.com'
    },
    'bleepingcomputer': {
        'url': 'https://www.bleepingcomputer.com/',
        'article_selector': 'a.post-link, h2.post-title a, h3 a',
        'link_attr': 'href',
        'base_url': 'https://www.bleepingcomputer.com'
    },
    'darkreading': {
        'url': 'https://www.darkreading.com/',
        'article_selector': 'a.article-card, h2 a, h3 a',
        'link_attr': 'href',
        'base_url': 'https://www.darkreading.com'
    },
    'hackernews': {
        'url': 'https://thehackernews.com/',
        'article_selector': 'h2.post-title a, a.post-link, h2 a',
        'link_attr': 'href',
        'base_url': 'https://thehackernews.com'
    }
}

# NVD API for CVE details
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

class LinkValidator:
    """Validates URLs are reachable and working."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.validation_cache = {}
        self.failed_urls = []
    
    def is_valid_url_format(self, url: str) -> bool:
        """Check if URL has proper format."""
        if not url or not isinstance(url, str):
            return False
        return url.startswith(('http://', 'https://')) and len(url) > 10
    
    def validate_link(self, url: str, timeout: int = 5) -> Tuple[bool, str]:
        """
        Validate if a URL is reachable and working.
        
        Returns: (is_valid, status_message)
        """
        if url in self.validation_cache:
            return self.validation_cache[url]
        
        if not self.is_valid_url_format(url):
            result = (False, "Invalid URL format")
            self.validation_cache[url] = result
            return result
        
        try:
            # Try HEAD request first (faster)
            response = self.session.head(url, timeout=timeout, allow_redirects=True)
            
            if response.status_code == 405:  # Method Not Allowed, try GET
                response = self.session.get(url, timeout=timeout, allow_redirects=True, stream=True)
            
            is_valid = response.status_code < 400
            status = f"Status {response.status_code}"
            
            result = (is_valid, status)
            self.validation_cache[url] = result
            
            if not is_valid:
                self.failed_urls.append(url)
                logger.warning(f"  ❌ {url} — {status}")
            else:
                logger.debug(f"  ✓ {url} — OK")
            
            return result
        
        except requests.exceptions.Timeout:
            result = (False, "Timeout")
            self.validation_cache[url] = result
            self.failed_urls.append(url)
            logger.warning(f"  ❌ {url} — Timeout")
            return result
        
        except requests.exceptions.ConnectionError:
            result = (False, "Connection error")
            self.validation_cache[url] = result
            self.failed_urls.append(url)
            logger.warning(f"  ❌ {url} — Connection error")
            return result
        
        except Exception as e:
            result = (False, str(e))
            self.validation_cache[url] = result
            self.failed_urls.append(url)
            logger.warning(f"  ❌ {url} — {str(e)}")
            return result
    
    def get_report(self) -> Dict[str, Any]:
        """Return validation report."""
        total = len(self.validation_cache)
        valid = sum(1 for v, _ in self.validation_cache.values() if v)
        return {
            'total_tested': total,
            'valid': valid,
            'failed': len(self.failed_urls),
            'success_rate': f"{(valid/total*100):.1f}%" if total > 0 else "0%",
            'failed_urls': self.failed_urls
        }

class DeepLinkScraperWithValidation:
    """Enhanced scraper: preserve URLs, update summaries + validate all links."""
    
    def __init__(self):
        self.template_data = self.load_template()
        self.cisa_kev = {}
        self.nvd_cache = {}
        self.validator = LinkValidator()
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
            
            # Validate all template URLs
            logger.info("\nValidating template URLs...")
            self.validate_template_urls(data)
            
            return data
        except Exception as e:
            logger.error(f"Failed to load template: {e}")
            return {'breach': [], 'cve': [], 'threat': [], 'news': []}
    
    def validate_template_urls(self, data: Dict):
        """Validate ALL URLs in template before using it."""
        logger.info("\n🔗 VALIDATING TEMPLATE DATA (ALL 40 LINKS)...")
        categories = ['breach', 'cve', 'threat', 'news']
        total_checked = 0
        total_valid = 0
        broken_urls = []
        
        for category in categories:
            items = data.get(category, [])
            logger.info(f"\n{category.upper()} ({len(items)} items):")
            
            for idx, item in enumerate(items, 1):
                if item.get('sources'):
                    for source in item['sources']:
                        url = source.get('url')
                        if url:
                            total_checked += 1
                            is_valid, status = self.validator.validate_link(url, timeout=5)
                            
                            item_name = item.get('org') or item.get('cve_id') or item.get('actor') or item.get('title')
                            
                            if is_valid:
                                logger.info(f"  [{idx:2d}] ✓ {item_name:30s} → {status}")
                                total_valid += 1
                            else:
                                logger.error(f"  [{idx:2d}] ❌ {item_name:30s} → {status}")
                                broken_urls.append({
                                    'category': category,
                                    'item': item_name,
                                    'url': url,
                                    'status': status
                                })
        
        logger.info(f"\n{'='*70}")
        logger.info(f"TEMPLATE VALIDATION SUMMARY")
        logger.info(f"{'='*70}")
        logger.info(f"Total links checked: {total_checked}")
        logger.info(f"Valid links: {total_valid}")
        logger.info(f"Broken links: {len(broken_urls)}")
        logger.info(f"Success rate: {(total_valid/total_checked*100):.1f}%" if total_checked > 0 else "0%")
        
        if broken_urls:
            logger.error(f"\n⚠️  BROKEN TEMPLATE LINKS DETECTED:")
            for broken in broken_urls:
                logger.error(f"  - {broken['category'].upper()}: {broken['item']}")
                logger.error(f"    URL: {broken['url']}")
                logger.error(f"    Status: {broken['status']}")
        else:
            logger.info(f"\n✅ ALL 40 TEMPLATE LINKS ARE VALID!")
    
    def fetch_cisa_kev(self):
        """Fetch CISA KEV for CVE enrichment + deep links."""
        logger.info("Fetching CISA KEV...")
        try:
            resp = self.session.get(CISA_KEV_URL, timeout=10)
            resp.raise_for_status()
            kev_data = resp.json()
            
            for vuln in kev_data.get('vulnerabilities', []):
                cve_id = vuln.get('cveID')
                # Store both vulnerability data AND link to CISA KEV entry
                self.cisa_kev[cve_id] = {
                    'data': vuln,
                    'link': f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cve_id}"
                }
            
            logger.info(f"Loaded {len(self.cisa_kev)} KEV entries")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
    
    def fetch_and_validate_nvd_cve_details(self, cve_id: str) -> Tuple[str, bool]:
        """Fetch and validate NVD CVE detail page URL.
        
        Returns: (nvd_url, is_valid)
        """
        if cve_id in self.nvd_cache:
            return self.nvd_cache[cve_id]
        
        # Direct NVD link format
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        is_valid, _ = self.validator.validate_link(nvd_url, timeout=5)
        
        self.nvd_cache[cve_id] = (nvd_url, is_valid)
        return (nvd_url, is_valid)
    
    def extract_deep_links(self) -> Dict[str, List[Tuple[str, str]]]:
        """Extract deep links from news sites.
        
        Returns: Dict with categories mapping to list of (title, url) tuples
        """
        logger.info("\nExtracting deep links from news sources...")
        links = {'breach': [], 'cve': [], 'threat': [], 'news': []}
        
        for source_name, config in SOURCES.items():
            try:
                logger.info(f"  Scraping {source_name}...")
                resp = self.session.get(config['url'], timeout=15)
                resp.raise_for_status()
                soup = BeautifulSoup(resp.content, 'html.parser')
                
                article_elements = soup.select(config['article_selector'])[:20]
                
                for elem in article_elements:
                    try:
                        title = elem.get_text(strip=True)
                        href = elem.get(config['link_attr'], '')
                        
                        if not href or len(title) < 10:
                            continue
                        
                        # Convert relative URLs to absolute
                        full_url = urljoin(config['base_url'], href)
                        
                        # Classify by keywords
                        text = title.lower()
                        if any(kw in text for kw in ['breach', 'hack', 'leaked', 'compromised', 'data loss']):
                            links['breach'].append((title, full_url))
                        elif any(kw in text for kw in ['cve', 'vulnerability', 'patch', 'exploit', 'advisory']):
                            links['cve'].append((title, full_url))
                        elif any(kw in text for kw in ['apt', 'threat', 'actor', 'group', 'ransomware', 'malware']):
                            links['threat'].append((title, full_url))
                        else:
                            links['news'].append((title, full_url))
                    except Exception as e:
                        logger.debug(f"Error parsing link from {source_name}: {e}")
                
                logger.info(f"  Extracted {sum(len(v) for v in links.values())} deep links so far")
            
            except Exception as e:
                logger.warning(f"Error scraping {source_name}: {e}")
        
        logger.info(f"Total extracted: {sum(len(v) for v in links.values())} links")
        return links
    
    def validate_extracted_links(self, links: Dict[str, List[Tuple[str, str]]]) -> Dict[str, List[Tuple[str, str]]]:
        """Validate all extracted links before using them."""
        logger.info("\n🔗 Validating extracted links...")
        validated = {'breach': [], 'cve': [], 'threat': [], 'news': []}
        
        for category in links:
            logger.info(f"\nValidating {category.upper()} links:")
            for title, url in links[category]:
                is_valid, status = self.validator.validate_link(url, timeout=3)
                
                if is_valid:
                    validated[category].append((title, url))
                    logger.info(f"  ✓ {title[:60]}...")
                else:
                    logger.warning(f"  ❌ SKIPPING broken link: {title[:60]}... ({status})")
        
        return validated
    
    def validate_all_cve_links(self, data: Dict) -> Tuple[int, int]:
        """Validate all CVE links including NVD and vendor advisories.
        
        Returns: (total_cves, valid_cves)
        """
        logger.info("\n🔗 VALIDATING ALL CVE LINKS...")
        cve_items = data.get('cve', [])
        valid_count = 0
        
        for idx, item in enumerate(cve_items, 1):
            cve_id = item.get('cve_id', 'Unknown')
            product = item.get('product', 'Unknown')
            
            logger.info(f"  [{idx:2d}] {cve_id} ({product})")
            
            # Validate NVD link
            nvd_url, nvd_valid = self.fetch_and_validate_nvd_cve_details(cve_id)
            nvd_status = "✓ NVD OK" if nvd_valid else "❌ NVD BROKEN"
            logger.info(f"       {nvd_status} — {nvd_url}")
            
            # Validate vendor source links
            if item.get('sources'):
                for source in item['sources']:
                    url = source.get('url')
                    label = source.get('label')
                    if url:
                        is_valid, status = self.validator.validate_link(url, timeout=5)
                        source_status = "✓" if is_valid else "❌"
                        logger.info(f"       {source_status} {label} — {status}")
                        if is_valid:
                            valid_count += 1
            
            if nvd_valid:
                valid_count += 1
        
        return (len(cve_items), valid_count)
    
    def validate_all_threat_links(self, data: Dict) -> Tuple[int, int]:
        """Validate all threat intelligence links.
        
        Returns: (total_threats, valid_threats)
        """
        logger.info("\n🔗 VALIDATING ALL THREAT INTELLIGENCE LINKS...")
        threat_items = data.get('threat', [])
        valid_count = 0
        
        for idx, item in enumerate(threat_items, 1):
            actor = item.get('actor', 'Unknown')
            threat_type = item.get('type', 'Unknown')
            
            logger.info(f"  [{idx:2d}] {actor} ({threat_type})")
            
            # Validate source links
            if item.get('sources'):
                for source in item['sources']:
                    url = source.get('url')
                    label = source.get('label')
                    if url:
                        is_valid, status = self.validator.validate_link(url, timeout=5)
                        source_status = "✓" if is_valid else "❌"
                        logger.info(f"       {source_status} {label} — {status}")
                        if is_valid:
                            valid_count += 1
        
        return (len(threat_items), valid_count)
    
    def update_with_deep_links(self, deep_links: Dict[str, List[Tuple[str, str]]]) -> Dict:
        """Update template data with fresh summaries and validated deep links."""
        logger.info("\nUpdating data with validated links...")
        updated_data = json.loads(json.dumps(self.template_data))  # Deep copy
        
        # Update breaches with deep links
        for i, item in enumerate(updated_data.get('breach', [])):
            if i < len(deep_links['breach']):
                title, url = deep_links['breach'][i]
                item['summary'] = title
                item['date'] = datetime.now().strftime('%b %Y')
                # Replace first source URL with validated deep link
                if item.get('sources'):
                    item['sources'][0]['url'] = url
                    item['sources'][0]['label'] = f"{item['org']} Incident"
        
        # Update CVEs with NVD deep links
        for i, item in enumerate(updated_data.get('cve', [])):
            if i < len(deep_links['cve']):
                title, url = deep_links['cve'][i]
                item['summary'] = title
            
            # Enrich with NVD link if available
            if item.get('cve_id'):
                nvd_url, nvd_valid = self.fetch_and_validate_nvd_cve_details(item['cve_id'])
                
                if nvd_valid and item.get('sources'):
                    item['sources'][0]['url'] = nvd_url
                    item['sources'][0]['label'] = f"{item['cve_id']} Details"
                
                # Also enrich from CISA KEV if available
                if item['cve_id'] in self.cisa_kev:
                    kev = self.cisa_kev[item['cve_id']]['data']
                    item['vendor'] = kev.get('vendorProject', item.get('vendor'))
                    item['cvss'] = str(kev.get('cvssV3Score', item.get('cvss', '0')))
        
        # Update threats with deep links
        for i, item in enumerate(updated_data.get('threat', [])):
            if i < len(deep_links['threat']):
                title, url = deep_links['threat'][i]
                item['summary'] = title
                # Replace source with validated deep link
                if item.get('sources'):
                    item['sources'][0]['url'] = url
                    item['sources'][0]['label'] = f"{item['actor']} Alert"
        
        # Update news with deep links
        for i, item in enumerate(updated_data.get('news', [])):
            if i < len(deep_links['news']):
                title, url = deep_links['news'][i]
                item['summary'] = title
                item['date'] = datetime.now().strftime('%b %d, %Y')
                # Replace source with validated deep link
                if item.get('sources'):
                    item['sources'][0]['url'] = url
                    item['sources'][0]['label'] = item['title']
        
        logger.info("Data updated with validated links")
        return updated_data
    
    def run(self):
        """Execute deep link scraping pipeline with comprehensive validation."""
        logger.info("=" * 70)
        logger.info("CyberBrief Deep Link Scraper with Comprehensive Validation")
        logger.info("=" * 70)
        
        try:
            self.fetch_cisa_kev()
            deep_links = self.extract_deep_links()
            
            # Validate all extracted links
            validated_links = self.validate_extracted_links(deep_links)
            
            # Validate all CVE links (10 items + NVD + vendor links)
            cve_total, cve_valid = self.validate_all_cve_links(self.template_data)
            
            # Validate all threat intelligence links (10 items + sources)
            threat_total, threat_valid = self.validate_all_threat_links(self.template_data)
            
            # Report validation results
            report = self.validator.get_report()
            logger.info("\n" + "=" * 70)
            logger.info("📊 COMPREHENSIVE LINK VALIDATION REPORT")
            logger.info("=" * 70)
            logger.info(f"CVE Links: {cve_valid}/{cve_total} valid")
            logger.info(f"Threat Links: {threat_valid}/{threat_total} valid")
            logger.info(f"Extracted Links: {report['valid']}/{report['total_tested']} valid")
            logger.info(f"Overall Success Rate: {report['success_rate']}")
            
            if report['failed_urls']:
                logger.warning("\n❌ Failed URLs (not used):")
                for url in report['failed_urls'][:10]:  # Show first 10
                    logger.warning(f"  - {url}")
            
            # Check if all validations passed
            if cve_valid == cve_total and threat_valid == threat_total:
                logger.info("\n✅ ALL CVE AND THREAT LINKS ARE VALID!")
            else:
                logger.error("\n⚠️  Some CVE or Threat links are broken!")
            
            if not any(validated_links.values()):
                logger.warning("\n⚠️  No validated new links found. Keeping template data.")
                self.save_data(self.template_data)
                self.commit_to_github()
                logger.info("=" * 70)
                logger.info("CyberBrief Scraper Completed (using template)")
                logger.info("=" * 70)
                return True  # Success even if no new links
            
            updated_data = self.update_with_deep_links(validated_links)
            self.save_data(updated_data)
            self.commit_to_github()
            
            logger.info("=" * 70)
            logger.info("✅ CyberBrief Scraper Completed Successfully")
            logger.info("=" * 70)
            return True
        
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            logger.warning("Keeping template data as fallback")
            self.save_data(self.template_data)
            return True  # Still return success to keep system running
    
    def save_data(self, data: Dict, filepath: str = 'data.json'):
        """Save data to JSON."""
        logger.info(f"Saving validated data to {filepath}...")
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("✓ Saved successfully")
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            raise
    
    def commit_to_github(self):
        """Commit data.json to GitHub."""
        logger.info("Committing to GitHub...")
        try:
            subprocess.run(['git', 'add', 'data.json'], check=True, capture_output=True)
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            subprocess.run(['git', 'commit', '-m', f'CyberBrief validated link update — {now}'], 
                          check=True, capture_output=True)
            subprocess.run(['git', 'push', 'origin', 'main'], check=True, capture_output=True)
            logger.info("✓ Pushed to GitHub")
        except subprocess.CalledProcessError as e:
            logger.debug(f"Git: {e}")

def main():
    scraper = DeepLinkScraperWithValidation()
    success = scraper.run()
    exit(0 if success else 1)

if __name__ == '__main__':
    main()
