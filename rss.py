import os, re, json, logging, requests, feedparser, threading
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
from dateutil.tz import gettz
import pandas as pd
import streamlit as st

if os.path.exists('cybersecnews.json'):
    os.remove('cybersecnews.json')

if os.path.exists('cybersecurity-advisories.xml'):
    os.remove('cybersecurity-advisories.xml')

if os.path.exists('bleepingcomputer.xml'):
    os.remove('bleepingcomputer.xml')

st.set_page_config(
    page_title="Cybersecurity News Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Hide Streamlit clutter
st.markdown("""
    <style>
    #MainMenu, header, footer,
    .st-emotion-cache-1dp5vir.ezrtsby2,
    button[title="View app in full screen"],
    .stDeployButton,
    .st-emotion-cache-13ln4jf,
    div[data-testid="stStatusWidget"],
    div[class*="statusWidget"],
    a[href*="cloud.streamlit.io"] {
        visibility: hidden !important;
        display: none !important;
        height: 0px !important;
        overflow: hidden !important;
    }
    </style>
""", unsafe_allow_html=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_json_outdated(json_filename):
    if not os.path.exists(json_filename):
        return True
    file_mod_time = datetime.fromtimestamp(os.path.getmtime(json_filename))
    return file_mod_time.date() < datetime.now().date()

def download_cisa_xml():
    url = 'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml'
    sources_dir = os.getcwd()
    local_file = os.path.join(sources_dir, 'cybersecurity-advisories.xml')
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] CISA advisories saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch CISA XML: {e}")

def download_bleepingcomputer_xml():
    url = 'https://www.bleepingcomputer.com/feed/'
    sources_dir = os.getcwd()
    os.makedirs(sources_dir, exist_ok=True)
    local_file = os.path.join(sources_dir, 'bleepingcomputer.xml')

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://www.bleepingcomputer.com/'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] BleepingComputer feed saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch BleepingComputer XML: {e}")
        
def download_databreaches_xml():
    url = 'https://databreaches.net/feed/'
    sources_dir = os.getcwd()
    local_file = os.path.join(sources_dir, 'databreaches.xml')

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://databreaches.net/'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] DataBreaches.net feed saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch DataBreaches XML: {e}")
        
def download_microsoftsecurity_xml():
    url = 'https://www.microsoft.com/en-us/security/blog/feed/'
    sources_dir = os.getcwd()
    local_file = os.path.join(sources_dir, 'microsoftsecurity.xml')

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://www.microsoft.com/'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] Microsoft Security Blog feed saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch Microsoft Security Blog XML: {e}")
        
def download_securityweek_xml():
    url = 'https://feeds.feedburner.com/securityweek'
    sources_dir = os.getcwd()
    local_file = os.path.join(sources_dir, 'securityweek.xml')

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://www.securityweek.com/'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] SecurityWeek feed saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch SecurityWeek XML: {e}")
        
def download_proofpoint_xml():
    url = 'https://www.proofpoint.com/us/rss.xml'
    sources_dir = os.getcwd()
    local_file = os.path.join(sources_dir, 'proofpoint.xml')

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://www.proofpoint.com/'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] Proofpoint feed saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch Proofpoint XML: {e}")
        
def download_crowdstrike_xml():
    url = 'https://www.crowdstrike.com/blog/feed/'
    sources_dir = os.getcwd()
    local_file = os.path.join(sources_dir, 'crowdstrike.xml')

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer': 'https://www.crowdstrike.com/'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        with open(local_file, 'wb') as f:
            f.write(response.content)
        logging.info(f"[DOWNLOAD OK] CrowdStrike feed saved to {local_file}")
    except Exception as e:
        logging.warning(f"[DOWNLOAD FAIL] Failed to fetch CrowdStrike XML: {e}")
 
def process_rss_feeds(json_filename='cybersecnews.json'):
    rss_urls = [
        'https://krebsonsecurity.com/feed/',
        'https://malware-traffic-analysis.net/blog-entries.rss',
        'https://www.securityweek.com/feed/',
        'https://www.darkreading.com/rss.xml',
        'https://feeds.feedburner.com/TheHackersNews',
        'https://securityboulevard.com/feed/',
        'https://unit42.paloaltonetworks.com/feed/',
        'https://securelist.com/feed/',
        'https://www.schneier.com/blog/atom.xml',
        'https://blog.malwarebytes.com/feed/',
        'https://security.googleblog.com/feeds/posts/default',
        'https://www.theregister.com/security/headlines.atom',
        'https://www.proofpoint.com/us/rss.xml'
    ]

    keywords = [
        'APT', 'DDoS', 'IoT security', 'SQL injection', 'advanced persistent threat',
        'adware', 'backdoor', 'botnet', 'breach', 'brute force', 'credential stuffing',
        'cross-site scripting (XSS)', 'cryptojacking', 'cyber defense', 'cyber espionage',
        'cyber warfare', 'cyberattack', 'cybercrime', 'cybersecurity incident', 'dark web',
        'data leak', 'data theft', 'digital extortion', 'digital forensics', 'endpoint protection',
        'exfiltration', 'exploit', 'exposed data', 'hack', 'hacktivist', 'information security',
        'insider threat', 'keylogger', 'malware', 'man-in-the-middle', 'network intrusion',
        'password attack', 'phishing', 'ransomware group', 'rootkit', 'security breach',
        'session hijacking', 'social engineering', 'spear-phishing', 'spyware', 'threat actor',
        'trojan', 'vulnerability', 'worm', 'zero-day', 'deepfake', 'supply chain attack',
        'zero trust', 'cloud jacking', 'AI-powered attack', 'RansomOps', 'fileless malware',
        'living off the land', 'credential harvesting', 'cyber hygiene', 'shadow IT',
        'cryptographic failures', 'smart contract vulnerabilities', 'insider risk', 'API abuse',
        'harvest now, decrypt later', 'initial access broker', 'infostealer', 'lolbin',
        'MFA fatigue', 'SIM swapping', 'active directory attack', 'data exfil', 'BEC scam',
        'darknet market', 'c2 infrastructure', 'malvertising', 'RCE', 'privilege escalation',
        'supply chain compromise', 'domain shadowing', 'CVE-', 'sandbox evasion', 'TTPs',
        'command and control', 'stealer logs', 'threat hunting', 'EDR evasion', 'double extortion',
        'payload delivery', 'phishing kit', 'malspam', 'vishing', 'smishing'
    ]
    pattern = re.compile('|'.join(keywords), re.IGNORECASE)

    def clean_title(title):
        title = re.sub(r'^\d{4}-\d{2}-\d{2} ', '', title)
        title = re.sub(r'^[#\d\s-]+', '', title)
        title = re.sub(r'^[^:]+:\s*', '', title)
        return title

    def is_recent(date_str):
        if not date_str:
            return False
        try:
            dt = date_parser.parse(date_str, tzinfos={"EDT": gettz("America/New_York"), "EST": gettz("America/New_York")})
            dt = dt.astimezone(timezone.utc)
            return dt > datetime.now(timezone.utc) - timedelta(days=30)
        except Exception as e:
            logging.warning(f"[DATE PARSE FAIL] {date_str} | Error: {e}")
            return False

    def fetch_feed(url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/rss+xml'}
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code != 200:
                return []
            feed = feedparser.parse(res.content)
            if feed.bozo or not feed.entries:
                return []

            entries = []
            for e in feed.entries:
                date_str = e.get('published') or e.get('updated') or e.get('pubDate')
                if not is_recent(date_str):
                    continue
                title = clean_title(e.get('title', 'No Title'))
                summary = BeautifulSoup(e.get('summary', ''), 'html.parser').get_text()
                pub_date = date_parser.parse(date_str, tzinfos={"EDT": gettz("America/New_York")}).astimezone(timezone.utc)

                if pattern.search(f"{title} {summary}"):
                    entries.append({
                        'title': title,
                        'link': e.get('link', '#'),
                        'summary': summary,
                        'published': pub_date.strftime('%Y-%m-%d')
                    })
            return entries
        except:
            return []

    def process_local_feed(filepath, label):
        if not os.path.exists(filepath):
            logging.warning(f"[MISSING] Local {label} feed not found at {filepath}")
            return []
        with open(filepath, 'rb') as f:
            content = f.read()
        soup = BeautifulSoup(content, 'xml')
        items = soup.find_all('item')
        logging.info(f"[{label.upper()} LOCAL] Found {len(items)} items in local {label} feed.")
        entries = []
        for item in items:
            title = item.title.text if item.title else 'No Title'
            summary = BeautifulSoup(item.description.text, 'html.parser').get_text() if item.description else ''
            link = item.link.text if item.link else '#'
            pub_date = item.pubDate.text if item.pubDate else ''
            if not is_recent(pub_date):
                continue
            if pattern.search(f"{title} {summary}"):
                parsed_date = date_parser.parse(pub_date, tzinfos={"EDT": gettz("America/New_York")}).astimezone(timezone.utc)
                entries.append({
                    'title': title,
                    'link': link,
                    'summary': summary,
                    'published': parsed_date.strftime('%Y-%m-%d')
                })
        logging.info(f"[{label.upper()} LOCAL] {len(entries)} entries matched and parsed.")
        return entries

    all_entries = []
    download_cisa_xml()
    download_bleepingcomputer_xml()
    download_databreaches_xml()
    download_microsoftsecurity_xml()
    download_securityweek_xml()
    download_proofpoint_xml()
    download_crowdstrike_xml()

    for url in rss_urls:
        entries = fetch_feed(url)
        if entries:
            logging.info(f"[OK] {len(entries)} entries fetched from: {url}")
        else:
            logging.warning(f"[EMPTY] No entries from: {url}")
        all_entries.extend(entries)

    all_entries.extend(process_local_feed('cybersecurity-advisories.xml', 'CISA'))
    all_entries.extend(process_local_feed('bleepingcomputer.xml', 'BleepingComputer'))
    all_entries.extend(process_local_feed('databreaches.xml', 'DataBreaches'))
    all_entries.extend(process_local_feed('microsoftsecurity.xml', 'MicrosoftSecurity'))
    all_entries.extend(process_local_feed('securityweek.xml', 'SecurityWeek'))
    all_entries.extend(process_local_feed('proofpoint.xml', 'Proofpoint'))
    all_entries.extend(process_local_feed('crowdstrike.xml', 'CrowdStrike'))

    unique = {(e['title'], e['link']): e for e in all_entries}
    with open(json_filename, 'w') as f:
        json.dump(list(unique.values()), f, indent=4)

# UI – Streamlit
st.title("Cybersecurity News Dashboard")

col1, col2 = st.columns([1, 3])
with col1:
    date_range = st.date_input("Filter by Date Range", [])
with col2:
    keyword = st.text_input("Search by Keyword").strip().lower()

if is_json_outdated('cybersecnews.json'):
    with st.spinner("Retrieving Articles..."):
        thread = threading.Thread(target=process_rss_feeds)
        thread.start()
        thread.join()

if os.path.exists('cybersecnews.json'):
    with open('cybersecnews.json', 'r') as f:
        data = json.load(f)

    df = pd.DataFrame(data)
    df['published'] = pd.to_datetime(df['published'])

    if len(date_range) == 2:
        start_date, end_date = date_range
        df = df[(df['published'].dt.date >= start_date) & (df['published'].dt.date <= end_date)]
    elif len(date_range) == 1:
        df = df[df['published'].dt.date == date_range[0]]

    if keyword:
        df = df[df['title'].str.lower().str.contains(keyword) | df['summary'].str.lower().str.contains(keyword)]

    df = df.sort_values(by='published', ascending=False)

    per_row = 4
    for i in range(0, len(df), per_row):
        cols = st.columns(per_row)
        for idx, col in enumerate(cols):
            if i + idx < len(df):
                row = df.iloc[i + idx]
                with col:
                    st.write(row['published'].strftime('%Y-%m-%d'))
                    st.markdown(f"### {row['title']}")
                    preview = ' '.join(row['summary'].split()[:25])
                    st.write(f"{preview}..." if len(row['summary'].split()) > 25 else preview)
                    st.markdown(f"[Read More]({row['link']})")
