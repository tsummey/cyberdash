# ... all imports unchanged ...
import re, json, logging, requests, feedparser, threading
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
from dateutil.tz import gettz
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Cybersecurity News Dashboard", layout="wide", initial_sidebar_state="collapsed")

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
    'https://www.theregister.com/security/headlines.atom',
    'https://www.proofpoint.com/us/rss.xml'
]

special_sources = [
    #('CISA', 'https://www.cisa.gov/sites/default/files/feeds/cybersecurity-advisories.xml'),
    ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/'),
    ('DataBreaches', 'https://databreaches.net/feed/'),
    ('MicrosoftSecurity', 'https://www.microsoft.com/en-us/security/blog/feed/'),
    ('SecurityWeek', 'https://feeds.feedburner.com/securityweek'),
    ('Proofpoint', 'https://www.proofpoint.com/us/rss.xml'),
    ('CrowdStrike', 'https://www.crowdstrike.com/blog/feed/')
]

headers_spoofed = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/115.0.0.0 Safari/537.36'
    ),
    'Accept': 'application/rss+xml,application/xml;q=0.9,*/*;q=0.8',
    'Referer': 'https://www.google.com/'
}

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
    except:
        return False

def fetch_rss_entries(url):
    try:
        res = requests.get(url, headers=headers_spoofed, timeout=15)
        res.raise_for_status()
        feed = feedparser.parse(res.content)
        if feed.bozo or not feed.entries:
            logging.warning(f"[EMPTY] No entries from: {url}")
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
        logging.info(f"[OK] {len(entries)} entries fetched from: {url}")
        return entries
    except Exception as e:
        logging.warning(f"[FAIL] {url} | {e}")
        return []

def process_feed_content(xml_bytes, label):
    try:
        soup = BeautifulSoup(xml_bytes, 'xml')
        items = soup.find_all('item')
        logging.info(f"[{label}] Found {len(items)} items.")
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
        logging.info(f"[{label}] {len(entries)} entries matched and parsed.")
        return entries
    except Exception as e:
        logging.warning(f"[FAIL] {label} feed parsing failed | {e}")
        return []

def process_all_feeds():
    all_entries = []

    for url in rss_urls:
        all_entries.extend(fetch_rss_entries(url))

    for label, url in special_sources:
        try:
            res = requests.get(url, headers=headers_spoofed, timeout=15)
            res.raise_for_status()
            all_entries.extend(process_feed_content(res.content, label))
        except Exception as e:
            logging.warning(f"[FAIL] {label} feed fetch failed | {e}")

    unique = {(e['title'], e['link']): e for e in all_entries}
    return list(unique.values())

# Streamlit UI
st.title("Cybersecurity News Dashboard")
col1, col2 = st.columns([1, 3])
with col1:
    date_range = st.date_input("Filter by Date Range", [])
with col2:
    keyword = st.text_input("Search by Keyword").strip().lower()

@st.cache_data(ttl=3600, show_spinner=False)
def get_data():
    return process_all_feeds()

with st.spinner("Retrieving Articles..."):
    data = get_data()

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
