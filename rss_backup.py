import os, re, json, logging, requests, feedparser, threading
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
import pandas as pd
import streamlit as st

if os.path.exists('cybersecnews.json'):
    os.remove('cybersecnews.json')

st.set_page_config(
    page_title="Cybersecurity News Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Hide UI clutter
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

def process_rss_feeds(json_filename='cybersecnews.json'):
    rss_urls = [
        'https://krebsonsecurity.com/feed/',
        'https://malware-traffic-analysis.net/blog-entries.rss',
        'https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml',
        'https://cybersecuritynews.com/feed/',
        'https://www.bleepingcomputer.com/feed/',
        'https://www.securityweek.com/feed/',
        'https://www.darkreading.com/rss.xml',
        'https://www.zdnet.com/topic/security/rss.xml',
        'https://feeds.feedburner.com/TheHackersNews',
        'https://cert.gov.ua/api/articles/rss',
        'https://securityboulevard.com/feed/',
        'https://unit42.paloaltonetworks.com/feed/',
        'https://securelist.com/feed/',
        'https://www.schneier.com/blog/atom.xml',
        'https://blog.malwarebytes.com/feed/',
        'https://security.googleblog.com/feeds/posts/default',
        'https://www.theregister.com/security/headlines.atom',
        'https://databreaches.net/feed',
        'https://feeds.reuters.com/reuters/technologyNews'
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
        try:
            dt = date_parser.parse(date_str, ignoretz=True).replace(tzinfo=timezone.utc)
            return dt > datetime.now(timezone.utc) - timedelta(days=30)
        except:
            return False

    def fetch_feed(url):
        try:
            res = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if res.status_code != 200:
                return []
            feed = feedparser.parse(res.content)
            if feed.bozo or not feed.entries:
                return []

            entries = []
            for e in feed.entries:
                if 'published' not in e or not is_recent(e.published):
                    continue
                title = clean_title(e.get('title', 'No Title'))
                summary = BeautifulSoup(e.get('summary', ''), 'html.parser').get_text()
                pub_date = date_parser.parse(e.published, ignoretz=True).replace(tzinfo=timezone.utc)
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

    all_entries = []
    for url in rss_urls:
        all_entries.extend(fetch_feed(url))

    unique = {(e['title'], e['link']): e for e in all_entries}
    with open(json_filename, 'w') as f:
        json.dump(list(unique.values()), f, indent=4)

# UI – Title and Filter Inputs
st.title("Cybersecurity News Dashboard")

col1, col2 = st.columns([1, 3])
with col1:
    date_range = st.date_input("Filter by Date Range", [])
with col2:
    keyword = st.text_input("Search by Keyword").strip().lower()

# Update JSON if outdated
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

    # Apply date range filter
    if len(date_range) == 2:
        start_date, end_date = date_range
        df = df[(df['published'].dt.date >= start_date) & (df['published'].dt.date <= end_date)]
    elif len(date_range) == 1:
        df = df[df['published'].dt.date == date_range[0]]

    # Apply keyword filter
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
