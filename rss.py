import os, re, json, logging, requests, feedparser, threading
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Cybersecurity News Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Hide Streamlit UI clutter
hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    .st-emotion-cache-1dp5vir.ezrtsby2 {display: none;}
    button[title="View app in full screen"] {display: none;}
    .stDeployButton {visibility: hidden !important;}
    .st-emotion-cache-13ln4jf {visibility: hidden !important; height: 0px !important;}
    div[data-testid="stStatusWidget"],
    div[class*="statusWidget"],
    a[href*="cloud.streamlit.io"] {
        display: none !important;
        visibility: hidden !important;
        height: 0px !important;
        overflow: hidden !important;
    }
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to check if JSON file was modified on the previous day
def is_json_outdated(json_filename):
    if not os.path.exists(json_filename):
        return True  # File doesn't exist, so it's considered outdated

    # Get the last modified time of the file
    file_mod_time = datetime.fromtimestamp(os.path.getmtime(json_filename))
    current_time = datetime.now()

    # Check if the file was modified on the previous day
    yesterday = current_time - timedelta(days=1)
    return file_mod_time.date() == yesterday.date()

# Function to process RSS feeds
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
        'https://www.darkreading.com/rss.xml',
        'https://www.schneier.com/blog/atom.xml',
        'https://blog.malwarebytes.com/feed/',
        'https://security.googleblog.com/feeds/posts/default',
        'https://www.theregister.com/security/headlines.atom',
        'https://databreaches.net/feed'
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
        'cryptographic failures', 'smart contract vulnerabilities', 'insider risk', 'API abuse'
    ]

    keyword_pattern = re.compile('|'.join(keywords), re.IGNORECASE)

    def clean_title(title):
        title = re.sub(r'^\d{4}-\d{2}-\d{2} ', '', title)  # Remove leading date
        title = re.sub(r'^[#\d\s-]+', '', title)   # Remove leading hashtags or numbers
        title = re.sub(r'^[^:]+:\s*', '', title)
        return title

    def is_within_last_30_days(date_str):
        try:
            entry_date = date_parser.parse(date_str, ignoretz=True).replace(tzinfo=timezone.utc)
            thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30))
            return entry_date > thirty_days_ago
        except ValueError as e:
            logging.error(f"Date format not recognized: {date_str} - Error: {str(e)}")
            return False

    def fetch_and_filter_feed(rss_url, timeout=10):
        logging.info(f"Fetching RSS feed from: {rss_url}")
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36',
                'Referer': 'https://www.google.com/'
            }
            response = requests.get(rss_url, headers=headers, timeout=timeout)

            if response.status_code != 200:
                logging.error(f"Failed to retrieve feed: {rss_url} - Status Code: {response.status_code}")
                return []

            feed = feedparser.parse(response.content)
            if feed.bozo and not feed.entries:
                logging.error(f"Error parsing feed {rss_url}: {feed.bozo_exception}")
                return []

            filtered_entries = []

            for entry in feed.entries:
                if 'published' in entry and is_within_last_30_days(entry.published):
                    title = clean_title(entry.title if 'title' in entry else 'No Title')
                    summary = entry.summary if 'summary' in entry else 'No Summary'
                    clean_summary = BeautifulSoup(summary, 'html.parser').get_text()
                    published_date = date_parser.parse(entry.published, ignoretz=True).replace(tzinfo=timezone.utc)
                    published_date_str = published_date.strftime("%Y-%m-%d")
                    content = f"{title} {clean_summary}"
                    if keyword_pattern.search(content):
                        filtered_entries.append({
                            'title': title,
                            'link': entry.link if 'link' in entry else 'No Link',
                            'summary': clean_summary,
                            'published': published_date_str
                        })
            logging.info(f"Found {len(filtered_entries)} relevant entries in {rss_url}")
            return filtered_entries
        except requests.exceptions.Timeout:
            logging.error(f"Timeout reached while fetching feed from: {rss_url}")
            return []  # Return empty if timeout occurs
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error while fetching feed from {rss_url}: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error while fetching feed from {rss_url}: {str(e)}")
            return []

    def save_to_json(entries, json_filename):
        try:
            if os.path.exists(json_filename):
                os.remove(json_filename)

            unique_entries = {(entry['title'], entry['link']): entry for entry in entries}
            entries_no_duplicates = list(unique_entries.values())

            with open(json_filename, 'w') as json_file:
                json.dump(entries_no_duplicates, json_file, indent=4)
            logging.info("JSON file operation complete.")
        except IOError as e:
            logging.error(f"Error saving JSON file: {json_filename} - Error: {str(e)}")

    all_filtered_entries = []

    for rss_url in rss_urls:
        entries = fetch_and_filter_feed(rss_url)
        all_filtered_entries.extend(entries)

    save_to_json(all_filtered_entries, json_filename)

# Streamlit app
st.title("Cybersecurity News Dashboard")

# Run the fetching process with a spinner if the JSON file is outdated or missing
def run_fetching_process():
    process_rss_feeds()

if is_json_outdated('cybersecnews.json'):
    with st.spinner("Retrieving Articles... Please wait."):
        thread = threading.Thread(target=run_fetching_process)
        thread.start()
        thread.join()

# Load JSON data and display the dashboard
if os.path.exists('cybersecnews.json'):
    with open('cybersecnews.json', 'r') as file:
        data = json.load(file)

    df = pd.DataFrame(data)

    # Convert 'published' to datetime for accurate sorting
    df['published'] = pd.to_datetime(df['published'])

    # Sort by the 'published' column in descending order
    df = df.sort_values(by='published', ascending=False)

    articles_per_row = 4

    for i in range(0, len(df), articles_per_row):
        cols = st.columns(articles_per_row)
        for idx, col in enumerate(cols):
            if i + idx < len(df):
                row = df.iloc[i + idx]
                with col:
                    st.write(row['published'])
                    st.markdown(f"### {row['title']}")
                    summary = ' '.join(row['summary'].split()[:25]) + ("..." if len(row['summary'].split()) > 25 else "")
                    st.write(summary)
                    st.markdown(f"[Read More]({row['link']})")
