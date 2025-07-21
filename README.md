# Cybersecurity News Dashboard

A real-time threat feed powered by Streamlit and public threat intel RSS feeds.

## 🔍 What It Does

- Pulls headlines from top cybersecurity news sources
- Filters by keywords like `breach`, `ransomware`, `APT`, etc.
- Updates every 6 hours via GitHub Actions (cron-ready)
- Displays in a clean, responsive dashboard (Streamlit Cloud)

## Live App

[Launch Dashboard](https://your-streamlit-app-url.streamlit.app)

## Tech Stack

- Python 3
- Streamlit
- Feedparser + BeautifulSoup
- GitHub Actions (scheduled fetch)

## Setup (Local)

```bash
git clone https://github.com/youruser/cybersecuritydash.git
cd cybersecuritydash
pip install -r requirements.txt
streamlit run rss_dashboard.py

