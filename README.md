# Cybersecurity News Dashboard

This project provides a Streamlit-based dashboard for aggregating, filtering, and displaying the latest cybersecurity news from multiple reputable RSS feeds.  

---

## Key Features

### 1. Automated RSS Feed Aggregation
- Fetches articles from leading cybersecurity sources, including:
  - Krebs on Security
  - BleepingComputer
  - Dark Reading
  - The Hacker News
  - Palo Alto Unit 42
  - CrowdStrike, Proofpoint, and more
- Keeps the feed current by pulling the latest articles.

### 2. Keyword-Based Filtering
- Uses a curated list of cybersecurity keywords such as APT, ransomware, zero-day, and IoT security.
- Filters results to highlight only relevant and impactful articles.

### 3. Interactive Streamlit Dashboard
- Displays news in a clean, user-friendly interface.
- Includes:
  - Article titles, summaries, and publication dates.
  - Direct links to the full articles.
  - Date range filter for focused browsing.
  - Keyword search functionality.

### 4. Duplicate and Outdated Content Removal
- Eliminates duplicate entries to avoid repetition.
- Ensures articles shown are from the last 30 days.

### 5. In-Memory Data Processing
- Processes feed data entirely in memory.
- No local files are created, making the app lightweight and easy to deploy.

### 6. Error Handling and Logging
- Logs warnings and errors for malformed feeds or network issues.
- Continues to run smoothly even if some feeds fail.

### 7. Extensible and Modular Design
- Easy to add or remove RSS feeds.
- Keyword list can be updated to match evolving cybersecurity trends.
- Modular code makes maintenance and expansion simple.

---

## Requirements

Install the following Python packages:

- streamlit
- requests
- feedparser
- beautifulsoup4
- lxml
- python-dateutil
- pandas
