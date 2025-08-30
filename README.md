# CTI Darknet Analysis Platform

A comprehensive Cyber Threat Intelligence platform for analyzing darknet forums and marketplaces.

## Features

- **Tor Integration**: Anonymous crawling via Tor network with circuit management
- **Delta Crawling**: Only crawls new/updated content to reduce bandwidth
- **Session Management**: Handle CAPTCHA-protected sites with manual session import
- **NLP Processing**: Extract IOCs, malware families, threat actors using spaCy
- **Elasticsearch**: Store and search threat intelligence data
- **Decoupled Architecture**: Separate crawler (producer) and processor (consumer)

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

2. **Start Tor** (install separately):
   ```bash
   # Ubuntu/Debian
   sudo apt install tor
   sudo systemctl start tor
   ```

3. **Start Elasticsearch** (install separately):
   ```bash
   # Download and run Elasticsearch locally
   # Default: http://localhost:9200
   ```

4. **Add sessions for CAPTCHA-protected sites**:
   ```bash
   python tools/session_helper.py add example.onion --cookies "session_id=abc123; csrf_token=xyz789"
   ```

5. **Run crawler**:
   ```bash
   python run_crawler.py
   ```

6. **Run processor** (in separate terminal):
   ```bash
   python run_processor.py
   ```

## Session Management

For CAPTCHA-protected sites:

1. Manually solve CAPTCHA in browser
2. Copy cookies from Developer Tools
3. Add session: `python tools/session_helper.py add domain.onion --cookies "cookie_string"`
4. Sessions are automatically used by crawler

## Architecture

```
Tor Network → Crawler (Producer) → Raw Data Queue → Processor (Consumer) → Elasticsearch → Kibana
```

- **Producer**: Scrapy spider crawls .onion sites via Tor
- **Consumer**: Processes HTML, extracts entities with NLP, indexes to Elasticsearch
- **State Management**: SQLite tracks crawled URLs and content hashes
- **Session Management**: Handles authentication cookies for protected sites

## Configuration

Edit `config/settings.py` to customize:
- Target .onion URLs
- Crawling delays and limits  
- Database paths
- Elasticsearch settings

## Target Sites

Currently configured for:
- `santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion`
- `dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion`
- `bestteermb42clir6ux7xm76d4jjodh3fpahjqgbddbmfrgp4skg2wqd.onion`
- `bfdxjkv5e2z3ilrifzbnvxxvhbzsj67akjpj3zc6smzr4vv6oz565gyd.onion`

## Extracted Entities

- **IOCs**: IP addresses, domains, file hashes, crypto wallets
- **CVEs**: Vulnerability identifiers
- **Malware**: Family names, executables
- **Threat Actors**: Group names and affiliations
- **Infrastructure**: URLs, registry keys, file paths

## Commands

```bash
# Session management
python tools/session_helper.py list
python tools/session_helper.py test domain.onion http://domain.onion/test

# Run components
python run_crawler.py          # Start crawler
python run_processor.py        # Start processor (continuous)
python run_processor.py batch  # Process existing files once
```

## Legal Notice

This tool is for legitimate cybersecurity research and threat intelligence purposes only. Users are responsible for compliance with applicable laws and regulations.

