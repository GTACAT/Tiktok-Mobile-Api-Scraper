# TikTok Mobile Scraper Framework

A Python-based framework to scrape TikTok user posts and hashtag-related videos using the mobile API. The scraper handles dynamic signature generation (`X-Argus`, `X-Gorgon`, `X-Ladon`) and supports optional proxy rotation.

---

## Features

- **Dynamic Signature Generation**
  - X-Argus, X-Gorgon, X-Khronos, X-Ladon headers
- **Scrape By Username or Hashtag**
- **Proxy Support** (optional, via `proxy.txt`)
- **Advanced Crypto Implementation**
  - AES, Simon cipher, SM3 hash, Protobuf encoding

---

## Setup

### Requirements
Install dependencies with pip:
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install requests
pip install pycryptodome
pip install pycryptodomex
pip install curl_cffi
```

### Optional: Proxy Configuration
Create a file `proxy.txt`:
```
http://user:pass@host:port
socks5://host:port
```
If missing or empty, proxies are disabled.

---

## Usage

### Run the CLI
```bash
python tiktok_scraper_en.py
```
- Input `username` or `#hashtag`
- Input number of videos to scrape or type `all`
- Results saved to `video_json_details/` as JSON

---

## Quick Start Tutorial

```bash
# Clone repository
https://github.com/yourusername/tiktok-mobile-scraper.git
cd tiktok-mobile-scraper

# Install dependencies
pip install -r requirements.txt

# Optional: Add proxies
nano proxy.txt

# Run scraper
python tiktok_scraper_en.py
```

---

## Project Structure
```
Tiktok-Mobile-Api-Scraper/
├── tiktok_scraper_en.py       # Main scraper
├── requirements.txt           # Python dependencies
├── .gitignore                 
├── LICENSE                    
└── README.md                  
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This tool is provided for educational and research purposes only. Use responsibly. The author assumes no liability for misuse.
t.me/WolfofChinatown

---

## Support

If you find this project helpful, consider supporting me:

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/woct)
