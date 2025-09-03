\# 🦅 Wayback Ripper



\*\*Wayback Ripper\*\* is a powerful all-in-one recon tool for extracting, analyzing, and hacking archived URLs from the \*\*Wayback Machine\*\*.  

It helps penetration testers, bug bounty hunters, and researchers discover hidden attack surfaces from historical data.



---



\## 🚀 Features



\- ✅ Extract all archived URLs from Wayback Machine

\- ✅ Subdomain enumeration support

\- ✅ Filter by extension (`.php`, `.js`, `.json`, `.aspx`, etc.)

\- ✅ Alive URL validation (HTTP 200, 404, etc.)

\- ✅ Smart deduplication (ignores query order, trailing slashes)

\- ✅ Output formatting: TXT, JSON, CSV

\- ✅ Integration with \*\*httpx\*\* \& \*\*nuclei\*\*

\- ✅ Time range selection (`--from 2015 --to 2020`)

\- ✅ JavaScript extractor (scrape `.js` files for endpoints \& secrets)

\- ✅ Parameter discovery mode

\- ✅ Technology fingerprinting

\- ✅ Directory tree view

\- ✅ Archive comparison mode

\- ✅ Keyword/regex search (`--grep admin,backup`)

\- ✅ Content diff mode (detect content changes across years)

\- ✅ Cloud bucket finder (S3/GCP/Azure)

\- ✅ Async super-speed mode (100k+ URLs ⚡ with `aiohttp`)

\- ✅ Interactive menu when no flags are passed



---



\## 📦 Installation



Clone the repo and install dependencies:



```bash

git clone https://github.com/yourusername/wayback-ripper.git

cd wayback-ripper

pip install -r requirements.txt

Install Playwright browser (only once):



playwright install chromium



🔥 Usage Examples



Extract all URLs:



python wayback\_ripper.py -d example.com





Filter by extension:



python wayback\_ripper.py -d example.com --filter .php,.js





Alive check:



python wayback\_ripper.py -d example.com --alive





Pipe into httpx:



python wayback\_ripper.py -d example.com | httpx -status-code -title

Pipe into nuclei:



python wayback\_ripper.py -d example.com | nuclei -t cves/





JavaScript endpoint extraction:



python wayback\_ripper.py -d example.com --js-extract





Screenshot alive URLs:



python wayback\_ripper.py -d example.com --alive --screenshot





Time range selection:



python wayback\_ripper.py -d example.com --from 2015 --to 2020





Archive comparison:



python wayback\_ripper.py -d example.com --from 2010 --to 2015 > old.txt

python wayback\_ripper.py -d example.com --from 2016 --to 2020 > new.txt

diff old.txt new.txt

Keyword/Regex search:



python wayback\_ripper.py -d example.com --grep admin,backup





Interactive mode (no flags):



python wayback\_ripper.py



⚡ Pro Tips



Use --async for massive speedups with 100k+ URLs.



Combine with httpx and nuclei for instant vulnerability hunting:



python wayback\_ripper.py -d example.com | httpx -status-code -title | nuclei -t cves/





Use screenshot mode to visually spot admin panels, dashboards, or misconfigurations.



🛠 Requirements



Install all required Python libraries via:



pip install -r requirements.txt

requirements.txt

requests

aiohttp

beautifulsoup4

lxml

tqdm

colorama

pyfiglet

playwright



🦅 Author



Built with ❤️ by Onkar BUCHKUL 

For bug bounty hunters, red teamers, and researchers.



