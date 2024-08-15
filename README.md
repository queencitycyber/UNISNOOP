# 🕵️‍♂️ UNISNOOP 🔍

## Unleash the power of Unicode Normalization detection! 🚀

Are your web applications secretly normalizing Unicode? Don't let sneaky character transformations catch you off guard! UNISNOOP is here to save the day! 🦸‍♀️🦸‍♂️

### 🌟 Features

- 🔎 Detect Unicode normalization in web applications
- 🚄 Lightning-fast concurrent scanning
- 📜 Scan single URLs or entire lists
- 🕸️ Proxy support for stealthy hunting
- 🧪 Built-in PoC and verification options


### 📦 Installation

1. Ensure you have Go installed on your system.
2. Clone this repository: 

```
git clone https://github.com/queencitycyber/UNISNOOP
cd UNISNOOP
go mod init unisnoop.go
go mod tidy
go build .
```

### How UNISNOOP Detects Vulnerabilities

UNISNOOP works by sending requests with specially crafted Unicode characters that, when normalized, result in different strings. For example:

```
UNIＯN normalizes to UNION
ＳELECT normalizes to SELECT
ＦROM normalizes to FROM
```

The tool then checks if the server's response contains the normalized version but not the original version. If this pattern is detected, it indicates that the server is performing Unicode normalization, which could potentially be exploited for bypasses or other attacks.

When testing against the vulnerable Flask application (see below), UNISNOOP would likely report:

```
Unicode Normalization detected: http://localhost:5000/search
Context: Normalized 'ＳELECT' to 'SELECT'
```

This detection suggests that an attacker could potentially use Unicode characters to bypass filters or input validation, possibly leading to SQL injection or other attacks.


## 🏃‍♂️ Quick Start

### Help Menu

```

🔍 UNISNOOP 🕵️ - Detect Unicode Normalization (Testing with: SpecialK)

  -c int
    	Number of concurrent workers (default 10)
  -d	Debug output
  -list string
    	File containing list of URLs to scan
  -poc
    	Show explanation for detection
  -proof
    	Show curl command for verification
  -proxy string
    	Proxy URL (e.g. http://127.0.0.1:8080)
  -url string
    	Single URL to scan
  -v	Verbose output

```

### Scan a single URL
```
UNISNOOP -url https://example.com
```

### Scan a list of URLs
```
UNISNOOP -list urls.txt
```

### Use a proxy
```
UNISNOOP -url https://example.com -proxy http://127.0.0.1:8080
```
### Show PoC and verification command
```
UNISNOOP -url https://example.com -poc -proof
```


## 🎭 Example Vulnerable Webpage

Want to test UNISNOOP yourself? We've got you covered! Here's a fun and slightly evil educational vulnerable webpage:

```
from flask import Flask, request, render_template_string
import unicodedata

app = Flask(__name__)

@app.route('/')
def index():
    param = request.args.get('param', '')
    normalized_param = unicodedata.normalize('NFKC', param)
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>UniSnoop Test Server</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }
                h1 { color: #333; }
                pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>UniSnoop Test Server</h1>
            <h2>Original Parameter:</h2>
            <pre>{{ param }}</pre>
            <h2>Normalized Parameter:</h2>
            <pre>{{ normalized_param }}</pre>
            <p>Character codes in normalized param:</p>
            <pre>{{ char_codes }}</pre>
        </body>
        </html>
    ''', param=param, normalized_param=normalized_param, 
    char_codes=' '.join(f'U+{ord(c):04X}' for c in normalized_param))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    normalized_query = unicodedata.normalize('NFKC', query)
    # Simulating a database query (DO NOT USE IN PRODUCTION!)
    results = f"SELECT * FROM products WHERE name LIKE '%{normalized_query}%'"
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Search Results</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }
                h1 { color: #333; }
                pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>Search Results</h1>
            <h2>Original Query:</h2>
            <pre>{{ query }}</pre>
            <h2>Normalized Query:</h2>
            <pre>{{ normalized_query }}</pre>
            <h2>SQL Query (for demonstration only):</h2>
            <pre>{{ results }}</pre>
        </body>
        </html>
    ''', query=query, normalized_query=normalized_query, results=results)

if __name__ == '__main__':
    app.run(debug=True)
```    

Save this as `vulnerable_app.py` and run it:

```bash
pip install flask
python vulnerable_app.py
```

Now you have a local vulnerable webpage to test UNISNOOP! 🎈

Primary Inspiration: [https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
