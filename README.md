
## Nuclei2Dojo   
This project is a small CLI utility that: 
- Runs **Nuclei** scans (single target or list of targets). 
- Optionally uses **httpx** to fingerprint technologies and build smarter **Nuclei** tag profiles (`--profile httpx`).
- Supports custom request headers (repeatable) passed to Nuclei using `-H` / `--header`.
- Splits Nuclei results **per host** and imports/reimports them into **DefectDojo** via its API v2. 

## 1. Prerequisites   
### 1.1 Runtime & Dependencies
- **Python** 3.10+ (recommended). 
### 1.2 Nuclei CLI
Nuclei is a fast, template-driven vulnerability scanner from **ProjectDiscovery.**

Install via Go:  
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Or download a prebuilt binary from the releases page and put it in your `$PATH`

bash

```bash
# Example (Linux)
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_Linux_x86_64.zip
unzip nuclei_Linux_x86_64.zip
sudo mv nuclei /usr/local/bin/
nuclei -version
```

## 1.3 httpx (optional but recommended)
`httpx` here refers to the **ProjectDiscovery httpx CLI**, not the Python library.
It is used to probe targets and detect technologies (`-tech-detect`) before running Nuclei.

Install via Go:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Or download from the official releases or your distro (e.g. `httpx-toolkit` package in Kali). 

Verify:

```bash
httpx -version
```

> If your binary name is not `httpx` (e.g. `httpx-toolkit`), you can point the tool to it with `HTTPX_BIN` env (see below).

## 1.4 DefectDojo

You need a running **DefectDojo** instance (local Docker, remote server, etc.).
Official repository and install docs:

* GitHub: `https://github.com/DefectDojo/django-DefectDojo`
* Docs: `https://defectdojo.github.io/django-DefectDojo/`

You must have:

* API v2 enabled
* An **API token**
* The base URL of your instance (e.g. `http://127.0.0.1:42003/api/v2`)

---
## 2. Project Layout (Core Components)

* `main.py` – entry point, reads CLI arguments and dispatches to **list** or **single** mode. 
* `proc/cli.py` – defines the command-line interface, arguments, and profiles. 
* `proc/config.py` – global config, default output directory, DefectDojo base URL and headers. 
* `proc/nuclei_runner.py` – wrappers around `nuclei` for **single** and **list** mode, including severity, tags, rate limit, concurrency, template usage, and custom headers (`-H`). 
    
* `proc/pipeline.py` – main orchestration:

  * runs httpx (if `--profile httpx`)
  * derives nuclei tags from detected technologies
  * runs Nuclei
  * splits results by host
  * uploads per-host JSON into DefectDojo.
* `proc/dojo_client.py` – small DefectDojo API client (paging, product matching, import vs reimport, finding count). 
---

## 3. Installation
1. **Clone your repo**:

```bash
git clone https://github.com/BananaMoustache/nuclei2dojo.git
cd nuclei2dojo
```
---


## 4. Configuration

## 4.1 Environment variables

The tool reads several values from environment variables, with CLI flags as overrides. 

**Core DefectDojo settings** 

-   `DD_URL`    
    -   Base URL for DefectDojo API v2
        
    -   Example: `http://127.0.0.1:42003/api/v2` 
        
-   `DD_TOKEN` 
    
    -   API token used for authentication. 
        
-   `DD_PROD_TYPE_NAME` (optional, default: `Research and Development`) 
    
    -   Product type name to use when creating new products. 
        
-   `DD_PROD_TYPE_ID` (optional) 
    
    -   If set, product type ID will be used directly. 
        
-   `DD_ALLOW_BASE_FALLBACK` (optional, `"true"` / `"false"`) 
    
    -   Whether to allow base-domain fallback when matching products. 
        

**Nuclei / httpx profile settings**

-   `DD_PRODUCT_FMT` (optional, default: `"ASM ({host})"`) 
    
    -   Format string for auto-created product names; supports `{host}` and `{ip}`. 
        
-   `HTTPX_BIN` (optional, default: `httpx`) 
    
    -   Name/path of the httpx binary. 
        
-   `HTTPX_TIMEOUT` (optional, default: `900`) 
    
    -   Timeout (seconds) for httpx profiling. 
        

Output directory: 

-   Default: `outputs/` under the project root, created automatically. 
    

----------

## 5. CLI Usage

The main entry point is `main.py`.

```bash
python3 main.py --help
```

## 5.1 Global arguments (ALL)

-   `--mode {list,single}` (required) 
    
    -   `list`: scan using a targets file (one host/URL per line) 
        
    -   `single`: scan one URL/host 
        
-   `--targets PATH`
    
    -   Path to targets file (mode=list). One URL/host per line. 
        
-   `--target URL` 
    
    -   Single target URL (mode=single). 
        
-   `--dd-url DD_URL` 
    
    -   Override DefectDojo base URL (otherwise uses `DD_URL` env). 
        
-   `--dd-token DD_TOKEN` 
    
    -   Override DefectDojo API token (otherwise uses `DD_TOKEN` env). 
        
-   `--out-dir PATH` 
    
    -   Where to store per-host JSON and optional combined JSON. 
        
-   `--save-json` 
    
    -   If set, keep Nuclei JSON files instead of deleting temporary ones. 
        
-   `-s, --severity SEVERITY` 
    
    -   Nuclei severity filter, e.g. `"info"` or `"low,medium,high,critical"`. 
        
-   `-rl, --rate-limit N`
    
    -   Requests per second for Nuclei, e.g. `120`. 
        
-   `-c, --concurrency N` 
    
    -   Worker concurrency for Nuclei, e.g. `80`. 
        
-   `-H, --header "Key: Value"` (repeatable) 
    
    -   Custom header passed to Nuclei (repeatable like Nuclei `-H`). 
        
    -   Example: `-H "Authorization: Bearer XXX" -H "Cookie: a=b"`. 
        
-   `--profile {default,httpx}` 
    
    -   `default` – run Nuclei directly without tech profiling. 
        
    -   `httpx` – run httpx first, derive Nuclei tags from detected technologies, then scan with those tags (plus base include/exclude tags/templates). 
        
-   `-v, --verbose` 
    
    -   Verbose output and pass `-v` to nuclei. 
        
-   `--cve-template TEMPLATE_PATH` 
    
    -   Run only this nuclei template (any template path). 
        
-   `--cve-tech-filter KW1,KW2,...` 
    
    -   Comma-separated technology keywords required to scan a host when using `--cve-template` (from httpx `-tech-detect`).
        
-   `--cve-auto-filter` 
    
    -   If `--cve-template` is used and `--cve-tech-filter` is empty, try reading template YAML `tags:` and auto-derive a tech filter. 
        

## 5.2 Mode: `list`

Scan a list of targets from a text file:

```bash
python3 main.py \   
--mode list \ 
--targets list.txt \ 
--profile httpx \ 
--severity "low,medium,high,critical" \ 
--rate-limit 120 \ 
--concurrency 80 \ 
--save-json
```


Same as above but with custom headers (repeatable):

```bash 
python3 main.py \   
--mode list \ 
--targets list.txt \ 
--profile httpx \ 
-H "Authorization: Bearer XXX"  \ 
-H "Cookie: session=abcd"  \ 
--save-json
```

Template mode (scan only one template):

```bash
python3 main.py \   
--mode list \ 
--targets list.txt \ 
--cve-template http/cves/2025/CVE-2025-55182.yaml \ 
--save-json
```

Template mode + tech filter (only scan matching hosts):

```bash
python3 main.py \   
--mode list \ 
--targets list.txt \ 
--cve-template http/cves/2025/CVE-2025-55182.yaml \ 
--cve-tech-filter "wordpress,php"  \ 
--save-json
```

Template mode + auto filter from template tags:

```bash
python3 main.py \ 
--mode list \ 
--targets list.txt \ 
--cve-template http/cves/2025/CVE-2025-55182.yaml \ 
--cve-auto-filter \ 
--save-json
```


-   `--targets list.txt` – a file with one URL/host per line. 
    
-   If `--profile httpx` is used: 
    
    -   The pipeline runs `httpx -l list.txt -status-code -tech-detect -title -content-length -json`. 
        
    -   Technologies are mapped to Nuclei **tags** (e.g. PHP, WordPress, IIS, jQuery → related tags). 
        
    -   Nuclei is called once with: 
        
        -   `-list list.txt` 
        -   `-H "<header>"` (for each `-H/--header` you provide) 
        -   `-tags <aggregated_tags>` 
        -   `-exclude-tags fuzz,dos,bruteforce,network`     
        -   `-exclude-templates "http/fuzzing/,network/,dns/"`. 
            

Results are split per host and uploaded into DefectDojo, with products matched/created automatically. 

## 5.3 Mode: `single`

Scan a single URL/host:

```bash
python3 main.py \   
--mode single \ 
--target https://testphp.vulnweb.com \ 
--profile httpx \ 
--severity "medium,high,critical"  \ 
--rate-limit 80  \ 
--concurrency 50
``` 

Single target with custom headers:

```bash
python3 main.py \  
--mode single \ 
--target https://example.com \ 
--profile httpx \
-H "Authorization: Bearer XXX"  \
-H "X-Forwarded-For: 127.0.0.1"
``` 
-   A temporary hosts file is created with your target. 
-   If `--profile httpx` is used: 
    -   httpx runs against that target and builds **host-specific tags**. 
    -   Nuclei runs with those tags plus base include/exclude tags/templates.
-   The resulting JSON is sanitized and imported into DefectDojo for one product/engagement. 
    


