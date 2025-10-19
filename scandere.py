import os
import re
import time
import random
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json

# ==============================================================
# SELENIUM SETUP (for DOM-based XSS detection)
# ==============================================================
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("[!] Selenium not available. DOM-based XSS detection will be skipped.")
    print("    Install with: pip install selenium")

# ==============================================================
# CONFIGURATION & SESSION MANAGEMENT
# ==============================================================

class ScanConfig:
    """Configuration for authenticated scanning"""
    def __init__(self):
        self.session = requests.Session()
        self.cookies = {}
        self.headers = {"User-Agent": "Mozilla/5.0 (SCANDERE-XSS)"}
        self.auth_token = None
        
    def set_auth_cookies(self, cookies: Dict[str, str]):
        """Set authentication cookies for session"""
        self.cookies.update(cookies)
        self.session.cookies.update(cookies)
        
    def set_auth_header(self, header_name: str, token: str):
        """Set authentication header (e.g., Bearer token)"""
        self.headers[header_name] = token
        self.auth_token = token
        
    def login(self, login_url: str, credentials: Dict[str, str], 
              method: str = "POST") -> bool:
        """Perform login and store session"""
        try:
            if method.upper() == "POST":
                r = self.session.post(login_url, data=credentials, 
                                     headers=self.headers, timeout=10)
            else:
                r = self.session.get(login_url, params=credentials, 
                                    headers=self.headers, timeout=10)
            
            self.cookies.update(self.session.cookies.get_dict())
            return r.status_code == 200
        except Exception as e:
            print(f"[!] Login failed: {e}")
            return False

# ==============================================================
# 1️⃣  ENDPOINT DISCOVERY (Enhanced with form discovery)
# ==============================================================

def discover_endpoints(domain: str, limit: int = 25, discover_forms: bool = True) -> Tuple[List[str], List[Dict]]:
    """Discover same-domain endpoints and forms."""
    endpoints = []
    forms = []
    
    try:
        if not domain.startswith("http"):
            domain = "https://" + domain

        base_parsed = urlparse(domain)
        base_host = base_parsed.netloc.replace("www.", "")

        response = requests.get(domain, timeout=3)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Discover links
        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(domain, href)
            parsed = urlparse(full_url)
            host = parsed.netloc.replace("www.", "")

            if base_host in host:
                endpoints.append(full_url)

        # Discover forms
        if discover_forms:
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                full_action = urljoin(domain, action)
                
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    inp_name = inp.get('name', '')
                    inp_type = inp.get('type', 'text')
                    if inp_name:
                        inputs.append({
                            'name': inp_name,
                            'type': inp_type,
                            'value': inp.get('value', '')
                        })
                
                if inputs:
                    forms.append({
                        'action': full_action,
                        'method': method,
                        'inputs': inputs
                    })

        endpoints = list(dict.fromkeys(endpoints))
        if domain not in endpoints:
            endpoints.insert(0, domain)

        if len(endpoints) > limit:
            print(f"[!] {len(endpoints)} endpoints found, limiting to top {limit}")
            endpoints = endpoints[:limit]

        return endpoints, forms

    except Exception as e:
        print(f"Error discovering endpoints: {e}")
        return [domain], []


# ==============================================================
# 2️⃣  PARAMETER HELPERS (Enhanced)
# ==============================================================

COMMON_PARAMS = [
    "q", "search", "s", "query", "id", "page", "term", "keyword",
    "email", "name", "username", "redirect", "next", "url", "ref",
    "category", "view", "path", "lang", "file", "img", "title", "desc",
    "comment", "message", "content", "data", "input", "text"
]

def extract_params_from_url(url: str) -> List[str]:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query))
    return list(qs.keys()) or COMMON_PARAMS

def _build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query))
    qs[param] = value
    new_query = urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


# ==============================================================
# 3️⃣  ENHANCED XSS DETECTION
# ==============================================================

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "javascript:alert(1)",
    "<a href='javascript:alert(1)'>click</a>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=\"alert(1)\">",
    "<svg><script>alert(1)</script></svg>",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
]

# DOM XSS sinks to check
DOM_XSS_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout", "setInterval", "location.href", "location.replace",
    ".src=", ".href=", "insertAdjacentHTML"
]

def detect_reflected_xss(endpoint: str, config: ScanConfig, timeout: int = 3, 
                         fast_mode: bool = False) -> Dict:
    """Detect reflected XSS with adaptive payload set."""
    found = False
    best_conf = 0.0
    best_method = None
    best_snippet = ""
    found_param = None

    try:
        params_to_test = extract_params_from_url(endpoint)
        payloads = XSS_PAYLOADS if fast_mode else XSS_PAYLOADS + [
            "<math><mi><script>alert(1)</script></mi></math>",
            "<style>@import'javascript:alert(1)';</style>"
        ]
        
        for param in params_to_test[:3]:
            for payload in random.sample(payloads, min(8 if fast_mode else 15, len(payloads))):
                try:
                    test_url = _build_url_with_param(endpoint, param, payload)
                    r = config.session.get(test_url, timeout=timeout, 
                                          headers=config.headers, cookies=config.cookies)
                    text = r.text or ""
                    
                    if payload in text:
                        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                        snippet = text[:1000]
                        if escaped in text:
                            conf, method = 0.4, "reflected-escaped"
                        else:
                            conf, method = 0.85, "reflected-unescaped"
                        if conf > best_conf:
                            found, best_conf, best_method = True, conf, method
                            best_snippet, found_param = snippet, param
                except Exception:
                    continue
                    
        return {
            "found": found,
            "confidence": best_conf,
            "method": best_method or "no-reflection",
            "snippet": best_snippet,
            "param": found_param
        }
    except Exception as e:
        return {"found": False, "confidence": 0.0, "method": "error", "error": str(e)}


def detect_dom_xss(endpoint: str, timeout: int = 10) -> Dict:
    """Detect DOM-based XSS using Selenium."""
    if not SELENIUM_AVAILABLE:
        return {"found": False, "confidence": 0.0, "method": "selenium-unavailable"}
    
    try:
        chrome_opts = Options()
        chrome_opts.add_argument("--headless")
        chrome_opts.add_argument("--no-sandbox")
        chrome_opts.add_argument("--disable-dev-shm-usage")
        chrome_opts.add_argument("--disable-gpu")
        
        driver = webdriver.Chrome(options=chrome_opts)
        driver.set_page_load_timeout(timeout)
        
        # Test with DOM XSS payload in URL fragment
        test_payload = "#<img src=x onerror=alert(1)>"
        driver.get(endpoint + test_payload)
        time.sleep(2)
        
        # Check for alert dialog
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.dismiss()
            driver.quit()
            return {
                "found": True,
                "confidence": 0.95,
                "method": "dom-xss-confirmed",
                "snippet": f"Alert triggered: {alert_text}"
            }
        except:
            pass
        
        # Check page source for dangerous sinks
        page_source = driver.page_source
        script_content = driver.execute_script("return document.documentElement.innerHTML")
        
        found_sinks = [sink for sink in DOM_XSS_SINKS if sink in script_content]
        
        driver.quit()
        
        if found_sinks:
            return {
                "found": True,
                "confidence": 0.6,
                "method": "dom-xss-sinks-found",
                "snippet": f"Potential sinks: {', '.join(found_sinks[:5])}"
            }
        
        return {"found": False, "confidence": 0.0, "method": "no-dom-xss"}
        
    except Exception as e:
        return {"found": False, "confidence": 0.0, "method": "error", "error": str(e)}


def detect_stored_xss(endpoint: str, config: ScanConfig, forms: List[Dict], 
                      timeout: int = 5) -> Dict:
    """Detect stored XSS by submitting payloads and checking if they persist."""
    results = []
    unique_marker = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    for form in forms:
        action = form['action']
        method = form['method']
        
        # Create unique payload with marker
        payload = f"<script>alert('{unique_marker}')</script>"
        
        # Build form data
        form_data = {}
        for inp in form['inputs']:
            if inp['type'] in ['text', 'textarea', 'email', 'search']:
                form_data[inp['name']] = payload
            elif inp['type'] == 'hidden':
                form_data[inp['name']] = inp.get('value', '')
            else:
                form_data[inp['name']] = 'test'
        
        try:
            # Submit form
            if method == 'POST':
                r = config.session.post(action, data=form_data, 
                                       headers=config.headers, 
                                       cookies=config.cookies, timeout=timeout)
            else:
                r = config.session.get(action, params=form_data, 
                                      headers=config.headers, 
                                      cookies=config.cookies, timeout=timeout)
            
            # Check if payload is reflected in response
            if unique_marker in r.text:
                escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
                if escaped not in r.text:
                    results.append({
                        "found": True,
                        "confidence": 0.8,
                        "method": "stored-xss-unescaped",
                        "snippet": r.text[:800],
                        "form_action": action
                    })
                else:
                    results.append({
                        "found": True,
                        "confidence": 0.5,
                        "method": "stored-xss-escaped",
                        "snippet": r.text[:800],
                        "form_action": action
                    })
        except Exception as e:
            continue
    
    if results:
        # Return highest confidence result
        best = max(results, key=lambda x: x['confidence'])
        return best
    
    return {"found": False, "confidence": 0.0, "method": "no-stored-xss"}


def detect_xss_comprehensive(endpoint: str, config: ScanConfig, forms: List[Dict] = None,
                             timeout: int = 3, fast_mode: bool = False, 
                             check_dom: bool = True, check_stored: bool = True) -> Dict:
    """Comprehensive XSS detection combining all methods."""
    results = {
        "reflected": {"found": False, "confidence": 0.0},
        "dom": {"found": False, "confidence": 0.0},
        "stored": {"found": False, "confidence": 0.0}
    }
    
    # Test reflected XSS
    reflected = detect_reflected_xss(endpoint, config, timeout, fast_mode)
    results["reflected"] = reflected
    
    # Test DOM XSS if enabled and Selenium available
    if check_dom and SELENIUM_AVAILABLE:
        try:
            dom = detect_dom_xss(endpoint, timeout)
            results["dom"] = dom
        except Exception as e:
            results["dom"] = {"found": False, "confidence": 0.0, "error": str(e)}
    
    # Test stored XSS if forms provided
    if check_stored and forms:
        try:
            stored = detect_stored_xss(endpoint, config, forms, timeout)
            results["stored"] = stored
        except Exception as e:
            results["stored"] = {"found": False, "confidence": 0.0, "error": str(e)}
    
    # Aggregate results
    max_conf = max(r.get("confidence", 0.0) for r in results.values())
    any_found = any(r.get("found", False) for r in results.values())
    
    methods = [k for k, v in results.items() if v.get("found", False)]
    
    return {
        "found": any_found,
        "confidence": max_conf,
        "method": ", ".join(methods) if methods else "no-xss",
        "details": results,
        "snippet": next((r.get("snippet", "") for r in results.values() 
                        if r.get("found")), "")
    }


# ==============================================================
# 4️⃣  SQL INJECTION DETECTION (unchanged but uses config)
# ==============================================================

SQLI_ERROR_PATTERNS = [
    "sql syntax", "syntax error", "mysql", "sql error", "ora-", "postgresql",
    "pdoexception", "warning: sqlite", "nativeclient::"
]
SQLI_TRUE = "1' OR '1'='1"
SQLI_FALSE = "1' OR '1'='2"
SQLI_SLEEP = "1' OR (SELECT IF(1=1, SLEEP(5), 0))-- "

def detect_sqli(endpoint: str, config: ScanConfig, timeout: int = 3, 
                do_time_test: bool = False) -> Dict:
    """Detect SQL Injection using error-based, boolean, and time-based."""
    parsed = urlparse(endpoint)
    qs = dict(parse_qsl(parsed.query))
    param = list(qs.keys())[0] if qs else 'id'

    def make_url(payload: str) -> str:
        return _build_url_with_param(endpoint, param, payload)

    try:
        r = config.session.get(make_url("'"), timeout=timeout, 
                              headers=config.headers, cookies=config.cookies)
        body = (r.text or "").lower()
        snippet = body[:800]
        if any(pat in body for pat in SQLI_ERROR_PATTERNS):
            return {"found": True, "confidence": 0.65, "method": "error-based", 
                   "snippet": snippet}

        r_true = config.session.get(make_url(SQLI_TRUE), timeout=timeout,
                                   headers=config.headers, cookies=config.cookies)
        r_false = config.session.get(make_url(SQLI_FALSE), timeout=timeout,
                                    headers=config.headers, cookies=config.cookies)
        if r_true.text != r_false.text:
            diff_len = abs(len(r_true.text) - len(r_false.text))
            conf = 0.9 if diff_len > 80 else 0.65
            return {"found": True, "confidence": conf, "method": "boolean-diff", 
                   "snippet": r_true.text[:600]}

        if do_time_test:
            start = time.time()
            config.session.get(make_url(SQLI_SLEEP), timeout=timeout + 5,
                             headers=config.headers, cookies=config.cookies)
            if time.time() - start > 4:
                return {"found": True, "confidence": 0.95, "method": "time-based", 
                       "snippet": ""}

        return {"found": False, "confidence": 0.0, "method": "no-evidence", 
               "snippet": snippet}
    except Exception as e:
        return {"found": False, "confidence": 0.0, "method": "error", "error": str(e)}


# ==============================================================
# 5️⃣  OPEN REDIRECT DETECTION (unchanged but uses config)
# ==============================================================

def detect_open_redirect(endpoint: str, config: ScanConfig, timeout: int = 3) -> Dict:
    parsed = urlparse(endpoint)
    qs = dict(parse_qsl(parsed.query))
    param = list(qs.keys())[0] if qs else 'redirect'
    test_url = _build_url_with_param(endpoint, param, "https://evil.com")
    try:
        r = config.session.get(test_url, allow_redirects=False, timeout=timeout,
                              headers=config.headers, cookies=config.cookies)
        loc = r.headers.get('Location', '')
        found = False
        if r.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
            found = True
        return {"found": found, "status_code": r.status_code, "location": loc, 
               "confidence": 0.7 if found else 0.0}
    except Exception as e:
        return {"found": False, "status_code": None, "location": "", 
               "confidence": 0.0, "error": str(e)}


# ==============================================================
# 6️⃣  PARALLEL SCANNING WRAPPER (Enhanced)
# ==============================================================

def scan_single_endpoint(endpoint: str, config: ScanConfig, forms: List[Dict] = None,
                        confirm: bool = False, do_time_test: bool = False, 
                        fast_mode: bool = False, check_dom: bool = True, 
                        check_stored: bool = True) -> Dict:
    """Scan one endpoint with comprehensive tests."""
    result = {
        'endpoint': endpoint,
        'xss': {"found": False, "confidence": 0.0, "method": None, "snippet": ""},
        'sqli': {"found": False, "confidence": 0.0, "method": None, "snippet": ""},
        'open_redirect': {"found": False, "status_code": None, "location": "", 
                         "confidence": 0.0}
    }

    try:
        endpoint_forms = [f for f in (forms or []) if endpoint in f.get('action', '')]
        result['xss'].update(detect_xss_comprehensive(
            endpoint, config, endpoint_forms, fast_mode=fast_mode,
            check_dom=check_dom, check_stored=check_stored
        ))
    except Exception as e:
        result['xss'].update({"found": False, "method": "error", "error": str(e)})

    try:
        result['sqli'].update(detect_sqli(endpoint, config, 
                                         do_time_test=(confirm and do_time_test)))
    except Exception as e:
        result['sqli'].update({"found": False, "method": "error", "error": str(e)})

    try:
        result['open_redirect'].update(detect_open_redirect(endpoint, config))
    except Exception as e:
        result['open_redirect'].update({"found": False, "method": "error", "error": str(e)})

    return result


def check_web_flaws(endpoints: List[str], forms: List[Dict], config: ScanConfig,
                   confirm: bool = False, do_time_test: bool = False, 
                   fast_mode: bool = False, check_dom: bool = True,
                   check_stored: bool = True) -> List[Dict]:
    """Run all vulnerability checks concurrently."""
    results = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_ep = {
            executor.submit(scan_single_endpoint, ep, config, forms, confirm, 
                          do_time_test, fast_mode, check_dom, check_stored): ep
            for ep in endpoints
        }
        for i, future in enumerate(as_completed(future_to_ep), 1):
            ep = future_to_ep[future]
            try:
                result = future.result()
                print(f"[{i}/{len(endpoints)}] Scanned: {ep}")
                results.append(result)
            except Exception as e:
                print(f"Error scanning {ep}: {e}")
    return results


# ==============================================================
# 7️⃣  HTML REPORT GENERATOR (Enhanced)
# ==============================================================

def generate_html_report(results: List[Dict], filename: str, summary: Dict = None):
    """Generate enhanced dark-themed HTML report."""
    if summary is None:
        summary = {
            "target": "",
            "endpoints_scanned": len(results),
            "endpoints_with_issues": sum(
                1 for r in results if (r.get('xss', {}).get('found') or 
                                      r.get('sqli', {}).get('found') or 
                                      r.get('open_redirect', {}).get('found'))
            )
        }

    css = """
    body { background-color: #0b0f13; color: #e6eef8; font-family: Arial; padding: 20px; }
    .title { color: #00d1ff; font-size: 32px; margin-bottom: 5px; }
    .subtitle { color: #9ad7ff; margin-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { padding: 10px; border: 1px solid #20272b; text-align: left; vertical-align: top; }
    th { background: #071018; color: #9ad7ff; }
    tr:nth-child(even) { background: #071018; }
    .safe { background: #0b3b12; color: #b7f5c7; }
    .vuln { background: #3b0b0b; color: #ffb7b7; }
    .warn { background: #3b2b0b; color: #ffe9b7; }
    .confidence { font-size: 12px; color: #b7cbd8; }
    .snippet { font-family: monospace; white-space: pre-wrap; max-height: 160px; 
               overflow: auto; background: #061014; padding: 8px; border: 1px solid #23303a; 
               margin-top:6px; color: #dbeffc; }
    .summary { margin-top: 10px; padding: 10px; background: #071018; 
              border: 1px solid #23303a; }
    details { margin-top: 6px; }
    .xss-details { font-size: 11px; color: #a8c5d8; margin-top: 4px; }
    """

    html = [
        "<!doctype html>",
        "<html><head><meta charset='utf-8'><title>SCANDERE - Enhanced Scan Report</title>",
        f"<style>{css}</style></head><body>",
        "<div class='title'>ENHANCED SCAN REPORT - SCANDERE</div>",
        "<div class='subtitle'>Comprehensive XSS Detection (Reflected + DOM + Stored)</div>",
        "<div class='summary'>"
        f"<strong>Endpoints scanned:</strong> {summary.get('endpoints_scanned', 0)} &nbsp;&nbsp;"
        f"<strong>Endpoints with issues:</strong> {summary.get('endpoints_with_issues', 0)}"
        "</div>",
        "<table>",
        "<thead><tr><th>Endpoint</th><th>XSS</th><th>SQLi</th><th>Open Redirect</th></tr></thead>",
        "<tbody>"
    ]

    for r in results:
        def vuln_cell_xss(v):
            found, conf, method = v.get('found'), v.get('confidence', 0.0), v.get('method', '')
            snippet = v.get('snippet', '')
            details = v.get('details', {})
            
            if found:
                cls = "vuln" if conf >= 0.75 else "warn"
                cell = f"<td class='{cls}'>FOUND<br><span class='confidence'>conf: {conf:.2f}, method: {method}</span>"
                
                # Add XSS type breakdown
                if details:
                    types = []
                    if details.get('reflected', {}).get('found'):
                        types.append(f"Reflected({details['reflected']['confidence']:.2f})")
                    if details.get('dom', {}).get('found'):
                        types.append(f"DOM({details['dom']['confidence']:.2f})")
                    if details.get('stored', {}).get('found'):
                        types.append(f"Stored({details['stored']['confidence']:.2f})")
                    if types:
                        cell += f"<div class='xss-details'>Types: {', '.join(types)}</div>"
                
                if snippet:
                    cell += f"<details><summary>snippet</summary><div class='snippet'>{snippet}</div></details>"
                return cell + "</td>"
            return f"<td class='safe'>SAFE<br><span class='confidence'>conf: {conf:.2f}</span></td>"

        def vuln_cell(v):
            found, conf, method = v.get('found'), v.get('confidence', 0.0), v.get('method', '')
            snippet = v.get('snippet', '')
            if found:
                cls = "vuln" if conf >= 0.75 else "warn"
                return f"<td class='{cls}'>FOUND<br><span class='confidence'>conf: {conf:.2f}, method: {method}</span>" + \
                       (f"<details><summary>snippet</summary><div class='snippet'>{snippet}</div></details>" if snippet else "") + "</td>"
            return f"<td class='safe'>SAFE<br><span class='confidence'>conf: {conf:.2f}</span></td>"

        def redirect_cell(v):
            if v.get('found'):
                return f"<td class='warn'>POTENTIAL<br><span class='confidence'>status: {v.get('status_code')}, conf: {v.get('confidence', 0.0):.2f}</span></td>"
            return f"<td class='safe'>SAFE<br><span class='confidence'>conf: {v.get('confidence', 0.0):.2f}</span></td>"

        html.append("<tr>")
        html.append(f"<td>{r.get('endpoint')}</td>")
        html.append(vuln_cell_xss(r.get('xss', {})))
        html.append(vuln_cell(r.get('sqli', {})))
        html.append(redirect_cell(r.get('open_redirect', {})))
        html.append("</tr>")

    html.append("</tbody></table></body></html>")
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(html))
    print(f"[+] Report saved to: {filename}")


# ==============================================================
# 8️⃣  BANNER
# ==============================================================

def print_banner():
    """Display ASCII banner."""
    banner = """
\033[96m
███████╗ ██████╗ █████╗ ███╗   ██╗██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝
███████╗██║     ███████║██╔██╗ ██║██║  ██║█████╗  ██████╔╝█████╗  
╚════██║██║     ██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  
███████║╚██████╗██║  ██║██║ ╚████║██████╔╝███████╗██║  ██║███████╗
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
\033[0m
\033[93m          Advanced Web Vulnerability Scanner v2.0\033[0m
\033[90m          Reflected | DOM | Stored XSS + SQLi + Open Redirects\033[0m
\033[90m          ═══════════════════════════════════════════════════\033[0m

                    =====  Developed by Cybermj ====
"""
    print(banner)


# ==============================================================
# 9️⃣  MAIN EXECUTION FUNCTION
# ==============================================================

def main(target: str, output: str = "scan_report.html", 
         
         auth_cookies: Dict = None, login_url: str = None, 
         credentials: Dict = None, fast_mode: bool = False,
         check_dom: bool = True, check_stored: bool = True):
    """
    Main scanning function with authentication support.
    
    Args:
        target: Target domain to scan
        output: Output HTML report filename
        auth_cookies: Dict of cookies for authentication
        login_url: URL to perform login (if credentials provided)
        credentials: Dict with login credentials
        fast_mode: Use fewer payloads for faster scanning
        check_dom: Enable DOM-based XSS detection (requires Selenium)
        check_stored: Enable stored XSS detection
    """
    print("\n[*] Initializing SCANDERE Enhanced Scanner")
    print(f"[*] Target: {target}")
    
    # Setup configuration
    config = ScanConfig()
    
    # Handle authentication
    if auth_cookies:
        print("[*] Setting authentication cookies")
        config.set_auth_cookies(auth_cookies)
    
    if login_url and credentials:
        print(f"[*] Attempting login at {login_url}")
        if config.login(login_url, credentials):
            print("[+] Login successful")
        else:
            print("[!] Login failed, continuing with unauthenticated scan")
    
    # Discover endpoints and forms
    print("[*] Discovering endpoints and forms...")
    endpoints, forms = discover_endpoints(target, limit=25, discover_forms=True)
    print(f"[+] Found {len(endpoints)} endpoints and {len(forms)} forms")
    
    # Display form summary
    if forms:
        print(f"[*] Forms discovered:")
        for i, form in enumerate(forms[:5], 1):
            print(f"    {i}. {form['method']} {form['action']} ({len(form['inputs'])} inputs)")
        if len(forms) > 5:
            print(f"    ... and {len(forms) - 5} more")
    
    # Run comprehensive scan
    print("[*] Starting comprehensive vulnerability scan...")
    print(f"[*] DOM XSS Detection: {'Enabled' if check_dom and SELENIUM_AVAILABLE else 'Disabled'}")
    print(f"[*] Stored XSS Detection: {'Enabled' if check_stored else 'Disabled'}")
    
    results = check_web_flaws(
        endpoints, forms, config,
        confirm=False,
        do_time_test=False,
        fast_mode=fast_mode,
        check_dom=check_dom,
        check_stored=check_stored
    )
    
    # Generate summary
    xss_count = sum(1 for r in results if r.get('xss', {}).get('found'))
    sqli_count = sum(1 for r in results if r.get('sqli', {}).get('found'))
    redirect_count = sum(1 for r in results if r.get('open_redirect', {}).get('found'))
    
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Endpoints scanned: {len(results)}")
    print(f"XSS vulnerabilities found: {xss_count}")
    print(f"SQLi vulnerabilities found: {sqli_count}")
    print(f"Open redirects found: {redirect_count}")
    
    # Detailed XSS breakdown
    if xss_count > 0:
        reflected = sum(1 for r in results if r.get('xss', {}).get('details', {}).get('reflected', {}).get('found'))
        dom = sum(1 for r in results if r.get('xss', {}).get('details', {}).get('dom', {}).get('found'))
        stored = sum(1 for r in results if r.get('xss', {}).get('details', {}).get('stored', {}).get('found'))
        print(f"\nXSS Breakdown:")
        print(f"  - Reflected XSS: {reflected}")
        print(f"  - DOM-based XSS: {dom}")
        print(f"  - Stored XSS: {stored}")
    
    # Generate report
    summary = {
        "target": target,
        "endpoints_scanned": len(results),
        "endpoints_with_issues": xss_count + sqli_count + redirect_count
    }
    
    generate_html_report(results, output, summary)
    print(f"[+] HTML report generated: {output}")


# ==============================================================
# 🔟  COMMAND LINE INTERFACE
# ==============================================================

if __name__ == "__main__":
    import argparse
    
    # Print banner first before any argument parsing
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="SCANDERE - Enhanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python scandere.py -t https://example.com
  
  # Fast scan (fewer payloads)
  python scandere.py -t https://example.com --fast
  
  # Scan with authentication cookies
  python scandere.py -t https://example.com --cookies '{"session":"abc123"}'
  
  # Scan with login
  python scandere.py -t https://example.com --login-url https://example.com/login \
                     --credentials '{"username":"admin","password":"pass"}'
  
  # Skip DOM XSS detection (no Selenium)
  python scandere.py -t https://example.com --no-dom
  
  # Full comprehensive scan
  python scandere.py -t https://example.com --dom --stored -o full_report.html
        """
    )
    
    parser.add_argument("-t", "--target", required=True, 
                       help="Target domain to scan")
    parser.add_argument("-o", "--output", default="scan_report.html",
                       help="Output HTML report filename (default: scan_report.html)")
    parser.add_argument("--cookies", type=str,
                       help="Authentication cookies as JSON string")
    parser.add_argument("--login-url", type=str,
                       help="Login URL for authentication")
    parser.add_argument("--credentials", type=str,
                       help="Login credentials as JSON string")
    parser.add_argument("--fast", action="store_true",
                       help="Fast mode - use fewer payloads")
    parser.add_argument("--dom", action="store_true", default=True,
                       help="Enable DOM-based XSS detection (default: enabled)")
    parser.add_argument("--no-dom", action="store_false", dest="dom",
                       help="Disable DOM-based XSS detection")
    parser.add_argument("--stored", action="store_true", default=True,
                       help="Enable stored XSS detection (default: enabled)")
    parser.add_argument("--no-stored", action="store_false", dest="stored",
                       help="Disable stored XSS detection")
    
    args = parser.parse_args()
    
    # Parse JSON arguments
    cookies = json.loads(args.cookies) if args.cookies else None
    credentials = json.loads(args.credentials) if args.credentials else None
    
    # Run scan
    main(
        target=args.target,
        output=args.output,
        auth_cookies=cookies,
        login_url=args.login_url,
        credentials=credentials,
        fast_mode=args.fast,
        check_dom=args.dom,
        check_stored=args.stored
    )