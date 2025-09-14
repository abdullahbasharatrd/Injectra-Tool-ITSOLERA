import argparse
from sql_generator import SQLiPayloadGenerator
from xss_generator import generate_xss_payloads
from cmd_injection_generator import generate_cmd_payloads

def print_banner():
    banner = """
+--------------------------------------------------+
|                                                  |
|               Welcome to Injectra               |
|    A CLI tool for testing injection payloads     |
|                                                  |
+--------------------------------------------------+
"""
    print(banner)

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Injectra - A CLI tool for XSS, SQLi, and Command Injection testing")

    # XSS
    parser.add_argument('--xss', metavar='TARGET', help='Run XSS payload generator on target URL')
    parser.add_argument('--xss-type', nargs='+', choices=['reflected', 'stored', 'dom', 'bypass', 'all'], help='XSS payload types')

    # SQLi
    parser.add_argument('--sql', metavar='TARGET', help='Run SQL Injection payload generator on target URL')
    parser.add_argument('--type', choices=['all', 'error', 'union', 'blind'], default='all', help='SQLi payload type')
    parser.add_argument('--param', default='id', help='GET parameter to inject (default: id)')
    parser.add_argument('--keyword', help='Keyword to look for in SQLi response')

    # Shared options
    parser.add_argument('--encode', choices=['base64', 'url', 'hex', 'unicode'], help='Encoding method for payloads')
    parser.add_argument('--export', choices=['cli', 'json'], default='cli', help='Output format for payloads')

    # Command Injection
    parser.add_argument('--cmdinjection', metavar='TARGET', help='Run Command Injection payload generator on target URL')
    parser.add_argument('--os', choices=['linux', 'windows', 'all'], default='all', help='Target OS for command injection')
    parser.add_argument('--obfuscate', action='store_true', help='Apply basic obfuscation')
    parser.add_argument('--copy', action='store_true', help='Copy payloads to clipboard (if pyperclip is available)')

    args = parser.parse_args()

    if args.xss:
        generate_xss_payloads(
            target=args.xss,
            types=args.xss_type or ['reflected'],
            encoding=args.encode,
            export=args.export
        )

    elif args.sql:
        from urllib.parse import urlparse
        parsed = urlparse(args.sql)
        if not parsed.scheme or not parsed.netloc:
            print("[X] Invalid URL. Include full URL with http:// or https://")
            return

        sqli = SQLiPayloadGenerator()
        payloads = sqli.generate_payloads(payload_type=args.type, encode=args.encode)

        if args.export == "json":
            import json
            print(json.dumps({"payloads": payloads}, indent=2))
        else:
            sqli.test_target(args.sql, args.param, payloads, keyword=args.keyword)

    elif args.cmdinjection:
        generate_cmd_payloads(
            target_os=args.os,
            encode=args.encode,
            obfuscate=args.obfuscate,
            export=args.export,
            copy=args.copy
        )

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
