from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    # Log the request
    with open("/home/kali/downloads", "a") as f:
        f.write(f"Request URL: {flow.request.url}\n")
        f.write(f"Request Headers: {flow.request.headers}\n")
        f.write(f"Request Content: {flow.request.content}\n\n")

    # Example modification: Replace 'https' with 'http'
    flow.request.url = flow.request.url.replace("https:", "http:")


def response(flow: http.HTTPFlow) -> None:
    # Log the response
    with open("/home/kali/downloads", "a") as f:
        f.write(f"Response Status Code: {flow.response.status_code}\n")
        f.write(f"Response Headers: {flow.response.headers}\n")
        f.write(f"Response Content: {flow.response.content}\n\n")
