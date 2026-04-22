from mitmproxy import http

DNS_MAPPING = {
    "example.com": "192.168.1.50",
    # Add your mappings here
}

def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    
    if host in DNS_MAPPING:
        # Add your code here
        pass

def response(flow: http.HTTPFlow) -> None:
    # Inject TRUE POSITIVE if redirection is successful
    # Add your code here
    pass
