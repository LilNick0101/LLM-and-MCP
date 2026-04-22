from mitmproxy import http

TARGET_HOSTS = {
    # Add target hosts if needed
}


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.host
    path = flow.request.path.split("?")[0]
    if host in TARGET_HOSTS:
        # Add your code here
        pass


def response(flow: http.HTTPFlow) -> None:
    host = flow.request.host
    path = flow.request.path.split("?")[0]
    if host in TARGET_HOSTS:
        try:
            # Add your code here, idea: put TRUE POSITIVE in the body of the response, or in the header, or in the url, etc. to make it easier to detect the attack in the logs
            pass
        except Exception:
            pass