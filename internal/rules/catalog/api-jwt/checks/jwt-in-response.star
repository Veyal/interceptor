# Flag a JWT (bearer token) returned in a response body, where caches or
# intermediaries may retain it. Demonstrates re_search().

def check(flow):
    jwt = re_search("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{4,}", flow.res_body)
    if jwt:
        return [finding(
            "high",
            "Session token (JWT) leaked in response body",
            evidence=jwt[:32] + "…",
            fix="Deliver tokens via a Secure, HttpOnly cookie instead of the body.",
        )]
    return []
