# Flag a Set-Cookie that is missing the HttpOnly attribute.
# Demonstrates header access + simple string logic.

def check(flow):
    cookie = flow.res_header("Set-Cookie")
    if cookie and "httponly" not in cookie.lower():
        return [finding(
            "low",
            "Cookie set without HttpOnly",
            evidence=cookie[:80],
            fix="Add HttpOnly (and Secure; SameSite) to session cookies.",
        )]
    return []
