"""Test data shared by several test modules."""

# Built at runtime so this source file is not itself flagged by real antivirus products.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*").encode()

URL_CASES = [
    "https://www.google.com/search?q=cats", "https://github.com/login", "http://paypa1-secure-login.xyz/verify",
    "https://paypal.com.account-check.top/", "http://192.168.1.1@evil.com/", "http://185.1.2.3/login",
    "http://xn--pypal-4ve.com/", "http://sentinel-test-bad.test/", "http://3232235777/login",
    "http://0xC0A80001/login", "http://0300.0250.0.1/", "http://192.168.1.1/",
    "http://pаypal-secure-login.xyz/verify", "https://evil.s3.amazonaws.com/paypal/login",
    "https://fonts.googleapis.com/css2?family=Inter", "https://storage.googleapis.com/google-fonts/a.woff2",
    "https://paypal-account.web.app/signin", "https://myproject.github.io/docs/",
]
