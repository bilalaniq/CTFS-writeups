import base64
import urllib.parse

# Step 1: the expected Base64 string from Java
expected = ("JTYzJTMwJTZlJTc2JTMzJTcyJTc0JTMxJTZlJTY3JTVm"
            "JTY2JTcyJTMwJTZkJTVmJTYyJTYxJTM1JTY1JTVmJTM2"
            "JTM0JTVmJTM4JTM0JTY2JTY0JTM1JTMwJTM5JTM1")

# Step 2: Base64 decode → URL-encoded string
url_encoded_bytes = base64.b64decode(expected)
url_encoded_str = url_encoded_bytes.decode()

# Step 3: URL decode → original password
password = urllib.parse.unquote(url_encoded_str)

print("Recovered password:", password)