import requests
import json

url = "http://localhost:8000/api/generate-key"

def generate_key(fingerprint):
    print(f"Generating key for fingerprint: {fingerprint}")
    response = requests.post(url, json={"fingerprint": fingerprint})
    if response.ok:
        data = response.json()
        print(f"  Success! Prefix: {data['key_prefix']}")
        return data['key']
    else:
        print(f"  Failed: {response.text}")
        return None

# Test 1: Generate key for User A
key_a = generate_key("fingerprint_user_a")

# Test 2: Generate key for User B (Same IP, different fingerprint)
key_b = generate_key("fingerprint_user_b")

if key_a and key_b:
    if key_a != key_b:
        print("\nPASS: Users on same IP with different fingerprints got DIFFERENT keys.")
    else:
        print("\nFAIL: Users on same IP with different fingerprints got the SAME key!")

# Test 3: Generate key for User A again (Persistence)
key_a_2 = generate_key("fingerprint_user_a")
if key_a == key_a_2:
    print("PASS: User A's key remained stable on recovery.")
else:
    print("FAIL: User A's key changed!")
