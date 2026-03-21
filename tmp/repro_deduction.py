import requests
import time

base_url = "http://localhost:8000"
fp = "repro-fp-789"

def check_usage(key):
    resp = requests.get(f"{base_url}/api/my-usage", headers={"Authorization": f"Bearer {key}"})
    if resp.ok:
        data = resp.json()
        print(f"Usage: RPD={data['rpd_used']}, Tokens={data['total_tokens']}")
        return data['rpd_used']
    else:
        print(f"Usage Error: {resp.text}")
        return None

# 1. Generate Key
print("Step 1: Generating Key")
resp = requests.post(f"{base_url}/api/generate-key", json={"fingerprint": fp})
if resp.ok:
    key = resp.json()['key']
    print(f"Key: {key}")
else:
    print(f"Generate Error: {resp.status_code} - {resp.text}")
    # Try to get existing key
    resp = requests.get(f"{base_url}/api/my-key?fingerprint={fp}")
    if resp.ok:
        key = resp.json()['full_key']
        print(f"Recovered Key: {key}")
    else:
        print(f"Recovery Error: {resp.text}")
        exit(1)

# 2. Check initial usage
initial_rpd = check_usage(key)

# 3. Call /api/my-usage 5 times
print("\nStep 2: Calling /api/my-usage 5 times")
for i in range(5):
    check_usage(key)

# 4. Call /v1/models 5 times
print("\nStep 3: Calling /v1/models 5 times")
for i in range(5):
    requests.get(f"{base_url}/v1/models", headers={"Authorization": f"Bearer {key}"})
    check_usage(key)

# 5. Final check
final_rpd = check_usage(key)

if final_rpd > initial_rpd:
    print(f"\nREPRODUCED! RPD went from {initial_rpd} to {final_rpd}")
else:
    print("\nNOT reproduced. RPD stayed at", final_rpd)
