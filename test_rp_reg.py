import requests
import json
import uuid

BASE_URL = "http://localhost:1890/api/rp"

def test_registration():
    username = f"testuser_{uuid.uuid4().hex[:8]}"
    password = "testpassword123"
    
    payload = {
        "username": username,
        "password": password
    }
    
    print(f"Testing registration for {username}...")
    try:
        response = requests.post(f"{BASE_URL}/register", json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_registration()
