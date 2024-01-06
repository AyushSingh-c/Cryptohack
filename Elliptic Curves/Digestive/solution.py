import requests
import json 

url_sign = "https://web.cryptohack.org/digestive/sign/"
url_verify = "https://web.cryptohack.org/digestive/verify/"

# Any username value works
username = "admin"
r = requests.get(url_sign + username)

# Forging a new message with the signature obtained
response = json.loads(r.text)

# Append admin = True to the dictionary, note that we can't use json.dumps here
# as it will shrink into {"admin": true, "username": "admin"}, which will have
# a different first 20 characters
msg = '{"admin": false, "username": "admin", "admin": true}' 
signature = response['signature'] # previously requested signature

r = requests.get(url_verify + msg + "/" + signature)
print(r.text)