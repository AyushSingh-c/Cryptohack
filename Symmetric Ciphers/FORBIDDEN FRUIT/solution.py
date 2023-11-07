import requests

def send_decrypt(nonce, ciphertext, tag, associated_data):
    r = requests.get('https://aes.cryptohack.org/forbidden_fruit/decrypt/<nonce>/<ciphertext>/<tag>/<associated_data>/' 
                        + nonce.hex() + "/" 
                        + ciphertext.hex() + "/" 
                        + tag.hex() + "/"
                        + associated_data.hex())
    
    print(r.text)
