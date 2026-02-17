import requests

SERVER = "http://mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25053

link = f"{SERVER}:{PORT}"

# Create a session to persist the cookies between requests
s = requests.Session()

# Access the first link to set the user cookie
s.get(link)

response = s.get(f"{link}/hello")

split = response.text.split("<br>")

match = split[0].replace(".", "").split(" ")[-1]

value = split[1].split(" ")[-1]

while(match != value):
    response = s.get(f"{link}/more")
    
    split = response.text.split("<br>")
    value = split[2].split(" ")[-1]

response = s.get(f"{link}/finish")
print(response.text)