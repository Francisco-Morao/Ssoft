import requests

SERVER = "http://mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25052 

link = f"{SERVER}:{PORT}"

# Create a session to persist the cookies between requests
s = requests.Session()

# Access the first link to set the user cookie
s.get(link)

lower = 0
hiher = 100000
while(True):
    v = (lower + hiher) // 2
    response = s.get(f"{link}/number/{v}")
    
    if ("Higher!" in response.text):
        lower = v +1
    elif ("Lower!" in response.text):
        hiher = v - 1
    else:
        print(response.text)
        break