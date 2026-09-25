import os
import time

SEQ_FILE = "/data/data/com.termux/files/home/.sovr_global_seq"

def get_next_seq(step=1):
    base = int(time.time()) + 1000000
    current = base
    if os.path.exists(SEQ_FILE):
        try:
            with open(SEQ_FILE, "r") as f:
                val = int(f.read().strip())
                if val >= base:
                    current = val
        except Exception:
            pass
    current += step
    with open(SEQ_FILE, "w") as f:
        f.write(str(current))
    return current
