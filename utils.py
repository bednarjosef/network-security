import os, sys
from dotenv import load_dotenv

# UTILITY FUNCTIONS

# works on linux/macOS only?
def ensure_root():
    if os.geteuid() != 0:
        print('The program must be run with sudo. Try sudo .venv/bin/python3 main.py')
        sys.exit(1)
