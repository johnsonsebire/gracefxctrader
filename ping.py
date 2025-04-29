import requests
import time
import os
from dotenv import load_dotenv

# Load .env variables
load_dotenv()

url = os.getenv("PING_URL")
interval = int(os.getenv("PING_INTERVAL", 20))

while True:
    try:
        response = requests.get(url)
        print("Status Code:", response.status_code)
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)
    
    time.sleep(interval)
