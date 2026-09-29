import os
import requests
from dotenv import load_dotenv

load_dotenv()

LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_API_URL = os.getenv("LLM_API_URL")
LLM_MODEL = os.getenv("LLM_MODEL")

headers = {
    "Authorization": f"Bearer {LLM_API_KEY}",
    "Content-Type": "application/json"
}

payload = {
    "model": LLM_MODEL,
    "messages": [
        {"role": "system", "content": "You are an AI. Output strictly valid JSON."},
        {"role": "user", "content": "Return {\"status\": \"ok\"}"}
    ],
    "response_format": {"type": "json_object"}
}

resp = requests.post(LLM_API_URL, headers=headers, json=payload)
print(f"Status Code: {resp.status_code}")
print(f"Response: {resp.text}")
