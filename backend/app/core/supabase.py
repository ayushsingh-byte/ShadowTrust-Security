
import os
from dotenv import load_dotenv
from postgrest import SyncPostgrestClient

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("Warning: Supabase credentials not found in .env")

class SupabaseClientWrapper:
    def __init__(self, url: str, key: str):
        self.url = f"{url}/rest/v1"
        self.headers = {
            "apikey": key, 
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }
        self.postgrest = SyncPostgrestClient(self.url, headers=self.headers)

    def table(self, name: str):
        return self.postgrest.from_(name)

try:
    if SUPABASE_URL and SUPABASE_KEY:
        supabase = SupabaseClientWrapper(SUPABASE_URL, SUPABASE_KEY)
    else:
        supabase = None
except Exception as e:
    print(f"Error creating Supabase client: {e}")
    supabase = None