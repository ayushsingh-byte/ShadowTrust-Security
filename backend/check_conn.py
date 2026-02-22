
import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load .env explicitly
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

print(f"URL: {SUPABASE_URL}")
# Mask Key for security in logs
masked_key = SUPABASE_KEY[:5] + "..." + SUPABASE_KEY[-5:] if SUPABASE_KEY else "None"
print(f"Key: {masked_key}")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("[-] Error: Missing credentials in .env")
    exit(1)

try:
    print("[*] Connecting to Supabase...")
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    
    # Try a simple query
    # We query the 'users' table since it exists in our schema
    response = supabase.table("users").select("*", count="exact").limit(1).execute()
    
    print("[+] Connection Successful!")
    print(f"[+] Found {response.count} users in the database.")
    
except Exception as e:
    print(f"[-] Connection Failed: {e}")
