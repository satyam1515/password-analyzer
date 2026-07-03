"""
pwned_checker.py
----------------
Checks a password against the HaveIBeenPwned (HIBP) API using the secure
k-anonymity model. This ensures the password is never sent over the network.
Instead, we hash the password locally (SHA-1) and only send the first 5
characters of the hash.
"""

import hashlib
import requests
from functools import lru_cache

@lru_cache(maxsize=128)
def check_pwned(password: str) -> int:
    """
    Check if a password has been exposed in data breaches.
    
    Args:
        password (str): The plaintext password to check.
        
    Returns:
        int: The number of times the password was found in breaches. 0 if safe or if API fails.
    """
    if not password:
        return 0
        
    # 1. Hash the password using SHA-1 (required by HIBP)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # 2. Split into prefix (first 5 chars) and suffix (the rest)
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "PassMetric-Research-Academic-Project"
    }
    
    try:
        # We use a short timeout so the UI doesn't freeze if the API is down
        response = requests.get(url, headers=headers, timeout=5.0)
        
        if response.status_code != 200:
            print(f"[HIBP Error] API returned status code {response.status_code}")
            return 0
            
        # 3. The API returns a list of suffixes that match our prefix, 
        #    along with the count of how many times each was breached.
        #    Format: SUFFIX:COUNT
        hashes = response.text.splitlines()
        
        for h in hashes:
            returned_suffix, count = h.split(':')
            if returned_suffix == suffix:
                return int(count)
                
        return 0
        
    except requests.exceptions.RequestException:
        # If there's no internet or the API is blocked, gracefully fail to 0
        return 0
