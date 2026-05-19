import requests

try:
    # Test if the LLM is reachable
    llm_test = requests.get("http://localhost:11434/api/tags")
    print(f"LLM Status: {llm_test.status_code} (Success!)")
    
    # Test if the Website is reachable
    site_test = requests.get("https://google.com", timeout=5)
    print(f"Website Status: {site_test.status_code} (Success!)")
    
except Exception as e:
    print(f"Error found: {e}")