import requests
import whois

def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/").json()
        return f"{response.get('city', 'Unknown')}, {response.get('country_name', 'Unknown')}"
    except:
        return "Local/Unknown"

def get_org_owner(ip):
    try:
        w = whois.whois(ip)
        return w.org or w.registrar or "Private/Unknown"
    except:
        return "Internal Network"