import whois
from urllib.parse import urlparse
from datetime import datetime
import socket
import ssl
import requests

def get_extended_domain_info(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return None
            
        if domain.startswith("www."):
            domain = domain[4:]

        info = {
            "domain": domain,
            "age_days": None,
            "age_string": "Unknown",
            "registrar": "Unknown",
            "nameservers": [],
            "resolves": False,
            "ip_address": "Unknown",
            "asn": "Unknown",
            "country": "Unknown",
            "ssl_valid": False,
            "ssl_issuer": "Unknown"
        }

        # 1. DNS Resolution & IP
        try:
            info["ip_address"] = socket.gethostbyname(domain)
            info["resolves"] = True
            
            # Geolocation & ASN via free IP API
            geo_resp = requests.get(f"http://ip-api.com/json/{info['ip_address']}?fields=status,country,as", timeout=3).json()
            if geo_resp.get("status") == "success":
                info["asn"] = geo_resp.get("as", "Unknown").split(" ")[0] # Gets 'AS12345'
                info["country"] = geo_resp.get("country", "Unknown")
        except:
            pass

        # 2. SSL Certificate Validation
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Extract the issuer's Organization Name (O)
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    info["ssl_issuer"] = issuer_dict.get("organizationName", "Unknown")
                    info["ssl_valid"] = True
        except:
            pass

        # 3. WHOIS Data
        try:
            w = whois.whois(domain)
            info["registrar"] = w.registrar or "Unknown"
            
            if w.name_servers:
                ns_list = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                info["nameservers"] = [ns.lower() for ns in ns_list[:2]] # Keep it clean (top 2)

            creation_date = w.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]

            if isinstance(creation_date, datetime):
                creation_date = creation_date.replace(tzinfo=None)
                age_days = (datetime.now() - creation_date).days
                info["age_days"] = age_days
                
                # Format age string for the UI
                if age_days > 365:
                    info["age_string"] = f"{round(age_days / 365.25, 1)} years"
                else:
                    info["age_string"] = f"{age_days} days"
        except:
            pass

        return info

    except Exception as e:
        print(f"Network scan failed: {e}")
        return None