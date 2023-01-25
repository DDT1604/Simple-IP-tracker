from scapy.all import *
import requests

def get_ip(pkt):
    try:
        ip = pkt[IP].src
        if ip[:4] == "192.":
            return
        req = requests.get(f"https://ipapi.co/{ip}/json/").json()
        print("""
IP: {req.get('ip')}
Country: {req.get('country_name')}
City: {req.get('city')}
Region: {req.get('region')}
ISP: {req.get('org')}
{'-'*20}""")
    except:
        return
while True:
    sniff(filter="udp", prn=get_ip, count = 1)
    time.sleep(0.5)