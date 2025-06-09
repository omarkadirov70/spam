import re
import socket
import dns.resolver

DNSBL_LISTS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
]

URIBL_LISTS = [
    'multi.uribl.com',
    'dbl.spamhaus.org',
]

ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
url_regex = re.compile(r'https?://([^/\s]+)')

def extract_ips(text):
    return ip_regex.findall(text)

def extract_domains(text):
    domains = []
    for match in url_regex.findall(text):
        domains.append(match.split(':')[0])
    return domains

def query_dnsbl(ip):
    reversed_ip = '.'.join(reversed(ip.split('.')))
    results = []
    for bl in DNSBL_LISTS:
        query = f"{reversed_ip}.{bl}"
        try:
            dns.resolver.resolve(query, 'A')
            results.append(bl)
        except Exception:
            pass
    return results

def query_uribl(domain):
    results = []
    for bl in URIBL_LISTS:
        query = f"{domain}.{bl}"
        try:
            dns.resolver.resolve(query, 'A')
            results.append(bl)
        except Exception:
            pass
    return results
