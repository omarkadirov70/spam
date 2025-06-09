import re
import dns.resolver
from email.message import Message
import spf
import dkim

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


def parse_headers(msg: Message) -> dict:
    """Return key email headers for analysis."""
    return {
        'from': msg.get('From', ''),
        'reply_to': msg.get('Reply-To', ''),
        'subject': msg.get('Subject', ''),
        'received': msg.get_all('Received', []),
    }


def check_spf(ip: str, sender: str, helo: str | None = None) -> str:
    """Return SPF result string."""
    helo = helo or sender.split('@')[-1]
    try:
        result, *_ = spf.check2(i=ip, s=sender, h=helo)
    except Exception as exc:
        result = f'error: {exc}'
    return result


def check_dkim(message_bytes: bytes) -> bool:
    try:
        return dkim.verify(message_bytes)
    except Exception:
        return False


def check_dmarc(domain: str) -> bool:
    try:
        records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in records:
            txt = b''.join(r.strings)
            if b'v=DMARC1' in txt:
                return True
    except Exception:
        pass
    return False