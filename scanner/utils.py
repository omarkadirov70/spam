import re
import dns.resolver
from email.message import Message
import spf
import dkim
try:
    import magic
except Exception:
    magic = None
from bs4 import BeautifulSoup

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

# Spam content patterns
KEYWORDS = [
    'free money',
    'viagra',
    'lottery',
    'prince',
]
KEYWORD_REGEXES = [re.compile(k, re.IGNORECASE) for k in KEYWORDS]

WORD_FREQ_TERMS = ['free', 'win', 'click', 'offer']

SUSPICIOUS_EXT = {'.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.jar', '.zip', '.rar'}
magic_mime = magic.Magic(mime=True) if magic else None

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


def find_keywords(text: str) -> list[str]:
    """Return spam keywords found in text."""
    hits = []
    for regex in KEYWORD_REGEXES:
        if regex.search(text):
            hits.append(regex.pattern)
    return hits


def word_frequencies(text: str, words: list[str] | None = None) -> dict:
    words = words or WORD_FREQ_TERMS
    tokens = re.findall(r'\b\w+\b', text.lower())
    return {w.lower(): tokens.count(w.lower()) for w in words}


def extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s>]+', text)


def suspicious_attachments(message: Message) -> list[str]:
    suspects = []
    if hasattr(message, 'attachments'):
        for att in message.attachments:
            name = (
                getattr(att, 'longFilename', None)
                or getattr(att, 'shortFilename', None)
                or ''
            )
            data = getattr(att, 'data', b'')
            mime = magic_mime.from_buffer(data) if (magic_mime and data) else ''
            if any(name.lower().endswith(ext) for ext in SUSPICIOUS_EXT) or (
                'executable' in mime
            ):
                suspects.append(name or '(unnamed)')
    else:
        for part in message.walk():
            if part.is_multipart():
                continue
            name = part.get_filename() or ''
            if not name:
                continue
            data = part.get_payload(decode=True) or b''
            mime = magic_mime.from_buffer(data) if (magic_mime and data) else ''
            if any(name.lower().endswith(ext) for ext in SUSPICIOUS_EXT) or (
                'executable' in mime
            ):
                suspects.append(name)
    return suspects


# === Machine learning spam classifier (Level 4) ===
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

_vectorizer: CountVectorizer | None = None
_classifier: MultinomialNB | None = None

SAMPLE_DATA = [
    ("Win money now", 1),
    ("Cheap viagra available", 1),
    ("Meeting schedule attached", 0),
    ("Let's have lunch tomorrow", 0),
]


def train_default_model() -> None:
    """Train the Naive Bayes classifier on the built-in sample dataset."""
    global _vectorizer, _classifier
    texts = [t for t, _ in SAMPLE_DATA]
    labels = [l for _, l in SAMPLE_DATA]
    _vectorizer = CountVectorizer()
    X = _vectorizer.fit_transform(texts)
    _classifier = MultinomialNB()
    _classifier.fit(X, labels)


def predict_spam(text: str) -> bool:
    """Return True if text is predicted to be spam using a Naive Bayes model."""
    global _vectorizer, _classifier
    if _classifier is None:
        train_default_model()
    X = _vectorizer.transform([text])
    return bool(_classifier.predict(X)[0])


def reset_model() -> None:
    """Reset the trained model (for tests)."""
    global _vectorizer, _classifier
    _vectorizer = None
    _classifier = None

# === Caching and logging (Level 5) ===
from . import cache
from .logger import logger


def cache_lookup(message_bytes: bytes):
    """Return (hash, cached result) if present."""
    h = cache.message_hash(message_bytes)
    return h, cache.get(h)


def cache_store(h: str, result: dict) -> None:
    cache.set(h, result)


def log_result(h: str, result: dict) -> None:
    logger.info("hash=%s ml_spam=%s", h, result.get('ml_spam'))


def scan_statistics() -> dict:
    """Aggregate statistics from all cached scan results."""
    results = cache.all_results()
    total = len(results)
    ml_spam = sum(1 for r in results if r.get('ml_spam'))
    ip_hits = sum(
        1
        for r in results
        if any(r.get('ip_results', {}).get(ip) for ip in r.get('ip_results', {}))
    )
    domain_hits = sum(
        1
        for r in results
        if any(
            r.get('domain_results', {}).get(d) for d in r.get('domain_results', {})
        )
    )
    return {
        'total': total,
        'ml_spam': ml_spam,
        'ml_ham': total - ml_spam,
        'ip_hits': ip_hits,
        'domain_hits': domain_hits,