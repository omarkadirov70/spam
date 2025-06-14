import re
from collections import Counter
import dns.resolver
from email.message import Message
import spf
import dkim
try:
    import magic
except Exception:
    magic = None
from bs4 import BeautifulSoup
import tarfile
import io

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
# Default terms used if fetching from the training dataset fails
DEFAULT_KEYWORDS = [
    'free money',
    'viagra',
    'lottery',
    'prince',
]
DEFAULT_WORD_FREQ_TERMS = ['free', 'win', 'click', 'offer']

# URLs for a small portion of the SpamAssassin public corpus
EMAIL_SPAM_URL = (
    "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2"
)
EMAIL_HAM_URL = (
    "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2"
)

def preprocess_text(text: str) -> str:
    """Extract text from HTML if needed."""
    if "<html" in text.lower():
        soup = BeautifulSoup(text, "html.parser")
        text = soup.get_text(" ", strip=True)
    return text

_keywords: list[str] | None = None
_keyword_regexes: list[re.Pattern] | None = None
_freq_terms: list[str] | None = None

SUSPICIOUS_EXT = {'.exe', '.bat', '.cmd', '.scr', '.js', '.vbs', '.jar', '.zip', '.rar'}
magic_mime = magic.Magic(mime=True) if magic else None


def _ensure_patterns() -> None:
    """Load spam keyword and frequency terms from training data."""
    global _keywords, _keyword_regexes, _freq_terms
    if _keywords is not None and _freq_terms is not None:
        return
    try:
        data = fetch_training_data()
    except Exception:
        data = SAMPLE_DATA

    spam_texts = [preprocess_text(text) for text, label in data if label == 1]
    tokens: list[str] = []
    bigrams: list[str] = []
    for text in spam_texts:
        words = re.findall(r"\b\w+\b", text.lower())
        tokens.extend(words)
        bigrams.extend([f"{w1} {w2}" for w1, w2 in zip(words, words[1:])])
    counts = Counter(tokens + bigrams)
    common = [word for word, _ in counts.most_common(50)]
    _keywords = common[:20] or DEFAULT_KEYWORDS
    _freq_terms = common[:10] or DEFAULT_WORD_FREQ_TERMS
    _keyword_regexes = [re.compile(k, re.IGNORECASE) for k in _keywords]


def reset_patterns() -> None:
    """Reset loaded spam patterns (for tests)."""
    global _keywords, _keyword_regexes, _freq_terms
    _keywords = None
    _keyword_regexes = None
    _freq_terms = None

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
    _ensure_patterns()
    hits = []
    for regex in _keyword_regexes or []:
        if regex.search(text):
            hits.append(regex.pattern)
    return hits


def word_frequencies(text: str, words: list[str] | None = None) -> dict:
    _ensure_patterns()
    words = words or _freq_terms
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
from urllib.request import urlopen
import csv
import io

_vectorizer: CountVectorizer | None = None
_classifier: MultinomialNB | None = None
_training_data: list[tuple[str, int]] | None = None

TRAINING_SPAM_URL = EMAIL_SPAM_URL
TRAINING_HAM_URL = EMAIL_HAM_URL

SAMPLE_DATA = [
    ("Win money now", 1),
    ("Cheap viagra available", 1),
    ("Meeting schedule attached", 0),
    ("Let's have lunch tomorrow", 0),
]


def fetch_training_data() -> list[tuple[str, int]]:
    """Download a subset of the SpamAssassin corpus."""
    data: list[tuple[str, int]] = []
    try:
        for url, label in ((TRAINING_SPAM_URL, 1), (TRAINING_HAM_URL, 0)):
            with urlopen(url) as resp:
                buf = io.BytesIO(resp.read())
            with tarfile.open(fileobj=buf, mode="r:bz2") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    f = tar.extractfile(member)
                    if not f:
                        continue
                    raw = f.read().decode(errors="ignore")
                    text = preprocess_text(raw)
                    data.append((text, label))
    except Exception:
        data = SAMPLE_DATA
    return data


def train_default_model() -> None:
    """Train the Naive Bayes classifier using data from the internet."""
    global _vectorizer, _classifier, _training_data
    if _training_data is None:
        _training_data = fetch_training_data()
    texts = [preprocess_text(t) for t, _ in _training_data]
    labels = [l for _, l in _training_data]
    _vectorizer = CountVectorizer()
    X = _vectorizer.fit_transform(texts)
    _classifier = MultinomialNB()
    _classifier.fit(X, labels)


def predict_spam(text: str) -> bool:
    """Return True if text is predicted to be spam using a Naive Bayes model."""
    global _vectorizer, _classifier
    if _classifier is None:
        train_default_model()
    text = preprocess_text(text)
    X = _vectorizer.transform([text])
    return bool(_classifier.predict(X)[0])


def reset_model() -> None:
    """Reset the trained model (for tests)."""
    global _vectorizer, _classifier, _training_data
    _vectorizer = None
    _classifier = None
    _training_data = None

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
    logger.info(
        "hash=%s ml_spam=%s score=%.2f keywords=%s ip_hits=%s domain_hits=%s",
        h,
        result.get("ml_spam"),
        result.get("spam_score", 0.0),
        ",".join(result.get("keyword_hits", [])),
        ",".join(k for k, v in result.get("ip_results", {}).items() if v),
        ",".join(k for k, v in result.get("domain_results", {}).items() if v),
    )


SPAM_THRESHOLD = 3.0


def compute_score(result: dict) -> float:
    """Return a heuristic spam score for a scan result."""
    score = 0.0
    if result.get("ml_spam"):
        score += 2
    if not result.get("dkim_result", True):
        score += 1
    spf = result.get("spf_result") or ""
    if spf and "pass" not in spf.lower():
        score += 1
    if any(result.get("ip_results", {}).get(ip) for ip in result.get("ip_results", {})):
        score += 1
    if any(
        result.get("domain_results", {}).get(d) for d in result.get("domain_results", {})
    ):
        score += 1
    score += 0.5 * len(result.get("keyword_hits", []))
    score += 0.5 * len(result.get("suspicious_attachments", []))
    subj = result.get("header_info", {}).get("subject", "").lower()
    if subj.startswith("[spam"):
        score += 1
    return score


def is_spam_score(score: float) -> bool:
    return score >= SPAM_THRESHOLD


def scan_statistics() -> dict:
    """Aggregate statistics from all cached scan results."""
    results = cache.all_results()
    total = len(results)
    ml_spam = sum(1 for r in results if r.get('ml_spam'))
    overall_spam = sum(1 for r in results if r.get('overall_spam'))
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
        'overall_spam': overall_spam,
        'overall_ham': total - overall_spam,
        'ip_hits': ip_hits,
        'domain_hits': domain_hits,
    }