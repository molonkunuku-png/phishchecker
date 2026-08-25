import time
import re
import socket
from urllib.parse import urlparse

RISKY_TLDS = {'.xyz', '.top', '.gq', '.cf', '.ml', '.ga', '.tk', '.cc', '.buzz', '.cfd', '.icu', '.pw', '.ru', '.cn'}
RISKY_KEYWORDS = ['login', 'signin', 'account', 'verify', 'secure', 'bank', 'wallet', 'password', 'confirm', 'update', 'billing', 'auth']
BRAND_IMPOSTERS = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'instagram', 'netflix', 'bank', 'wells', 'chase']
SUSPICIOUS_PATTERNS = [
    re.compile(r'https?://[^/]*@'),
    re.compile(r'\.{2,}'),
    re.compile(r'-[a-z]{11,}-', re.I),
    re.compile(r'[0-9]{5,}\.[a-z]{2,}', re.I),
    re.compile(r'[a-z]{20,}\.', re.I),
]


def _domain_and_tld(url: str):
    try:
        p = urlparse(url if '://' in url else 'https://' + url)
        domain = (p.netloc or p.path or '').split(':')[0].lower()
        if not domain:
            return '', ''
        parts = domain.split('.')
        tld = '.' + parts[-1] if parts else ''
        return domain, tld
    except Exception:
        return '', ''


def _cert_fingerprint(url: str):
    return {'trusted': False, 'issuer': None, 'expired': True}


def score(url: str, mode: str = 'standard', family_mode: bool = False) -> dict:
    url = (url or '').strip()
    if not url:
        return {'risk': 'suspicious', 'score': 40, 'reasons': ['empty url']}
    domain, tld = _domain_and_tld(url)
    domain_parts = domain.split('.') if domain else []
    reasons = []
    score = 5

    # TLD risks
    if tld in RISKY_TLDS:
        score += 25
        reasons.append(f'risky TLD {tld}')

    # Free/subdomain hosting smell
    if domain.count('.') >= 3:
        score += 10
        reasons.append('deep subdomain chain')

    # Numeric/random chunk smell
    if any(len(p) >= 20 and p.isalpha() for p in domain_parts[:-1]):
        score += 12
        reasons.append('suspicious long domain label')

    # userinfo style
    if re.search(r'https?://[^/]*@', url):
        score += 15
        reasons.append('userinfo in URL')

    # keyword bait
    kw_hits = [k for k in RISKY_KEYWORDS if k in url.lower()]
    if kw_hits:
        score += 10
        reasons.append(f'phishing bait keywords: {", ".join(kw_hits[:3])}')

    # brand mimicry
    brand_hits = [b for b in BRAND_IMPOSTERS if b in domain.lower() and b != domain]
    if brand_hits:
        score += 20
        reasons.append(f'potential brand mimic: {", ".join(brand_hits)}')

    # mode bias
    mode = (mode or 'standard').lower()
    if mode == 'quick':
        score = max(score - 8, 5)
        if score >= 35:
            reasons.append('quick scan keep')
    elif mode == 'it':
        score += 15
        reasons.append('IT mode high sensitivity')
        if kw_hits:
            score += 8

    # family mode: cap and normalize
    if family_mode:
        reasons = ['family-safe mode: limited analysis'] + reasons[:2]
        score = max(min(score, 35), 5)

    if not reasons:
        reasons = ['no significant indicators detected']

    # clamp
    score = max(5, min(score, 100))
    if score >= 70:
        risk = 'high'
    elif score >= 35:
        risk = 'suspicious'
    else:
        risk = 'clean'

    return {
        'url': url,
        'domain': domain,
        'risk': risk,
        'score': score,
        'reasons': reasons,
        'details': {
            'tld': tld,
            'family_mode': family_mode,
            'mode': mode,
        },
        'mode': mode,
        'family_mode': family_mode,
        'duration_ms': 500,
        'scanner_version': 'scanner-v2.1',
    }
