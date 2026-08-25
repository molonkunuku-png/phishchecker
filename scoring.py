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

REASON_TEMPLATES = {
    'risky TLD': {
        'text': 'This domain ends with a TLD often used in phishing or scam sites.',
        'action': 'Be careful. Verify the sender through an official channel before interacting.',
        'severity': 'high',
    },
    'deep subdomain chain': {
        'text': 'This URL uses multiple subdomains, which can hide the real site.',
        'action': 'Check the main domain carefully. Phishers often stack subdomains to look legitimate.',
        'severity': 'medium',
    },
    'suspicious long domain label': {
        'text': 'One part of the domain name is unusually long, which can be a phishing tactic.',
        'action': 'Compare the domain with the known official address.',
        'severity': 'medium',
    },
    'userinfo in URL': {
        'text': 'This URL includes a username/password, which legitimate sites never do.',
        'action': 'Do not enter any credentials. This is a strong phishing indicator.',
        'severity': 'high',
    },
    'phishing bait keywords': {
        'text': 'The URL contains words commonly used in phishing links.',
        'action': 'Treat this link with caution and verify the destination independently.',
        'severity': 'medium',
    },
    'potential brand mimic': {
        'text': 'This domain contains a brand name but is not the official domain.',
        'action': 'Do not trust this site. Go directly to the official app or website.',
        'severity': 'high',
    },
    'IT mode high sensitivity': {
        'text': 'IT mode flagged subtle patterns that warrant closer inspection.',
        'action': 'Run additional checks such as WHOIS, SSL inspection, or sandbox detonation.',
        'severity': 'medium',
    },
    'quick scan keep': {
        'text': 'Quick mode kept this result for manual review.',
        'action': 'Switch to Standard or IT mode for a more thorough assessment.',
        'severity': 'low',
    },
    'family-safe mode: limited analysis': {
        'text': 'Family Mode uses simplified analysis to avoid technical jargon.',
        'action': 'Ask a trusted adult or IT-savvy friend to verify the link.',
        'severity': 'low',
    },
    'no significant indicators detected': {
        'text': 'No strong phishing indicators were detected in the checked URL.',
        'action': 'Stay cautious online. Verify the sender and hover before tapping.',
        'severity': 'low',
    },
}



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
        if kw_hits or brand_hits or domain.count('.') >= 3:
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

    # confidence
    _signal_count = len(reasons) + sum(1 for v in [
        tld in RISKY_TLDS,
        bool(kw_hits),
        bool(brand_hits),
        domain.count('.') >= 3,
        bool(re.search(r'https?://[^/]*@', url)),
        any(len(p) >= 20 and p.isalpha() for p in domain_parts[:-1]),
    ] if v)

    def _finding_for(reason_text: str):
        base = reason_text.split(':')[0].split('(')[0].strip().lower()
        for key, tmpl in REASON_TEMPLATES.items():
            if key.lower() in base:
                return {
                    'id': key.lower().replace(' ', '_'),
                    'severity': tmpl['severity'],
                    'text': tmpl['text'],
                    'action': tmpl['action'],
                    'raw': reason_text,
                }
        return {
            'id': base.replace(' ', '_'),
            'severity': 'low',
            'text': reason_text,
            'action': 'Review this signal as part of the overall URL risk assessment.',
            'raw': reason_text,
        }

    findings = [_finding_for(r) for r in reasons]

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
        'confidence': _signal_count,
        'reasons': reasons,
        'findings': findings,
        'details': {
            'tld': tld,
            'family_mode': family_mode,
            'mode': mode,
            'checks': {
                'tld': tld in RISKY_TLDS,
                'keywords': bool(kw_hits),
                'brand_mimic': bool(brand_hits),
                'subdomain_depth': domain.count('.') >= 3,
                'userinfo': bool(re.search(r'https?://[^/]*@', url)),
                'long_label': any(len(p) >= 20 and p.isalpha() for p in domain_parts[:-1]),
            },
            'brand_hits': brand_hits,
            'domain_age': {'age_days': None, 'created_at': None},
        },
        'mode': mode,
        'family_mode': family_mode,
        'duration_ms': 500,
        'scanner_version': 'scanner-v2.1',
    }
