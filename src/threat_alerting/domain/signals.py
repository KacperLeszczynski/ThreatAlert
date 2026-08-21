import re

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

EXPLOITATION_NEGATIONS = (
    re.compile(r"\bnot actively exploited\b", re.IGNORECASE),
    re.compile(r"\bno evidence of (?:active )?exploitation\b", re.IGNORECASE),
    re.compile(r"\bno known (?:active )?exploitation\b", re.IGNORECASE),
    re.compile(r"\bnot exploited in the wild\b", re.IGNORECASE),
)

CATEGORY_PATTERNS = {
    "active_exploitation": (
        re.compile(r"\bactively exploited\b", re.IGNORECASE),
        re.compile(r"\bactive exploitation\b", re.IGNORECASE),
        re.compile(r"\bexploited in the wild\b", re.IGNORECASE),
    ),
    "proof_of_concept": (
        re.compile(r"\bproof[ -]of[ -]concept\b", re.IGNORECASE),
        re.compile(r"\bPoC\b", re.IGNORECASE),
    ),
    "rce": (
        re.compile(r"\bremote code execution\b", re.IGNORECASE),
        re.compile(r"\bRCE\b", re.IGNORECASE),
    ),
    "authentication_bypass": (
        re.compile(r"\bauthentication bypass\b", re.IGNORECASE),
        re.compile(r"\bauth bypass\b", re.IGNORECASE),
    ),
    "privilege_escalation": (re.compile(r"\bprivilege escalation\b", re.IGNORECASE),),
    "denial_of_service": (
        re.compile(r"\bdenial[ -]of[ -]service\b", re.IGNORECASE),
        re.compile(r"\bDoS\b", re.IGNORECASE),
    ),
    "ransomware": (re.compile(r"\bransomware\b", re.IGNORECASE),),
    "data_breach": (re.compile(r"\bdata breach\b", re.IGNORECASE),),
    "internet_facing": (
        re.compile(r"\binternet[ -]facing\b", re.IGNORECASE),
        re.compile(r"\bpublicly exposed\b", re.IGNORECASE),
    ),
}


def extract_cves(text: str) -> tuple[str, ...]:
    seen: set[str] = set()
    normalized: list[str] = []
    for match in CVE_PATTERN.finditer(text):
        cve = match.group(0).upper()
        if cve not in seen:
            seen.add(cve)
            normalized.append(cve)
    return tuple(normalized)


def extract_categories(text: str) -> tuple[str, ...]:
    exploitation_safe_text = mask_exploitation_negations(text)
    categories = []
    for category, patterns in CATEGORY_PATTERNS.items():
        candidate = exploitation_safe_text if category == "active_exploitation" else text
        if any(pattern.search(candidate) for pattern in patterns):
            categories.append(category)
    return tuple(categories)


def mask_exploitation_negations(text: str) -> str:
    masked = text
    for pattern in EXPLOITATION_NEGATIONS:
        masked = pattern.sub(lambda match: " " * len(match.group(0)), masked)
    return masked
