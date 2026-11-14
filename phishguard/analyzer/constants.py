"""Reference data used by the analyzer."""

BRANDS = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "hotmail",
    "google", "gmail", "amazon", "facebook", "instagram", "whatsapp", "netflix",
    "linkedin", "twitter", "telegram", "tiktok", "snapchat", "yahoo", "ebay",
    "dropbox", "adobe", "docusign", "fedex", "aramex", "binance", "coinbase",
    "metamask", "blockchain", "steam", "roblox", "chase", "wellsfargo",
    "bankofamerica", "citibank", "hsbc", "barclays", "alrajhi", "alrajhibank",
    "riyadbank", "stcpay", "absher", "emiratesnbd",
)

SUSPICIOUS_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "work", "click",
    "link", "country", "kim", "rest", "fit", "support", "cam", "icu", "buzz",
    "monster", "quest", "cfd", "sbs", "lol", "beauty", "hair", "bond",
})

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "s.id", "v.gd", "bl.ink", "lnkd.in", "shorte.st", "adf.ly",
})

PHISH_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "security", "banking", "confirm", "password", "passwd",
    "wallet", "suspend", "unlock", "billing", "invoice", "payment", "webscr",
    "cmd=_", "ebayisapi", "gift", "bonus", "prize", "winner", "recover",
    "restore", "authenticate", "credential", "validation",
)

DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".apk", ".msi", ".bat", ".cmd", ".js", ".vbs", ".jar",
    ".ps1", ".hta", ".iso", ".dll",
)

# Characters commonly swapped in to imitate letters (paypa1 -> paypal).
HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i",
})

SEVERITY_LABELS = {"high": "عالية", "medium": "متوسطة", "low": "منخفضة", "info": "معلومة"}

CATEGORY_LABELS = {
    "heuristics": "تحليل الرابط",
    "whois": "WHOIS",
    "ssl": "SSL",
    "dns": "DNS",
    "reputation": "السمعة",
}

SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 60

VERDICTS = {
    "safe": {"label": "آمن", "en": "Safe", "color": "success", "icon": "bi-shield-check"},
    "suspicious": {"label": "مشبوه", "en": "Suspicious", "color": "warning", "icon": "bi-shield-exclamation"},
    "malicious": {"label": "ضار / تصيد", "en": "Malicious", "color": "danger", "icon": "bi-shield-x"},
}
