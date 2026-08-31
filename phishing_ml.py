# Simple ML phishing classifier stub for demonstration
# You can replace this with a real model or API
import re

def ml_phishing_score(text: str) -> float:
    """
    Returns a phishing probability score between 0 and 1 based on simple heuristics.
    Replace with a real ML model for production use.
    """
    # Example heuristics: lots of links, urgent words, obfuscated text
    link_count = len(re.findall(r'https?://', text))
    urgent_words = sum(1 for w in ["urgent", "verify", "suspend", "login", "account", "immediately", "click"] if w in text.lower())
    if link_count > 3 or urgent_words > 2:
        return 0.95
    if link_count > 0 or urgent_words > 0:
        return 0.6
    return 0.1
