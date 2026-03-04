# -*- coding: utf-8 -*-
"""
signal_parser.py
────────────────
Parses Quotex signal messages from Telegram and converts them into structured
trade arguments understood by the pyquotex API.

Expected message formats (single or multi-part):

  NEXT SIGNAL 🔜

  👉 USD/ARS (OTC)
  ⏱ 2 MINUTE
  💵Use 200 $ from balance

  📈THE RISE BEGINS! ENTERING UP! 🔼🔼

Direction may arrive in a *separate* follow-up message (2-part signal flow).
"""

import re
from typing import Optional, Dict, Any


def normalize_asset(raw: str) -> str:
    """
    Convert a Quotex display asset name to the pyquotex API format.

    Examples:
        'USD/ARS (OTC)' → 'USDARS_otc'
        'NZD/JPY'       → 'NZDJPY'
        'EUR/USD (OTC)' → 'EURUSD_otc'
        'Bitcoin (OTC)' → 'BITCOIN_otc'
    """
    is_otc = bool(re.search(r'\(OTC\)', raw, re.IGNORECASE))
    # Strip (OTC), parentheses, slashes, spaces, dashes — keep only letters
    base = re.sub(r'\s*\(OTC\)\s*', '', raw, flags=re.IGNORECASE)
    base = re.sub(r'[^A-Za-z]', '', base)
    base = base.upper()
    return (base + '_otc') if is_otc else base


def parse_direction(text: str) -> Optional[str]:
    """
    Detect trade direction from message text.

    Accepted examples (case-insensitive, with or without emoji):
        BUY / UP / CALL / ENTERING UP / THE RISE / GOING UP / BULLISH
        📈  🔼  ↑
        SELL / DOWN / PUT / ENTERING DOWN / FALLING / GOING DOWN / BEARISH
        📉  🔽  ↓

    Returns:
        'call'  – BUY / UP direction
        'put'   – SELL / DOWN direction
        None    – not detected
    """
    if not text:
        return None

    t = text.upper()

    # ── CALL / BUY / UP ────────────────────────────────────────────────────
    # Word-boundary patterns catch standalone words (BUY, UP, CALL) as well
    # as longer phrases (ENTERING UP, THE RISE BEGINS, etc.)
    UP_PATTERNS = [
        r'\bENTERING\s+UP\b',
        r'\bTHE\s+RISE\b',
        r'\bGOING\s+UP\b',
        r'\bCALL\b',
        r'\bBUY\b',
        r'\bUP\b',
        r'\bBULLISH\b',
        r'\bLONG\b',
    ]
    UP_CHARS = ['🔼', '📈', '↑']

    # ── PUT / SELL / DOWN ──────────────────────────────────────────────────
    DOWN_PATTERNS = [
        r'\bENTERING\s+DOWN\b',
        r'\bFALLING\b',
        r'\bGOING\s+DOWN\b',
        r'\bPUT\b',
        r'\bSELL\b',
        r'\bDOWN\b',
        r'\bBEARISH\b',
        r'\bSHORT\b',
    ]
    DOWN_CHARS = ['🔽', '📉', '↓']

    # Check emoji/char indicators first (unambiguous)
    for ch in UP_CHARS:
        if ch in text:
            return 'call'
    for ch in DOWN_CHARS:
        if ch in text:
            return 'put'

    # Then word-boundary patterns on the uppercased text
    for pattern in UP_PATTERNS:
        if re.search(pattern, t):
            return 'call'
    for pattern in DOWN_PATTERNS:
        if re.search(pattern, t):
            return 'put'

    return None


def parse_signal(text: str) -> Optional[Dict[str, Any]]:
    """
    Parse a signal message — full or partial.

    Returns a dict with some or all of:
        asset         (str)  – pyquotex API asset name, e.g. 'USDARS_otc'
        asset_display (str)  – raw display name from the signal, e.g. 'USD/ARS (OTC)'
        duration      (int)  – expiry in seconds (minutes × 60)
        amount        (float)– trade amount in USD
        direction     (str)  – 'call' or 'put' (absent if not yet posted)

    Returns None if no signal-like content detected.
    """
    if not text:
        return None

    result: Dict[str, Any] = {}

    # ── Asset ──────────────────────────────────────────────────────────────
    # Primary:  👉 USD/ARS (OTC)
    m = re.search(r'👉\s*(.+?)(?:\n|$)', text)
    if m:
        raw = m.group(1).strip()
        result['asset_display'] = raw
        result['asset'] = normalize_asset(raw)
    else:
        # Fallback: plain line like "NZD/USD (OTC)" or "EURUSD_otc" (no emoji)
        m = re.search(
            r'(?:^|\n)\s*([A-Za-z]{2,6}/[A-Za-z]{2,6}(?:\s*\(OTC\))?)\s*(?:\n|$)',
            text, re.IGNORECASE
        )
        if m:
            raw = m.group(1).strip()
            result['asset_display'] = raw
            result['asset'] = normalize_asset(raw)

    # ── Duration ───────────────────────────────────────────────────────────
    # Matches:  ⏱ 2 MINUTE  |  ⏱️ 5 MINUTES  |  ⏰ 3 MINUTE  |  5 MINUTE (no emoji)
    # '️' (U+FE0F) is a variation selector that may trail the clock emoji — consume it.
    m = re.search(r'[⏱⏰]\ufe0f?[\s\ufe0f]*([\d]+)\s*MINUTES?', text, re.IGNORECASE)
    if not m:
        # Plain-text fallback: "5 MINUTE" or "2 MINUTES" on its own segment
        m = re.search(r'(?:^|\n|\s)([\d]+)\s*MINUTES?(?:\s|$)', text, re.IGNORECASE)
    if m:
        result['duration'] = int(m.group(1)) * 60  # convert minutes → seconds

    # ── Amount ─────────────────────────────────────────────────────────────
    # Matches:  💵Use 200 $ from balance  |  Use 125$  |  Use 1,000 $  |  plain "Use 5 $"
    m = re.search(r'Use\s+([\d,]+(?:\.\d+)?)\s*\$', text, re.IGNORECASE)
    if m:
        result['amount'] = float(m.group(1).replace(',', ''))

    # If no asset was found, this is probably not a signal message at all
    if 'asset' not in result:
        return None

    # ── Direction (optional — may arrive in a separate follow-up message) ──
    direction = parse_direction(text)
    if direction:
        result['direction'] = direction

    return result


def is_signal_message(text: str) -> bool:
    """Quick pre-filter: does this message look at all like a signal?"""
    if not text:
        return False
    emoji_indicators = ['👉', '⏱', '⏰', '💵', '🔼', '🔽', '📈', '📉']
    text_indicators  = [
        'SIGNAL', 'ENTERING UP', 'ENTERING DOWN', 'MINUTE', 'FROM BALANCE',
        'THE RISE', 'FALLING', 'GOING UP', 'GOING DOWN',
    ]
    # Standalone direction words (word-boundary aware)
    direction_words  = [r'\bBUY\b', r'\bSELL\b', r'\bUP\b', r'\bDOWN\b',
                        r'\bCALL\b', r'\bPUT\b']
    # Forex pair lines like "NZD/USD" or "EUR/USD (OTC)"
    has_pair = bool(re.search(r'[A-Za-z]{2,6}/[A-Za-z]{2,6}', text))
    text_upper = text.upper()
    return (
        has_pair
        or any(ind in text for ind in emoji_indicators)
        or any(ind in text_upper for ind in text_indicators)
        or any(re.search(p, text_upper) for p in direction_words)
    )
