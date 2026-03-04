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

    Returns:
        'call'  – for BUY / UP / RISE signals
        'put'   – for SELL / DOWN / FALL signals
        None    – direction not detected
    """
    if not text:
        return None

    t = text.upper()

    # BUY / UP / RISE / CALL indicators
    up_keywords = [
        'ENTERING UP', 'THE RISE', 'GOING UP', '🔼', 'CALL', '↑',
        'UP!', ' BUY ', 'BULLISH', 'LONG ',
    ]
    # SELL / DOWN / FALL / PUT indicators
    down_keywords = [
        'ENTERING DOWN', 'FALLING', 'GOING DOWN', '🔽', 'PUT', '↓',
        'DOWN!', ' SELL ', 'BEARISH', 'SHORT ',
    ]

    for kw in up_keywords:
        if kw in t:
            return 'call'
    for kw in down_keywords:
        if kw in t:
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
    # Matches:  👉 USD/ARS (OTC)   or   👉 EURUSD_otc
    m = re.search(r'👉\s*(.+?)(?:\n|$)', text)
    if m:
        raw = m.group(1).strip()
        result['asset_display'] = raw
        result['asset'] = normalize_asset(raw)

    # ── Duration ───────────────────────────────────────────────────────────
    # Matches:  ⏱ 2 MINUTE  |  ⏱ 5 MINUTES  |  ⏰ 3 MINUTE
    m = re.search(r'[⏱⏰]\s*(\d+)\s*MINUTES?', text, re.IGNORECASE)
    if m:
        result['duration'] = int(m.group(1)) * 60  # convert minutes → seconds

    # ── Amount ─────────────────────────────────────────────────────────────
    # Matches:  💵Use 200 $ from balance  |  Use 125$  |  Use 1,000 $
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
    indicators = ['👉', '⏱', '💵', 'SIGNAL', '🔼', '🔽', 'ENTERING UP', 'ENTERING DOWN']
    text_upper = text.upper()
    return any(ind in text_upper or ind in text for ind in indicators)
