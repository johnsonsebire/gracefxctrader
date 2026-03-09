# -*- coding: utf-8 -*-
"""
signal_parser.py
────────────────
Parses Quotex signal messages from Telegram and converts them into structured
trade arguments understood by the pyquotex API.

Supported formats (with or without emojis):

  Complete signal (direction included):
    📊 USDMXN-OTCq
    ⏰ 01:35
    ⌛ 1 Minutes
    🔴 PUT DOWN ⬇️

  Partial — asset + duration + optional amount:
    👉 USD/BRL (OTC)
    ⏱ 2 MINUTE
    💵Use 200 $ from balance

  Partial — asset + duration only (direction arrives later):
    👉 USD/BRL (OTC)
    ⏱ 2 MINUTE

  Seconds duration:
    👉 EURUSD
    ⌛ 30 SECONDS

Direction may arrive in a *separate* follow-up message (2-part signal flow).
"""

import re
from typing import Optional, Dict, Any

# ── Unicode normalization (Mathematical Alphanumeric Symbols → ASCII) ──────────
# Many Telegram channels style text with Unicode bold/monospace/italic variants
# (U+1D400–U+1D7FF). We normalise them to plain ASCII before applying regexes.
_MATH_UPPER_BASES = (
    0x1D400, 0x1D434, 0x1D468, 0x1D49C, 0x1D4D0, 0x1D504,
    0x1D538, 0x1D56C, 0x1D5A0, 0x1D5D4, 0x1D608, 0x1D63C, 0x1D670,
)
_MATH_LOWER_BASES = (
    0x1D41A, 0x1D44E, 0x1D482, 0x1D4B6, 0x1D4EA, 0x1D51E,
    0x1D552, 0x1D586, 0x1D5BA, 0x1D5EE, 0x1D622, 0x1D656, 0x1D68A,
)
_MATH_DIGIT_BASES = (0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6)


def _normalize_unicode(text: str) -> str:
    """Map Unicode mathematical styled letters/digits to plain ASCII equivalents."""
    out = []
    for ch in text:
        cp = ord(ch)
        if not (0x1D400 <= cp <= 0x1D7FF):
            out.append(ch)
            continue
        mapped = False
        for base in _MATH_UPPER_BASES:
            if base <= cp < base + 26:
                out.append(chr(65 + cp - base))
                mapped = True
                break
        if not mapped:
            for base in _MATH_LOWER_BASES:
                if base <= cp < base + 26:
                    out.append(chr(97 + cp - base))
                    mapped = True
                    break
        if not mapped:
            for base in _MATH_DIGIT_BASES:
                if base <= cp < base + 10:
                    out.append(chr(48 + cp - base))
                    mapped = True
                    break
        if not mapped:
            out.append(ch)
    return ''.join(out)


# ── Referral link replacement ──────────────────────────────────────────────────
# Any broker-qx.pro sign-up URL found in non-signal channel messages will be
# replaced with the configured affiliate link.
MY_REFERRAL_LINK = "https://broker-qx.pro/sign-up/?lid=2024742"
_BROKER_URL_RE = re.compile(
    r'https?://(?:[\w.-]+\.)?broker-qx\.pro/sign-up[^\s)]*',
    re.IGNORECASE,
)


def replace_referral_links(text: str) -> str:
    """Replace any broker-qx.pro sign-up URLs in *text* with MY_REFERRAL_LINK."""
    return _BROKER_URL_RE.sub(MY_REFERRAL_LINK, text)


def normalize_asset(raw: str) -> str:
    """
    Convert a Quotex display asset name to the pyquotex API format.

    Handles:
        'USD/ARS (OTC)'     → 'USDARS_otc'
        'NZD/JPY'           → 'NZDJPY'
        'USDMXN-OTCq'       → 'USDMXN_otc'  (dash-OTC or OTCq suffix variants)
        'EURUSD_otc'        → 'EURUSD_otc'
        'Bitcoin (OTC)'     → 'BITCOIN_otc'
    """
    # Detect OTC by any of: (OTC), -OTC, _otc, OTCq (case-insensitive)
    is_otc = bool(re.search(r'[\s\-_(]?otc\w*', raw, re.IGNORECASE))
    # Strip OTC markers, parentheses, slashes, spaces, dashes — keep only letters
    base = re.sub(r'[\s\-_(]?otc\w*', '', raw, flags=re.IGNORECASE)
    base = re.sub(r'[^A-Za-z]', '', base)
    base = base.upper()
    return (base + '_otc') if is_otc else base


def parse_direction(text: str) -> Optional[str]:
    """
    Detect trade direction from message text.

    Accepted (case-insensitive, with or without emoji):
        BUY / UP / CALL / ENTERING UP / THE RISE / GOING UP / BULLISH
        📈  🔼  ↑  🟢  ⬆️
        SELL / DOWN / PUT / ENTERING DOWN / FALLING / GOING DOWN / BEARISH
        📉  🔽  ↓  🔴  ⬇️

    Returns: 'call', 'put', or None.
    """
    if not text:
        return None

    text = _normalize_unicode(text)
    t = text.upper()

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
    UP_CHARS = ['🔼', '📈', '↑', '🟢', '⬆']

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
    DOWN_CHARS = ['🔽', '📉', '↓', '🔴', '⬇']

    # Emoji/char indicators (unambiguous — check first)
    for ch in UP_CHARS:
        if ch in text:
            return 'call'
    for ch in DOWN_CHARS:
        if ch in text:
            return 'put'

    for pattern in UP_PATTERNS:
        if re.search(pattern, t):
            return 'call'
    for pattern in DOWN_PATTERNS:
        if re.search(pattern, t):
            return 'put'

    return None


# ── Asset extraction helpers ───────────────────────────────────────────────────

# Emojis that commonly precede the asset symbol line
_ASSET_EMOJI_RE = re.compile(
    r'(?:👉|📊|📈|📉|💹|🎯|⚡|🔔|🔸|🔹|➡|▶|💷|💵|•|\*)\s*(.+?)(?:\n|$)'
)

# Standalone forex-pair line: "USD/BRL (OTC)", "USDMXN-OTCq", "EURUSD_otc", "NZD/JPY"
_PAIR_LINE_RE = re.compile(
    r'(?:^|\n)\s*([A-Za-z]{2,8}(?:/[A-Za-z]{2,8})?(?:[\s\-_]?\(?OTC\w*\)?)?)\s*(?:\n|$)',
    re.IGNORECASE,
)

# A raw all-caps word pair like "USDBRL" or "EURUSD" that looks like a forex symbol
_RAW_PAIR_RE = re.compile(r'\b([A-Z]{6,8}(?:_otc)?)\b')


# Words that must never be treated as an asset name even if they appear on
# their own line or after an emoji.
_NON_ASSET_WORDS = frozenset([
    'UP', 'DOWN', 'CALL', 'PUT', 'BUY', 'SELL',
    'BULLISH', 'BEARISH', 'LONG', 'SHORT',
    'ENTERING', 'RISE', 'FALLING', 'GOING',
    'SIGNAL', 'NEXT', 'MINUTE', 'SECOND', 'USE', 'FROM', 'BALANCE',
    'THE', 'AND', 'FOR', 'NOT',
])


def _is_valid_asset_raw(raw: str) -> bool:
    """Return False if *raw* looks like a direction word or a generic keyword."""
    words = re.split(r'[\s/()]+', raw.strip())
    # Reject if ALL words are in the non-asset list (e.g. "down", "put DOWN")
    significant = [w.upper() for w in words if w]
    if not significant:
        return False
    if all(w in _NON_ASSET_WORDS for w in significant):
        return False
    return True


def _extract_asset(text: str) -> Optional[tuple]:
    """
    Try to extract (asset_display, asset_api) from *text*.
    Returns (raw_display, normalized) or None.
    """
    # 1. Emoji-prefixed line  e.g.  👉 USD/BRL (OTC)  or  📊 USDMXN-OTCq
    m = _ASSET_EMOJI_RE.search(text)
    if m:
        raw = m.group(1).strip()
        # Signal lines often have separators: "USDMXN-OTCq / ⏰ 01:35 / ..."
        # Strip everything from the first separator to isolate the asset token
        raw_clean = re.split(r'\s+/\s+|\s*\|\s*|\t', raw)[0].strip()
        # Discard if the "asset" part looks like a direction word or generic phrase
        if not re.match(r'^[A-Za-z0-9/\-_()\s]+$', raw_clean):
            pass  # contains emojis / unexpected chars — fall through
        elif re.search(r'\b(?:SIGNAL|NEXT|MINUTE|SECOND|USE|FROM|BALANCE|ENTERING|RISE|FALL)\b',
                       raw_clean.upper()):
            pass
        elif not _is_valid_asset_raw(raw_clean):
            pass
        else:
            return raw_clean, normalize_asset(raw_clean)

    # 2. Plain pair line (with or without (OTC) suffix)
    m = _PAIR_LINE_RE.search(text)
    if m:
        raw = m.group(1).strip()
        # Must contain at least one letter pair (not just numbers/time) and not be a direction word
        if re.search(r'[A-Za-z]{3}', raw) and _is_valid_asset_raw(raw):
            return raw, normalize_asset(raw)

    return None


def parse_signal(text: str) -> Optional[Dict[str, Any]]:
    """
    Parse a signal message — full or partial.

    Returns a dict with some or all of:
        asset         (str)   – pyquotex API asset name, e.g. 'USDARS_otc'
        asset_display (str)   – raw display name from the signal
        duration      (int)   – expiry in **seconds**
        amount        (float) – trade amount in USD (absent if not specified)
        direction     (str)   – 'call' or 'put' (absent if not yet posted)

    Returns None if no signal-like content is detected.
    """
    if not text:
        return None

    text = _normalize_unicode(text)
    result: Dict[str, Any] = {}

    # ── Asset ──────────────────────────────────────────────────────────────
    asset_info = _extract_asset(text)
    if asset_info:
        result['asset_display'], result['asset'] = asset_info

    # ── Duration ───────────────────────────────────────────────────────────
    # Minutes: ⏱ 2 MINUTE | ⌛ 1 Minutes | ⏰ 3 MINUTE | plain "5 MINUTES"
    # Seconds: ⌛ 30 SECONDS | ⏱ 30s | "30 SEC" | "30 SECOND"
    # Variation selector U+FE0F may trail clock emojis — consume it.

    # Try minutes first
    m = re.search(
        r'[⏱⏰⌛⌚]\ufe0f?[\s\ufe0f]*(\d+)\s*(?:MINUTES?|MINS?|MIN\b)',
        text, re.IGNORECASE,
    )
    if not m:
        m = re.search(r'(?:^|\n|\s)(\d+)\s*(?:MINUTES?|MINS?|MIN\b)(?:\s|$)', text, re.IGNORECASE)
    if m:
        result['duration'] = int(m.group(1)) * 60

    # Try M-notation shorthand: M1 / M5 / M15 / M30 (e.g. "⌚️ M1", "⏱ M5")
    if 'duration' not in result:
        m = re.search(r'[⌚⏱⏰⌛]\ufe0f?[\s]*[Mm](\d+)\b', text)
        if not m:
            m = re.search(r'(?:^|\n)\s*[Mm](\d+)\b', text)
        if m:
            result['duration'] = int(m.group(1)) * 60

    # Try seconds if no minutes found
    if 'duration' not in result:
        m = re.search(
            r'[⏱⏰⌛⌚]\ufe0f?[\s\ufe0f]*([\d]+)\s*(?:SECONDS?|SECS?|S\b)',
            text, re.IGNORECASE,
        )
        if not m:
            m = re.search(
                r'(?:^|\n|\s)([\d]+)\s*(?:SECONDS?|SECS?)(?:\s|$)',
                text, re.IGNORECASE,
            )
        if not m:
            # Shorthand: "30s" — digit(s) immediately followed by 's' at a word boundary
            m = re.search(r'(?:^|\n|\s)(\d+)s\b', text)
        if m:
            result['duration'] = int(m.group(1))  # already in seconds

    # ── Entry Time (optional — ⏰ HH:MM or standalone HH:MM line) ─────────
    # Supports 24-hour (23:41) and 12-hour (11:41 PM / 11:41PM) formats.
    # Must NOT fire on duration lines like "⏰ 3 MINUTES".
    # Strategy: match HH:MM only when NOT followed by a time-unit word.
    m_et = re.search(
        r'[⏰⏳]\ufe0f?\s*(\d{1,2}):(\d{2})[^\S\n]*(AM|PM)?[^\S\n]*(?!\S*(?:MINUTE|SECOND|MIN|SEC)\b)',
        text, re.IGNORECASE,
    )
    if not m_et:
        # Fallback: standalone HH:MM on its own line — optional AM/PM on same line
        m_et = re.search(
            r'(?:^|\n)\s*(\d{1,2}):(\d{2})[^\S\n]*(AM|PM)?[^\S\n]*(?:\n|$)',
            text, re.MULTILINE | re.IGNORECASE,
        )
    if m_et:
        hh_v = int(m_et.group(1))
        mm_v = int(m_et.group(2))
        ampm = (m_et.group(3) or '').upper()
        # Convert 12-hour to 24-hour
        if ampm == 'PM' and hh_v != 12:
            hh_v += 12
        elif ampm == 'AM' and hh_v == 12:
            hh_v = 0
        if 0 <= hh_v <= 23 and 0 <= mm_v <= 59:
            result['entry_time'] = f"{hh_v:02d}:{mm_v:02d}"

    # ── Amount (optional) ──────────────────────────────────────────────────
    # Matches:  💵Use 200 $ from balance | Use 125$ | Use 1,000 $ | "Use 5 $"
    m = re.search(r'Use\s+([\d,]+(?:\.\d+)?)\s*\$', text, re.IGNORECASE)
    if m:
        result['amount'] = float(m.group(1).replace(',', ''))

    # ── Require at least asset + duration to be a valid partial signal ─────
    # (A message with only an asset and no duration is probably not a signal)
    if 'asset' not in result:
        return None
    if 'duration' not in result and 'direction' not in result:
        # Still accept if there's a direction — it may be a complete signal
        # with no explicit duration (rely on default)
        direction_only = parse_direction(text)
        if not direction_only:
            return None

    # ── Direction (optional — may arrive in a separate follow-up message) ──
    direction = parse_direction(text)
    if direction:
        result['direction'] = direction

    return result


def is_signal_message(text: str) -> bool:
    """
    Quick pre-filter: does this message look at all like a signal?

    Returns True if the message could plausibly be a signal or a standalone
    direction follow-up for a pending partial signal.  The full parse_signal /
    parse_direction calls will decide more precisely.
    """
    if not text:
        return False

    text = _normalize_unicode(text)
    text_upper = text.upper()

    # Has a forex/crypto pair  (e.g. USD/BRL, USDMXN, EURUSD-OTCq)
    # Strip URLs first so e.g. "https://broker-qx.pro/sign-up/" doesn't match
    text_no_urls = re.sub(r'https?://\S+', '', text, flags=re.IGNORECASE)
    has_pair = bool(re.search(
        r'[A-Za-z]{2,8}/[A-Za-z]{2,8}'          # slash-separated pair: USD/BRL
        r'|[A-Z]{6,8}[\s\-_]?\(?OTC\w*\)?'      # USDMXN-OTCq  (OTC marker required)
        r'|[A-Z]{3,8}_otc',                       # EURUSD_otc explicit
        text_no_urls,
    ))

    # Emoji hints that strongly suggest a signal
    signal_emojis = ['👉', '⏱', '⏰', '⌛', '⌚', '⏳', '💵', '💷', '🔼', '🔽', '📈', '📉', '⬆', '⬇', '🟢', '🔴']

    # Text keywords
    text_kws = [
        'SIGNAL', 'ENTERING UP', 'ENTERING DOWN', 'MINUTE', 'SECOND',
        'FROM BALANCE', 'THE RISE', 'FALLING', 'GOING UP', 'GOING DOWN',
    ]

    # Standalone direction words (strip URLs first so e.g. "sign-up" doesn't
    # trigger \bUP\b) — use IGNORECASE so HTTPS:// is also stripped
    text_no_urls = re.sub(r'https?://\S+', '', text_upper, flags=re.IGNORECASE)
    dir_words = [r'\bBUY\b', r'\bSELL\b', r'\bCALL\b', r'\bPUT\b',
                 r'\bUP\b', r'\bDOWN\b']

    return (
        has_pair
        or any(e in text for e in signal_emojis)
        or any(kw in text_upper for kw in text_kws)
        or any(re.search(p, text_no_urls) for p in dir_words)
    )
