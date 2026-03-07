# -*- coding: utf-8 -*-
import os
import sys
import time
import concurrent.futures
import asyncio
import logging
import datetime
import re # For PIN detection
import json
from pathlib import Path
import builtins
from unittest.mock import patch

try:
    import quotex_auth as _quotex_auth
except ImportError:
    _quotex_auth = None
import asyncio # Ensure asyncio is imported if not already globally
from functools import wraps
from typing import Optional, Dict, Any, Tuple, List
from dotenv import load_dotenv
import os
# --- DNS Resolver Patch ---

USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"

try:
    from pyrogram import Client, filters
    from pyrogram.types import (
        InlineKeyboardMarkup, InlineKeyboardButton, Message, CallbackQuery,
        ForceReply
    )
    from pyrogram import enums
    from pyrogram.errors import UserIsBlocked, FloodWait, InputUserDeactivated, UserDeactivated
except ImportError:
    print("Error: Pyrofork not found. Install it: pip install pyrofork tgcrypto")
    sys.exit(1)

# ── Monkey-patch pyrogram Session.restart ───────────────────────────────────
# Pyrogram maintains multiple concurrent DC sessions.  When connectivity is
# lost all of them try to restart() simultaneously on the same session object,
# racing on recv_task and producing:
#   RuntimeError: read() called while another coroutine is already waiting
# Fix: serialise restart() per session instance; drop duplicate callers.
try:
    from pyrogram.session import Session as _PyrSession
    _orig_session_restart = _PyrSession.restart

    async def _patched_session_restart(self) -> None:  # type: ignore[override]
        # Lazily create a per-session asyncio lock (asyncio is single-threaded,
        # so the getattr/setattr sequence is race-free).
        lock = getattr(self, '_restart_lock', None)
        if lock is None:
            lock = asyncio.Lock()
            self._restart_lock = lock  # type: ignore[attr-defined]
        if lock.locked():
            # Another coroutine is already restarting this session — skip.
            return
        async with lock:
            try:
                await _orig_session_restart(self)
            except RuntimeError as _e:
                if 'read() called while another coroutine' in str(_e):
                    pass  # silently swallow the known concurrent-read race
                else:
                    raise

    _PyrSession.restart = _patched_session_restart  # type: ignore[method-assign]
except Exception as _patch_err:
    import warnings
    warnings.warn(f"[Startup] Could not patch Session.restart: {_patch_err}")
# ────────────────────────────────────────────────────────────────────────────

try:
    import motor.motor_asyncio
except ImportError:
    print("Error: Motor not found. Install it: pip install motor")
    sys.exit(1)

import ssl
try:
    import certifi
except ImportError:
    certifi = None

# Patch pymongo's get_ssl_context to set SECLEVEL=1 for OpenSSL 3.x compatibility
# with MongoDB Atlas (fixes TLSV1_ALERT_INTERNAL_ERROR on Python 3.12+/OpenSSL 3.x)
try:
    import pymongo.ssl_support as _pymongo_ssl_support
    _orig_get_ssl_context = _pymongo_ssl_support.get_ssl_context
    def _patched_get_ssl_context(*args, **kwargs):
        ctx = _orig_get_ssl_context(*args, **kwargs)
        if ctx is not None:
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=1")
            except Exception:
                pass
        return ctx
    _pymongo_ssl_support.get_ssl_context = _patched_get_ssl_context
except Exception:
    pass

_orig_create_default_context = ssl.create_default_context
def _patched_create_default_context(purpose=ssl.Purpose.SERVER_AUTH, *args, **kwargs):
    ctx = _orig_create_default_context(purpose, *args, **kwargs)
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx
ssl.create_default_context = _patched_create_default_context

try:
    from colorama import init, Fore, Style
    init(autoreset=True) # Initialize Colorama for script logging if needed
except ImportError:
    print("Colorama not found. Installing it is recommended: pip install colorama")
    class DummyStyle:
        def __getattr__(self, name): return ""
    Fore = DummyStyle()
    Style = DummyStyle()

# --- pyquotex Imports ---
try:
    from pyquotex.stable_api import Quotex
    from pyquotex.utils.processor import get_color # Optional
    import pyquotex.global_value as _qx_global_value
    # Monkey patch target detection function (safer approach)
    # --- Inside your script, replace the existing function ---
    
except ImportError:
    print(f"{Fore.RED}Error: pyquotex library not found or import failed.")
    print(f"{Fore.YELLOW}Please install it via pip:")
    print(f"{Fore.CYAN}pip install git+https://github.com/cleitonleonel/pyquotex.git")
    sys.exit(1)
except Exception as e:
    print(f"{Fore.RED}Error during pyquotex import or patching setup: {e}")
    sys.exit(1)

# --- Signal Parser ---
try:
    from signal_parser import parse_signal, parse_direction, is_signal_message, replace_referral_links
except ImportError:
    print("Error: signal_parser.py not found. Place it in the same directory as bot.py.")
    sys.exit(1)

# --- Configuration (Load from environment variables or a config file) ---
# It's better practice to load these from environment or a separate config.py
# For simplicity in a single file as requested:
# Load environment variables from a .env file
load_dotenv()

API_ID = int(os.getenv("API_ID") or 12345678)  # Replace with a default value if needed
API_HASH = os.getenv("API_HASH") or "your_api_hash"
BOT_TOKEN = os.getenv("BOT_TOKEN") or "your_bot_token"
MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017/"
OWNER_ID = int(os.getenv("OWNER_ID") or 987654321)  # Replace with a default value if needed

# Signal channel monitoring
USERBOT_PHONE: str = os.getenv("USERBOT_PHONE", "").strip()
_raw_channel = os.getenv("SIGNAL_CHANNEL_ID", "").strip()
SIGNAL_CHANNEL_ID: Optional[int] = int(_raw_channel) if _raw_channel.lstrip('-').isdigit() else None

# Quotex session overrides (optional). Useful when anti-bot protection blocks
# raw credential login from server environments.
QUOTEX_USER_AGENT = os.getenv("QUOTEX_USER_AGENT", USER_AGENT).strip() or USER_AGENT
QUOTEX_SSID = os.getenv("QUOTEX_SSID", "").strip()
QUOTEX_COOKIES = os.getenv("QUOTEX_COOKIES", "").strip()

# Basic Logging
_LOG_FMT = '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
_log_dir = Path(os.path.dirname(os.path.abspath(__file__)))
_log_file = _log_dir / 'bot.log'

_root_logger = logging.getLogger()
_root_logger.setLevel(logging.INFO)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(logging.Formatter(_LOG_FMT))
_root_logger.addHandler(_console_handler)
try:
    from logging.handlers import RotatingFileHandler as _RFH
    _file_handler = _RFH(_log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
    _file_handler.setFormatter(logging.Formatter(_LOG_FMT))
    _root_logger.addHandler(_file_handler)
except Exception as _e:
    print(f'[WARNING] Could not create log file {_log_file}: {_e}')

logger = logging.getLogger(__name__)
logging.getLogger("pyrofork").setLevel(logging.WARNING) # Reduce pyrogram verbosity
logging.getLogger("undetected_chromedriver").setLevel(logging.WARNING)
logging.getLogger("selenium").setLevel(logging.WARNING)

try:
    import dns.resolver
    if hasattr(dns.resolver, 'get_default_resolver'):
         dns.resolver.get_default_resolver().nameservers=['8.8.8.8', '1.1.1.1']
    else:
         dns.resolver.default_resolver=dns.resolver.Resolver(configure=False)
         dns.resolver.default_resolver.nameservers=['8.8.8.8', '1.1.1.1']
    logger.info("Applied DNS resolver patch.")
except ImportError:
    logger.warning("dnspython not installed. Skipping DNS resolver patch.")
except Exception as e:
    logger.error(f"Error applying DNS resolver patch: {e}")
# --- Third-party Libraries ---

# --- Global Variables & Bot Initialization ---
bot_instance: Optional[Client] = None
userbot_instance: Optional[Client] = None  # MTProto user session for channel monitoring
_ubot_restart_lock: asyncio.Lock = asyncio.Lock()  # serialises watchdog restarts
_manual_trade_lock: asyncio.Lock = asyncio.Lock()  # prevents double-execution on rapid button taps
db = None  # Database client
main_event_loop = None # <<< ADD THIS GLOBAL VARIABLE
users_db = None # Collection for users, roles, basic settings
quotex_accounts_db = None # Collection for Quotex credentials
trade_settings_db = None # Collection for trade settings per user/account
signal_settings_db = None  # Collection for signal channel + pending signal state
signal_logs_db = None       # Collection for per-signal timing/event log
trade_journal_db = None  # Collection for per-account daily trade journal
trade_journal_balances_db = None  # Collection for daily opening/closing account balances
trade_journal_withdrawals_db = None  # Collection for withdrawal records

# Temporary storage for OTP requests: {user_id: {'qx_client': qx_client_instance, 'event': asyncio.Event()}}
active_otp_requests: Dict[int, Dict[str, Any]] = {}

# Temporary storage for ongoing user actions (e.g., waiting for broadcast message)
user_states: Dict[int, str] = {} # e.g., {user_id: "waiting_broadcast_message"}

# Default Quotex Settings (can be overridden from DB)
DEFAULT_TRADE_AMOUNT = 5
DEFAULT_TRADE_DURATION = 60 # For Timer/Time mode number

# Maximum seconds allowed between signal receipt and the actual buy() call.
# If setup (auth, asset check, price feed) takes longer than this, the trade
# is skipped — a late entry is worse than no entry.
MAX_ENTRY_DELAY_SECONDS = 5.0

# UTC+5:30 (IST) timezone for signal timing logs
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
DEFAULT_TRADE_MODE = "TIMER" # 'TIMER' or 'TIME'
DEFAULT_CANDLE_SIZE = 60
DEFAULT_SERVICE_STATUS = True # Accounts Active (participate in signal trades) by default

MARTINGALE_MULTIPLIER = 2.0
MAX_CONSECUTIVE_LOSSES = 3
COOLDOWN_MINUTES = 3

# ── Strategy Mode ─────────────────────────────────────────────────────────────
# Each strategy is a sequence of 10 trade amounts.
# On WIN  → step resets to 0 (start of sequence).
# On LOSS → step advances by 1 (next higher amount to recover).
# If step reaches end of sequence → resets to 0 (fresh cycle).
# Minimum balance required = first step amount.
STRATEGIES: Dict[int, Dict[str, Any]] = {
    1: {
        "name":        "Strategy 1 ($25 min balance)",
        "min_balance": 25.0,
        "steps":       [5, 10, 15, 20, 25, 30, 75, 100, 125, 175],
    },
    2: {
        "name":        "Strategy 2 ($50 min balance)",
        "min_balance": 50.0,
        "steps":       [15, 20, 25, 30, 35, 65, 125, 200, 300, 350],
    },
}
# ─────────────────────────────────────────────────────────────────────────────

# --- Database Setup ---
async def setup_database():
    """Initializes MongoDB connection and collections."""
    global db, users_db, quotex_accounts_db, trade_settings_db, signal_settings_db, signal_logs_db, trade_journal_db, trade_journal_balances_db, trade_journal_withdrawals_db
    try:
        is_atlas = MONGO_URI.startswith("mongodb+srv") or "mongodb.net" in MONGO_URI
        tls_kwargs = {"tlsCAFile": certifi.where()} if (is_atlas and certifi) else {}
        client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI, **tls_kwargs)
        db = client['quotexTraderBot'] # Database name
        users_db = db['users']
        quotex_accounts_db = db['quotex_accounts']
        trade_settings_db = db['trade_settings']
        signal_settings_db = db['signal_settings']
        signal_logs_db     = db['signal_logs']
        trade_journal_db   = db['trade_journal']
        trade_journal_balances_db = db['trade_journal_balances']
        # Create indexes for faster lookups
        await users_db.create_index("user_id", unique=True)
        await quotex_accounts_db.create_index([("user_id", 1), ("email", 1)], unique=True)
        await trade_settings_db.create_index("account_doc_id", unique=True) # Link to quotex account document
        await signal_settings_db.create_index("owner_id", unique=True)
        await signal_logs_db.create_index("received_at")
        await signal_logs_db.create_index(
            "created_at",
            expireAfterSeconds=60 * 60 * 24 * 30,  # auto-delete after 30 days
        )
        await trade_journal_db.create_index([("account_doc_id", 1), ("date", 1)])
        await trade_journal_db.create_index("entry_time")
        await trade_journal_balances_db.create_index([("account_doc_id", 1), ("date", 1)], unique=True)
        trade_journal_withdrawals_db = db['trade_journal_withdrawals']
        await trade_journal_withdrawals_db.create_index([("account_doc_id", 1), ("date", 1)])
        logger.info("Database connection successful and collections initialized.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}", exc_info=True)
        sys.exit(1)

# --- Database Helper Functions ---

async def add_user_if_not_exists(user_id: int):
    """Adds a user to the database if they aren't already there."""
    if users_db is None:
        logger.error("Users DB not initialized.")
        return None
    user_data = await users_db.find_one({"user_id": user_id})
    if not user_data:
        is_owner = (user_id == OWNER_ID)
        new_user = {
            "user_id": user_id,
            "is_sudo": is_owner, # Owner is automatically sudo
            "is_premium": is_owner, # Owner is automatically premium
            "join_date": datetime.datetime.now(datetime.timezone.utc)
        }
        await users_db.insert_one(new_user)
        logger.info(f"New user added to DB: {user_id}")
        return new_user
    return user_data

async def get_user(user_id: int):
    """Retrieves user data from DB."""
    if users_db is None: return None
    return await users_db.find_one({"user_id": user_id})

async def is_sudo_user(user_id: int) -> bool:
    """Checks if a user has sudo privileges."""
    if user_id == OWNER_ID: return True
    if users_db is None: return False
    user_data = await users_db.find_one({"user_id": user_id})
    return user_data and user_data.get("is_sudo", False)

async def is_premium_user(user_id: int) -> bool:
    """Checks if a user is premium."""
    if user_id == OWNER_ID: return True # Owner always premium
    if users_db is None: return False
    user_data = await users_db.find_one({"user_id": user_id})
    # Allow sudo users to access premium features too
    return user_data and (user_data.get("is_premium", False) or user_data.get("is_sudo", False))

async def set_user_role(target_user_id: int, role: str, status: bool):
    """Sets 'is_sudo' or 'is_premium' status for a user."""
    if users_db is None: return False
    if role not in ["is_sudo", "is_premium"]: return False
    result = await users_db.update_one(
        {"user_id": target_user_id},
        {"$set": {role: status}}
    )
    return result.modified_count > 0

async def get_all_user_ids() -> list[int]:
    """Gets a list of all user IDs from the DB."""
    if users_db is None: return []
    users_cursor = users_db.find({}, {"_id": 0, "user_id": 1})
    return [user["user_id"] async for user in users_cursor]

async def get_role_user_ids(role: str) -> list[int]:
    """Gets user IDs for a specific role (is_sudo or is_premium)."""
    if users_db is None or role not in ["is_sudo", "is_premium"]: return []
    users_cursor = users_db.find({role: True}, {"_id": 0, "user_id": 1})
    return [user["user_id"] async for user in users_cursor]

# --- Quotex Account DB Functions ---

async def add_quotex_account(user_id: int, email: str, password: str):
    """Adds a Quotex account credential for a user."""
    if quotex_accounts_db is None: return False
    try:
        # Consider encrypting the password before storing!
        await quotex_accounts_db.insert_one({
            "user_id": user_id,
            "email": email.lower(), # Store email in lowercase for consistency
            "password": password, # WARNING: Storing plain text password!
            "added_date": datetime.datetime.now(datetime.timezone.utc)
        })
        return True
    except Exception as e: # Likely duplicate key error if email already exists for user
        logger.warning(f"Failed to add Quotex account {email} for user {user_id}: {e}")
        return False

async def get_user_quotex_accounts(user_id: int) -> List[Dict[str, Any]]:
    """Gets all Quotex accounts associated with a user."""
    if quotex_accounts_db is None: return []
    accounts_cursor = quotex_accounts_db.find({"user_id": user_id}, {"_id": 1, "email": 1}) # Fetch ID and email
    return await accounts_cursor.to_list(length=None) # Get all accounts

async def get_all_quotex_accounts(search: str = None) -> List[Dict[str, Any]]:
    """Gets all Quotex accounts across all users, with optional email/user_id search."""
    if quotex_accounts_db is None: return []
    query = {}
    if search:
        search = search.strip()
        # Search by email (case-insensitive) or user_id if numeric
        if search.lstrip('-').isdigit():
            query = {"$or": [{"user_id": int(search)}, {"email": {"$regex": search, "$options": "i"}}]}
        else:
            query = {"email": {"$regex": search, "$options": "i"}}
    cursor = quotex_accounts_db.find(query, {"_id": 1, "email": 1, "user_id": 1})
    return await cursor.to_list(length=100)

async def get_quotex_account_details(account_doc_id: str) -> Optional[Dict[str, Any]]:
    """Gets full details of a specific Quotex account by its DB document ID."""
    from bson import ObjectId
    if quotex_accounts_db is None: return None
    try:
        return await quotex_accounts_db.find_one({"_id": ObjectId(account_doc_id)})
    except Exception:
        return None

async def delete_quotex_account(account_doc_id: str) -> bool:
    """Deletes a Quotex account and its associated settings."""
    from bson import ObjectId
    if quotex_accounts_db is None or trade_settings_db is None: return False
    try:
        # Delete account credentials
        delete_acc_result = await quotex_accounts_db.delete_one({"_id": ObjectId(account_doc_id)})
        # Delete associated trade settings
        await trade_settings_db.delete_many({"account_doc_id": ObjectId(account_doc_id)}) # Use delete_many for safety

        return delete_acc_result.deleted_count > 0
    except Exception as e:
        logger.error(f"Error deleting account {account_doc_id}: {e}", exc_info=True)
        return False

# --- Trade Settings DB Functions ---

async def get_or_create_trade_settings(account_doc_id: str) -> Dict[str, Any]:
    """Gets trade settings for a Quotex account, creating defaults if none exist."""
    from bson import ObjectId
    if trade_settings_db is None:
        raise ConnectionError("Trade settings DB not initialized.")
    settings = await trade_settings_db.find_one({"account_doc_id": ObjectId(account_doc_id)})
    if not settings:
        settings = {
            "account_doc_id": ObjectId(account_doc_id),
            "account_mode": "PRACTICE", # PRACTICE / REAL
            "trade_mode": DEFAULT_TRADE_MODE, # TIMER / TIME
            "candle_size": DEFAULT_CANDLE_SIZE, # seconds
            "service_status": DEFAULT_SERVICE_STATUS, # Trading on/off (boolean)
            "assets": [], # List of dicts: {'name': str, 'amount': int, 'duration': int}
            # Martingale state can also be stored here per asset if needed for persistence
            "martingale_state": {}, # { asset_name: {'current_amount': float, 'consecutive_losses': int}}
            "cooldown_until": 0.0, # Timestamp
            "last_updated": datetime.datetime.now(datetime.timezone.utc)
        }
        await trade_settings_db.insert_one(settings)
        logger.info(f"Created default trade settings for account_doc_id {account_doc_id}")
    # Ensure all default keys exist in case new settings are added later
    defaults = {
        "account_mode": "PRACTICE", "trade_mode": DEFAULT_TRADE_MODE,
        "candle_size": DEFAULT_CANDLE_SIZE, "service_status": DEFAULT_SERVICE_STATUS,
        "assets": [], "martingale_state": {}, "cooldown_until": 0.0
    }
    updated = False
    for key, default_value in defaults.items():
        if key not in settings:
            settings[key] = default_value
            updated = True
    if updated:
         await update_trade_setting(account_doc_id, settings) # Save potentially added default keys

    return settings

async def update_trade_setting(account_doc_id: str, update_data: dict):
    """Updates specific trade settings for a Quotex account."""
    from bson import ObjectId
    if trade_settings_db is None: return False
    update_data["last_updated"] = datetime.datetime.now(datetime.timezone.utc)
    result = await trade_settings_db.update_one(
        {"account_doc_id": ObjectId(account_doc_id)},
        {"$set": update_data},
        upsert=True # Create if somehow missing, though get_or_create should handle it
    )
    return result.modified_count > 0 or result.upserted_id is not None

# --- Trade Journal DB Functions ---

async def save_journal_entry(entry: dict) -> bool:
    """Persist a single trade journal record to the database."""
    if trade_journal_db is None:
        logger.warning("[Journal] trade_journal_db not initialized.")
        return False
    try:
        await trade_journal_db.insert_one(entry)
        return True
    except Exception as e:
        logger.error(f"[Journal] Failed to save entry: {e}", exc_info=True)
        return False

async def get_journal_entries(
    account_doc_ids: list = None,
    date_str: str = None,      # "YYYY-MM-DD"
    limit: int = 100,
) -> list:
    """Fetch journal entries filtered by account(s) and/or date, newest first."""
    if trade_journal_db is None:
        return []
    query: dict = {}
    if account_doc_ids:
        query["account_doc_id"] = {"$in": account_doc_ids}
    if date_str:
        query["date"] = date_str
    cursor = trade_journal_db.find(query).sort("entry_time", -1).limit(limit)
    return await cursor.to_list(length=limit)

async def get_journal_summary(account_doc_ids: list, date_str: str) -> dict:
    """Return aggregated win/loss/tie counts, net P&L, and daily balances for a given day."""
    entries = await get_journal_entries(account_doc_ids=account_doc_ids, date_str=date_str)
    total = len(entries)
    wins   = sum(1 for e in entries if e.get("result") == "WIN")
    losses = sum(1 for e in entries if e.get("result") == "LOSS")
    ties   = sum(1 for e in entries if e.get("result") == "TIE")
    net_pl = sum(e.get("profit_loss", 0) for e in entries)
    daily_balances = await get_daily_balances(account_doc_ids, date_str)
    daily_withdrawals = await get_daily_withdrawals(account_doc_ids, date_str)
    return {"total": total, "wins": wins, "losses": losses, "ties": ties, "net_pl": round(net_pl, 2), "entries": entries, "daily_balances": daily_balances, "daily_withdrawals": daily_withdrawals}

async def record_opening_balance(account_doc_id: str, email: str, date_str: str, account_mode: str, balance: float) -> bool:
    """Record the opening balance for the day — only written on the very first trade."""
    if trade_journal_balances_db is None:
        return False
    try:
        await trade_journal_balances_db.update_one(
            {"account_doc_id": account_doc_id, "date": date_str},
            {
                "$setOnInsert": {
                    "account_doc_id": account_doc_id,
                    "email": email,
                    "date": date_str,
                    "account_mode": account_mode,
                    "opening_balance": balance,
                },
                "$set": {"closing_balance": balance},  # initialise closing too
            },
            upsert=True,
        )
        return True
    except Exception as e:
        logger.error(f"[Journal] Failed to save opening balance: {e}", exc_info=True)
        return False

async def record_closing_balance(account_doc_id: str, date_str: str, balance: float) -> bool:
    """Update the closing balance after each trade."""
    if trade_journal_balances_db is None:
        return False
    try:
        await trade_journal_balances_db.update_one(
            {"account_doc_id": account_doc_id, "date": date_str},
            {"$set": {"closing_balance": balance}},
        )
        return True
    except Exception as e:
        logger.error(f"[Journal] Failed to save closing balance: {e}", exc_info=True)
        return False

async def get_daily_balances(account_doc_ids: list, date_str: str) -> dict:
    """Return {account_doc_id: {opening_balance, closing_balance, email, account_mode}} for a date."""
    if trade_journal_balances_db is None:
        return {}
    cursor = trade_journal_balances_db.find({"account_doc_id": {"$in": account_doc_ids}, "date": date_str})
    docs = await cursor.to_list(length=100)
    return {d["account_doc_id"]: d for d in docs}

async def save_withdrawal(account_doc_id: str, email: str, date_str: str, amount: float, note: str = "") -> bool:
    """Record a withdrawal for an account on a given day."""
    if trade_journal_withdrawals_db is None:
        logger.warning("[Journal] trade_journal_withdrawals_db not initialized.")
        return False
    try:
        await trade_journal_withdrawals_db.insert_one({
            "account_doc_id": account_doc_id,
            "email": email,
            "date": date_str,
            "amount": round(amount, 2),
            "note": note,
            "recorded_at": datetime.datetime.now(datetime.timezone.utc),
        })
        return True
    except Exception as e:
        logger.error(f"[Journal] Failed to save withdrawal: {e}", exc_info=True)
        return False

async def get_daily_withdrawals(account_doc_ids: list, date_str: str) -> dict:
    """Return {account_doc_id: [withdrawal_docs]} for a date."""
    if trade_journal_withdrawals_db is None:
        return {}
    cursor = trade_journal_withdrawals_db.find({"account_doc_id": {"$in": account_doc_ids}, "date": date_str})
    docs = await cursor.to_list(length=200)
    result: dict = {}
    for d in docs:
        result.setdefault(d["account_doc_id"], []).append(d)
    return result


def _build_journal_text(summary: dict, view_date: str) -> str:
    """Build the display text for a journal view (shared helper for all 3 display locations)."""
    entries = summary["entries"]
    journal_text = f"📓 **Trading Journal — {view_date}**\n\n"

    if not entries:
        journal_text += "_No trades recorded for this day._\n"
    else:
        by_account: Dict[str, list] = {}
        for e in entries:
            by_account.setdefault(e.get("email", "Unknown"), []).append(e)

        daily_bals = summary.get("daily_balances", {})
        daily_wds = summary.get("daily_withdrawals", {})

        def _fmt_bal(v: Optional[float]) -> str:
            return f"${v:,.2f}" if v is not None else "N/A"

        acct_sections = list(by_account.items())
        for sec_idx, (acct_email, trades) in enumerate(acct_sections):
            if sec_idx > 0:
                journal_text += "━━━━━━━━━━━━━━━━━━━━━\n"
            acct_doc_id = trades[0].get("account_doc_id", "")
            bal_rec = daily_bals.get(acct_doc_id, {})
            opening_bal = bal_rec.get("opening_balance")
            closing_bal = bal_rec.get("closing_balance")
            wds = daily_wds.get(acct_doc_id, [])
            total_wd = sum(w.get("amount", 0) for w in wds)
            adjusted_close = (closing_bal - total_wd) if (closing_bal is not None and total_wd) else closing_bal

            journal_text += f"📧 **{acct_email}** ({trades[0].get('account_mode', '')}):\n"
            if opening_bal is not None:
                bal_diff = (adjusted_close - opening_bal) if adjusted_close is not None else 0
                diff_str = (
                    f" ({'+' if bal_diff >= 0 else ''}{bal_diff:,.2f})"
                    if adjusted_close is not None else ""
                )
                close_label = f"{_fmt_bal(adjusted_close)}{diff_str}"
                if total_wd:
                    close_label += f"  _(−${total_wd:,.2f} withdrawn)_"
                journal_text += f"   💵 Open: {_fmt_bal(opening_bal)}  →  Close: {close_label}\n"

            for i, t in enumerate(trades, 1):
                res_icon = "✅" if t["result"] == "WIN" else ("⚠️" if t["result"] == "TIE" else "❌")
                pl = t.get("profit_loss", 0)
                pl_str = f"+${abs(pl):.2f}" if pl > 0 else (f"-${abs(pl):.2f}" if pl < 0 else "$0.00")
                entry_ts = t["entry_time"].strftime("%H:%M:%S") if isinstance(t.get("entry_time"), datetime.datetime) else "N/A"
                close_ts = t["closing_time"].strftime("%H:%M:%S") if isinstance(t.get("closing_time"), datetime.datetime) else "N/A"
                e_price = f"{t['entry_price']:.5f}" if t.get("entry_price") else "N/A"
                c_price = f"{t['closing_price']:.5f}" if t.get("closing_price") else "N/A"
                manual_tag = " ✍️" if t.get("manual") else ""
                journal_text += (
                    f"  {i}. {res_icon} `{t.get('symbol', 'N/A')}` | {t.get('direction', '?')} | "
                    f"${t.get('amount', 0)} | {t.get('duration', 0) // 60}min{manual_tag}\n"
                    f"      ⏰ Entry: {entry_ts} UTC @ {e_price}\n"
                    f"      🏁 Close: {close_ts} UTC @ {c_price}\n"
                    f"      📌 Result: **{t['result']}**  {pl_str}\n"
                )
                if i < len(trades):
                    journal_text += "      ─ ─ ─ ─ ─ ─ ─ ─ ─ ─\n"

            if wds:
                for w in wds:
                    note_str = f" — {w['note']}" if w.get("note") else ""
                    journal_text += f"   💸 Withdrawal: ${w.get('amount', 0):,.2f}{note_str}\n"

            journal_text += "\n"

        # Summary footer
        total_wd_all = sum(
            sum(w.get("amount", 0) for w in wlist)
            for wlist in daily_wds.values()
        )
        net_str = f"+${summary['net_pl']:.2f}" if summary['net_pl'] >= 0 else f"-${abs(summary['net_pl']):.2f}"
        journal_text += (
            f"─────────────────────\n"
            f"📊 **Summary:** {summary['total']} trade(s) | "
            f"✅ {summary['wins']} Win | ❌ {summary['losses']} Loss | ⚠️ {summary['ties']} Tie\n"
            f"💰 **Net P&L:** {net_str}"
        )
        if total_wd_all:
            journal_text += f"\n💸 **Total Withdrawn:** ${total_wd_all:,.2f}"

    return journal_text


# --- Signal Settings DB Functions ---

async def log_signal_event(
    event_type: str,
    message,                        # pyrofork Message object
    parsed: Optional[Dict] = None,
    direction: Optional[str] = None,
    extra: Optional[Dict] = None,
):
    """
    Persist a signal timing entry to MongoDB with UTC+5:30 timestamps.

    event_type values:
        'full'              – complete signal (asset + duration + amount + direction)
        'partial'           – signal without direction yet
        'direction'         – standalone direction follow-up matched to pending
        'direction_expired' – direction arrived but pending had expired
        'unmatched_direction' – direction msg but no pending signal
    """
    if signal_logs_db is None:
        return
    try:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_ist = now_utc.astimezone(IST)

        # message.date is a datetime (UTC) in pyrofork
        provider_dt_utc = message.date if message.date.tzinfo else message.date.replace(tzinfo=datetime.timezone.utc)
        provider_dt_ist = provider_dt_utc.astimezone(IST)
        delay_s = round((now_utc - provider_dt_utc).total_seconds(), 2)

        entry = {
            'event_type':       event_type,
            'received_at':      now_ist,          # UTC+5:30
            'received_at_utc':  now_utc,
            'provider_sent_at': provider_dt_ist,  # UTC+5:30
            'provider_sent_utc': provider_dt_utc,
            'delay_seconds':    delay_s,
            'channel_id':       str(message.chat.id),
            'message_id':       message.id,
            'raw_text':         (message.text or message.caption or '')[:300],
            'asset':            (parsed or {}).get('asset'),
            'asset_display':    (parsed or {}).get('asset_display'),
            'duration':         (parsed or {}).get('duration'),
            'amount':           (parsed or {}).get('amount'),
            'direction':        direction or (parsed or {}).get('direction'),
            'created_at':       now_utc,  # used by TTL index
        }
        if extra:
            entry.update(extra)
        await signal_logs_db.insert_one(entry)
        logger.info(
            f"[SignalLog] {event_type} | provider={provider_dt_ist.strftime('%H:%M:%S')} IST "
            f"| received={now_ist.strftime('%H:%M:%S')} IST | delay={delay_s}s"
        )
    except Exception as e:
        logger.warning(f"[SignalLog] Failed to write log entry: {e}")


async def get_signal_settings() -> Dict[str, Any]:
    """Get the single signal-settings document for the owner (creates defaults if missing)."""
    if signal_settings_db is None:
        return {}
    doc = await signal_settings_db.find_one({'owner_id': OWNER_ID})
    if not doc:
        initial_channels = [{'id': str(SIGNAL_CHANNEL_ID), 'active': True}] if SIGNAL_CHANNEL_ID else []
        doc = {
            'owner_id': OWNER_ID,
            'channel_id': SIGNAL_CHANNEL_ID,  # legacy field kept for compat
            'channels': initial_channels,
            'is_active': False,
            'pending_signal': None,
            'signal_delay': 15,
            'duration_remap_enabled': False,
            'ask_duration_on_partial': False,
            'manual_trade_mode': False,
            'inverse_mode': False,
            'strategy_mode': False,        # bool — strategy mode on/off
            'strategy_id': 1,              # int — which strategy (1 or 2)
            'strategy_step': 0,            # int — current step index (0-9)
        }
        await signal_settings_db.insert_one(doc)
    else:
        # One-time migration: promote legacy channel_id → channels list
        if 'channels' not in doc:
            legacy_ch = doc.get('channel_id')
            migrated = [{'id': str(legacy_ch), 'active': True}] if legacy_ch else []
            await signal_settings_db.update_one(
                {'owner_id': OWNER_ID},
                {'$set': {'channels': migrated}}
            )
            doc['channels'] = migrated
    return doc

async def update_signal_settings(data: dict):
    """Update the signal settings document for the owner."""
    if signal_settings_db is None:
        return
    data['last_updated'] = datetime.datetime.now(datetime.timezone.utc)
    await signal_settings_db.update_one(
        {'owner_id': OWNER_ID},
        {'$set': data},
        upsert=True
    )


# ── Strategy Mode helpers ────────────────────────────────────────────────────

def _strategy_summary(sig_settings: dict) -> str:
    """One-line summary for display in panels."""
    if not sig_settings.get('strategy_mode'):
        return 'Disabled'
    sid = sig_settings.get('strategy_id', 1)
    step = sig_settings.get('strategy_step', 0)
    strat = STRATEGIES.get(sid)
    if not strat:
        return f'Strategy {sid} (unknown)'
    steps = strat['steps']
    current_amt = steps[min(step, len(steps) - 1)]
    return f"Strategy {sid} — Step {step + 1}/10 (${current_amt})"


def _strategy_panel_text(sig_settings: dict) -> str:
    """Text body for the Strategy Mode settings panel."""
    enabled = sig_settings.get('strategy_mode', False)
    active_sid = sig_settings.get('strategy_id', 1)
    step = sig_settings.get('strategy_step', 0)

    lines = ["🎯 **Strategy Mode**\n"]
    lines.append(f"Status: {'🟢 **Enabled**' if enabled else '🔴 Disabled'}\n")
    if enabled:
        strat = STRATEGIES.get(active_sid, {})
        steps = strat.get('steps', [])
        current_amt = steps[min(step, len(steps) - 1)] if steps else '?'
        lines.append(f"Active: **{strat.get('name', f'Strategy {active_sid}')}**")
        lines.append(f"Progress: Step **{step + 1}/10** — Next trade amount: **${current_amt}**\n")
        lines.append("_WIN → resets to step 1 | LOSS → advances to next step_\n")
    lines.append("\n**Available Strategies:**")
    for sid, strat in STRATEGIES.items():
        marker = '✅' if (enabled and sid == active_sid) else '○'
        lines.append(f"{marker} **{strat['name']}**")
        lines.append("  Steps: " + " → ".join(f"${s}" for s in strat['steps']))
    return '\n'.join(lines)


def _strategy_panel_keyboard(sig_settings: dict) -> list:
    """Keyboard for the Strategy Mode panel."""
    enabled = sig_settings.get('strategy_mode', False)
    active_sid = sig_settings.get('strategy_id', 1)
    rows = []
    toggle_label = '🔴 Disable Strategy Mode' if enabled else '🟢 Enable Strategy Mode'
    rows.append([InlineKeyboardButton(toggle_label, callback_data='strat_toggle')])
    rows.append([InlineKeyboardButton('🔄 Reset Step Counter', callback_data='strat_reset_step')])
    rows.append([InlineKeyboardButton('— Select Strategy —', callback_data='noop')])
    for sid, strat in STRATEGIES.items():
        selected = '✅ ' if sid == active_sid else ''
        rows.append([InlineKeyboardButton(
            f"{selected}{strat['name']}",
            callback_data=f'strat_select:{sid}',
        )])
    rows.append(back_button('settings_main'))
    return rows


def _build_step_selector_keyboard(
    strategy_id: int,
    current_step: int,
) -> Optional[InlineKeyboardMarkup]:
    """Compact 2-row step selector keyboard embedded in trade/result messages."""
    strat = STRATEGIES.get(strategy_id)
    if not strat:
        return None
    steps = strat['steps']
    rows: list = []
    row: list = []
    for i, amt in enumerate(steps):
        star = '⭐' if i == current_step else ''
        row.append(InlineKeyboardButton(
            f"{star}{i + 1}·${amt}",
            callback_data=f"strat_step_set:{i}",
        ))
        if len(row) == 5:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([InlineKeyboardButton("🎯 Strategy Panel", callback_data="strategy_view")])
    return InlineKeyboardMarkup(rows)

# ─────────────────────────────────────────────────────────────────────────────

def _ch_display(ch: dict) -> str:
    """Human-friendly display string for a channel: nickname if set, else the ID."""
    nick = ch.get('nickname', '').strip()
    return nick if nick else str(ch.get('id', ''))


def _channels_summary(sig_settings: dict) -> str:
    """Short summary of channels for the Signal Monitor panel status line."""
    channels = sig_settings.get('channels', [])
    if not channels:
        return 'None configured'
    active = sum(1 for c in channels if c.get('active', True))
    names = ', '.join(_ch_display(c) for c in channels[:3])
    suffix = ', …' if len(channels) > 3 else ''
    return f"{active}/{len(channels)} active ({names}{suffix})"


def _channels_panel_text(channels: list) -> str:
    """Text body for the Manage Channels panel."""
    text = "📺 **Signal Channels**\n\n"
    if not channels:
        text += "No channels configured yet.\n\nAdd a channel below to start monitoring signals."
    else:
        for idx, ch in enumerate(channels, 1):
            ch_id = str(ch.get('id', ''))
            nick = ch.get('nickname', '').strip()
            active = ch.get('active', True)
            icon = '🟢' if active else '🔴'
            name_line = f"**{nick}** (`{ch_id}`)" if nick else f"`{ch_id}`"
            text += f"{idx}. {name_line} — {icon} {'**Active**' if active else 'Inactive'}\n"
        text += "\nTap a channel to toggle ON/OFF · ✏️ rename · 🗑 remove."
    return text


def _channels_panel_keyboard(channels: list) -> list:
    """Keyboard rows for the Manage Channels panel."""
    rows = []
    for idx, ch in enumerate(channels):
        active = ch.get('active', True)
        display = _ch_display(ch)
        if len(display) > 18:
            display = display[:15] + '…'
        rows.append([
            InlineKeyboardButton(
                f"{'🟢' if active else '🔴'} {display}",
                callback_data=f"sig_ch_toggle:{idx}",
            ),
            InlineKeyboardButton("✏️", callback_data=f"sig_ch_rename:{idx}"),
            InlineKeyboardButton("🗑", callback_data=f"sig_ch_remove:{idx}"),
        ])
    rows.append([InlineKeyboardButton("➕ Add Channel", callback_data="sig_channel_add")])
    rows.append(back_button("signal_status_view"))
    return rows

# --- Permission Decorators ---
def owner_only(func):
    @wraps(func)
    async def wrapper(client: Client, update: Message | CallbackQuery):
        user_id = update.from_user.id
        if user_id != OWNER_ID:
            if isinstance(update, Message):
                await update.reply_text("⛔️ Access Denied: Only the bot owner can use this command.")
            elif isinstance(update, CallbackQuery):
                await update.answer("⛔️ Access Denied: Owner only.", show_alert=True)
            return None # Indicate failure or stop processing
        return await func(client, update)
    return wrapper

def sudo_only(func):
    @wraps(func)
    async def wrapper(client: Client, update: Message | CallbackQuery):
        user_id = update.from_user.id
        if not await is_sudo_user(user_id):
            if isinstance(update, Message):
                await update.reply_text("⛔️ Access Denied: You need Sudo privileges for this.")
            elif isinstance(update, CallbackQuery):
                await update.answer("⛔️ Access Denied: Sudo privileges required.", show_alert=True)
            return None
        return await func(client, update)
    return wrapper

def premium_only(func):
    @wraps(func)
    async def wrapper(client: Client, update: Message | CallbackQuery):
        user_id = update.from_user.id
        if not await is_premium_user(user_id):
            if isinstance(update, Message):
                await update.reply_text("⛔️ Access Denied: This feature requires a Premium subscription or Sudo privileges.")
            elif isinstance(update, CallbackQuery):
                await update.answer("⛔️ Access Denied: Premium or Sudo required.", show_alert=True)
            return None
        return await func(client, update)
    return wrapper


# --- Restore/Keep the ASYNC helper function ---
async def handle_potential_pin_input(prompt: str) -> Optional[str]:
    """
    This ASYNC function is called by our patched input ONLY when
    the specific PIN prompt is detected. It handles the bot interaction.
    """
    target_prompt = "Insira o código PIN que acabamos de enviar para o seu e-mail:"
    logger.debug(f"handle_potential_pin_input received prompt: '{prompt}'")

    if target_prompt in prompt:
        logger.critical(f"--- !!! BUILTIN INPUT PATCH TRIGGERED FOR PIN !!! Prompt: '{prompt}'")
        global bot_instance, active_otp_requests

        user_id = None
        qx_client_instance = None
        for uid, data in active_otp_requests.items():
             # Assuming the current call belongs to the context we just added
             user_id = uid
             qx_client_instance = data.get('qx_client')
             logger.info(f"Found potential user_id {user_id} and client {id(qx_client_instance)} from active_otp_requests.")
             break

        if not bot_instance:
            logger.error("CRITICAL: Cannot ask for PIN via patched input - bot_instance is None!")
            return None
        if not user_id:
            logger.error(f"CRITICAL: Cannot ask for PIN via patched input - no user_id found in active_otp_requests. State: {active_otp_requests}")
            return None
        if not qx_client_instance:
             logger.error(f"CRITICAL: Cannot ask for PIN via patched input - no qx_client found for user {user_id}.")
             return None

        pin_code = None
        try:
            logger.info(f"Asking user {user_id} for PIN via bot.ask() [from patched input]. Timeout: 120s")
            pin_message = await bot_instance.ask(
                chat_id=user_id,
                text=f"❗️ **QUOTEX 2FA REQUIRED** ❗️\n\n"
                     f"To log in to `{qx_client_instance.email}`, Quotex needs the PIN code sent to your email.\n\n"
                     #f"**Prompt:**\n`{prompt}`\n\n"
                     f"➡️ Please reply to **this message** with the **PIN code only**.",
                timeout=600, # 2 minutes timeout
            )
            if pin_message and pin_message.text:
                pin_code = pin_message.text.strip()
                if not pin_code.isdigit(): # Optional check
                    logger.warning(f"User {user_id} entered non-digit PIN '{pin_code}'. Using it anyway.")
                logger.info(f"Received PIN '{pin_code}' from user {user_id} via patched input.")
                await pin_message.delete() # Optional: delete the message after reading
                return pin_code # Return the actual PIN
            else:
                logger.warning(f"User {user_id} did not provide a PIN response message [via patched input].")
                await bot_instance.send_message(user_id, "❓ Did not receive a PIN response. Login failed.")
                return "" # Return empty string maybe better than None for input()?
        except asyncio.TimeoutError:
            logger.error(f"Timeout waiting for PIN from user {user_id} [via patched input].")
            try: await bot_instance.send_message(user_id, "⏳ PIN request timed out (2 minutes). Login failed.")
            except Exception: pass
            return "" # Return empty string on timeout
        except Exception as e:
            logger.error(f"Error occurred in bot.ask() while getting PIN [via patched input] from {user_id}: {e}", exc_info=True)
            try: await bot_instance.send_message(user_id, f"❌ An error occurred while processing your PIN: {e}\nLogin failed.")
            except Exception: pass
            # Raise exception to clearly signal failure in wrapper
            raise ConnectionError("Failed to get PIN via Telegram interaction.") from e
    else:
        # IMPORTANT: If prompt not recognised, call original input
        logger.warning(f"Patched input called with UNEXPECTED prompt: '{prompt}'. Falling back to original input.")
        return original_builtin_input(prompt) # This will likely hang bot


# --- Restore/Keep the SYNC input_wrapper function ---
# Store original input safely AT MODULE LEVEL
original_builtin_input = builtins.input
patch_state = {'expecting_pin': False} # Manage patch activation state

def input_wrapper(prompt=""):
    """Synchronous wrapper that replaces input. Calls async handler if needed."""
    global patch_state # Access the global state flag
    target_prompt_substr = "Insira o código PIN"
    # Check if we are *expecting* the PIN and if the prompt matches
    if target_prompt_substr in prompt and patch_state.get('expecting_pin', False):
        logger.info(f"Input wrapper intercepting prompt: '{prompt}'")
        if not main_event_loop:
            logger.error("CRITICAL: Main event loop not available in input_wrapper!")
            # Decide how to fail: raise error or return empty? Raising is cleaner.
            raise RuntimeError("Cannot handle PIN input: Main event loop not set.")
        if not main_event_loop.is_running():
            logger.error("CRITICAL: Main event loop is not running in input_wrapper!")
            raise RuntimeError("Cannot handle PIN input: Main event loop not running.")

        # Prepare the coroutine to run
        coro = handle_potential_pin_input(prompt) # Pass the prompt

        # Schedule the coroutine on the main loop from this (likely worker) thread
        # This returns a concurrent.futures.Future, NOT an asyncio.Future
        future = asyncio.run_coroutine_threadsafe(coro, main_event_loop)
        logger.debug(f"Scheduled async PIN handler on loop {id(main_event_loop)}. Waiting for result...")

        try:
            # Block *this thread* (waiting for input) until the coroutine completes
            # Add a reasonable timeout (e.g., slightly longer than your bot.listen timeout)
            pin_result = future.result(timeout=130) # Wait up to 130 seconds
            logger.info(f"Async PIN handler returned: {type(pin_result)} '{pin_result}'")
            # Return the pin (string) or empty string if it failed/timed out internally
            return pin_result if pin_result is not None else ""
        except concurrent.futures.TimeoutError:
            logger.error("Timeout waiting for async PIN handler result in input_wrapper.")
            # Optional: Try to cancel the coroutine if it's still running
            # future.cancel() # May not work reliably depending on coro state
            # Propagate the timeout or return empty/raise custom error
            raise TimeoutError("Timed out waiting for PIN input via Telegram.") from None
        except Exception as e:
            # This catches exceptions raised *inside* handle_potential_pin_input OR
            # errors during scheduling/retrieval.
            logger.error(f"Exception occurred retrieving async PIN handler result in input_wrapper: {e}", exc_info=True)
            # Propagate the exception so get_quotex_client knows it failed clearly
            # Wrap it maybe?
            raise ConnectionError("Failed to get PIN via Telegram interaction.") from e
        finally:
             # Optional: Log when the wait finishes
             logger.debug("Exiting input_wrapper after waiting for future.")
    else:
         # If not expecting PIN or prompt mismatch, use original input
         logger.warning(f"Input wrapper calling original input for prompt: '{prompt}' (expecting_pin={patch_state.get('expecting_pin')})")
         return original_builtin_input(prompt)

active_quotex_clients: Dict[str, Quotex] = {}

# --- REPLACE the get_quotex_client function (using the AGGRESSIVE timing with CORRECT patch function) ---
async def get_quotex_client(user_id: int, account_doc_id: str, interaction_type: str = "info") -> Tuple[Optional[Quotex], str]:
    """
    Gets or creates a connected Quotex client instance for an account.
    Uses AGGRESSIVE patching on builtins.input + ASYNC handler for PIN prompts.
    """
    global active_quotex_clients, active_otp_requests, bot_instance, patch_state # Ensure patch_state is global

    # --- Cache check logic ---
    if account_doc_id in active_quotex_clients:
        cached = active_quotex_clients[account_doc_id]
        # Verify the cached connection is still alive before reusing it.
        # check_connect() is async — MUST be awaited or it returns a truthy coroutine.
        try:
            still_connected = await cached.check_connect()
        except Exception:
            still_connected = False
        if still_connected:
            # Re-apply the account mode from DB every time — the user may have
            # switched between PRACTICE and REAL since this client was cached.
            try:
                current_settings = await get_or_create_trade_settings(account_doc_id)
                required_mode = current_settings.get("account_mode", "PRACTICE")
                await cached.change_account(required_mode)
                logger.info(f"Reusing cached client for {account_doc_id} (mode: {required_mode})")
            except Exception as mode_err:
                logger.warning(f"Could not re-apply account mode for {account_doc_id}: {mode_err}")
            return cached, "Reused existing client (cache)."
        else:
            logger.warning(f"Cached client for {account_doc_id} is stale/disconnected. Reconnecting...")
            try:
                await cached.close()
            except Exception:
                pass
            del active_quotex_clients[account_doc_id]

    # --- Get account details ---
    logger.info(f"Fetching Quotex account details for Doc ID: {account_doc_id} (User: {user_id})")
    account_details = await get_quotex_account_details(account_doc_id)
    if not account_details: return None, " Quotex account details not found in DB."
    email = account_details["email"]
    password = account_details["password"]
    # temp_session_path = f"session_{user_id}_{account_doc_id}"
    # # Ensure the directory for session files exists
    # session_dir = Path(temp_session_path).parent
    # session_dir.mkdir(parents=True, exist_ok=True)

    # Per-account isolated session directory so multiple accounts don't share tokens
    session_path = f"sessions/{account_doc_id}"

    # --- Selenium pre-auth: ensure a valid __cf_clearance is in session.json ---
    # pyquotex cannot solve Cloudflare's managed challenge on its own.
    # ensure_session() checks whether the saved session is still fresh; if not it
    # runs a headless or visible Selenium login to obtain a new __cf_clearance cookie.
    if _quotex_auth:
        try:
            await _quotex_auth.ensure_session(email, password, session_path=session_path)
        except Exception as _auth_err:
            logger.warning(f"[Auth] Selenium pre-auth for {email} failed: {_auth_err}")
    else:
        logger.warning("[Auth] quotex_auth not available; skipping Selenium pre-auth.")

    qx_client: Optional[Quotex] = None
    connection_check = False
    connection_reason = "Initialization error"
    patcher = None
    is_patched = False

    try:
        # --- Apply AGGRESSIVE patch BEFORE creating instance ---
        logger.warning("Applying AGGRESSIVE builtins.input patch (using input_wrapper)...")
        # *** USE THE CORRECT WRAPPER ***
        patcher = patch('builtins.input', input_wrapper)
        patcher.start()
        is_patched = True
        logger.info("Aggressive builtins.input patch STARTED.")

        # Create instance UNDER the patch — use per-account session directory
        logger.info(f"Creating new Quotex client instance for {email} UNDER PATCH")
        qx_client = Quotex(
            email=email,
            password=password,
            user_agent=QUOTEX_USER_AGENT,
            root_path=session_path,
            user_data_dir="browser",
        )

        # pyquotex always loads ./session.json from CWD; override with our per-account session
        _per_acct_session_file = Path(f"{session_path}/session.json")
        if _per_acct_session_file.exists():
            try:
                with open(_per_acct_session_file) as _sf:
                    _saved_session = json.load(_sf)
                if _saved_session.get("token") or _saved_session.get("cookies"):
                    qx_client.session_data = _saved_session
                    logger.info(f"[Auth] Loaded per-account session for {email} (token={'ok' if _saved_session.get('token') else 'MISSING'}, cookies={'ok' if _saved_session.get('cookies') else 'MISSING'})")
            except Exception as _se:
                logger.warning(f"[Auth] Could not load per-account session from {_per_acct_session_file}: {_se}")

        # If env-level override is provided, apply it (overrides the file)
        if QUOTEX_SSID or QUOTEX_COOKIES:
            qx_client.set_session(
                user_agent=QUOTEX_USER_AGENT,
                cookies=QUOTEX_COOKIES or None,
                ssid=QUOTEX_SSID or None,
            )

        # Add context *before* connect call
        logger.info(f"Adding user {user_id} to active_otp_requests BEFORE connect (under patch).")
        # Allow startup pre-connect to proceed even before the Telegram bot is live.
        if not bot_instance and interaction_type != "startup_preconnect":
            raise ConnectionAbortedError("Bot instance not available for OTP context.")
        active_otp_requests[user_id] = {'qx_client': qx_client, 'doc_id': account_doc_id}

        # Activate patch state
        patch_state['expecting_pin'] = True
        logger.info("Patch state set to expect PIN.")

        # Call connect UNDER the patch
        logger.info(f"Attempting connection for {email} (aggressive patch active)...")
        # Run the connection process in a separate thread to avoid blocking the main event loop

        def connect_in_thread():
            """Wrapper to run the connect method in a thread."""
            return asyncio.run(qx_client.connect())

        # Use an explicit executor (not a context-manager `with`) so that
        # asyncio.CancelledError / KeyboardInterrupt during bot shutdown does
        # NOT block on shutdown(wait=True) while the thread is still running.
        _executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = _executor.submit(connect_in_thread)
        try:
            connection_check, connection_reason = await asyncio.wait_for(
                asyncio.wrap_future(future),
                timeout=180.0
            )
        except asyncio.TimeoutError:
            logger.error("Connection attempt timed out.")
            connection_check, connection_reason = False, "Timeout during connection"
        except (asyncio.CancelledError, KeyboardInterrupt):
            _executor.shutdown(wait=False, cancel_futures=True)
            raise
        except Exception as e:
            logger.error(f"Error during connection in thread: {e}", exc_info=True)
            connection_check, connection_reason = False, str(e)
        finally:
            _executor.shutdown(wait=False, cancel_futures=True)
        # Deactivate patch state immediately after
        patch_state['expecting_pin'] = False
        logger.info("Patch state set to NOT expect PIN.")
        logger.info(f"Connect() call finished (aggressive patch active).")
        logger.info(f"Connection attempt finished. Result Check: {connection_check}, Reason: '{connection_reason}'")

        # --- Handle connection results ---
        if connection_check:
            # ... (Success logic: log, switch mode, add to cache) ...
            logger.info(f"Quotex connection successful for {email}.")
            settings = await get_or_create_trade_settings(account_doc_id)
            account_mode = settings.get("account_mode", "PRACTICE")
            try:
                await qx_client.change_account(account_mode)
                logger.info(f"Switched Quotex account {email} to {account_mode} mode.")
            except Exception as e_mode:
                logger.error(f"Failed to switch account {email} to {account_mode}: {e_mode}", exc_info=True)
                # Socket closed immediately after connect — the client is unusable; discard it
                try:
                    await qx_client.close()
                except Exception:
                    pass
                return None, f"Connection Failed: socket closed before account mode could be set ({e_mode})"

            active_quotex_clients[account_doc_id] = qx_client
            return qx_client, f"Connected successfully in {account_mode} mode."
        else:
            # ... (Failure logic: check reasons, handle Invalid credentials, Token rejected, PIN/Auth errors) ...
            logger.error(f"Quotex connection explicitly failed for {email}. Reason: {connection_reason}")
            reason_str = str(connection_reason) if connection_reason else "Unknown reason"
            # (Include all failure checks from previous versions)
            if "Invalid credentials" in reason_str and interaction_type == "login_attempt":
                await delete_quotex_account(account_doc_id)
                return None, "Connection Failed: Invalid Credentials. Removed entry."
            elif "check your email" in reason_str.lower() or "verifique seu e-mail" in reason_str.lower() or "pin" in reason_str.lower():
                 return None, f"Connection Failed: Authentication error ({reason_str}). Check PIN/email or account status."
            elif "Token rejected" in reason_str:
                # ...(delete session file logic)...
                return None, "Connection Failed: Token rejected. Session deleted."
            elif (
                "403" in reason_str
                or "forbidden" in reason_str.lower()
                or "cf-mitigated" in reason_str.lower()
                or "just a moment" in reason_str.lower()
                or "cloudflare" in reason_str.lower()
                or "websocket connection closed" in reason_str.lower()
            ):
                # Delete the stale session so the next restart forces a fresh Selenium login
                _stale_sess = Path(f"{session_path}/session.json")
                if _stale_sess.exists():
                    try:
                        _stale_sess.unlink()
                        logger.warning(
                            f"[Auth] Deleted stale session.json for {email} "
                            "(Cloudflare 403 on WebSocket connect)."
                        )
                    except Exception as _del_err:
                        logger.warning(f"[Auth] Could not delete stale session: {_del_err}")
                return None, (
                    "Connection blocked by Cloudflare — stale session deleted. "
                    "Restart the bot; a browser window will open for you to log in."
                )
            else:
                 return None, f"Connection Failed: {reason_str}"

    except asyncio.TimeoutError:
         logger.error(f"Connection attempt for {email} timed out overall (aggressive patch).")
         patch_state['expecting_pin'] = False
         return None, "Connection Failed: Timed out during connection/authentication."
    except ConnectionAbortedError as cae: # Bot context missing error
         logger.error(f"Connection aborted for {email}: {cae}")
         patch_state['expecting_pin'] = False
         return None, f"Connection Failed: {cae}"
    except ConnectionError as ce: # Error explicitly raised by PIN handling failure
         logger.error(f"ConnectionError during PIN handling for {email}: {ce}")
         patch_state['expecting_pin'] = False
         # Provide the clearer error from the PIN handler
         return None, f"Connection Failed: Error during PIN retrieval ({ce})"
    except Exception as e:
        logger.error(f"Unexpected error during Quotex connect/setup for {email} (aggressive patch): {e}", exc_info=True)
        patch_state['expecting_pin'] = False
        if qx_client:
             try: await qx_client.close()
             except: pass
        return None, f"Connection Failed: An unexpected error occurred ({type(e).__name__}). Check logs."
    finally:
         # --- ALWAYS CLEANUP ---
         patch_state['expecting_pin'] = False # Reset patch state
         logger.debug(f"Running FINALLY block for get_quotex_client (aggressive patch w/ handler)")
         # Stop the patch
         if is_patched and patcher:
             try:
                 patcher.stop()
                 logger.info("Aggressive builtins.input patch STOPPED.")
             except Exception as stop_err:
                 logger.error(f"Error stopping aggressive patch: {stop_err}")
         # Cleanup OTP context dict
         if user_id in active_otp_requests:
             if active_otp_requests[user_id].get('doc_id') == account_doc_id:
                 logger.info(f"Removing user {user_id} from active_otp_requests in finally.")
                 del active_otp_requests[user_id]
             else:
                 logger.warning(f"Context mismatch during finally cleanup for {user_id}/{account_doc_id}.")
# ----------------------------------------------------

async def disconnect_quotex_client(account_doc_id: str):
    """Disconnects and removes a Quotex client instance."""
    global active_quotex_clients
    if account_doc_id in active_quotex_clients:
        client = active_quotex_clients[account_doc_id]
        logger.info(f"Disconnecting Quotex client for {account_doc_id}...")
        try:
            await client.close() # Assuming close is async
        except Exception as e:
            logger.warning(f"Error closing Quotex client for {account_doc_id}: {e}")
        del active_quotex_clients[account_doc_id]
        logger.info(f"Removed Quotex client instance for {account_doc_id}.")


# --- Bot UI Buttons ---
async def main_menu_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Generates the main menu keyboard."""
    keyboard = [
        [InlineKeyboardButton("➕ Add Trading Account", callback_data="quotex_add")],
        [InlineKeyboardButton("👤 My Trading Accounts", callback_data="quotex_list")],
    ]
    # Dynamic buttons based on role
    # Add settings etc. later
    keyboard.append([InlineKeyboardButton("⚙️ Settings", callback_data="settings_main")])
    keyboard.append([InlineKeyboardButton("📊 Trading Dashboard", callback_data="trade_dashboard")])
    keyboard.append([InlineKeyboardButton("📓 Trading Journal", callback_data="journal_today")])
    # Check role ASYNCHRONOUSLY
    is_user_sudo = await is_sudo_user(user_id) # Correct use of await
    if is_user_sudo:
        keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data="admin_panel")])
    keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
    return InlineKeyboardMarkup(keyboard)

def back_button(callback_data="main_menu"):
    return [InlineKeyboardButton("⬅️ Back", callback_data=callback_data)]

def account_management_keyboard(account_doc_id: str, settings: Dict) -> InlineKeyboardMarkup:
    """Keyboard for managing a specific Quotex account."""
    is_active = settings.get('service_status', False)
    status_label = "🟢 Active" if is_active else "🔴 Inactive"
    keyboard = [
        [
            InlineKeyboardButton("📊 Get Profile", callback_data=f"qx_profile:{account_doc_id}"),
            InlineKeyboardButton("💰 Get Balance", callback_data=f"qx_balance:{account_doc_id}"),
        ],
        [
            InlineKeyboardButton(f"Status: {status_label}", callback_data=f"toggle_status:{account_doc_id}"),
        ],
        [
            InlineKeyboardButton(f"Account Type: {settings.get('account_mode', 'N/A')}", callback_data=f"set_amode:{account_doc_id}"),
        ],
        [InlineKeyboardButton("🗑 Delete Account", callback_data=f"qx_delete_confirm:{account_doc_id}")],
        back_button("quotex_list") # Back to account list
    ]
    return InlineKeyboardMarkup(keyboard)

def admin_panel_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast"),
            InlineKeyboardButton("👥 List Users", callback_data="admin_list_users")
        ],
        [
            InlineKeyboardButton("⭐ Manage Sudo", callback_data="admin_manage_sudo"),
            InlineKeyboardButton("💎 Manage Premium", callback_data="admin_manage_premium")
        ],
        [InlineKeyboardButton("🏦 Account Management", callback_data="admin_acct_mgmt")],
        back_button("main_menu")
    ]
    return InlineKeyboardMarkup(keyboard)

def admin_acct_mgmt_keyboard() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton("📋 List All Accounts", callback_data="admin_accts_list"),
            InlineKeyboardButton("🔍 Search Accounts", callback_data="admin_acct_search"),
        ],
        back_button("admin_panel")
    ]
    return InlineKeyboardMarkup(keyboard)

def admin_acct_view_keyboard(account_doc_id: str, is_active: bool, account_mode: str) -> InlineKeyboardMarkup:
    status_label = "🟢 Active" if is_active else "🔴 Inactive"
    keyboard = [
        [InlineKeyboardButton(f"Status: {status_label} (tap to toggle)", callback_data=f"admin_acct_toggle_status:{account_doc_id}")],
        [InlineKeyboardButton(f"Account Type: {account_mode} (tap to toggle)", callback_data=f"admin_acct_toggle_type:{account_doc_id}")],
        [InlineKeyboardButton("🗑 Delete This Account", callback_data=f"admin_acct_del_confirm:{account_doc_id}")],
        back_button("admin_accts_list")
    ]
    return InlineKeyboardMarkup(keyboard)

def manage_role_keyboard(role_name: str) -> InlineKeyboardMarkup: # role_name = "Sudo" or "Premium"
    role_prefix = role_name.lower()
    keyboard = [
        [
            InlineKeyboardButton(f"➕ Add {role_name}", callback_data=f"admin_add_{role_prefix}"),
            InlineKeyboardButton(f"➖ Remove {role_name}", callback_data=f"admin_remove_{role_prefix}")
        ],
        [
            InlineKeyboardButton(f"📄 List {role_name} Users", callback_data=f"admin_list_{role_prefix}")
        ],
        back_button("admin_panel")
    ]
    return InlineKeyboardMarkup(keyboard)

# --- Command Handlers ---

@Client.on_message(
    (filters.command(["start", "hello", "menu"]) | filters.regex(r'^(hi|/)$', re.IGNORECASE))
    & filters.private
)
async def start_command(client: Client, message: Message):
    global bot_instance # Store the client instance
    if not bot_instance: bot_instance = client

    user_id = message.from_user.id
    await add_user_if_not_exists(user_id)
    logger.info(f"User {user_id} ({message.from_user.first_name}) started the bot.")

    welcome_text = (
        f"👋 Welcome, {message.from_user.mention}!\n\n"
        f"**GraceFXCTrader** automates your trades based on high-quality, curated trading signals — "
        f"so you never miss a market opportunity.\n\n"
        f"📊 **New to Quotex?** We recommend registering through our official partner link to get started "
        f"with the best available conditions:\n"
        f"🔗 [Create your Quotex account here](https://broker-qx.pro/sign-up/?lid=2024742)\n\n"
        f"⚠️ **Risk Disclaimer:** Trading financial instruments involves substantial risk of loss and "
        f"may not be suitable for all investors. Past performance is not indicative of future results. "
        f"Only trade with capital you can afford to lose.\n\n"
        f"Use the menu below to get started."
    )

    await message.reply_text(
        welcome_text,
        reply_markup=await main_menu_keyboard(user_id),
        quote=True
    )

@Client.on_message(filters.command("help") & filters.private)
async def help_command(client: Client, message: Message):
    # Add more detailed help information here
    help_text = """
    **ℹ️ GraceFXCTrader — Help & Information**

    **GraceFXCTrader** is a signal-driven automated trading bot for Binary Trading. When a verified trading signal arrives, the bot instantly places the trade on all your linked active accounts — no manual intervention required.

    **What this bot does:**
    - Receives high-quality trading signals from a monitored channel.
    - Automatically executes trades on your linked Quotex accounts.
    - Maintains a **Trading Journal** — daily trade logs with opening & closing account balances, per-trade results, and P&L summaries.

    **Key Menu Options:**
    - **➕ Add Trading Account:** Securely link a Quotex account using your credentials (2FA-verified).
    - **👤 My Trading Accounts:** View, manage, and configure your linked accounts (account type, active/inactive status, deletion).
    - **📊 Trading Dashboard:** Overview of all linked accounts and their current status.
    - **📓 Trading Journal:** Daily trade history with balance snapshots and performance summaries.
    - **⚙️ Settings:** Configure signal mode and other bot preferences.

    **🏦 Our Recommended Broker**
    We partner exclusively with **Quotex** — a fast, reliable, and user-friendly binary options platform. If you haven't opened an account yet, we strongly encourage you to register through our referral link. It costs you nothing extra and directly supports the continued development of this bot:

    🔗 [Sign up on Quotex — Our Partner Link](https://broker-qx.pro/sign-up/?lid=2024742)

    **Important Notes:**
    - ⚠️ Trading involves risk. Never risk funds you cannot afford to lose.
    - This bot uses the `pyquotex` library to interface with Quotex. API changes may occasionally affect functionality.
    - Your credentials are stored in the bot's database. Use with caution and only on accounts you control.

    For assistance, contact the bot owner.
    """
    await message.reply_text(
        help_text,
        reply_markup=InlineKeyboardMarkup([back_button("main_menu")]),
        quote=True
    )

@Client.on_message(filters.command("broadcast") & filters.private)
@owner_only # Or use @sudo_only if Sudo can also broadcast
async def broadcast_command_handler(client: Client, message: Message):
    global user_states
    user_id = message.from_user.id
    user_states[user_id] = "waiting_broadcast_message"
    await message.reply_text(
        "Okay, send me the message you want to broadcast.\n"
        "You can use text, photos, videos, documents, formatting, etc.\n"
        "Send /cancel to abort.",
        reply_markup=ForceReply(selective=True),
        quote=True
    )

# --- Callback Query Handler (Main Router) ---
@Client.on_callback_query()
async def callback_query_handler(client: Client, callback_query: CallbackQuery):
    global bot_instance # Store the client instance
    if not bot_instance: bot_instance = client

    user_id = callback_query.from_user.id
    data = callback_query.data
    message = callback_query.message # The message where the button was clicked

    # --- Acknowledge Callback ---
    try:
        await callback_query.answer() # Acknowledge the button press
    except Exception as e:
        logger.warning(f"Failed to answer callback query: {e}")

    # --- Main Menu Navigation ---
    if data == "main_menu":
        await message.edit_text(
            f"👋 Welcome back, {callback_query.from_user.mention}!\n\nChoose an option:",
            reply_markup=await main_menu_keyboard(user_id)
        )
    elif data == "help":
         await help_command(client, message) # Reuse help command logic on the message object
         # We need to edit the original message, not send a new one if called from button
         await message.edit_reply_markup(reply_markup=InlineKeyboardMarkup([back_button("main_menu")])) # Keep help text, add back btn


    # --- Quotex Account Management ---
    elif data == "quotex_add":
        await callback_query.message.reply_text(
            "Let's add a new Quotex account.\n"
            "Please reply with the **Email Address** for the account.\n"
            "Send /cancel to abort.",
             reply_markup=ForceReply(selective=True) # Ask for reply
        )
        user_states[user_id] = "waiting_qx_email"

    elif data == "quotex_list":
        accounts = await get_user_quotex_accounts(user_id)
        if not accounts:
            await message.edit_text(
                "You haven't added any Quotex accounts yet.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("➕ Add Account Now", callback_data="quotex_add")],
                    back_button("main_menu")
                ])
            )
        else:
            keyboard = []
            for acc in accounts:
                 # Ensure '_id' is retrieved and is ObjectId, then convert to string
                acc_id_str = str(acc['_id'])
                keyboard.append([InlineKeyboardButton(f"👤 {acc['email']}", callback_data=f"qx_manage:{acc_id_str}")])
            keyboard.append(back_button("main_menu"))
            await message.edit_text(
                "Select a Quotex account to manage:",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )

    elif data.startswith("qx_manage:"):
        account_doc_id = data.split(":")[1]
        account_details = await get_quotex_account_details(account_doc_id)
        if not account_details or account_details["user_id"] != user_id:
            await message.edit_text("Error: Account not found or access denied.", reply_markup=InlineKeyboardMarkup([back_button("quotex_list")]))
            return

        # Fetch current settings for this account to display in buttons
        settings = await get_or_create_trade_settings(account_doc_id)

        await message.edit_text(
            f"Managing account: **{account_details['email']}**\n"
            f"Select an action:",
            reply_markup=account_management_keyboard(account_doc_id, settings)
        )

    elif data.startswith("qx_profile:") or data.startswith("qx_balance:"):
        action = "profile" if data.startswith("qx_profile:") else "balance"
        account_doc_id = data.split(":")[1]

        account_details = await get_quotex_account_details(account_doc_id)
        if not account_details or account_details["user_id"] != user_id:
             await message.edit_text("Error: Account not found or access denied.", reply_markup=InlineKeyboardMarkup([back_button(f"qx_manage:{account_doc_id}")]))
             return

        # Attempt to connect or get existing client
        await callback_query.edit_message_text("🔄 Connecting to Quotex and fetching data...")
        qx_client, status_msg = await get_quotex_client(user_id, account_doc_id, interaction_type=action)

        text = f"Managing account: **{account_details['email']}**\nStatus: {status_msg}\n\n"
        settings = await get_or_create_trade_settings(account_doc_id) # Needed for keyboard refresh

        if qx_client:
            try:
                if action == "profile":
                    try:
                        profile = await qx_client.get_profile()
                    except TypeError as _te:
                        # Stale session — evict and reconnect once
                        await disconnect_quotex_client(account_doc_id)
                        qx_client, _status = await get_quotex_client(user_id, account_doc_id, "profile_retry")
                        try:
                            profile = await qx_client.get_profile() if qx_client else None
                        except Exception:
                            profile = None
                    if profile:
                        pid   = getattr(profile, 'profile_id',   'N/A')
                        demo  = getattr(profile, 'demo_balance',  'N/A')
                        real  = getattr(profile, 'live_balance',  'N/A')
                        nick  = getattr(profile, 'nick_name',     'N/A')
                        avatar= getattr(profile, 'avatar',        'N/A')
                        country=getattr(profile,'country_name',  'N/A')
                        try:
                            real = f"{float(real):.2f}"
                        except (TypeError, ValueError):
                            pass
                        text += f"**🆔 ID: `{pid}`**\n"
                        text += f"**💰 Current Balance:**\n\n"
                        text += f" - 🪙 Demo: `{demo}`\n"
                        text += f" - 💵 Real: `{real}`\n"
                        text += f"**👤 User Name: {nick}**\n"
                        text += f"**🖼️ Avatar: {avatar}**\n"
                        text += f"**🌍 Country: {country}**\n"
                    else:
                        text += "❌ Failed to retrieve profile details."
                elif action == "balance":
                    async def _fetch_profile(client):
                        """Fetch profile, raising on stale-session NoneType errors."""
                        try:
                            return await client.get_profile()
                        except TypeError as _te:
                            raise ConnectionError(f"Stale session: {_te}") from _te

                    try:
                        profile = await _fetch_profile(qx_client)
                    except ConnectionError:
                        # Session went stale — evict cache and reconnect once
                        await disconnect_quotex_client(account_doc_id)
                        qx_client, status_msg = await get_quotex_client(user_id, account_doc_id, "balance_retry")
                        if qx_client:
                            try:
                                profile = await _fetch_profile(qx_client)
                            except Exception as _retry_err:
                                profile = None
                                text += f"❌ Reconnected but still failed to get balance: {_retry_err}"
                        else:
                            profile = None
                            text += f"❌ Session expired and reconnect failed: {status_msg}"

                    if profile:
                        demo_bal = getattr(profile, 'demo_balance', 'N/A')
                        real_bal = getattr(profile, 'live_balance', 'N/A')
                        text += f"**💰 Current Balance:**\n\n"
                        text += f" - Demo: `{demo_bal}`\n"
                        text += f" - Real: `{real_bal}`"
                    elif '❌' not in text:
                        text += "❌ Failed to retrieve balance information (could not get profile)."


                # Option: Disconnect immediately after action? Or keep client alive?
                # await disconnect_quotex_client(account_doc_id) # Disconnect now
            except Exception as e:
                text += f"❌ Error getting {action} data: {e}"
                logger.error(f"Error during Quotex {action} for {account_doc_id}: {e}", exc_info=True)
                 # Consider disconnecting on error?
                # await disconnect_quotex_client(account_doc_id)
        else:
             text += "\nCould not perform action." # Status message already added

        # Edit the message with results and the management keyboard
        await message.edit_text(text, reply_markup=account_management_keyboard(account_doc_id, settings))


    # --- Asset Management ---
    elif data.startswith("asset_manage:"):
         # TODO: Implement Asset Management UI (Add, Remove, List)
         account_doc_id = data.split(":")[1]
         settings = await get_or_create_trade_settings(account_doc_id)
         assets = settings.get("assets", [])
         text = f"**💱 Asset Management for Account**\n"
         if not assets:
             text += "\nNo assets configured yet."
         else:
             text += "\nCurrent Assets:\n"
             for i, asset in enumerate(assets):
                 text += f"{i+1}. `{asset['name']}` (Amt: {asset['amount']}, Dur: {asset['duration']}s)\n"

         keyboard = [
              [InlineKeyboardButton("➕ Add Asset", callback_data=f"asset_add:{account_doc_id}")],
               # Add buttons to remove specific assets if list is not empty
         ]
         if assets:
             keyboard.append([InlineKeyboardButton("➖ Remove Asset", callback_data=f"asset_remove_select:{account_doc_id}")]) # Leads to selection

         keyboard.append(back_button(f"qx_manage:{account_doc_id}"))
         await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard))


    elif data.startswith("asset_add:"):
        account_doc_id = data.split(":")[1]
        user_states[user_id] = f"waiting_asset_add:{account_doc_id}"
        await message.reply_text(
            "Enter the asset details to add.\n"
            "Format: `ASSET_NAME,Amount,Duration`\n"
            f"Example: `EURUSD_otc,{DEFAULT_TRADE_AMOUNT},{DEFAULT_TRADE_DURATION}`\n"
            "(Amount and Duration are optional, defaults will be used if omitted)\n"
            "Send /cancel to abort.",
            reply_markup=ForceReply(selective=True),
            parse_mode=enums.ParseMode.DEFAULT
        )

    elif data.startswith("asset_remove_select:"):
         account_doc_id = data.split(":")[1]
         settings = await get_or_create_trade_settings(account_doc_id)
         assets = settings.get("assets", [])
         if not assets:
              await message.edit_text("No assets to remove.", reply_markup=InlineKeyboardMarkup([back_button(f"asset_manage:{account_doc_id}")]))
              return

         keyboard = []
         for i, asset in enumerate(assets):
             # Store index in callback data for removal
             keyboard.append([InlineKeyboardButton(f"❌ Remove {asset['name']}", callback_data=f"asset_remove_confirm:{account_doc_id}:{i}")])

         keyboard.append(back_button(f"asset_manage:{account_doc_id}"))
         await message.edit_text("Select the asset to remove:", reply_markup=InlineKeyboardMarkup(keyboard))


    elif data.startswith("asset_remove_confirm:"):
         parts = data.split(":")
         account_doc_id = parts[1]
         asset_index_to_remove = int(parts[2])

         settings = await get_or_create_trade_settings(account_doc_id)
         assets = settings.get("assets", [])

         if 0 <= asset_index_to_remove < len(assets):
             removed_asset = assets.pop(asset_index_to_remove)
             await update_trade_setting(account_doc_id, {"assets": assets})
             await callback_query.answer(f"Removed asset: {removed_asset['name']}", show_alert=True)
              # Go back to asset manage screen
             await callback_query_handler(client, CallbackQuery(
                    id=callback_query.id, from_user=callback_query.from_user,
                    message=message, chat_instance="dummy",
                    data=f"asset_manage:{account_doc_id}", game_short_name=None, inline_message_id=None
                )) # Simulate callback
         else:
              await callback_query.answer("Error: Invalid asset index for removal.", show_alert=True)


    # --- Settings Management ---
    elif data.startswith("set_tmode:"): # Trade Mode (TIMER/TIME)
         account_doc_id = data.split(":")[1]
         settings = await get_or_create_trade_settings(account_doc_id)
         current_mode = settings.get('trade_mode', DEFAULT_TRADE_MODE)
         keyboard = [
             [
                InlineKeyboardButton(f"{'✅ ' if current_mode == 'TIMER' else ''}TIMER", callback_data=f"tmode_set:{account_doc_id}:TIMER"),
                InlineKeyboardButton(f"{'✅ ' if current_mode == 'TIME' else ''}TIME", callback_data=f"tmode_set:{account_doc_id}:TIME"),
             ],
             back_button(f"qx_manage:{account_doc_id}")
         ]
         await message.edit_text(f"Select Trade Mode for **{settings.get('email','N/A')}**:", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("tmode_set:"):
         parts = data.split(":")
         account_doc_id, new_mode = parts[1], parts[2]
         if new_mode in ["TIMER", "TIME"]:
             await update_trade_setting(account_doc_id, {"trade_mode": new_mode})
             await callback_query.answer(f"Trade mode set to {new_mode}")
             # Refresh the management screen
             account_details = await get_quotex_account_details(account_doc_id) # Need email again maybe
             settings = await get_or_create_trade_settings(account_doc_id) # Reload updated settings
             await message.edit_text(
                f"Managing account: **{account_details['email']}**\nTrade mode updated.",
                reply_markup=account_management_keyboard(account_doc_id, settings)
             )
         else:
              await callback_query.answer("Invalid trade mode selected.", show_alert=True)


    elif data.startswith("set_csize:"): # Candle Size
        account_doc_id = data.split(":")[1]
        user_states[user_id] = f"waiting_candle_size:{account_doc_id}"
        settings = await get_or_create_trade_settings(account_doc_id)
        await message.reply_text(
            f"Enter the new **Candle Size** in seconds (e.g., 60, 120, 300).\n"
            f"Current: `{settings.get('candle_size', DEFAULT_CANDLE_SIZE)}`s\n"
            "Send /cancel to abort.",
            reply_markup=ForceReply(selective=True),
            parse_mode=enums.ParseMode.DEFAULT
        )

    elif data.startswith("set_amode:"): # Account Mode (PRACTICE/REAL)
        account_doc_id = data.split(":")[1]
        settings = await get_or_create_trade_settings(account_doc_id)
        current_mode = settings.get('account_mode', "PRACTICE")
        keyboard = [
             [
                InlineKeyboardButton(f"{'✅ ' if current_mode == 'PRACTICE' else ''}PRACTICE", callback_data=f"amode_set:{account_doc_id}:PRACTICE"),
                InlineKeyboardButton(f"{'✅ ' if current_mode == 'REAL' else ''}REAL", callback_data=f"amode_set:{account_doc_id}:REAL"),
             ],
             back_button(f"qx_manage:{account_doc_id}")
         ]
        await message.edit_text(f"Select Account Type for **{settings.get('email','N/A')}**:", reply_markup=InlineKeyboardMarkup(keyboard))

    elif data.startswith("amode_set:"):
         parts = data.split(":")
         account_doc_id, new_mode = parts[1], parts[2]
         if new_mode in ["PRACTICE", "REAL"]:
             await update_trade_setting(account_doc_id, {"account_mode": new_mode})
             # If a client is active, try changing its mode immediately? Risky maybe.
             if account_doc_id in active_quotex_clients:
                 try:
                     await active_quotex_clients[account_doc_id].change_account(new_mode)
                     await callback_query.answer(f"Account mode set to {new_mode} and active client updated.")
                 except Exception as e_mode:
                     await callback_query.answer(f"Account mode set to {new_mode}. Error updating active client: {e_mode}")
             else:
                 await callback_query.answer(f"Account mode set to {new_mode}.")

             # Refresh the management screen
             account_details = await get_quotex_account_details(account_doc_id)
             settings = await get_or_create_trade_settings(account_doc_id) # Reload
             await message.edit_text(
                f"Managing account: **{account_details['email']}**\nAccount mode updated.",
                reply_markup=account_management_keyboard(account_doc_id, settings)
             )
         else:
              await callback_query.answer("Invalid account mode selected.", show_alert=True)


    # --- Simple Status Toggle (Active/Inactive) ---
    elif data.startswith("toggle_status:"):
        account_doc_id = data.split(":")[1]
        # Verify ownership
        account_details = await get_quotex_account_details(account_doc_id)
        if not account_details or account_details["user_id"] != user_id:
            await callback_query.answer("Account not found or access denied.", show_alert=True)
            return
        settings = await get_or_create_trade_settings(account_doc_id)
        new_status = not settings.get('service_status', False)
        await update_trade_setting(account_doc_id, {"service_status": new_status})
        status_label = "Active" if new_status else "Inactive"
        await callback_query.answer(f"Status set to {status_label}")
        refreshed_settings = await get_or_create_trade_settings(account_doc_id)
        await message.edit_text(
            f"Managing account: **{account_details['email']}**\nStatus updated to **{status_label}**.",
            reply_markup=account_management_keyboard(account_doc_id, refreshed_settings)
        )


    # --- Delete Quotex Account ---
    elif data.startswith("qx_delete_confirm:"):
        account_doc_id = data.split(":")[1]
        account_details = await get_quotex_account_details(account_doc_id)
        if not account_details or account_details["user_id"] != user_id:
             await message.edit_text("Error: Account not found.", reply_markup=InlineKeyboardMarkup([back_button("quotex_list")]))
             return

        keyboard = [
            [InlineKeyboardButton("❗️ YES, DELETE IT", callback_data=f"qx_delete_do:{account_doc_id}")],
            back_button(f"qx_manage:{account_doc_id}") # Back to managing this account
        ]
        await message.edit_text(
             f"🚨 **Are you sure you want to delete the account {account_details['email']}?**\n\n"
             "This will remove the credentials and all associated trading settings from the bot's database.\n"
             "**This action cannot be undone!**",
             reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("qx_delete_do:"):
        account_doc_id = data.split(":")[1]
        # Double check ownership before deleting
        account_details = await get_quotex_account_details(account_doc_id)
        if not account_details or account_details["user_id"] != user_id:
             await callback_query.answer("Error: Account not found or permission denied.", show_alert=True)
             return

        deleted = await delete_quotex_account(account_doc_id)
        if deleted:
             await callback_query.answer(f"Account {account_details['email']} deleted successfully.", show_alert=True)
             # Disconnect if active
             await disconnect_quotex_client(account_doc_id)
              # Go back to the account list screen
             await callback_query_handler(client, CallbackQuery(
                 id=callback_query.id, from_user=callback_query.from_user,
                 message=message, chat_instance="dummy",
                 data="quotex_list", game_short_name=None, inline_message_id=None
             ))
        else:
             await callback_query.answer("Error: Failed to delete the account.", show_alert=True)


    # --- Admin Panel ---
    elif data == "admin_panel":
        if not await is_sudo_user(user_id):
            await callback_query.answer("⛔️ Access Denied", show_alert=True)
            return
        await message.edit_text(
            "👑 **Admin Panel**\nChoose an administrative action:",
            reply_markup=admin_panel_keyboard()
        )
    
        # --- Inside callback_query_handler function ---

    # (...) other handlers like main_menu, help, quotex_list etc.

    elif data == "trade_dashboard":
        # Optional: Check if this feature is premium?
        # if not await is_premium_user(user_id):
        #    await callback_query.answer("Trading Dashboard requires Premium.", show_alert=True)
        #    return

        await callback_query.message.edit_text("⏳ Loading Trading Dashboard...", reply_markup=InlineKeyboardMarkup([back_button("main_menu")]))

        accounts = await get_user_quotex_accounts(user_id)
        if not accounts:
            await callback_query.message.edit_text(
                "📊 **Trading Dashboard**\n\nYou haven't added any Quotex accounts yet.",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("➕ Add Account Now", callback_data="quotex_add")],
                    back_button("main_menu")
                ])
            )
            return

        dashboard_text = "📊 **Trading Dashboard Overview**\n\n"
        keyboard_rows = []

        for acc in accounts:
            account_doc_id = str(acc['_id'])
            email = acc['email']
            settings = await get_or_create_trade_settings(account_doc_id)

            acc_mode = settings.get('account_mode', 'N/A')

            active_status = "Active" if settings.get('service_status', False) else "Inactive"
            dashboard_text += (
                f"👤 **Account:** `{email}`\n"
                f"   ┣ Status: **{active_status}**\n"
                f"   ┗ Account Type: `{acc_mode}`\n\n"
            )
            # Add a button to manage this specific account
            keyboard_rows.append(
                [InlineKeyboardButton(f"⚙️ Manage {email}", callback_data=f"qx_manage:{account_doc_id}")]
            )


        keyboard_rows.append([InlineKeyboardButton("📓 Today's Journal", callback_data="journal_today")])
        keyboard_rows.append(back_button("main_menu"))
        await callback_query.message.edit_text(
            dashboard_text,
            reply_markup=InlineKeyboardMarkup(keyboard_rows),
            parse_mode=enums.ParseMode.DEFAULT
        )

    # --- Broadcast ---
    elif data == "admin_broadcast":
        if not await is_sudo_user(user_id): # Re-check just in case
             await callback_query.answer("⛔️ Access Denied", show_alert=True)
             return
        user_states[user_id] = "waiting_broadcast_message"
        await message.edit_text( # Edit the message instead of sending new
            "Okay, send/forward the message you want to broadcast.\n"
             "Send /cancel in chat to abort.",
            reply_markup=InlineKeyboardMarkup([back_button("admin_panel")]) # Add back button here too
        )
        # Wait for user's message in the message handler

    # --- User Listing ---
    elif data == "admin_list_users":
         if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
         await message.edit_text("⏳ Fetching user list...", reply_markup=InlineKeyboardMarkup([back_button("admin_panel")]))
         all_users = await get_all_user_ids()
         sudo_users = await get_role_user_ids("is_sudo")
         premium_users = await get_role_user_ids("is_premium")

         text = f"👥 **User List ({len(all_users)})**\n\n"
         text += f"👑 **Sudo Users ({len(sudo_users)}):**\n"
         text += ", ".join(f"`{uid}`" for uid in sudo_users) if sudo_users else "None\n"
         text += f"\n\n💎 **Premium Users ({len(premium_users)}):**\n"
         text += ", ".join(f"`{uid}`" for uid in premium_users if uid not in sudo_users) # Show only non-sudo premiums
         non_sudo_premium_count = len([uid for uid in premium_users if uid not in sudo_users])
         if not non_sudo_premium_count: text += "None"

         text += f"\n\n(__Note: Sudo users have all premium privileges automatically__)"
         # Add pagination if list is very long
         await message.edit_text(text, reply_markup=InlineKeyboardMarkup([back_button("admin_panel")]))

    # --- Admin: Account Management ---
    elif data == "admin_acct_mgmt":
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        await message.edit_text(
            "🏦 **Account Management**\nList, search, update or delete any Quotex account across all users.",
            reply_markup=admin_acct_mgmt_keyboard()
        )

    elif data in ("admin_accts_list", "admin_acct_search_all"):
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        await message.edit_text("⏳ Fetching all accounts...", reply_markup=InlineKeyboardMarkup([back_button("admin_acct_mgmt")]))
        all_accts = await get_all_quotex_accounts()
        if not all_accts:
            await message.edit_text("No accounts found.", reply_markup=InlineKeyboardMarkup([back_button("admin_acct_mgmt")]))
            return
        text = f"🏦 **All Accounts ({len(all_accts)})**\n\n"
        keyboard_rows = []
        for acct in all_accts:
            doc_id = str(acct['_id'])
            email = acct.get('email', 'N/A')
            uid = acct.get('user_id', 'N/A')
            text += f"\u2022 `{email}` — User: `{uid}`\n"
            keyboard_rows.append([InlineKeyboardButton(f"⚙️ {email}", callback_data=f"admin_acct_view:{doc_id}")])
        keyboard_rows.append(back_button("admin_acct_mgmt"))
        await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard_rows), parse_mode=enums.ParseMode.DEFAULT)

    elif data == "admin_acct_search":
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        user_states[user_id] = "waiting_admin_acct_search"
        await message.reply_text(
            "🔍 Enter an **email** or **User ID** to search for accounts.\nSend /cancel to abort.",
            reply_markup=ForceReply(selective=True)
        )

    elif data.startswith("admin_acct_view:"):
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        account_doc_id = data.split(":")[1]
        acct = await get_quotex_account_details(account_doc_id)
        if not acct:
            await callback_query.answer("Account not found.", show_alert=True); return
        settings = await get_or_create_trade_settings(account_doc_id)
        is_active = settings.get('service_status', False)
        acc_mode = settings.get('account_mode', 'N/A')
        text = (
            f"🏦 **Account Details**\n\n"
            f"📧 Email: `{acct.get('email', 'N/A')}`\n"
            f"👤 User ID: `{acct.get('user_id', 'N/A')}`\n"
            f"Status: **{'Active 🟢' if is_active else 'Inactive 🔴'}**\n"
            f"Account Type: **{acc_mode}**"
        )
        await message.edit_text(text, reply_markup=admin_acct_view_keyboard(account_doc_id, is_active, acc_mode))

    elif data.startswith("admin_acct_toggle_status:"):
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        account_doc_id = data.split(":")[1]
        acct = await get_quotex_account_details(account_doc_id)
        if not acct: await callback_query.answer("Account not found.", show_alert=True); return
        settings = await get_or_create_trade_settings(account_doc_id)
        new_status = not settings.get('service_status', False)
        await update_trade_setting(account_doc_id, {"service_status": new_status})
        await callback_query.answer(f"Status set to {'Active' if new_status else 'Inactive'}")
        refreshed = await get_or_create_trade_settings(account_doc_id)
        acc_mode = refreshed.get('account_mode', 'N/A')
        text = (
            f"🏦 **Account Details**\n\n"
            f"📧 Email: `{acct.get('email', 'N/A')}`\n"
            f"👤 User ID: `{acct.get('user_id', 'N/A')}`\n"
            f"Status: **{'Active 🟢' if new_status else 'Inactive 🔴'}**\n"
            f"Account Type: **{acc_mode}**"
        )
        await message.edit_text(text, reply_markup=admin_acct_view_keyboard(account_doc_id, new_status, acc_mode))

    elif data.startswith("admin_acct_toggle_type:"):
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        account_doc_id = data.split(":")[1]
        acct = await get_quotex_account_details(account_doc_id)
        if not acct: await callback_query.answer("Account not found.", show_alert=True); return
        settings = await get_or_create_trade_settings(account_doc_id)
        current_mode = settings.get('account_mode', 'PRACTICE')
        new_mode = 'REAL' if current_mode == 'PRACTICE' else 'PRACTICE'
        await update_trade_setting(account_doc_id, {"account_mode": new_mode})
        await callback_query.answer(f"Account Type set to {new_mode}")
        refreshed = await get_or_create_trade_settings(account_doc_id)
        is_active = refreshed.get('service_status', False)
        text = (
            f"🏦 **Account Details**\n\n"
            f"📧 Email: `{acct.get('email', 'N/A')}`\n"
            f"👤 User ID: `{acct.get('user_id', 'N/A')}`\n"
            f"Status: **{'Active 🟢' if is_active else 'Inactive 🔴'}**\n"
            f"Account Type: **{new_mode}**"
        )
        await message.edit_text(text, reply_markup=admin_acct_view_keyboard(account_doc_id, is_active, new_mode))

    elif data.startswith("admin_acct_del_confirm:"):
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        account_doc_id = data.split(":")[1]
        acct = await get_quotex_account_details(account_doc_id)
        if not acct: await callback_query.answer("Account not found.", show_alert=True); return
        keyboard = [
            [InlineKeyboardButton("❗️ YES, DELETE IT", callback_data=f"admin_acct_del_do:{account_doc_id}")],
            back_button(f"admin_acct_view:{account_doc_id}")
        ]
        await message.edit_text(
            f"🚨 **Delete Account `{acct.get('email', 'N/A')}`?**\n\n"
            f"User ID: `{acct.get('user_id', 'N/A')}`\n\n"
            "This will permanently remove the account and all its settings. **Cannot be undone!**",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

    elif data.startswith("admin_acct_del_do:"):
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return
        account_doc_id = data.split(":")[1]
        acct = await get_quotex_account_details(account_doc_id)
        deleted = await delete_quotex_account(account_doc_id)
        if deleted:
            await disconnect_quotex_client(account_doc_id)
            await callback_query.answer(f"Account deleted.", show_alert=True)
            all_accts = await get_all_quotex_accounts()
            text = f"🏦 **All Accounts ({len(all_accts)})**\n\n"
            keyboard_rows = []
            for a in all_accts:
                did = str(a['_id'])
                keyboard_rows.append([InlineKeyboardButton(f"⚙️ {a.get('email','N/A')}", callback_data=f"admin_acct_view:{did}")])
            keyboard_rows.append(back_button("admin_acct_mgmt"))
            await message.edit_text(text or "No accounts remaining.", reply_markup=InlineKeyboardMarkup(keyboard_rows))
        else:
            await callback_query.answer("Failed to delete account.", show_alert=True)

    
    elif data == "settings_main":
        # --- User Settings Menu ---
        # Currently, most critical settings are per-account.
        # This menu can hold future global settings (notifications, language, etc.)

        user_info = await get_user(user_id) # Get user data for display
        user_role = "Owner" if user_id == OWNER_ID else \
                    "Sudo" if user_info.get("is_sudo") else \
                    "Premium" if user_info.get("is_premium") else \
                    "Regular"

        settings_text = (
            f"⚙️ **Bot Settings**\n\n"
            f"Here you can configure general bot settings (if available).\n\n"
            f"👤 **Your Status:**\n"
            f"   - User ID: `{user_id}`\n"
            f"   - Role: **{user_role}**"
        )

        keyboard_rows = []
        if user_id == OWNER_ID:
            keyboard_rows.append([InlineKeyboardButton("📡 Signal Mode", callback_data="signal_status_view")])
            keyboard_rows.append([InlineKeyboardButton("🎯 Strategy Mode", callback_data="strategy_view")])

        keyboard_rows.append(back_button("main_menu")) # Always provide a way back

        await callback_query.message.edit_text(
            settings_text,
            reply_markup=InlineKeyboardMarkup(keyboard_rows),
            parse_mode=enums.ParseMode.DEFAULT
        )

    # ── Strategy Mode ─────────────────────────────────────────────────────────

    elif data == "strategy_view":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        await message.edit_text(
            _strategy_panel_text(sig_settings),
            reply_markup=InlineKeyboardMarkup(_strategy_panel_keyboard(sig_settings)),
        )

    elif data == "strat_toggle":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        new_val = not sig_settings.get('strategy_mode', False)
        await update_signal_settings({'strategy_mode': new_val})
        await callback_query.answer(f"Strategy Mode {'enabled ✅' if new_val else 'disabled 🔴'}")
        sig_settings = await get_signal_settings()
        try:
            await message.edit_text(
                _strategy_panel_text(sig_settings),
                reply_markup=InlineKeyboardMarkup(_strategy_panel_keyboard(sig_settings)),
            )
        except Exception as _e:
            if "MESSAGE_NOT_MODIFIED" not in str(_e):
                raise

    elif data == "strat_reset_step":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        await update_signal_settings({'strategy_step': 0})
        await callback_query.answer("Step counter reset to 1.")
        sig_settings = await get_signal_settings()
        try:
            await message.edit_text(
                _strategy_panel_text(sig_settings),
                reply_markup=InlineKeyboardMarkup(_strategy_panel_keyboard(sig_settings)),
            )
        except Exception as _e:
            if "MESSAGE_NOT_MODIFIED" not in str(_e):
                raise

    elif data.startswith("strat_select:"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        try:
            new_sid = int(data.split(":", 1)[1])
        except (ValueError, IndexError):
            await callback_query.answer("Invalid.", show_alert=True)
            return
        if new_sid not in STRATEGIES:
            await callback_query.answer("Unknown strategy.", show_alert=True)
            return
        await update_signal_settings({'strategy_id': new_sid, 'strategy_step': 0})
        await callback_query.answer(f"Switched to {STRATEGIES[new_sid]['name']} — step reset.")
        sig_settings = await get_signal_settings()
        try:
            await message.edit_text(
                _strategy_panel_text(sig_settings),
                reply_markup=InlineKeyboardMarkup(_strategy_panel_keyboard(sig_settings)),
            )
        except Exception as _e:
            if "MESSAGE_NOT_MODIFIED" not in str(_e):
                raise

    elif data == "noop":
        await callback_query.answer()

    elif data.startswith("strat_step_set:"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        try:
            new_step_idx = int(data.split(":", 1)[1])
        except (ValueError, IndexError):
            await callback_query.answer("Invalid.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        strat = STRATEGIES.get(sig_settings.get('strategy_id', 1))
        if not strat or new_step_idx < 0 or new_step_idx >= len(strat['steps']):
            await callback_query.answer("Invalid step.", show_alert=True)
            return
        await update_signal_settings({'strategy_step': new_step_idx})
        amt = strat['steps'][new_step_idx]
        await callback_query.answer(f"✅ Step {new_step_idx + 1} active — ${amt}")
        # Refresh the keyboard on the current message to highlight the new step
        sig_settings = await get_signal_settings()
        try:
            pending = sig_settings.get('pending_signal')
            if pending:
                direction = pending.get('signal_direction')
                await message.edit_reply_markup(
                    reply_markup=build_manual_trade_keyboard(direction, sig_settings)
                )
            else:
                kbd = _build_step_selector_keyboard(sig_settings.get('strategy_id', 1), new_step_idx)
                if kbd:
                    await message.edit_reply_markup(reply_markup=kbd)
        except Exception:
            pass

    # ── End Strategy Mode ──────────────────────────────────────────────────────

    # --- Role Management Navigation ---
    elif data == "admin_manage_sudo":
        if user_id != OWNER_ID: await callback_query.answer("⛔️ Owner Only", show_alert=True); return # Only owner manages sudo
        await message.edit_text("⭐ Manage Sudo Users", reply_markup=manage_role_keyboard("Sudo"))
    elif data == "admin_manage_premium":
         if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return # Sudo can manage premium
         await message.edit_text("💎 Manage Premium Users", reply_markup=manage_role_keyboard("Premium"))

    # --- Role Management Actions (Add/Remove/List) ---
    elif data.startswith("admin_add_") or data.startswith("admin_remove_"):
        action = "add" if "add" in data else "remove"
        role = "sudo" if "sudo" in data else "premium"

        if role == "sudo" and not user_id == OWNER_ID:
             await callback_query.answer("⛔️ Only the Owner can modify Sudo list.", show_alert=True)
             return
        elif not await is_sudo_user(user_id):
             await callback_query.answer("⛔️ Sudo privileges required.", show_alert=True)
             return

        user_states[user_id] = f"waiting_{action}_{role}_id"
        await message.reply_text( # Use reply_text to ask for ID
            f"Enter the **User ID** to {action} as {role.capitalize()}.\n"
            f"Send /cancel to abort.",
            reply_markup=ForceReply(selective=True)
        )

    elif data.startswith("admin_list_"): # List Sudo or Premium
        role = "sudo" if "sudo" in data else "premium"
        if not await is_sudo_user(user_id): await callback_query.answer("⛔️ Access Denied", show_alert=True); return

        await message.edit_text(f"⏳ Fetching {role.capitalize()} user list...", reply_markup=InlineKeyboardMarkup([back_button(f"admin_manage_{role}")]))
        user_ids = await get_role_user_ids(f"is_{role}")
        text = f"**{role.capitalize()} Users ({len(user_ids)})**\n\n"
        if user_ids:
            text += "\n".join(f"- `{uid}`" for uid in user_ids)
        else:
            text += "No users found with this role."
        await message.edit_text(text, reply_markup=InlineKeyboardMarkup([back_button(f"admin_manage_{role}")]))

    elif data in ("signal_status_view", "signal_toggle", "signal_clear_pending"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return

        # ── Actions first ────────────────────────────────────────────────
        if data == "signal_toggle":
            sig_settings = await get_signal_settings()
            new_status = not sig_settings.get('is_active', False)
            _active_chs = [c for c in sig_settings.get('channels', []) if c.get('active', True)]
            if new_status and not _active_chs:
                await callback_query.answer("Add and activate at least one channel first.", show_alert=True)
                return
            if new_status and not userbot_instance:
                await callback_query.answer("Userbot not configured (USERBOT_PHONE missing)", show_alert=True)
                return
            await update_signal_settings({'is_active': new_status})
            await callback_query.answer(f"Signal mode {'ON' if new_status else 'OFF'}")

        elif data == "signal_clear_pending":
            await update_signal_settings({'pending_signal': None})
            await callback_query.answer("Pending signal cleared.")

        # ── Always re-render the view with fresh DB state ────────────────
        sig_settings = await get_signal_settings()
        is_active = sig_settings.get('is_active', False)
        channel_id = sig_settings.get('channel_id', 'Not set')
        pending = sig_settings.get('pending_signal')
        signal_delay = int(sig_settings.get('signal_delay', 0))
        dur_remap_on = sig_settings.get('duration_remap_enabled', False)
        ask_dur_on = sig_settings.get('ask_duration_on_partial', False)
        manual_on = sig_settings.get('manual_trade_mode', False)
        userbot_ok = userbot_instance is not None

        status_icon = "🟢" if is_active else "🔴"
        toggle_label = "🔴 Turn OFF" if is_active else "🟢 Turn ON"

        text = (
            f"📡 **Signal Monitor**\n\n"
            f"{status_icon} Status: **{'ON' if is_active else 'OFF'}**\n"
            f"📺 Channels: {_channels_summary(sig_settings)}\n"
            f"🤖 Userbot: **{'Running ✅' if userbot_ok else 'Not configured ❌'}**\n"
            f"⏱ Delay Compensation: **{f'{signal_delay}s subtracted from duration' if signal_delay > 0 else 'Disabled'}**\n"
            f"🔄 2min→5min Remap: **{'ON ✅' if dur_remap_on else 'OFF'}**\n"
            f"⏱ Ask Duration on Partial: **{'ON ✅' if ask_dur_on else 'OFF'}**\n"
            f"🕹 Manual Trade Mode: **{'ON ✅' if manual_on else 'OFF'}**\n"
            f"🔁 Inverse Mode: **{'ON ✅' if sig_settings.get('inverse_mode', False) else 'OFF'}**\n"
        )
        if pending:
            age_s = int(time.time() - pending.get('timestamp', 0))
            text += (
                f"\n⏳ **Pending Signal** (awaiting direction):\n"
                f"  `{pending.get('asset_display', pending.get('asset'))}` "
                f"${pending.get('amount')} {pending.get('duration', 0) // 60}min "
                f"— {age_s}s ago {'⚠️ expired' if age_s > 300 else ''}\n"
            )
        else:
            text += "\nNo pending signal.\n"

        delay_off_btn = InlineKeyboardButton("🚫 Disable Delay", callback_data="sig_delay_off")
        delay_set_btn = InlineKeyboardButton(f"✏️ Set Delay ({signal_delay}s)", callback_data="sig_delay_set")
        remap_btn = InlineKeyboardButton(
            f"🔄 2min→5min: {'ON ✅' if dur_remap_on else 'OFF'}",
            callback_data="sig_dur_remap_toggle",
        )
        ask_dur_btn = InlineKeyboardButton(
            f"⏱ Ask Duration: {'ON ✅' if ask_dur_on else 'OFF'}",
            callback_data="sig_ask_dur_toggle",
        )
        manual_btn = InlineKeyboardButton(
            f"🕹 Manual Mode: {'ON ✅' if manual_on else 'OFF'}",
            callback_data="sig_manual_mode_toggle",
        )
        inverse_btn = InlineKeyboardButton(
            f"🔁 Inverse Mode: {'ON ✅' if sig_settings.get('inverse_mode', False) else 'OFF'}",
            callback_data="sig_inverse_toggle",
        )
        keyboard = [
            [InlineKeyboardButton(toggle_label, callback_data="signal_toggle")],
            [InlineKeyboardButton("📺 Manage Channels", callback_data="sig_channels_view")],
            [delay_set_btn, delay_off_btn],
            [remap_btn, ask_dur_btn],
            [manual_btn, inverse_btn],
            [InlineKeyboardButton("🗑 Clear Pending Signal", callback_data="signal_clear_pending")],
            [InlineKeyboardButton("📋 Signal Logs", callback_data="signal_logs_view")],
            back_button("main_menu"),
        ]
        try:
            await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard))
        except Exception as e:
            if "MESSAGE_NOT_MODIFIED" in str(e):
                pass  # content unchanged — nothing to do
            else:
                raise

    # ── Signal Logs View ──────────────────────────────────────────────────────

    elif data == "signal_logs_view":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        await _send_signal_logs(message, edit=True)

    # ── Signal Channels Management ────────────────────────────────────────────────

    elif data in ("sig_channels_view", "sig_set_channel"):
        # sig_set_channel retained as alias for any cached/old button presses
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        channels = sig_settings.get('channels', [])
        try:
            await message.edit_text(
                _channels_panel_text(channels),
                reply_markup=InlineKeyboardMarkup(_channels_panel_keyboard(channels)),
            )
        except Exception as _e:
            if "MESSAGE_NOT_MODIFIED" not in str(_e):
                raise

    elif data == "sig_channel_add":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        user_states[user_id] = f"waiting_signal_channel_add:{message.id}"
        try:
            await message.edit_text(
                "📺 **Add Signal Channel**\n\n"
                "Send the **channel ID** or **@username** to add.\n\n"
                "Examples:\n"
                "  • `-1001234567890` _(numeric ID — recommended)_\n"
                "  • `@mysignalchannel` _(public username)_\n\n"
                "Send /cancel to go back.",
            )
        except Exception:
            pass

    elif data.startswith("sig_ch_toggle:"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        try:
            ch_idx = int(data.split(":", 1)[1])
        except (ValueError, IndexError):
            await callback_query.answer("Invalid.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        channels = list(sig_settings.get('channels', []))
        if 0 <= ch_idx < len(channels):
            channels[ch_idx]['active'] = not channels[ch_idx].get('active', True)
            await update_signal_settings({'channels': channels})
            state_str = 'activated' if channels[ch_idx]['active'] else 'paused'
            await callback_query.answer(f"Channel {state_str}.")
            logger.info(f"[Signal] Channel {channels[ch_idx]['id']} {state_str} by user {user_id}")
        else:
            await callback_query.answer("Channel not found.", show_alert=True)
            return
        sig_settings2 = await get_signal_settings()
        chs2 = sig_settings2.get('channels', [])
        try:
            await message.edit_text(
                _channels_panel_text(chs2),
                reply_markup=InlineKeyboardMarkup(_channels_panel_keyboard(chs2)),
            )
        except Exception as _e:
            if "MESSAGE_NOT_MODIFIED" not in str(_e):
                raise

    elif data.startswith("sig_ch_rename:"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        try:
            ch_idx = int(data.split(":", 1)[1])
        except (ValueError, IndexError):
            await callback_query.answer("Invalid.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        channels = sig_settings.get('channels', [])
        if ch_idx < 0 or ch_idx >= len(channels):
            await callback_query.answer("Channel not found.", show_alert=True)
            return
        ch = channels[ch_idx]
        user_states[user_id] = f"waiting_channel_rename:{ch_idx}:{message.id}"
        try:
            await message.edit_text(
                f"✏️ **Rename Channel**\n\n"
                f"Channel: `{ch.get('id','')}` "
                f"(current name: **{ch.get('nickname','') or 'none'}**)\n\n"
                "Send a new nickname for this channel, or /skip to clear it.\n"
                "Send /cancel to go back."
            )
        except Exception:
            pass

    elif data.startswith("sig_ch_remove:"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        try:
            ch_idx = int(data.split(":", 1)[1])
        except (ValueError, IndexError):
            await callback_query.answer("Invalid.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        channels = list(sig_settings.get('channels', []))
        if 0 <= ch_idx < len(channels):
            removed = channels.pop(ch_idx)
            await update_signal_settings({'channels': channels})
            await callback_query.answer(f"Removed {_ch_display(removed)}.")
            logger.info(f"[Signal] Channel {removed.get('id')} removed by user {user_id}")
        else:
            await callback_query.answer("Channel not found.", show_alert=True)
            return
        sig_settings2 = await get_signal_settings()
        chs2 = sig_settings2.get('channels', [])
        try:
            await message.edit_text(
                _channels_panel_text(chs2),
                reply_markup=InlineKeyboardMarkup(_channels_panel_keyboard(chs2)),
            )
        except Exception as _e:
            if "MESSAGE_NOT_MODIFIED" not in str(_e):
                raise

    # ── Signal Delay Callbacks ────────────────────────────────────────────────

    elif data in ("sig_delay_off", "sig_delay_set"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return

        if data == "sig_delay_off":
            await update_signal_settings({'signal_delay': 0})
            await callback_query.answer("Delay compensation disabled.")
            # Re-render signal status view
            callback_query.data = "signal_status_view"
            sig_settings2 = await get_signal_settings()
            is_active2 = sig_settings2.get('is_active', False)
            channel_id2 = sig_settings2.get('channel_id', 'Not set')
            pending2 = sig_settings2.get('pending_signal')
            dur_remap2 = sig_settings2.get('duration_remap_enabled', False)
            ask_dur2 = sig_settings2.get('ask_duration_on_partial', False)
            userbot_ok2 = userbot_instance is not None
            status_icon2 = "🟢" if is_active2 else "🔴"
            toggle_label2 = "🔴 Turn OFF" if is_active2 else "🟢 Turn ON"
            text2 = (
                f"📡 **Signal Monitor**\n\n"
                f"{status_icon2} Status: **{'ON' if is_active2 else 'OFF'}**\n"
                f"📺 Channels: {_channels_summary(sig_settings2)}\n"
                f"🤖 Userbot: **{'Running ✅' if userbot_ok2 else 'Not configured ❌'}**\n"
                f"⏱ Delay Compensation: **Disabled**\n"
                f"🔄 2min→5min Remap: **{'ON ✅' if dur_remap2 else 'OFF'}**\n"
                f"⏱ Ask Duration on Partial: **{'ON ✅' if ask_dur2 else 'OFF'}**\n"
                f"🕹 Manual Trade Mode: **{'ON ✅' if sig_settings2.get('manual_trade_mode', False) else 'OFF'}**\n"
                f"🔁 Inverse Mode: **{'ON ✅' if sig_settings2.get('inverse_mode', False) else 'OFF'}**\n"
            )
            if pending2:
                age_s2 = int(time.time() - pending2.get('timestamp', 0))
                text2 += (
                    f"\n⏳ **Pending Signal** (awaiting direction):\n"
                    f"  `{pending2.get('asset_display', pending2.get('asset'))}` "
                    f"${pending2.get('amount')} {pending2.get('duration', 0) // 60}min "
                    f"— {age_s2}s ago {'⚠️ expired' if age_s2 > 300 else ''}\n"
                )
            else:
                text2 += "\nNo pending signal.\n"
            _man2 = sig_settings2.get('manual_trade_mode', False)
            _inv2 = sig_settings2.get('inverse_mode', False)
            kb2 = [
                [InlineKeyboardButton(toggle_label2, callback_data="signal_toggle")],
                [InlineKeyboardButton("📺 Manage Channels", callback_data="sig_channels_view")],
                [InlineKeyboardButton("✏️ Set Delay (0s)", callback_data="sig_delay_set"),
                 InlineKeyboardButton("🚫 Disable Delay", callback_data="sig_delay_off")],
                [InlineKeyboardButton(f"🔄 2min→5min: {'ON ✅' if dur_remap2 else 'OFF'}", callback_data="sig_dur_remap_toggle"),
                 InlineKeyboardButton(f"⏱ Ask Duration: {'ON ✅' if ask_dur2 else 'OFF'}", callback_data="sig_ask_dur_toggle")],
                [InlineKeyboardButton(f"🕹 Manual Mode: {'ON ✅' if _man2 else 'OFF'}", callback_data="sig_manual_mode_toggle"),
                 InlineKeyboardButton(f"🔁 Inverse: {'ON ✅' if _inv2 else 'OFF'}", callback_data="sig_inverse_toggle")],
                [InlineKeyboardButton("🗑 Clear Pending Signal", callback_data="signal_clear_pending")],
                [InlineKeyboardButton("📋 Signal Logs", callback_data="signal_logs_view")],
                back_button("main_menu"),
            ]
            try:
                await message.edit_text(text2, reply_markup=InlineKeyboardMarkup(kb2))
            except Exception as e:
                if "MESSAGE_NOT_MODIFIED" not in str(e):
                    raise

        else:  # sig_delay_set
            user_states[user_id] = f"waiting_signal_delay:{message.id}"
            try:
                sig_s = await get_signal_settings()
                cur_delay = int(sig_s.get('signal_delay', 0))
                await message.edit_text(
                    f"⏱ **Set Signal Delay Compensation**\n\n"
                    f"Current delay: **{cur_delay}s**\n\n"
                    f"Enter the number of seconds to subtract from the signal's duration at execution.\n"
                    f"Typical value: `15` (for a 2‑min signal this gives 1m 45s).\n\n"
                    f"Send `0` to disable, or /cancel to keep current setting.",
                )
            except Exception:
                pass

    # ── Signal Duration Remap Toggle ──────────────────────────────────────────

    elif data == "sig_dur_remap_toggle":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        new_val = not sig_settings.get('duration_remap_enabled', False)
        await update_signal_settings({'duration_remap_enabled': new_val})
        await callback_query.answer(f"2min→5min remap {'enabled' if new_val else 'disabled'}.")
        logger.info(f"[Signal] Duration remap (2min→5min) {'enabled' if new_val else 'disabled'} by user {user_id}")
        # Re-render the signal monitor panel
        callback_query.data = "signal_status_view"
        sig_s = await get_signal_settings()
        is_active_r = sig_s.get('is_active', False)
        s_icon = "🟢" if is_active_r else "🔴"
        t_label = "🔴 Turn OFF" if is_active_r else "🟢 Turn ON"
        sd = int(sig_s.get('signal_delay', 0))
        dr = sig_s.get('duration_remap_enabled', False)
        ad = sig_s.get('ask_duration_on_partial', False)
        pend_r = sig_s.get('pending_signal')
        ch_r = sig_s.get('channel_id', 'Not set')
        ub_r = userbot_instance is not None
        txt_r = (
            f"📡 **Signal Monitor**\n\n"
            f"{s_icon} Status: **{'ON' if is_active_r else 'OFF'}**\n"
            f"📺 Channels: {_channels_summary(sig_s)}\n"
            f"🤖 Userbot: **{'Running ✅' if ub_r else 'Not configured ❌'}**\n"
            f"⏱ Delay Compensation: **{f'{sd}s subtracted from duration' if sd > 0 else 'Disabled'}**\n"
            f"🔄 2min→5min Remap: **{'ON ✅' if dr else 'OFF'}**\n"
            f"⏱ Ask Duration on Partial: **{'ON ✅' if ad else 'OFF'}**\n"
            f"🕹 Manual Trade Mode: **{'ON ✅' if sig_s.get('manual_trade_mode', False) else 'OFF'}**\n"
            f"🔁 Inverse Mode: **{'ON ✅' if sig_s.get('inverse_mode', False) else 'OFF'}**\n"
        )
        if pend_r:
            age_r = int(time.time() - pend_r.get('timestamp', 0))
            txt_r += (
                f"\n⏳ **Pending Signal** (awaiting direction):\n"
                f"  `{pend_r.get('asset_display', pend_r.get('asset'))}` "
                f"${pend_r.get('amount')} {pend_r.get('duration', 0) // 60}min "
                f"— {age_r}s ago {'⚠️ expired' if age_r > 300 else ''}\n"
            )
        else:
            txt_r += "\nNo pending signal.\n"
        _man_r = sig_s.get('manual_trade_mode', False)
        _inv_r = sig_s.get('inverse_mode', False)
        kb_r = [
            [InlineKeyboardButton(t_label, callback_data="signal_toggle")],
            [InlineKeyboardButton("📺 Manage Channels", callback_data="sig_channels_view")],
            [InlineKeyboardButton(f"✏️ Set Delay ({sd}s)", callback_data="sig_delay_set"),
             InlineKeyboardButton("🚫 Disable Delay", callback_data="sig_delay_off")],
            [InlineKeyboardButton(f"🔄 2min→5min: {'ON ✅' if dr else 'OFF'}", callback_data="sig_dur_remap_toggle"),
             InlineKeyboardButton(f"⏱ Ask Duration: {'ON ✅' if ad else 'OFF'}", callback_data="sig_ask_dur_toggle")],
            [InlineKeyboardButton(f"🕹 Manual Mode: {'ON ✅' if _man_r else 'OFF'}", callback_data="sig_manual_mode_toggle"),
             InlineKeyboardButton(f"🔁 Inverse: {'ON ✅' if _inv_r else 'OFF'}", callback_data="sig_inverse_toggle")],
            [InlineKeyboardButton("🗑 Clear Pending Signal", callback_data="signal_clear_pending")],
            [InlineKeyboardButton("📋 Signal Logs", callback_data="signal_logs_view")],
            back_button("main_menu"),
        ]
        try:
            await message.edit_text(txt_r, reply_markup=InlineKeyboardMarkup(kb_r))
        except Exception as e:
            if "MESSAGE_NOT_MODIFIED" not in str(e):
                raise

    # ── Ask Duration on Partial Toggle ────────────────────────────────────────

    elif data == "sig_ask_dur_toggle":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        new_val = not sig_settings.get('ask_duration_on_partial', False)
        await update_signal_settings({'ask_duration_on_partial': new_val})
        await callback_query.answer(f"Ask duration on partial {'enabled' if new_val else 'disabled'}.")
        logger.info(f"[Signal] Ask duration on partial {'enabled' if new_val else 'disabled'} by user {user_id}")
        # Re-render the signal monitor panel
        callback_query.data = "signal_status_view"
        sig_s = await get_signal_settings()
        is_active_q = sig_s.get('is_active', False)
        s_icon_q = "🟢" if is_active_q else "🔴"
        t_label_q = "🔴 Turn OFF" if is_active_q else "🟢 Turn ON"
        sd_q = int(sig_s.get('signal_delay', 0))
        dr_q = sig_s.get('duration_remap_enabled', False)
        ad_q = sig_s.get('ask_duration_on_partial', False)
        pend_q = sig_s.get('pending_signal')
        ch_q = sig_s.get('channel_id', 'Not set')
        ub_q = userbot_instance is not None
        txt_q = (
            f"📡 **Signal Monitor**\n\n"
            f"{s_icon_q} Status: **{'ON' if is_active_q else 'OFF'}**\n"
            f"📺 Channels: {_channels_summary(sig_s)}\n"
            f"🤖 Userbot: **{'Running ✅' if ub_q else 'Not configured ❌'}**\n"
            f"⏱ Delay Compensation: **{f'{sd_q}s subtracted from duration' if sd_q > 0 else 'Disabled'}**\n"
            f"🔄 2min→5min Remap: **{'ON ✅' if dr_q else 'OFF'}**\n"
            f"⏱ Ask Duration on Partial: **{'ON ✅' if ad_q else 'OFF'}**\n"
            f"🕹 Manual Trade Mode: **{'ON ✅' if sig_s.get('manual_trade_mode', False) else 'OFF'}**\n"
            f"🔁 Inverse Mode: **{'ON ✅' if sig_s.get('inverse_mode', False) else 'OFF'}**\n"
        )
        if pend_q:
            age_q = int(time.time() - pend_q.get('timestamp', 0))
            txt_q += (
                f"\n⏳ **Pending Signal** (awaiting direction):\n"
                f"  `{pend_q.get('asset_display', pend_q.get('asset'))}` "
                f"${pend_q.get('amount')} {pend_q.get('duration', 0) // 60}min "
                f"— {age_q}s ago {'⚠️ expired' if age_q > 300 else ''}\n"
            )
        else:
            txt_q += "\nNo pending signal.\n"
        _man_q = sig_s.get('manual_trade_mode', False)
        _inv_q = sig_s.get('inverse_mode', False)
        kb_q = [
            [InlineKeyboardButton(t_label_q, callback_data="signal_toggle")],
            [InlineKeyboardButton("📺 Manage Channels", callback_data="sig_channels_view")],
            [InlineKeyboardButton(f"✏️ Set Delay ({sd_q}s)", callback_data="sig_delay_set"),
             InlineKeyboardButton("🚫 Disable Delay", callback_data="sig_delay_off")],
            [InlineKeyboardButton(f"🔄 2min→5min: {'ON ✅' if dr_q else 'OFF'}", callback_data="sig_dur_remap_toggle"),
             InlineKeyboardButton(f"⏱ Ask Duration: {'ON ✅' if ad_q else 'OFF'}", callback_data="sig_ask_dur_toggle")],
            [InlineKeyboardButton(f"🕹 Manual Mode: {'ON ✅' if _man_q else 'OFF'}", callback_data="sig_manual_mode_toggle"),
             InlineKeyboardButton(f"🔁 Inverse: {'ON ✅' if _inv_q else 'OFF'}", callback_data="sig_inverse_toggle")],
            [InlineKeyboardButton("🗑 Clear Pending Signal", callback_data="signal_clear_pending")],
            [InlineKeyboardButton("📋 Signal Logs", callback_data="signal_logs_view")],
            back_button("main_menu"),
        ]
        try:
            await message.edit_text(txt_q, reply_markup=InlineKeyboardMarkup(kb_q))
        except Exception as e:
            if "MESSAGE_NOT_MODIFIED" not in str(e):
                raise

    # ── Manual Trade Mode Toggle ──────────────────────────────────────────────

    elif data == "sig_manual_mode_toggle":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        new_val = not sig_settings.get('manual_trade_mode', False)
        await update_signal_settings({'manual_trade_mode': new_val})
        await callback_query.answer(f"Manual trade mode {'enabled' if new_val else 'disabled'}.")
        logger.info(f"[Signal] Manual trade mode {'enabled' if new_val else 'disabled'} by user {user_id}")
        # Re-render the signal monitor panel by re-using the main view path
        sig_sm = await get_signal_settings()
        is_am = sig_sm.get('is_active', False)
        ch_m = sig_sm.get('channel_id', 'Not set')
        pend_m = sig_sm.get('pending_signal')
        sd_m = int(sig_sm.get('signal_delay', 0))
        dr_m = sig_sm.get('duration_remap_enabled', False)
        ad_m = sig_sm.get('ask_duration_on_partial', False)
        man_m = sig_sm.get('manual_trade_mode', False)
        ub_m = userbot_instance is not None
        s_icon_m = "🟢" if is_am else "🔴"
        t_label_m = "🔴 Turn OFF" if is_am else "🟢 Turn ON"
        txt_m = (
            f"📡 **Signal Monitor**\n\n"
            f"{s_icon_m} Status: **{'ON' if is_am else 'OFF'}**\n"
            f"📺 Channels: {_channels_summary(sig_sm)}\n"
            f"🤖 Userbot: **{'Running ✅' if ub_m else 'Not configured ❌'}**\n"
            f"⏱ Delay Compensation: **{f'{sd_m}s subtracted from duration' if sd_m > 0 else 'Disabled'}**\n"
            f"🔄 2min→5min Remap: **{'ON ✅' if dr_m else 'OFF'}**\n"
            f"⏱ Ask Duration on Partial: **{'ON ✅' if ad_m else 'OFF'}**\n"
            f"🕹 Manual Trade Mode: **{'ON ✅' if man_m else 'OFF'}**\n"
            f"🔁 Inverse Mode: **{'ON ✅' if sig_sm.get('inverse_mode', False) else 'OFF'}**\n"
        )
        if pend_m:
            age_m = int(time.time() - pend_m.get('timestamp', 0))
            txt_m += (
                f"\n⏳ **Pending Signal** (awaiting direction):\n"
                f"  `{pend_m.get('asset_display', pend_m.get('asset'))}` "
                f"${pend_m.get('amount')} {pend_m.get('duration', 0) // 60}min "
                f"— {age_m}s ago {'⚠️ expired' if age_m > 300 else ''}\n"
            )
        else:
            txt_m += "\nNo pending signal.\n"
        _inv_m = sig_sm.get('inverse_mode', False)
        kb_m = [
            [InlineKeyboardButton(t_label_m, callback_data="signal_toggle")],
            [InlineKeyboardButton("📺 Manage Channels", callback_data="sig_channels_view")],
            [InlineKeyboardButton(f"✏️ Set Delay ({sd_m}s)", callback_data="sig_delay_set"),
             InlineKeyboardButton("🚫 Disable Delay", callback_data="sig_delay_off")],
            [InlineKeyboardButton(f"🔄 2min→5min: {'ON ✅' if dr_m else 'OFF'}", callback_data="sig_dur_remap_toggle"),
             InlineKeyboardButton(f"⏱ Ask Duration: {'ON ✅' if ad_m else 'OFF'}", callback_data="sig_ask_dur_toggle")],
            [InlineKeyboardButton(f"🕹 Manual Mode: {'ON ✅' if man_m else 'OFF'}", callback_data="sig_manual_mode_toggle"),
             InlineKeyboardButton(f"🔁 Inverse: {'ON ✅' if _inv_m else 'OFF'}", callback_data="sig_inverse_toggle")],
            [InlineKeyboardButton("🗑 Clear Pending Signal", callback_data="signal_clear_pending")],
            [InlineKeyboardButton("📋 Signal Logs", callback_data="signal_logs_view")],
            back_button("main_menu"),
        ]
        try:
            await message.edit_text(txt_m, reply_markup=InlineKeyboardMarkup(kb_m))
        except Exception as e:
            if "MESSAGE_NOT_MODIFIED" not in str(e):
                raise

    elif data == "sig_inverse_toggle":
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return
        sig_settings = await get_signal_settings()
        new_val = not sig_settings.get('inverse_mode', False)
        await update_signal_settings({'inverse_mode': new_val})
        await callback_query.answer(f"Inverse mode {'enabled' if new_val else 'disabled'}.")
        logger.info(f"[Signal] Inverse mode {'enabled' if new_val else 'disabled'} by user {user_id}")
        # Re-render the signal monitor panel
        sig_si = await get_signal_settings()
        is_ai = sig_si.get('is_active', False)
        ch_i = sig_si.get('channel_id', 'Not set')
        pend_i = sig_si.get('pending_signal')
        sd_i = int(sig_si.get('signal_delay', 0))
        dr_i = sig_si.get('duration_remap_enabled', False)
        ad_i = sig_si.get('ask_duration_on_partial', False)
        man_i = sig_si.get('manual_trade_mode', False)
        inv_i = sig_si.get('inverse_mode', False)
        ub_i = userbot_instance is not None
        s_icon_i = "🟢" if is_ai else "🔴"
        t_label_i = "🔴 Turn OFF" if is_ai else "🟢 Turn ON"
        txt_i = (
            f"📡 **Signal Monitor**\n\n"
            f"{s_icon_i} Status: **{'ON' if is_ai else 'OFF'}**\n"
            f"📺 Channels: {_channels_summary(sig_si)}\n"
            f"🤖 Userbot: **{'Running ✅' if ub_i else 'Not configured ❌'}**\n"
            f"⏱ Delay Compensation: **{f'{sd_i}s subtracted from duration' if sd_i > 0 else 'Disabled'}**\n"
            f"🔄 2min→5min Remap: **{'ON ✅' if dr_i else 'OFF'}**\n"
            f"⏱ Ask Duration on Partial: **{'ON ✅' if ad_i else 'OFF'}**\n"
            f"🕹 Manual Trade Mode: **{'ON ✅' if man_i else 'OFF'}**\n"
            f"🔀 Inverse Mode: **{'ON ✅' if inv_i else 'OFF'}**\n"
        )
        if pend_i:
            age_i = int(time.time() - pend_i.get('timestamp', 0))
            txt_i += (
                f"\n⏳ **Pending Signal** (awaiting direction):\n"
                f"  `{pend_i.get('asset_display', pend_i.get('asset'))}` "
                f"${pend_i.get('amount')} {pend_i.get('duration', 0) // 60}min "
                f"— {age_i}s ago {'⚠️ expired' if age_i > 300 else ''}\n"
            )
        else:
            txt_i += "\nNo pending signal.\n"
        kb_i = [
            [InlineKeyboardButton(t_label_i, callback_data="signal_toggle")],
            [InlineKeyboardButton("📺 Manage Channels", callback_data="sig_channels_view")],
            [InlineKeyboardButton(f"✏️ Set Delay ({sd_i}s)", callback_data="sig_delay_set"),
             InlineKeyboardButton("🚫 Disable Delay", callback_data="sig_delay_off")],
            [InlineKeyboardButton(f"🔄 2min→5min: {'ON ✅' if dr_i else 'OFF'}", callback_data="sig_dur_remap_toggle"),
             InlineKeyboardButton(f"⏱ Ask Duration: {'ON ✅' if ad_i else 'OFF'}", callback_data="sig_ask_dur_toggle")],
            [InlineKeyboardButton(f"🕹 Manual Mode: {'ON ✅' if man_i else 'OFF'}", callback_data="sig_manual_mode_toggle"),
             InlineKeyboardButton(f"🔀 Inverse: {'ON ✅' if inv_i else 'OFF'}", callback_data="sig_inverse_toggle")],
            [InlineKeyboardButton("🗑 Clear Pending Signal", callback_data="signal_clear_pending")],
            [InlineKeyboardButton("📋 Signal Logs", callback_data="signal_logs_view")],
            back_button("main_menu"),
        ]
        try:
            await message.edit_text(txt_i, reply_markup=InlineKeyboardMarkup(kb_i))
        except Exception as e:
            if "MESSAGE_NOT_MODIFIED" not in str(e):
                raise

    # ── Signal Amount Selection Callbacks ─────────────────────────────────────

    elif data.startswith("sig_amt:") or data in ("sig_amt_custom", "sig_amt_cancel"):
        sig_settings = await get_signal_settings()
        pending = sig_settings.get('pending_signal')

        if not pending:
            try:
                await message.edit_text("⚠️ No pending signal to confirm amount for.")
            except Exception:
                pass
            return

        if data == "sig_amt_cancel":
            await update_signal_settings({'pending_signal': None})
            try:
                await message.edit_text("❌ Signal cancelled.")
            except Exception:
                pass
            return

        if data == "sig_amt_custom":
            user_states[user_id] = f"waiting_signal_amount:{message.id}"
            try:
                await message.edit_text(
                    f"✏️ **Enter custom trade amount**\n\n"
                    f"Current signal amount: `${pending.get('amount', 0):g}`\n\n"
                    f"Send a number (e.g. `45` or `12.50`)\n"
                    f"Or send /cancel to abort.",
                )
            except Exception:
                pass
            return

        # data = "sig_amt:<float>"
        try:
            chosen_amount = float(data.split(":", 1)[1])
        except (IndexError, ValueError):
            return

        pending['amount'] = chosen_amount
        pending['amount_confirmed'] = True
        await update_signal_settings({'pending_signal': pending})

        dur_display = f"{pending['duration'] // 60} min" if pending['duration'] >= 60 else f"{pending['duration']} sec"
        try:
            await message.edit_text(
                f"✅ **Amount confirmed: ${chosen_amount:g}**\n\n"
                f"📊 Asset: `{pending.get('asset_display', pending.get('asset'))}`\n"
                f"⏱ Duration: `{dur_display}`\n\n"
                f"⏳ Waiting for direction signal (UP/DOWN)..."
            )
        except Exception:
            pass

    # ── Signal Duration Selection Callbacks ───────────────────────────────────

    elif data.startswith("sig_dur:"):
        if user_id != OWNER_ID:
            return
        sig_settings = await get_signal_settings()
        pending = sig_settings.get('pending_signal')

        if not pending:
            try:
                await message.edit_text("⚠️ No pending signal to set duration for.")
            except Exception:
                pass
            return

        try:
            chosen_duration = int(data.split(":", 1)[1])
        except (IndexError, ValueError):
            return

        pending['duration'] = chosen_duration
        pending['duration_confirmed'] = True
        await update_signal_settings({'pending_signal': pending})

        dur_display = f"{chosen_duration // 60} min" if chosen_duration >= 60 else f"{chosen_duration} sec"
        try:
            await message.edit_text(
                f"✅ **Duration set: {dur_display}**\n\n"
                f"📊 Asset: `{pending.get('asset_display', pending.get('asset'))}`\n"
                f"💵 Amount: `${pending.get('amount', 0):g}`\n\n"
                f"⏳ Waiting for direction signal (UP/DOWN)..."
            )
        except Exception:
            pass

    # ── Manual Trade Direction Callbacks ──────────────────────────────────────

    elif data in ("sig_manual_call", "sig_manual_put", "sig_manual_cancel"):
        if user_id != OWNER_ID:
            await callback_query.answer("⛔️ Owner only.", show_alert=True)
            return

        # Use a lock to prevent double-execution from rapid double-taps.
        # The critical section is the DB read→check→clear of pending_signal.
        async with _manual_trade_lock:
            sig_settings = await get_signal_settings()
            pending = sig_settings.get('pending_signal')

            if not pending:
                try:
                    await message.edit_text("⚠️ No pending signal found.")
                except Exception:
                    pass
                return

            if data == "sig_manual_cancel":
                await update_signal_settings({'pending_signal': None})
                await callback_query.answer("Signal cancelled.")
                try:
                    await message.edit_text("❌ Manual trade cancelled.")
                except Exception:
                    pass
                return

            # Atomically claim and clear the pending signal before any awaitable work
            chosen_direction = 'call' if data == 'sig_manual_call' else 'put'
            full_manual_signal = {**pending, 'direction': chosen_direction}
            await update_signal_settings({'pending_signal': None})
        # Lock released — UI update and trade execution outside the lock

        dir_icon = '🔼 UP (CALL)' if chosen_direction == 'call' else '🔽 DOWN (PUT)'
        signal_dir = pending.get('signal_direction')
        signal_agreed = (
            f" _(matches signal ✅)_" if signal_dir == chosen_direction
            else f" _(signal was {'🔼' if signal_dir == 'call' else '🔽'} — you chose opposite)_" if signal_dir
            else ""
        )

        try:
            await message.edit_text(
                f"🚀 **Executing Manual Trade**\n\n"
                f"📊 Asset: `{pending.get('asset_display', pending.get('asset'))}`\n"
                f"📈 Direction: **{dir_icon}**{signal_agreed}\n"
                f"💵 Amount: `${float(pending.get('amount', DEFAULT_TRADE_AMOUNT)):g}`\n\n"
                f"⏳ Placing trade..."
            )
        except Exception:
            pass

        logger.info(f"[Manual Trade] User chose {chosen_direction.upper()} (signal was {signal_dir or 'N/A'})")        
        full_manual_signal['received_at'] = time.time()  # deadline starts when user taps
        await execute_signal_trade(full_manual_signal)

    # ── Trading Journal ───────────────────────────────────────────────────────

    elif data.startswith("journal_today") or data.startswith("journal_date:") or data.startswith("journal_nav:"):
        # Resolve which date to show
        today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        if data.startswith("journal_date:"):
            view_date = data.split(":", 1)[1]
        elif data.startswith("journal_nav:"):
            view_date = data.split(":", 1)[1]
        else:
            view_date = today_str

        # Validate date format
        try:
            view_dt = datetime.datetime.strptime(view_date, "%Y-%m-%d")
        except ValueError:
            await callback_query.answer("Invalid date format.", show_alert=True)
            return

        await callback_query.message.edit_text(
            f"⏳ Loading journal for **{view_date}**...",
            reply_markup=InlineKeyboardMarkup([back_button("main_menu")])
        )

        accounts = await get_user_quotex_accounts(user_id)
        account_doc_ids = [str(a['_id']) for a in accounts]
        summary = await get_journal_summary(account_doc_ids, view_date)
        entries = summary["entries"]

        journal_text = _build_journal_text(summary, view_date)

        # Prev / Next day navigation
        prev_dt = (view_dt - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        next_dt = (view_dt + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        nav_row = [
            InlineKeyboardButton("◀ Prev Day", callback_data=f"journal_nav:{prev_dt}"),
            InlineKeyboardButton("▶ Next Day", callback_data=f"journal_nav:{next_dt}"),
        ]
        keyboard_rows = [
            nav_row,
            [InlineKeyboardButton("✍️ Manual Entry", callback_data=f"journal_add_manual:{view_date}"),
             InlineKeyboardButton("💸 Record Withdrawal", callback_data=f"journal_add_wd:{view_date}")],
            [InlineKeyboardButton("📅 Go to Date", callback_data="journal_pick_date")],
            back_button("main_menu"),
        ]
        try:
            await callback_query.message.edit_text(
                journal_text,
                reply_markup=InlineKeyboardMarkup(keyboard_rows),
                parse_mode=enums.ParseMode.DEFAULT
            )
        except Exception as e:
            if "MESSAGE_NOT_MODIFIED" not in str(e):
                raise

    elif data.startswith("journal_add_manual:"):
        # journal_add_manual:{date_str}
        date_str = data.split(":", 1)[1]
        accounts = await get_user_quotex_accounts(user_id)
        if not accounts:
            await callback_query.answer("No accounts found.", show_alert=True)
            return
        if len(accounts) == 1:
            acct = accounts[0]
            acct_doc_id = str(acct["_id"])
            user_states[user_id] = f"waiting_manual_entry:{acct_doc_id}:{date_str}"
            await callback_query.message.reply_text(
                f"✍️ **Manual Trade Entry** for `{acct.get('email', acct_doc_id)}`\n"
                f"📅 Date: **{date_str}**\n\n"
                "Send the trade details in this format:\n"
                "`SYMBOL DIRECTION AMOUNT DURATION_MIN RESULT PL`\n\n"
                "**Example:** `EURUSD_OTC CALL 10 1 WIN 9.20`\n"
                "• DIRECTION: `CALL` or `PUT`\n"
                "• RESULT: `WIN`, `LOSS`, or `TIE`\n"
                "• PL: stake/profit as a positive number (auto-signed from RESULT)\n\n"
                "Send /cancel to abort.",
                reply_markup=ForceReply(selective=True),
                parse_mode=enums.ParseMode.DEFAULT
            )
        else:
            buttons = [
                [InlineKeyboardButton(
                    f"📧 {acct.get('email', str(acct['_id']))} ({acct.get('account_mode', '')})",
                    callback_data=f"journal_me_acct:{str(acct['_id'])}:{date_str}"
                )]
                for acct in accounts
            ]
            buttons.append(back_button("main_menu"))
            await callback_query.message.edit_text(
                "✍️ **Manual Entry** — Select the account for this trade:",
                reply_markup=InlineKeyboardMarkup(buttons)
            )

    elif data.startswith("journal_me_acct:"):
        # journal_me_acct:{account_doc_id}:{date_str}
        parts = data.split(":", 2)
        if len(parts) < 3:
            await callback_query.answer("Invalid action.", show_alert=True)
            return
        acct_doc_id, date_str = parts[1], parts[2]
        accounts = await get_user_quotex_accounts(user_id)
        acct = next((a for a in accounts if str(a["_id"]) == acct_doc_id), None)
        acct_label = acct.get("email", acct_doc_id) if acct else acct_doc_id
        user_states[user_id] = f"waiting_manual_entry:{acct_doc_id}:{date_str}"
        await callback_query.message.reply_text(
            f"✍️ **Manual Trade Entry** for `{acct_label}`\n"
            f"📅 Date: **{date_str}**\n\n"
            "Send the trade details in this format:\n"
            "`SYMBOL DIRECTION AMOUNT DURATION_MIN RESULT PL`\n\n"
            "**Example:** `EURUSD_OTC CALL 10 1 WIN 9.20`\n"
            "• DIRECTION: `CALL` or `PUT`\n"
            "• RESULT: `WIN`, `LOSS`, or `TIE`\n"
            "• PL: stake/profit as a positive number (auto-signed from RESULT)\n\n"
            "Send /cancel to abort.",
            reply_markup=ForceReply(selective=True),
            parse_mode=enums.ParseMode.DEFAULT
        )

    elif data.startswith("journal_add_wd:"):
        # journal_add_wd:{date_str}
        date_str = data.split(":", 1)[1]
        accounts = await get_user_quotex_accounts(user_id)
        if not accounts:
            await callback_query.answer("No accounts found.", show_alert=True)
            return
        if len(accounts) == 1:
            acct = accounts[0]
            acct_doc_id = str(acct["_id"])
            user_states[user_id] = f"waiting_withdrawal:{acct_doc_id}:{acct.get('email', '')}:{date_str}"
            await callback_query.message.reply_text(
                f"💸 **Record Withdrawal** for `{acct.get('email', acct_doc_id)}`\n"
                f"📅 Date: **{date_str}**\n\n"
                "Enter the withdrawal amount (e.g. `150.00` or `$150`).\n"
                "Optionally add a note after the amount: `150 Profit withdrawal`\n\n"
                "Send /cancel to abort.",
                reply_markup=ForceReply(selective=True),
                parse_mode=enums.ParseMode.DEFAULT
            )
        else:
            buttons = [
                [InlineKeyboardButton(
                    f"📧 {acct.get('email', str(acct['_id']))} ({acct.get('account_mode', '')})",
                    callback_data=f"journal_wd_acct:{str(acct['_id'])}:{date_str}"
                )]
                for acct in accounts
            ]
            buttons.append(back_button("main_menu"))
            await callback_query.message.edit_text(
                "💸 **Record Withdrawal** — Select the account:",
                reply_markup=InlineKeyboardMarkup(buttons)
            )

    elif data.startswith("journal_wd_acct:"):
        # journal_wd_acct:{account_doc_id}:{date_str}
        parts = data.split(":", 2)
        if len(parts) < 3:
            await callback_query.answer("Invalid action.", show_alert=True)
            return
        acct_doc_id, date_str = parts[1], parts[2]
        accounts = await get_user_quotex_accounts(user_id)
        acct = next((a for a in accounts if str(a["_id"]) == acct_doc_id), None)
        acct_label = acct.get("email", acct_doc_id) if acct else acct_doc_id
        user_states[user_id] = f"waiting_withdrawal:{acct_doc_id}:{acct_label}:{date_str}"
        await callback_query.message.reply_text(
            f"💸 **Record Withdrawal** for `{acct_label}`\n"
            f"📅 Date: **{date_str}**\n\n"
            "Enter the withdrawal amount (e.g. `150.00` or `$150`).\n"
            "Optionally add a note after the amount: `150 Profit withdrawal`\n\n"
            "Send /cancel to abort.",
            reply_markup=ForceReply(selective=True),
            parse_mode=enums.ParseMode.DEFAULT
        )

    elif data == "journal_pick_date":
        user_states[user_id] = "waiting_journal_date"
        await callback_query.message.reply_text(
            "📅 Enter the date you want to view in **YYYY-MM-DD** format (e.g. `2026-03-01`).\n"
            "Send /cancel to abort.",
            reply_markup=ForceReply(selective=True)
        )

    else:
        logger.warning(f"Unhandled callback data from user {user_id}: {data}")
        await callback_query.answer("Unknown button action.", show_alert=False)


# --- Message Handler (for replies and potentially commands not handled by filters) ---
@Client.on_message(filters.private)
async def message_handler(client: Client, message: Message):
    global user_states, bot_instance
    if not bot_instance: bot_instance = client # Ensure instance is set

    user_id = message.from_user.id
    text = message.text

    if not text and not message.caption and user_states.get(user_id) == "waiting_broadcast_message":
        # Allow broadcast of media without text (uses caption if available later)
        pass
    elif not text or text.startswith('/'): # Ignore commands unless it's /cancel
         if text == "/cancel":
             if user_id in user_states:
                 state = user_states.pop(user_id)
                 _cancel_labels = {
                     "waiting_qx_email": "Adding New Account Action Canceled",
                     "waiting_qx_password": "Adding New Account Action Canceled",
                 }
                 _cancel_msg = _cancel_labels.get(state.split(':')[0], f"Action ({state.split(':')[0]}) cancelled.")
                 await message.reply_text(_cancel_msg, quote=True)
             else:
                 await message.reply_text("Nothing to cancel.", quote=True)
         # Potentially handle other non-command text if needed
         return

    # --- State Machine for User Inputs ---
    state = user_states.get(user_id)

    if state == "waiting_qx_email":
        email = text.strip()
        if "@" in email and "." in email: # Basic email validation
            user_states[user_id] = f"waiting_qx_password:{email}"
            await message.reply_text(
                f"Got it. Now please reply with the **Password** for `{email}`.\n"
                 "⚠️ **Warning:** Password will be stored. Be aware of security risks.\n"
                "Send /cancel to abort.",
                reply_markup=ForceReply(selective=True)
            )
        else:
            await message.reply_text(
                "Invalid email format. Please try again or send /cancel.",
                 reply_markup=ForceReply(selective=True)
            )

    elif state and state.startswith("waiting_qx_password:"):
        email = state.split(":", 1)[1]
        password = text.strip()
        if password:
            del user_states[user_id] # Clear state
            # Attempt to add account - This automatically tries connection & 2FA
            await message.reply_text(f"Adding account `{email}` and attempting login/verification...")

             # Store temporary placeholder first
            temp_doc = {
                "user_id": user_id, "email": email.lower(), "password": password,
                "added_date": datetime.datetime.now(datetime.timezone.utc), "_temp_login": True
            }
            try:
                insert_result = await quotex_accounts_db.insert_one(temp_doc)
                account_doc_id = str(insert_result.inserted_id)

                # Now attempt connection which triggers OTP if needed
                qx_client, status_msg = await get_quotex_client(user_id, account_doc_id, interaction_type="login_attempt")

                if qx_client:
                     # Login successful! Remove temp flag
                     await quotex_accounts_db.update_one({"_id": insert_result.inserted_id}, {"$unset": {"_temp_login": ""}})
                     await message.reply_text(f"✅ Account `{email}` added and verified successfully!", reply_markup=InlineKeyboardMarkup([back_button("quotex_list")]))
                     await disconnect_quotex_client(account_doc_id) # Disconnect after verification
                else:
                    # Connection failed - status_msg contains reason
                    # get_quotex_client handles deletion if Invalid Credentials
                    if "removed" not in status_msg: # Delete if not already removed
                        await delete_quotex_account(account_doc_id) # Clean up failed attempt
                    await message.reply_text(f"❌ Failed to add account `{email}`: {status_msg}", reply_markup=InlineKeyboardMarkup([back_button("quotex_list")]))

            except Exception as e:
                 logger.error(f"Error during account add/verify process for {email}: {e}", exc_info=True)
                 await message.reply_text(f"An unexpected error occurred while adding the account: {e}", reply_markup=InlineKeyboardMarkup([back_button("quotex_list")]))
                 # Ensure cleanup of potentially inserted doc if error happens after insert but before connect attempt
                 if 'insert_result' in locals() and insert_result.inserted_id:
                     await delete_quotex_account(str(insert_result.inserted_id))
                 if user_id in user_states: del user_states[user_id]
                 if user_id in active_otp_requests: del active_otp_requests[user_id]

        else:
            await message.reply_text("Password cannot be empty. Please try again or send /cancel.")


    elif state and state.startswith("waiting_asset_add:"):
         account_doc_id = state.split(":")[1]
         del user_states[user_id] # Clear state
         try:
             parts = [p.strip() for p in text.split(',')]
             asset_name = parts[0] # Store asset names consistently
             amount = DEFAULT_TRADE_AMOUNT
             duration = DEFAULT_TRADE_DURATION

             if len(parts) > 1: amount = int(parts[1])
             if len(parts) > 2: duration = int(parts[2])
             # Basic validation
             if not asset_name: raise ValueError("Asset name cannot be empty.")
             if amount <= 0: raise ValueError("Amount must be positive.")
             if duration <= 0: raise ValueError("Duration must be positive.") # Add more duration checks if needed

             new_asset = {'name': asset_name, 'amount': amount, 'duration': duration}

             # Add asset to the list in DB
             settings = await get_or_create_trade_settings(account_doc_id)
             current_assets = settings.get("assets", [])
              # Prevent duplicates? Check by name?
             if any(a['name'] == new_asset['name'] for a in current_assets):
                 await message.reply_text(f"Asset `{new_asset['name']}` already exists.", quote=True)
             else:
                 current_assets.append(new_asset)
                 await update_trade_setting(account_doc_id, {"assets": current_assets})
                 await message.reply_text(f"✅ Asset `{new_asset['name']}` added successfully!", quote=True)

              # Show updated asset list screen
             settings_reloaded = await get_or_create_trade_settings(account_doc_id)
             assets_reloaded = settings_reloaded.get("assets", [])
             text = f"✅ Asset added!\n\nCurrent Assets for account `{account_doc_id}`:\n"
             if assets_reloaded:
                 for i, a in enumerate(assets_reloaded):
                     text += f"  {i+1}. `{a['name']}` | Amount: {a.get('amount', DEFAULT_TRADE_AMOUNT)} | Duration: {a.get('duration', DEFAULT_TRADE_DURATION)}s\n"
             else:
                 text += "  No assets configured yet.\n"
             keyboard = [
                 [InlineKeyboardButton("➕ Add Asset", callback_data=f"asset_add:{account_doc_id}")],
             ]
             if assets_reloaded:
                 keyboard.append([InlineKeyboardButton("❌ Remove an Asset", callback_data=f"asset_remove_select:{account_doc_id}")])
             keyboard.append(back_button(f"qx_manage:{account_doc_id}"))
             await message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=enums.ParseMode.DEFAULT)


         except (ValueError, IndexError) as e:
             await message.reply_text(f"Invalid format: {e}\nPlease use `ASSET_NAME,Amount,Duration` (e.g., `EURUSD,10,60`). Send /cancel to abort.", quote=True)
             user_states[user_id] = state # Put state back to retry
         except Exception as e:
              await message.reply_text(f"An error occurred: {e}", quote=True)
              logger.error(f"Error adding asset for {account_doc_id}: {e}", exc_info=True)


    elif state and state.startswith("waiting_candle_size:"):
         account_doc_id = state.split(":")[1]
         del user_states[user_id]
         try:
            new_size = int(text.strip())
            if new_size <= 0: raise ValueError("Candle size must be positive.")
            # Add checks for valid sizes supported by Quotex if known (e.g., 5, 15, 30, 60, 120, ...)
            await update_trade_setting(account_doc_id, {"candle_size": new_size})
            await message.reply_text(f"✅ Candle size updated to {new_size} seconds.", quote=True)
             # Navigate back (similar tricky part as above)
            acc_details = await get_quotex_account_details(account_doc_id)
            settings = await get_or_create_trade_settings(account_doc_id) # Reload
            await message.reply_text("Returning to account management.", reply_markup=account_management_keyboard(account_doc_id, settings))

         except ValueError:
              await message.reply_text("Invalid input. Please enter a positive number for candle size (in seconds) or send /cancel.", quote=True)
              user_states[user_id] = state # Retry state
         except Exception as e:
             await message.reply_text(f"An error occurred: {e}", quote=True)
             logger.error(f"Error setting candle size for {account_doc_id}: {e}")

    elif state and (state.startswith("waiting_add_") or state.startswith("waiting_remove_")):
        # Handle Add/Remove Sudo/Premium ID input
         parts = state.split("_")
         action, role = parts[1], parts[2]
         target_id_str = text.strip()
         del user_states[user_id] # Clear state

         try:
             target_user_id = int(target_id_str)
             if target_user_id == user_id and action == "remove" and role == "sudo":
                  await message.reply_text("You cannot remove Sudo from yourself.", quote=True)
                  return
             if role == "sudo" and target_user_id == OWNER_ID:
                 await message.reply_text("Owner cannot be removed from Sudo.", quote=True)
                 return

             target_user_info = await add_user_if_not_exists(target_user_id) # Ensure target exists
             if not target_user_info:
                  await message.reply_text(f"Could not find or add user with ID `{target_user_id}`.", quote=True)
                  return

             new_status = (action == "add")
             success = await set_user_role(target_user_id, f"is_{role}", new_status)

             if success:
                  action_verb = "granted" if new_status else "revoked"
                  await message.reply_text(f"✅ {role.capitalize()} status {action_verb} for user `{target_user_id}`.", quote=True)
                  # Try notify the target user? Optional.
                  try:
                       await client.send_message(target_user_id, f"Your **{role.capitalize()}** status has been **{action_verb.upper()}** by an administrator.")
                  except (UserIsBlocked, InputUserDeactivated, UserDeactivated):
                       logger.warning(f"Could not notify user {target_user_id} about role change (user blocked or deactivated).")
                  except Exception as e_notify:
                      logger.error(f"Error notifying user {target_user_id} about role change: {e_notify}")

             else:
                  await message.reply_text(f"⚠️ Failed to update {role.capitalize()} status for user `{target_user_id}` (maybe already set/unset?).", quote=True)

             # Go back to the relevant management screen
             if bot_instance:
                  # Attempt to trigger callback to refresh menu (complex)
                  # Easier: just send the menu again
                  await message.reply_text("Returning to role management:", reply_markup=manage_role_keyboard(role.capitalize()))


         except ValueError:
             await message.reply_text("Invalid User ID. Please enter a numeric ID or send /cancel.", quote=True)
             user_states[user_id] = state # Retry state
         except Exception as e:
             await message.reply_text(f"An error occurred: {e}", quote=True)
             logger.error(f"Error managing role {role} for user {target_id_str}: {e}")


    elif state == "waiting_broadcast_message":
         # Only Owner/Sudo should be in this state
         if not await is_sudo_user(user_id): return
         del user_states[user_id] # Clear state

         await message.reply_text("⏳ Starting broadcast...", quote=True)
         all_user_ids = await get_all_user_ids()
         success_count = 0
         fail_count = 0
         total_users = len(all_user_ids)

         start_time = time.time()

         for target_user_id in all_user_ids:
             if target_user_id == user_id: # Don't broadcast to self? Optional.
                  #success_count += 1
                  continue
             try:
                 # Use copy_message for flexibility (handles text, media, formatting)
                 await client.copy_message(
                     chat_id=target_user_id,
                     from_chat_id=user_id,
                     message_id=message.id # The message user sent as broadcast content
                 )
                 success_count += 1
                 logger.info(f"Broadcast sent successfully to {target_user_id}")
             except FloodWait as fw:
                 logger.warning(f"Broadcast FloodWait for {fw.value} seconds. Pausing.")
                 await asyncio.sleep(fw.value + 1)
                 # Retry sending to the same user after wait?
                 try:
                     await client.copy_message(target_user_id, user_id, message.id)
                     success_count += 1
                 except Exception as e_retry:
                     logger.error(f"Broadcast failed to {target_user_id} after FloodWait retry: {e_retry}")
                     fail_count += 1
             except (UserIsBlocked, InputUserDeactivated, UserDeactivated):
                 logger.warning(f"Broadcast failed to {target_user_id}: User blocked or deactivated.")
                 fail_count += 1
                 # Optional: Remove inactive user from DB? Be careful with this.
             except Exception as e:
                 logger.error(f"Broadcast failed to {target_user_id}: {e}")
                 fail_count += 1

             # Add small delay between sends to be safe
             await asyncio.sleep(0.2) # Adjust delay as needed (5 messages/sec)

         end_time = time.time()
         duration = end_time - start_time
         await message.reply_text(
            f"✅ **Broadcast Complete**\n\n"
            f"Sent to: {success_count} users\n"
            f"Failed for: {fail_count} users\n"
            f"Total users: {total_users}\n"
            f"Duration: {duration:.2f} seconds",
            reply_markup=InlineKeyboardMarkup([back_button("admin_panel")]),
            quote=True
        )


    # --- Admin: Account Search ---
    elif state == "waiting_admin_acct_search":
        if not await is_sudo_user(user_id): return
        del user_states[user_id]
        query = text.strip()
        results = await get_all_quotex_accounts(search=query)
        if not results:
            await message.reply_text(
                f"No accounts found matching `{query}`.",
                reply_markup=InlineKeyboardMarkup([back_button("admin_acct_mgmt")]),
                quote=True
            )
            return
        resp_text = f"🔍 **Search Results for `{query}` ({len(results)})**\n\n"
        keyboard_rows = []
        for acct in results:
            doc_id = str(acct['_id'])
            email = acct.get('email', 'N/A')
            uid = acct.get('user_id', 'N/A')
            resp_text += f"• `{email}` — User: `{uid}`\n"
            keyboard_rows.append([InlineKeyboardButton(f"⚙️ {email}", callback_data=f"admin_acct_view:{doc_id}")])
        keyboard_rows.append(back_button("admin_acct_mgmt"))
        await message.reply_text(
            resp_text,
            reply_markup=InlineKeyboardMarkup(keyboard_rows),
            parse_mode=enums.ParseMode.DEFAULT,
            quote=True
        )

    # --- Journal Date Picker ---
    elif state == "waiting_journal_date":
        del user_states[user_id]
        date_input = text.strip()
        try:
            datetime.datetime.strptime(date_input, "%Y-%m-%d")  # validate
        except ValueError:
            await message.reply_text(
                "❌ Invalid format. Please use **YYYY-MM-DD** (e.g. `2026-03-01`).",
                quote=True
            )
            return
        # Trigger the journal view for the chosen date
        accounts = await get_user_quotex_accounts(user_id)
        account_doc_ids = [str(a['_id']) for a in accounts]
        summary = await get_journal_summary(account_doc_ids, date_input)
        entries = summary["entries"]
        view_dt = datetime.datetime.strptime(date_input, "%Y-%m-%d")

        journal_text = _build_journal_text(summary, date_input)

        prev_dt = (view_dt - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        next_dt = (view_dt + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
        keyboard_rows = [
            [InlineKeyboardButton("◀ Prev Day", callback_data=f"journal_nav:{prev_dt}"),
             InlineKeyboardButton("▶ Next Day", callback_data=f"journal_nav:{next_dt}")],
            [InlineKeyboardButton("✍️ Manual Entry", callback_data=f"journal_add_manual:{date_input}"),
             InlineKeyboardButton("💸 Record Withdrawal", callback_data=f"journal_add_wd:{date_input}")],
            [InlineKeyboardButton("📅 Go to Date", callback_data="journal_pick_date")],
            back_button("main_menu"),
        ]
        await message.reply_text(
            journal_text,
            reply_markup=InlineKeyboardMarkup(keyboard_rows),
            parse_mode=enums.ParseMode.DEFAULT,
            quote=True
        )

    elif state.startswith("waiting_manual_entry:"):
        # state = "waiting_manual_entry:{account_doc_id}:{date_str}"
        del user_states[user_id]
        parts = state.split(":", 2)
        if len(parts) < 3:
            await message.reply_text("❌ Session error. Please try again.", quote=True)
            return
        acct_doc_id, date_str = parts[1], parts[2]

        tokens = text.strip().split()
        if len(tokens) < 6:
            await message.reply_text(
                "❌ Invalid format. Expected:\n"
                "`SYMBOL DIRECTION AMOUNT DURATION_MIN RESULT PL`\n\n"
                "Example: `EURUSD_OTC CALL 10 1 WIN 9.20`",
                quote=True
            )
            return

        symbol = tokens[0].upper()
        direction = tokens[1].upper()
        try:
            amount = float(tokens[2])
        except ValueError:
            await message.reply_text("❌ Invalid amount. Must be a number.", quote=True)
            return
        try:
            duration_min = int(tokens[3])
        except ValueError:
            await message.reply_text("❌ Invalid duration. Must be a whole number of minutes.", quote=True)
            return
        result = tokens[4].upper()
        try:
            pl_abs = float(tokens[5])
        except ValueError:
            await message.reply_text("❌ Invalid P&L value. Must be a number.", quote=True)
            return

        if direction not in ("CALL", "PUT"):
            await message.reply_text("❌ Direction must be `CALL` or `PUT`.", quote=True)
            return
        if result not in ("WIN", "LOSS", "TIE"):
            await message.reply_text("❌ Result must be `WIN`, `LOSS`, or `TIE`.", quote=True)
            return

        # Auto-sign profit_loss from result
        if result == "WIN":
            profit_loss = abs(pl_abs)
        elif result == "LOSS":
            profit_loss = -abs(pl_abs)
        else:  # TIE
            profit_loss = 0.0

        # Use midnight UTC of the given date for entry/close timestamps
        try:
            entry_dt = datetime.datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            entry_dt = datetime.datetime.now(datetime.timezone.utc)

        accounts = await get_user_quotex_accounts(user_id)
        acct = next((a for a in accounts if str(a["_id"]) == acct_doc_id), None)
        acct_email = acct.get("email", "") if acct else ""
        acct_mode = acct.get("account_mode", "PRACTICE") if acct else "PRACTICE"

        entry = {
            "user_id": user_id,
            "account_doc_id": acct_doc_id,
            "email": acct_email,
            "account_mode": acct_mode,
            "symbol": symbol,
            "direction": direction,
            "amount": amount,
            "duration": duration_min * 60,
            "result": result,
            "profit_loss": profit_loss,
            "entry_price": None,
            "closing_price": None,
            "entry_time": entry_dt,
            "closing_time": entry_dt,
            "manual": True,
            "created_at": datetime.datetime.now(datetime.timezone.utc),
        }
        await save_journal_entry(entry)

        res_icon = "✅" if result == "WIN" else ("⚠️" if result == "TIE" else "❌")
        pl_display = f"+${abs(profit_loss):.2f}" if profit_loss > 0 else (f"-${abs(profit_loss):.2f}" if profit_loss < 0 else "$0.00")
        await message.reply_text(
            f"✍️ **Manual entry saved!**\n\n"
            f"{res_icon} `{symbol}` | {direction} | ${amount} | {duration_min}min\n"
            f"📌 Result: **{result}**  {pl_display}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📓 View Journal", callback_data=f"journal_date:{date_str}")]
            ]),
            parse_mode=enums.ParseMode.DEFAULT,
            quote=True
        )

    elif state.startswith("waiting_withdrawal:"):
        # state = "waiting_withdrawal:{account_doc_id}:{email}:{date_str}"
        del user_states[user_id]
        parts = state.split(":", 3)
        if len(parts) < 4:
            await message.reply_text("❌ Session error. Please try again.", quote=True)
            return
        acct_doc_id, acct_email, date_str = parts[1], parts[2], parts[3]

        raw = text.strip().lstrip("$").strip()
        raw_parts = raw.split(None, 1)
        amount_str = raw_parts[0].replace(",", "")
        note = raw_parts[1].strip() if len(raw_parts) > 1 else ""
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
        except ValueError:
            await message.reply_text(
                "❌ Invalid amount. Please send a positive number, e.g. `150.00`",
                quote=True
            )
            return

        await save_withdrawal(acct_doc_id, acct_email, date_str, amount, note)

        note_display = f"\n📝 Note: _{note}_" if note else ""
        await message.reply_text(
            f"💸 **Withdrawal recorded!**\n\n"
            f"📧 Account: `{acct_email}`\n"
            f"📅 Date: **{date_str}**\n"
            f"💵 Amount: **${amount:,.2f}**{note_display}",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("📓 View Journal", callback_data=f"journal_date:{date_str}")]
            ]),
            parse_mode=enums.ParseMode.DEFAULT,
            quote=True
        )

    # --- Placeholder for other states if needed ---

    elif state and (state.startswith("waiting_signal_channel:") or state.startswith("waiting_signal_channel_add:")):
        del user_states[user_id]
        try:
            ch_msg_id = int(state.split(":", 1)[1])
        except (IndexError, ValueError):
            ch_msg_id = None

        raw = text.strip()
        if raw.lower() == "/cancel":
            await message.reply_text("❌ Cancelled.", quote=True)
            return

        # Accept numeric IDs (negative or positive) and @usernames
        if not re.match(r'^-?\d+$', raw) and not re.match(r'^@?[\w]{4,}$', raw):
            await message.reply_text(
                "❌ Invalid format. Send a numeric channel ID (e.g. `-1001234567890`) "
                "or a public username (e.g. `@channelname`).",
                quote=True,
            )
            return

        if re.match(r'^-?\d+$', raw):
            new_channel: Any = int(raw)
        else:
            new_channel = raw if raw.startswith('@') else f'@{raw}'

        # Add to channels list (dedup)
        sig_settings_cur = await get_signal_settings()
        channels = list(sig_settings_cur.get('channels', []))
        ch_id_str = str(new_channel)
        if not any(str(c.get('id', '')) == ch_id_str for c in channels):
            channels.append({'id': ch_id_str, 'active': True})
            await update_signal_settings({'channels': channels, 'channel_id': new_channel})
            action = "added"
        else:
            action = "already in list"
        logger.info(f"[Signal] Channel {new_channel} {action} (set by user {user_id})")

        # Prompt for a nickname
        _sent = await message.reply_text(
            f"✅ Signal channel `{new_channel}` {action}.\n\n"
            "✏️ **Nickname** (optional): Reply with a short name for this channel "
            "(e.g. _Pro Signals_), or /skip to leave it unnamed.",
            quote=True,
        )
        user_states[user_id] = f"waiting_channel_nickname:{ch_id_str}:{ch_msg_id}"

    elif state and state.startswith("waiting_channel_nickname:"):
        del user_states[user_id]
        parts_s = state.split(":", 2)
        ch_id_target = parts_s[1] if len(parts_s) > 1 else ''
        try:
            ch_msg_id = int(parts_s[2]) if len(parts_s) > 2 else None
        except (ValueError, TypeError):
            ch_msg_id = None

        raw = text.strip()
        if raw.lower() in ("/cancel", "/skip"):
            nickname = ''
        else:
            nickname = raw[:40]  # cap at 40 chars

        sig_settings_cur = await get_signal_settings()
        channels = list(sig_settings_cur.get('channels', []))
        for ch in channels:
            if str(ch.get('id', '')) == ch_id_target:
                ch['nickname'] = nickname
                break
        await update_signal_settings({'channels': channels})
        if nickname:
            await message.reply_text(f"✅ Nickname set to **{nickname}**.", quote=True)

        # Refresh the channels panel
        if bot_instance and ch_msg_id:
            try:
                sig_settings_updated = await get_signal_settings()
                chs_updated = sig_settings_updated.get('channels', [])
                await bot_instance.edit_message_text(
                    chat_id=user_id,
                    message_id=ch_msg_id,
                    text=_channels_panel_text(chs_updated),
                    reply_markup=InlineKeyboardMarkup(_channels_panel_keyboard(chs_updated)),
                )
            except Exception:
                pass

    elif state and state.startswith("waiting_channel_rename:"):
        del user_states[user_id]
        parts_s = state.split(":", 2)
        try:
            ch_idx = int(parts_s[1]) if len(parts_s) > 1 else -1
        except (ValueError, TypeError):
            ch_idx = -1
        try:
            ch_msg_id = int(parts_s[2]) if len(parts_s) > 2 else None
        except (ValueError, TypeError):
            ch_msg_id = None

        raw = text.strip()
        if raw.lower() == "/cancel":
            await message.reply_text("❌ Cancelled.", quote=True)
        else:
            nickname = '' if raw.lower() == "/skip" else raw[:40]
            sig_settings_cur = await get_signal_settings()
            channels = list(sig_settings_cur.get('channels', []))
            if 0 <= ch_idx < len(channels):
                channels[ch_idx]['nickname'] = nickname
                await update_signal_settings({'channels': channels})
                label = f"**{nickname}**" if nickname else "cleared"
                await message.reply_text(f"✅ Channel nickname {label}.", quote=True)
            else:
                await message.reply_text("❌ Channel not found.", quote=True)

        # Refresh the channels panel
        if bot_instance and ch_msg_id:
            try:
                sig_settings_updated = await get_signal_settings()
                chs_updated = sig_settings_updated.get('channels', [])
                await bot_instance.edit_message_text(
                    chat_id=user_id,
                    message_id=ch_msg_id,
                    text=_channels_panel_text(chs_updated),
                    reply_markup=InlineKeyboardMarkup(_channels_panel_keyboard(chs_updated)),
                )
            except Exception:
                pass

    elif state and state.startswith("waiting_signal_delay:"):
        del user_states[user_id]
        try:
            delay_msg_id = int(state.split(":", 1)[1])
        except (IndexError, ValueError):
            delay_msg_id = None

        raw = text.strip()
        if raw.lower() == "/cancel":
            await message.reply_text("Cancelled — delay setting unchanged.", quote=True)
            return
        try:
            new_delay = int(raw)
            if new_delay < 0:
                raise ValueError("Delay cannot be negative")
        except ValueError:
            await message.reply_text(
                "❌ Invalid value. Send a whole number of seconds (e.g. `15`), or `0` to disable.",
                quote=True,
            )
            return

        await update_signal_settings({'signal_delay': new_delay})
        delay_display = f"{new_delay}s" if new_delay > 0 else "Disabled"

        # Edit the settings message if possible
        if bot_instance and delay_msg_id:
            try:
                await bot_instance.edit_message_text(
                    chat_id=user_id,
                    message_id=delay_msg_id,
                    text=(
                        f"✅ **Delay compensation set to: {delay_display}**\n\n"
                        f"Go back to Signal Monitor to review settings."
                    ),
                )
            except Exception:
                pass

        await message.reply_text(
            f"✅ Signal delay set to **{delay_display}**."
            + (f" Durations will be reduced by {new_delay}s at execution." if new_delay > 0 else " No compensation will be applied."),
            quote=True,
        )

    elif state and state.startswith("waiting_signal_amount:"):
        # state = "waiting_signal_amount:{amount_msg_id}"
        del user_states[user_id]
        try:
            amt_msg_id = int(state.split(":", 1)[1])
        except (IndexError, ValueError):
            amt_msg_id = None

        raw = text.strip().lstrip("$").strip().replace(",", "")
        try:
            custom_amount = float(raw)
            if custom_amount <= 0:
                raise ValueError("Amount must be positive")
        except ValueError:
            await message.reply_text(
                "❌ Invalid amount. Please send a positive number, e.g. `45` or `12.50`",
                quote=True,
            )
            return

        sig_settings = await get_signal_settings()
        pending = sig_settings.get('pending_signal')
        if not pending:
            await message.reply_text("⚠️ No pending signal found. It may have expired.", quote=True)
            return

        pending['amount'] = custom_amount
        pending['amount_confirmed'] = True
        await update_signal_settings({'pending_signal': pending})

        dur_display = f"{pending['duration'] // 60} min" if pending['duration'] >= 60 else f"{pending['duration']} sec"

        # Edit the original amount selection message if possible
        if bot_instance and amt_msg_id:
            try:
                await bot_instance.edit_message_text(
                    chat_id=user_id,
                    message_id=amt_msg_id,
                    text=(
                        f"✅ **Custom amount set: ${custom_amount:g}**\n\n"
                        f"📊 Asset: `{pending.get('asset_display', pending.get('asset'))}`\n"
                        f"⏱ Duration: `{dur_display}`\n\n"
                        f"⏳ Waiting for direction signal (UP/DOWN)..."
                    ),
                )
            except Exception:
                pass

        await message.reply_text(
            f"✅ Trade amount set to **${custom_amount:g}**. Waiting for direction...",
            quote=True,
        )


async def _check_asset_open_and_get_name(qx_client: Quotex, asset_name_original: str) -> Optional[str]:
    """
    Checks if the asset (or its OTC/non-OTC counterpart) is open.
    Returns the name of the tradeable asset, or None if unavailable.

    Resolution order:
      • Non-OTC asset  → try force_open=False, then _otc with force_open=True
      • OTC asset      → try force_open=True first, then non-OTC base as fallback
    """
    try:
        is_otc = asset_name_original.endswith("_otc")

        if not is_otc:
            # 1. Try the base asset
            checked_name, data = await qx_client.get_available_asset(asset_name_original, force_open=False)
            if checked_name and data and data[2]:
                logger.info(f"[{asset_name_original}] Asset is open.")
                return checked_name

            # 2. Base is closed — try the OTC variant
            otc_asset = asset_name_original + "_otc"
            logger.info(f"[{asset_name_original}] Closed. Trying OTC variant {otc_asset}...")
            checked_name_otc, data_otc = await qx_client.get_available_asset(otc_asset, force_open=True)
            if checked_name_otc and data_otc:
                logger.info(f"[{otc_asset}] OTC variant is open.")
                return checked_name_otc

            logger.warning(f"[{asset_name_original}] Neither base nor OTC variant is available.")
            return None

        else:
            # 1. Asset name is already OTC.
            # Do NOT use get_available_asset(force_open=True) here — when the OTC
            # instrument's i[14] flag is 0, it silently strips "_otc" and returns
            # the base non-OTC name, causing orders on the wrong asset and not_price_.
            # OTC pairs on Quotex are available 24/7, so we only need to confirm the
            # symbol exists in the instruments list (i[0] != None), ignoring i[14].
            _, otc_data = await qx_client.check_asset_open(asset_name_original)
            if otc_data and otc_data[0] is not None:
                logger.info(f"[{asset_name_original}] OTC asset found in instruments.")
                return asset_name_original

            # 2. OTC symbol not in instruments list — try the non-OTC base as fallback
            base_asset = asset_name_original[:-4]  # strip "_otc"
            logger.info(f"[{asset_name_original}] OTC not in instruments. Trying base asset {base_asset}...")
            checked_name_base, data_base = await qx_client.get_available_asset(base_asset, force_open=False)
            if checked_name_base and data_base and data_base[2]:
                logger.info(f"[{base_asset}] Base asset is open (fallback from OTC).")
                return checked_name_base

            logger.warning(f"[{asset_name_original}] Neither OTC nor base asset {base_asset} is available.")
            return None

    except Exception as e:
        logger.error(f"[{asset_name_original}] Error checking asset availability: {e}", exc_info=True)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL-BASED TRADING
# ═══════════════════════════════════════════════════════════════════════════════

# ── Amount Selection Helpers ──────────────────────────────────────────────────

async def get_owner_balance() -> Optional[float]:
    """Fetch current account balance for the owner's first Quotex account."""
    try:
        accounts = await get_user_quotex_accounts(OWNER_ID)
        if not accounts:
            return None
        account_doc_id = str(accounts[0]['_id'])
        if account_doc_id in active_quotex_clients:
            qx_client = active_quotex_clients[account_doc_id]
            settings = await get_or_create_trade_settings(account_doc_id)
            account_mode = settings.get('account_mode', 'PRACTICE')
            profile = await qx_client.get_profile()
            if profile:
                bal = profile.live_balance if account_mode == 'REAL' else profile.demo_balance
                return float(bal)
    except Exception as e:
        logger.warning(f"[SignalAmt] Could not fetch owner balance: {e}")
    return None


def get_amount_tiers(balance: Optional[float]) -> list:
    """Return the tiered bet amounts based on account balance."""
    if balance is None or balance < 50:
        return [5, 10, 15, 20, 25, 30, 75, 100, 125, 150]
    return [15, 20, 25, 30, 35, 65, 125, 200, 300, 350]


def build_manual_trade_keyboard(
    signal_direction: Optional[str] = None,
    sig_settings: Optional[dict] = None,
) -> InlineKeyboardMarkup:
    """
    Build the UP/DOWN inline keyboard for manual trade confirmation.
    signal_direction: highlights the matching button with ⭐.
    sig_settings: when strategy mode is on, prepends a compact step selector.
    """
    call_label = f"⭐ 🔼 UP (CALL)" if signal_direction == 'call' else "🔼 UP (CALL)"
    put_label  = f"⭐ 🔽 DOWN (PUT)" if signal_direction == 'put'  else "🔽 DOWN (PUT)"
    keyboard: list = []
    if sig_settings and sig_settings.get('strategy_mode'):
        sid = sig_settings.get('strategy_id', 1)
        current_step = sig_settings.get('strategy_step', 0)
        strat = STRATEGIES.get(sid)
        if strat:
            steps = strat['steps']
            amt_now = steps[min(current_step, len(steps) - 1)]
            keyboard.append([InlineKeyboardButton(
                f"🎯 Strategy: Step {current_step + 1}/10 — ${amt_now}  (tap to change)",
                callback_data="noop",
            )])
            row: list = []
            for i, amt in enumerate(steps):
                star = '⭐' if i == current_step else ''
                row.append(InlineKeyboardButton(
                    f"{star}{i + 1}·${amt}",
                    callback_data=f"strat_step_set:{i}",
                ))
                if len(row) == 5:
                    keyboard.append(row)
                    row = []
            if row:
                keyboard.append(row)
    keyboard.append([
        InlineKeyboardButton(call_label, callback_data="sig_manual_call"),
        InlineKeyboardButton(put_label,  callback_data="sig_manual_put"),
    ])
    keyboard.append([InlineKeyboardButton("❌ Skip / Cancel", callback_data="sig_manual_cancel")])
    return InlineKeyboardMarkup(keyboard)


def build_duration_keyboard(signal_duration: int) -> InlineKeyboardMarkup:
    """Build inline keyboard for duration selection before a signal trade."""
    keyboard = [
        [InlineKeyboardButton(
            f"📊 Use Signal Duration ({signal_duration // 60}min{f' {signal_duration % 60}s' if signal_duration % 60 else ''})",
            callback_data=f"sig_dur:{signal_duration}",
        )]
    ]
    row: list = []
    for d in [60, 120, 180, 300, 600]:  # 1, 2, 3, 5, 10 min
        row.append(InlineKeyboardButton(f"{d // 60} min", callback_data=f"sig_dur:{d}"))
        if len(row) == 3:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    keyboard.append([InlineKeyboardButton("❌ Cancel Signal", callback_data="sig_amt_cancel")])
    return InlineKeyboardMarkup(keyboard)


def build_amount_keyboard(signal_amount: float, tiers: list) -> InlineKeyboardMarkup:
    # First row: use signal amount
    keyboard = [
        [InlineKeyboardButton(f"📊 Use Signal Amount (${signal_amount:g})", callback_data=f"sig_amt:{signal_amount}")]
    ]
    # Tier buttons: 3 per row
    row: list = []
    for amt in tiers:
        row.append(InlineKeyboardButton(f"${int(amt)}", callback_data=f"sig_amt:{int(amt)}"))
        if len(row) == 3:
            keyboard.append(row)
            row = []
    if row:
        keyboard.append(row)
    # Bottom controls
    keyboard.append([InlineKeyboardButton("✏️ Custom Amount", callback_data="sig_amt_custom")])
    keyboard.append([InlineKeyboardButton("❌ Cancel Signal", callback_data="sig_amt_cancel")])
    return InlineKeyboardMarkup(keyboard)


async def execute_signal_trade(signal: Dict[str, Any]):
    """
    Execute a signal trade on ALL owner Quotex accounts simultaneously.
    Notifies the owner with per-account trade results.
    """
    # Capture the moment we start — used to enforce MAX_ENTRY_DELAY_SECONDS.
    # Callers may supply their own timestamp (e.g. exact moment direction arrived).
    received_at: float = signal.get('received_at') or time.time()

    asset = signal.get('asset')
    direction = signal.get('direction')
    amount = float(signal.get('amount', DEFAULT_TRADE_AMOUNT))
    raw_duration = int(signal.get('duration', DEFAULT_TRADE_DURATION))
    asset_display = signal.get('asset_display', asset)

    if not asset or not direction:
        logger.error(f"[Signal Trade] Cannot execute — missing asset or direction: {signal}")
        return

    # ── Apply signal-delay compensation ──────────────────────────────────────
    sig_settings = await get_signal_settings()
    signal_delay = int(sig_settings.get('signal_delay', 0))

    # ── Strategy Mode: override trade amount ──────────────────────────────────
    # ── Strategy Mode: override trade amount ──────────────────────────────────
    # If the user manually confirmed a specific amount (amount_confirmed=True on
    # the signal dict), that choice takes priority over the strategy step amount.
    user_confirmed_amount: Optional[float] = (
        float(signal['amount'])
        if signal.get('amount_confirmed') and signal.get('amount') is not None
        else None
    )

    strategy_override: Optional[dict] = None  # passed down to per-account handler
    if sig_settings.get('strategy_mode') and user_confirmed_amount is None:
        sid   = sig_settings.get('strategy_id', 1)
        step  = sig_settings.get('strategy_step', 0)
        strat = STRATEGIES.get(sid)
        if strat:
            steps = strat['steps']
            step  = min(step, len(steps) - 1)
            strategy_amount = float(steps[step])
            strategy_override = {
                'strategy_id':     sid,
                'strategy_step':   step,
                'strategy_amount': strategy_amount,
                'strategy_steps':  steps,
                'strategy_name':   strat['name'],
                'min_balance':     strat['min_balance'],
            }
            amount = strategy_amount  # use for the initial notification
            logger.info(
                f"[Signal Trade] Strategy Mode — {strat['name']} "
                f"step {step + 1}/10 amount=${strategy_amount}"
            )
        else:
            logger.warning(f"[Signal Trade] Unknown strategy_id={sid}, proceeding with signal amount.")
    elif sig_settings.get('strategy_mode') and user_confirmed_amount is not None:
        logger.info(
            f"[Signal Trade] Strategy Mode active but user manually confirmed "
            f"amount=${user_confirmed_amount:g} — strategy amount bypassed."
        )

    if signal_delay > 0:
        duration = max(raw_duration - signal_delay, 5)  # floor at 5s
        delay_note = f" _(−{signal_delay}s delay compensation)_"
    else:
        duration = raw_duration
        delay_note = ""
    # ─────────────────────────────────────────────────────────────────────────

    # ── Duration remap (e.g. 2 min → 5 min) ──────────────────────────────────
    _DURATION_REMAP = {120: 300}  # 2 min → 5 min
    if sig_settings.get('duration_remap_enabled'):
        _remapped = _DURATION_REMAP.get(duration)
        if _remapped:
            logger.info(f"[Signal Trade] Duration remapped {duration}s → {_remapped}s (remap rule active)")
            duration = _remapped
    # ─────────────────────────────────────────────────────────────────────────

    # ── Inverse mode (flip direction) ────────────────────────────────────────
    original_direction = direction
    if sig_settings.get('inverse_mode') and not sig_settings.get('manual_trade_mode'):
        direction = 'put' if direction == 'call' else 'call'
        logger.info(f"[Signal Trade] Inverse mode active — direction flipped {original_direction} → {direction}")
    # ─────────────────────────────────────────────────────────────────────────

    dir_label = '🔼 BUY (CALL)' if direction == 'call' else '🔽 SELL (PUT)'
    inverse_note = f" _(inverted from {original_direction.upper()})_" if direction != original_direction else ""

    logger.info(f"[Signal Trade] {asset_display} | {dir_label} | ${amount} | {duration}s (signal: {raw_duration}s, delay: {signal_delay}s){inverse_note}")

    if bot_instance:
        try:
            dur_display = f"{duration // 60}m {duration % 60}s" if duration % 60 else f"{duration // 60} min"
            raw_dur_display = f"{raw_duration // 60}m {raw_duration % 60}s" if raw_duration % 60 else f"{raw_duration // 60} min"
            await bot_instance.send_message(
                OWNER_ID,
                f"🔔 **Signal Received — Executing Trades**\n\n"
                f"📊 Asset: `{asset_display}`\n"
                f"📈 Direction: **{dir_label}**{inverse_note}\n"
                f"💵 Amount: `${amount}`\n"
                f"⏱ Duration: `{dur_display}`"
                + (f" _(signal: {raw_dur_display}, −{signal_delay}s)_" if signal_delay > 0 else f" `({duration}s)`")
                + f"\n\n⚡ Placing on all **Active** accounts...",
            )
        except Exception as e:
            logger.warning(f"[Signal Trade] Could not notify owner: {e}")

    accounts = await get_user_quotex_accounts(OWNER_ID)
    if not accounts:
        logger.warning("[Signal Trade] No Quotex accounts found for owner.")
        if bot_instance:
            await bot_instance.send_message(OWNER_ID, "⚠️ Signal received but no Quotex accounts are linked.")
        return

    trade_tasks = [
        _execute_single_account_signal_trade(
            str(acc['_id']), acc['email'], asset, asset_display, direction, amount, duration,
            strategy_override=strategy_override,
            received_at=received_at,
        )
        for acc in accounts
    ]
    results = await asyncio.gather(*trade_tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            logger.error(f"[Signal Trade] Unhandled exception in trade task: {r}", exc_info=r)


async def _execute_single_account_signal_trade(
    account_doc_id: str, email: str,
    asset: str, asset_display: str,
    direction: str, amount: float, duration: int,
    strategy_override: Optional[dict] = None,
    received_at: Optional[float] = None,
):
    """Execute a signal-based trade on one Quotex account and report result to owner."""
    try:
        qx_client, status_msg = await get_quotex_client(OWNER_ID, account_doc_id, "signal_trade")
        if not qx_client:
            if bot_instance:
                await bot_instance.send_message(
                    OWNER_ID,
                    f"❌ **{email}**\nCould not connect to Quotex.\n_Reason: {status_msg}_",
                )
            return

        settings = await get_or_create_trade_settings(account_doc_id)

        # Skip accounts that are not Active
        if not settings.get('service_status', False):
            logger.info(f"[Signal Trade] [{email}] Skipping — account is Inactive.")
            if bot_instance:
                await bot_instance.send_message(
                    OWNER_ID,
                    f"⏭ **{email}**\nSkipped — account status is **Inactive**.",
                )
            return

        trade_mode = settings.get("trade_mode", DEFAULT_TRADE_MODE)
        account_mode = settings.get("account_mode", "PRACTICE")

        # Explicitly switch to the account mode from settings (PRACTICE / REAL).
        # This is critical — the cached client may still be in PRACTICE mode even
        # after the user switches to REAL in the bot settings.
        try:
            await qx_client.change_account(account_mode)
            logger.info(f"[Signal Trade] [{email}] Account mode set to {account_mode}")
        except Exception as mode_err:
            logger.warning(f"[Signal Trade] [{email}] Could not switch to {account_mode}: {mode_err}")

        # Check asset availability (tries OTC variant automatically)
        asset_open = await _check_asset_open_and_get_name(qx_client, asset)
        if not asset_open:
            if bot_instance:
                await bot_instance.send_message(
                    OWNER_ID,
                    f"⚠️ **{email}**\nAsset `{asset_display}` is not available right now. Trade skipped.",
                )
            return

        # ── Strategy Mode: balance check + override amount ────────────────────
        if strategy_override:
            try:
                current_balance = await qx_client.get_balance()
            except Exception:
                current_balance = None

            strategy_amount = strategy_override['strategy_amount']
            min_balance     = strategy_override['min_balance']
            strat_name      = strategy_override['strategy_name']
            strat_step      = strategy_override['strategy_step']

            if current_balance is not None and current_balance < strategy_amount:
                logger.warning(
                    f"[Signal Trade] [{email}] Strategy balance check failed: "
                    f"balance=${current_balance:.2f} < step amount=${strategy_amount} "
                    f"(step {strat_step + 1}/10, {strat_name})"
                )
                if bot_instance:
                    await bot_instance.send_message(
                        OWNER_ID,
                        f"⚠️ **{email}** — Strategy trade skipped\n\n"
                        f"🎯 {strat_name}\n"
                        f"📍 Step {strat_step + 1}/10 requires **${strategy_amount:g}**\n"
                        f"💰 Current balance: **${current_balance:.2f}**\n\n"
                        f"_Insufficient balance for this strategy step. "
                        f"Deposit funds or reset the step counter._",
                    )
                return
            # Override signal amount with strategy amount
            amount = strategy_amount
            logger.info(
                f"[Signal Trade] [{email}] Strategy override: amount=${amount} "
                f"(step {strat_step + 1}/10, {strat_name})"
            )
        # ─────────────────────────────────────────────────────────────────────

        logger.info(f"[Signal Trade] [{email}] {direction.upper()} {asset_open} ${amount} {duration}s {trade_mode}")

        # Capture opening balance (only persisted on first trade of the calendar day)
        date_str_today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        try:
            balance_before = await qx_client.get_balance()
            await record_opening_balance(account_doc_id, email, date_str_today, account_mode, balance_before)
            logger.info(f"[Signal Trade] [{email}] Balance before trade: {balance_before}")
        except Exception as bal_err:
            logger.warning(f"[Signal Trade] [{email}] Could not fetch pre-trade balance: {bal_err}")
            balance_before = None

        # Prime the price feed before placing the order.
        # Quotex rejects orders with "not_price_" when no price data is actively
        # streaming for the asset. start_realtime_price() subscribes AND waits
        # until the server sends at least one tick, preventing the race condition
        # that buy() has (it calls start_candles_stream but doesn't wait for data).
        try:
            await asyncio.wait_for(
                qx_client.start_realtime_price(asset_open),
                timeout=8,
            )
            logger.info(f"[Signal Trade] [{email}] Price feed ready for {asset_open}.")
        except asyncio.TimeoutError:
            logger.warning(
                f"[Signal Trade] [{email}] Price feed for {asset_open} not ready after 8s — "
                "proceeding anyway."
            )
        except Exception as pf_err:
            logger.warning(f"[Signal Trade] [{email}] Price feed priming error: {pf_err} — proceeding anyway.")

        # Clear any stale WebSocket error flag from a previous trade or session.
        # global_value.check_websocket_if_error is never reset by pyquotex — once it
        # is set (e.g. from a prior not_price_ response) every subsequent buy() call
        # exits the wait loop immediately with the old error reason.
        _qx_global_value.check_websocket_if_error = False
        _qx_global_value.websocket_error_reason = None

        # ── Deadline check ────────────────────────────────────────────────────
        # All setup is done. If more than MAX_ENTRY_DELAY_SECONDS have elapsed
        # since the signal arrived, skip the trade — a late entry is worse than
        # no entry. This catches slow re-auth, slow WS reconnects, etc.
        if received_at is not None:
            elapsed = time.time() - received_at
            if elapsed > MAX_ENTRY_DELAY_SECONDS:
                logger.warning(
                    f"[Signal Trade] [{email}] Trade SKIPPED — {elapsed:.1f}s elapsed since signal "
                    f"(limit: {MAX_ENTRY_DELAY_SECONDS}s). Late entry risk too high."
                )
                if bot_instance:
                    try:
                        await bot_instance.send_message(
                            OWNER_ID,
                            f"⏱ **{email}**\n"
                            f"Trade skipped — setup took **{elapsed:.1f}s** "
                            f"(limit: {MAX_ENTRY_DELAY_SECONDS:.0f}s).\n"
                            "_A late entry was avoided. Check your session health._",
                        )
                    except Exception:
                        pass
                return
        # ─────────────────────────────────────────────────────────────────────

        # Attempt buy with one automatic reconnect on connection-reset errors
        entry_time = datetime.datetime.now(datetime.timezone.utc)
        _CONNECTION_ERRS = (ConnectionResetError, ConnectionAbortedError, ConnectionError, OSError)
        for attempt in range(2):
            try:
                status, buy_info = await qx_client.buy(amount, asset_open, direction, duration, trade_mode)
                break  # success — exit retry loop
            except _CONNECTION_ERRS as conn_err:
                if attempt == 0:
                    logger.warning(
                        f"[Signal Trade] [{email}] Connection error on buy() (attempt 1): {conn_err}. "
                        "Evicting stale client and reconnecting..."
                    )
                    await disconnect_quotex_client(account_doc_id)
                    qx_client, status_msg = await get_quotex_client(OWNER_ID, account_doc_id, "signal_trade_retry")
                    if not qx_client:
                        if bot_instance:
                            await bot_instance.send_message(
                                OWNER_ID,
                                f"❌ **{email}**\nReconnect failed after connection drop.\n_{status_msg}_",
                            )
                        return
                    # re-check asset availability on fresh client
                    asset_open = await _check_asset_open_and_get_name(qx_client, asset) or asset_open
                else:
                    raise  # second attempt also failed — let outer handler report it

        if not status:
            err = buy_info if isinstance(buy_info, str) else str(buy_info)
            logger.warning(
                f"[Signal Trade] [{email}] buy() returned status=False "
                f"(buy_info={err!r}). Trade was not placed — "
                f"likely a WebSocket timeout (no buy_id received from Quotex)."
            )
            if bot_instance:
                await bot_instance.send_message(
                    OWNER_ID,
                    f"❌ **{email}**\nTrade placement failed.\n_Reason: {err}_",
                )
            return

        trade_id = buy_info.get('id', 'N/A')
        entry_price = (
            buy_info.get('openPrice') or buy_info.get('open_price')
            or buy_info.get('price') or buy_info.get('open')
        )
        dur_display_r = f"{duration // 60}m {duration % 60}s" if duration % 60 else f"{duration // 60} min"
        dir_label_r = '🔼 BUY (CALL)' if direction == 'call' else '🔽 SELL (PUT)'
        entry_price_str = f"`{entry_price}`" if entry_price else "_unknown_"
        logger.info(f"[Signal Trade] [{email}] Trade ID {trade_id} placed. Waiting {duration + 2}s for result...")
        if bot_instance:
            try:
                await bot_instance.send_message(
                    OWNER_ID,
                    f"✅ **Trade Placed** — `{email}`\n\n"
                    f"📊 Asset: `{asset_display}` → `{asset_open}`\n"
                    f"📈 Direction: **{dir_label_r}**\n"
                    f"💵 Amount: `${amount}`\n"
                    f"⏱ Duration: `{dur_display_r}`\n"
                    f"🏷 Trade ID: `{trade_id}`\n"
                    f"📌 Entry Price: {entry_price_str}\n\n"
                    f"⏳ Waiting for result...",
                )
            except Exception as notify_err:
                logger.warning(f"[Signal Trade] [{email}] Could not send placement notification: {notify_err}")
        await asyncio.sleep(duration + 2)

        # check_win polls listinfodata (populated via WebSocket).
        # If the result packet is lost (e.g. after a reconnect), it loops forever.
        # Wrap with a generous timeout and fall back to get_result() (history API).
        _CHECK_TIMEOUT = 45  # seconds after the trade should already be settled
        win_result = None
        profit = 0.0
        try:
            win_result = await asyncio.wait_for(
                qx_client.check_win(buy_info["id"]), timeout=_CHECK_TIMEOUT
            )
            profit = qx_client.get_profit()
            logger.info(f"[Signal Trade] [{email}] check_win={win_result}, profit={profit}")
        except asyncio.TimeoutError:
            logger.warning(
                f"[Signal Trade] [{email}] check_win timed out after {_CHECK_TIMEOUT}s "
                f"(trade_id={trade_id}). Trying get_result() fallback..."
            )
            try:
                fb_status, fb_data = await qx_client.get_result(str(trade_id))
                if fb_status in ("win", "loss") and isinstance(fb_data, dict):
                    profit = float(fb_data.get("profitAmount", 0))
                    win_result = profit > 0
                    logger.info(
                        f"[Signal Trade] [{email}] get_result fallback: "
                        f"status={fb_status}, profit={profit}"
                    )
                else:
                    logger.warning(
                        f"[Signal Trade] [{email}] get_result fallback: not found "
                        f"({fb_status!r}: {fb_data!r}). Reporting as unavailable."
                    )
                    if bot_instance:
                        await bot_instance.send_message(
                            OWNER_ID,
                            f"⏳ **{email}** — Trade result could not be retrieved.\n"
                            f"Trade ID: `{trade_id}`\n"
                            f"_Check your Quotex account directly._",
                        )
                    return
            except Exception as fb_err:
                logger.error(
                    f"[Signal Trade] [{email}] get_result fallback also failed: {fb_err}",
                    exc_info=True,
                )
                if bot_instance:
                    await bot_instance.send_message(
                        OWNER_ID,
                        f"⏳ **{email}** — Trade result unavailable (timed out + fallback failed).\n"
                        f"Trade ID: `{trade_id}`\n"
                        f"_Check your Quotex account directly._",
                    )
                return
        except KeyError:
            logger.error(
                f"[Signal Trade] [{email}] buy_info missing 'id' key — buy_info={buy_info!r}",
                exc_info=True,
            )
            if bot_instance:
                await bot_instance.send_message(
                    OWNER_ID,
                    f"⚠️ **{email}** — Trade placed but result check failed (no trade ID in buy response).",
                )
            return

        closing_time = datetime.datetime.now(datetime.timezone.utc)
        closing_price = (
            (win_result if isinstance(win_result, dict) and win_result.get('closePrice') else None)
            or buy_info.get('closePrice') or buy_info.get('close_price') or buy_info.get('close')
        )

        if win_result:
            icon, outcome, result_str = "✅", f"WIN!  Profit: +${abs(profit):.2f}", "WIN"
        elif profit == 0:
            icon, outcome, result_str = "⚠️", "TIE  (no profit/loss)", "TIE"
        else:
            icon, outcome, result_str = "❌", f"LOSS!  Lost: -${abs(profit):.2f}", "LOSS"

        # ── Strategy step advance / reset ─────────────────────────────────────
        strategy_note = ""
        result_keyboard = None
        if strategy_override:
            strat_step  = strategy_override['strategy_step']
            strat_steps = strategy_override['strategy_steps']
            strat_name  = strategy_override['strategy_name']
            if result_str == "WIN":
                new_step = 0
                strategy_note = f"\n🎯 Strategy: WIN — step reset to **1** ✅"
            elif result_str == "TIE":
                # Treat tie as no change — stay on same step
                new_step = strat_step
                strategy_note = f"\n🎯 Strategy: TIE — step unchanged (**{strat_step + 1}/10**)"
            else:  # LOSS
                new_step = strat_step + 1
                if new_step >= len(strat_steps):
                    new_step = 0
                    strategy_note = (
                        f"\n🎯 Strategy: LOSS — full cycle complete, resetting to step **1** 🔄"
                    )
                else:
                    next_amt = strat_steps[new_step]
                    strategy_note = (
                        f"\n🎯 Strategy: LOSS — advancing to step **{new_step + 1}/10** "
                        f"(next amount: **${next_amt}**) 📈"
                    )
            # Persist the new step unconditionally — we always want the step to
            # reflect the latest trade result. For single-account setups this is
            # correct; for concurrent multi-account the last writer wins, which is
            # acceptable since all accounts trade the same signal at the same step.
            try:
                await update_signal_settings({'strategy_step': new_step})
                logger.info(
                    f"[Signal Trade] [{email}] Strategy step "
                    f"{strat_step + 1} → {new_step + 1} ({result_str})"
                )
            except Exception as step_err:
                logger.warning(f"[Signal Trade] [{email}] Could not update strategy step: {step_err}")
            result_keyboard = _build_step_selector_keyboard(strategy_override['strategy_id'], new_step)
        # ─────────────────────────────────────────────────────────────────────

        # Capture closing balance after trade settlement
        try:
            balance_after = await qx_client.get_balance()
            await record_closing_balance(account_doc_id, date_str_today, balance_after)
            logger.info(f"[Signal Trade] [{email}] Balance after trade: {balance_after}")
        except Exception as bal_err:
            logger.warning(f"[Signal Trade] [{email}] Could not fetch post-trade balance: {bal_err}")
            balance_after = None

        # ── Record to trading journal ──────────────────────────────────
        await save_journal_entry({
            "account_doc_id":  account_doc_id,
            "email":           email,
            "date":            entry_time.strftime("%Y-%m-%d"),
            "symbol":          asset_display,
            "symbol_actual":   asset_open,
            "direction":       direction.upper(),
            "duration":        duration,
            "amount":          amount,
            "account_mode":    account_mode,
            "trade_id":        str(trade_id),
            "entry_time":      entry_time,
            "entry_price":     entry_price,
            "closing_time":    closing_time,
            "closing_price":   closing_price,
            "result":          result_str,
            "profit_loss":     round(profit, 2),
            "balance_before":  balance_before,
            "balance_after":   balance_after,
        })

        if bot_instance:
            await bot_instance.send_message(
                OWNER_ID,
                f"{icon} **Signal Trade Result** — `{email}`\n\n"
                f"📊 Asset: `{asset_display}` → `{asset_open}`\n"
                f"📈 Direction: `{direction.upper()}`\n"
                f"💵 Amount: `${amount}`\n"
                f"🏷 Trade ID: `{trade_id}`\n"
                f"📌 Result: **{outcome}**"
                + strategy_note,
                reply_markup=result_keyboard,
            )

    except Exception as e:
        logger.error(f"[Signal Trade] Error on account {account_doc_id}: {e}", exc_info=True)

        # Detect stale-session: server returns no profile data (expired token)
        _stale_auth = (
            isinstance(e, (TypeError, RuntimeError))
            and "NoneType" in str(e) or "session token" in str(e).lower()
        )
        if _stale_auth:
            logger.warning(
                f"[Signal Trade] {account_doc_id}: stale auth detected — evicting client "
                "and deleting session.json so next trade triggers a fresh login."
            )
            # Evict the cached client
            try:
                _stale_client = active_quotex_clients.pop(account_doc_id, None)
                if _stale_client:
                    await _stale_client.close()
            except Exception:
                pass
            # Delete the stale session file
            _session_file = Path(f"sessions/{account_doc_id}/session.json")
            if _session_file.exists():
                try:
                    _session_file.unlink()
                    logger.warning(
                        f"[Signal Trade] {account_doc_id}: deleted stale session.json."
                    )
                except Exception as _del_err:
                    logger.warning(f"[Signal Trade] Could not delete session.json: {_del_err}")

        if bot_instance:
            try:
                _msg = (
                    f"⚠️ **{email}**\n"
                    "Session expired mid-trade — stale session cleared.\n"
                    "The next signal will re-authenticate automatically."
                    if _stale_auth else
                    f"❌ **{email}**\nUnexpected error during signal trade.\n`{type(e).__name__}: {e}`"
                )
                await bot_instance.send_message(OWNER_ID, _msg)
            except Exception:
                pass


# ── Userbot Channel Listener ─────────────────────────────────────────────────

def build_userbot() -> Optional[Client]:
    """Create (but do not start) the MTProto userbot Client."""
    global userbot_instance
    if not USERBOT_PHONE:
        logger.warning(
            "[Userbot] USERBOT_PHONE not set in .env — signal channel monitoring disabled. "
            "Set USERBOT_PHONE and restart to enable."
        )
        return None
    userbot_instance = Client(
        "userbot_session",
        api_id=API_ID,
        api_hash=API_HASH,
        phone_number=USERBOT_PHONE,
        sleep_threshold=60,  # wait up to 60 s on FloodWait instead of raising
    )
    return userbot_instance


async def handle_channel_message(client: Client, message):
    """Processes every incoming message on the userbot and applies signal logic."""
    global bot_instance
    try:
        # ── Safety guard ──────────────────────────────────────────────────────
        if not message or not message.chat:
            return

        msg_chat_id = message.chat.id
        chat_username = (getattr(message.chat, 'username', None) or '').lower()
        chat_type = str(getattr(message.chat, 'type', '')).lower()

        # ── Only log channel-type messages at this stage (avoids DM/group spam) ──
        is_channel_msg = 'channel' in chat_type

        sig_settings = await get_signal_settings()

        if not sig_settings:
            if is_channel_msg:
                logger.warning(f"[Userbot] get_signal_settings() returned empty (DB issue?), chat_id={msg_chat_id}")
            return

        is_active = sig_settings.get('is_active', False)
        if not is_active:
            if is_channel_msg:
                logger.info(f"[Userbot] Signal monitor is OFF — ignoring channel msg from chat_id={msg_chat_id}")
            return

        channels = sig_settings.get('channels', [])
        # Fallback to legacy channel_id if channels list is absent
        if not channels and sig_settings.get('channel_id'):
            channels = [{'id': str(sig_settings['channel_id']), 'active': True}]
        active_channels = [c for c in channels if c.get('active', True)]
        if not active_channels:
            if is_channel_msg:
                logger.warning(
                    f"[Userbot] No active channels configured — ignoring msg from chat_id={msg_chat_id}. "
                    f"channels in DB: {channels}"
                )
            return

        # ── Also try the channel a message was forwarded from (linked groups etc.) ──
        fwd_chat_id = None
        fwd_username = ''
        try:
            fwd_origin = getattr(message, 'forward_origin', None)
            if fwd_origin is not None:
                fwd_chat = getattr(fwd_origin, 'chat', None)
                if fwd_chat is not None:
                    fwd_chat_id = fwd_chat.id
                    fwd_username = (getattr(fwd_chat, 'username', None) or '').lower()
        except Exception:
            pass

        matched_channel = None
        for ch in active_channels:
            ch_str = str(ch.get('id', '')).strip()
            # Numeric ID match — direct chat
            try:
                ch_int = int(ch_str)
                if msg_chat_id == ch_int or (fwd_chat_id is not None and fwd_chat_id == ch_int):
                    matched_channel = ch_str
                    break
            except (ValueError, TypeError):
                pass
            # Username match — direct chat or forwarded chat
            ch_bare = ch_str.lstrip('@').lower()
            if (chat_username and ch_bare == chat_username) or \
               (fwd_username and ch_bare == fwd_username):
                matched_channel = ch_str
                break

        if not matched_channel:
            # Only log channel-type messages so logs stay readable
            if is_channel_msg:
                logger.info(
                    f"[Userbot] Channel msg not matched: chat_id={msg_chat_id} username={chat_username!r} "
                    f"fwd_chat_id={fwd_chat_id} — active_channels={[c.get('id') for c in active_channels]}"
                )
            return

        text = message.text or message.caption or ''

        if not text:
            return

        if not is_signal_message(text):
            # ── Non-signal channel message → forward as CHANNEL UPDATE ──────
            try:
                update_text = replace_referral_links(text)
                # Use channel nickname if available, fall back to raw ID
                _ch_obj = next((c for c in active_channels if str(c.get('id','')) == matched_channel), {})
                _ch_label = _ch_obj.get('nickname', '').strip() or matched_channel
                await bot_instance.send_message(
                    OWNER_ID,
                    f"📢 **Channel Update** — **{_ch_label}**\n\n{update_text}",
                    disable_web_page_preview=False,
                )
            except Exception as fwd_err:
                logger.warning(f"[Userbot] Could not forward channel update: {fwd_err}")
            return

        logger.info(f"[Userbot] Signal-like message from channel {matched_channel}: {text[:120]!r}")

        parsed = parse_signal(text)

        if not parsed:
            # Maybe it's a standalone direction message for a stored partial signal
            direction = parse_direction(text)
            if direction:
                pending = sig_settings.get('pending_signal')
                if pending:
                    age = time.time() - pending.get('timestamp', 0)
                    if age < 300:  # 5-minute window
                        amount_confirmed = pending.get('amount_confirmed', True)
                        trade_amount = float(pending.get('amount', DEFAULT_TRADE_AMOUNT))
                        full_signal = {**pending, 'direction': direction}
                        await update_signal_settings({'pending_signal': None})

                        # Log the direction follow-up
                        await log_signal_event('direction', message, pending, direction=direction)

                        # Edit the amount selection message if it exists
                        if bot_instance and pending.get('amount_msg_id'):
                            try:
                                if amount_confirmed:
                                    edit_text = (
                                        f"✅ **Amount confirmed: ${trade_amount:g}**\n"
                                        f"🚀 Executing trade now ({direction.upper()})..."
                                    )
                                else:
                                    edit_text = (
                                        f"⚡ Direction arrived before selection.\n"
                                        f"💵 Using signal amount: **${trade_amount:g}**\n"
                                        f"🚀 Executing trade ({direction.upper()})..."
                                    )
                                await bot_instance.edit_message_text(
                                    chat_id=OWNER_ID,
                                    message_id=pending['amount_msg_id'],
                                    text=edit_text,
                                )
                            except Exception:
                                pass

                        manual_mode = sig_settings.get('manual_trade_mode', False)
                        if manual_mode:
                            # Manual mode: update the pending signal with the arrived direction
                            # and refresh/send the manual trade keyboard highlighting it
                            full_signal['signal_direction'] = direction
                            await update_signal_settings({'pending_signal': full_signal})
                            logger.info(f"[Userbot] Manual mode — direction arrived ({direction}), awaiting user confirmation.")
                            manual_msg_id = pending.get('manual_msg_id') or pending.get('amount_msg_id')
                            if bot_instance:
                                try:
                                    dur_d = full_signal.get('duration', DEFAULT_TRADE_DURATION)
                                    dur_disp_d = f"{dur_d // 60} min" if dur_d >= 60 else f"{dur_d} sec"
                                    dir_icon_d = '🔼 UP (CALL)' if direction == 'call' else '🔽 DOWN (PUT)'
                                    new_text = (
                                        f"🖐 **Manual Trade — Direction Arrived**\n\n"
                                        f"📊 Asset: `{full_signal.get('asset_display', full_signal.get('asset'))}`\n"
                                        f"⏱ Duration: `{dur_disp_d}`\n"
                                        f"💵 Amount: `${float(full_signal.get('amount', DEFAULT_TRADE_AMOUNT)):g}`\n\n"
                                        f"📡 Signal says: **{dir_icon_d}**\n\n"
                                        f"Choose your direction:"
                                    )
                                    if manual_msg_id:
                                        try:
                                            await bot_instance.edit_message_text(
                                                chat_id=OWNER_ID,
                                                message_id=manual_msg_id,
                                                text=new_text,
                                                reply_markup=build_manual_trade_keyboard(direction, sig_settings),
                                            )
                                        except Exception:
                                            await bot_instance.send_message(
                                                OWNER_ID, new_text,
                                                reply_markup=build_manual_trade_keyboard(direction, sig_settings),
                                            )
                                    else:
                                        sent = await bot_instance.send_message(
                                            OWNER_ID, new_text,
                                            reply_markup=build_manual_trade_keyboard(direction, sig_settings),
                                        )
                                        full_signal['manual_msg_id'] = sent.id
                                        await update_signal_settings({'pending_signal': full_signal})
                                except Exception as exc:
                                    logger.warning(f"[Userbot] Could not update manual trade keyboard: {exc}")
                        else:
                            full_signal['received_at'] = time.time()  # direction just arrived
                            await execute_signal_trade(full_signal)
                    else:
                        logger.info("[Userbot] Pending signal expired (>5 min). Discarding.")
                        await update_signal_settings({'pending_signal': None})
                        await log_signal_event('direction_expired', message, direction=direction)
                else:
                    await log_signal_event('unmatched_direction', message, direction=direction)
            return

        if 'direction' in parsed:
            # Full signal
            await log_signal_event('full', message, parsed)
            manual_mode = sig_settings.get('manual_trade_mode', False)
            if manual_mode:
                # Manual mode: show UP/DOWN buttons with the signal direction pre-highlighted
                sig_dir = parsed.get('direction')
                sig_amt_f = float(parsed.get('amount', DEFAULT_TRADE_AMOUNT))
                dur_f = int(parsed.get('duration', DEFAULT_TRADE_DURATION))
                dur_disp_f = f"{dur_f // 60} min" if dur_f >= 60 else f"{dur_f} sec"
                manual_pending = {
                    'asset':              parsed['asset'],
                    'asset_display':      parsed.get('asset_display', parsed['asset']),
                    'duration':           dur_f,
                    'amount':             sig_amt_f,
                    'timestamp':          time.time(),
                    'amount_confirmed':   True,
                    'duration_confirmed': True,
                    'amount_msg_id':      None,
                    'duration_msg_id':    None,
                    'signal_direction':   sig_dir,
                    'manual_msg_id':      None,
                }
                await update_signal_settings({'pending_signal': manual_pending})
                logger.info(f"[Userbot] Manual mode — full signal held for confirmation: {manual_pending}")
                if bot_instance:
                    try:
                        dir_icon = '🔼 UP (CALL)' if sig_dir == 'call' else '🔽 DOWN (PUT)'
                        manual_msg = await bot_instance.send_message(
                            OWNER_ID,
                            f"🖐 **Manual Trade — Confirm Direction**\n\n"
                            f"📊 Asset: `{manual_pending['asset_display']}`\n"
                            f"⏱ Duration: `{dur_disp_f}`\n"
                            f"💵 Amount: `${sig_amt_f:g}`\n\n"
                            f"📡 Signal says: **{dir_icon}**\n\n"
                            f"Choose your direction:",
                            reply_markup=build_manual_trade_keyboard(sig_dir, sig_settings),
                        )
                        manual_pending['manual_msg_id'] = manual_msg.id
                        await update_signal_settings({'pending_signal': manual_pending})
                    except Exception as exc:
                        logger.warning(f"[Userbot] Could not send manual trade keyboard: {exc}")
            else:
                await update_signal_settings({'pending_signal': None})
                parsed['received_at'] = time.time()  # full signal — timer starts now
                await execute_signal_trade(parsed)
        else:
            # Partial signal — store and wait for direction follow-up
            sig_amount = float(parsed.get('amount', DEFAULT_TRADE_AMOUNT))
            ask_dur = sig_settings.get('ask_duration_on_partial', False)
            manual_mode = sig_settings.get('manual_trade_mode', False)
            pending = {
                'asset':              parsed['asset'],
                'asset_display':      parsed.get('asset_display', parsed['asset']),
                'duration':           parsed.get('duration', DEFAULT_TRADE_DURATION),
                'amount':             sig_amount,
                'timestamp':          time.time(),
                'amount_confirmed':   False,
                'amount_msg_id':      None,
                'duration_confirmed': not ask_dur,  # pre-confirmed unless ask is enabled
                'duration_msg_id':    None,
                'signal_direction':   None,   # filled when direction arrives
                'manual_msg_id':      None,
            }
            await update_signal_settings({'pending_signal': pending})
            await log_signal_event('partial', message, parsed)
            logger.info(f"[Userbot] Partial signal stored: {pending}")
            if bot_instance:
                try:
                    balance = await get_owner_balance()
                    tiers = get_amount_tiers(balance)
                    balance_str = f"${balance:,.2f}" if balance is not None else "N/A"
                    dur_min = pending['duration'] // 60
                    dur_display = f"{dur_min} min" if dur_min > 0 else f"{pending['duration']} sec"
                    amt_msg = await bot_instance.send_message(
                        OWNER_ID,
                        f"📨 **Partial Signal Received**\n\n"
                        f"📊 Asset: `{pending['asset_display']}`\n"
                        f"⏱ Duration: `{dur_display}`\n"
                        f"💰 Balance: `{balance_str}`\n\n"
                        f"💵 **Select trade amount** (signal: `${sig_amount:g}`)\n"
                        f"_(Direction arriving soon — choose before it does)_",
                        reply_markup=build_amount_keyboard(sig_amount, tiers),
                    )
                    pending['amount_msg_id'] = amt_msg.id
                    await update_signal_settings({'pending_signal': pending})

                    # Ask for duration override if the feature is enabled
                    if ask_dur:
                        dur_msg = await bot_instance.send_message(
                            OWNER_ID,
                            f"⏱ **Select Trade Duration**\n\n"
                            f"📊 Asset: `{pending['asset_display']}`\n"
                            f"Signal duration: `{dur_display}`\n\n"
                            f"Choose the duration to use for this trade:",
                            reply_markup=build_duration_keyboard(pending['duration']),
                        )
                        pending['duration_msg_id'] = dur_msg.id
                        await update_signal_settings({'pending_signal': pending})

                    # Manual mode: also show UP/DOWN keyboard immediately (no direction yet)
                    if manual_mode:
                        manual_msg = await bot_instance.send_message(
                            OWNER_ID,
                            f"🕹 **Manual Trade \u2014 Choose Direction**\n\n"
                            f"📊 Asset: `{pending['asset_display']}`\n"
                            f"⏱ Duration: `{dur_display}`\n\n"
                            f"_(Direction signal not yet received \u2014 buttons will update when it arrives)_\n\n"
                            f"Choose your direction:",
                            reply_markup=build_manual_trade_keyboard(None, sig_settings),
                        )
                        pending['manual_msg_id'] = manual_msg.id
                        await update_signal_settings({'pending_signal': pending})
                except Exception as exc:
                    logger.warning(f"[Userbot] Could not send amount/duration keyboard: {exc}")

    except Exception as e:
        logger.error(f"[Userbot] Error processing channel message: {e}", exc_info=True)


# ── Signal Bot Commands ───────────────────────────────────────────────────────

async def _send_signal_logs(target, edit: bool = False, limit: int = 20):
    """
    Fetch the most recent signal log entries and send/edit a formatted message.
    target: a Message object (supports reply_text and edit_text).
    """
    if signal_logs_db is None:
        text = "⚠️ Signal log database not available."
    else:
        cursor = signal_logs_db.find(
            {}, sort=[('received_at', -1)], limit=limit
        )
        docs = await cursor.to_list(length=limit)

        if not docs:
            text = "📊 **Signal Timing Log**\n\nNo entries recorded yet."
        else:
            TYPE_ICON = {
                'full':                 '🟢',
                'partial':              '🟡',
                'direction':            '➡️',
                'direction_expired':    '⏰',
                'unmatched_direction':  '❓',
            }
            lines = [f"📊 **Signal Timing Log** _(last {len(docs)}, UTC+5:30)_\n"]
            for doc in docs:
                icon    = TYPE_ICON.get(doc.get('event_type', ''), '🟤')
                recv    = doc.get('received_at')
                sent    = doc.get('provider_sent_at')
                delay   = doc.get('delay_seconds', 0)
                asset   = doc.get('asset_display') or doc.get('asset') or '—'
                etype   = doc.get('event_type', '?')

                recv_str = recv.strftime('%b %d %H:%M:%S') if recv else '?'
                sent_str = sent.strftime('%H:%M:%S') if sent else '?'

                delay_flag = ' ⚠️' if delay > 20 else ('  ✅' if delay <= 5 else '')
                lines.append(
                    f"{icon} `{recv_str}` — **{etype}**\n"
                    f"   📡 Provider: `{sent_str}` | Delay: `{delay:.1f}s`{delay_flag}\n"
                    f"   Asset: `{asset}`"
                    + (f" | Dir: `{doc.get('direction', '—')}`" if doc.get('direction') else "")
                    + "\n"
                )
            text = "\n".join(lines)

    kb = InlineKeyboardMarkup([back_button("signal_status_view")])
    try:
        if edit:
            await target.edit_text(text, reply_markup=kb)
        else:
            await target.reply_text(text, reply_markup=kb, quote=True)
    except Exception as e:
        if "MESSAGE_NOT_MODIFIED" not in str(e):
            logger.warning(f"[SignalLogs] Could not send log message: {e}")


@Client.on_message(filters.command("setchannel") & filters.private)
@owner_only
async def setchannel_command(client: Client, message: Message):
    """Set the Telegram channel/group to monitor for signals."""
    parts = message.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await message.reply_text(
            "**Usage:** `/setchannel <channel_id>`\n\n"
            "Pass the numeric channel ID (negative for groups/channels, e.g. `-1001234567890`).\n"
            "You can also pass a `@username`.\n\n"
            "The userbot must already be a member of that channel.",
            quote=True,
        )
        return

    raw = parts[1].strip()
    # Accept numeric ids (possibly negative) or @username strings
    if raw.lstrip('-').isdigit():
        new_channel = int(raw)
    else:
        new_channel = raw  # Store as username string

    sig_s = await get_signal_settings()
    chs = list(sig_s.get('channels', []))
    ch_id_str = str(new_channel)
    if not any(str(c.get('id', '')) == ch_id_str for c in chs):
        chs.append({'id': ch_id_str, 'active': True})
        action_word = "added"
    else:
        action_word = "already configured"
    await update_signal_settings({'channel_id': new_channel, 'channels': chs})
    logger.info(f"[Signal] Channel {new_channel} {action_word} via /setchannel by user {message.from_user.id}")
    await message.reply_text(
        f"✅ Signal channel `{new_channel}` {action_word}.\n\n"
        f"Use /signalmode to toggle monitoring ON/OFF.",
        quote=True,
    )


@Client.on_message(filters.command("signalmode") & filters.private)
@owner_only
async def signalmode_command(client: Client, message: Message):
    """Toggle signal monitoring on or off."""
    sig_settings = await get_signal_settings()
    current = sig_settings.get('is_active', False)
    new_status = not current

    _chs_active = [c for c in sig_settings.get('channels', []) if c.get('active', True)]
    if new_status and not _chs_active:
        await message.reply_text(
            "⚠️ No active signal channel configured. Add one via the Channels panel or with `/setchannel <channel_id>`.",
            quote=True,
        )
        return

    if new_status and not userbot_instance:
        await message.reply_text(
            "⚠️ Userbot is not running (USERBOT_PHONE not configured or bot not started with userbot).\n"
            "Set `USERBOT_PHONE` in your `.env` and restart the bot.",
            quote=True,
        )
        return

    await update_signal_settings({'is_active': new_status})
    status_text = "🟢 **ON**" if new_status else "🔴 **OFF**"
    channel_id = sig_settings.get('channel_id', 'not set')
    await message.reply_text(
        f"📡 **Signal Mode:** {status_text}\n\n"
        f"📺 Channel: `{channel_id}`\n"
        f"{'Monitoring active — trades will execute automatically when signals arrive.' if new_status else 'Monitoring paused.'}",
        quote=True,
    )


@Client.on_message(filters.command("signalstatus") & filters.private)
@owner_only
async def signalstatus_command(client: Client, message: Message):
    """Show current signal monitoring status and any pending partial signal."""
    sig_settings = await get_signal_settings()
    is_active = sig_settings.get('is_active', False)
    channel_id = sig_settings.get('channel_id', 'Not set')
    pending = sig_settings.get('pending_signal')
    userbot_ok = userbot_instance is not None

    status_icon = "🟢" if is_active else "🔴"
    userbot_icon = "✅" if userbot_ok else "❌"

    text = (
        f"📡 **Signal Monitor Status**\n\n"
        f"{status_icon} Monitoring: **{'ON' if is_active else 'OFF'}**\n"
        f"📺 Channels: {_channels_summary(sig_settings)}\n"
        f"{userbot_icon} Userbot: **{'Running' if userbot_ok else 'Not configured'}**\n"
    )
    if pending:
        age_s = int(time.time() - pending.get('timestamp', 0))
        text += (
            f"\n⏳ **Pending Partial Signal** (waiting for direction):\n"
            f"  Asset: `{pending.get('asset_display', pending.get('asset'))}`\n"
            f"  Amount: `${pending.get('amount')}`\n"
            f"  Duration: `{pending.get('duration', 0) // 60} min`\n"
            f"  Age: `{age_s}s` {'⚠️ (expired — will be discarded)' if age_s > 300 else ''}\n"
        )
    else:
        text += "\nNo pending partial signal.\n"

    text += (
        f"\n**Commands:**\n"
        f"`/setchannel <id>` — set channel\n"
        f"`/signalmode` — toggle ON/OFF\n"
        f"`/signallogs` — view timing log"
    )
    await message.reply_text(text, quote=True)


@Client.on_message(filters.command("signallogs") & filters.private)
@owner_only
async def signallogs_command(client: Client, message: Message):
    """Show the recent signal timing log (UTC+5:30)."""
    await _send_signal_logs(message, edit=False)


@Client.on_message(filters.command("journal") & filters.private)
async def journal_command(client: Client, message: Message):
    """Show today's trading journal."""
    user_id = message.from_user.id
    today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    accounts = await get_user_quotex_accounts(user_id)
    if not accounts:
        await message.reply_text("You have no linked Quotex accounts.", quote=True)
        return
    account_doc_ids = [str(a['_id']) for a in accounts]
    summary = await get_journal_summary(account_doc_ids, today_str)
    entries = summary["entries"]

    journal_text = _build_journal_text(summary, today_str)

    today_dt = datetime.datetime.strptime(today_str, "%Y-%m-%d")
    prev_dt = (today_dt - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    keyboard_rows = [
        [InlineKeyboardButton("◀ Prev Day", callback_data=f"journal_nav:{prev_dt}"),
         InlineKeyboardButton("▶ Today", callback_data="journal_today")],
        [InlineKeyboardButton("✍️ Manual Entry", callback_data=f"journal_add_manual:{today_str}"),
         InlineKeyboardButton("💸 Record Withdrawal", callback_data=f"journal_add_wd:{today_str}")],
        [InlineKeyboardButton("📅 Go to Date", callback_data="journal_pick_date")],
    ]
    await message.reply_text(
        journal_text,
        reply_markup=InlineKeyboardMarkup(keyboard_rows),
        parse_mode=enums.ParseMode.DEFAULT,
        quote=True
    )


# --- Main Function ---
async def _quotex_keepalive():
    """
    Send a Socket.IO tick heartbeat to every active Quotex WebSocket connection
    every 20 seconds.  This is a belt-and-suspenders guard against the server's
    ~30 s idle-close (the primary fix is in ws/client.py on_message).
    """
    while True:
        await asyncio.sleep(20)
        for acct_id, qx_client in list(active_quotex_clients.items()):
            try:
                ws = getattr(qx_client, 'websocket', None)  # WebSocketApp
                if ws:
                    ws.send('42["tick"]')
            except Exception as exc:
                logger.debug(f"[KeepAlive] {acct_id}: {exc}")


# Track consecutive failed connection cycles per account for the health monitor
_ws_fail_ticks: dict = {}


async def _quotex_ws_health_monitor():
    """
    Detect when a Quotex WebSocket is stuck in a Cloudflare 403 reconnect loop
    and automatically re-authenticate to get fresh cookies.

    Every 30 s it checks each cached client.  If the websocket thread is alive
    but the connection flag shows disconnected for 2+ consecutive checks
    (~60 s), it tears down the old WebSocket, runs ensure_session() for fresh
    __cf_clearance cookies, then reconnects.
    """
    await asyncio.sleep(60)  # let the bot settle before first check
    while True:
        await asyncio.sleep(30)
        for acct_id, qx_client in list(active_quotex_clients.items()):
            try:
                from pyquotex import global_value as _gv

                ws_thread_alive = (
                    hasattr(qx_client, 'websocket_thread') and
                    qx_client.websocket_thread is not None and
                    qx_client.websocket_thread.is_alive()
                )
                ws_connected = _gv.check_websocket_if_connect == 1

                if ws_thread_alive and not ws_connected:
                    # Thread is alive but no active connection → likely in a
                    # Cloudflare 403 reconnect loop.
                    _ws_fail_ticks[acct_id] = _ws_fail_ticks.get(acct_id, 0) + 1
                    logger.warning(
                        f"[WSHealth] {acct_id}: WS thread alive but disconnected "
                        f"(tick {_ws_fail_ticks[acct_id]})."
                    )

                    if _ws_fail_ticks[acct_id] >= 2:
                        # Stuck for ~60 s → attempt full re-auth + reconnect
                        logger.warning(
                            f"[WSHealth] {acct_id}: stuck for multiple cycles — "
                            "re-authenticating and reconnecting ..."
                        )
                        _ws_fail_ticks[acct_id] = 0

                        # Fetch account creds from DB
                        account_details = await get_quotex_account_details(acct_id)
                        if not account_details:
                            logger.error(f"[WSHealth] {acct_id}: could not fetch account details.")
                            continue

                        email = account_details["email"]
                        password = account_details["password"]
                        session_path = f"sessions/{acct_id}"

                        # Delete the stale session.json so pyquotex does a
                        # clean native HTTP login on the next connect attempt.
                        _stale_p = Path(f"{session_path}/session.json")
                        if _stale_p.exists():
                            try:
                                _stale_p.unlink()
                                logger.warning(
                                    f"[WSHealth] {acct_id}: deleted stale session.json "
                                    "(WS stuck in 403 loop — will re-auth via pyquotex native login)."
                                )
                            except Exception as _del_err:
                                logger.warning(
                                    f"[WSHealth] {acct_id}: could not delete stale "
                                    f"session.json: {_del_err}"
                                )

                        # Evict cache — next trade signal or keepalive will
                        # fully reconnect using pyquotex's own HTTP auth.
                        try:
                            await qx_client.close()
                        except Exception:
                            pass
                        active_quotex_clients.pop(acct_id, None)
                        logger.info(
                            f"[WSHealth] {acct_id}: evicted stale client. "
                            "Will reconnect (native re-auth) on next signal."
                        )
                else:
                    # Connection looks healthy — reset counter
                    _ws_fail_ticks[acct_id] = 0

            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.debug(f"[WSHealth] {acct_id}: monitor error: {exc}")


async def preconnect_all_accounts():
    """
    At startup, Playwright-authenticate and pre-open WebSocket connections
    for all owner Quotex accounts so signal execution is instant (0-3 s).
    """
    if quotex_accounts_db is None:
        logger.warning("[Startup] DB not ready — skipping account pre-connect.")
        return
    accounts = await quotex_accounts_db.find({"user_id": OWNER_ID}).to_list(length=None)
    if not accounts:
        logger.info("[Startup] No Quotex accounts found for owner — nothing to pre-connect.")
        return
    logger.info(f"[Startup] Pre-connecting {len(accounts)} Quotex account(s) for owner {OWNER_ID} ...")
    for acct in accounts:
        account_doc_id = str(acct["_id"])
        email = acct.get("email", "unknown")
        try:
            client, msg = await get_quotex_client(OWNER_ID, account_doc_id, "startup_preconnect")
            if client:
                logger.info(f"[Startup] Connected {email} — {msg}")
            else:
                logger.warning(f"[Startup] Could not connect {email} — {msg}")
        except Exception as exc:
            logger.error(f"[Startup] Error pre-connecting {email}: {exc}", exc_info=True)


async def _userbot_watchdog(ubot: Client):
    """
    Periodically checks the userbot connection health and performs a clean
    stop/start recovery if it has gone dead (e.g. after a Telegram DC dropped
    the TCP connection and the concurrent-restart race corrupted the session).
    """
    global userbot_instance
    INTERVAL = 60        # seconds between health checks
    PROBE_TIMEOUT = 20   # seconds to wait for get_me() before declaring dead
    await asyncio.sleep(INTERVAL)  # initial grace period after startup
    while True:
        try:
            # A lightweight API call — throws if the connection is broken.
            await asyncio.wait_for(ubot.get_me(), timeout=PROBE_TIMEOUT)
        except asyncio.CancelledError:
            break
        except Exception as probe_err:
            logger.warning(f"[Userbot] Watchdog: health check failed ({probe_err}), attempting recovery...")

            # If a restart is already underway (from a previous watchdog cycle
            # or from pyrogram internals), don't pile on.
            if _ubot_restart_lock.locked():
                logger.info("[Userbot] Watchdog: restart already in progress, skipping cycle.")
                await asyncio.sleep(INTERVAL)
                continue

            async with _ubot_restart_lock:
                # Re-check connection after acquiring the lock — it may have
                # been restored by the time we got here.
                try:
                    await asyncio.wait_for(ubot.get_me(), timeout=10)
                    logger.info("[Userbot] Watchdog: connection restored on its own, skipping restart.")
                    await asyncio.sleep(INTERVAL)
                    continue
                except Exception:
                    pass

                # Full stop → start cycle to get a clean connection.
                try:
                    await asyncio.wait_for(ubot.stop(), timeout=10)
                except Exception:
                    pass
                await asyncio.sleep(3)
                try:
                    await ubot.start()
                    userbot_instance = ubot
                    logger.info("[Userbot] Watchdog: userbot recovered successfully.")
                except Exception as start_err:
                    logger.error(f"[Userbot] Watchdog: recovery failed: {start_err}", exc_info=True)
                    await asyncio.sleep(30)
        await asyncio.sleep(INTERVAL)


async def run_bot():
    global bot_instance, main_event_loop
    await setup_database()

    app = Client(
        "QuotexBot",
        api_id=API_ID,
        api_hash=API_HASH,
        bot_token=BOT_TOKEN
    )

    # Add handlers using the proper pyrogram.handlers classes
    from pyrogram.handlers import MessageHandler, CallbackQueryHandler

    app.add_handler(MessageHandler(start_command,
        (filters.command(["start", "hello", "menu"]) | filters.regex(r'^(hi|/)$', re.IGNORECASE))
        & filters.private
    ))
    app.add_handler(MessageHandler(help_command, filters.command("help") & filters.private))
    app.add_handler(MessageHandler(broadcast_command_handler, filters.command("broadcast") & filters.private))  # Has own perm check
    # Signal trading commands
    app.add_handler(MessageHandler(setchannel_command, filters.command("setchannel") & filters.private))
    app.add_handler(MessageHandler(signalmode_command, filters.command("signalmode") & filters.private))
    app.add_handler(MessageHandler(signalstatus_command, filters.command("signalstatus") & filters.private))
    app.add_handler(MessageHandler(signallogs_command, filters.command("signallogs") & filters.private))
    app.add_handler(MessageHandler(journal_command, filters.command("journal") & filters.private))
    app.add_handler(CallbackQueryHandler(callback_query_handler))
    app.add_handler(MessageHandler(message_handler, filters.private))  # Handles replies and non-command text

    # Build the userbot (MTProto user session for channel monitoring)
    ubot = build_userbot()

    try:
        await app.start()
        bot_instance = app # Set global instance after start
        main_event_loop = asyncio.get_running_loop()
        bot_info = await app.get_me()
        logger.info(f"Bot started as @{bot_info.username} (ID: {bot_info.id})")

        # Pre-connect all owner accounts NOW that bot_instance is set.
        # Sessions were already fetched via Playwright — this just opens the WebSocket.
        asyncio.create_task(preconnect_all_accounts())

        # Start the userbot if configured
        if ubot:
            try:
                ubot.add_handler(
                    __import__('pyrogram.handlers', fromlist=['MessageHandler']).MessageHandler(
                        handle_channel_message,
                        filters.all
                    )
                )
                await ubot.start()
                logger.info("[Userbot] Userbot started and listening for signals.")
                asyncio.create_task(_userbot_watchdog(ubot))
            except Exception as ub_err:
                logger.error(f"[Userbot] Failed to start userbot: {ub_err}", exc_info=True)

        logger.info("Bot is running... Press CTRL+C to stop.")
        # Start Quotex WebSocket keep-alive heartbeat task
        asyncio.create_task(_quotex_keepalive())
        # Start Quotex WebSocket health monitor (detects + recovers from 403 loops)
        asyncio.create_task(_quotex_ws_health_monitor())
        # Keep the main thread alive (Pyrogram handles the event loop)
        await asyncio.Event().wait() # Keeps running until interrupted

    except KeyboardInterrupt:
        logger.warning("Shutdown signal received (KeyboardInterrupt)...")
    except Exception as e:
        logger.error(f"An error occurred during bot execution: {e}", exc_info=True)
    finally:
        if app.is_connected:
            # Stop userbot if running
            if ubot and ubot.is_connected:
                try:
                    await ubot.stop()
                    logger.info("[Userbot] Userbot stopped.")
                except Exception:
                    pass

            logger.info("Stopping bot...")
            await app.stop()
            logger.info("Bot stopped.")

if __name__ == "__main__":
     # Basic check for config existence might be needed here if not using Env Vars
    print("Starting Quotex Trading Bot...")
    # Run the asynchronous main function
    try:
        asyncio.run(run_bot())
    except RuntimeError as e:
         # Handle potential loop issues on exit in some environments
        if "Event loop is closed" in str(e):
            print("Event loop closed.")
        else:
            raise e