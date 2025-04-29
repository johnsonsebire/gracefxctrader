# -*- coding: utf-8 -*-
import os
import sys
import time
import concurrent.futures
import asyncio
import logging
import datetime
import re # For PIN detection
from pathlib import Path
import builtins
from unittest.mock import patch
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

try:
    import motor.motor_asyncio
except ImportError:
    print("Error: Motor not found. Install it: pip install motor")
    sys.exit(1)

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
    from quotexapi.stable_api import Quotex
    from quotexapi.utils.processor import get_color # Optional
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

# --- Configuration (Load from environment variables or a config file) ---
# It's better practice to load these from environment or a separate config.py
# For simplicity in a single file as requested:
# Load environment variables from a .env file
load_dotenv()

API_ID = int(os.getenv("API_ID", 12345678))  # Replace with a default value if needed
API_HASH = os.getenv("API_HASH", "your_api_hash")
BOT_TOKEN = os.getenv("BOT_TOKEN", "your_bot_token")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
OWNER_ID = int(os.getenv("OWNER_ID", 987654321))  # Replace with a default value if needed

# Basic Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("pyrofork").setLevel(logging.WARNING) # Reduce pyrogram verbosity

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
db = None  # Database client
main_event_loop = None # <<< ADD THIS GLOBAL VARIABLE
users_db = None # Collection for users, roles, basic settings
quotex_accounts_db = None # Collection for Quotex credentials
trade_settings_db = None # Collection for trade settings per user/account

# Temporary storage for OTP requests: {user_id: {'qx_client': qx_client_instance, 'event': asyncio.Event()}}
active_otp_requests: Dict[int, Dict[str, Any]] = {}

# Temporary storage for ongoing user actions (e.g., waiting for broadcast message)
user_states: Dict[int, str] = {} # e.g., {user_id: "waiting_broadcast_message"}

# Default Quotex Settings (can be overridden from DB)
DEFAULT_TRADE_AMOUNT = 5
DEFAULT_TRADE_DURATION = 60 # For Timer/Time mode number
DEFAULT_TRADE_MODE = "TIMER" # 'TIMER' or 'TIME'
DEFAULT_CANDLE_SIZE = 60
DEFAULT_SERVICE_STATUS = False # Trading Off by default

MARTINGALE_MULTIPLIER = 2.0
MAX_CONSECUTIVE_LOSSES = 3
COOLDOWN_MINUTES = 3

# --- Database Setup ---
async def setup_database():
    """Initializes MongoDB connection and collections."""
    global db, users_db, quotex_accounts_db, trade_settings_db
    try:
        client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
        db = client['quotexTraderBot'] # Database name
        users_db = db['users']
        quotex_accounts_db = db['quotex_accounts']
        trade_settings_db = db['trade_settings']
        # Create indexes for faster lookups
        await users_db.create_index("user_id", unique=True)
        await quotex_accounts_db.create_index([("user_id", 1), ("email", 1)], unique=True)
        await trade_settings_db.create_index("account_doc_id", unique=True) # Link to quotex account document
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
                     f"**Prompt:**\n`{prompt}`\n\n"
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
         # ... (Existing cache logic) ...
         logger.info(f"Reusing cached client for {account_doc_id}")
         return active_quotex_clients[account_doc_id], "Reused existing client (cache)."

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

        # Create instance UNDER the patch
        logger.info(f"Creating new Quotex client instance for {email} UNDER PATCH")
        qx_client = Quotex(email=email, password=password)

        # Add context *before* connect call
        logger.info(f"Adding user {user_id} to active_otp_requests BEFORE connect (under patch).")
        if not bot_instance: raise ConnectionAbortedError("Bot instance not available for OTP context.")
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

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(connect_in_thread)
            try:
                connection_check, connection_reason = await asyncio.wait_for(
                    asyncio.wrap_future(future),  # Wrap the thread future for asyncio compatibility
                    timeout=180.0
                )
            except asyncio.TimeoutError:
                logger.error("Connection attempt timed out.")
                connection_check, connection_reason = False, "Timeout during connection"
            except Exception as e:
                logger.error(f"Error during connection in thread: {e}", exc_info=True)
                connection_check, connection_reason = False, str(e)
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
                qx_client.change_account(account_mode)
                logger.info(f"Switched Quotex account {email} to {account_mode} mode.")
            except Exception as e_mode:
                logger.error(f"Failed to switch account {email} to {account_mode}: {e_mode}", exc_info=True)
                active_quotex_clients[account_doc_id] = qx_client
                return qx_client, f"Connected but failed to switch to {account_mode} mode."

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
        [InlineKeyboardButton("➕ Add Quotex Account", callback_data="quotex_add")],
        [InlineKeyboardButton("👤 My Quotex Accounts", callback_data="quotex_list")],
    ]
    # Dynamic buttons based on role
    # Add settings etc. later
    keyboard.append([InlineKeyboardButton("⚙️ Settings", callback_data="settings_main")])
    keyboard.append([InlineKeyboardButton("Trading Dashboard", callback_data="trade_dashboard")]) # Maybe
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
    trading_status = "ON" if settings.get('service_status', False) else "OFF"
    toggle_trading_text = f"🔴 Stop Trading" if trading_status == "ON" else f"🟢 Start Trading"

    keyboard = [
         [
            InlineKeyboardButton("📊 Get Profile", callback_data=f"qx_profile:{account_doc_id}"),
            InlineKeyboardButton("💰 Get Balance", callback_data=f"qx_balance:{account_doc_id}")
        ],
        [
             InlineKeyboardButton("💱 Manage Assets", callback_data=f"asset_manage:{account_doc_id}"),
             InlineKeyboardButton(f"Mode: {settings.get('trade_mode', 'N/A')}", callback_data=f"set_tmode:{account_doc_id}"),
        ],
        [
            InlineKeyboardButton(f"Candle: {settings.get('candle_size', 'N/A')}s", callback_data=f"set_csize:{account_doc_id}"),
             InlineKeyboardButton(f"Acct: {settings.get('account_mode', 'N/A')}", callback_data=f"set_amode:{account_doc_id}"),

        ],
        [
             InlineKeyboardButton(toggle_trading_text, callback_data=f"toggle_trade:{account_doc_id}"),
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
        back_button("main_menu")
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

@Client.on_message(filters.command("start") & filters.private)
async def start_command(client: Client, message: Message):
    global bot_instance # Store the client instance
    if not bot_instance: bot_instance = client

    user_id = message.from_user.id
    await add_user_if_not_exists(user_id)
    logger.info(f"User {user_id} ({message.from_user.first_name}) started the bot.")

    welcome_text = f"👋 Welcome, {message.from_user.mention}!\n\n" \
                   f"This bot helps you interact with your Quotex account(s).\n\n" \
                   f"Use the buttons below to navigate."

    await message.reply_text(
        welcome_text,
        reply_markup=await main_menu_keyboard(user_id),
        quote=True
    )

@Client.on_message(filters.command("help") & filters.private)
async def help_command(client: Client, message: Message):
    # Add more detailed help information here
    help_text = """
    **ℹ️ Bot Help & Information**

    This bot allows you to:
    - Add and manage multiple Quotex accounts.
    - Check account profile and balance.
    - Manage assets for trading.
    - Configure trade settings (Mode, Candle Size, Account Type).
    - Toggle automated trading (Premium feature, requires setup).
    - (Admin) Manage users and broadcast messages.

    **Key Features:**
    - **➕ Add Quotex Account:** Securely add your credentials (Requires 2FA/PIN verification via bot).
    - **👤 My Quotex Accounts:** View and manage your linked accounts and their specific settings.
    - **⚙️ Settings:** Configure bot or global preferences (if applicable).
    - **👑 Admin Panel:** (For Owner/Sudo) Access user management and broadcast tools.

    **Important Notes:**
    - **Security:** While we try to be secure, storing credentials always has risks. Be cautious.
    - **Quotex API:** This bot uses the `pyquotex` library, which interacts with Quotex in ways that might be unofficial. Use at your own risk. API changes can break functionality.
    - **Trading:** Automated trading involves significant financial risk. Ensure you understand the strategy and risks before enabling it.

    Use the buttons or contact the owner if you need further assistance.
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
                    profile = await qx_client.get_profile() # Profile often includes both balances
                    if profile:
                        #current_mode = qx_client.account_type # Check instance mode
                        #balance_val = profile.live_balance if current_mode == 'REAL' else profile.demo_balance
                        text += f"**🆔 ID: `{profile.profile_id}`**\n"
                        text += f"**💰 Current Balance:**\n\n"
                        text += f" - 🪙 Demo: `{float(profile.demo_balance)}`\n"
                        text += f" - 💵 Real: `{float(profile.live_balance):.2f}`\n"
                        text += f"**👤 User Name: {profile.nick_name}**\n"
                        text += f"**🖼️ Avatar: {profile.avatar}**\n"
                        text += f"**🌍 Country: {profile.country_name}**\n"
                    else:
                        text += "❌ Failed to retrieve profile details."
                elif action == "balance":
                    # Get current settings for account mode before fetching balance
                    #settings = await get_or_create_trade_settings(account_doc_id)
                    #current_mode = settings.get("account_mode", "PRACTICE")
                    # Balance from profile is often sufficient and quicker
                    #balance = await qx_client.get_balance() # Uses currently set mode

                    profile = await qx_client.get_profile() # Profile often includes both balances
                    if profile:
                        #current_mode = qx_client.account_type # Check instance mode
                        #balance_val = profile.live_balance if current_mode == 'REAL' else profile.demo_balance
                        text += f"**💰 Current Balance:**\n\n"
                        text += f" - Demo: `{profile.demo_balance}`\n"
                        text += f" - Real: `{profile.live_balance}`"
                    else:
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
                     active_quotex_clients[account_doc_id].change_account(new_mode)
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


        # Example for toggle_trade:
    elif data.startswith("toggle_trade:"):
        account_doc_id = data.split(":")[1]
        settings = await get_or_create_trade_settings(account_doc_id)
        current_status = settings.get('service_status', False)
        new_status = not current_status

        action_result = False
        if new_status: # Turning ON
            # --- ADD PREMIUM CHECK ---
            if not await is_premium_user(user_id):
                await callback_query.answer("Trading requires Premium/Sudo.", show_alert=True)
                # Ensure status is OFF in DB if check fails
                await update_trade_setting(account_doc_id, {"service_status": False})
                # No need to refresh keyboard here as nothing should change
                return # Stop processing
            # --- END PREMIUM CHECK ---

            action_result = await start_trading_task(user_id, account_doc_id) # This now also updates DB and checks assets
            status_text = "started" if action_result else "failed to start (check logs/assets)"
            answer_text = f"Trading service {status_text}"
            final_db_status = action_result # If started, status is ON
        else: # Turning OFF
            await stop_trading_task(account_doc_id) # This now also updates DB to OFF
            status_text = "stopped"
            answer_text = f"Trading service {status_text}"
            final_db_status = False # Status is OFF

        await callback_query.answer(answer_text)

        # Refresh the management screen - Need to fetch settings *again* after task function might have changed them
        account_details = await get_quotex_account_details(account_doc_id)
        refreshed_settings = await get_or_create_trade_settings(account_doc_id) # Get latest state
        final_status_text = "ON" if refreshed_settings.get("service_status", False) else "OFF" # Display actual DB status

        await message.edit_text(
            f"Managing account: **{account_details.get('email', 'N/A')}**\nTrading is now **{final_status_text}**.",
            reply_markup=account_management_keyboard(account_doc_id, refreshed_settings) # Use refreshed settings
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
        can_trade_count = 0 # Count accounts potentially eligible for trading

        for acc in accounts:
            account_doc_id = str(acc['_id'])
            email = acc['email']
            settings = await get_or_create_trade_settings(account_doc_id)

            status_icon = "🟢 ON" if settings.get('service_status', False) else "🔴 OFF"
            acc_mode = settings.get('account_mode', 'N/A')
            trade_mode = settings.get('trade_mode', 'N/A')
            can_trade_count += 1 # Assume all accounts are eligible for controls here initially

            dashboard_text += (
                f"👤 **Account:** `{email}`\n"
                f"   ┣ Status: **{status_icon}**\n"
                # Uncomment if you want balance here (slower loading)
                # f"   ┣ Balance: Fetching...\n" # Add logic later if needed
                f"   ┣ Acct Mode: `{acc_mode}`\n"
                f"   ┗ Trade Mode: `{trade_mode}`\n\n"
            )
            # Add a button to manage this specific account
            keyboard_rows.append(
                [InlineKeyboardButton(f"⚙️ Manage {email}", callback_data=f"qx_manage:{account_doc_id}")]
            )

        # --- Add Global Action Buttons (Optional) ---
        if can_trade_count > 0:
            # Add start/stop all only if there are accounts
             action_buttons = [
                InlineKeyboardButton("🚀 Start All Trading", callback_data="trade_start_all"),
                InlineKeyboardButton("🛑 Stop All Trading", callback_data="trade_stop_all")
             ]
             # You might want to add these on separate rows for clarity if many accounts
             keyboard_rows.append(action_buttons)


        keyboard_rows.append(back_button("main_menu"))
        await callback_query.message.edit_text(
            dashboard_text,
            reply_markup=InlineKeyboardMarkup(keyboard_rows),
            parse_mode=enums.ParseMode.DEFAULT
        )

    # --- Place this inside the Client.on_callback_query() handler function ---

    # (...) other callback handlers like qx_manage, set_tmode, etc.

    elif data == "trade_start_all" or data == "trade_stop_all":
        # Determine the action based on callback data
        action = "start" if data == "trade_start_all" else "stop"
        new_status = (action == "start") # True if starting, False if stopping
        action_verb_present = "Starting" if new_status else "Stopping"
        action_verb_past = "started" if new_status else "stopped"

        # Let the user know we are working on it
        await callback_query.answer(f"{action_verb_present} trading for all eligible accounts...")
        msg = await callback_query.message.edit_text(f"⏳ {action_verb_present} trading for your account(s)...") # Edit original message

        # --- Premium Check (Only necessary for starting) ---
        is_user_eligible = await is_premium_user(user_id)
        if action == "start" and not is_user_eligible:
            logger.warning(f"User {user_id} attempted 'Start All' without Premium/Sudo.")
            await msg.edit_text(
                f"⛔️ Starting all trading services requires Premium or Sudo privileges.",
                reply_markup=InlineKeyboardMarkup([back_button("trade_dashboard")]) # Back to dashboard
            )
            return # Stop processing this action
        # --- End Premium Check ---

        # Get all accounts for this user
        accounts = await get_user_quotex_accounts(user_id)
        if not accounts:
            await msg.edit_text("You have no Quotex accounts configured to manage.", reply_markup=InlineKeyboardMarkup([back_button("trade_dashboard")]))
            return

        # Initialize counters for results
        success_count = 0
        fail_start_no_assets = 0 # Specific counter for start failure due to missing assets

        # Loop through each account and apply the action
        for acc in accounts:
            account_doc_id = str(acc['_id'])
            email = acc['email'] # Get email for logging clarity

            try:
                if action == "start":
                    # start_trading_task already includes the Premium check and asset check
                    started = await start_trading_task(user_id, account_doc_id)
                    if started:
                        success_count += 1
                    else:
                        # If starting failed, check if it was due to no assets
                        settings = await get_or_create_trade_settings(account_doc_id)
                        if not settings.get("assets"):
                            fail_start_no_assets += 1
                            logger.info(f"Start failed for {email} (ID: {account_doc_id}): No assets configured.")
                        else:
                            # Log other potential start failures if needed (start_trading_task handles logging too)
                            logger.warning(f"Start failed for {email} (ID: {account_doc_id}) for other reason (check logs).")

                else: # action == "stop"
                    # stop_trading_task handles turning off service in DB and cancelling the task
                    stopped = await stop_trading_task(account_doc_id)
                    # 'stopped' returns True if a running task was actually cancelled
                    if stopped:
                       success_count += 1
                       logger.info(f"Stopped running task for {email} (ID: {account_doc_id}).")
                    # else: task wasn't running or found, no need to increment count

            except Exception as e:
                logger.error(f"Error processing {action} action for {email} (ID: {account_doc_id}): {e}", exc_info=True)
                # Notify user? For now, just log it.

            await asyncio.sleep(0.1) # Brief pause between accounts to avoid overwhelming system/API

        # --- Build the Result Summary ---
        result_text = f"✅ **Action Complete**\n\n"
        result_text += f"Attempted to **{action.upper()}** trading for eligible accounts.\n"
        if action == "start":
            result_text += f"- Successfully started for: **{success_count}** account(s)\n"
            if fail_start_no_assets > 0:
                result_text += f"- Failed (No Assets): **{fail_start_no_assets}** account(s)\n"
            # Add line for premium skips if that check was moved inside the loop (currently it's outside)
        else: # stop
            result_text += f"- Stopped running tasks for: **{success_count}** account(s)\n"
            # Note: It might say 0 stopped if no tasks were actually running

        # --- Refresh the Dashboard View ---
        try:
            # Fetch accounts and their LATEST statuses again
            accounts_refresh = await get_user_quotex_accounts(user_id)
            dashboard_text_refresh = "📊 **Trading Dashboard Overview** (Refreshed)\n\n"
            keyboard_rows_refresh = []
            can_trade_count_refresh = 0

            if not accounts_refresh: # Should not happen if loop ran, but safe check
                dashboard_text_refresh += "No accounts found."
            else:
                for acc_refresh in accounts_refresh:
                    acc_doc_id_ref = str(acc_refresh['_id'])
                    email_ref = acc_refresh['email']
                    settings_ref = await get_or_create_trade_settings(acc_doc_id_ref) # Fetch fresh settings

                    status_icon_ref = "🟢 ON" if settings_ref.get('service_status', False) else "🔴 OFF"
                    acc_mode_ref = settings_ref.get('account_mode', 'N/A')
                    trade_mode_ref = settings_ref.get('trade_mode', 'N/A')
                    can_trade_count_refresh += 1 # Count accounts displayed

                    dashboard_text_refresh += (
                        f"👤 **Account:** `{email_ref}`\n"
                        f"   ┣ Status: **{status_icon_ref}**\n"
                        f"   ┣ Acct Mode: `{acc_mode_ref}`\n"
                        f"   ┗ Trade Mode: `{trade_mode_ref}`\n\n"
                    )
                    # Add button to manage this specific account
                    keyboard_rows_refresh.append(
                        [InlineKeyboardButton(f"⚙️ Manage {email_ref}", callback_data=f"qx_manage:{acc_doc_id_ref}")]
                    )

            # Re-add global action buttons if there are accounts
            if can_trade_count_refresh > 0:
                action_buttons_ref = [
                    InlineKeyboardButton("🚀 Start All Trading", callback_data="trade_start_all"),
                    InlineKeyboardButton("🛑 Stop All Trading", callback_data="trade_stop_all")
                 ]
                keyboard_rows_refresh.append(action_buttons_ref)

            # Add the back button
            keyboard_rows_refresh.append(back_button("main_menu"))

            # Combine the result text and the refreshed dashboard
            final_text = result_text + "\n---\n" + dashboard_text_refresh

            # Edit the message that showed "in progress" with the final summary and keyboard
            await msg.edit_text(
                final_text,
                reply_markup=InlineKeyboardMarkup(keyboard_rows_refresh),
                parse_mode=enums.ParseMode.DEFAULT
            )
        except Exception as refresh_err:
            logger.error(f"Error refreshing dashboard after {action} all: {refresh_err}", exc_info=True)
            # If refresh fails, show the results but indicate refresh error
            await msg.edit_text(result_text + "\n\n⚠️ _Could not refresh dashboard view._", reply_markup=InlineKeyboardMarkup([back_button("main_menu")]))

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
            f"   - Role: **{user_role}**\n\n"
            f"➡️ Most trading configurations (Assets, Mode, Candle Size, Start/Stop) "
            f"are managed individually for each linked account via the "
            f"➡️ **My Quotex Accounts** section."
        )

        keyboard_rows = [
            # Add buttons for future settings here, e.g.:
            # [InlineKeyboardButton("🔔 Notification Preferences (NYI)", callback_data="settings_notifications")],
            # [InlineKeyboardButton("🌐 Language (NYI)", callback_data="settings_language")],
        ]

        keyboard_rows.append(back_button("main_menu")) # Always provide a way back

        await callback_query.message.edit_text(
            settings_text,
            reply_markup=InlineKeyboardMarkup(keyboard_rows),
            parse_mode=enums.ParseMode.DEFAULT
        )

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
                 await message.reply_text(f"Action ({state.split(':')[0]}) cancelled.", quote=True)
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
             if bot_instance: # Check if client exists (should always here)
                  # Create a dummy CallbackQuery to call the handler again
                 dummy_cb = CallbackQuery(
                        id="dummy_callback_id", # This needs a real ID structure maybe? Using dummy.
                        from_user=message.from_user,
                        chat_instance=str(message.chat.id), # Needs instance value
                        message=message, # Pass original message? Maybe the one with buttons
                        data=f"asset_manage:{account_doc_id}",
                         # Following needs correct structure if required by handler
                         #game_short_name=None,
                         #inline_message_id=None,
                    )
                    # Need to find the message with the buttons to edit
                 try:
                    # This is tricky - need reference to the button message. Assume last bot message
                     await bot_instance.edit_message_text(message.chat.id, message.id -1 , "Refreshing assets...", ) # Example idea - often fails
                     await asyncio.sleep(0.5) # Let edit register
                     #await callback_query_handler(client, dummy_cb) # Problem: Need real CB ID and structure
                     # Safer: just send back to main account management
                     acc_details = await get_quotex_account_details(account_doc_id)
                     settings_reloaded = await get_or_create_trade_settings(account_doc_id)
                     await message.reply_text("Navigating back to account management...", reply_markup=account_management_keyboard(account_doc_id, settings_reloaded))

                 except Exception as edit_err:
                      logger.error(f"Could not auto-navigate after asset add: {edit_err}")
                      await message.reply_text("Asset added. Please navigate back manually if needed.")


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


    # --- Placeholder for other states if needed ---

# --- Trading Loop Logic (Conceptual - Needs Careful Implementation) ---
# This is highly complex to manage per user account via a bot.
# Consider if manual trade initiation is sufficient first.

active_trading_tasks: Dict[str, asyncio.Task] = {} # {account_doc_id: task_instance}

# --- REPLACE THE EXISTING run_trading_loop_for_account FUNCTION ---

async def _get_candle_direction(qx_client: Quotex, asset_name: str, candle_size: int) -> Optional[str]:
    """
    Fetches the last completed candle and determines its direction ('call', 'put', 'doji').
    Internal helper for the trading loop.
    """
    if not qx_client or not qx_client.check_connect: # Should check connection status appropriately
        logger.warning(f"[{asset_name}] QX client not connected in _get_candle_direction.")
        return None
    try:
        end_time = time.time()
        offset_seconds = 0 # Usually fetches last ~1min needed for 60s candle check
        # Important: Use the candle_size passed from settings
        candles = await qx_client.get_candles(asset_name, end_time, offset_seconds, candle_size) # Request 2 candles to better identify last completed one
        # Note: `amount` and `end_time` args might vary based on specific pyquotex version/method used

        if candles and isinstance(candles, list) and len(candles) > 0:
             # Often the last candle is incomplete, second-to-last is the target
             target_candle = None
             if len(candles) > 1 and all(k in candles[-2] for k in ['open', 'close']):
                  target_candle = candles[-1] # Prefer second to last
             elif len(candles) >= 1 and all(k in candles[-1] for k in ['open', 'close']):
                 target_candle = candles[-1] # Use last if second to last invalid or only one received

             if target_candle:
                open_price = target_candle['open']
                close_price = target_candle['close']
                logger.debug(f"[{asset_name}] Candle Check: Open={open_price}, Close={close_price}")
                if close_price > open_price: return 'call'
                elif close_price < open_price: return 'put'
                else: return 'doji'
             else:
                  logger.warning(f"[{asset_name}] Could not identify valid candle structure from response: {candles}")
                  return None
        else:
            logger.warning(f"[{asset_name}] No candle data received or empty list. Response: {candles}")
            return None
    except Exception as e:
        logger.error(f"[{asset_name}] Error fetching candle data: {e}", exc_info=True)
        return None

async def _check_asset_open_and_get_name(qx_client: Quotex, asset_name_original: str) -> Optional[str]:
    """Checks if asset or its OTC variant is open, returns the name of the open asset or None."""
    try:
        # Check original asset first
        checked_name, data = await qx_client.get_available_asset(asset_name_original, force_open=False)
        if checked_name and data and data[2]:
            logger.info(f"[{asset_name_original}] Asset is open.")
            return checked_name # Return the name API confirmed (might be same or slightly different case)

        # If original closed and not already OTC, try OTC
        if not asset_name_original.endswith("_otc"):
            otc_asset = asset_name_original + "_otc"
            logger.info(f"[{asset_name_original}] Closed. Trying {otc_asset}...")
            checked_name_otc, data_otc = await qx_client.get_available_asset(otc_asset, force_open=True) # Force open check for OTC
            if checked_name_otc and data_otc:
                logger.info(f"[{otc_asset}] Asset is open (OTC).")
                return checked_name_otc
            else:
                logger.warning(f"[{asset_name_original}/{otc_asset}] Both closed or unavailable.")
                return None
        else:
            # Original was OTC and it's closed
            logger.warning(f"[{asset_name_original}] Asset (OTC) is closed or unavailable.")
            return None

    except Exception as e:
        logger.error(f"[{asset_name_original}] Error checking asset availability: {e}", exc_info=True)
        return None


async def run_trading_loop_for_account(user_id: int, account_doc_id: str):
    """The background task function that runs the trading logic for one account."""
    logger.info(f"[Trading Task {account_doc_id}]: Starting loop for User {user_id}")
    is_first_run = True # Flag to prevent immediate shutdown if turned off before first check

    while True:
        # --- Check External Cancellation ---
        # Important: Check if the task is still supposed to be running early in the loop
        if account_doc_id not in active_trading_tasks:
             logger.info(f"[Trading Task {account_doc_id}]: Task record not found in active_trading_tasks. Stopping loop.")
             break

        try:
            # 1. Fetch Latest Settings & Check Status from DB
            # Use account_doc_id passed to the function
            settings = await get_or_create_trade_settings(account_doc_id)
            if not settings:
                logger.error(f"[Trading Task {account_doc_id}]: Failed to get trade settings. Stopping loop.")
                break # Stop if settings can't be retrieved

            if not settings.get("service_status", False) and not is_first_run:
                logger.info(f"[Trading Task {account_doc_id}]: Service status is OFF in DB. Stopping loop.")
                # Ensure the task is actually removed from the global dict by calling stop_trading_task
                # Need to schedule this outside the loop's context or handle it carefully
                # The most reliable way is if the trigger (button press) calls stop_trading_task itself.
                # Here, we just break the loop.
                await stop_trading_task(account_doc_id) # Attempt cleanup
                break

            is_first_run = False # Service status checked at least once

            # Extract settings needed
            assets_to_trade = settings.get("assets", [])
            trade_mode = settings.get("trade_mode", DEFAULT_TRADE_MODE) # 'TIME' or 'TIMER'
            candle_size = settings.get("candle_size", DEFAULT_CANDLE_SIZE)
            martingale_state_db = settings.get("martingale_state", {})
            cooldown_until_db = settings.get("cooldown_until", 0.0)

            # 2. Check Cooldown Period
            now_time = time.time()
            if now_time < cooldown_until_db:
                remaining_cooldown = int(cooldown_until_db - now_time)
                if remaining_cooldown % 30 == 0 or remaining_cooldown < 5: # Log periodically
                    logger.info(f"[Trading Task {account_doc_id}]: In cooldown for {remaining_cooldown}s.")
                await asyncio.sleep(5) # Check frequently during cooldown
                continue # Skip to next loop iteration

            if not assets_to_trade:
                logger.warning(f"[Trading Task {account_doc_id}]: No assets configured in DB. Pausing for 60s.")
                await asyncio.sleep(60)
                continue

            # 3. Get Connected Quotex Client
            # Use the user_id and account_doc_id passed to the function
            qx_client, status_msg = await get_quotex_client(user_id, account_doc_id, "trading")
            if not qx_client:
                logger.error(f"[Trading Task {account_doc_id}]: Cannot get Quotex client ({status_msg}). Pausing for 60s.")
                await asyncio.sleep(60)
                continue # Try again next iteration
            # Ensure client is connected (get_quotex_client usually handles this)
            # if not await qx_client.check_connect(): ... (optional extra check)

            # 4. --- Trading Cycle Start ---
            logger.debug(f"[Trading Task {account_doc_id}]: Starting trade processing cycle...")
            active_cooldown_until = cooldown_until_db # Use local var for updates within the cycle
            active_martingale_state = martingale_state_db.copy() # Work with a copy for updates

            for asset_info in assets_to_trade:
                 # Check if service turned OFF or task cancelled mid-cycle
                 current_settings_check = await get_or_create_trade_settings(account_doc_id)
                 if not current_settings_check.get("service_status", False):
                     logger.info(f"[Trading Task {account_doc_id}]: Service turned OFF during asset loop. Stopping.")
                     await stop_trading_task(account_doc_id)
                     return # Exit function completely
                 if account_doc_id not in active_trading_tasks:
                    logger.info(f"[Trading Task {account_doc_id}]: Task removed during asset loop. Stopping.")
                    return # Exit function completely

                 # Check cooldown again before *each* trade (could be triggered by previous asset)
                 if time.time() < active_cooldown_until:
                     logger.info(f"[Trading Task {account_doc_id}]: Cooldown activated mid-cycle. Skipping remaining assets.")
                     break # Break from assets loop for this cycle

                 asset_name_original = asset_info.get('name')
                 base_amount = asset_info.get('amount', DEFAULT_TRADE_AMOUNT)
                 # 'duration' field stores the value used for BOTH timer/time expiry setting
                 duration_or_timeframe_value = asset_info.get('duration', DEFAULT_TRADE_DURATION)

                 if not asset_name_original: continue # Skip if asset structure is invalid

                 # Get Martingale state for *this specific asset* from our working copy
                 asset_mtg = active_martingale_state.get(asset_name_original, {'current_amount': base_amount, 'consecutive_losses': 0})
                 current_trade_amount = asset_mtg['current_amount']
                 consecutive_losses = asset_mtg['consecutive_losses']

                 logger.info(f"[Trading Task {account_doc_id}]---> Processing Asset: {asset_name_original}")
                 logger.info(f"  Settings: Mode={trade_mode}, Candle={candle_size}s, Base Amount={base_amount}, Duration/TF={duration_or_timeframe_value}s")
                 logger.info(f"  MTG State: Trade Amount={current_trade_amount}, Losses={consecutive_losses}")

                 # 4a. Check Asset Availability & Get Correct Name (e.g., _otc)
                 asset_name_open = await _check_asset_open_and_get_name(qx_client, asset_name_original)
                 if not asset_name_open:
                     logger.warning(f"[{asset_name_original}] Skipping: Asset or OTC variant not open/available.")
                     await asyncio.sleep(0.5) # Small delay before next asset
                     continue # Go to next asset in the list
                    

                 # --- Update MTG state key if OTC name is different ---
                 if asset_name_open != asset_name_original and asset_name_original in active_martingale_state:
                      logger.info(f"Trading using OTC name '{asset_name_open}', migrating MTG state from '{asset_name_original}'.")
                      active_martingale_state[asset_name_open] = active_martingale_state.pop(asset_name_original)
                      asset_mtg = active_martingale_state[asset_name_open] # Update local ref
                 # Ensure MTG state exists for the open asset name
                 if asset_name_open not in active_martingale_state:
                      active_martingale_state[asset_name_open] = {'current_amount': base_amount, 'consecutive_losses': 0}
                      asset_mtg = active_martingale_state[asset_name_open]
                 #---------------------------------------------------


                 # 4b. Get Trading Direction
                 direction = await _get_candle_direction(qx_client, asset_name_open, candle_size)
                 if direction is None:
                      logger.warning(f"[{asset_name_open}] Skipping: Could not determine trade direction.")
                      await asyncio.sleep(0.5)
                      continue
                 if direction == 'doji':
                      logger.info(f"[{asset_name_open}] Skipping: Last candle was Doji.")
                      await asyncio.sleep(0.5)
                      continue
                 logger.info(f"[{asset_name_open}] Trade Direction Signal: {direction.upper()}")


                 # 4c. Place the Trade
                 logger.info(f"[{asset_name_open}] Placing {direction.upper()} trade. Amount: {current_trade_amount}, Exp: {duration_or_timeframe_value}s, Mode: {trade_mode}")
                 trade_placed_success = False
                 profit_or_loss_amount = 0
                 buy_error_reason = ""
                 try:
                      status, buy_info = await qx_client.buy(current_trade_amount, asset_name_open, direction, duration_or_timeframe_value, trade_mode) # Pass 'TIMER' or 'TIME'

                      if status:
                           trade_id = buy_info.get('id', 'N/A')
                           logger.info(f"[{asset_name_open}] Trade placed successfully! ID: {trade_id}. Waiting for result...")

                           # Wait for duration + buffer
                           await asyncio.sleep(duration_or_timeframe_value + 2) # Increased buffer slightly

                           logger.info(f"[{asset_name_open}] Checking result for Trade ID: {trade_id}...")
                           # IMPORTANT: Use buy_info which might contain necessary identifiers for check_win_v3/v4/get_order
                           # Adapt based on the exact check_win version you are using. Assume it takes ID.
                           win_result = await qx_client.check_win(buy_info["id"]) # Or check_win, check_win_v3 depending on library version and details needed

                           # Get profit might depend on check_win or need separate call
                           profit_or_loss_amount = qx_client.get_profit() # Returns positive for win, negative for loss, 0 for tie
                           trade_placed_success = True # Mark as successful execution pathway

                           if win_result:
                                logger.info(f"[{asset_name_open}] Trade Result: WIN! Profit: {profit_or_loss_amount:.2f}")
                                await bot_instance.send_message(user_id, f"✅ Trade Result: WIN! Profit: {profit_or_loss_amount:.2f}")  
                                # Reset MTG state for this asset on WIN
                                asset_mtg['current_amount'] = base_amount
                                asset_mtg['consecutive_losses'] = 0
                                await update_trade_setting(account_doc_id, {
                                    f"martingale_state.{asset_name_open}.current_amount": asset_mtg['current_amount']
                                })
                                await update_trade_setting(account_doc_id, {
                                    f"martingale_state.{asset_name_open}.consecutive_losses": asset_mtg['consecutive_losses']
                                })
                           else:
                                if profit_or_loss_amount == 0: # Tie / Doji
                                    logger.warning(f"[{asset_name_open}] Trade Result: TIE/DOJI.")
                                    await bot_instance.send_message(user_id, f"⚠️ Trade Result: TIE/DOJI. No profit/loss.")
                                    # No change in MTG state needed for a tie
                                else: # Loss
                                    logger.warning(f"[{asset_name_open}] Trade Result: LOSS! Lost: {abs(profit_or_loss_amount):.2f}")
                                    await bot_instance.send_message(user_id, f"❌ Trade Result: LOSS! Lost: {abs(profit_or_loss_amount):.2f}")
                                    asset_mtg['consecutive_losses'] += 1
                                    # Update consecutive losses in the database for the asset
                                    await update_trade_setting(account_doc_id, {
                                        f"martingale_state.{asset_name_open}.consecutive_losses": asset_mtg['consecutive_losses']
                                    })
                                    asset_mtg['current_amount'] = round(asset_mtg['current_amount'] * MARTINGALE_MULTIPLIER, 2)
                                    await update_trade_setting(account_doc_id, {
                                        f"martingale_state.{asset_name_open}.current_amount": asset_mtg['current_amount']
                                    })

                                    if asset_mtg['consecutive_losses'] >= MAX_CONSECUTIVE_LOSSES:
                                         logger.warning(f"[{asset_name_open}] Max losses ({MAX_CONSECUTIVE_LOSSES}) reached. Activating {COOLDOWN_MINUTES} min cooldown.")
                                         active_cooldown_until = time.time() + (COOLDOWN_MINUTES * 60)
                                         # Reset MTG state for the asset AFTER triggering cooldown
                                         asset_mtg['current_amount'] = base_amount
                                         asset_mtg['consecutive_losses'] = 0
                                         await update_trade_setting(account_doc_id, {
                                            f"martingale_state.{asset_name_open}.current_amount": asset_mtg['current_amount']
                                        })
                                         await update_trade_setting(account_doc_id, {
                                            f"martingale_state.{asset_name_open}.consecutive_losses": asset_mtg['consecutive_losses']
                                         })

                      else: # buy status = False
                           buy_error_reason = buy_info if isinstance(buy_info, str) else str(buy_info)
                           logger.error(f"[{asset_name_open}] Trade placement failed: {buy_error_reason}")
                           # Decide if this error warrants stopping or pausing (e.g., Not enough money)
                           if "not_money" in buy_error_reason or "Insufficient balance" in buy_error_reason:
                                logger.critical(f"[Trading Task {account_doc_id}]: Insufficient funds detected for {asset_name_open}. Turning off trading service.")
                                await update_trade_setting(account_doc_id, {"service_status": False})
                                # Notify user?
                                try: await bot_instance.send_message(user_id, f"⚠️ Trading stopped for account `{qx_client.email}`: Insufficient balance to place trade on `{asset_name_open}`.")
                                except Exception: pass
                                await stop_trading_task(account_doc_id) # Clean up task
                                return # Exit the loop completely


                 except Exception as trade_exec_error:
                     logger.error(f"[{asset_name_open}] Unexpected error during trade execution/check: {trade_exec_error}", exc_info=True)
                     # Consider if connection should be dropped or retried

                 # 4d. Update Martingale state IN THE WORKING COPY
                 active_martingale_state[asset_name_open] = asset_mtg # Update the main dict with changes for this asset

                 # 4e. Update Database State IMMEDIATELY
                 # This prevents losing state if the bot crashes or is stopped.
                 # Only update if state actually changed (or cooldown activated)
                 state_update_payload = {}
                 if active_martingale_state != martingale_state_db:
                     state_update_payload["martingale_state"] = active_martingale_state
                 if active_cooldown_until > cooldown_until_db:
                      state_update_payload["cooldown_until"] = active_cooldown_until

                 if state_update_payload:
                      logger.debug(f"[{asset_name_open}] Saving updated state to DB: {state_update_payload}")
                      try:
                           await update_trade_setting(account_doc_id, state_update_payload)
                           # Refresh local DB vars to match the saved state
                           martingale_state_db = active_martingale_state.copy()
                           cooldown_until_db = active_cooldown_until
                      except Exception as db_save_err:
                           logger.error(f"[Trading Task {account_doc_id}]: CRITICAL: Failed to save state to DB after trade: {db_save_err}. State may be inconsistent.", exc_info=True)
                           # Maybe stop the task here to prevent further inconsistency? Or retry saving? For now, log and continue.


                 # 4f. TIMER Mode Pacing (Wait until next minute)
                 if trade_placed_success and trade_mode == "TIMER":
                     now_dt = datetime.datetime.now()
                     wait_seconds = max(0, 60 - now_dt.second - (now_dt.microsecond / 1_000_000))
                     if wait_seconds > 0.2: # Only wait if significant time remaining
                         logger.info(f"[{asset_name_open}] {trade_mode} mode: Waiting {wait_seconds:.2f}s for next candle/minute.")
                         await asyncio.sleep(wait_seconds)

                 # Small delay before processing next asset to avoid overwhelming API/system
                 await asyncio.sleep(1)

            # --- End of Asset Loop ---
            logger.debug(f"[Trading Task {account_doc_id}]: Finished asset processing cycle.")

            # Wait a bit before starting the *next full cycle* unless in cooldown
            if time.time() >= active_cooldown_until:
                 await asyncio.sleep(5) # Wait 5 seconds before next check

        except asyncio.CancelledError:
             logger.info(f"[Trading Task {account_doc_id}]: Loop cancelled.")
             try:
                 await disconnect_quotex_client(account_doc_id) # Clean up connection
             except Exception as cleanup_error:
                 logger.error(f"[Trading Task {account_doc_id}]: Error during cleanup: {cleanup_error}", exc_info=True)
             finally:
                 break # Exit the while loop
        except ConnectionError as ce: # Catch connection errors from get_quotex_client or within loop
             logger.error(f"[Trading Task {account_doc_id}]: ConnectionError encountered: {ce}. Pausing for 60s.")
             await disconnect_quotex_client(account_doc_id) # Ensure cleanup on error
             await asyncio.sleep(60)
        except Exception as e:
             # Catch unexpected errors in the main loop logic
             logger.error(f"[Trading Task {account_doc_id}]: Unexpected error in trading loop: {e}", exc_info=True)
             await disconnect_quotex_client(account_doc_id) # Ensure cleanup on error
             logger.info(f"[Trading Task {account_doc_id}]: Pausing for 60s due to error.")
             await asyncio.sleep(60) # Wait after unexpected error

    logger.info(f"[Trading Task {account_doc_id}]: Exiting trading loop function.")
    # Final check: ensure client is disconnected if loop terminates unexpectedly
    await disconnect_quotex_client(account_doc_id)
    # Remove from active tasks just in case stop_trading_task wasn't called
    if account_doc_id in active_trading_tasks:
        if account_doc_id in active_trading_tasks:
            if account_doc_id in active_trading_tasks:
                if account_doc_id in active_trading_tasks:
                    active_trading_tasks.pop(account_doc_id, None)
                else:
                    logger.warning(f"Attempted to delete non-existent task for account_doc_id: {account_doc_id}")
            else:
                logger.warning(f"Attempted to delete non-existent task for account_doc_id: {account_doc_id}")
        else:
            logger.warning(f"Attempted to delete non-existent task for account_doc_id: {account_doc_id}")


# --- Ensure these functions handle the task lifecycle correctly ---

async def start_trading_task(user_id: int, account_doc_id: str):
    """Starts the trading loop task for a given account if not already running."""
    global active_trading_tasks
    # Ensure user is Premium or Sudo if this is a Premium feature
    if not await is_premium_user(user_id):
        logger.warning(f"Attempt to start trading for non-premium user {user_id} on account {account_doc_id}. Denied.")
        # Maybe notify the user via bot?
        if bot_instance:
             try: await bot_instance.send_message(user_id, "⛔️ Trading is a premium feature. Please upgrade or contact the owner.")
             except Exception: pass
        return False # Indicate failure

    if account_doc_id in active_trading_tasks:
        # Check if task is actually running
        task = active_trading_tasks[account_doc_id]
        if task and not task.done():
            logger.warning(f"Trading task for {account_doc_id} is already running.")
            return True # Task already exists and running
        else:
             logger.warning(f"Found a completed/cancelled task entry for {account_doc_id}. Will restart.")
             # Remove the old entry before creating a new one
             del active_trading_tasks[account_doc_id]


    # Create and store the task
    # Crucial: Check if the user has assets configured BEFORE starting
    settings = await get_or_create_trade_settings(account_doc_id)
    if not settings.get("assets"):
         logger.warning(f"Cannot start trading for {account_doc_id}: No assets configured.")
         if bot_instance:
             try: await bot_instance.send_message(user_id, f"⚠️ Cannot start trading for account linked to {settings.get('email', account_doc_id)}: No assets are configured. Please add assets first.")
             except Exception: pass
         # Make sure the DB status reflects OFF if we can't start
         await update_trade_setting(account_doc_id, {"service_status": False})
         return False


    logger.info(f"Scheduling trading task for account {account_doc_id} (User: {user_id})...")
    # Make sure the DB reflects that the service is ON
    await update_trade_setting(account_doc_id, {"service_status": True})
    task = asyncio.create_task(run_trading_loop_for_account(user_id, account_doc_id))
    active_trading_tasks[account_doc_id] = task
    # Optional: Add callback to remove task from dict if it finishes unexpectedly
    # task.add_done_callback(lambda t: active_trading_tasks.pop(account_doc_id, None)) # Needs careful implementation
    return True # Indicate success

async def stop_trading_task(account_doc_id: str):
    """Stops the trading loop task for a given account and updates DB status."""
    global active_trading_tasks
    was_running = False
    if account_doc_id in active_trading_tasks:
        task = active_trading_tasks[account_doc_id]
        if task and not task.done():
            logger.info(f"Sending cancellation request to trading task for {account_doc_id}")
            task.cancel()
            was_running = True
            try:
                # Wait briefly for the task to acknowledge cancellation
                await asyncio.wait_for(task, timeout=5.0)
            except asyncio.CancelledError:
                 logger.info(f"Trading task {account_doc_id} acknowledged cancellation.")
            except asyncio.TimeoutError:
                 logger.warning(f"Trading task {account_doc_id} did not finish cancellation within timeout.")
            except Exception as e:
                 logger.error(f"Error during task cancellation await for {account_doc_id}: {e}")

        # Remove from dict regardless of whether it was running or finished/cancelled cleanly
        removed_task = active_trading_tasks.pop(account_doc_id, None)
        if removed_task:
            logger.info(f"Trading task removed from active list for {account_doc_id}.")
        else:
            logger.warning(f"Attempted to delete non-existent task for account_doc_id: {account_doc_id}")
    else:
         logger.warning(f"No active trading task found in dict for {account_doc_id} to stop.")

    # Update DB status to OFF
    logger.info(f"Setting service_status to OFF in DB for {account_doc_id}.")
    await update_trade_setting(account_doc_id, {"service_status": False})

    # Also disconnect any active client session for this account
    logger.info(f"Requesting disconnect for any cached client for {account_doc_id}.")
    await disconnect_quotex_client(account_doc_id)
    return was_running # Indicate if a running task was actually stopped

async def resume_active_trading_tasks():
    """Checks DB on startup and resumes tasks for accounts with service ON."""
    logger.info("Checking for trading tasks to resume...")
    active_settings_cursor = trade_settings_db.find({"service_status": True})
    count = 0
    async for settings in active_settings_cursor:
        try:
            account_doc_id = str(settings['account_doc_id'])
             # Find the user_id associated with this account_doc_id
            account_info = await get_quotex_account_details(account_doc_id)
            if account_info:
                user_id = account_info['user_id']
                logger.info(f"Resuming trading task for account {account_doc_id} (User: {user_id})...")
                await start_trading_task(user_id, account_doc_id)
                count += 1
            else:
                 logger.warning(f"Cannot resume task for account {account_doc_id}: Associated user/account info not found.")
        except Exception as e:
             logger.error(f"Error resuming task for account_doc_id {settings.get('account_doc_id')}: {e}", exc_info=True)
    logger.info(f"Resumed {count} active trading tasks.")

# --- Main Function ---
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

    app.add_handler(MessageHandler(start_command, filters.command("start") & filters.private))
    app.add_handler(MessageHandler(help_command, filters.command("help") & filters.private))
    app.add_handler(MessageHandler(broadcast_command_handler, filters.command("broadcast") & filters.private))  # Has own perm check
    app.add_handler(CallbackQueryHandler(callback_query_handler))
    app.add_handler(MessageHandler(message_handler, filters.private))  # Handles replies and non-command text

    try:
        await app.start()
        bot_instance = app # Set global instance after start
        main_event_loop = asyncio.get_running_loop()
        bot_info = await app.get_me()
        logger.info(f"Bot started as @{bot_info.username} (ID: {bot_info.id})")
        # Resume trading tasks after bot starts and DB is ready
        await resume_active_trading_tasks() # Uncomment carefully - ensure loop logic is solid first

        logger.info("Bot is running... Press CTRL+C to stop.")
        # Keep the main thread alive (Pyrogram handles the event loop)
        await asyncio.Event().wait() # Keeps running until interrupted

    except KeyboardInterrupt:
        logger.warning("Shutdown signal received (KeyboardInterrupt)...")
    except Exception as e:
        logger.error(f"An error occurred during bot execution: {e}", exc_info=True)
    finally:
        if app.is_connected:
            logger.info("Stopping all active trading tasks...")
             # Stop all trading tasks gracefully
            await asyncio.gather(*(stop_trading_task(doc_id) for doc_id in list(active_trading_tasks.keys())))

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