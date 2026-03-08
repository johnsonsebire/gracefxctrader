"""quotex_auth.py - Selenium/undetected-chromedriver Quotex session refresh.

Uses undetected-chromedriver (UC) which patches the ChromeDriver binary so
navigator.webdriver and all CDP automation signals are invisible to Cloudflare.
Persistent Chrome profile per-account stores __cf_clearance so the challenge
only needs to be solved ONCE manually; all future starts are automatic.

Flow:
  1. If a valid token already exists on disk, skip auth entirely.
  2. Try headless UC login with persistent profile.
  3. If headless fails, open a VISIBLE Chrome window and wait for the user
     to complete the challenge. The profile is then saved for next time.

Usage:
  from quotex_auth import ensure_session
  await ensure_session(email, password, session_path="sessions/<account_id>")
"""

import asyncio
import json
import logging
import os
import re
from functools import partial
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/134.0.0.0 Safari/537.36"
)

_LOGIN_URL  = "https://qxbroker.com/en/sign-in"
_TRADE_PATH = "/trade"


def _profile_dir(session_path: str) -> Path:
    return (Path(session_path) / "browser_profile").resolve()


def _make_driver(profile_dir: Path, headless: bool):
    """Create a UC-patched Chrome driver with a persistent profile."""
    import setuptools  # must be imported before uc to ensure distutils is available on Python 3.12+
    import undetected_chromedriver as uc

    options = uc.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--lang=en-US,en;q=0.9")
    # Suppress additional automation signals that Cloudflare checks
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument(f"--user-agent={_UA}")
    if headless:
        options.add_argument("--headless=new")
    else:
        options.add_argument("--start-maximized")

    return uc.Chrome(
        options=options,
        user_data_dir=str(profile_dir),
        use_subprocess=True,
    )


def _make_plain_driver():
    """Last-resort fallback: plain Selenium Chrome with automation signals suppressed."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions

    options = ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--lang=en-US,en;q=0.9")
    options.add_argument("--start-maximized")
    options.add_argument(f"--user-agent={_UA}")
    # Remove the 'Chrome is controlled by automated software' banner and
    # suppress navigator.webdriver / automation fingerprints that Cloudflare detects.
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    driver = webdriver.Chrome(options=options)
    # Patch navigator.webdriver to undefined at the JS level
    driver.execute_cdp_cmd(
        "Page.addScriptToEvaluateOnNewDocument",
        {"source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"},
    )
    return driver


def _extract_and_save_session(driver, session_dir: Path) -> dict:
    """Extract SSID token + cookies from an authenticated /trade page."""
    ssid_token: Optional[str] = None

    try:
        result = driver.execute_script(
            "return typeof window.settings !== 'undefined' "
            "? JSON.stringify(window.settings) : null;"
        )
        if result:
            ssid_token = json.loads(result).get("token")
            if ssid_token:
                logger.info("[Selenium] SSID token extracted from window.settings.")
    except Exception as exc:
        logger.warning(f"[Selenium] window.settings read failed: {exc}")

    if not ssid_token:
        try:
            scripts = driver.execute_script(
                "return Array.from(document.querySelectorAll('script'))"
                ".map(s => s.textContent);"
            )
            for text in (scripts or []):
                m = re.search(r"window\.settings\s*=\s*(\{.+?\});", text, re.DOTALL)
                if m:
                    ssid_token = json.loads(re.sub(r",\s*}", "}", m.group(1))).get("token")
                    if ssid_token:
                        logger.info("[Selenium] SSID token extracted from script tag.")
                        break
        except Exception as exc:
            logger.warning(f"[Selenium] Script tag fallback failed: {exc}")

    cookies = driver.get_cookies()
    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)

    if not ssid_token:
        logger.warning("[Selenium] No SSID token found; session saved with cookies only.")

    session = {"cookies": cookie_str, "token": ssid_token or "", "user_agent": _UA}
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "session.json").write_text(json.dumps(session, indent=4))
    logger.info(
        f"[Selenium] session.json saved -> {session_dir / 'session.json'}  "
        f"(token={'ok' if ssid_token else 'MISSING'})"
    )
    return session


def _do_login_sync(
    email: str,
    password: str,
    session_path: str,
    headless: bool,
    manual_timeout: int = 300,
) -> dict:
    """Blocking Selenium login. Called from async wrappers via run_in_executor."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException

    session_dir = Path(session_path)
    profile_dir = _profile_dir(session_path)
    profile_dir.mkdir(parents=True, exist_ok=True)

    # Kill any lingering Chrome/ChromeDriver processes before launching.
    # On a server this bot is the only Chrome user, so this is safe.
    # Leftover processes hold file locks on the profile directory and cause
    # "Chrome cannot read or write to its directory" errors on startup.
    import subprocess as _sp
    import time as _time
    for _proc in ("chrome.exe", "chromedriver.exe"):
        try:
            _sp.run(
                ["taskkill", "/F", "/IM", _proc],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, check=False
            )
        except Exception:
            pass
    _time.sleep(1)  # give Windows a moment to release file handles

    if not headless:
        # Wipe the browser profile before every visible-mode session.
        # A stale/fingerprinted profile makes Cloudflare loop the challenge
        # endlessly even when a human solves it. Starting clean guarantees
        # a single successful solve and a fresh __cf_clearance cookie.
        import shutil as _shutil
        if profile_dir.exists():
            try:
                _shutil.rmtree(profile_dir)
                logger.info(
                    f"[Selenium] Cleared stale browser_profile for {email} "
                    "(fresh fingerprint for Cloudflare challenge)."
                )
            except Exception as _rm_err:
                logger.warning(f"[Selenium] Could not clear browser_profile: {_rm_err}")
        profile_dir.mkdir(parents=True, exist_ok=True)

        print(
            f"\n{'='*62}\n"
            f"[Quotex Auth] Opening VISIBLE browser for {email}.\n"
            f"  Credentials have been pre-filled.\n"
            f"  Complete any Cloudflare challenge / 2FA shown.\n"
            f"  The bot resumes once you reach the trading dashboard.\n"
            f"  You have {manual_timeout} seconds.\n"
            f"{'='*62}\n"
        )
        logger.warning(f"[Selenium] Visible browser opened for {email}.")
    else:
        # In headless mode, only remove Chrome's lock files left behind by a
        # previous unclean exit. Deleting these preserves the saved
        # __cf_clearance cookie while letting Chrome open the profile cleanly.
        for _lock_name in ("SingletonLock", "SingletonCookie", "SingletonSocket",
                           "lockfile", ".parentlock"):
            _lock_path = profile_dir / _lock_name
            if _lock_path.exists() or _lock_path.is_symlink():
                try:
                    _lock_path.unlink()
                    logger.info(f"[Selenium] Removed stale lock file: {_lock_path}")
                except Exception as _le:
                    logger.warning(f"[Selenium] Could not remove lock file {_lock_path}: {_le}")
        # Also clear lock files inside the Default sub-profile
        for _sub in ("Default", "Default/Network"):
            _sub_lock = profile_dir / _sub / "LOCK"
            if _sub_lock.exists():
                try:
                    _sub_lock.unlink()
                    logger.info(f"[Selenium] Removed sub-profile lock: {_sub_lock}")
                except Exception as _le:
                    logger.warning(f"[Selenium] Could not remove {_sub_lock}: {_le}")

    try:
        driver = _make_driver(profile_dir, headless)
    except Exception as uc_err:
        if headless:
            raise  # propagate so ensure_session falls through to visible mode
        # UC Chrome failed in visible mode — try plain Selenium Chrome as a last resort
        logger.warning(
            f"[Selenium] UC Chrome failed ({str(uc_err)[:120]}); retrying with plain Chrome ..."
        )
        print(
            f"\n{'='*62}\n"
            f"[Quotex Auth] undetected-chromedriver failed for {email}.\n"
            f"  Opening plain Chrome instead.\n"
            f"  A browser window should appear — complete the Cloudflare\n"
            f"  challenge, then log in manually if credentials weren't filled.\n"
            f"  You have {manual_timeout} seconds.\n"
            f"{'='*62}\n"
        )
        driver = _make_plain_driver()
    try:
        logger.info(f"[Selenium] Navigating to login page (headless={headless}) ...")
        driver.get(_LOGIN_URL)

        _CF_TITLES = {"Just a moment...", "Verifying you are human", "Please Wait...", ""}
        cf_wait = 90 if headless else manual_timeout
        try:
            WebDriverWait(driver, cf_wait).until(
                lambda d: d.title not in _CF_TITLES
            )
        except TimeoutException:
            if headless:
                raise RuntimeError("Cloudflare challenge did not clear in headless mode.")

        try:
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.NAME, "email"))
            )
            driver.find_element(By.NAME, "email").send_keys(email)
            driver.find_element(By.NAME, "password").send_keys(password)
            if headless:
                driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        except Exception as exc:
            if headless:
                raise RuntimeError(f"Could not fill login form: {exc}")

        trade_wait = 90 if headless else manual_timeout
        try:
            WebDriverWait(driver, trade_wait).until(
                lambda d: _TRADE_PATH in d.current_url
            )
        except TimeoutException:
            body = ""
            try:
                body = driver.find_element(By.TAG_NAME, "body").text.lower()
            except Exception:
                pass
            # Truncate body to avoid flooding logs with HTML
            body_snippet = body[:300].replace('\n', ' ') if body else '(empty)'
            logger.warning(f"[Selenium] Page content at timeout: {body_snippet}")
            if headless and any(w in body for w in ("invalid", "incorrect", "wrong")):
                raise RuntimeError("Quotex login failed: invalid credentials.")
            raise RuntimeError(
                f"Did not reach /trade within timeout "
                f"({'headless' if headless else f'{manual_timeout}s manual'})."
            )

        logger.info("[Selenium] Reached /trade - extracting session ...")
        return _extract_and_save_session(driver, session_dir)

    finally:
        try:
            driver.quit()
        except Exception:
            pass


async def selenium_login(
    email: str,
    password: str,
    session_path: str = ".",
    headless: bool = True,
) -> dict:
    """Headless automated login. Raises RuntimeError on failure."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, partial(_do_login_sync, email, password, session_path, True)
    )


async def interactive_login(
    email: str,
    password: str,
    session_path: str = ".",
    manual_timeout: int = 300,
) -> dict:
    """Visible browser fallback for manual challenge completion."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, partial(_do_login_sync, email, password, session_path, False, manual_timeout)
    )


async def ensure_session(
    email: str,
    password: str,
    session_path: str = ".",
    force: bool = False,
    manual_timeout: int = 300,
) -> bool:
    """
    Ensure a valid session.json exists for this account.

    1. Return early if a saved token already exists (unless force=True).
    2. Headless UC login with persistent profile.
    3. Visible browser fallback - user solves challenge once; __cf_clearance
       is persisted so subsequent headless runs pass automatically.
    """
    _MAX_SESSION_AGE_HOURS = 6  # re-auth if session file is older than this

    session_file = Path(session_path) / "session.json"
    if not force and session_file.exists():
        try:
            import time as _time
            session_data = json.loads(session_file.read_text())
            token = session_data.get("token")
            cookies = session_data.get("cookies", "")
            # Check both token presence AND session file age.
            # __cf_clearance cookies on qxbroker.com expire in a few hours, so we
            # force a refresh when the session is older than _MAX_SESSION_AGE_HOURS.
            age_hours = (_time.time() - session_file.stat().st_mtime) / 3600
            has_cf_clearance = "__cf_clearance" in cookies
            if token and has_cf_clearance and age_hours < _MAX_SESSION_AGE_HOURS:
                logger.info(
                    f"[Selenium] Session on disk for {email} is "
                    f"{age_hours:.1f}h old — reusing."
                )
                return True
            elif token and age_hours >= _MAX_SESSION_AGE_HOURS:
                logger.warning(
                    f"[Selenium] Session for {email} is {age_hours:.1f}h old "
                    f"(> {_MAX_SESSION_AGE_HOURS}h) — forcing refresh."
                )
            elif token and not has_cf_clearance:
                logger.warning(
                    f"[Selenium] Session for {email} has no __cf_clearance cookie "
                    "— forcing refresh."
                )
        except Exception:
            pass

    logger.info(f"[Selenium] Attempting headless login for {email} ...")
    try:
        result = await selenium_login(email, password, session_path=session_path)
        if result.get("token"):
            return True
        logger.warning("[Selenium] Headless login gave no token - trying visible browser.")
    except Exception as exc:
        # Strip newlines so stack trace stays readable in the log file
        logger.warning(f"[Selenium] Headless login failed: {str(exc)[:200]} - opening visible browser.")

    try:
        result = await interactive_login(
            email, password, session_path=session_path, manual_timeout=manual_timeout
        )
        if result.get("token"):
            return True
        logger.error(f"[Selenium] Visible login completed but no token captured for {email}.")
        return False
    except Exception as exc:
        logger.error(f"[Selenium] Visible login failed for {email}: {str(exc)[:300]}", exc_info=False)
        logger.error("[Selenium] Auth failed. Bot will run without a pre-cached session; "
                     "pyquotex will attempt its own login when a trade signal arrives.")
        return False


def refresh_session_sync(
    email: str,
    password: str,
    session_path: str = ".",
    force: bool = False,
) -> bool:
    """Synchronous convenience wrapper."""
    try:
        return asyncio.run(ensure_session(email, password, session_path=session_path, force=force))
    except Exception as exc:
        logger.error(f"[Selenium] Sync refresh failed for {email}: {exc}", exc_info=True)
        return False


if __name__ == "__main__":
    import sys
    from dotenv import load_dotenv

    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    _email    = os.getenv("TEST_QUOTEX_EMAIL")    or input("Quotex email: ").strip()
    _password = os.getenv("TEST_QUOTEX_PASSWORD") or input("Quotex password: ").strip()
    _path     = os.getenv("TEST_SESSION_PATH", ".")
    _force    = os.getenv("TEST_FORCE_REFRESH", "false").lower() == "true"

    ok = asyncio.run(ensure_session(_email, _password, session_path=_path, force=_force))
    sys.exit(0 if ok else 1)
