#!/usr/bin/env python3
"""Interactive CLI tool for Kalshi prediction markets."""

import json
import os
import re
import sys
import csv
import time
import base64
from datetime import datetime, timezone, timedelta
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import questionary
from tabulate import tabulate
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

API_HOST = "https://api.elections.kalshi.com"
API_PATH_PREFIX = "/trade-api/v2"

EST = timezone(timedelta(hours=-5))

EXPIRATION_PRESETS = {
    "1h": 1,
    "4h": 4,
    "12h": 12,
    "1d": 24,
    "3d": 72,
    "7d": 168,
}


def parse_expiration(value: str) -> int:
    """Parse expiration input into a Unix timestamp. Dates/times are interpreted as EST.

    Accepts:
        - Preset shorthand: '1h', '4h', '12h', '1d', '3d', '7d'
        - Date: '2025-03-15' (midnight EST)
        - Datetime: '2025-03-15 14:00' (EST)
    Returns Unix timestamp (seconds).
    """
    value = value.strip().lower()

    # Preset shorthand
    if value in EXPIRATION_PRESETS:
        hours = EXPIRATION_PRESETS[value]
        return int(time.time()) + hours * 3600

    # Try datetime then date — all interpreted as EST
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=EST)
            ts = int(dt.timestamp())
            if ts <= int(time.time()):
                raise ValueError("Expiration must be in the future.")
            return ts
        except ValueError as e:
            if "future" in str(e):
                raise
            continue

    raise ValueError(f"Invalid expiration format: {value}")


def parse_prices(value: str) -> list:
    """Parse price input into a sorted list of unique integers.

    Accepts:
        - Single value: '5'
        - Comma-separated: '1,2,3,5'
        - Range: '1-5' (expands to 1,2,3,4,5)
        - Mixed: '1-3,7,10-12'
    All values must be 1-99.
    """
    prices = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            bounds = part.split("-", 1)
            lo, hi = int(bounds[0].strip()), int(bounds[1].strip())
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, hi + 1):
                prices.add(p)
        else:
            prices.add(int(part))

    if not prices:
        raise ValueError("No prices parsed.")
    for p in prices:
        if p < 1 or p > 99:
            raise ValueError(f"Price {p} out of range (1-99).")
    return sorted(prices)


def validate_prices(value: str) -> bool:
    """Validator for questionary price input."""
    if value.lower() in ("back", "exit"):
        return True
    try:
        parse_prices(value)
        return True
    except (ValueError, IndexError):
        return False


def cents_to_dollars(cents) -> str:
    """Convert cents (int or float) to API dollar string. 42 -> '0.4200'"""
    return f"{float(cents) / 100:.4f}"


def dollars_to_cents(dollars_str) -> float:
    """Convert API dollar string to cents. '0.4200' -> 42.0"""
    try:
        return float(dollars_str) * 100
    except (TypeError, ValueError):
        return 0.0


def to_fp(count) -> str:
    """Convert count to API fixed-point string. 10 -> '10.00'"""
    return f"{float(count):.2f}"


def fp_to_float(fp_str) -> float:
    """Convert API fixed-point string to float. '10.00' -> 10.0"""
    try:
        return float(fp_str)
    except (TypeError, ValueError):
        return 0.0


def fmt_cents(cents_value) -> str:
    """Format cents for display. 42.0 -> '42', 5.5 -> '5.5'"""
    if cents_value == int(cents_value):
        return str(int(cents_value))
    return f"{cents_value:g}"


def ask_expiration() -> int:
    """Prompt user for an optional order expiration. Returns Unix timestamp or None for GTC."""
    preset_labels = ", ".join(EXPIRATION_PRESETS.keys())
    exp_str = questionary.text(
        f"Order expiration (Enter=GTC, or: {preset_labels}, YYYY-MM-DD, YYYY-MM-DD HH:MM) [EST]:",
        default="",
    ).ask()

    if exp_str is None or exp_str.strip() == "":
        return None

    try:
        ts = parse_expiration(exp_str)
        exp_dt = datetime.fromtimestamp(ts, tz=EST)
        print(f"  Expiration: {exp_dt.strftime('%Y-%m-%d %H:%M')} EST")
        return ts
    except ValueError as e:
        print(f"  {e} — defaulting to GTC (no expiration).")
        return None


def load_private_key():
    """Load private key from file path or direct env var."""
    key_path = os.getenv("KALSHI_PRIVATE_KEY_PATH")
    key_direct = os.getenv("KALSHI_PRIVATE_KEY")

    if key_direct:
        pem_data = key_direct.replace("\\n", "\n").encode()
    elif key_path:
        with open(key_path, "rb") as f:
            pem_data = f.read()
    else:
        print("Error: No private key found.")
        print("Set KALSHI_PRIVATE_KEY_PATH or KALSHI_PRIVATE_KEY in .env")
        sys.exit(1)

    return load_pem_private_key(pem_data, password=None)


def _make_session() -> requests.Session:
    """Create a requests session with automatic retry on transient errors."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class KalshiAPI:
    def __init__(self, api_key_id: str, private_key):
        self.api_key_id = api_key_id
        self.private_key = private_key
        self.session = _make_session()

    def _sign(self, timestamp_ms: int, method: str, path: str) -> str:
        """Sign request using RSA-PSS."""
        message = f"{timestamp_ms}{method}{path}".encode()
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def _request(self, method: str, path: str, params: dict = None, json_body: dict = None) -> dict:
        """Make authenticated request."""
        full_path = f"{API_PATH_PREFIX}{path}"
        timestamp_ms = int(time.time() * 1000)
        signature = self._sign(timestamp_ms, method, full_path)

        headers = {
            "Content-Type": "application/json",
            "KALSHI-ACCESS-KEY": self.api_key_id,
            "KALSHI-ACCESS-SIGNATURE": signature,
            "KALSHI-ACCESS-TIMESTAMP": str(timestamp_ms),
        }

        url = f"{API_HOST}{full_path}"
        response = self.session.request(method, url, headers=headers, params=params, json=json_body)
        response.raise_for_status()
        return response.json()

    def get_positions(self) -> dict:
        """Get current positions."""
        return self._request("GET", "/portfolio/positions")

    def get_settlements(self, limit: int = 100, cursor: str = None) -> dict:
        """Get settled (closed) positions."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._request("GET", "/portfolio/settlements", params)

    def get_all_settlements(self) -> list:
        """Get all settlements using pagination."""
        all_settlements = []
        cursor = None
        while True:
            data = self.get_settlements(limit=100, cursor=cursor)
            settlements = data.get("settlements", [])
            all_settlements.extend(settlements)
            cursor = data.get("cursor")
            if not cursor or not settlements:
                break
        return all_settlements

    def get_fills(self, limit: int = 100, cursor: str = None) -> dict:
        """Get executed fills (trades)."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._request("GET", "/portfolio/fills", params)

    def get_all_fills(self, include_historical: bool = False) -> list:
        """Get all executed fills using pagination, optionally including historical."""
        all_fills = []
        cursor = None
        while True:
            data = self.get_fills(limit=100, cursor=cursor)
            fills = data.get("fills", [])
            all_fills.extend(fills)
            cursor = data.get("cursor")
            if not cursor or not fills:
                break
        if include_historical:
            try:
                historical = self.get_all_historical_fills()
                all_fills.extend(historical)
            except Exception:
                pass  # Historical endpoint may not be available
        return all_fills

    def get_market(self, ticker: str) -> dict:
        """Get market details, falling back to historical for settled markets."""
        url = f"{API_HOST}{API_PATH_PREFIX}/markets/{ticker}"
        response = self.session.get(url)
        if response.status_code == 404:
            # Market may have been archived to historical
            try:
                return self.get_historical_market(ticker)
            except Exception:
                pass
        response.raise_for_status()
        return response.json()

    def get_series(self, series_ticker: str) -> dict:
        """Get series details (public endpoint, no auth needed)."""
        url = f"{API_HOST}{API_PATH_PREFIX}/series/{series_ticker}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()

    def get_events_by_series(self, series_ticker: str, status: str = None) -> dict:
        """Get all events for a series (public endpoint, no auth needed)."""
        url = f"{API_HOST}{API_PATH_PREFIX}/events"
        params = {"series_ticker": series_ticker}
        if status:
            params["status"] = status
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def get_event(self, event_ticker: str, with_nested_markets: bool = False) -> dict:
        """Get event details (public endpoint, no auth needed)."""
        url = f"{API_HOST}{API_PATH_PREFIX}/events/{event_ticker}"
        params = {"with_nested_markets": "true"} if with_nested_markets else {}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def get_mention_series_map(self) -> dict:
        """Get mention series as {ticker: {title, tags}} map."""
        url = f"{API_HOST}{API_PATH_PREFIX}/series"
        response = self.session.get(url, params={"category": "Mentions"})
        response.raise_for_status()
        data = response.json()
        result = {}
        for s in data.get("series", []):
            ticker = s.get("ticker")
            if ticker:
                result[ticker] = {
                    "title": s.get("title", ticker),
                    "tags": s.get("tags") or [],
                }
        return result

    def get_all_mention_events(self) -> tuple:
        """Get all open mention events by scanning open events.

        Returns (events_list, series_map) where series_map has tag info.
        """
        series_map = self.get_mention_series_map()
        series_set = set(series_map.keys())

        url = f"{API_HOST}{API_PATH_PREFIX}/events"
        all_events = []
        cursor = None
        while True:
            params = {"status": "open", "limit": 200}
            if cursor:
                params["cursor"] = cursor
            response = self.session.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            events = data.get("events", [])
            for e in events:
                if e.get("series_ticker", "") in series_set:
                    all_events.append(e)
            cursor = data.get("cursor")
            if not cursor or not events:
                break
        return all_events, series_map

    def get_orders(self, status: str = None, limit: int = 100, cursor: str = None) -> dict:
        """Get orders, optionally filtered by status (resting, canceled, executed)."""
        params = {"limit": limit}
        if status:
            params["status"] = status
        if cursor:
            params["cursor"] = cursor
        return self._request("GET", "/portfolio/orders", params)

    def get_all_orders(self, status: str = None) -> list:
        """Get all orders using pagination."""
        all_orders = []
        cursor = None
        while True:
            data = self.get_orders(status=status, limit=100, cursor=cursor)
            orders = data.get("orders", [])
            all_orders.extend(orders)
            cursor = data.get("cursor")
            if not cursor or not orders:
                break
        return all_orders

    def get_balance(self) -> dict:
        """Get account balance."""
        return self._request("GET", "/portfolio/balance")

    def create_order(self, ticker: str, side: str, action: str, count,
                     yes_price=None, no_price=None,
                     expiration_ts: int = None) -> dict:
        """Create a limit order.

        Args:
            ticker: Market ticker
            side: 'yes' or 'no'
            action: 'buy' or 'sell'
            count: Number of contracts (int or float)
            yes_price: Price in cents for yes side (converted to dollars for API)
            no_price: Price in cents for no side (converted to dollars for API)
            expiration_ts: Unix timestamp for order expiration (None = GTC)
        """
        body = {
            "ticker": ticker,
            "side": side,
            "action": action,
            "count_fp": to_fp(count),
            "type": "limit",
        }
        if yes_price is not None:
            body["yes_price_dollars"] = cents_to_dollars(yes_price)
        if no_price is not None:
            body["no_price_dollars"] = cents_to_dollars(no_price)
        if expiration_ts is not None:
            body["expiration_ts"] = expiration_ts
        return self._request("POST", "/portfolio/orders", json_body=body)

    def cancel_order(self, order_id: str) -> dict:
        """Cancel a resting order."""
        return self._request("DELETE", f"/portfolio/orders/{order_id}")

    def get_historical_cutoff(self) -> dict:
        """Get cutoff timestamps for historical vs live data."""
        return self._request("GET", "/historical/cutoff")

    def get_historical_fills(self, limit: int = 100, cursor: str = None) -> dict:
        """Get historical fills (before cutoff)."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._request("GET", "/historical/fills", params)

    def get_all_historical_fills(self) -> list:
        """Get all historical fills using pagination."""
        all_fills = []
        cursor = None
        while True:
            data = self.get_historical_fills(limit=200, cursor=cursor)
            fills = data.get("fills", [])
            all_fills.extend(fills)
            cursor = data.get("cursor")
            if not cursor or not fills:
                break
        return all_fills

    def get_historical_orders(self, limit: int = 100, cursor: str = None) -> dict:
        """Get historical orders (before cutoff)."""
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._request("GET", "/historical/orders", params)

    def get_historical_market(self, ticker: str) -> dict:
        """Get a historical market by ticker (for settled markets past cutoff)."""
        return self._request("GET", f"/historical/markets/{ticker}")


def print_positions(api: KalshiAPI):
    """Print current open positions."""
    print("\n=== OPEN POSITIONS ===\n")

    data = api.get_positions()
    positions = data.get("market_positions", [])

    # Filter to non-zero positions
    open_positions = [p for p in positions if fp_to_float(p.get("position_fp", "0")) != 0]

    if not open_positions:
        print("No open positions.\n")
        return

    rows = []
    for pos in open_positions:
        ticker = pos.get("ticker", "")
        position = fp_to_float(pos.get("position_fp", "0"))
        exposure = pos.get("market_exposure_dollars", "0")
        pnl = pos.get("realized_pnl_dollars", "0")

        # Get market title
        try:
            market = api.get_market(ticker)
            title = market.get("market", {}).get("title", ticker)
        except Exception:
            title = ticker

        # Truncate title if too long
        if len(title) > 40:
            title = title[:37] + "..."

        side = "Yes" if position > 0 else "No"
        qty = abs(position)

        rows.append([title, ticker, side, qty, f"${exposure}", f"${pnl}"])

    headers = ["Market", "Ticker", "Side", "Qty", "Exposure", "P&L"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    print()


def print_settlements(api: KalshiAPI):
    """Print settled (closed) positions."""
    print("\n=== CLOSED POSITIONS (Settlements) ===\n")

    data = api.get_settlements()
    settlements = data.get("settlements", [])

    if not settlements:
        print("No settlements found.\n")
        return

    rows = []
    for s in settlements:
        ticker = s.get("ticker", "")
        revenue = float(s.get("revenue_dollars", "0"))
        settled_at = s.get("settled_time", "")

        # Get market title
        try:
            market = api.get_market(ticker)
            title = market.get("market", {}).get("title", ticker)
        except Exception:
            title = ticker

        # Truncate title if too long
        if len(title) > 40:
            title = title[:37] + "..."

        # Format settled time (take just the date part if it's a full timestamp)
        if "T" in settled_at:
            settled_at = settled_at.split("T")[0]

        rows.append([title, ticker, f"${revenue:.2f}", settled_at])

    headers = ["Market", "Ticker", "Revenue", "Settled"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    print()


def get_orders_grouped(api: KalshiAPI, status: str = "resting") -> dict:
    """Get orders grouped by event. Returns dict of event_ticker -> {title, orders}."""
    orders = api.get_all_orders(status)

    if not orders:
        return {}

    grouped = {}
    for order in orders:
        ticker = order.get("ticker", "")
        event_ticker = ticker.rsplit("-", 1)[0]
        if event_ticker not in grouped:
            grouped[event_ticker] = {"title": event_ticker, "orders": []}
        grouped[event_ticker]["orders"].append(order)

    # Fetch event titles
    for event_ticker in list(grouped.keys()):
        try:
            event_data = api.get_event(event_ticker)
            event = event_data.get("event", {})
            grouped[event_ticker]["title"] = event.get("title", event_ticker)
        except Exception:
            pass

    return grouped


def print_orders_summary(api: KalshiAPI, status: str = "resting"):
    """Print orders grouped by market. Returns grouped dict for drill-down."""
    status_labels = {
        "resting": "RESTING ORDERS",
        "executed": "EXECUTED ORDERS",
        "canceled": "CANCELED ORDERS",
    }
    print(f"\n=== {status_labels.get(status, status.upper())} ===\n")

    grouped = get_orders_grouped(api, status)

    if not grouped:
        print(f"No {status} orders found.\n")
        return {}

    total = sum(len(g["orders"]) for g in grouped.values())
    print(f"Found {total} order(s) across {len(grouped)} market(s):\n")

    rows = []
    for event_ticker, g in grouped.items():
        title = g["title"]
        if len(title) > 50:
            title = title[:47] + "..."
        total_qty = sum(fp_to_float(o.get("remaining_count_fp", "0")) for o in g["orders"])
        rows.append([title, len(g["orders"]), total_qty])

    headers = ["Market", "# Orders", "Total Qty"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    print()
    return grouped


def print_orders_detail(orders: list):
    """Print detailed order rows for a single market's orders."""
    rows = []
    for order in orders:
        ticker = order.get("ticker", "")
        side = order.get("side", "").upper()
        action = order.get("action", "").upper()
        order_type = order.get("type", "")
        remaining = fp_to_float(order.get("remaining_count_fp", "0"))
        filled = fp_to_float(order.get("fill_count_fp", "0"))
        yes_price = dollars_to_cents(order.get("yes_price_dollars", "0"))
        no_price = dollars_to_cents(order.get("no_price_dollars", "0"))
        price = yes_price if yes_price else no_price

        order_desc = f"{action} {side}"
        rows.append([ticker, order_desc, remaining, f"{fmt_cents(price)}¢", filled, order_type])

    headers = ["Ticker", "Action", "Qty", "Price", "Filled", "Type"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    print()


def print_fills(api: KalshiAPI):
    """Print recent fills (trade history)."""
    print("\n=== RECENT FILLS ===\n")

    data = api.get_fills()
    fills = data.get("fills", [])

    if not fills:
        print("No fills found.\n")
        return

    rows = []
    for fill in fills:
        ticker = fill.get("ticker", "")
        side = fill.get("side", "").upper()
        action = fill.get("action", "").upper()
        count = fp_to_float(fill.get("count_fp", "0"))
        yes_price = dollars_to_cents(fill.get("yes_price_dollars", "0"))
        no_price = dollars_to_cents(fill.get("no_price_dollars", "0"))
        price = yes_price if yes_price else no_price
        is_taker = fill.get("is_taker", False)
        created_time = fill.get("created_time", "")

        # Get market title
        try:
            market = api.get_market(ticker)
            title = market.get("market", {}).get("title", ticker)
        except Exception:
            title = ticker

        # Truncate title if too long
        if len(title) > 35:
            title = title[:32] + "..."

        # Format time (take just date and time portion)
        if "T" in created_time:
            created_time = created_time.replace("T", " ").split(".")[0]

        taker_label = "Taker" if is_taker else "Maker"
        trade_desc = f"{action} {side}"
        rows.append([title, ticker, trade_desc, count, f"{fmt_cents(price)}¢", taker_label, created_time])

    headers = ["Market", "Ticker", "Action", "Qty", "Price", "Role", "Time"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    print()


def download_all_fills(api: KalshiAPI):
    """Download all fills to CSV."""
    print("\n=== DOWNLOADING ALL FILLS ===\n")
    print("Fetching fills (this may take a moment)...")

    try:
        fills = api.get_all_fills(include_historical=True)

        if not fills:
            print("No fills found.\n")
            return

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"kalshi_fills_{timestamp}.csv"

        # Define CSV columns (fixed-point field names)
        fieldnames = [
            "created_time", "ticker", "side", "action", "count_fp",
            "yes_price_dollars", "no_price_dollars", "is_taker", "order_id", "trade_id"
        ]

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for fill in fills:
                writer.writerow(fill)

        print(f"Downloaded {len(fills)} fills to {filename}\n")

    except requests.exceptions.HTTPError as e:
        print(f"\nAPI Error: {e}")
        if e.response:
            print(f"Response: {e.response.text}\n")
    except Exception as e:
        print(f"\nError: {e}\n")


def download_all_settlements(api: KalshiAPI):
    """Download all settlements to CSV."""
    print("\n=== DOWNLOADING ALL SETTLEMENTS ===\n")
    print("Fetching settlements (this may take a moment)...")

    try:
        settlements = api.get_all_settlements()

        if not settlements:
            print("No settlements found.\n")
            return

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"kalshi_settlements_{timestamp}.csv"

        # Define CSV columns (fixed-point field names)
        fieldnames = [
            "settled_time", "ticker", "market_result", "no_count_fp",
            "no_total_cost_dollars", "yes_count_fp", "yes_total_cost_dollars",
            "revenue_dollars"
        ]

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for settlement in settlements:
                writer.writerow(settlement)

        print(f"Downloaded {len(settlements)} settlements to {filename}\n")

    except requests.exceptions.HTTPError as e:
        print(f"\nAPI Error: {e}")
        if e.response:
            print(f"Response: {e.response.text}\n")
    except Exception as e:
        print(f"\nError: {e}\n")


def download_everything(api: KalshiAPI):
    """Download both fills and settlements."""
    download_all_fills(api)
    download_all_settlements(api)


DOWNLOAD_MENU_CHOICES = [
    "Download all fills",
    "Download all settlements",
    "Download everything",
    "Back",
]


def run_download_menu(api: KalshiAPI):
    """Run the download submenu."""
    while True:
        choice = questionary.select(
            "Download - What would you like to download?",
            choices=DOWNLOAD_MENU_CHOICES,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "Back":
            break

        if choice == "Download all fills":
            download_all_fills(api)
        elif choice == "Download all settlements":
            download_all_settlements(api)
        elif choice == "Download everything":
            download_everything(api)


def print_balance(api: KalshiAPI):
    """Print account balance."""
    print("\n=== ACCOUNT BALANCE ===\n")

    data = api.get_balance()
    balance = data.get("balance", 0) / 100  # cents to dollars
    portfolio_value = data.get("portfolio_value", 0) / 100

    print(f"  Cash Balance:    ${balance:.2f}")
    print(f"  Portfolio Value: ${portfolio_value:.2f}")
    print(f"  Total:           ${balance + portfolio_value:.2f}")
    print()


def get_uncovered_positions(api: KalshiAPI):
    """Get uncovered positions grouped by event. Returns dict of event_ticker -> {title, items}."""
    positions_data = api.get_positions()
    positions = positions_data.get("market_positions", [])
    open_positions = [p for p in positions if fp_to_float(p.get("position_fp", "0")) != 0]

    if not open_positions:
        return {}

    resting_orders = api.get_all_orders("resting")

    resting_coverage = {}
    for order in resting_orders:
        ticker = order.get("ticker", "")
        action = order.get("action", "").lower()
        side = order.get("side", "").lower()
        remaining = fp_to_float(order.get("remaining_count_fp", "0"))

        if action != "sell":
            continue

        if ticker not in resting_coverage:
            resting_coverage[ticker] = {"yes": 0.0, "no": 0.0}
        resting_coverage[ticker][side] += remaining

    uncovered = []
    for pos in open_positions:
        ticker = pos.get("ticker", "")
        position = fp_to_float(pos.get("position_fp", "0"))

        if position > 0:
            side = "yes"
            qty = position
        else:
            side = "no"
            qty = abs(position)

        coverage = resting_coverage.get(ticker, {}).get(side, 0)
        uncovered_qty = qty - coverage

        if uncovered_qty > 0:
            uncovered.append({
                "ticker": ticker,
                "side": side,
                "position_qty": qty,
                "resting_qty": coverage,
                "uncovered_qty": uncovered_qty,
                "exposure": pos.get("market_exposure_dollars", "0"),
            })

    if not uncovered:
        return {}

    # Group by event ticker
    grouped = {}
    for item in uncovered:
        event_ticker = item["ticker"].rsplit("-", 1)[0]
        if event_ticker not in grouped:
            grouped[event_ticker] = {"title": event_ticker, "items": []}
        grouped[event_ticker]["items"].append(item)

    # Fetch event data (title + market statuses) once per unique event
    for event_ticker in list(grouped.keys()):
        try:
            event_data = api.get_event(event_ticker, with_nested_markets=True)
            event = event_data.get("event", {})
            grouped[event_ticker]["title"] = event.get("title", event_ticker)

            # Build status lookup from nested markets
            market_statuses = {}
            for m in event.get("markets", []):
                market_statuses[m.get("ticker", "")] = m.get("status", "")

            # Filter to only active markets
            grouped[event_ticker]["items"] = [
                item for item in grouped[event_ticker]["items"]
                if market_statuses.get(item["ticker"], "") == "active"
            ]
        except Exception:
            pass

    # Remove events with no active uncovered items
    grouped = {k: v for k, v in grouped.items() if v["items"]}

    return grouped


def print_uncovered_positions(api: KalshiAPI):
    """Print positions without corresponding resting orders (or partial coverage)."""
    print("\n=== UNCOVERED POSITIONS ===\n")

    grouped = get_uncovered_positions(api)

    if not grouped:
        print("No uncovered positions.\n")
        return grouped

    total = sum(len(g["items"]) for g in grouped.values())
    print(f"Found {total} position(s) without full resting order coverage:\n")

    rows = []
    for event_ticker, g in grouped.items():
        rows.append([g["title"], len(g["items"])])

    headers = ["Market", "# of Tickers"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    print()
    return grouped


def place_sell_orders_uncovered(api: KalshiAPI, grouped: dict):
    """Place sell orders for uncovered positions, selecting at the event/market level."""
    if not grouped:
        print("\nNo uncovered positions to sell.\n")
        return

    select_mode = questionary.select(
        "Which markets to place sell orders for?",
        choices=["Select all", "Choose individually", "Back", "Exit"],
    ).ask()

    if select_mode is None or select_mode == "Back":
        return
    if select_mode == "Exit":
        print("Goodbye!")
        sys.exit(0)

    if select_mode == "Select all":
        selected_events = list(grouped.keys())
        print(f"\nSelected all {len(selected_events)} market(s).")
    else:
        choices = []
        for event_ticker, g in grouped.items():
            display = f"{g['title']} ({len(g['items'])} tickers)"
            choices.append({"name": display, "value": event_ticker})

        selected_events = questionary.checkbox(
            "Select markets (Space to select, Enter to confirm):",
            choices=choices,
        ).ask()

        if not selected_events:
            print("No markets selected.\n")
            return

    # Ask for price
    price_str = questionary.text(
        "Sell price in cents (1-99):",
        default="80",
        validate=lambda x: x.lower() in ("back", "exit") or (x.isdigit() and 1 <= int(x) <= 99),
    ).ask()

    if price_str is None or price_str.lower() == "back":
        return
    if price_str.lower() == "exit":
        print("Goodbye!")
        sys.exit(0)

    price = int(price_str)

    # Ask for expiration
    expiration_ts = ask_expiration()

    # Collect all tickers from selected events
    all_orders = []
    for event_ticker in selected_events:
        for item in grouped[event_ticker]["items"]:
            all_orders.append(item)

    # Summary
    print(f"\n=== ORDER SUMMARY ===\n")
    rows = []
    for item in all_orders:
        rows.append([item["ticker"], item["side"].upper(), f"{price}¢", item["uncovered_qty"]])

    headers = ["Ticker", "Side", "Price", "Qty"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    exp_label = datetime.fromtimestamp(expiration_ts, tz=EST).strftime("%Y-%m-%d %H:%M EST") if expiration_ts else "GTC"
    print(f"\nTotal: {len(all_orders)} sell order(s) across {len(selected_events)} market(s)")
    print(f"Expiration: {exp_label}\n")

    confirm = questionary.confirm("Place these orders?", default=False).ask()

    if not confirm:
        print("Orders cancelled.\n")
        return

    # Place orders
    print()
    for item in all_orders:
        ticker = item["ticker"]
        side = item["side"]
        qty = item["uncovered_qty"]
        try:
            if side == "yes":
                result = api.create_order(ticker, side, "sell", qty, yes_price=price, expiration_ts=expiration_ts)
            else:
                result = api.create_order(ticker, side, "sell", qty, no_price=price, expiration_ts=expiration_ts)

            order = result.get("order", {})
            status = order.get("status", "N/A")
            print(f"  {ticker}: OK (status: {status})")
        except requests.exceptions.HTTPError as e:
            msg = str(e)
            if e.response is not None and e.response.text:
                msg += f" | {e.response.text}"
            print(f"  {ticker}: FAILED - {msg}")
        except Exception as e:
            print(f"  {ticker}: FAILED - {e}")

    print()


def place_sell_order(api: KalshiAPI):
    """Interactive workflow to place a limit sell order for uncovered positions."""
    print("\n=== PLACE LIMIT SELL ORDER ===\n")

    # Get open positions
    positions_data = api.get_positions()
    positions = positions_data.get("market_positions", [])
    open_positions = [p for p in positions if fp_to_float(p.get("position_fp", "0")) != 0]

    if not open_positions:
        print("No open positions to sell.\n")
        return

    # Get resting orders to find uncovered positions
    resting_orders = api.get_all_orders("resting")

    # Build map of ticker -> resting sell quantity by side
    resting_coverage = {}
    for order in resting_orders:
        ticker = order.get("ticker", "")
        action = order.get("action", "").lower()
        side = order.get("side", "").lower()
        remaining = fp_to_float(order.get("remaining_count_fp", "0"))

        if action != "sell":
            continue

        if ticker not in resting_coverage:
            resting_coverage[ticker] = {"yes": 0.0, "no": 0.0}
        resting_coverage[ticker][side] += remaining

    # Build choices from uncovered positions only
    choices = []
    for pos in open_positions:
        ticker = pos.get("ticker", "")
        position = fp_to_float(pos.get("position_fp", "0"))

        if position > 0:
            side = "yes"
            qty = position
        else:
            side = "no"
            qty = abs(position)

        # Calculate uncovered quantity
        coverage = resting_coverage.get(ticker, {}).get(side, 0)
        uncovered_qty = qty - coverage

        if uncovered_qty <= 0:
            continue  # Skip fully covered positions

        # Get market title
        try:
            market = api.get_market(ticker)
            title = market.get("market", {}).get("title", ticker)
        except Exception:
            title = ticker

        display = f"{ticker} | {side.upper()} x{uncovered_qty} uncovered | {title}"
        choices.append({"name": display, "value": {"ticker": ticker, "side": side, "qty": uncovered_qty}})

    if not choices:
        print("All positions are fully covered by resting orders.\n")
        return

    choices.append({"name": "Back", "value": "back"})

    # Select position
    selected = questionary.select(
        "Select a position to sell:",
        choices=choices,
        use_arrow_keys=True,
    ).ask()

    if selected is None or selected == "back":
        return

    ticker = selected["ticker"]
    side = selected["side"]
    max_qty = selected["qty"]

    # Get price
    price_str = questionary.text(
        f"Enter price in cents (1-99):",
        validate=lambda x: x.isdigit() and 1 <= int(x) <= 99,
    ).ask()

    if price_str is None:
        return

    price = int(price_str)

    # Get quantity
    qty_str = questionary.text(
        f"Enter quantity to sell (max {max_qty}):",
        default=str(max_qty),
        validate=lambda x: x.isdigit() and 1 <= int(x) <= max_qty,
    ).ask()

    if qty_str is None:
        return

    qty = int(qty_str)

    # Ask for expiration
    expiration_ts = ask_expiration()

    # Confirmation
    exp_label = datetime.fromtimestamp(expiration_ts, tz=EST).strftime("%Y-%m-%d %H:%M EST") if expiration_ts else "GTC"
    print(f"\n--- Order Summary ---")
    print(f"  Market: {ticker}")
    print(f"  Action: SELL {side.upper()}")
    print(f"  Quantity: {qty}")
    print(f"  Price: {price}¢")
    print(f"  Expiration: {exp_label}")
    print()

    confirm = questionary.confirm("Place this order?", default=False).ask()

    if not confirm:
        print("Order cancelled.\n")
        return

    # Place order
    try:
        if side == "yes":
            result = api.create_order(ticker, side, "sell", qty, yes_price=price, expiration_ts=expiration_ts)
        else:
            result = api.create_order(ticker, side, "sell", qty, no_price=price, expiration_ts=expiration_ts)

        order = result.get("order", {})
        print(f"\nOrder placed successfully!")
        print(f"  Order ID: {order.get('order_id', 'N/A')}")
        print(f"  Status: {order.get('status', 'N/A')}")
        print()
    except requests.exceptions.HTTPError as e:
        print(f"\nFailed to place order: {e}")
        if e.response:
            print(f"Response: {e.response.text}\n")


def cancel_order_ui(api: KalshiAPI):
    """Interactive workflow to cancel a resting order."""
    print("\n=== CANCEL ORDER ===\n")

    # Get resting orders
    orders = api.get_all_orders("resting")

    if not orders:
        print("No resting orders to cancel.\n")
        return

    # Build choices from orders
    choices = []
    for order in orders:
        order_id = order.get("order_id", "")
        ticker = order.get("ticker", "")
        side = order.get("side", "").upper()
        action = order.get("action", "").upper()
        remaining = fp_to_float(order.get("remaining_count_fp", "0"))
        yes_price = dollars_to_cents(order.get("yes_price_dollars", "0"))
        no_price = dollars_to_cents(order.get("no_price_dollars", "0"))
        price = yes_price if yes_price else no_price

        display = f"{ticker} | {action} {side} x{remaining} @ {fmt_cents(price)}¢"
        choices.append({"name": display, "value": {"order_id": order_id, "ticker": ticker, "side": side, "remaining": remaining, "price": price}})

    choices.append({"name": "Back", "value": "back"})

    # Select order
    selected = questionary.select(
        "Select an order to cancel:",
        choices=choices,
        use_arrow_keys=True,
    ).ask()

    if selected is None or selected == "back":
        return

    order_id = selected["order_id"]
    ticker = selected["ticker"]
    side = selected["side"]
    remaining = selected["remaining"]
    price = selected["price"]

    # Confirmation
    print(f"\n--- Order to Cancel ---")
    print(f"  Ticker: {ticker}")
    print(f"  Side: {side}")
    print(f"  Remaining: {remaining}")
    print(f"  Price: {fmt_cents(price)}¢")
    print()

    confirm = questionary.confirm("Cancel this order?", default=False).ask()

    if not confirm:
        print("Cancellation aborted.\n")
        return

    # Cancel order
    try:
        result = api.cancel_order(order_id)
        print(f"\nOrder cancelled successfully!")
        reduced_by = fp_to_float(result.get("reduced_by_fp", "0"))
        print(f"  Reduced by: {reduced_by} contracts\n")
    except requests.exceptions.HTTPError as e:
        print(f"\nFailed to cancel order: {e}")
        if e.response:
            print(f"Response: {e.response.text}\n")


# Standard options that appear at every menu level
STANDARD_OPTIONS = ["Refresh", "Exit"]

MAIN_MENU_CHOICES = [
    "Your Account Details",
    "Market Details",
    "Mention Markets",
] + STANDARD_OPTIONS

ACCOUNT_MENU_CHOICES = [
    "View open positions",
    "View resting orders",
    "View uncovered positions",
    "Place limit sell order",
    "Cancel an order",
    "View account balance",
    "View recent fills",
    "View settlements",
    "Download",
    "Back",
    "Exit",
]

# Options shown after displaying data
POST_VIEW_CHOICES = [
    "Refresh",
    "Back to menu",
    "Exit",
]


def run_view_with_refresh(api: KalshiAPI, view_func, *args):
    """Run a view function with refresh/back/exit options after display."""
    while True:
        try:
            view_func(api, *args) if args else view_func(api)
        except requests.exceptions.HTTPError as e:
            print(f"\nAPI Error: {e}")
            if e.response is not None:
                print(f"Response: {e.response.text}\n")
        except requests.exceptions.ConnectionError:
            print("\nConnection error - check your internet connection and try again.\n")
        except Exception as e:
            print(f"\nError: {e}\n")

        post_choice = questionary.select(
            "What next?",
            choices=POST_VIEW_CHOICES,
            use_arrow_keys=True,
        ).ask()

        if post_choice is None or post_choice == "Back to menu":
            break

        if post_choice == "Exit":
            print("Goodbye!")
            sys.exit(0)

        # "Refresh" continues the loop to re-fetch and display


def run_account_menu(api: KalshiAPI):
    """Run the account details submenu."""
    while True:
        choice = questionary.select(
            "Account Details - What would you like to view?",
            choices=ACCOUNT_MENU_CHOICES,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "Back":
            break

        if choice == "Exit":
            print("Goodbye!")
            sys.exit(0)

        if choice == "View open positions":
            run_view_with_refresh(api, print_positions)
        elif choice == "View resting orders":
            while True:
                try:
                    grouped = print_orders_summary(api, "resting")
                except requests.exceptions.HTTPError as e:
                    print(f"\nAPI Error: {e}")
                    if e.response is not None:
                        print(f"Response: {e.response.text}\n")
                    grouped = {}
                except requests.exceptions.ConnectionError:
                    print("\nConnection error - check your internet connection and try again.\n")
                    grouped = {}
                except Exception as e:
                    print(f"\nError: {e}\n")
                    grouped = {}

                if grouped:
                    market_choices = []
                    for event_ticker, g in grouped.items():
                        title = g["title"]
                        if len(title) > 50:
                            title = title[:47] + "..."
                        display = f"{title} ({len(g['orders'])} orders)"
                        market_choices.append(questionary.Choice(title=display, value=event_ticker))
                    market_choices += [questionary.Choice(title="Refresh", value="__refresh__"),
                                       questionary.Choice(title="Back to menu", value="__back__"),
                                       questionary.Choice(title="Exit", value="__exit__")]

                    pick = questionary.select(
                        "Select a market to view orders, or:",
                        choices=market_choices,
                        use_arrow_keys=True,
                    ).ask()

                    if pick is None or pick == "__back__":
                        break
                    if pick == "__exit__":
                        print("Goodbye!")
                        sys.exit(0)
                    if pick == "__refresh__":
                        continue

                    # Show buy/sell sub-menu for the selected market
                    g = grouped[pick]
                    buy_orders = [o for o in g["orders"] if o.get("action", "").lower() == "buy"]
                    sell_orders = [o for o in g["orders"] if o.get("action", "").lower() == "sell"]
                    back_to_menu = False
                    cancelled = False

                    while True:
                        print(f"\n--- {g['title']} ---")
                        print(f"  Buy orders: {len(buy_orders)}  |  Sell orders: {len(sell_orders)}\n")

                        action_choices = []
                        if buy_orders:
                            action_choices.append(f"View buy orders ({len(buy_orders)})")
                        if sell_orders:
                            action_choices.append(f"View sell orders ({len(sell_orders)})")
                        action_choices += ["Back to markets", "Back to menu", "Exit"]

                        action_pick = questionary.select(
                            "What would you like to view?",
                            choices=action_choices,
                            use_arrow_keys=True,
                        ).ask()

                        if action_pick is None or action_pick == "Back to markets":
                            break
                        if action_pick == "Back to menu":
                            back_to_menu = True
                            break
                        if action_pick == "Exit":
                            print("Goodbye!")
                            sys.exit(0)

                        if action_pick.startswith("View buy"):
                            shown_orders = buy_orders
                            order_type_label = "buy"
                            print(f"\n--- {g['title']} — Buy Orders ---\n")
                            print_orders_detail(shown_orders)
                        else:
                            shown_orders = sell_orders
                            order_type_label = "sell"
                            print(f"\n--- {g['title']} — Sell Orders ---\n")
                            print_orders_detail(shown_orders)

                        detail_choices = [
                            f"Cancel {order_type_label} orders by price ({len(shown_orders)})",
                            "Back to order types",
                            "Back to markets",
                            "Back to menu",
                            "Exit",
                        ]
                        detail_choice = questionary.select(
                            "What next?",
                            choices=detail_choices,
                            use_arrow_keys=True,
                        ).ask()

                        if detail_choice is None or detail_choice == "Back to menu":
                            back_to_menu = True
                            break
                        if detail_choice == "Exit":
                            print("Goodbye!")
                            sys.exit(0)
                        if detail_choice == "Back to markets":
                            break
                        if detail_choice.startswith("Cancel"):
                            # Collect unique prices and count orders at each price
                            price_counts = {}
                            for o in shown_orders:
                                yes_p = dollars_to_cents(o.get("yes_price_dollars", "0"))
                                no_p = dollars_to_cents(o.get("no_price_dollars", "0"))
                                p = yes_p if yes_p else no_p
                                price_counts[p] = price_counts.get(p, 0) + 1

                            sorted_prices = sorted(price_counts.keys())
                            price_choices = []
                            for p in sorted_prices:
                                cnt = price_counts[p]
                                label = f"{fmt_cents(p)}¢ ({cnt} order{'s' if cnt > 1 else ''})"
                                price_choices.append(questionary.Choice(title=label, value=p, checked=True))

                            selected_prices = questionary.checkbox(
                                "Select price points to cancel (Space to toggle, Enter to confirm):",
                                choices=price_choices,
                            ).ask()

                            if not selected_prices:
                                print("No prices selected.\n")
                                continue

                            # Filter orders to selected prices
                            to_cancel = []
                            for o in shown_orders:
                                yes_p = dollars_to_cents(o.get("yes_price_dollars", "0"))
                                no_p = dollars_to_cents(o.get("no_price_dollars", "0"))
                                p = yes_p if yes_p else no_p
                                if p in selected_prices:
                                    to_cancel.append(o)

                            prices_label = ", ".join(f"{fmt_cents(p)}¢" for p in sorted(selected_prices))
                            confirm = questionary.confirm(
                                f"Cancel {len(to_cancel)} {order_type_label} order(s) at {prices_label}?",
                                default=False,
                            ).ask()
                            if confirm:
                                success = 0
                                failed = 0
                                for o in to_cancel:
                                    oid = o.get("order_id", "")
                                    try:
                                        api.cancel_order(oid)
                                        success += 1
                                    except Exception as e:
                                        failed += 1
                                        print(f"  Failed to cancel {oid}: {e}")
                                print(f"\nCancelled {success} order(s).", end="")
                                if failed:
                                    print(f" {failed} failed.", end="")
                                print("\n")
                            else:
                                print("Cancellation aborted.\n")
                            cancelled = True
                            break
                        # "Back to order types" continues the inner loop

                    if back_to_menu:
                        break
                    if cancelled:
                        continue  # re-fetch from API
                else:
                    post_choice = questionary.select(
                        "What next?",
                        choices=POST_VIEW_CHOICES,
                        use_arrow_keys=True,
                    ).ask()
                    if post_choice is None or post_choice == "Back to menu":
                        break
                    if post_choice == "Exit":
                        print("Goodbye!")
                        sys.exit(0)
        elif choice == "View uncovered positions":
            while True:
                try:
                    grouped = print_uncovered_positions(api)
                except requests.exceptions.HTTPError as e:
                    print(f"\nAPI Error: {e}")
                    if e.response is not None:
                        print(f"Response: {e.response.text}\n")
                    grouped = {}
                except requests.exceptions.ConnectionError:
                    print("\nConnection error - check your internet connection and try again.\n")
                    grouped = {}
                except Exception as e:
                    print(f"\nError: {e}\n")
                    grouped = {}

                post_choices = ["Place sell orders", "Refresh", "Back to menu", "Exit"] if grouped else POST_VIEW_CHOICES
                post_choice = questionary.select(
                    "What next?",
                    choices=post_choices,
                    use_arrow_keys=True,
                ).ask()

                if post_choice is None or post_choice == "Back to menu":
                    break
                if post_choice == "Exit":
                    print("Goodbye!")
                    sys.exit(0)
                if post_choice == "Place sell orders":
                    place_sell_orders_uncovered(api, grouped)
        elif choice == "Place limit sell order":
            place_sell_order(api)
        elif choice == "Cancel an order":
            cancel_order_ui(api)
        elif choice == "View account balance":
            run_view_with_refresh(api, print_balance)
        elif choice == "View recent fills":
            run_view_with_refresh(api, print_fills)
        elif choice == "View settlements":
            run_view_with_refresh(api, print_settlements)
        elif choice == "Download":
            run_download_menu(api)


def load_saved_series() -> list:
    """Load saved series tickers from series.json config file."""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "series.json")
    if not os.path.exists(config_path):
        return []
    try:
        with open(config_path, "r") as f:
            data = json.load(f)
        return data.get("series", [])
    except (json.JSONDecodeError, IOError):
        return []


def parse_kalshi_url(url: str) -> dict:
    """Parse a Kalshi URL to extract series and event tickers.

    URL format: kalshi.com/markets/{series_ticker}/{slug}/{event_ticker}
    """
    # Handle with or without protocol
    pattern = r"kalshi\.com/markets/([^/]+)/[^/]+/([^/\s?]+)"
    match = re.search(pattern, url)
    if match:
        return {
            "series_ticker": match.group(1).upper(),
            "event_ticker": match.group(2).upper(),
        }
    return None


def print_markets_table(markets: list, sort_by: str = None):
    """Print markets in table format with optional sorting."""
    # Sort markets if requested
    if sort_by == "alphabetical":
        markets = sorted(markets, key=lambda m: m.get("yes_sub_title", "") or m.get("ticker", ""))
    elif sort_by == "status":
        markets = sorted(markets, key=lambda m: m.get("status", ""))
    elif sort_by == "oi":
        markets = sorted(markets, key=lambda m: fp_to_float(m.get("open_interest_fp", "0")), reverse=True)
    elif sort_by == "volume":
        markets = sorted(markets, key=lambda m: fp_to_float(m.get("volume_fp", "0")), reverse=True)

    rows = []
    for m in markets:
        # Use yes_sub_title for human-readable name
        name = m.get("yes_sub_title", "") or m.get("subtitle", "") or m.get("ticker", "")
        if len(name) > 22:
            name = name[:19] + "..."

        status = m.get("status", "")[:8]

        # Yes prices (dollars -> cents for display)
        yes_bid = dollars_to_cents(m.get("yes_bid_dollars", "0"))
        yes_ask = dollars_to_cents(m.get("yes_ask_dollars", "0"))
        yes_ba = f"{fmt_cents(yes_bid)}/{fmt_cents(yes_ask)}"

        # No prices
        no_bid = dollars_to_cents(m.get("no_bid_dollars", "0"))
        no_ask = dollars_to_cents(m.get("no_ask_dollars", "0"))
        no_ba = f"{fmt_cents(no_bid)}/{fmt_cents(no_ask)}"

        # Last prices
        last_yes = dollars_to_cents(m.get("last_price_dollars", "0"))
        last_no = 100 - last_yes
        last_yn = f"{fmt_cents(last_yes)}/{fmt_cents(last_no)}"

        open_interest = fp_to_float(m.get("open_interest_fp", "0"))
        volume = fp_to_float(m.get("volume_fp", "0"))

        rows.append([name, status, yes_ba, no_ba, last_yn, open_interest, volume])

    headers = ["Market", "Status", "Yes B/A", "No B/A", "Last Y/N", "OI", "Vol"]
    print(tabulate(rows, headers=headers, tablefmt="simple", numalign="right"))


def place_buy_orders(api: KalshiAPI, markets: list):
    """Place buy orders on multiple markets from the event markets view."""
    # Filter to active markets only
    active_markets = [m for m in markets if m.get("status", "").lower() == "active"]

    if not active_markets:
        print("\nNo active markets available to buy.\n")
        return

    # Ask whether to select all or pick individually
    all_tickers = [m.get("ticker", "") for m in active_markets]

    select_mode = questionary.select(
        "Which markets to buy?",
        choices=["Select all", "Choose individually", "Back", "Exit"],
    ).ask()

    if select_mode is None or select_mode == "Back":
        return
    if select_mode == "Exit":
        print("Goodbye!")
        sys.exit(0)

    if select_mode == "Select all":
        selected_tickers = all_tickers
        print(f"\nSelected all {len(selected_tickers)} active market(s).")
    else:
        # Build checkbox choices
        choices = []
        for m in active_markets:
            name = m.get("yes_sub_title", "") or m.get("subtitle", "") or m.get("ticker", "")
            ticker = m.get("ticker", "")
            yes_ask = dollars_to_cents(m.get("yes_ask_dollars", "0"))
            display = f"{name} [{ticker}] (Yes ask: {fmt_cents(yes_ask)}¢)"
            choices.append({"name": display, "value": ticker})

        selected_tickers = questionary.checkbox(
            "Select markets to buy (Space to select, Enter to confirm):",
            choices=choices,
        ).ask()

        if not selected_tickers:
            print("No markets selected.\n")
            return

    # Ask for side
    side = questionary.select(
        "Side:",
        choices=["Yes", "No", "Back", "Exit"],
    ).ask()

    if side is None or side == "Back":
        return
    if side == "Exit":
        print("Goodbye!")
        sys.exit(0)

    side = side.lower()

    # Ask for price (supports single, comma-separated, and ranges)
    price_str = questionary.text(
        "Price in cents (e.g. 5, 1-5, 1,3,5), or 'back'/'exit':",
        validate=validate_prices,
    ).ask()

    if price_str is None or price_str.lower() == "back":
        return
    if price_str.lower() == "exit":
        print("Goodbye!")
        sys.exit(0)

    prices = parse_prices(price_str)

    # Ask for quantity
    qty_str = questionary.text(
        "Quantity (number of contracts), or 'back'/'exit':",
        validate=lambda x: x.lower() in ("back", "exit") or (x.isdigit() and int(x) >= 1),
    ).ask()

    if qty_str is None or qty_str.lower() == "back":
        return
    if qty_str.lower() == "exit":
        print("Goodbye!")
        sys.exit(0)

    qty = int(qty_str)

    # Ask for expiration
    expiration_ts = ask_expiration()

    # Build summary
    total_orders = len(prices) * len(selected_tickers)
    total_cost_cents = sum(prices) * qty * len(selected_tickers)
    prices_label = ",".join(str(p) for p in prices)
    print(f"\n=== ORDER SUMMARY ===\n")

    rows = []
    for ticker in selected_tickers:
        m = next((m for m in active_markets if m.get("ticker") == ticker), {})
        name = m.get("yes_sub_title", "") or m.get("subtitle", "") or ticker
        if len(name) > 30:
            name = name[:27] + "..."
        for price in prices:
            rows.append([name, ticker, side.upper(), f"{price}¢", qty, f"${price * qty / 100:.2f}"])

    headers = ["Market", "Ticker", "Side", "Price", "Qty", "Cost"]
    print(tabulate(rows, headers=headers, tablefmt="simple"))
    exp_label = datetime.fromtimestamp(expiration_ts, tz=EST).strftime("%Y-%m-%d %H:%M EST") if expiration_ts else "GTC"
    print(f"\nTotal: {total_orders} order(s), ${total_cost_cents / 100:.2f} across {len(selected_tickers)} market(s), {len(prices)} price(s) [{prices_label}¢]")
    print(f"Expiration: {exp_label}\n")

    confirm = questionary.confirm("Place these orders?", default=False).ask()

    if not confirm:
        print("Orders cancelled.\n")
        return

    # Place orders
    print()
    for ticker in selected_tickers:
        for price in prices:
            try:
                if side == "yes":
                    result = api.create_order(ticker, side, "buy", qty, yes_price=price, expiration_ts=expiration_ts)
                else:
                    result = api.create_order(ticker, side, "buy", qty, no_price=price, expiration_ts=expiration_ts)

                order = result.get("order", {})
                status = order.get("status", "N/A")
                print(f"  {ticker} @ {price}¢: OK (status: {status})")
            except requests.exceptions.HTTPError as e:
                msg = str(e)
                if e.response is not None and e.response.text:
                    msg += f" | {e.response.text}"
                print(f"  {ticker} @ {price}¢: FAILED - {msg}")
            except Exception as e:
                print(f"  {ticker} @ {price}¢: FAILED - {e}")

    print()


def print_event_markets(api: KalshiAPI, event_ticker: str):
    """Print all markets for an event with their current prices in table format."""
    data = api.get_event(event_ticker, with_nested_markets=True)
    event = data.get("event", {})
    markets = event.get("markets", [])

    sort_by = None
    while True:
        print(f"\n=== MARKETS FOR {event_ticker} ===\n")
        print(f"Event: {event.get('title', event_ticker)}")
        sub_title = event.get("sub_title", "")
        if sub_title:
            print(f"Date: {sub_title}")
        print(f"Markets: {len(markets)}")
        if sort_by:
            print(f"Sorted by: {sort_by}")
        print()

        print_markets_table(markets, sort_by)

        # Combined sort and back menu
        sort_choice = questionary.select(
            "Sort by (or Back to exit):",
            choices=[
                {"name": "Alphabetical", "value": "alphabetical"},
                {"name": "Status", "value": "status"},
                {"name": "Open Interest (highest first)", "value": "oi"},
                {"name": "Volume (highest first)", "value": "volume"},
                {"name": "Place buy order", "value": "buy"},
                {"name": "Back", "value": "back"},
                {"name": "Refresh", "value": "refresh"},
                {"name": "Exit", "value": "exit"},
            ],
            use_arrow_keys=True,
        ).ask()

        if sort_choice is None or sort_choice == "back":
            break

        if sort_choice == "exit":
            print("Goodbye!")
            sys.exit(0)

        if sort_choice == "refresh":
            continue

        if sort_choice == "buy":
            place_buy_orders(api, markets)
            continue

        sort_by = sort_choice


def run_market_menu(api: KalshiAPI):
    """Run the market details submenu."""
    print("\n=== MARKET DETAILS ===\n")

    # Build entry method choices
    entry_choices = [{"name": "Enter a Kalshi market URL", "value": "url"}]
    saved_series = load_saved_series()
    for s in saved_series:
        label = s.get("label", s["ticker"])
        entry_choices.append({"name": label, "value": s["ticker"]})
    entry_choices.append({"name": "Back", "value": "back"})

    selection = questionary.select(
        "Select a series or enter a URL:",
        choices=entry_choices,
        use_arrow_keys=True,
    ).ask()

    if selection is None or selection == "back":
        return

    if selection == "url":
        url = questionary.text(
            "Enter a Kalshi market URL (or 'back' to return):",
            validate=lambda x: len(x) > 0,
        ).ask()

        if url is None or url.lower() == "back":
            return

        parsed = parse_kalshi_url(url)
        if not parsed:
            print("\nCouldn't parse URL. Expected format:")
            print("  https://kalshi.com/markets/{series}/{slug}/{event}\n")
            return

        series_ticker = parsed["series_ticker"]
    else:
        series_ticker = selection

    while True:
        try:
            # Get series info
            series_data = api.get_series(series_ticker)
            series = series_data.get("series", {})
            print(f"\nSeries: {series.get('title', series_ticker)}")
            print(f"Category: {series.get('category', 'N/A')}\n")

            # Get events in series
            events_data = api.get_events_by_series(series_ticker, status="open")
            events = events_data.get("events", [])

            if not events:
                print("No events found for this series.\n")
                return

            # Fetch resting buy orders and build set of event tickers with buys
            try:
                resting_orders = api.get_all_orders("resting")
                buy_event_tickers = set()
                for order in resting_orders:
                    if order.get("action", "").lower() == "buy":
                        market_ticker = order.get("ticker", "")
                        event_t = market_ticker.rsplit("-", 1)[0]
                        buy_event_tickers.add(event_t)
            except Exception:
                buy_event_tickers = set()

            # Build choices from event titles with sub_title (date)
            choices = []
            for e in events:
                ticker = e.get("event_ticker", "")
                title = e.get("title", ticker)
                sub_title = e.get("sub_title", "")

                # Indicator for buy orders
                has_buys = "[x]" if ticker in buy_event_tickers else "[ ]"

                # Build display string with date if available
                if sub_title:
                    display = f"{has_buys} {title} ({sub_title})"
                else:
                    display = f"{has_buys} {title}"

                choices.append({"name": display, "value": ticker})
            choices.append({"name": "Back", "value": "back"})
            choices.append({"name": "Refresh", "value": "refresh"})
            choices.append({"name": "Exit", "value": "exit"})

            # Let user select an event
            selected = questionary.select(
                "Select an event to view markets:",
                choices=choices,
                use_arrow_keys=True,
            ).ask()

            if selected is None or selected == "back":
                return

            if selected == "exit":
                print("Goodbye!")
                sys.exit(0)

            if selected == "refresh":
                continue

            # Fetch and display market data for selected event
            print_event_markets(api, selected)

        except requests.exceptions.HTTPError as e:
            print(f"\nAPI Error: {e}")
            if e.response:
                print(f"Response: {e.response.text}\n")
            return
        except Exception as e:
            print(f"\nError: {e}\n")
            return


def run_mention_markets_menu(api: KalshiAPI):
    """Browse active mention markets grouped by category and series."""
    while True:
        print("\n=== MENTION MARKETS ===\n")
        print("Fetching mention events (scanning open events)...")

        try:
            events, series_map = api.get_all_mention_events()
        except requests.exceptions.HTTPError as e:
            print(f"\nAPI Error: {e}")
            if e.response:
                print(f"Response: {e.response.text}\n")
            return
        except Exception as e:
            print(f"\nError: {e}\n")
            return

        if not events:
            print("No active mention events found.\n")
            post = questionary.select("What next?", choices=["Back", "Refresh", "Exit"]).ask()
            if post is None or post == "Back":
                return
            if post == "Exit":
                print("Goodbye!")
                sys.exit(0)
            continue

        # Fetch resting buy orders and build set of event tickers with buys
        try:
            resting_orders = api.get_all_orders("resting")
            buy_event_tickers = set()
            for order in resting_orders:
                if order.get("action", "").lower() == "buy":
                    market_ticker = order.get("ticker", "")
                    event_t = market_ticker.rsplit("-", 1)[0]
                    buy_event_tickers.add(event_t)
        except Exception:
            buy_event_tickers = set()

        # Group by series_ticker, enriched with tag from series_map
        grouped = {}
        for e in events:
            series = e.get("series_ticker", "UNKNOWN")
            if series not in grouped:
                info = series_map.get(series, {})
                tags = info.get("tags", [])
                tag = tags[0] if tags else "Other"
                grouped[series] = {"events": [], "tag": tag}
            grouped[series]["events"].append(e)

        # Collect unique tags for category filter
        all_tags = sorted(set(g["tag"] for g in grouped.values()))

        # Display summary table grouped by category
        rows = []
        for series, g in grouped.items():
            title = g["events"][0].get("title", series)
            if len(title) > 45:
                title = title[:42] + "..."
            rows.append([g["tag"], title, len(g["events"])])

        rows.sort(key=lambda r: (r[0], r[1]))
        print(f"\nFound {len(events)} mention event(s) in {len(grouped)} series.\n")
        print(tabulate(rows, headers=["Category", "Title", "# Events"], tablefmt="simple"))
        print()

        # Category filter then series selection
        filter_choices = [{"name": "All markets", "value": "all"}]
        for tag in all_tags:
            count = sum(len(g["events"]) for g in grouped.values() if g["tag"] == tag)
            filter_choices.append({"name": f"{tag} ({count} events)", "value": tag})
        filter_choices.append({"name": "Back", "value": "back"})
        filter_choices.append({"name": "Refresh", "value": "refresh"})
        filter_choices.append({"name": "Exit", "value": "exit"})

        selected_filter = questionary.select(
            "Filter by category:",
            choices=filter_choices,
            use_arrow_keys=True,
        ).ask()

        if selected_filter is None or selected_filter == "back":
            return
        if selected_filter == "exit":
            print("Goodbye!")
            sys.exit(0)
        if selected_filter == "refresh":
            continue

        # Filter series by selected category
        if selected_filter == "all":
            filtered = grouped
        else:
            filtered = {s: g for s, g in grouped.items() if g["tag"] == selected_filter}

        # Flatten to event list for selection
        all_filtered_events = []
        for g in filtered.values():
            all_filtered_events.extend(g["events"])

        while True:
            event_choices = []
            for e in all_filtered_events:
                ticker = e.get("event_ticker", "")
                title = e.get("title", ticker)
                sub_title = e.get("sub_title", "")
                has_buys = "[x]" if ticker in buy_event_tickers else "[ ]"
                display = f"{has_buys} {title} ({sub_title})" if sub_title else f"{has_buys} {title}"
                event_choices.append({"name": display, "value": ticker})
            event_choices.append({"name": "Back", "value": "back"})
            event_choices.append({"name": "Exit", "value": "exit"})

            selected_event = questionary.select(
                "Select an event to view markets:",
                choices=event_choices,
                use_arrow_keys=True,
            ).ask()

            if selected_event is None or selected_event == "back":
                break
            if selected_event == "exit":
                print("Goodbye!")
                sys.exit(0)

            print_event_markets(api, selected_event)


def run_menu(api: KalshiAPI):
    """Run the main interactive menu loop."""
    while True:
        choice = questionary.select(
            "What would you like to do?",
            choices=MAIN_MENU_CHOICES,
            use_arrow_keys=True,
        ).ask()

        if choice is None or choice == "Exit":
            print("Goodbye!")
            break

        if choice == "Refresh":
            continue

        if choice == "Your Account Details":
            run_account_menu(api)
        elif choice == "Market Details":
            run_market_menu(api)
        elif choice == "Mention Markets":
            run_mention_markets_menu(api)


def main():
    load_dotenv()

    api_key_id = os.getenv("KALSHI_API_KEY_ID")
    if not api_key_id:
        print("Error: KALSHI_API_KEY_ID not set in .env")
        sys.exit(1)

    private_key = load_private_key()
    api = KalshiAPI(api_key_id, private_key)

    print("Kalshi Portfolio CLI")
    print("=" * 40)

    run_menu(api)


if __name__ == "__main__":
    main()
