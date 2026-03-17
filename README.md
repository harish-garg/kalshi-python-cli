# kcli

An interactive command-line tool for trading on [Kalshi](https://kalshi.com) prediction markets.

## Features

- **Portfolio management** — view open positions, resting orders, balances, fills, and settlements
- **Order placement** — place limit buy/sell orders with flexible pricing (single, ranges, comma-separated)
- **Uncovered position detection** — find positions without resting sell orders and place coverage in bulk
- **Order cancellation** — cancel orders individually or in bulk by price point
- **Market browsing** — explore markets by URL or browse mention markets by series
- **Data export** — download fills and settlements to CSV
- **Order expiration** — set expiration via presets (`1h`, `4h`, `1d`, etc.) or specific dates

## Installation

```bash
git clone https://github.com/harish-garg/kalshi-python-cli
cd kcli
python -m venv venv
venv\Scripts\activate    # Windows
# source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

## Configuration

1. Copy the example environment file:

```bash
cp .env.example .env
```

2. Fill in your Kalshi API credentials in `.env`:

```
KALSHI_API_KEY_ID=your-api-key-id
```

3. Provide your RSA private key using one of two methods:

   **Option A** — path to a PEM file:
   ```
   KALSHI_PRIVATE_KEY_PATH=path/to/your/private_key.pem
   ```

   **Option B** — paste the key directly:
   ```
   KALSHI_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
   ...your key...
   -----END RSA PRIVATE KEY-----"
   ```

You can generate API credentials from your [Kalshi account settings](https://kalshi.com/account/settings).

## Usage

```bash
python kcli.py
```

The tool presents an interactive menu:

```
? What would you like to do?
> Your Account Details
  Market Details
  Mention Markets
  Refresh
  Exit
```

### Account Details

- **View open positions** — shows your current holdings with exposure and P&L
- **View resting orders** — browse orders grouped by market, drill down by buy/sell
- **View uncovered positions** — find positions without matching sell orders
- **Place limit sell order** — sell from your uncovered positions
- **Cancel an order** — cancel individual or bulk orders by price
- **View account balance** — cash balance and portfolio value
- **View recent fills** — trade execution history
- **View settlements** — closed/settled positions
- **Download** — export fills and settlements to CSV

### Market Details

Paste a Kalshi market URL to browse all events in that series and view market data including bid/ask prices, last trade, open interest, and volume. Place buy orders directly from the market view.

### Mention Markets

Browse active mention markets grouped by series. Drill into individual events to view contract prices and place orders.

## License

[MIT](LICENSE)
