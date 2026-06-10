# Setup

Requirements:

- Python 3.11 or newer.
- No third-party packages.

Smoke run:

```powershell
python -m ignirelay_lab.cli --all
```

Test run:

```powershell
python -m unittest discover -s tests
```

This simulator validates delivery and logging concepts. It does not
validate real LoRa RF behavior, range, antenna quality, mobile BLE
background behavior, or SX1262 timing.
