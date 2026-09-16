"""Fixture that never speaks MCP. Used to test the scan timeout."""

import time

if __name__ == "__main__":
    while True:
        time.sleep(3600)
