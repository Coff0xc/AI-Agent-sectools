#!/usr/bin/env python
"""MCP Security Scanner - Entry point."""
import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.mcp import SecurityMCPServer


def main():
    Path("logs").mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/mcp_server.log'),
            logging.StreamHandler(sys.stderr)
        ]
    )

    server = SecurityMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
