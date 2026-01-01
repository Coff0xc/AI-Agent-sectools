#!/usr/bin/env python
"""MCP server startup script for AI penetration testing tool."""
import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.mcp.server import PentestMCPServer


def setup_logging():
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/mcp_server.log'),
            logging.StreamHandler(sys.stderr)
        ]
    )


async def main():
    """Main entry point."""
    # Setup logging
    Path("logs").mkdir(exist_ok=True)
    setup_logging()
    logger = logging.getLogger(__name__)

    try:
        logger.info("Starting AI Pentest MCP Server...")

        # Create and initialize server
        server = PentestMCPServer()
        await server.initialize()

        logger.info("MCP Server initialized, starting stdio server...")

        # Run server
        await server.run()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
