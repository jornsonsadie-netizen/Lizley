#!/usr/bin/env python3
"""Application entry point for the AI Proxy.

This script serves as the main entry point for running the AI Proxy application.
It loads environment variables from .env file and starts the uvicorn server.

Usage:
    python run.py
    
Or with custom port:
    PORT=3000 python run.py
"""

import os

# Load environment variables from .env file before importing anything else
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()

import uvicorn

from backend.config import load_settings


def main():
    """Main entry point for the application."""
    # Try to load settings to validate configuration
    try:
        settings = load_settings()
        port = settings.port
        print(f"* Configuration loaded successfully")
        print(f"  - Admin password: {'*' * len(settings.admin_password)}")
        print(f"  - Target API URL: {settings.target_api_url}")
        print(f"  - Max context: {settings.max_context}")
        print(f"  - Max output tokens: {settings.max_output_tokens}")
        print(f"  - Database path: {settings.database_path}")
    except ValueError as e:
        print(f"⚠ Warning: {e}")
        print("  Using default configuration for development")
        port = int(os.getenv("PORT", "8000"))
    
    print(f"\n🚀 Starting AI Proxy on port {port}...")
    print(f"   Public frontend: http://localhost:{port}/")
    print(f"   Admin dashboard: http://localhost:{port}/admin")
    print(f"   API docs: http://localhost:{port}/docs\n")
    
    # Run the uvicorn server
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=port,
        reload=os.getenv("DEBUG", "false").lower() == "true",
    )


if __name__ == "__main__":
    main()
