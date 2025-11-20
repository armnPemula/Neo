#!/usr/bin/env python3
"""
NeoC2 Remote CLI Entry Point

This module serves as the entry point for the NeoC2 remote command-line interface.
The remote CLI connects to the C2 server via socket connection, supporting both local and remote operators.
"""

import sys
import argparse
from cli.remote_cli import main as remote_cli_main

def main():
    parser = argparse.ArgumentParser(description="NeoC2 Remote Command Line Interface")
    parser.add_argument("--remote-cli", action="store_true", help="Start remote CLI (default - connects to server via socket)")
    
    args = parser.parse_args()
    
    print("Starting NeoC2 Remote CLI (Socket-based)...")
    remote_cli_main()

if __name__ == "__main__":
    main()