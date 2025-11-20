"""
CLI components of the NeoC2 framework.
This module now contains the socket-based remote CLI for connecting to the C2 server.
"""

from .remote_cli import NeoC2RemoteCLI

__all__ = [
    'NeoC2RemoteCLI'
]
