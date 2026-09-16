"""MCPShield: static scanner for Model Context Protocol servers."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcpshield")
except PackageNotFoundError:  # running from a checkout without an install
    __version__ = "0.0.0+dev"
