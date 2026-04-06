
"""
VulnScan - Advanced Vulnerability Scanner

A comprehensive web application vulnerability scanner with AI-powered detection.
"""

__version__ = "3.4.5"
__author__ = "Gokul Kannan Ganesamoorthy"
__email__ = "gokulkannan.dev@gmail.com"

# Import main components for easier access
from .main import *
from .cli import main as cli_main

__all__ = ["main", "cli_main", "__version__"]
