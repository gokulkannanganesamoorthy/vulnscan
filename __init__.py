
"""
VulnScan - Advanced Vulnerability Scanner

A comprehensive web application vulnerability scanner with AI-powered detection.
"""

__version__ = "1.0.3"
__author__ = "Gokul Kannan Ganesamoorthy"
__email__ = "gokulkannan.dev@gmail.com"

# Import main components for easier access
from .main import *
from .cli import main as cli_main

__all__ = ["main", "cli_main", "__version__"]
