#!/usr/bin/env python3
from vulnscan.main import main
import sys
import os

# Add the current directory to the path so we can import vulnscan
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    from vulnscan.main import main as run_scan
    run_scan()


if __name__ == "__main__":
    main()
