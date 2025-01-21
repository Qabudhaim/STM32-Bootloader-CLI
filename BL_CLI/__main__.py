#!/usr/bin/env python3

import sys
import os

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from BL_CLI.cli import cli

if __name__ == '__main__':
    cli() 