#!/usr/bin/env python
"""The main entry point. Invoke as `syncrypto' or `python -m syncrypto'.

"""
import sys
from .core import main


if __name__ == '__main__':
    sys.exit(main())
