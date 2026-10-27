"""Website change monitor — entry point.

    python monitor_system.py run              start monitoring (default)
    python monitor_system.py inspect URL      analyse a page and suggest settings
    python monitor_system.py --help           all commands
"""

import sys

from webmonitor.cli import main

if __name__ == "__main__":
    sys.exit(main())
