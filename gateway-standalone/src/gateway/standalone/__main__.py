"""Run the gateway: python -m gateway.standalone

The entry point is this module rather than `server`, so `server` is only ever
imported.
"""

import sys

from gateway.standalone.server import main

sys.exit(main())
