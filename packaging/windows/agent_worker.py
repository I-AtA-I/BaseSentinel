from __future__ import annotations

import os
import sys

os.environ["BASESENTINEL_AGENT_SCOPE"] = "machine"

from basesentinel_agent.cli import main

sys.argv = [sys.argv[0], "startup-service-run", *sys.argv[1:]]
raise SystemExit(main())
