__version__ = "1.0.0"

import sys
import platform

if platform.system().lower() != "linux":
    raise RuntimeError(
        f"AIDK is Linux-only. Detected: {platform.system()}"
    )

if not (sys.version_info.major == 3 and sys.version_info.minor == 10):
    raise RuntimeError(
        f"AIDK requires Python 3.10.x exactly. Detected: {sys.version.split()[0]}"
    )

from .ai_dev_kit import *
__all__ = []

