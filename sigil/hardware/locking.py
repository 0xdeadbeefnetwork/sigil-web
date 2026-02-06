"""
File locking for exclusive SE050 access.

Provides cross-process locking to prevent concurrent access to the
SE050 secure element over the serial/USB interface.
"""

import os
import time
from pathlib import Path

# File locking for exclusive SE050 access
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False  # Windows

# Lock file location
_SE050_LOCK_FILE = Path("/tmp/sigil-se050.lock")
_SE050_LOCK_TIMEOUT = 30  # seconds to wait for lock
_SE050_LOCK_STALE_TIMEOUT = 120  # seconds before considering lock stale

def _check_stale_lock() -> bool:
    """
    Check if lock file exists and belongs to a dead process.
    Returns True if lock was stale and cleaned up.
    """
    if not _SE050_LOCK_FILE.exists():
        return False

    try:
        content = _SE050_LOCK_FILE.read_text().strip()
        if not content:
            return False

        pid = int(content.split()[0])

        # Check if process exists
        try:
            os.kill(pid, 0)  # Signal 0 = check if process exists
            # Process exists - check if it's been too long (might be hung)
            mtime = _SE050_LOCK_FILE.stat().st_mtime
            age = time.time() - mtime
            if age > _SE050_LOCK_STALE_TIMEOUT:
                print(f"  [SE050PY] Lock held by PID {pid} for {age:.0f}s - considering stale")
                _SE050_LOCK_FILE.unlink()
                return True
            return False
        except ProcessLookupError:
            # Process is dead - clean up stale lock
            print(f"  [SE050PY] Cleaning stale lock from dead PID {pid}")
            _SE050_LOCK_FILE.unlink()
            return True
        except PermissionError:
            # Can't check process - assume it's alive
            return False
    except Exception as e:
        # Any error - try to remove lock file
        try:
            _SE050_LOCK_FILE.unlink()
            return True
        except:
            return False
