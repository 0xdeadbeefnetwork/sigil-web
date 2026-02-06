"""
SIGIL Web - SE050 Session Management

Thread-safe context manager for SE050 hardware operations.
Connects at start, disconnects at end to allow device sharing
between the desktop app and web app.
"""

import time
import threading
from contextlib import contextmanager

from sigil.hardware.interface import se050_connect, se050_disconnect

_se050_lock = threading.Lock()


@contextmanager
def se050_session(max_retries: int = 3, retry_delay: float = 1.0):
    """
    Context manager for SE050 operations.
    Connects at start, disconnects at end.
    This allows the desktop app and web app to share the device.

    Args:
        max_retries: Number of connection attempts
        retry_delay: Seconds between retries
    """
    with _se050_lock:  # Thread safety within web app
        connected = False
        last_error = None

        for attempt in range(max_retries):
            try:
                if se050_connect(retries=2):
                    connected = True
                    break
                else:
                    last_error = "Connection returned False"
            except Exception as e:
                last_error = str(e)

            if attempt < max_retries - 1:
                time.sleep(retry_delay)

        if not connected:
            raise Exception(f"Failed to connect to SE050 after {max_retries} attempts: {last_error}")

        try:
            yield
        finally:
            try:
                se050_disconnect()
            except Exception:
                pass  # Ignore disconnect errors
