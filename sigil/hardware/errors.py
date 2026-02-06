"""
SE050 error handling.
"""

from sigil.hardware.constants import _ERROR_MESSAGES


class SE050Error(Exception):
    """Exception raised for SE050 errors"""
    def __init__(self, code: int, message: str = None):
        self.code = code
        self.message = message or _ERROR_MESSAGES.get(code, f"Unknown error ({code})")
        super().__init__(f"SE050 error {code}: {self.message}")
