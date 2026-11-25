"""Custom errors."""


class AccountEnumToolError(Exception):
    """Base error for user-correctable failures."""


class SafetyGateError(AccountEnumToolError):
    """Raised when a scan would violate a safety limit."""
