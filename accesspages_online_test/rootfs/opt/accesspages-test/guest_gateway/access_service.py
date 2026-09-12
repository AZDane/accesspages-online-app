"""Errors from the OpenNHP Service control adapter."""
class AccessServiceError(RuntimeError):
    def __init__(self, message, status=None, detail=None):
        super().__init__(message)
        self.status = status
        self.detail = detail
