import json
import logging
from datetime import datetime, timezone

_logger = logging.getLogger("access_service_gateway.audit")
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_handler)
_logger.setLevel(logging.INFO)
_logger.propagate = False


def audit(event: str, **fields) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event": event,
        **{key: value for key, value in fields.items() if value not in (None, "")},
    }
    _logger.info(json.dumps(payload, separators=(",", ":"), sort_keys=True))
