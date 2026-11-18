from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Transaction:
    transaction_id: str
    card_id: str
    amount: float
    currency: str

    merchant_id: str
    mcc: str
    country: str

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    channel: str = "card_present"

    latitude: Optional[float] = None
    longitude: Optional[float] = None
    card_country: Optional[str] = None
    device_id: Optional[str] = None