from datetime import datetime, timezone
from collections import defaultdict
from functools import partial

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from models import Transaction
from engine import run_engine
from rules import check_amount_threshold, check_velocity, check_high_risk_mcc
from auth import init_db, router as auth_router, get_current_user, require_admin

app = FastAPI(title="Fraud Rule Engine")

init_db()
app.include_router(auth_router)

transaction_history = defaultdict(list)

RULE_CONFIG = {
    "amount_threshold": 2000.0,
    "review_threshold": 3.0,
    "decline_threshold": 6.0,
}


class TransactionIn(BaseModel):
    transaction_id: str
    card_id: str
    amount: float
    currency: str = "USD"
    merchant_id: str
    mcc: str
    country: str
    channel: str = "card_present"


class ConfigIn(BaseModel):
    amount_threshold: float
    review_threshold: float
    decline_threshold: float


# Any logged-in user (admin or analyst)
@app.post("/evaluate")
def evaluate(txn_in: TransactionIn, user: dict = Depends(get_current_user)):
    txn = Transaction(
        transaction_id=txn_in.transaction_id,
        card_id=txn_in.card_id,
        amount=txn_in.amount,
        currency=txn_in.currency,
        merchant_id=txn_in.merchant_id,
        mcc=txn_in.mcc,
        country=txn_in.country,
        timestamp=datetime.now(timezone.utc),
        channel=txn_in.channel,
    )

    active_rules = [
        partial(check_amount_threshold, threshold=RULE_CONFIG["amount_threshold"]),
        check_velocity,
        check_high_risk_mcc,
    ]

    result = run_engine(
        txn,
        transaction_history,
        rules=active_rules,
        review_threshold=RULE_CONFIG["review_threshold"],
        decline_threshold=RULE_CONFIG["decline_threshold"],
    )
    return result


# Any logged-in user can VIEW the rules
@app.get("/config")
def get_config(user: dict = Depends(get_current_user)):
    return RULE_CONFIG


# Only admins can CHANGE the rules
@app.post("/config")
def update_config(config: ConfigIn, admin: dict = Depends(require_admin)):
    RULE_CONFIG["amount_threshold"] = config.amount_threshold
    RULE_CONFIG["review_threshold"] = config.review_threshold
    RULE_CONFIG["decline_threshold"] = config.decline_threshold
    return RULE_CONFIG


# Public (for uptime checks)
@app.get("/health")
def health():
    return {"status": "ok"}