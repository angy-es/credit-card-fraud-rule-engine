from datetime import timedelta
from collections import defaultdict


def check_amount_threshold(txn, history, threshold=2000.0):
    triggered = txn.amount > threshold
    reason = f"amount ${txn.amount:.2f} exceeds threshold ${threshold:.2f}" if triggered else ""
    return {
        "rule_name": "amount_threshold",
        "triggered": triggered,
        "score": 2.0 if triggered else 0.0,
        "reason": reason,
    }


def check_velocity(txn, history, window_seconds=600, max_count=5):
    window = timedelta(seconds=window_seconds)
    cutoff = txn.timestamp - window

    recent = [t for t in history[txn.card_id] if t.timestamp >= cutoff]
    count = len(recent) + 1

    triggered = count > max_count
    reason = f"{count} txns in {window_seconds}s (limit {max_count})" if triggered else ""

    return {
        "rule_name": "velocity",
        "triggered": triggered,
        "score": 2.0 if triggered else 0.0,
        "reason": reason,
    }


def check_high_risk_mcc(txn, history, high_risk_mccs=None):
    if high_risk_mccs is None:
        high_risk_mccs = {"7995", "6051", "4829"}

    triggered = txn.mcc in high_risk_mccs
    reason = f"MCC {txn.mcc} is on the high-risk list" if triggered else ""

    return {
        "rule_name": "high_risk_mcc",
        "triggered": triggered,
        "score": 1.5 if triggered else 0.0,
        "reason": reason,
    }


def check_device_sharing(txn, device_history, window_hours=24, max_distinct_cards=3):
    if txn.device_id is None:
        return {"rule_name": "device_sharing", "triggered": False, "score": 0.0, "reason": "no device_id"}

    window = timedelta(hours=window_hours)
    cutoff = txn.timestamp - window

    recent = [t for t in device_history[txn.device_id] if t.timestamp >= cutoff]
    distinct_cards = {t.card_id for t in recent} | {txn.card_id}

    triggered = len(distinct_cards) > max_distinct_cards
    reason = f"{len(distinct_cards)} distinct cards on device {txn.device_id} in {window_hours}h (limit {max_distinct_cards})" if triggered else ""

    return {
        "rule_name": "device_sharing",
        "triggered": triggered,
        "score": 2.5 if triggered else 0.0,
        "reason": reason,
    }


def check_blacklist(txn, blacklisted_cards):
    triggered = txn.card_id in blacklisted_cards
    reason = f"card {txn.card_id} is on the blacklist" if triggered else ""

    return {
        "rule_name": "blacklist",
        "triggered": triggered,
        "score": 10.0 if triggered else 0.0,
        "reason": reason,
    }