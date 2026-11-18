def run_engine(txn, history, rules=None, review_threshold=3.0, decline_threshold=6.0):
    from rules import check_amount_threshold, check_velocity

    if rules is None:
        rules = [check_amount_threshold, check_velocity]

    results = [rule_fn(txn, history) for rule_fn in rules]

    total_score = sum(r["score"] for r in results if r["triggered"])

    if total_score >= decline_threshold:
        decision = "DECLINE"
    elif total_score >= review_threshold:
        decision = "REVIEW"
    else:
        decision = "APPROVE"

    history[txn.card_id].append(txn)

    return {
        "transaction_id": txn.transaction_id,
        "total_score": total_score,
        "decision": decision,
        "triggered_rules": [r for r in results if r["triggered"]],
    }