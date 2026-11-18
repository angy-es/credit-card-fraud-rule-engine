from sqlalchemy import Column, String, Float, DateTime, Boolean, ForeignKey, Integer
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from database import Base


class TransactionDB(Base):
    __tablename__ = "transactions"

    transaction_id = Column(String, primary_key=True)
    card_id = Column(String, index=True)
    amount = Column(Float)
    currency = Column(String)
    merchant_id = Column(String)
    mcc = Column(String)
    country = Column(String)
    channel = Column(String)
    transaction_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String)       # APPROVE / REVIEW / DECLINE
    risk_score = Column(Float)

    rule_evaluations = relationship("RuleEvaluationDB", back_populates="transaction")


class RuleEvaluationDB(Base):
    __tablename__ = "rule_evaluations"

    evaluation_id = Column(Integer, primary_key=True, autoincrement=True)
    transaction_id = Column(String, ForeignKey("transactions.transaction_id"))
    rule_name = Column(String)
    triggered = Column(Boolean)
    score_contribution = Column(Float)
    reason = Column(String)
    evaluated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    transaction = relationship("TransactionDB", back_populates="rule_evaluations")