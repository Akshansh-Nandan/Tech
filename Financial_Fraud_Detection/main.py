from datetime import datetime, timedelta
from federal_fraud_engine import FraudEngine
import json

# Example Usage
engine = FraudEngine()
now = datetime.now()
recent_txns = [(200, now - timedelta(minutes=60 - i * 10)) for i in range(600)]
profile = {
    "amounts": [199, 240, 500, 50, 10, 15],
    "cities": {
        "Delhi": 4,
        "Mumbai": 2
    },
    "devices": {
        "dev-x1": 5,
        "dev-backup": 1
    },
    "time_slots": {
        "morning": 3,
        "evening": 2
    }
}

result = engine.detect(
    txn_amount=250,
    city="Bhagalpur",
    device_id="dev-x1",
    user_id="user_999",
    profile=profile,
    txn_time=now,
    risk_history_of_user=[0.1, 0.17, 0.23, 0.45, 0.31, 0.76],
    last_city="Mumbai",
    recent_txns=recent_txns,
    recent_devices={"dev-old"},
    recent_time_slots={"morning": 3, "evening": 2},
    recent_amount_buckets={"low": 4, "micro": 10, "medium": 1},
    current_velocity=7
)

print(json.dumps(result, indent=4))

print()
input("Press `Enter` to continue... ")


