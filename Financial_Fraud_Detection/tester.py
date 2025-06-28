from federal_fraud_engine import FraudEngine
from datetime import datetime, timedelta
import numpy as np

engine = FraudEngine()
now = datetime.now()

# 💥 Hardcoded labeled test cases
test_cases = [
    # ----- Safe -----
    {
        "txn_amount": 50,
        "city": "Delhi",
        "device_id": "dev-x1",
        "user_id": "user_001",
        "profile": {
            "amounts": [45, 60, 40],
            "cities": {"Delhi": 5},
            "devices": {"dev-x1": 3},
            "time_slots": {"morning": 3}
        },
        "txn_time": now,
        "risk_history": [0.1, 0.2, 0.25],
        "last_city": "Delhi",
        "recent_txns": [(50, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"morning": 3},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 1,
        "label": "Safe"
    },
    # ----- Suspicious -----
    {
        "txn_amount": 4000,
        "city": "Mumbai",
        "device_id": "dev-new",
        "user_id": "user_002",
        "profile": {
            "amounts": [2000, 2500],
            "cities": {"Mumbai": 1},
            "devices": {"dev-old": 1},
            "time_slots": {"night": 1}
        },
        "txn_time": now.replace(hour=3),
        "risk_history": [0.2, 0.3, 0.5],
        "last_city": "Delhi",
        "recent_txns": [(3000, now - timedelta(minutes=20*i)) for i in range(5)],
        "recent_devices": {"dev-old"},
        "recent_time_slots": {"night": 1},
        "recent_amount_buckets": {"medium": 3},
        "current_velocity": 4,
        "label": "Suspicious"
    },
    # ----- Alert -----
    {
        "txn_amount": 99000,
        "city": "Bhagalpur",
        "device_id": "hacked-1337",
        "user_id": "user_003",
        "profile": {
            "amounts": [500, 600],
            "cities": {"Delhi": 2},
            "devices": {"dev-x1": 2},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=2),
        "risk_history": [0.6, 0.8, 0.9],
        "last_city": "Mumbai",
        "recent_txns": [(500, now - timedelta(minutes=2*i)) for i in range(10)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"micro": 5, "low": 3},
        "current_velocity": 7,
        "label": "Alert"
    },
    # ----- Suspicious -----
    {
        "txn_amount": 700,
        "city": "Ranchi",
        "device_id": "dev-x1",
        "user_id": "user_004",
        "profile": {
            "amounts": [100, 150, 90],
            "cities": {"Delhi": 2, "Mumbai": 2},
            "devices": {"dev-x1": 2},
            "time_slots": {"evening": 1}
        },
        "txn_time": now.replace(hour=18),
        "risk_history": [0.3, 0.4, 0.5],
        "last_city": "Delhi",
        "recent_txns": [(200, now - timedelta(minutes=12*i)) for i in range(5)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"evening": 1},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 2,
        "label": "Suspicious"
    },
    # ----- Alert -----
    {
        "txn_amount": 8,
        "city": "Lucknow",
        "device_id": "unknown-device",
        "user_id": "user_005",
        "profile": {
            "amounts": [10, 12, 11],
            "cities": {"Delhi": 1},
            "devices": {"dev-old": 1},
            "time_slots": {"night": 1}
        },
        "txn_time": now.replace(hour=1),
        "risk_history": [0.7, 0.9, 0.8],
        "last_city": "Kanpur",
        "recent_txns": [(8, now - timedelta(minutes=i)) for i in range(15)],
        "recent_devices": {"dev-old"},
        "recent_time_slots": {"night": 3},
        "recent_amount_buckets": {"micro": 15},
        "current_velocity": 6,
        "label": "Alert"
    },
    # ----- Safe -----
    {
        "txn_amount": 220,
        "city": "Kolkata",
        "device_id": "dev-x1",
        "user_id": "user_006",
        "profile": {
            "amounts": [200, 210, 230],
            "cities": {"Kolkata": 4},
            "devices": {"dev-x1": 3},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=13),
        "risk_history": [0.1, 0.1, 0.2],
        "last_city": "Kolkata",
        "recent_txns": [(210, now - timedelta(minutes=6*i)) for i in range(5)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 2,
        "label": "Safe"
    },
    # ----- Alert (speed + tier + unknown everything) -----
    {
        "txn_amount": 18000,
        "city": "Agartala",
        "device_id": "unreg-209",
        "user_id": "user_007",
        "profile": {
            "amounts": [1000, 1500],
            "cities": {"Mumbai": 2},
            "devices": {"dev-10": 2},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=5),
        "risk_history": [0.7, 0.85, 0.9],
        "last_city": "Pune",
        "recent_txns": [(1200, now - timedelta(minutes=3*i)) for i in range(6)],
        "recent_devices": {"dev-10"},
        "recent_time_slots": {"evening": 3},
        "recent_amount_buckets": {"medium": 4},
        "current_velocity": 5,
        "label": "Alert"
    },
    # ----- Suspicious (amount spike, new city, mild activity) -----
    {
        "txn_amount": 4500,
        "city": "Surat",
        "device_id": "dev-x1",
        "user_id": "user_008",
        "profile": {
            "amounts": [500, 600],
            "cities": {"Delhi": 2},
            "devices": {"dev-x1": 2},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=8),
        "risk_history": [0.2, 0.4],
        "last_city": "Delhi",
        "recent_txns": [(550, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"morning": 1},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 3,
        "label": "Suspicious"
    },
    # ----- Safe (frequent txn pattern) -----
    {
        "txn_amount": 320,
        "city": "Pune",
        "device_id": "dev-x1",
        "user_id": "user_009",
        "profile": {
            "amounts": [300, 310, 340],
            "cities": {"Pune": 5},
            "devices": {"dev-x1": 5},
            "time_slots": {"evening": 4}
        },
        "txn_time": now.replace(hour=19),
        "risk_history": [0.15, 0.12, 0.11],
        "last_city": "Pune",
        "recent_txns": [(320, now - timedelta(minutes=8*i)) for i in range(5)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"evening": 4},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 2,
        "label": "Safe"
    },
    # ----- Alert (burn pattern: large, late, velocity, new city) -----
    {
        "txn_amount": 99999,
        "city": "Srinagar",
        "device_id": "burner-1",
        "user_id": "user_010",
        "profile": {
            "amounts": [5000, 8000, 10000],
            "cities": {"Delhi": 2},
            "devices": {"trusted-1": 2},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=23),
        "risk_history": [0.9, 0.95, 0.88],
        "last_city": "Delhi",
        "recent_txns": [(10000, now - timedelta(minutes=1*i)) for i in range(10)],
        "recent_devices": {"trusted-1"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"critical": 3},
        "current_velocity": 9,
        "label": "Alert"
    },
    # ----- Alert (multiple new elements, spike, odd hour) -----
    {
        "txn_amount": 85000,
        "city": "Imphal",
        "device_id": "unknown-lap",
        "user_id": "user_011",
        "profile": {
            "amounts": [1000, 1200],
            "cities": {"Kolkata": 3},
            "devices": {"dev-x1": 3},
            "time_slots": {"morning": 2}
        },
        "txn_time": now.replace(hour=2),
        "risk_history": [0.65, 0.7, 0.72],
        "last_city": "Kolkata",
        "recent_txns": [(1100, now - timedelta(minutes=1*i)) for i in range(8)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 8,
        "label": "Alert"
    },
    # ----- Safe (known device, time, city, tier-1) -----
    {
        "txn_amount": 310,
        "city": "Bangalore",
        "device_id": "dev-main",
        "user_id": "user_012",
        "profile": {
            "amounts": [300, 305, 315],
            "cities": {"Bangalore": 6},
            "devices": {"dev-main": 5},
            "time_slots": {"afternoon": 3}
        },
        "txn_time": now.replace(hour=13),
        "risk_history": [0.1, 0.15],
        "last_city": "Bangalore",
        "recent_txns": [(305, now - timedelta(minutes=8*i)) for i in range(5)],
        "recent_devices": {"dev-main"},
        "recent_time_slots": {"afternoon": 3},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 2,
        "label": "Safe"
    },
    # ----- Suspicious (city jump + time slot change + entropy rise) -----
    {
        "txn_amount": 1200,
        "city": "Indore",
        "device_id": "dev-x1",
        "user_id": "user_013",
        "profile": {
            "amounts": [900, 950],
            "cities": {"Bhopal": 3},
            "devices": {"dev-x1": 3},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=9),
        "risk_history": [0.3, 0.45, 0.5],
        "last_city": "Bhopal",
        "recent_txns": [(920, now - timedelta(minutes=10*i)) for i in range(6)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"evening": 2},
        "recent_amount_buckets": {"medium": 3},
        "current_velocity": 3,
        "label": "Suspicious"
    },
    # ----- Alert (small town, new device, night abuse, entropy spike) -----
    {
        "txn_amount": 100,
        "city": "Banda",
        "device_id": "dev-rogue",
        "user_id": "user_014",
        "profile": {
            "amounts": [80, 90],
            "cities": {"Lucknow": 3},
            "devices": {"dev-home": 2},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=1),
        "risk_history": [0.6, 0.75, 0.7],
        "last_city": "Lucknow",
        "recent_txns": [(90, now - timedelta(minutes=i)) for i in range(12)],
        "recent_devices": {"dev-home"},
        "recent_time_slots": {"morning": 1},
        "recent_amount_buckets": {"micro": 12},
        "current_velocity": 6,
        "label": "Alert"
    },
    # ----- Suspicious (new time, city-tier shift, mid-velocity) -----
    {
        "txn_amount": 2750,
        "city": "Guwahati",
        "device_id": "dev-x1",
        "user_id": "user_015",
        "profile": {
            "amounts": [2400, 2600],
            "cities": {"Delhi": 2},
            "devices": {"dev-x1": 2},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=22),
        "risk_history": [0.4, 0.5, 0.45],
        "last_city": "Delhi",
        "recent_txns": [(2500, now - timedelta(minutes=5*i)) for i in range(5)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 4,
        "label": "Suspicious"
    },
    # ----- Safe (normal activity, consistent slots, known pattern) -----
    {
        "txn_amount": 120,
        "city": "Hyderabad",
        "device_id": "laptop-01",
        "user_id": "user_016",
        "profile": {
            "amounts": [100, 110, 115],
            "cities": {"Hyderabad": 6},
            "devices": {"laptop-01": 4},
            "time_slots": {"night": 3}
        },
        "txn_time": now.replace(hour=23),
        "risk_history": [0.15, 0.12, 0.1],
        "last_city": "Hyderabad",
        "recent_txns": [(110, now - timedelta(minutes=10*i)) for i in range(4)],
        "recent_devices": {"laptop-01"},
        "recent_time_slots": {"night": 3},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 1,
        "label": "Safe"
    },
    # ----- Alert (burn device, velocity abuse, regression spike) -----
    {
        "txn_amount": 20000,
        "city": "Varanasi",
        "device_id": "dev-temp",
        "user_id": "user_017",
        "profile": {
            "amounts": [500, 800],
            "cities": {"Kanpur": 2},
            "devices": {"dev-trusted": 3},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=7),
        "risk_history": [0.6, 0.8],
        "last_city": "Kanpur",
        "recent_txns": [(700, now - timedelta(minutes=1*i)) for i in range(10)],
        "recent_devices": {"dev-trusted"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 9,
        "label": "Alert"
    },
    # ----- Suspicious (medium velocity, micro entropy, new city) -----
    {
        "txn_amount": 18,
        "city": "Patna",
        "device_id": "dev-x1",
        "user_id": "user_018",
        "profile": {
            "amounts": [10, 12, 13],
            "cities": {"Delhi": 2},
            "devices": {"dev-x1": 3},
            "time_slots": {"evening": 1}
        },
        "txn_time": now.replace(hour=17),
        "risk_history": [0.3, 0.35],
        "last_city": "Delhi",
        "recent_txns": [(11, now - timedelta(minutes=2*i)) for i in range(7)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"evening": 1},
        "recent_amount_buckets": {"micro": 7},
        "current_velocity": 5,
        "label": "Suspicious"
    },
    # ----- Safe (weekend pattern, known IP-city-device) -----
    {
        "txn_amount": 900,
        "city": "Chennai",
        "device_id": "dev-office",
        "user_id": "user_019",
        "profile": {
            "amounts": [880, 950],
            "cities": {"Chennai": 5},
            "devices": {"dev-office": 4},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=14),
        "risk_history": [0.1, 0.2],
        "last_city": "Chennai",
        "recent_txns": [(900, now - timedelta(minutes=10*i)) for i in range(3)],
        "recent_devices": {"dev-office"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"medium": 3},
        "current_velocity": 1,
        "label": "Safe"
    },
    # ----- Alert (city shift + high amount + new everything) -----
    {
        "txn_amount": 9999,
        "city": "Shillong",
        "device_id": "new-rogue-dev",
        "user_id": "user_020",
        "profile": {
            "amounts": [500, 700],
            "cities": {"Mumbai": 3},
            "devices": {"trusted": 2},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=21),
        "risk_history": [0.85, 0.95],
        "last_city": "Mumbai",
        "recent_txns": [(650, now - timedelta(minutes=1*i)) for i in range(7)],
        "recent_devices": {"trusted"},
        "recent_time_slots": {"morning": 1},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 6,
        "label": "Alert"
    },
    # -- SAFE CASES --
    {
        "txn_amount": 120,
        "city": "Delhi",
        "device_id": "dev-01",
        "user_id": "user_001",
        "profile": {
            "amounts": [100, 110, 130],
            "cities": {"Delhi": 5},
            "devices": {"dev-01": 3},
            "time_slots": {"morning": 3}
        },
        "txn_time": now.replace(hour=10),
        "risk_history": [0.1, 0.2],
        "last_city": "Delhi",
        "recent_txns": [(120, now - timedelta(minutes=20*i)) for i in range(5)],
        "recent_devices": {"dev-01"},
        "recent_time_slots": {"morning": 3},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 2,
        "label": "Safe"
    },
    {
        "txn_amount": 40,
        "city": "Jaipur",
        "device_id": "dev-jpr",
        "user_id": "user_002",
        "profile": {
            "amounts": [30, 50, 35],
            "cities": {"Jaipur": 6},
            "devices": {"dev-jpr": 4},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=19),
        "risk_history": [0.05, 0.15],
        "last_city": "Jaipur",
        "recent_txns": [(40, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-jpr"},
        "recent_time_slots": {"evening": 2},
        "recent_amount_buckets": {"micro": 5},
        "current_velocity": 1,
        "label": "Safe"
    },
    {
        "txn_amount": 499,
        "city": "Kolkata",
        "device_id": "dev-kolkata",
        "user_id": "user_003",
        "profile": {
            "amounts": [450, 480, 510],
            "cities": {"Kolkata": 3},
            "devices": {"dev-kolkata": 3},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=13),
        "risk_history": [0.2, 0.18],
        "last_city": "Kolkata",
        "recent_txns": [(480, now - timedelta(minutes=15*i)) for i in range(4)],
        "recent_devices": {"dev-kolkata"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 1,
        "label": "Safe"
    },
    {
        "txn_amount": 600,
        "city": "Hyderabad",
        "device_id": "dev-hyd",
        "user_id": "user_004",
        "profile": {
            "amounts": [580, 610],
            "cities": {"Hyderabad": 5},
            "devices": {"dev-hyd": 2},
            "time_slots": {"afternoon": 1}
        },
        "txn_time": now.replace(hour=15),
        "risk_history": [0.3, 0.25],
        "last_city": "Hyderabad",
        "recent_txns": [(590, now - timedelta(minutes=25*i)) for i in range(3)],
        "recent_devices": {"dev-hyd"},
        "recent_time_slots": {"afternoon": 1},
        "recent_amount_buckets": {"medium": 3},
        "current_velocity": 1,
        "label": "Safe"
    },
    {
        "txn_amount": 75,
        "city": "Bangalore",
        "device_id": "dev-blr",
        "user_id": "user_005",
        "profile": {
            "amounts": [70, 80],
            "cities": {"Bangalore": 2},
            "devices": {"dev-blr": 2},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=9),
        "risk_history": [0.2, 0.15],
        "last_city": "Bangalore",
        "recent_txns": [(72, now - timedelta(minutes=12*i)) for i in range(3)],
        "recent_devices": {"dev-blr"},
        "recent_time_slots": {"morning": 1},
        "recent_amount_buckets": {"low": 3},
        "current_velocity": 1,
        "label": "Safe"
    },

    # -- SUSPICIOUS CASES --
    {
        "txn_amount": 3200,
        "city": "Ahmedabad",
        "device_id": "dev-new",
        "user_id": "user_006",
        "profile": {
            "amounts": [1500, 1800],
            "cities": {"Delhi": 3},
            "devices": {"old-pc": 2},
            "time_slots": {"night": 1}
        },
        "txn_time": now.replace(hour=2),
        "risk_history": [0.4, 0.5, 0.6],
        "last_city": "Delhi",
        "recent_txns": [(1500, now - timedelta(minutes=20*i)) for i in range(5)],
        "recent_devices": {"old-pc"},
        "recent_time_slots": {"night": 1},
        "recent_amount_buckets": {"medium": 4},
        "current_velocity": 3,
        "label": "Suspicious"
    },
    {
        "txn_amount": 7000,
        "city": "Pune",
        "device_id": "dev-unknown",
        "user_id": "user_007",
        "profile": {
            "amounts": [2000, 2100],
            "cities": {"Mumbai": 2},
            "devices": {"dev-mumbai": 1},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=11),
        "risk_history": [0.3, 0.55],
        "last_city": "Mumbai",
        "recent_txns": [(2000, now - timedelta(minutes=30*i)) for i in range(5)],
        "recent_devices": {"dev-mumbai"},
        "recent_time_slots": {"morning": 1},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 2,
        "label": "Suspicious"
    },
    {
        "txn_amount": 80,
        "city": "Nashik",
        "device_id": "dev-new2",
        "user_id": "user_008",
        "profile": {
            "amounts": [50, 55],
            "cities": {"Delhi": 3},
            "devices": {"dev-x": 1},
            "time_slots": {"evening": 1}
        },
        "txn_time": now.replace(hour=23),
        "risk_history": [0.4, 0.45],
        "last_city": "Delhi",
        "recent_txns": [(60, now - timedelta(minutes=15*i)) for i in range(4)],
        "recent_devices": {"dev-x"},
        "recent_time_slots": {"evening": 1},
        "recent_amount_buckets": {"micro": 4},
        "current_velocity": 3,
        "label": "Suspicious"
    },

    # -- ALERT CASES --
    {
        "txn_amount": 95000,
        "city": "Nagpur",
        "device_id": "hacked-001",
        "user_id": "user_009",
        "profile": {
            "amounts": [300, 350],
            "cities": {"Delhi": 1},
            "devices": {"pc-old": 1},
            "time_slots": {"afternoon": 1}
        },
        "txn_time": now.replace(hour=1),
        "risk_history": [0.8, 0.9],
        "last_city": "Delhi",
        "recent_txns": [(300, now - timedelta(minutes=2*i)) for i in range(10)],
        "recent_devices": {"pc-old"},
        "recent_time_slots": {"afternoon": 1},
        "recent_amount_buckets": {"micro": 4, "low": 2},
        "current_velocity": 6,
        "label": "Alert"
    },
    {
        "txn_amount": 7,
        "city": "Lucknow",
        "device_id": "rogue-x",
        "user_id": "user_010",
        "profile": {
            "amounts": [5, 6],
            "cities": {"Delhi": 1},
            "devices": {"known-dev": 1},
            "time_slots": {"night": 1}
        },
        "txn_time": now.replace(hour=2),
        "risk_history": [0.9, 0.85],
        "last_city": "Kanpur",
        "recent_txns": [(7, now - timedelta(minutes=1*i)) for i in range(20)],
        "recent_devices": {"known-dev"},
        "recent_time_slots": {"night": 3},
        "recent_amount_buckets": {"micro": 20},
        "current_velocity": 10,
        "label": "Alert"
    },
    # --- ALERT: Insane velocity + huge deviation ---
    {
        "txn_amount": 150000,
        "city": "Patna",
        "device_id": "burner-99",
        "user_id": "user_011",
        "profile": {
            "amounts": [3000, 3100],
            "cities": {"Delhi": 2},
            "devices": {"dev-main": 1},
            "time_slots": {"morning": 2}
        },
        "txn_time": now.replace(hour=4),
        "risk_history": [0.7, 0.8, 0.9],
        "last_city": "Delhi",
        "recent_txns": [(3000, now - timedelta(minutes=1*i)) for i in range(10)],
        "recent_devices": {"dev-main"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"medium": 10},
        "current_velocity": 10,
        "label": "Alert"
    },

    # --- SUSPICIOUS: Foreign city, small jump ---
    {
        "txn_amount": 1200,
        "city": "Chandigarh",
        "device_id": "dev-c1",
        "user_id": "user_012",
        "profile": {
            "amounts": [1100, 1150],
            "cities": {"Lucknow": 3},
            "devices": {"dev-c1": 2},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=16),
        "risk_history": [0.3, 0.4],
        "last_city": "Lucknow",
        "recent_txns": [(1100, now - timedelta(minutes=15*i)) for i in range(5)],
        "recent_devices": {"dev-c1"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 2,
        "label": "Suspicious"
    },

    # --- ALERT: Impossible travel + foreign device + time shift ---
    {
        "txn_amount": 9800,
        "city": "London",
        "device_id": "new-global-1",
        "user_id": "user_013",
        "profile": {
            "amounts": [3000, 3200],
            "cities": {"Mumbai": 2},
            "devices": {"local-dev": 2},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=3),
        "risk_history": [0.85, 0.9],
        "last_city": "Mumbai",
        "recent_txns": [(3100, now - timedelta(minutes=30*i)) for i in range(6)],
        "recent_devices": {"local-dev"},
        "recent_time_slots": {"evening": 2},
        "recent_amount_buckets": {"medium": 6},
        "current_velocity": 6,
        "label": "Alert"
    },

    # --- SUSPICIOUS: Same pattern, but unexpected device ---
    {
        "txn_amount": 600,
        "city": "Indore",
        "device_id": "dev-x2",
        "user_id": "user_014",
        "profile": {
            "amounts": [500, 550],
            "cities": {"Indore": 5},
            "devices": {"dev-x1": 3},
            "time_slots": {"morning": 2}
        },
        "txn_time": now.replace(hour=10),
        "risk_history": [0.3, 0.4],
        "last_city": "Indore",
        "recent_txns": [(550, now - timedelta(minutes=10*i)) for i in range(4)],
        "recent_devices": {"dev-x1"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"medium": 4},
        "current_velocity": 1,
        "label": "Suspicious"
    },

    # --- SAFE: Purely stable ---
    {
        "txn_amount": 99,
        "city": "Chennai",
        "device_id": "dev-chennai",
        "user_id": "user_015",
        "profile": {
            "amounts": [90, 100, 110],
            "cities": {"Chennai": 4},
            "devices": {"dev-chennai": 3},
            "time_slots": {"morning": 2}
        },
        "txn_time": now.replace(hour=9),
        "risk_history": [0.1, 0.12],
        "last_city": "Chennai",
        "recent_txns": [(100, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-chennai"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- ALERT: Micro-spam fraud ---
    {
        "txn_amount": 3,
        "city": "Bhopal",
        "device_id": "rogue-micro",
        "user_id": "user_016",
        "profile": {
            "amounts": [5, 7],
            "cities": {"Bhopal": 1},
            "devices": {"old-tab": 1},
            "time_slots": {"night": 1}
        },
        "txn_time": now.replace(hour=2),
        "risk_history": [0.8, 0.9],
        "last_city": "Bhopal",
        "recent_txns": [(3, now - timedelta(minutes=1*i)) for i in range(20)],
        "recent_devices": {"old-tab"},
        "recent_time_slots": {"night": 3},
        "recent_amount_buckets": {"micro": 20},
        "current_velocity": 15,
        "label": "Alert"
    },

    # --- SAFE: Mid-range, everything known ---
    {
        "txn_amount": 4200,
        "city": "Surat",
        "device_id": "dev-surat",
        "user_id": "user_017",
        "profile": {
            "amounts": [4000, 4300],
            "cities": {"Surat": 3},
            "devices": {"dev-surat": 2},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=14),
        "risk_history": [0.2, 0.15],
        "last_city": "Surat",
        "recent_txns": [(4200, now - timedelta(minutes=20*i)) for i in range(5)],
        "recent_devices": {"dev-surat"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- ALERT: Sudden huge jump in amount ---
    {
        "txn_amount": 100000,
        "city": "Raipur",
        "device_id": "hacked-ai",
        "user_id": "user_018",
        "profile": {
            "amounts": [500, 600],
            "cities": {"Raipur": 2},
            "devices": {"dev-old": 2},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=21),
        "risk_history": [0.65, 0.75],
        "last_city": "Raipur",
        "recent_txns": [(600, now - timedelta(minutes=10*i)) for i in range(6)],
        "recent_devices": {"dev-old"},
        "recent_time_slots": {"evening": 2},
        "recent_amount_buckets": {"medium": 6},
        "current_velocity": 2,
        "label": "Alert"
    },

    # --- SUSPICIOUS: Rare city, weird time ---
    {
        "txn_amount": 1100,
        "city": "Shillong",
        "device_id": "dev-alt",
        "user_id": "user_019",
        "profile": {
            "amounts": [1050, 1000],
            "cities": {"Delhi": 2},
            "devices": {"dev-delhi": 2},
            "time_slots": {"morning": 2}
        },
        "txn_time": now.replace(hour=1),
        "risk_history": [0.4, 0.45],
        "last_city": "Delhi",
        "recent_txns": [(1000, now - timedelta(minutes=10*i)) for i in range(4)],
        "recent_devices": {"dev-delhi"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"medium": 4},
        "current_velocity": 2,
        "label": "Suspicious"
    },

    # --- SAFE: Everything matches like a boss ---
    # TRANSACTION EXAMPLE FOR TESTING
    {
        "txn_amount": 280,
        "city": "Noida",
        "device_id": "dev-noida",
        "user_id": "user_020",
        "profile": {
            "amounts": [270, 290],
            "cities": {"Noida": 3},
            "devices": {"dev-noida": 3},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=18),
        "risk_history": [0.1, 0.2],
        "last_city": "Noida",
        "recent_txns": [(280, now - timedelta(minutes=15*i)) for i in range(5)],
        "recent_devices": {"dev-noida"},
        "recent_time_slots": {"evening": 2},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 1,
        "label": "Safe"
    },
    # --- SAFE: Known city, common amount, known device ---
    {
        "txn_amount": 300,
        "city": "Hyderabad",
        "device_id": "dev-hyd",
        "user_id": "user_021",
        "profile": {
            "amounts": [280, 320, 290],
            "cities": {"Hyderabad": 5},
            "devices": {"dev-hyd": 4},
            "time_slots": {"morning": 3}
        },
        "txn_time": now.replace(hour=9),
        "risk_history": [0.1, 0.2],
        "last_city": "Hyderabad",
        "recent_txns": [(300, now - timedelta(minutes=12*i)) for i in range(4)],
        "recent_devices": {"dev-hyd"},
        "recent_time_slots": {"morning": 3},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- SUSPICIOUS: Slightly new device, valid pattern ---
    {
        "txn_amount": 1300,
        "city": "Ahmedabad",
        "device_id": "dev-new-a",
        "user_id": "user_022",
        "profile": {
            "amounts": [1200, 1250],
            "cities": {"Ahmedabad": 3},
            "devices": {"dev-old-a": 2},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=14),
        "risk_history": [0.3, 0.4],
        "last_city": "Ahmedabad",
        "recent_txns": [(1250, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-old-a"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 2,
        "label": "Suspicious"
    },

    # --- SAFE: Known low activity account ---
    {
        "txn_amount": 20,
        "city": "Pune",
        "device_id": "dev-pune",
        "user_id": "user_023",
        "profile": {
            "amounts": [15, 25],
            "cities": {"Pune": 2},
            "devices": {"dev-pune": 2},
            "time_slots": {"evening": 1}
        },
        "txn_time": now.replace(hour=19),
        "risk_history": [0.1],
        "last_city": "Pune",
        "recent_txns": [(20, now - timedelta(minutes=20*i)) for i in range(3)],
        "recent_devices": {"dev-pune"},
        "recent_time_slots": {"evening": 1},
        "recent_amount_buckets": {"micro": 3},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- SUSPICIOUS: Known everything but unusual time slot ---
    {
        "txn_amount": 600,
        "city": "Kolkata",
        "device_id": "dev-kolkata",
        "user_id": "user_024",
        "profile": {
            "amounts": [580, 610],
            "cities": {"Kolkata": 3},
            "devices": {"dev-kolkata": 2},
            "time_slots": {"evening": 2}
        },
        "txn_time": now.replace(hour=3),
        "risk_history": [0.3],
        "last_city": "Kolkata",
        "recent_txns": [(590, now - timedelta(minutes=15*i)) for i in range(4)],
        "recent_devices": {"dev-kolkata"},
        "recent_time_slots": {"evening": 2},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 1,
        "label": "Suspicious"
    },

    # --- SAFE: Mid-frequency, calm profile ---
    {
        "txn_amount": 1450,
        "city": "Nagpur",
        "device_id": "dev-nagpur",
        "user_id": "user_025",
        "profile": {
            "amounts": [1400, 1500],
            "cities": {"Nagpur": 2},
            "devices": {"dev-nagpur": 2},
            "time_slots": {"afternoon": 1}
        },
        "txn_time": now.replace(hour=13),
        "risk_history": [0.15, 0.2],
        "last_city": "Nagpur",
        "recent_txns": [(1450, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-nagpur"},
        "recent_time_slots": {"afternoon": 1},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- SUSPICIOUS: Low city tier + minor device entropy ---
    {
        "txn_amount": 2500,
        "city": "Gaya",
        "device_id": "dev-gaya-2",
        "user_id": "user_026",
        "profile": {
            "amounts": [2400, 2600],
            "cities": {"Patna": 2},
            "devices": {"dev-gaya": 1},
            "time_slots": {"afternoon": 1}
        },
        "txn_time": now.replace(hour=14),
        "risk_history": [0.4, 0.5],
        "last_city": "Patna",
        "recent_txns": [(2500, now - timedelta(minutes=12*i)) for i in range(5)],
        "recent_devices": {"dev-gaya"},
        "recent_time_slots": {"afternoon": 1},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 2,
        "label": "Suspicious"
    },

    # --- SAFE: Consistent 5 txn streak ---
    {
        "txn_amount": 75,
        "city": "Varanasi",
        "device_id": "dev-varanasi",
        "user_id": "user_027",
        "profile": {
            "amounts": [70, 80],
            "cities": {"Varanasi": 4},
            "devices": {"dev-varanasi": 3},
            "time_slots": {"morning": 2}
        },
        "txn_time": now.replace(hour=10),
        "risk_history": [0.1, 0.2],
        "last_city": "Varanasi",
        "recent_txns": [(75, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"dev-varanasi"},
        "recent_time_slots": {"morning": 2},
        "recent_amount_buckets": {"low": 5},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- SUSPICIOUS: Semi-unknown pattern emerging ---
    {
        "txn_amount": 310,
        "city": "Amritsar",
        "device_id": "dev-amritsar-new",
        "user_id": "user_028",
        "profile": {
            "amounts": [250, 300],
            "cities": {"Amritsar": 1},
            "devices": {"dev-amritsar": 1},
            "time_slots": {"evening": 1}
        },
        "txn_time": now.replace(hour=20),
        "risk_history": [0.35],
        "last_city": "Amritsar",
        "recent_txns": [(280, now - timedelta(minutes=15*i)) for i in range(4)],
        "recent_devices": {"dev-amritsar"},
        "recent_time_slots": {"evening": 1},
        "recent_amount_buckets": {"low": 4},
        "current_velocity": 2,
        "label": "Suspicious"
    },

    # --- SAFE: Idle user reactivating ---
    {
        "txn_amount": 150,
        "city": "Coimbatore",
        "device_id": "dev-cbe",
        "user_id": "user_029",
        "profile": {
            "amounts": [140, 160],
            "cities": {"Coimbatore": 2},
            "devices": {"dev-cbe": 2},
            "time_slots": {"morning": 1}
        },
        "txn_time": now.replace(hour=10),
        "risk_history": [0.2],
        "last_city": "Coimbatore",
        "recent_txns": [(150, now - timedelta(minutes=30*i)) for i in range(3)],
        "recent_devices": {"dev-cbe"},
        "recent_time_slots": {"morning": 1},
        "recent_amount_buckets": {"low": 3},
        "current_velocity": 1,
        "label": "Safe"
    },

    # --- SUSPICIOUS: New device + night transaction ---
    {
        "txn_amount": 870,
        "city": "Agartala",
        "device_id": "fresh-ag",
        "user_id": "user_030",
        "profile": {
            "amounts": [900, 850],
            "cities": {"Agartala": 3},
            "devices": {"old-ag": 2},
            "time_slots": {"afternoon": 2}
        },
        "txn_time": now.replace(hour=2),
        "risk_history": [0.4, 0.5],
        "last_city": "Agartala",
        "recent_txns": [(860, now - timedelta(minutes=10*i)) for i in range(5)],
        "recent_devices": {"old-ag"},
        "recent_time_slots": {"afternoon": 2},
        "recent_amount_buckets": {"medium": 5},
        "current_velocity": 2,
        "label": "Suspicious"
    }
]

# 🎯 Run test
correct = 0
total = len(test_cases)

print("🧪 Running FraudEngine Accuracy Test...\n")

for i, case in enumerate(test_cases):
    result = engine.detect(
        txn_amount=case["txn_amount"],
        city=case["city"],
        device_id=case["device_id"],
        user_id=case["user_id"],
        profile=case["profile"],
        txn_time=case["txn_time"],
        risk_history_of_user=case["risk_history"],
        last_city=case["last_city"],
        recent_txns=case["recent_txns"],
        recent_devices=case["recent_devices"],
        recent_time_slots=case["recent_time_slots"],
        recent_amount_buckets=case["recent_amount_buckets"],
        current_velocity=case["current_velocity"]
    )

    pred = result["flag"][0]
    expected = case["label"]

    match = "✅" if pred == expected else "⚠️" if pred == "Suspicious" or (pred == "Safe" and expected == "Suspicious") or (pred == "Alert" and expected == "Suspicious") else "❌"
    if pred == expected:
        correct += 1
    elif pred == "Suspicious" or (pred == "Safe" and expected == "Suspicious") or (pred == "Alert" and expected == "Suspicious"):
        correct += 0.5
    else:
        correct += 0

    print(f"[{match}] Test #{i+1}: Predicted = {pred}, Expected = {expected}")

accuracy = (correct / total) * 100
print(f"\n📊 Final Accuracy: {accuracy:.2f}% ({correct}/{total} correct)")

print()
input("Press `Enter` to continue... ")


