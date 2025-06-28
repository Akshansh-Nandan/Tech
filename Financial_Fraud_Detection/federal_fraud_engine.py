# federal_fraud_engine.py (GeoNamesCache + CLI Mode)

import numpy as np
from datetime import datetime, timedelta
from geopy.distance import geodesic
from sklearn.linear_model import LinearRegression
from difflib import get_close_matches
from scipy.stats import entropy
import geonamescache
import json

class FraudEngine:
    def __init__(self):
        gc = geonamescache.GeonamesCache()
        self.cities = gc.get_cities()
        self.city_index = {
            city_info['name']: city_id for city_id, city_info in self.cities.items()
        }
        self.city_names = list(self.city_index.keys())

        self.flags = {
            "Safe" : 0,
            "Suspicious" : 1,
            "Alert" : 2
        }

    def autocorrect_city(self, input_city):
        match = get_close_matches(input_city, self.city_names, n=1, cutoff=0.7)
        return match[0] if match else input_city

    def get_city_info(self, city):
        city = self.autocorrect_city(city)
        city_id = self.city_index.get(city)
        if city_id:
            city_obj = self.cities[city_id]
            lat, lon = city_obj.get("latitude", 0.0), city_obj.get("longitude", 0.0)
            population = city_obj.get("population", 0)
            # Estimate tier based on population
            if population >= 5000000:
                tier = 0
            elif population >= 1000000:
                tier = 1
            elif population >= 500000:
                tier = 2
            elif population >= 100000:
                tier = 3
            elif population >= 20000:
                tier = 4
            else:
                tier = 5
            return {"tier": tier, "lat": lat, "lon": lon}
        return {"tier": 5, "lat": 0.0, "lon": 0.0}

    def bucketize_amount(self, amt):
        if amt <= 10: return 'micro'
        elif amt <= 500: return 'low'
        elif amt <= 5000: return 'medium'
        elif amt <= 50000: return 'high'
        else: return 'critical'

    def time_slot(self, hour):
        if 0 <= hour < 6: return 'night'
        elif 6 <= hour < 12: return 'morning'
        elif 12 <= hour < 18: return 'afternoon'
        else: return 'evening'
    
    def calculate_adaptive_threshold(self, user_id, risk_history, default=0.5):
        scores = risk_history.setdefault(user_id, [])
        if len(scores) < 10:
            return default
        return min(0.95, max(0.05, np.percentile(scores[-50:], 85)))
    
    def ai_risk_score(self, profile, txn_amount, city, device_id, slot):
        score = 0.0
        amt_avg = np.mean(profile["amounts"]) if profile["amounts"] else txn_amount

        # Amount deviation
        deviation = abs(txn_amount - amt_avg) / (amt_avg + 1e-6)
        if deviation > 0.5:
            score += 0.2

        # New/unseen city
        if profile["cities"].get(city, 0) < 2:
            score += 0.2

        # New device
        if profile["devices"].get(device_id, 0) == 0:
            score += 0.2

        # Unusual time slot
        if profile["time_slots"].get(slot, 0) < 2:
            score += 0.2

        # Entropy factor
        values = np.array(list(profile["cities"].values()) + list(profile["devices"].values()))
        if len(values) > 1 and entropy(values) > 2:
            score += 0.25

        return round(min(1.0, score), 4)

    def detect(self, txn_amount, city, device_id, user_id, profile, txn_time,
               risk_history_of_user, last_city, recent_txns, recent_devices,
               recent_time_slots, recent_amount_buckets, current_velocity):

        alerts, risk_score = [], 0.0
        risk_history = {
            user_id : risk_history_of_user
        }

        # --- Geo Intelligence ---
        city_info = self.get_city_info(city)
        last_city_info = self.get_city_info(last_city)

        if city_info['tier'] >= 3:
            alerts.append(f"Tier-{city_info['tier']} location")
            risk_score += 0.1

        dist = geodesic((city_info['lat'], city_info['lon']), (last_city_info['lat'], last_city_info['lon'])).km
        minutes = (txn_time - recent_txns[-1][1]).total_seconds() / 60
        speed = dist / (minutes / 60 + 1e-5)
        if dist > 300 and speed > 500:
            alerts.append(f"Impossible travel: {dist:.1f} km @ {speed:.1f} km/h")
            risk_score += 0.2

        # --- Device Entropy ---
        if device_id not in recent_devices:
            diversity = len(recent_devices)
            alerts.append(f"New device used (seen {diversity} before)")
            risk_score += min(0.1 + 0.02 * diversity, 0.2)

        # --- Time Slot Profiling ---
        slot = self.time_slot(txn_time.hour)
        if recent_time_slots.get(slot, 0) < 2:
            alerts.append(f"Unusual transaction time ({slot})")
            risk_score += 0.1

        # --- Amount Bucket Anomaly ---
        bucket = self.bucketize_amount(txn_amount)
        dominant_bucket = max(recent_amount_buckets, key=recent_amount_buckets.get)
        if bucket != dominant_bucket:
            alerts.append(f"Unusual amount bucket: {bucket} vs usual {dominant_bucket}")
            risk_score += 0.1

        # --- Velocity Check ---
        if current_velocity >= 5:
            alerts.append("High transaction velocity")
            risk_score += 0.2

        # --- Microtransaction Spam Check ---
        micro_count = recent_amount_buckets.get('micro', 0)
        if bucket == 'micro':
            risk_score += 0.05 * micro_count  # Gradual risk buildup
            if micro_count >= 15:
                alerts.append("Microtransaction abuse pattern detected")
                risk_score += 0.25
            if current_velocity >= 5:
                alerts.append("High-frequency microtransactions")
                risk_score += 0.1

        # --- Regression Deviation ---
        if len(recent_txns) >= 5:
            X = np.array([(t[1] - recent_txns[0][1]).total_seconds() for t in recent_txns]).reshape(-1, 1)
            Y = np.array([t[0] for t in recent_txns])
            model = LinearRegression().fit(X, Y)
            predicted = model.predict([[ (txn_time - recent_txns[0][1]).total_seconds() ]])[0]
            deviation = abs(predicted - txn_amount) / (txn_amount + 1e-6)
            if deviation > 0.75:
                alerts.append(f"Spending behavior deviation: {deviation:.2f}")
                risk_score += 0.2

        # --- Entropy on buckets ---
        dist = np.array(list(recent_amount_buckets.values()))
        if len(dist) > 1 and entropy(dist) > 1.5:
            alerts.append("High spending entropy")
            risk_score += 0.1

        score = round(min(1.0, risk_score), 4)
        score = round((score + self.ai_risk_score(profile, txn_amount, city, device_id, slot)) / 2, 4)
        flag = "Safe" if score <= 0.25 else "Suspicious" if 0.25 <= score <= 0.65 else "Alert"
        return {
            'fraud': score >= self.calculate_adaptive_threshold(user_id, risk_history, 0.65),
            'score': score,
            'flag': [flag, self.flags[flag]],
            'alerts': alerts,
            'user_id': user_id,
            'city': city,
            'device_id': device_id,
            'timestamp': txn_time.strftime('%Y-%m-%d %H:%M:%S')
        }

if __name__ == "__main__":
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


