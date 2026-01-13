"""
Advanced module for making powerful Prediction AI models. Based on Scikit-Learn.
"""

import pickle
from sklearn.linear_model import LinearRegression, LogisticRegression
from sklearn.tree import DecisionTreeRegressor, DecisionTreeClassifier

class PredictionModel():
    def __init__(self, model_type: int):
        self.model_type = model_type
        if model_type == 0:
            self.model = LinearRegression()
        elif model_type == 1:
            self.model = DecisionTreeRegressor()
        elif model_type == 2:
            self.model = LogisticRegression(max_iter=1000)
        elif model_type == 3:
            self.model = DecisionTreeClassifier()
        else:
            raise ValueError("Invalid model_type! Must be 0, 1, 2, or 3.")
        print(f"Initialized {self.model.__class__.__name__}!")

    def train(self, X, y):
        self.model.fit(X, y)
        print(f"{self.model.__class__.__name__} trained successfully!")

    def predict(self, X):
        return self.model.predict(X)

    def save(self, filepath):
        with open(filepath, 'wb') as f:
            pickle.dump(self, f)
        print(f"Saved model to {filepath}")

    @staticmethod
    def load(filepath):
        with open(filepath, 'rb') as f:
            obj = pickle.load(f)
        print(f"Loaded model from {filepath}")
        return obj


