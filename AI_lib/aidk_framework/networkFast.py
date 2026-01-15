import tensorflow as tf
import numpy as np
import pandas as pd
from aidk_framework.token_manager import tokenize, untokenize

spacing = tokenize(" ")[0]

# Disable all GPUs for this session
tf.config.set_visible_devices([], 'GPU')

def get_activation(act):
    return {
        0: "relu",
        1: "sigmoid",
        2: "tanh",
        3: "linear"
    }[act]

class FastNeuralNetworkTF:
    def __init__(self, num_in, num_h, num_out, layer_activations, text_based=False, classifier=False):
        self.num_in = num_in
        self.num_h = num_h
        self.num_out = num_out
        self.layer_activations = layer_activations
        self.text_based = text_based
        self.classifier = classifier

        self.model = self._build_model()

    def _build_model(self):
        layers = []
        for h, act in zip(self.num_h, self.layer_activations[1:-1]):
            layers.append(tf.keras.layers.Dense(h, activation=get_activation(act)))

        layers.append(tf.keras.layers.Dense(
            self.num_out,
            activation=get_activation(self.layer_activations[-1])
        ))

        model = tf.keras.Sequential(layers)
        model.build((None, self.num_in))
        return model

    # -------------------------
    # Forward / Predict
    # -------------------------
    def calculate(self, input_prompt):
        if self.text_based:
            x = tokenize(input_prompt)
            x = x[:self.num_in] + [spacing] * (self.num_in - len(x))
        else:
            x = np.array(input_prompt, dtype=np.float32).flatten()
            x = np.pad(x, (0, self.num_in - len(x)))

        x = np.array([x], dtype=np.float32)
        y = self.model(x, training=False)[0].numpy()

        return untokenize([int(np.argmax(y))]) if self.text_based else y

    # -------------------------
    # Train
    # -------------------------
    def train(self, csv_file, epochs=1, learning_rate=0.01):
        data = pd.read_csv(csv_file)
        cols = list(data.columns)

        X, y = [], []
        for _, row in data.iterrows():
            xi = [tokenize(row[c]) if self.text_based else row[c] for c in cols[:-1]]
            xi = xi[:self.num_in] + [spacing if self.text_based else 0] * (self.num_in - len(xi))
            X.append(xi)

            yi = np.zeros(self.num_out, dtype=np.float32)
            yi[int(row[cols[-1]])] = 1
            y.append(yi)

        X = np.array(X, dtype=np.float32)
        y = np.array(y, dtype=np.float32)
        
        if self.classifier:
            self.model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate),
                loss='categorical_crossentropy',
                metrics=['accuracy']
            )
        else:
            self.model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate),
                loss="mse"
            )

        self.model.fit(X, y, epochs=epochs, verbose=1)

    # -------------------------
    # Test (same behavior as NN)
    # -------------------------
    def test(self, csv_file, view_working=False):
        data = pd.read_csv(csv_file)
        cols = list(data.columns)

        correct = 0
        total = 0

        for _, row in data.iterrows():
            xi = [tokenize(row[c]) if self.text_based else row[c] for c in cols[:-1]]
            xi = xi[:self.num_in] + [spacing if self.text_based else 0] * (self.num_in - len(xi))
            xi = np.array([xi], dtype=np.float32)

            y = self.model(xi, training=False)[0].numpy()
            pred = int(np.argmax(y))
            true = int(row[cols[-1]])

            if view_working:
                print(f"Predicted: {pred}, True: {true}")

            correct += (pred == true)
            total += 1

        acc = (correct / total) * 100
        print(f"\nAccuracy: {acc:.2f}% ({correct}/{total})")
        return acc

    # -------------------------
    # Finetune (RL-style, NumPy perturb)
    # -------------------------
    def finetune(self, target_fn, inputs, epochs=1, learning_rate=0.01):
        best_weights = self.model.get_weights()

        for epoch in range(epochs):
            weights = self.model.get_weights()
            perturbed = [
                w + np.random.randn(*w.shape) * learning_rate
                for w in weights
            ]
            self.model.set_weights(perturbed)

            success = target_fn(inputs, self.calculate(inputs))
            if success:
                print("Better configuration found!")
                best_weights = self.model.get_weights()
            else:
                self.model.set_weights(best_weights)

            print(f"Epoch {epoch+1}/{epochs}, Success: {success}")

    # -------------------------
    # Save / Load
    # -------------------------
    def save(self, path):
        self.model.save(path)

    def load(self, path):
        self.model = tf.keras.models.load_model(path)



