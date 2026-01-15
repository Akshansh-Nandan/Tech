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

class FastResFCN:
    def __init__(self, input_size, conv_layers, num_out, layer_activations, text_based=False, classifier=True):
        self.input_size = input_size
        self.conv_layers = conv_layers
        self.num_out = num_out
        self.layer_activations = layer_activations
        self.text_based = text_based
        self.classifier = classifier
        self.model = self._build_model()

    def _build_model(self):
        inputs = tf.keras.Input(shape=(self.input_size,), dtype=tf.float32)
        x = inputs
        residual = None

        for idx, (neurons, act) in enumerate(zip(self.conv_layers, self.layer_activations[:-1])):
            x_new = tf.keras.layers.Dense(neurons, activation=get_activation(act))(x)
            if residual is not None and residual.shape[-1] == x_new.shape[-1]:
                x_new = x_new + residual
            residual = x_new
            x = x_new

        outputs = tf.keras.layers.Dense(self.num_out, activation=get_activation(self.layer_activations[-1]))(x)
        model = tf.keras.Model(inputs=inputs, outputs=outputs)
        return model

    # -------------------------
    # Forward / predict
    # -------------------------
    def calculate(self, input_data):
        x = tokenize(input_data) if self.text_based else np.array(input_data, dtype=np.float32).flatten()
        
        if isinstance(x, np.ndarray):
            x = x.tolist()
        
        x = x[:self.input_size] + [spacing if self.text_based else 0]*(self.input_size-len(x))
        x = np.array([x], dtype=np.float32)
        y = self.model(x, training=False)[0].numpy()
        return untokenize([int(np.argmax(y))]) if self.text_based else y

    # -------------------------
    # Training
    # -------------------------
    def train(self, csv_file, epochs=1, learning_rate=0.01):
        data = pd.read_csv(csv_file)
        cols = list(data.columns)

        X, y = [], []
        for _, row in data.iterrows():
            xi = [tokenize(row[c]) if self.text_based else row[c] for c in cols[:-1]]
            xi = xi[:self.input_size] + [spacing if self.text_based else 0]*(self.input_size - len(xi))
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
                loss='mse'
            )

        self.model.fit(X, y, epochs=epochs, verbose=1)

    # -------------------------
    # Test / evaluate
    # -------------------------
    def test(self, csv_file, view_working=False):
        data = pd.read_csv(csv_file)
        cols = list(data.columns)

        correct = 0
        total = 0
        for _, row in data.iterrows():
            xi = [tokenize(row[c]) if self.text_based else row[c] for c in cols[:-1]]
            xi = xi[:self.input_size] + [spacing if self.text_based else 0]*(self.input_size - len(xi))
            xi = np.array([xi], dtype=np.float32)

            y = self.model(xi, training=False)[0].numpy()
            pred = int(np.argmax(y))
            true = int(row[cols[-1]])

            if view_working:
                print(f"Pred: {pred}, True: {true}")

            if pred == true:
                correct += 1
            total += 1

        acc = (correct/total)*100
        print(f"\nAccuracy: {acc:.2f}% ({correct}/{total})")
        return acc

    # -------------------------
    # Finetune (RL-style perturb)
    # -------------------------
    def finetune(self, target_fn, inputs, epochs=1, learning_rate=0.01):
        best_weights = self.model.get_weights()

        for epoch in range(epochs):
            weights = self.model.get_weights()
            perturbed = [w + np.random.randn(*w.shape)*learning_rate for w in weights]
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
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "wb") as f:
            import pickle
            pickle.dump(self.tensor(), f)

        self.model.save(model_path)

    def load(self, path):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "rb") as f:
            import pickle
            tensor = pickle.load(f)

        self.set_network(tensor[0], tensor[1], tensor[2], tensor[5], tensor[6])
        self.model = tf.keras.models.load_model(model_path)

    # -------------------------
    # Tensor (compat)
    # -------------------------
    def tensor(self):
        return [
            self.input_size,
            self.conv_layers,
            self.num_out,
            None, None,  # TF manages weights
            self.layer_activations,
            self.text_based,
            self.classifier
        ]

    # -------------------------
    # Set network (for load)
    # -------------------------
    def set_network(self, input_size, conv_layers, num_out, layer_activations, text_based=False, classifier=False):
        self.input_size = input_size
        self.conv_layers = conv_layers
        self.num_out = num_out
        self.layer_activations = layer_activations
        self.text_based = text_based
        self.classifier = classifier
        self.model = self._build_model()



