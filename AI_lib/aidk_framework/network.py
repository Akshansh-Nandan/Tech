from aidk_framework.token_manager import tokenize, untokenize, flatten
from aidk_framework.probmax import probmax
import numpy as np
import pandas as pd
import math
import random

spacing = tokenize(" ")[0]

class NeuralNetwork:
    def __init__(self, num_in:int, num_h:list[int], num_out:int, layer_activations:list[int], text_based:bool = False):
        self.num_in = num_in
        self.num_h = num_h
        self.num_out = num_out
        self.layer_activations = layer_activations
        self.text_based = text_based

        if not len(num_h) + 2 == len(layer_activations):
            raise RuntimeError("Length of layer activations must match number of layers.")

        # Initialize weights & biases
        self.weights = []
        self.biases = []

        prev = num_in
        # Hidden layers
        for h in num_h:
            self.weights.append(np.random.randn(h, prev))
            self.biases.append(np.random.randn(h))
            prev = h
        # Output layer
        self.weights.append(np.random.randn(num_out, prev))
        self.biases.append(np.random.randn(num_out))

    def activate(self, x, act_type):
        if act_type == 0:  # ReLU
            return np.maximum(0, x)
        elif act_type == 1:  # Sigmoid
            return 1 / (1 + np.exp(-x))
        elif act_type == 2:  # Tanh
            return np.tanh(x)
        elif act_type == 3:  # Identity
            return x
        else:
            raise RuntimeError("Invalid activation type")

    def activate_derivative(self, x, act_type):
        if act_type == 0:  # ReLU
            return np.where(x > 0, 1, 0)
        elif act_type == 1:  # Sigmoid
            s = 1 / (1 + np.exp(-x))
            return s * (1 - s)
        elif act_type == 2:  # Tanh
            return 1 - np.tanh(x)**2
        elif act_type == 3:  # Identity
            return np.ones_like(x)
        else:
            raise RuntimeError("Invalid activation type")
    
    def tensor(self):
        return [
            self.num_in,
            self.num_h,
            self.num_out,
            [w.copy() for w in self.weights[:-1]],  # hidden layers weights
            [b.copy() for b in self.biases[:-1]],   # hidden layers biases
            self.weights[-1].copy(),               # output layer weights
            self.biases[-1].copy(),                # output layer biases
            self.layer_activations,
            self.text_based
        ]
    
    def set_tensor(self, tensor):
        self.num_in = tensor[0]
        self.num_h = tensor[1]
        self.num_out = tensor[2]
        self.layer_activations = tensor[7]
        self.text_based = tensor[8]

        # Rebuild weights/biases
        self.weights = tensor[3] + [tensor[5]]   # hidden + output
        self.biases = tensor[4] + [tensor[6]]    # hidden + output

    def calculate(self, input_prompt, view_working=False):
        x = tokenize(input_prompt) if self.text_based else np.array(input_prompt, dtype=np.float64).flatten()
        # Pad/truncate input
        x = list(x) + [spacing if self.text_based else 0] * max(0, self.num_in - len(x))
        x = np.array(x[:self.num_in], dtype=np.float64)

        layer_inputs = [x]
        layer_z = []

        # Forward pass
        for idx, (w, b, act) in enumerate(zip(self.weights, self.biases, self.layer_activations[1:])):
            z = np.dot(w, layer_inputs[-1]) + b
            layer_z.append(z)
            a = self.activate(z, act)
            layer_inputs.append(a)

            if view_working:
                print(f"\nLayer {idx+1}")
                print("Weights:\n", w)
                print("Biases:\n", b)
                print("Z:\n", z)
                print(f"Activation ({'ReLU' if act==0 else 'Sigmoid' if act==1 else 'Tanh' if act==2 else 'Identity'}):\n", a)

        output = layer_inputs[-1]
        if self.text_based:
            output = untokenize([int(i) for i in output])
        return output

    def train(self, csv_file, epochs=1, learning_rate=0.01, view_working=False):
        data = pd.read_csv(csv_file)
        X = []
        y = []
        columns = list(data.columns)
        for _, row in data.iterrows():
            xi = [tokenize(row[col]) if self.text_based else row[col] for col in columns[:-1]]
            # yi = [tokenize(row[columns[-1]]) if self.text_based else row[columns[-1]]]
            
            # Instead of the line above
            label = int(row[columns[-1]])        # get numeric label
            yi = np.zeros(self.num_out, dtype=np.float64)
            yi[label] = 1                        # one-hot encode

            X.append(xi)
            y.append(yi)
        # X = np.array([xi[:self.num_in] + [spacing if self.text_based else 0]*(self.num_in-len(xi)) for xi in X], dtype=np.float64)
        # y = np.array([yi[:self.num_out] + [spacing if self.text_based else 0]*(self.num_out-len(yi)) for yi in y], dtype=np.float64)
        
        X = np.array(
            [xi[:self.num_in] + [spacing if self.text_based else 0] * (self.num_in - len(xi)) for xi in X],
            dtype=np.float64
        )

        y = np.array(y, dtype=np.float64)

        for epoch in range(epochs):
            total_error = 0
            for xi, yi in zip(X, y):
                # Forward pass
                layer_inputs = [xi]
                layer_z = []
                for w, b, act in zip(self.weights, self.biases, self.layer_activations[1:]):
                    z = np.dot(w, layer_inputs[-1]) + b
                    layer_z.append(z)
                    a = self.activate(z, act)
                    layer_inputs.append(a)
                output = layer_inputs[-1]
                error = output - yi
                total_error += np.mean(error**2)

                # Backward pass
                delta = error
                for l in reversed(range(len(self.weights))):
                    dz = delta * self.activate_derivative(layer_z[l], self.layer_activations[l+1])
                    dw = np.outer(dz, layer_inputs[l])
                    db = dz
                    # Gradient descent
                    self.weights[l] -= learning_rate * dw
                    self.biases[l] -= learning_rate * db
                    delta = np.dot(self.weights[l].T, dz)

            if view_working:
                print(f"Epoch {epoch+1}/{epochs}, MSE: {total_error/len(X):.5f}")
    
    def test(self, csv_file: str, view_working: bool = False) -> float:
        """
        Test the network on a CSV file.
        Last column is assumed to be the numeric label.
        Returns accuracy in percent.
        """
        data = pd.read_csv(csv_file)
        columns = list(data.columns)
        
        correct = 0
        total = 0
        
        for _, row in data.iterrows():
            # Prepare input
            xi = [tokenize(row[c]) if self.text_based else row[c] for c in columns[:-1]]
            xi = xi[:self.num_in] + [spacing if self.text_based else 0] * (self.num_in - len(xi))
            xi = np.array(xi, dtype=np.float64)
            
            # True label
            true_label = int(row[columns[-1]])
            
            # Predict
            y_pred = self.calculate(xi)
            pred_label = int(np.argmax(y_pred))
            
            if view_working:
                print(f"Predicted: {pred_label}, True: {true_label}")
            
            if pred_label == true_label:
                correct += 1
            total += 1
        
        accuracy = (correct / total) * 100
        print(f"\nAccuracy: {accuracy:.2f}% ({correct}/{total})")
        return accuracy

    def finetune(self, target_fn, inputs, epochs=1, learning_rate=0.01):
        best_weights = [w.copy() for w in self.weights]
        best_biases = [b.copy() for b in self.biases]

        for epoch in range(epochs):
            # Simple RL-style fine tuning
            perturb = [np.random.randn(*w.shape)*learning_rate for w in self.weights]
            for l in range(len(self.weights)):
                self.weights[l] += perturb[l]

            success = target_fn(inputs, self.calculate(inputs))
            if success:
                print("Better configuration found!")
                best_weights = [w.copy() for w in self.weights]
                best_biases = [b.copy() for b in self.biases]
            else:
                # Revert
                self.weights = [w.copy() for w in best_weights]
                self.biases = [b.copy() for b in best_biases]

            print(f"Epoch {epoch+1}/{epochs}, Success: {success}")


