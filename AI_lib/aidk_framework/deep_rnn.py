from aidk_framework.token_manager import tokenize, untokenize, flatten
from aidk_framework.probmax import probmax
import numpy as np
import pandas as pd
import math
import random

spacing = tokenize(" ")[0]

class DeepRNN:
    def __init__(self, num_in:int, num_h:list[int], num_out:int,
                 layer_activations:list[int], text_based:bool = False):

        self.num_in = num_in
        self.num_h = num_h
        self.num_out = num_out
        self.layer_activations = layer_activations
        self.text_based = text_based

        if len(num_h) + 2 != len(layer_activations):
            raise RuntimeError("Length of layer activations must match number of layers.")

        self.weights = []
        self.biases = []

        # Recurrent weights + hidden states
        self.recurrent_weights = []
        self.hidden_states = []

        prev = num_in
        for h in num_h:
            self.weights.append(np.random.randn(h, prev))
            self.biases.append(np.random.randn(h))

            self.recurrent_weights.append(np.random.randn(h, h))
            self.hidden_states.append(np.zeros(h))

            prev = h

        self.weights.append(np.random.randn(num_out, prev))
        self.biases.append(np.random.randn(num_out))

    # ================= ACTIVATIONS =================

    def activate(self, x, act_type):
        if act_type == 0:
            return np.maximum(0, x)
        elif act_type == 1:
            return 1 / (1 + np.exp(-x))
        elif act_type == 2:
            return np.tanh(x)
        elif act_type == 3:
            return x
        else:
            raise RuntimeError("Invalid activation type")

    def activate_derivative(self, x, act_type):
        if act_type == 0:
            return np.where(x > 0, 1, 0)
        elif act_type == 1:
            s = 1 / (1 + np.exp(-x))
            return s * (1 - s)
        elif act_type == 2:
            return 1 - np.tanh(x)**2
        elif act_type == 3:
            return np.ones_like(x)
        else:
            raise RuntimeError("Invalid activation type")

    # ================= STATE CONTROL =================

    def reset_state(self):
        for h in self.hidden_states:
            h.fill(0)

    # ================= TENSOR IO =================

    def tensor(self):
        return [
            self.num_in,
            self.num_h,
            self.num_out,
            [w.copy() for w in self.weights],
            [b.copy() for b in self.biases],
            [rw.copy() for rw in self.recurrent_weights],
            self.layer_activations,
            self.text_based
        ]

    def set_tensor(self, tensor):
        self.num_in = tensor[0]
        self.num_h = tensor[1]
        self.num_out = tensor[2]
        self.weights = tensor[3]
        self.biases = tensor[4]
        self.recurrent_weights = tensor[5]
        self.layer_activations = tensor[6]
        self.text_based = tensor[7]

        self.hidden_states = [np.zeros(h) for h in self.num_h]

    # ================= FORWARD =================

    def calculate(self, input_prompt, view_working=False):
        x = tokenize(input_prompt) if self.text_based else np.array(input_prompt, dtype=np.float64).flatten()
        x = list(x) + [spacing if self.text_based else 0] * max(0, self.num_in - len(x))
        a = np.array(x[:self.num_in], dtype=np.float64)

        layer_z = []

        # DEEP RNN FORWARD
        for i in range(len(self.num_h)):
            z = (
                np.dot(self.weights[i], a)
                + np.dot(self.recurrent_weights[i], self.hidden_states[i])
                + self.biases[i]
            )

            h = self.activate(z, self.layer_activations[i+1])
            self.hidden_states[i] = h.copy()
            a = h
            layer_z.append(z)

            if view_working:
                print(f"\nRecurrent Layer {i+1}")
                print("Z:\n", z)
                print("Hidden State:\n", h)

        # Output layer
        z_out = np.dot(self.weights[-1], a) + self.biases[-1]
        output = self.activate(z_out, self.layer_activations[-1])

        if self.text_based:
            output = untokenize([int(i) for i in output])

        return output

    # ================= TRAINING =================
    def train(self, csv_file, epochs=1, learning_rate=0.01, view_working=False):
        data = pd.read_csv(csv_file)
        columns = list(data.columns)

        X, Y = [], []
        for _, row in data.iterrows():
            x_seq = []
            for col in columns[:-1]:
                val = tokenize(row[col]) if self.text_based else row[col]
                x_seq.append(val)

            # y_val = tokenize(row[columns[-1]]) if self.text_based else row[columns[-1]]
            
            label = int(row[columns[-1]])
            y_val = np.zeros(self.num_out, dtype=np.float64)
            y_val[label] = 1

            X.append(x_seq)
            Y.append(y_val)

        X = np.array(X, dtype=np.float64)
        Y = np.array(Y, dtype=np.float64)

        T = X.shape[1]  # sequence length
        L = len(self.num_h)

        for epoch in range(epochs):
            total_error = 0

            for seq, target in zip(X, Y):
                # ========= FORWARD UNROLL =========
                self.reset_state()

                h_states = [[np.zeros(h) for h in self.num_h]]  # h[t][layer]
                z_states = []

                for t in range(T):
                    a = np.array([seq[t]]) if np.isscalar(seq[t]) else np.array(seq[t])
                    a = a.flatten()

                    z_t = []
                    h_t = []

                    for l in range(L):
                        z = (
                            np.dot(self.weights[l], a)
                            + np.dot(self.recurrent_weights[l], h_states[-1][l])
                            + self.biases[l]
                        )
                        a = self.activate(z, self.layer_activations[l+1])
                        z_t.append(z)
                        h_t.append(a)

                    h_states.append(h_t)
                    z_states.append(z_t)

                # Output from LAST timestep
                y_pred = self.activate(
                    np.dot(self.weights[-1], h_states[-1][-1]) + self.biases[-1],
                    self.layer_activations[-1]
                )

                error = y_pred - target
                total_error += np.mean(error**2)

                # ========= BACKWARD UNROLL =========
                dW = [np.zeros_like(w) for w in self.weights]
                dB = [np.zeros_like(b) for b in self.biases]
                dR = [np.zeros_like(rw) for rw in self.recurrent_weights]

                delta_out = error

                # Output layer gradients
                dW[-1] += np.outer(delta_out, h_states[-1][-1])
                dB[-1] += delta_out

                delta_next = np.dot(self.weights[-1].T, delta_out)

                # Backprop through time
                for t in reversed(range(T)):
                    delta_time = delta_next.copy()

                    for l in reversed(range(L)):
                        dz = delta_time * self.activate_derivative(
                            z_states[t][l],
                            self.layer_activations[l+1]
                        )

                        prev_a = h_states[t][l-1] if l > 0 else np.array([seq[t]])
                        prev_a = prev_a.flatten()

                        dW[l] += np.outer(dz, prev_a)
                        dB[l] += dz
                        dR[l] += np.outer(dz, h_states[t][l])

                        delta_time = np.dot(self.weights[l].T, dz)

                    delta_next = delta_time

                # ========= UPDATE =========
                for i in range(len(self.weights)):
                    self.weights[i] -= learning_rate * dW[i]
                    self.biases[i] -= learning_rate * dB[i]

                for i in range(len(self.recurrent_weights)):
                    self.recurrent_weights[i] -= learning_rate * dR[i]

            if view_working:
                print(f"Epoch {epoch+1}/{epochs}, MSE: {total_error/len(X):.6f}")

    # ================= FINETUNE =================

    def finetune(self, target_fn, inputs, epochs=1, learning_rate=0.01):
        best = self.tensor()

        for epoch in range(epochs):
            for i in range(len(self.weights)):
                self.weights[i] += np.random.randn(*self.weights[i].shape) * learning_rate

            success = target_fn(inputs, self.calculate(inputs))

            if success:
                print("Better configuration found!")
                best = self.tensor()
            else:
                self.set_tensor(best)

            print(f"Epoch {epoch+1}/{epochs}, Success: {success}")



