from aidk_framework.token_manager import tokenize, untokenize, flatten
from aidk_framework.probmax import probmax
import numpy as np
import pandas as pd
import random

spacing = tokenize(" ")[0]

class ResFCN:
    def __init__(self, input_size:int, conv_layers:list[int], num_out:int,
                 layer_activations:list[int], text_based:bool=False):
        self.input_size = input_size
        self.conv_layers = conv_layers
        self.num_out = num_out
        self.layer_activations = layer_activations
        self.text_based = text_based

        if len(conv_layers)+1 != len(layer_activations):
            raise RuntimeError("Length of activations must match conv layers + output.")

        # Initialize weights & biases
        self.weights = []
        self.biases = []

        prev = input_size
        for neurons in conv_layers:
            self.weights.append(np.random.randn(neurons, prev))
            self.biases.append(np.random.randn(neurons))
            prev = neurons

        self.weights.append(np.random.randn(num_out, prev))
        self.biases.append(np.random.randn(num_out))

    # ================= ACTIVATION =================
    def activate(self, x, act_type):
        if act_type == 0: return np.maximum(0, x)      # ReLU
        if act_type == 1: return 1/(1+np.exp(-x))     # Sigmoid
        if act_type == 2: return np.tanh(x)           # Tanh
        if act_type == 3: return x                     # Identity
        raise RuntimeError("Invalid activation type")

    def activate_derivative(self, x, act_type):
        if act_type == 0: return np.where(x>0,1,0)
        if act_type == 1: s = 1/(1+np.exp(-x)); return s*(1-s)
        if act_type == 2: return 1-np.tanh(x)**2
        if act_type == 3: return np.ones_like(x)
        raise RuntimeError("Invalid activation type")

    # ================= FORWARD =================
    def calculate(self, input_data, view_working=False):
        x = tokenize(input_data) if self.text_based else np.array(input_data,dtype=np.float64).flatten()
        x = list(x) + [spacing if self.text_based else 0]*(self.input_size-len(x))
        a = np.array(x[:self.input_size], dtype=np.float64)

        residual = None
        z_states = []

        # ResNet-style conv forward
        for idx, (w,b,act) in enumerate(zip(self.weights[:-1], self.biases[:-1], self.layer_activations[:-1])):
            z = np.dot(w,a)+b
            if residual is not None and residual.shape == z.shape:
                z += residual       # skip connection

            h = self.activate(z,act)
            residual = h.copy()
            a = h
            z_states.append(z)

            if view_working:
                print(f"\nConv Layer {idx+1}")
                print("Z:\n", z)
                print("Activation:\n", h)

        # Output layer
        z_out = np.dot(self.weights[-1],a)+self.biases[-1]
        output = self.activate(z_out,self.layer_activations[-1])

        if self.text_based:
            output = untokenize([int(i) for i in output])

        return output

    # ================= TENSOR IO =================
    def tensor(self):
        return [
            self.input_size,
            self.conv_layers,
            self.num_out,
            [w.copy() for w in self.weights],
            [b.copy() for b in self.biases],
            self.layer_activations,
            self.text_based
        ]

    def set_tensor(self, tensor):
        self.input_size = tensor[0]
        self.conv_layers = tensor[1]
        self.num_out = tensor[2]
        self.weights = tensor[3]
        self.biases = tensor[4]
        self.layer_activations = tensor[5]
        self.text_based = tensor[6]

    # ================= TRAINING =================
    def train(self, csv_file, epochs=1, learning_rate=0.01, view_working=False):
        data = pd.read_csv(csv_file)
        columns = list(data.columns)

        X,Y = [],[]
        for _,row in data.iterrows():
            xi = [tokenize(row[col]) if self.text_based else row[col] for col in columns[:-1]]
            # yi = [tokenize(row[columns[-1]]) if self.text_based else row[columns[-1]]]
            
            # For numeric classification like MNIST
            label = int(row[columns[-1]])            # read the label
            num_classes = self.num_out               # should be 10 for MNIST
            yi = np.zeros(num_classes, dtype=np.float64)
            yi[label] = 1                            # one-hot encode
            
            X.append(xi)
            Y.append(yi)

        X = np.array([xi[:self.input_size]+[0]*(self.input_size-len(xi)) for xi in X],dtype=np.float64)
        Y = np.array(Y,dtype=np.float64)

        for epoch in range(epochs):
            total_error = 0

            for xi,yi in zip(X,Y):
                # ========= FORWARD =========
                a = xi
                residual = None
                z_states = []
                activations = []

                for w,b,act in zip(self.weights[:-1],self.biases[:-1],self.layer_activations[:-1]):
                    z = np.dot(w,a)+b
                    if residual is not None and residual.shape==z.shape:
                        z+=residual
                    h = self.activate(z,act)
                    residual = h.copy()
                    z_states.append(z)
                    activations.append(h.copy())
                    a = h
                
                # Output layer
                z_out = np.dot(self.weights[-1], a) + self.biases[-1]
                y_pred = self.activate(z_out, self.layer_activations[-1])

                # Add output layer pre-activation to z_states for backprop
                z_states.append(z_out)

                y_pred = self.activate(np.dot(self.weights[-1],a)+self.biases[-1],self.layer_activations[-1])
                error = y_pred - yi
                total_error += np.mean(error**2)

                # ========= BACKPROP =========
                delta = error
                for l in reversed(range(len(self.weights))):
                    # dz = delta * self.activate_derivative(z_states[l-1] if l>0 else xi,self.layer_activations[l])
                    dz = delta * self.activate_derivative(z_states[l], self.layer_activations[l])
                    dw = np.outer(dz, xi if l==0 else activations[l-1])
                    db = dz
                    self.weights[l]-=learning_rate*dw
                    self.biases[l]-=learning_rate*db
                    # delta = np.dot(self.weights[l].T,dz)
                    delta = np.dot(self.weights[l].T, dz)

            if view_working:
                print(f"Epoch {epoch+1}/{epochs}, MSE: {total_error/len(X):.6f}")
    
    # ================= TESTING =================
    def test(self, csv_file, view_working=False):
        data = pd.read_csv(csv_file)
        columns = list(data.columns)

        correct = 0
        total = 0

        for _, row in data.iterrows():
            # ----- input -----
            xi = [tokenize(row[col]) if self.text_based else row[col]
                  for col in columns[:-1]]
            xi = xi[:self.input_size] + [0] * (self.input_size - len(xi))
            xi = np.array(xi, dtype=np.float64)

            # ----- true label -----
            true_label = int(row[columns[-1]])

            # ----- prediction -----
            y_pred = self.calculate(xi)
            pred_label = int(np.argmax(y_pred))

            if view_working:
                print(f"Pred: {pred_label}, True: {true_label}")

            if pred_label == true_label:
                correct += 1
            total += 1

        accuracy = (correct / total) * 100
        print(f"\nAccuracy: {accuracy:.2f}% ({correct}/{total})")
        return accuracy

    # ================= FINETUNE =================
    def finetune(self,target_fn,inputs,epochs=1,learning_rate=0.01):
        best = self.tensor()
        for epoch in range(epochs):
            for i in range(len(self.weights)):
                self.weights[i]+=np.random.randn(*self.weights[i].shape)*learning_rate

            success = target_fn(inputs,self.calculate(inputs))
            if success:
                print("Better configuration found!")
                best = self.tensor()
            else:
                self.set_tensor(best)

            print(f"Epoch {epoch+1}/{epochs}, Success: {success}")



