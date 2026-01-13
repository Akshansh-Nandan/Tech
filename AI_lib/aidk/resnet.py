import numpy as np
import pandas as pd
import pickle

# ======= ACTIVATIONS =======
def relu(x): return np.maximum(0, x)
def relu_deriv(x): return (x>0).astype(float)
def sigmoid(x): return 1/(1+np.exp(-x))
def sigmoid_deriv(x): s = sigmoid(x); return s*(1-s)
def identity(x): return x
def identity_deriv(x): return np.ones_like(x)

def clip(val, lim=5): return np.clip(val, -lim, lim)

activations = [relu, sigmoid, np.tanh, identity]
activations_deriv = [relu_deriv, sigmoid_deriv, lambda x: 1-np.tanh(x)**2, identity_deriv]

# ======= RESNET CNN CLASS =======
class ResNetCNN:
    def __init__(self, input_shape=(28,28), num_classes=10, conv_blocks=[(1,8,3),(8,16,3)], fc_layers=[64], text_based=False):
        self.input_shape = input_shape  # (H,W)
        self.num_classes = num_classes
        self.conv_blocks = []
        self.fc_layers = fc_layers
        self.text_based = text_based
        
        # Init conv layers: (in_channels, out_channels, kernel_size)
        for block in conv_blocks:
            in_c, out_c, k = block
            w = np.random.randn(out_c, in_c, k, k) * 0.1
            b = np.zeros(out_c)
            self.conv_blocks.append({'w':w,'b':b})

        # Flatten size after conv (simple assume no padding, stride=1)
        h, w = input_shape
        for block in conv_blocks:
            k = block[2]
            h = h - k + 1
            w = w - k + 1
        flatten_size = conv_blocks[-1][1]*h*w

        # FC layers
        self.fc_weights = []
        self.fc_biases = []
        prev = flatten_size
        for neurons in fc_layers:
            self.fc_weights.append(np.random.randn(neurons, prev) * 0.1)
            self.fc_biases.append(np.zeros(neurons))
            prev = neurons
        # Output layer
        self.fc_weights.append(np.random.randn(num_classes, prev) * 0.1)
        self.fc_biases.append(np.zeros(num_classes))

    # ======= FORWARD =======
    def conv_forward(self, x, w, b):
        # x: (C,H,W), w: (F,C,k,k)
        F,C,k,k = w.shape
        H,W = x.shape[1:]
        out_h = H - k + 1
        out_w = W - k + 1
        out = np.zeros((F,out_h,out_w))
        for f in range(F):
            for i in range(out_h):
                for j in range(out_w):
                    patch = x[:,i:i+k,j:j+k]
                    out[f,i,j] = np.sum(patch * w[f]) + b[f]
        return out

    def forward(self, x):
        # x: (C,H,W)
        self.conv_cache = []
        a = x
        residual = None
        for layer in self.conv_blocks:
            z = self.conv_forward(a, layer['w'], layer['b'])
            if residual is not None and residual.shape == z.shape:
                z += residual
            h = relu(z)
            residual = h.copy()
            a = h
            self.conv_cache.append((a,z))
        # Flatten
        self.flatten = a.flatten()
        # FC forward
        self.fc_cache = [self.flatten]
        h = self.flatten
        for w,b in zip(self.fc_weights[:-1], self.fc_biases[:-1]):
            z = w.dot(h)+b
            h = relu(z)
            self.fc_cache.append(h)
        # Output
        z = self.fc_weights[-1].dot(h)+self.fc_biases[-1]
        self.out = z
        return z

    # ======= PREDICTION =======
    def predict(self, x):
        z = self.forward(x)
        return np.argmax(z)

    # ======= TRAINING =======
    def train(self, X, Y, epochs=1, lr=0.01):
        for ep in range(epochs):
            total_loss = 0
            for x,y_true in zip(X,Y):
                # Forward
                z = self.forward(x)
                # Loss & delta
                y_vec = np.zeros(self.num_classes)
                y_vec[y_true] = 1
                delta = clip(z - y_vec, 200)
                total_loss += np.mean(delta**2)
                # Backprop FC
                grad_h = delta
                for l in reversed(range(len(self.fc_weights))):
                    h_prev = self.fc_cache[l]
                    dw = clip(np.outer(grad_h, h_prev))
                    db = clip(grad_h)
                    self.fc_weights[l] -= lr * dw
                    self.fc_biases[l] -= lr * db
                    if l>0:
                        grad_h = self.fc_weights[l].T.dot(grad_h)
                        grad_h = grad_h * (self.fc_cache[l]>0)  # ReLU deriv
                # Note: conv backprop omitted (can be added)
            print(f"Epoch {ep+1}/{epochs}, Loss: {total_loss/len(X):.6f}")

    # ======= TEST =======
    def test(self, X, Y):
        correct = 0
        for x,y in zip(X,Y):
            pred = self.predict(x)
            if pred==y: correct+=1
        acc = correct/len(X)*100
        print(f"Accuracy: {acc:.2f}%")
        return acc

    # ======= SAVE/LOAD TENSOR =======
    def save(self, path):
        with open(path,'wb') as f:
            pickle.dump(self.__dict__, f)

    def load(self, path):
        with open(path,'rb') as f:
            self.__dict__ = pickle.load(f)



