"""
Advanced module for making powerful Neural Network AI models.
"""

from aidk_framework.default_network import NeuralNetwork as def_NeuralNework
from aidk_framework.network import NeuralNetwork
from aidk_framework.networkFast import FastNeuralNetworkTF
from aidk_framework.resnet import ResNetCNN
from aidk_framework.resnetFast import FastResNetCNN
from aidk_framework.deep_rnn import DeepRNN
from aidk_framework.deep_rnnFast import FastDeepRNN
from aidk_framework.rfcn import ResFCN
from aidk_framework.rfcnFast import FastResFCN
from aidk_framework.gan import FastGAN
import aidk_framework.network as network
import aidk_framework.deep_rnn as deep_rnn
import aidk_framework.resnet as resnet
import aidk_framework.rfcn as rfcn
import aidk_framework.networkFast as networkFast
import aidk_framework.deep_rnnFast as deep_rnnFast
import aidk_framework.resnetFast as resnetFast
import aidk_framework.rfcnFast as rfcnFast
import aidk_framework.gan as gan
from PIL import Image
import tensorflow as tf
import numpy as np
import pandas as pd
import pickle
import os

class NN():
    def __init__(self) -> None:
        self.network = def_NeuralNework()
    
    def set_network(self, num_in:int, num_h:list[int], num_out:int, layer_activations:list[int], text_based:bool) -> None:
        self.network = NeuralNetwork(num_in, num_h, num_out, layer_activations, text_based)
    
    def tensor(self) -> list:
        return self.network.tensor()
    
    def prompt(self, prompt:str, view_working: bool) -> str:
        network = self.network
        return network.calculate(prompt, view_working)
    
    def train(self, csv_file: str, epochs: int, learning_rate: float, view_working: bool) -> None:
        return self.network.train(csv_file, epochs, learning_rate, view_working)
    
    def test(self, csv_file: str, view_working: bool):
        return self.network.test(csv_file, view_working)
    
    def finetune(self, target_fn, inputs, epochs: int, learning_rate: float) -> None:
        return self.network.finetune(target_fn, inputs, epochs, learning_rate)
    
    def save(self, path:str):
        with open(path, "wb") as f:
            pickle.dump(self.tensor(), f)

    def load(self, path:str):
        import pickle
        with open(path, "rb") as f:
            tensor = pickle.load(f)
        
        # Rebuild network
        self.set_network(tensor[0], tensor[1], tensor[2], tensor[7], tensor[8])
        self.network.set_tensor(tensor)

class FastNN:
    def __init__(self) -> None:
        self.network = None

    # -------------------------
    # Network setup
    # -------------------------
    def set_network(
        self,
        num_in: int,
        num_h: list[int],
        num_out: int,
        layer_activations: list[int],
        text_based: bool,
        classifier: bool
    ) -> None:
        self.network = FastNeuralNetworkTF(
            num_in=num_in,
            num_h=num_h,
            num_out=num_out,
            layer_activations=layer_activations,
            text_based=text_based,
            classifier=classifier
        )

    # -------------------------
    # Tensor (compat layer)
    # -------------------------
    def tensor(self) -> list:
        """
        Matches NeuralNetwork.tensor() format for compatibility.
        We store only metadata; TF handles weights internally.
        """
        return [
            self.network.num_in,
            self.network.num_h,
            self.network.num_out,
            None,  # hidden weights (TF-managed)
            None,  # hidden biases
            None,  # output weights
            None,  # output biases
            self.network.layer_activations,
            self.network.text_based,
            self.network.classifier
        ]

    # -------------------------
    # Prompt / inference
    # -------------------------
    def prompt(self, prompt):
        return self.network.calculate(prompt)

    # -------------------------
    # Training / evaluation
    # -------------------------
    def train(
        self,
        csv_file: str,
        epochs: int,
        learning_rate: float
    ) -> None:
        return self.network.train(csv_file, epochs, learning_rate)

    def test(self, csv_file: str, view_working: bool = False):
        return self.network.test(csv_file, view_working)

    def finetune(
        self,
        target_fn,
        inputs,
        epochs: int,
        learning_rate: float
    ) -> None:
        return self.network.finetune(target_fn, inputs, epochs, learning_rate)

    # -------------------------
    # Save / Load
    # -------------------------
    def save(self, path: str):
        """
        Saves:
        - metadata via pickle
        - TF model via SavedModel
        """
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "wb") as f:
            pickle.dump(self.tensor(), f)

        self.network.save(model_path)

    def load(self, path: str):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "rb") as f:
            tensor = pickle.load(f)

        # Rebuild network
        self.set_network(
            tensor[0],
            tensor[1],
            tensor[2],
            tensor[7],
            tensor[8]
        )

        # Load TF weights
        self.network.load(model_path)

class RNN():
    def __init__(self) -> None:
        self.network = def_NeuralNework()
    
    def set_network(self, num_in:int, num_h:list[int], num_out:int, layer_activations:list[int], text_based:bool) -> None:
        self.network = DeepRNN(num_in, num_h, num_out, layer_activations, text_based)
    
    def tensor(self) -> list:
        return self.network.tensor()
    
    def prompt(self, prompt:str, view_working: bool) -> str:
        network = self.network
        return network.calculate(prompt, view_working)
    
    def train(self, csv_file: str, epochs: int, learning_rate: float, view_working: bool) -> None:
        return self.network.train(csv_file, epochs, learning_rate, view_working)
    
    def finetune(self, target_fn, inputs, epochs: int, learning_rate: float) -> None:
        return self.network.finetune(target_fn, inputs, epochs, learning_rate)
    
    def save(self, path:str):
        with open(path, "wb") as f:
            pickle.dump(self.tensor(), f)

    def load(self, path:str):
        import pickle
        with open(path, "rb") as f:
            tensor = pickle.load(f)
        
        # Rebuild network
        self.set_network(tensor[0], tensor[1], tensor[2], tensor[7], tensor[8])
        self.network.set_tensor(tensor)

class FastRNN:
    def __init__(self) -> None:
        self.network = None

    # -------------------------
    # Network setup
    # -------------------------
    def set_network(
        self,
        num_in: int,
        num_h: list[int],
        num_out: int,
        layer_activations: list[int],
        text_based: bool,
        classifier: bool = False
    ) -> None:
        self.network = FastDeepRNN(
            num_in=num_in,
            num_h=num_h,
            num_out=num_out,
            layer_activations=layer_activations,
            text_based=text_based,
            classifier=classifier
        )

    # -------------------------
    # Tensor (compat layer)
    # -------------------------
    def tensor(self) -> list:
        """
        Returns metadata only (weights are managed internally by TF)
        Format matches original DeepRNN.tensor() for compatibility.
        """
        return [
            self.network.num_in,
            self.network.num_h,
            self.network.num_out,
            None,  # input->hidden weights (TF-managed)
            None,  # hidden biases
            None,  # recurrent weights
            None,  # output biases
            self.network.layer_activations,
            self.network.text_based,
            self.network.classifier
        ]

    # -------------------------
    # Prompt / inference
    # -------------------------
    def prompt(self, prompt: str):
        # view_working ignored, TF handles internally
        return self.network.calculate(prompt)

    # -------------------------
    # Training / evaluation
    # -------------------------
    def train(
        self,
        csv_file: str,
        epochs: int = 1,
        learning_rate: float = 0.01
    ) -> None:
        return self.network.train(csv_file, epochs, learning_rate)

    def test(self, csv_file: str, view_working: bool = False):
        return self.network.test(csv_file, view_working)

    def finetune(
        self,
        target_fn,
        inputs,
        epochs: int = 1,
        learning_rate: float = 0.01
    ) -> None:
        return self.network.finetune(target_fn, inputs, epochs, learning_rate)

    # -------------------------
    # Save / Load
    # -------------------------
    def save(self, path: str):
        """
        Saves:
        - metadata via pickle
        - TF model via SavedModel
        """
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "wb") as f:
            pickle.dump(self.tensor(), f)

        self.network.save(model_path)

    def load(self, path: str):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "rb") as f:
            tensor = pickle.load(f)

        # Rebuild network
        self.set_network(
            tensor[0],
            tensor[1],
            tensor[2],
            tensor[7],
            tensor[8],
            tensor[9]
        )

        # Load TF weights
        self.network.load(model_path)

class CNN():
    def __init__(self) -> None:
        # Initialize with a default small network
        self.network = ResNetCNN()

    def set_network(self, input_size:tuple, num_out:int, conv_layers:list, fc_layers:list, text_based:bool=False) -> None:
        """
        Rebuild the ResNetCNN with new settings.
        input_size: (H,W)
        num_out: number of output classes
        conv_layers: list of tuples [(in_c,out_c,kernel), ...]
        fc_layers: list of neurons in fully connected layers
        """
        self.network = ResNetCNN(input_shape=input_size, num_classes=num_out, conv_blocks=conv_layers, fc_layers=fc_layers, text_based=text_based)

    def tensor(self) -> list:
        """Return full tensor of network weights/biases/etc"""
        return [self.network.__dict__]

    def prompt(self, prompt, view_working:bool=False):
        """Forward pass for input"""
        # if text-based, assume prompt is already tokenized/processed
        return self.network.forward(prompt)

    def train(self, csv_file:str, epochs:int=1, learning_rate:float=0.01) -> None:
        # Load CSV, assume last column is label
        data = pd.read_csv(csv_file)
        X,Y = [],[]
        for _,row in data.iterrows():
            # xi = np.array([row[c] for c in data.columns[:-1]]).reshape(self.network.input_shape)
            # xi = np.array([...], dtype=np.float64).reshape(1, *self.network.input_shape)
            xi = np.array(row[:-1], dtype=np.float64).reshape(1, *self.network.input_shape)
            
            X.append(xi)
            Y.append(int(row[data.columns[-1]]))
        self.network.train(X,Y, epochs=epochs, lr=learning_rate)

    def test(self, csv_file:str, view_working:bool=False) -> float:
        data = pd.read_csv(csv_file)
        X,Y = [],[]
        for _,row in data.iterrows():
            xi = np.array([row[c] for c in data.columns[:-1]]).reshape(self.network.input_shape)
            X.append(xi)
            Y.append(int(row[data.columns[-1]]))
        return self.network.test(X,Y)

    def finetune(self, target_fn, inputs, epochs:int=1, learning_rate:float=0.01) -> None:
        best = self.tensor()
        for epoch in range(epochs):
            # Random perturbation
            for i in range(len(self.network.fc_weights)):
                self.network.fc_weights[i] += np.random.randn(*self.network.fc_weights[i].shape)*learning_rate
            success = target_fn(inputs, self.network.forward(inputs))
            if not success:
                # Revert
                self.network.__dict__ = best[0]

    def save(self, path:str):
        with open(path, "wb") as f:
            pickle.dump(self.tensor(), f)

    def load(self, path:str):
        with open(path, "rb") as f:
            tensor = pickle.load(f)
        # Rebuild network
        self.network.__dict__ = tensor[0]

class FastCNN:
    def __init__(self) -> None:
        # Default small network
        self.network = FastResNetCNN()

    # -------------------------
    # Rebuild / set network
    # -------------------------
    def set_network(self, input_size:tuple, num_out:int, conv_layers:list, fc_layers:list, classifier:bool=False) -> None:
        """
        input_size: (H,W,C)
        num_out: number of output classes
        conv_layers: list of tuples [(filters,kernel), ...]
        fc_layers: list of neurons in fully connected layers
        """
        self.network = FastResNetCNN(
            input_shape=input_size,
            num_classes=num_out,
            conv_blocks=conv_layers,
            fc_layers=fc_layers,
            classifier=classifier
        )

    # -------------------------
    # Tensor (metadata only)
    # -------------------------
    def tensor(self) -> list:
        return [self.network.input_shape,
                self.network.num_classes,
                self.network.fc_layers,
                self.network.classifier]

    # -------------------------
    # Forward / prompt
    # -------------------------
    def prompt(self, prompt):
        return self.network.forward(prompt)

    # -------------------------
    # Train
    # -------------------------
    def train(self, csv_file:str, epochs:int=1, learning_rate:float=0.001) -> None:
        data = pd.read_csv(csv_file)
        X,Y = [],[]
        for _,row in data.iterrows():
            xi = np.array(row[:-1], dtype=np.float32).reshape(*self.network.input_shape)
            X.append(xi)
            Y.append(int(row[data.columns[-1]]))
        self.network.train(X,Y, epochs=epochs, lr=learning_rate)

    # -------------------------
    # Test
    # -------------------------
    def test(self, csv_file:str) -> float:
        data = pd.read_csv(csv_file)
        X,Y = [],[]
        for _,row in data.iterrows():
            xi = np.array(row[:-1], dtype=np.float32).reshape(*self.network.input_shape)
            X.append(xi)
            Y.append(int(row[data.columns[-1]]))
        return self.network.test(X,Y)

    # -------------------------
    # Finetune (RL-style perturb)
    # -------------------------
    def finetune(self, target_fn, inputs, epochs:int=1, learning_rate:float=0.001) -> None:
        best_weights_path = "__temp_fastcnn_best__"
        self.save(best_weights_path)
        for epoch in range(epochs):
            # Perturb FC layers only (simple RL-style)
            for i, layer in enumerate(self.network.model.layers):
                if "dense" in layer.name:
                    weights, biases = layer.get_weights()
                    weights += np.random.randn(*weights.shape) * learning_rate
                    biases += np.random.randn(*biases.shape) * learning_rate
                    layer.set_weights([weights,biases])

            success = target_fn(inputs, self.network.forward(inputs))
            if not success:
                self.load(best_weights_path)

    # -------------------------
    # Save / Load
    # -------------------------
    def save(self, path:str):
        self.network.save(path)

    def load(self, path:str):
        self.network.load(path)

class RFCN():
    def __init__(self) -> None:
        self.network = def_NeuralNework()
    
    def set_network(self, input_size:int, conv_layers:list[int], num_out:int, layer_activations:list[int], text_based:bool) -> None:
        self.network = ResFCN(input_size, conv_layers, num_out, layer_activations, text_based)
    
    def tensor(self) -> list:
        return self.network.tensor()
    
    def prompt(self, prompt:str, view_working: bool) -> str:
        network = self.network
        return network.calculate(prompt, view_working)
    
    def train(self, csv_file: str, epochs: int, learning_rate: float, view_working: bool) -> None:
        return self.network.train(csv_file, epochs, learning_rate, view_working)
    
    def test(self, csv_file: str, view_working: bool) -> float:
        return self.network.test(csv_file, view_working)
    
    def finetune(self, target_fn, inputs, epochs: int, learning_rate: float) -> None:
        return self.network.finetune(target_fn, inputs, epochs, learning_rate)
    
    def save(self, path:str):
        with open(path, "wb") as f:
            pickle.dump(self.tensor(), f)

    def load(self, path:str):
        import pickle
        with open(path, "rb") as f:
            tensor = pickle.load(f)
        
        # Rebuild network
        self.set_network(tensor[0], tensor[1], tensor[2], tensor[5], tensor[6])
        self.network.set_tensor(tensor)

class FastRFCN():
    def __init__(self) -> None:
        self.network = None

    # -------------------------
    # Network setup
    # -------------------------
    def set_network(
        self,
        input_size: int,
        hidden_layers: list[int],
        num_out: int,
        layer_activations: list[int],
        text_based: bool = False,
        classifier: bool = True
    ) -> None:
        self.network = FastResFCN(
            input_size=input_size,
            conv_layers=hidden_layers,
            num_out=num_out,
            layer_activations=layer_activations,
            text_based=text_based,
            classifier=classifier
        )

    # -------------------------
    # Tensor (compatibility)
    # -------------------------
    def tensor(self) -> list:
        """
        Matches ResFCN.tensor() format for compatibility.
        TF handles weights internally.
        """
        return self.network.tensor()

    # -------------------------
    # Prompt / inference
    # -------------------------
    def prompt(self, prompt: str):
        return self.network.calculate(prompt)

    # -------------------------
    # Training / evaluation
    # -------------------------
    def train(self, csv_file: str, epochs: int, learning_rate: float) -> None:
        return self.network.train(csv_file, epochs, learning_rate)

    def test(self, csv_file: str, view_working: bool = False) -> float:
        return self.network.test(csv_file, view_working)

    def finetune(self, target_fn, inputs, epochs: int, learning_rate: float) -> None:
        return self.network.finetune(target_fn, inputs, epochs, learning_rate)

    # -------------------------
    # Save / Load
    # -------------------------
    def save(self, path: str):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "wb") as f:
            pickle.dump(self.tensor(), f)

        self.network.model.save(model_path)

    def load(self, path: str):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        with open(meta_path, "rb") as f:
            import pickle
            tensor = pickle.load(f)

        self.set_network(
            tensor[0],
            tensor[1],
            tensor[2],
            tensor[5],
            tensor[6],
            getattr(self.network, "classifier", True)
        )

        self.network.model = FastResFCN(
            tensor[0],
            tensor[1],
            tensor[2],
            tensor[5],
            tensor[6],
            getattr(self.network, "classifier", True)
        ).model
        
        self.network.model = tf.keras.models.load_model(model_path)

class GAN:
    def __init__(self) -> None:
        self.network: FastGAN | None = None
        self.sample_size = None
        self.input_shape = None

    # =====================================
    # Network setup
    # =====================================
    def set_network(
        self,
        num_in: tuple,          # discriminator input shape (H,W,C)
        num_h: list[int],       # hidden layers
        num_out: int,           # generator output size
        sample_size: int        # latent dim
    ) -> None:

        self.sample_size = sample_size
        self.input_shape = num_in

        self.network = FastGAN(
            generator={
                "input_size": sample_size,
                "hidden_layers": num_h,
                "num_out": num_out,
                "layer_activations": [0] * (len(num_h) + 2),
                "text_based": False,
                "classifier": False
            },
            discriminator={
                "input_size": num_in,
                "conv_layers": [(i, 1) for i in num_h],
                "num_out": num_out,
                "fc_layers": [*num_h, 2],
                "classifier": True
            }
        )

    # =====================================
    # Dataset loader (images)
    # =====================================
    def load_image_folder(
        self,
        folder: str,
        normalize: bool = True,
        limit: int | None = None
    ) -> np.ndarray:
        """
        Loads images from folder → numpy array
        """

        images = []
        files = sorted(os.listdir(folder))
        if limit:
            files = files[:limit]

        for file in files:
            path = os.path.join(folder, file)
            try:
                img = Image.open(path).convert("RGB")
                img = img.resize(self.input_shape[:2])
                arr = np.asarray(img, dtype=np.float32)

                if normalize:
                    arr /= 255.0

                images.append(arr)
            except Exception:
                continue

        return np.array(images)

    # =====================================
    # Training
    # =====================================
    def train(
        self,
        image_folder: str,
        epochs: int = 1000,
        batch_size: int = 32,
        lr_g: float = 0.001,
        lr_d: float = 0.001,
        view_working: bool = False,
        limit: int | None = None
    ) -> None:
        """
        Train GAN using images from a folder
        """

        real_data = self.load_image_folder(
            image_folder,
            normalize=True,
            limit=limit
        )

        self.network.train(
            real_data=real_data,
            epochs=epochs,
            batch_size=batch_size,
            lr_g=lr_g,
            lr_d=lr_d,
            view_working=view_working
        )

    # =====================================
    # Generate samples
    # =====================================
    def generate(
        self,
        num_samples: int = 1,
        latent_vectors: list | None = None
    ) -> np.ndarray:
        """
        Generate samples.
        You can pass your own latent vectors.
        """

        if latent_vectors is not None:
            return np.array([
                self.network.generator.prompt(z)
                for z in latent_vectors
            ])

        return self.network.generate(num_samples)

    # =====================================
    # Save / Load
    # =====================================
    def save(self, path: str):
        self.network.save(path)

    def load(self, path: str):
        self.network.load(path)



