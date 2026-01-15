import tensorflow as tf
import numpy as np
import pickle
from aidk_framework.token_manager import tokenize, untokenize

spacing = tokenize(" ")[0]

# Disable all GPUs for this session
tf.config.set_visible_devices([], 'GPU')

class FastResNetCNN:
    def __init__(self, input_shape=(28,28,1), num_classes=10,
                 conv_blocks=[(8,3),(16,3)], fc_layers=[64], classifier=False):
        """
        input_shape: (H,W,C) for TF
        conv_blocks: list of (filters,kernel) tuples
        fc_layers: list of neurons
        """
        self.input_shape = input_shape
        self.num_classes = num_classes
        self.fc_layers = fc_layers
        self.classifier = classifier

        self.model = self._build_model(conv_blocks, fc_layers)

    def _build_model(self, conv_blocks, fc_layers):
        inputs = tf.keras.Input(shape=self.input_shape)
        x = inputs
        residual = None

        # Conv blocks with simple residuals
        for filters,k in conv_blocks:
            z = tf.keras.layers.Conv2D(filters, k, padding='valid', activation='relu')(x)
            if residual is not None and residual.shape[1:] == z.shape[1:]:
                z = tf.keras.layers.Add()([z,residual])
            residual = z
            x = z

        x = tf.keras.layers.Flatten()(x)

        for neurons in fc_layers:
            x = tf.keras.layers.Dense(neurons, activation='relu')(x)
        
        if self.classifier:
            outputs = tf.keras.layers.Dense(self.num_classes, activation='softmax')(x)
        else:
            outputs = tf.keras.layers.Dense(self.num_classes, activation='linear')(x)

        model = tf.keras.Model(inputs, outputs)
        return model

    # -------------------------
    # Forward / Predict
    # -------------------------
    def forward(self, x):
        x = np.array(x, dtype=np.float32)
        if x.ndim == 2:  # (H,W)
            x = np.expand_dims(x, -1)
        x = np.expand_dims(x, 0)  # batch dimension
        y = self.model(x, training=False).numpy()[0]
        return y

    def predict(self, x):
        return int(np.argmax(self.forward(x)))

    # -------------------------
    # Train
    # -------------------------
    def train(self, X, Y, epochs=1, lr=0.001):
        # Preprocess
        X_proc = np.array([np.expand_dims(x, -1) if x.ndim==2 else x for x in X], dtype=np.float32)
        Y_proc = tf.keras.utils.to_categorical(Y, self.num_classes)
        
        if self.classifier:
            self.model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=lr),
                loss='categorical_crossentropy',
                metrics=['accuracy']
            )
        else:
            self.model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=lr),
                loss='mse'
            )

        self.model.fit(X_proc, Y_proc, epochs=epochs, verbose=1)

    # -------------------------
    # Test
    # -------------------------
    def test(self, X, Y):
        correct = 0
        for x,y_true in zip(X,Y):
            if self.predict(x) == y_true:
                correct += 1
        acc = correct/len(X)*100
        print(f"Accuracy: {acc:.2f}%")
        return acc

    # -------------------------
    # Save / Load
    # -------------------------
    def save(self, path):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        # Save TF model
        self.model.save(model_path)

        # Save metadata
        meta = {
            'input_shape': self.input_shape,
            'num_classes': self.num_classes,
            'fc_layers': self.fc_layers,
            'classifier': self.classifier
        }
        with open(meta_path, 'wb') as f:
            pickle.dump(meta, f)

    def load(self, path):
        meta_path = path + ".meta"
        model_path = path + ".keras"

        # Load metadata
        with open(meta_path,'rb') as f:
            meta = pickle.load(f)
        self.input_shape = meta['input_shape']
        self.num_classes = meta['num_classes']
        self.fc_layers = meta['fc_layers']
        self.classifier = meta['classifier']

        # Load TF model
        self.model = tf.keras.models.load_model(model_path)



