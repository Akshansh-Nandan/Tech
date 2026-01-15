import numpy as np
import aidk_framework.ai_dev_kit as aidk


class FastGAN:
    """
    Regular (Vanilla) GAN
    Generator : FastRFCN
    Discriminator : FastCNN
    """

    def __init__(self, generator: dict, discriminator: dict):
        # Fixed architecture (DO NOT CHANGE)
        self.generator = aidk_core.neuralnet_kit.FastRFCN()
        self.discriminator = aidk_core.neuralnet_kit.FastCNN()

        # Set networks
        self.generator.set_network(**generator)
        self.discriminator.set_network(**discriminator)

        # Cache dimensions
        self.latent_dim = generator["input_size"]        # z dim
        self.sample_size = generator["num_out"]          # generated vector size
        self.disc_input_shape = discriminator["input_size"]

    # ===============================
    # Utility
    # ===============================
    def _sample_noise(self, batch_size: int):
        # (B, latent_dim)
        return np.random.randn(batch_size, self.latent_dim).astype(np.float32)

    def _reshape_for_disc(self, x):
        """
        Ensure generated / real samples match discriminator input shape
        """
        return np.array(x, dtype=np.float32).reshape(self.disc_input_shape)

    # ===============================
    # Training
    # ===============================
    def train(
        self,
        real_data: np.ndarray,
        epochs: int = 1000,
        batch_size: int = 32,
        lr_g: float = 0.001,
        lr_d: float = 0.001,
        view_working: bool = False
    ):
        """
        real_data shape:
        - vector GAN  : (N, sample_size)
        - image GAN   : (N, *disc_input_shape)
        """

        for epoch in range(epochs):

            # ---------------------
            # Train Discriminator
            # ---------------------
            idx = np.random.randint(0, real_data.shape[0], batch_size)
            real_batch = real_data[idx]

            noise = self._sample_noise(batch_size)
            
            fake_batch = np.array([
                self.generator.prompt(z.tolist()) for z in noise
            ])

            # --- real samples ---
            for real in real_batch:
                real_x = self._reshape_for_disc(real)
                self.discriminator.finetune(
                    target_fn=lambda i, o: int(o[0] > 0.5),
                    inputs=real_x,
                    epochs=1,
                    learning_rate=lr_d
                )

            # --- fake samples ---
            for fake in fake_batch:
                fake_x = self._reshape_for_disc(fake)
                self.discriminator.finetune(
                    target_fn=lambda i, o: int(o[0] < 0.5),
                    inputs=fake_x,
                    epochs=1,
                    learning_rate=lr_d
                )

            # ---------------------
            # Train Generator
            # ---------------------
            noise = self._sample_noise(batch_size)

            def generator_target_fn(z, generated):
                gen_x = self._reshape_for_disc(generated)
                pred = self.discriminator.prompt(gen_x)
                return int(pred[0] > 0.5)  # fool discriminator

            for z in noise:
                self.generator.finetune(
                    target_fn=generator_target_fn,
                    inputs=z.tolist(),
                    epochs=1,
                    learning_rate=lr_g
                )

            # ---------------------
            # Logging
            # ---------------------
            if view_working and epoch % max(1, epochs // 10) == 0:
                print(f"[FastGAN] Epoch {epoch+1}/{epochs}")

    # ===============================
    # Inference
    # ===============================
    def generate(self, num_samples: int = 1):
        noise = self._sample_noise(num_samples)
        return np.array([self.generator.prompt(z) for z in noise])

    # ===============================
    # Save / Load
    # ===============================
    def save(self, path: str):
        self.generator.save(path + "_generator")
        self.discriminator.save(path + "_discriminator")

    def load(self, path: str):
        self.generator.load(path + "_generator")
        self.discriminator.load(path + "_discriminator")



