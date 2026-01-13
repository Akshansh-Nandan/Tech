import h5py
import pandas as pd
import numpy as np
import lava.lib.dl.netx as netx
import torch
import lava.lib.dl.slayer as slayer
from lava.magma.core.run_configs import Loihi2SimCfg
from lava.magma.core.run_conditions import RunSteps
# from lava.lib.dl.slayer.utils import hdf5

class NeuromorphicNN:
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.num_in = 0
        self.num_h = []
        self.num_out = 0
        self.slayer_model = None
        self.is_compiled = False
        
        # SLAYER Hyperparameters for Loihi 2
        self.slayer_params = {
            'threshold': 0.1,
            'current_decay': 0.25,
            'voltage_decay': 0.1,
            'tau_grad': 0.03,
            'scale_grad': 3.0
        }

    def set_network(self, num_in, num_h, num_out, **kwargs):
        """Builds a SLAYER-based SNN architecture by passing the raw dict positionally."""
        self.num_in = num_in
        self.num_h = num_h
        self.num_out = num_out
        
        class SlayerNetwork(torch.nn.Module):
            def __init__(self, n_in, n_h, n_out, neuron_cfg):
                super().__init__()
                # We do NOT create a Neuron object here.
                # We pass the 'neuron_cfg' dictionary directly.
                
                dims = [n_in] + n_h + [n_out]
                
                # POSITIONAL FIX: Pass 'neuron_cfg' (the dict) as the 3rd argument.
                # Lava's internal __init__ will do the **neuron_cfg unpacking itself.
                self.blocks = torch.nn.ModuleList([
                    torch.nn.Sequential(
                        slayer.synapse.Dense(
                            dims[i],
                            dims[i+1]
                        ),
                        slayer.neuron.cuba.Neuron(
                            **neuron_cfg
                        )
                    )
                    for i in range(len(dims) - 1)
                ])

            def forward(self, spike_train):
                for block in self.blocks:
                    spike_train = block(spike_train)
                return spike_train

        self.slayer_model = SlayerNetwork(num_in, num_h, num_out, self.slayer_params).to(self.device)
        print(f"Lava-DL Slayer Model Initialized on {self.device}")

    def _csv_to_spikes(self, csv_file, time_steps=20):
        """
        Converts CSV vectors into Spatio-Temporal Spike Trains.
        Lava-DL needs (Batch, Features, Time)
        """
        df = pd.read_csv(csv_file)
        # Assuming last column is label, rest are features
        X = df.iloc[:, :-1].values.astype(np.float32)
        y = df.iloc[:, -1].values.astype(np.int64)
        
        # Rate Encoding: Higher value = higher probability of spike per time step
        X_tensor = torch.from_numpy(X).to(self.device)
        # Expand to (Batch, Features, Time)
        spike_train = (torch.rand((*X_tensor.shape, time_steps)).to(self.device) < 
                       X_tensor.unsqueeze(-1)).float()
        
        return spike_train, torch.from_numpy(y).to(self.device)

    def train(self, csv_file, epochs=5, learning_rate=0.001, view_working=False):
        """Trains the SNN using SLAYER Backpropagation through time."""
        spike_train, labels = self._csv_to_spikes(csv_file)
        optimizer = torch.optim.Adam(self.slayer_model.parameters(), lr=learning_rate)
        error = slayer.loss.SpikeTime(time_constant=5).to(self.device)

        self.slayer_model.train()
        for epoch in range(epochs):
            output = self.slayer_model(spike_train)
            # Target is a spike train where the correct neuron spikes consistently
            target = torch.zeros_like(output)
            for i, label in enumerate(labels):
                target[i, label, :] = 1.0
            
            loss = error(output, target)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            if view_working:
                if (epoch + 1) % 10 == 0 or epoch == epochs - 1:
                    print(f"Epoch {epoch+1}/{epochs} - Loss: {loss.item():.4f}")

        self.is_compiled = True
        print("Training Complete. Weights ready for Loihi-NC deployment.")

    def prompt(self, prompt, time_steps=20, view_working=True):
        """Runs inference and returns the neuron with the highest spike count."""
        self.slayer_model.eval()
        with torch.no_grad():
            # Convert single prompt to spike train (1, Features, Time)
            input_tensor = torch.tensor(prompt, dtype=torch.float32).to(self.device)
            input_spikes = (torch.rand((*input_tensor.shape, time_steps)).to(self.device) < 
                            input_tensor.unsqueeze(-1)).float().unsqueeze(0)
            
            output_spikes = self.slayer_model(input_spikes)
            # Count spikes across time for each output neuron
            spike_count = torch.sum(output_spikes, dim=-1).squeeze(0)
            
            if view_working:
                print(f"Output Spike Distribution: {spike_count.cpu().numpy()}")
            
            return spike_count.cpu().numpy()

    def save(self, path):
        # Save PyTorch state dict
        torch.save(self.slayer_model.state_dict(), f"{path}.adkm")
        print(f"Model saved as {path}.adkm")

    def load(self, path):
        # Make sure network is already set with set_network()
        self.slayer_model.load_state_dict(torch.load(f"{path}.adkm", map_location=self.device))
        self.is_compiled = True
        print(f"Model loaded from {path}.adkm")

    # def deploy_to_loihi(self, time_steps=32):
    #     if not self.is_compiled:
    #         raise Exception("Train the model before deploying!")

    #     export_path = "model_exchange.h5"

    #     # Correct for lava-dl 0.6.0
    #     hdf5.export(
    #         self.slayer_model,
    #         export_path
    #     )

    #     self.lava_net = netx.hdf5.Network(filename=export_path)

    #     print(f"Deployment Successful: Created {len(self.lava_net.layers)} Lava layers.")
    #     return self.lava_net

    def hardware_inference(self, input_vector, time_steps=64):
        """
        CPU/GPU spike-based inference (Loihi-faithful timing, no NetX)
        """
        self.slayer_model.eval()
        with torch.no_grad():
            x = torch.tensor(input_vector, dtype=torch.float32).to(self.device)
            spikes = (torch.rand((1, x.shape[0], time_steps)).to(self.device)
                    < x.unsqueeze(0).unsqueeze(-1)).float()

            out = self.slayer_model(spikes)
            spike_count = out.sum(dim=-1).squeeze(0)

        print("Inference complete (Loihi-faithful simulation)")
        return spike_count.cpu().numpy()



