# AI (Artificial Intelligence) Development Kit Demo

# Import the module
import aidk_framework.ai_dev_kit as aidk

# Tranformer Module
# Note: Transformer Models use Meta-Learning by default and this setting cannot be changed

# Create an AI model tranformer, model_type 0 for EO, 1 for DO, 2 for ED, model_class 0 for Classical, 1 for MoE, 2 for Linear
transformer_model = aidk.transformers_kit.TransformerModel(
    model_type=1,
    model_class=0,
    dropout=0.1,
    max_seq_len=4096,
    d_model=64,
    nhead=16,
    ff_dim=512,
    num_layers=6,
    pretrain=False
)

# Process the pretraining corpus into dataset.csv suitable for training
aidk.transformers_kit.process_data(
    file_path="corpus.txt",
    max_length=4096,
    similarity_threshold=0.6
)

# Pretrain the model on the corpus
transformer_model.pretrain_on_corpus(
    corpus_path="corpus.txt",
    num_epochs=5,
    learning_rate=0.001,
    weight_decay=0.1,
    tokenizer=aidk.transformers_kit.tokenizer,
    batch_size=4
)

# Train the model on the dataset / generated dataset
transformer_model.train_on_dataset(
    dataset_path="dataset.csv",
    input_col="prompt",
    output_col="completion",
    num_epochs=5,
    learning_rate=0.001,
    weight_decay=0.1,
    tokenizer=aidk.transformers_kit.tokenizer,
    batch_size=16,
    system_prompt="You are a helpful assistant.",
    additional_prompt_engineering_parts="Memory: Example Memory\nTasks: Example task\netc.",
    user_label="User: ",
    response_label="AI: "
)

# Save the model to a file, any extension in the file path will be ignored
transformer_model.save_model(path="model")
# Load the model from a file with extension .adkm
transformer_model.load_model(path="model.adkm")

# Communicate with the model following the prompt engineering provided suring training
response = transformer_model.communicate(prompt="You are a helpful assistant. Give \nMemory: Example Memory\nTasks: Example task\netc.\nUser: Hi, how are you doing?", tokenizer=aidk.transformers_kit.tokenizer)
print(response)



# Neural Network Module
# Create target_fn function
# Example function provided, this function could also be linked to a game where the input is the map so the output is produced so accordingly, etc.
prev_error = -1
target = [2, 7, 3]

def target_fn(inputs, output):
    global prev_error
    error = sum([abs(target[i] - output[i]) for i in range(len(output))])
    
    if prev_error == -1 or error < prev_error:
        print("New Error:", error)
        prev_error = error
        return 1
    
    return 0

labels = ["N1", "N2", "N3"]

# Create an AI model Fully Connected Neural Network, default Neural Network is untrainable
nn_model = aidk.neuralnet_kit.NN() # Multiple types, NN is FCNN, CNN is ResNet, RNN is DeepRNN, RFCN is ResFCN, and each have a Fast edition

# Set the parameters to define the model and activate it
# Layer activations: 0 - ReLU, 1 - Sigmoid, 2 - Tanh, 3 - Identity
nn_model.set_network(
    num_in=4,
    num_h=[5, 5, 5, 5],
    num_out=3,
    layer_activations=[0, 2, 3, 3, 1, 0],
    text_based=False
)

# Train the model, set view_working to True for viewing all internal processes of training, back-propagation and forward passing
nn_model.train(
    csv_file="dataset.csv",
    epochs=5,
    learning_rate=0.001,
    view_working=False
)
# Finetune the model
nn_model.finetune(
    target_fn=target_fn,
    inputs=[1, 3, 8, 5],
    epochs=100,
    learning_rate=0.1
)

# Save the model to a file with extension .adkm
nn_model.save(path="model.adkm")
# Load the model from a file with extension .adkm
nn_model.load(path="model.adkm")

# View model tensor
print(nn_model.tensor())

# Communicate with the model, set view_working to True for viewing all internal processes of training, back-propagation and forward passing
response = nn_model.prompt(prompt=[5, 2, 0, 4], view_working=True)
print(*aidk.neuralnet_kit.network.probmax(response, labels))



# Prediction Model Module
# Import extra modules for training example
import random

# Create the model with model_type 0 for Linear Regression, 1 for Decision Tree Regressor, 2 for Logistic Regression and 3 for Decision Tree Classifier
prediction_model = aidk.prediction_kit.PredictionModel(model_type=0)

# Train the model
examples = [[example[0], [i + 2 for i in example[0]]] for example in [[[random.random() for i in range(4)]] for _ in range(100)]]

prediction_model.train(
    X=[example[0] for example in examples],
    y=[example[1] for example in examples]
)

# Save the model
prediction_model.save(filepath="model.adkm")
# Load the model
prediction_model.load(filepath="model.adkm")

# Communicate with the model
response = prediction_model.predict(X=[[3, 9, 11, 13]])
print(response)



# Neuromorphic Neural Network Module
# Create and set up
neuro_model = aidk.neuromorphic_nn.NeuromorphicNN()
neuro_model.set_network(num_in=64, num_h=[128, 64], num_out=10)

# 1. High-speed training on GPU/CPU (PyTorch based)
neuro_model.train(csv_file="neuromorphic_data.csv", epochs=20, view_working=True)

# 2. Hardware-accurate inference
result = neuro_model.hardware_inference(input_vector=[...])
print("Predicted neuron spike counts on Loihi-NC:", result)

# 3. Save the model for future use
neuro_model.save(path="neuromorphic_model")




