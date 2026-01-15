"""
Advanced module for making powerful Transformer AI models. Powered by PyTorch, TensorFlow and Scikit-Learn.
"""

from sklearn.model_selection import train_test_split
from transformers import pipeline
from transformers import T5Tokenizer, T5ForConditionalGeneration
from sentence_transformers import SentenceTransformer, util
from mixture_of_experts import MoE
import nltk
from nltk.tokenize import sent_tokenize
from textwrap import wrap
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset, TensorDataset
from torch.amp.autocast_mode import autocast
from tqdm import tqdm
import pandas as pd
import tiktoken
import json
import csv
from numba import cuda
import numpy as np
import functools
from functools import wraps
from torch.nn.utils.rnn import pad_sequence
import tensorflow as tf
from tensorflow.keras.layers import LayerNormalization, Dense, ReLU
from tensorflow.keras import Sequential
import learn2learn as l2l
import os
import aidk_framework.data as sample_data
from aidk_framework.data import sample_pretrain_data, sample_train_data

import bitsandbytes as bnb

torch.autograd.set_detect_anomaly(True)

# Download correct tokenizer
nltk.download("punkt_tab")

# Load the question generation model (fine-tuned for QA)
model_name = "valhalla/t5-small-qg-prepend"
tokenizer = T5Tokenizer.from_pretrained(model_name)
model = T5ForConditionalGeneration.from_pretrained(model_name, use_safetensors=True)

# Semantic similarity model
sentence_model = SentenceTransformer("all-MiniLM-L6-v2")

cuda_kill_switch = True

torch.cuda.empty_cache()
torch.cuda.ipc_collect()

print()

def general_accelerator(func):
    """A decorator to optimize functions."""
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Example optimization: simplify mathematical computations like expensive trig or powers.
        
        # Check if arguments have constant values that can be pre-calculated (if possible)
        optimized_args = []
        for arg in args:
            if isinstance(arg, float) and (arg.is_integer() or abs(arg) > 100):  # Example condition to optimize calculations
                optimized_args.append(arg)
            else:
                optimized_args.append(arg)  # No change
        
        # Example optimization for a function that does math: avoid redundant power calculations
        if 'n' in kwargs and kwargs['n'] == 2:  # Just an example: if `n` is 2, use sqrt instead of power
            kwargs['n'] = 2  # Use a faster operation like sqrt instead of `** 2`

        # You can apply other specific optimizations depending on known behavior of the function

        return func(*optimized_args, **kwargs)
    
    return wrapper

@general_accelerator
def accelerator(func, log: bool = False):
    """
    A decorator to run operations on the GPU if Numba CUDA is available.
    """
    def wrapper(*args, **kwargs):
        if cuda.is_available() and not cuda_kill_switch:
            try:
                if log:
                    print("CUDA is available. Running on GPU.")
                # Allocate memory on the GPU
                d_args = [cuda.to_device(arg) if isinstance(arg, np.ndarray) else arg for arg in args]
                d_kwargs = {k: cuda.to_device(v) if isinstance(v, np.ndarray) else v for k, v in kwargs.items()}
                result = func(*d_args, **d_kwargs)
                # Copy result back to host
                if isinstance(result, cuda.devicearray.DeviceNDArray):
                    result = result.copy_to_host()
                return result
            except cuda.CudaSupportError:
                if log:
                    print("CUDA is not available. Running function on CPU.")
                return func(*args, **kwargs)
            except cuda.KernelRuntimeError:
                if log:
                    print("CUDA runtime error. Running function on CPU.")
                return func(*args, **kwargs)
            except:
                if log:
                    print("Unknown Error encountered. Running function on CPU.")
                return func(*args, **kwargs)
        else:
            if log:
                print("CUDA is not available. Running function on CPU.")
            return func(*args, **kwargs)
    return wrapper

@general_accelerator
def model_accelerator(cls):
    original_init = cls.__init__

    @wraps(original_init)
    def new_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        device = torch.device("cuda" if torch.cuda.is_available() and not cuda_kill_switch else "cpu")
        self.to(device)
        print(f"[Accelerate] Model moved to {device}.")

    cls.__init__ = new_init
    return cls

@general_accelerator
def combine_csv_with_template(csv_file, template, input_col, output_col, flag):
    df = pd.read_csv(csv_file)
    
    combined_data = []
    for _, row in df.iterrows():
        formatted_str = template.format(row[input_col], row[output_col]) if not flag else template.format(row[input_col])
        combined_data.append(formatted_str)

    return combined_data

@general_accelerator
def generate_qa_pairs(text, top_k=50000, similarity_threshold=0.4):
    qa_pairs = []
    input_text = f"answer: {text}"
    encoding = tokenizer(input_text, padding=False, truncation=True, max_length=32768, return_tensors='pt')
    input_ids = encoding['input_ids']

    output = model.generate(
        input_ids=input_ids,
        max_length=256,
        num_beams=10,
        early_stopping=True,
        do_sample=True,
        top_k=top_k,
        top_p=0.9
    )

    question = tokenizer.decode(output[0], skip_special_tokens=True)
    answer = text

    embeddings = sentence_model.encode([question, answer])
    similarity = util.cos_sim(embeddings[0], embeddings[1]).item()

    if similarity >= similarity_threshold:
        qa_pairs.append({
            "question": question,
            "answer": answer,
            "similarity": round(similarity, 4)
        })

    return qa_pairs

def mf_func(m):
    if isinstance(m, nn.Linear):
        if not hasattr(mf_func, "prev"):
            nn.init.xavier_uniform_(m.weight)  # First layer gets Xavier
        else:
            try:
                with torch.no_grad():
                    u, _, v = torch.linalg.svd(mf_func.prev, full_matrices=False)
                    proj = torch.matmul(u, v)
                    m.weight.copy_(proj[:m.weight.shape[0], :m.weight.shape[1]])
            except:
                nn.init.xavier_uniform_(m.weight)  # Fallback
        mf_func.prev = m.weight.clone()

    elif isinstance(m, nn.LayerNorm):
        nn.init.ones_(m.weight)
        nn.init.zeros_(m.bias)

    elif isinstance(m, nn.Embedding):
        nn.init.normal_(m.weight, mean=0, std=0.02)

    elif isinstance(m, nn.MultiheadAttention):
        for name, param in m.named_parameters():
            if "in_proj_weight" in name:
                nn.init.xavier_uniform_(param)
            elif "out_proj.weight" in name:
                nn.init.xavier_uniform_(param)

    elif hasattr(m, "weight") and isinstance(m.weight, torch.nn.Parameter):
        nn.init.xavier_uniform_(m.weight)

# Dataset class
class TextDataset(Dataset):
    def __init__(self, dataframe, input_col, output_col, tokenizer, max_seq_len):
        self.data = dataframe
        self.input_col = input_col
        self.output_col = output_col
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        input_text = self.data.iloc[idx][self.input_col]
        output_text = self.data.iloc[idx][self.output_col]

        input_ids = self.tokenizer.encode(input_text, truncation=True, padding="max_length", max_length=self.max_seq_len)
        output_ids = self.tokenizer.encode(output_text, truncation=True, padding="max_length", max_length=self.max_seq_len)

        target_ids = torch.tensor(output_ids)
        
        # PyTorch's CrossEntropyLoss ignores the index -100 by default.
        target_ids[target_ids == self.tokenizer.pad_token_id] = -100
        
        return torch.tensor(input_ids), target_ids

class TextDataset2(Dataset):
    def __init__(self, lines, tokenizer, max_seq_len):
        self.lines = lines
        self.tokenizer = tokenizer
        self.max_seq_len = max_seq_len
        self.pad_id = tokenizer.pad_token_id

    def __len__(self):
        return len(self.lines)

    def __getitem__(self, idx):
        text = self.lines[idx]

        enc = self.tokenizer(
            text,
            truncation=True,
            max_length=self.max_seq_len,
            padding="max_length",
            return_tensors="pt"
        )

        input_ids = enc["input_ids"].squeeze(0)
        labels = input_ids.clone()

        # critical fix
        labels[labels == self.pad_id] = -100

        return input_ids, labels

def quantize_with_bnb(model, mode="int8"):
    """
    Quantizes all nn.Linear layers using bitsandbytes.
    Keeps LayerNorm, Embeddings, Attention, Softmax in FP32.
    """

    for name, module in model.named_children():
        # Recurse first
        quantize_with_bnb(module, mode)

        if isinstance(module, nn.Linear):
            in_f = module.in_features
            out_f = module.out_features
            bias = module.bias is not None

            if mode == "int8":
                quant_layer = bnb.nn.Linear8bitLt(
                    in_f, out_f, bias=bias
                )
            elif mode == "int4":
                quant_layer = bnb.nn.Linear4bit(
                    in_f, out_f, bias=bias,
                    compute_dtype=torch.float32
                )
            else:
                raise ValueError("mode must be int8 or int4")

            # Copy weights safely
            quant_layer.weight.data = module.weight.data.clone()
            if bias:
                quant_layer.bias.data = module.bias.data.clone()

            setattr(model, name, quant_layer)

    return model

# Decoder Block
class DecoderBlock(nn.Module):
    def __init__(self, d_model, nhead, ff_dim):
        super().__init__()
        self.self_attn = nn.MultiheadAttention(d_model, nhead, batch_first=True)
        self.cross_attn = nn.MultiheadAttention(d_model, nhead, batch_first=True)

        self.ff = nn.Sequential(
            nn.Linear(d_model, ff_dim),
            nn.ReLU(),
            nn.Linear(ff_dim, d_model)
        )

        self.ln1 = nn.LayerNorm(d_model)
        self.ln2 = nn.LayerNorm(d_model)
        self.ln3 = nn.LayerNorm(d_model)

    def forward(self, x, encoder_hidden):
        # 1️⃣ masked self-attention (you can add mask later)
        attn, _ = self.self_attn(x, x, x)
        x = self.ln1(x + attn)

        # 2️⃣ cross-attention (THIS is ED magic)
        attn, _ = self.cross_attn(x, encoder_hidden, encoder_hidden)
        x = self.ln2(x + attn)

        # 3️⃣ FFN
        ff = self.ff(x)
        return self.ln3(x + ff)

# Linear Attention Layer
class LinearAttention(nn.Module):
    def __init__(self, d_model, n_heads):
        super().__init__()
        self.d_model = d_model
        self.n_heads = n_heads
        self.head_dim = d_model // n_heads

        self.q_proj = nn.Linear(d_model, d_model)
        self.k_proj = nn.Linear(d_model, d_model)
        self.v_proj = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)

        self.epsilon = 1e-6

    def forward(self, x):
        B, T, D = x.shape
        H = self.n_heads
        d = self.head_dim

        # Project queries, keys, and values
        Q = self.q_proj(x).reshape(B, T, H, d).transpose(1, 2)  # (B, H, T, d)
        K = self.k_proj(x).reshape(B, T, H, d).transpose(1, 2)  # (B, H, T, d)
        V = self.v_proj(x).reshape(B, T, H, d).transpose(1, 2)  # (B, H, T, d)

        # Apply kernel feature (elu + 1) to Q and K for positive values
        Q = F.elu(Q) + 1
        K = F.elu(K) + 1

        # Compute KV and normalize
        KV = torch.einsum("bhnd,bhne->bhde", K, V)
        Z = 1 / (torch.einsum("bhnd,bhd->bhn", Q, K.sum(dim=2)) + self.epsilon)

        # Compute output
        context = torch.einsum("bhnd,bhde->bhne", Q, KV)
        context = context * Z.unsqueeze(-1)
        context = context.transpose(1, 2).contiguous().view(B, T, D)

        return self.out_proj(context)

# Transformer block
class TransformerBlock(nn.Module):
    def __init__(self, d_model, nhead, ff_dim):
        super().__init__()
        self.attn = nn.MultiheadAttention(embed_dim=d_model, num_heads=nhead, batch_first=True)
        self.ff = nn.Sequential(
            nn.Linear(d_model, ff_dim),
            nn.ReLU(),
            nn.Linear(ff_dim, d_model)
        )
        self.ln1 = nn.LayerNorm(d_model)
        self.ln2 = nn.LayerNorm(d_model)

    def forward(self, x, alibi_bias=None):
        attn_output, _ = self.attn(x, x, x)
        x = self.ln1(x + attn_output)
        ff_output = self.ff(x)
        return self.ln2(x + ff_output)

# MoE (Mixture of Experts) Transformer block
class MoETransformerBlock(nn.Module):
    def __init__(self, d_model, nhead, ff_dim):
        super().__init__()
        self.attn = nn.MultiheadAttention(embed_dim=d_model, num_heads=nhead, batch_first=True)
        self.ff = MoE(dim=d_model, hidden_dim=d_model * 8, num_experts=16)
        self.ln1 = nn.LayerNorm(d_model)
        self.ln2 = nn.LayerNorm(d_model)

    def forward(self, x, alibi_bias=None):
        attn_output, _ = self.attn(x, x, x)
        x = self.ln1(x + attn_output)
        ff_output = self.ff(x)
        return self.ln2(x + ff_output[0])

# Linear Transformer block
class LinearTransformerBlock(nn.Module):
    def __init__(self, d_model, nhead, ff_dim):
        super().__init__()
        self.attn = LinearAttention(d_model, nhead)
        self.ff = nn.Sequential(
            nn.Linear(d_model, ff_dim),
            nn.ReLU(),
            nn.Linear(ff_dim, d_model)
        )
        self.ln1 = nn.LayerNorm(d_model)
        self.ln2 = nn.LayerNorm(d_model)

    def forward(self, x, alibi_bias=None):
        attn_output = self.attn(x)
        x = self.ln1(x + attn_output)
        ff_output = self.ff(x)
        return self.ln2(x + ff_output)

# Alibi bias generator
@accelerator
def get_alibi_bias(n_heads, seq_len, device):
    return torch.zeros((1, n_heads, seq_len, seq_len), device=device)

# Full transformer model
class TransformerModel(nn.Module):
    def __init__(self, model_type, model_class, dropout, max_seq_len, d_model, nhead, ff_dim, num_layers, pretrain=False, checkpoint_model=True):
        super().__init__()
        vocab_size = tokenizer.vocab_size
        self.token_embed = nn.Embedding(vocab_size, d_model)
        self.model_type = model_type
        self.model_class = model_class

        if model_type in [0, 2]:
            self.encoder = nn.ModuleList([TransformerBlock(d_model, nhead, ff_dim) if model_class == 0 else MoETransformerBlock(d_model, nhead, ff_dim) if model_class == 1 else LinearTransformerBlock(d_model, nhead, ff_dim) for _ in range(num_layers)])
        if model_type in [1, 2]:
            if model_type == 2:
                self.decoder = nn.ModuleList(
                    [DecoderBlock(d_model, nhead, ff_dim) for _ in range(num_layers)]
                )
            elif model_type == 1:
                self.decoder = nn.ModuleList(
                    [TransformerBlock(d_model, nhead, ff_dim) for _ in range(num_layers)]
                )
            # self.decoder = nn.ModuleList([TransformerBlock(d_model, nhead, ff_dim) if model_class == 0 else MoETransformerBlock(d_model, nhead, ff_dim) if model_class == 1 else LinearTransformerBlock(d_model, nhead, ff_dim) for _ in range(num_layers)])

        self.ln_f = nn.LayerNorm(d_model)
        self.head = nn.Linear(d_model, vocab_size)

        self.max_seq_len = max_seq_len
        self.d_model = d_model
        self.nhead = nhead
        self.vocab = vocab_size
        self.ff_dim = ff_dim
        self.num_layers = num_layers
        self.dropout = nn.Dropout(dropout)

        self.total_params = sum(p.numel() for p in model.parameters())

        self.apply(mf_func)

        if pretrain:
            with open("./temp", "w") as file:
                file.write(sample_pretrain_data)

            self.pretrain_on_corpus("./temp", 5, 0.001, 0.1, tokenizer)
            
            with open("./temp.csv", "w") as file:
                file.write(sample_train_data)

            self.train_on_dataset("./temp.csv", "prompt", "completion", 5, 0.001, 0.1, tokenizer)
        
        if checkpoint_model:
            print()
            self.save_model("checkpoint_model")
        
        print(f"Total Parameters: {self.total_params}")

        print("Model Created\n")
    
    @accelerator
    def forward(self, input_ids, decoder_input_ids=None):
        input_ids = torch.clamp(input_ids, 0, self.vocab - 1)
        if decoder_input_ids is None:
            decoder_input_ids = input_ids
        B, T = input_ids.shape
        alibi_bias = get_alibi_bias(self.nhead, T, input_ids.device)

        x = self.token_embed(input_ids)
        x = self.dropout(x)

        if self.model_type == 0:
            for block in self.encoder:
                x = block(x, alibi_bias=alibi_bias)
            x = self.ln_f(x)
            return self.head(x)

        elif self.model_type == 1:
            for block in self.decoder:
                x = block(x, alibi_bias=alibi_bias)
            x = self.ln_f(x)
            return self.head(x)

        elif self.model_type == 2:
            enc_x = self.token_embed(input_ids)
            for block in self.encoder:
                enc_x = block(enc_x, alibi_bias=alibi_bias)

            dec_input = self.token_embed(decoder_input_ids)
            for block in self.decoder:
                dec_input = block(dec_input, alibi_bias=alibi_bias)

            x = self.ln_f(dec_input)
            return self.head(x)

    @accelerator
    def pretrain_on_corpus(self, corpus_path, num_epochs, learning_rate, weight_decay, tokenizer, batch_size=4, response_label="AI: ", training_flag=False, flag0=True):
        if self.model_type != 1:
            raise Exception("Pretraining is only for Decoder-Only models (model type 1)")

        if not training_flag:
            def yield_chunks(file_obj):
                buffer = ""
                for line in file_obj:
                    buffer += line
                    if "\n\n\n\n" in buffer:
                        parts = buffer.split("\n\n\n\n")
                        for part in parts[:-1]:
                            yield part.strip()
                        buffer = parts[-1]  # carry over the remaining
                if buffer.strip():
                    yield buffer.strip()  # last chunk

            with open(corpus_path, 'r', encoding='utf-8', errors="ignore") as f:
                for i, chunk in enumerate(yield_chunks(f)):
                    text_data = chunk

                    with open("./temp.csv", "w", encoding="utf-8") as file:
                        file.write("\"output\"\n" + "\"" + text_data.replace("\"", "\"\"") + "\"")
                    
                    self.train_on_dataset("./temp.csv", "output", "", num_epochs, learning_rate, weight_decay, tokenizer, batch_size, "", "", "", response_label, False)
            
            return
        else:
            # with open(corpus_path, "r", encoding="utf-8") as f:
            #     lines = [line.strip() for line in f if line.strip()]
            with open(corpus_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Split by the 4-newline delimiter and filter out empty strings
                lines = [chunk.strip() for chunk in content.split("\n\n\n\n") if chunk.strip()]

        # split = int(0.8 * len(lines))
        train_lines = lines[:]
        # val_lines = lines[split:]
        val_lines = []

        train_set = TextDataset2(train_lines, tokenizer, self.max_seq_len)
        val_set   = TextDataset2(val_lines, tokenizer, self.max_seq_len)

        # Split the data into training and validation sets (80-20 split)
        # split_index = int(0.8 * len(train_lines))
        train_text = train_lines[:]
        # val_text = val_lines[split_index:]
        val_text = []

        # Create dataset objects for training and validation sets
        train_set = TextDataset2(train_text, tokenizer, self.max_seq_len)
        val_set = TextDataset2(val_text, tokenizer, self.max_seq_len)

        # Create data loaders for batching
        train_loader = DataLoader(train_set, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_set, batch_size=batch_size, shuffle=False)

        meta_model = l2l.algorithms.MetaSGD(self, learning_rate)

        ln = learning_rate

        # Initialize the optimizer and loss function
        optimizer = torch.optim.AdamW(meta_model.parameters(), lr=ln, weight_decay=weight_decay)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.1, patience=10)
        loss_fn = nn.CrossEntropyLoss(ignore_index=-100)

        self.train()  # Set the model to training mode
        device = torch.device("cuda" if torch.cuda.is_available() and not cuda_kill_switch else "cpu")
        self.to(device)
        meta_model.to(device)

        print(f"Pretrain samples: {len(train_set)}, Batches: {len(train_loader)}" if flag0 else f"Train samples: {len(train_set)}, Batches: {len(train_loader)}")
        # print(f"Val samples: {len(val_set)}, Batches: {len(val_loader)}")

        for epoch in range(num_epochs):
            torch.cuda.empty_cache()
            
            total_loss = 0
            self.train()
            pbar = tqdm(train_loader, desc=f"Epoch {epoch + 1}/{num_epochs} [Pretraining]" if flag0 else f"Epoch {epoch + 1}/{num_epochs} [Training]")

            for x, _ in pbar:
                # x = x.to(device)

                if not flag0:
                    inputs = []
                    targets = []

                    for text in x:
                        text = tokenizer.decode(text, skip_special_tokens=True)
                        
                        if response_label in text:  # Only split if the response_label exists
                            prompt, response = text.split(response_label, 1)

                            # # Tokenize prompt as input (fixed part)
                            # input_tokens = tokenizer(prompt, truncation=True, max_length=self.max_seq_len, return_tensors="pt").input_ids
                            # # Tokenize response as target (what we want the model to predict)
                            # target_tokens = tokenizer(response, truncation=True, max_length=self.max_seq_len, return_tensors="pt").input_ids
                            
                            # Force padding to max_length so all tensors are equal size
                            input_tokens = tokenizer(
                                prompt, 
                                truncation=True, 
                                max_length=self.max_seq_len, 
                                padding='max_length', # CRUCIAL
                                return_tensors="pt"
                            ).input_ids
                            
                            target_tokens = tokenizer(
                                response, 
                                truncation=True, 
                                max_length=self.max_seq_len, 
                                padding='max_length', # CRUCIAL
                                return_tensors="pt"
                            ).input_ids

                            # Add tokenized inputs and targets to the lists
                            inputs.append(input_tokens)
                            targets.append(target_tokens)

                    # Stack the inputs and targets into tensors
                    if inputs and targets:
                        input_ids = torch.stack(inputs).squeeze(1)
                        target_ids = torch.stack(targets).squeeze(1)
                    else:
                        # print("No valid splits found for this batch. Skipping...")
                        continue  # Skip this batch if no valid splits found

                else:
                    input_ids = x[:, :-1]  # All tokens except the last
                    target_ids = x[:, 1:]  # All tokens except the first
                
                # Pad input tokens if needed to max_seq_len
                input_padding_length = self.max_seq_len - input_ids.shape[1]
                if input_padding_length > 0:
                    input_ids = torch.cat([input_ids, torch.full((input_ids.size(0), input_padding_length), tokenizer.pad_token_id)], dim=1)

                # Pad target tokens if needed to max_seq_len
                target_padding_length = self.max_seq_len - target_ids.shape[1]
                if target_padding_length > 0:
                    target_ids = torch.cat([
                        target_ids, 
                        torch.full(
                            (target_ids.size(0), target_padding_length), 
                            tokenizer.pad_token_id, 
                            dtype=torch.long, 
                            device=target_ids.device
                        )
                    ], dim=1)
                
                input_ids = input_ids.to(device)
                target_ids = target_ids.to(device)
                
                # support_size = input_ids.size(0) // 2
                support_size = max(1, input_ids.size(0) // 2)
                
                if support_size > 1:
                    support_x, query_x = input_ids[:support_size], input_ids[support_size:]
                    support_y, query_y = target_ids[:support_size], target_ids[support_size:]
                else:
                    support_x, query_x = input_ids[:], input_ids[:]
                    support_y, query_y = target_ids[:], target_ids[:]

                # print(support_x.shape, support_y.shape, query_x.shape, query_y.shape)
                # print([i for i in x.size()], support_size)

                # Forward pass
                learner = meta_model.clone()
                support_out = learner(support_x)
                
                support_out = support_out.view(-1, support_out.size(-1))  # [batch_size*seq_len, vocab_size]
                support_y = support_y.view(-1)                            # [batch_size*seq_len]

                support_loss = loss_fn(
                    support_out.view(-1, support_out.size(-1)),
                    support_y.view(-1)
                )

                learner.adapt(support_loss)

                query_out = learner(query_x)
                query_loss = loss_fn(
                    query_out.view(-1, query_out.size(-1)),
                    query_y.view(-1)
                )
                
                if query_loss.isnan():
                    # print("NaN loss detected. Skipping...")
                    continue

                optimizer.zero_grad()
                query_loss.backward()
                optimizer.step()

                total_loss += query_loss.item()
                pbar.set_postfix(loss=query_loss.item())

            avg_train_loss = total_loss / len(train_loader)

            # Validation step
            self.eval()
            val_loss = -1
            with torch.no_grad():
                for x, _ in val_loader:
                    # x = x.to(device)

                    if not flag0:
                        inputs = []
                        targets = []

                        for text in x:
                            text = tokenizer.decode(text, skip_special_tokens=True)
                            if response_label in text:  # Only split if the response_label exists
                                prompt, response = text.split(response_label, 1)

                                # Tokenize prompt as input
                                input_tokens = tokenizer(prompt, truncation=True, max_length=self.max_seq_len, return_tensors="pt").input_ids
                                # Tokenize response as target
                                target_tokens = tokenizer(response, truncation=True, max_length=self.max_seq_len, return_tensors="pt").input_ids

                                inputs.append(input_tokens)
                                targets.append(target_tokens)
                        
                        if inputs and targets:
                            input_ids = torch.stack(inputs).squeeze(1)
                            target_ids = torch.stack(targets).squeeze(1)
                        else:
                            continue

                    else:
                        input_ids = x[:, :-1]  # All tokens except the last
                        target_ids = x[:, 1:]  # All tokens except the first
                    
                    input_ids = input_ids.to(device)
                    target_ids = target_ids.to(device)
                
                    support_size = max(1, input_ids.size(0) // 2)
                
                    if support_size > 1:
                        support_x, query_x = input_ids[:support_size], input_ids[support_size:]
                        support_y, query_y = target_ids[:support_size], target_ids[support_size:]
                    else:
                        support_x, query_x = input_ids[:], input_ids[:]
                        support_y, query_y = target_ids[:], target_ids[:]

                    # Forward pass
                    learner = meta_model.clone()
                    support_out = learner(support_x)
                    support_loss = loss_fn(
                        support_out.view(-1, support_out.size(-1)),
                        support_y.view(-1)
                    )
                    learner.adapt(support_loss)

                    val_out = learner(query_x)
                    val_loss += loss_fn(
                        val_out.view(-1, val_out.size(-1)),
                        query_y.view(-1)
                    ).item()

            avg_val_loss = val_loss / max(len(val_loader), 1)
            print(f"Epoch {epoch + 1}: Pretrain Loss = {avg_train_loss:.4f}" if not training_flag else f"Epoch {epoch + 1}: Train Loss = {avg_train_loss:.4f}")

            # Adjust learning rate based on the average train loss
            scheduler.step(avg_train_loss)
    
    @accelerator
    def train_on_dataset(self, dataset_path, input_col, output_col, num_epochs, learning_rate, weight_decay, tokenizer, batch_size=4, system_prompt="My System Prompt", additional_prompt_engineering_parts="Memory: Example Memory\nTasks: Example task\netc.", user_label="User: ", response_label="AI: ", flag=True):
        template = system_prompt + "\n" + additional_prompt_engineering_parts + "\n" + user_label + "{0}\n" + response_label + "{1}"
        template = template if flag else "{0}"

        if self.model_type == 1:
            for sample in combine_csv_with_template(dataset_path, template, input_col, output_col, not flag):
                with open("./temp", "a", encoding="utf-8", errors="ignore") as file:
                    file.write(sample + "\n\n\n\n")
            
            self.pretrain_on_corpus("./temp", num_epochs, learning_rate, weight_decay, tokenizer, batch_size, response_label, True, not flag)
            
            if os.path.exists("./temp"):
                os.remove("./temp")
        else:
            # Regular dataset handling
            df = pd.read_csv(dataset_path)
            train_df, test_df = train_test_split(df, test_size=0.2, shuffle=False)

            train_set = TextDataset(train_df, input_col, output_col, tokenizer, self.max_seq_len)
            test_set = TextDataset(test_df, input_col, output_col, tokenizer, self.max_seq_len)

            train_loader = DataLoader(train_set, batch_size=batch_size, shuffle=True, drop_last=True)
            test_loader = DataLoader(test_set, batch_size=batch_size, shuffle=False, drop_last=False)

            optimizer = torch.optim.AdamW(self.parameters(), lr=learning_rate, weight_decay=weight_decay)
            scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.1, patience=10)
            loss_fn = nn.CrossEntropyLoss(ignore_index=-100)

            device = torch.device("cuda" if torch.cuda.is_available() and not cuda_kill_switch else "cpu")
            self.to(device)

            print(f"Train samples: {len(train_set)}, Batches: {len(train_loader)}")
            print(f"Test samples: {len(test_set)}, Batches: {len(test_loader)}")

            for epoch in range(num_epochs):
                torch.cuda.empty_cache()
                
                total_loss = 0
                self.train()
                pbar = tqdm(train_loader, desc=f"Epoch {epoch + 1}/{num_epochs} [Training]")

                for x, y in pbar:
                    x, y = x.to(device), y.to(device)

                    optimizer.zero_grad()
                    outputs = self(x)
                    loss = loss_fn(outputs.view(-1, outputs.size(-1)), y.reshape(-1))
                    loss.backward()
                    optimizer.step()

                    total_loss += loss.item()
                    pbar.set_postfix(loss=loss.item())

                avg_train_loss = total_loss / len(train_loader)

                # Small meta step using a cloned version of the model
                meta_model = l2l.algorithms.MetaSGD(self, learning_rate)
                for x, y in train_loader:
                    x, y = x.to(device), y.to(device)
                    # support_size = x.size(0) // 2
                    support_size = max(1, x.size(0) // 2)
                
                    if support_size > 1:
                        support_x, query_x = x[:support_size], x[support_size:]
                        support_y, query_y = y[:support_size], y[support_size:]
                    else:
                        support_x, query_x = x[:], x[:]
                        support_y, query_y = y[:], y[:]

                    learner = meta_model.clone()
                    support_out = learner(support_x)
                    support_loss = loss_fn(support_out.view(-1, support_out.size(-1)), support_y.reshape(-1))
                    
                    support_loss = support_loss + 0.0 * sum(
                        p.sum() for p in learner.parameters()
                    )
                    
                    learner.adapt(support_loss)
                    
                    query_out = learner(query_x)
                    _ = loss_fn(query_out.view(-1, query_out.size(-1)), query_y.reshape(-1)).item()  # just for meta insight

                # ---- Validation ----
                self.eval()
                val_loss = 0
                with torch.no_grad():
                    for x, y in test_loader:
                        x, y = x.to(device), y.to(device)
                        outputs = self(x)
                        val_loss += loss_fn(outputs.view(-1, outputs.size(-1)), y.reshape(-1)).item()

                avg_val_loss = val_loss / len(test_loader)
                print(f"Epoch {epoch+1}: Train Loss = {avg_train_loss:.4f}, Val Loss = {avg_val_loss:.4f}")

                scheduler.step(avg_train_loss)

    @general_accelerator
    def save_model(self, path):
        torch.save(self.state_dict(), path + ".adkm")
        print(f"Model saved to {path}")

    @general_accelerator
    def load_model(self, path):
        self.load_state_dict(torch.load(path))
        print(f"Model loaded from {path}")
    
    @accelerator
    def communicate(self, prompt, tokenizer, max_new_tokens=100, temperature=0.8, rep_penalty=1.5):
        """
        Generates text from a prompt. Handles DO, EO, and ED models correctly:
        - DO (Decoder-Only): autoregressive token-by-token generation
        - EO (Encoder-Only): returns model output directly (no autoregression)
        - ED (Encoder-Decoder): uses encoder for prompt, decoder autoregressive generation
        """
        self.eval()
        device = torch.device("cuda" if torch.cuda.is_available() and not cuda_kill_switch else "cpu")
        self.to(device)

        # Tokenize prompt and clamp to max sequence length
        input_ids = tokenizer.encode(prompt)
        input_ids = input_ids[-self.max_seq_len:]

        # EO: just encode and return (no autoregressive generation)
        if self.model_type == 0:  # Encoder-Only
            input_tensor = torch.tensor([input_ids], device=device)
            with torch.no_grad():
                logits = self.forward(input_tensor)
            predicted_ids = logits.argmax(dim=-1)[0].tolist()
            return tokenizer.decode(predicted_ids, skip_special_tokens=True)

        # DO: decoder-only, autoregressive
        elif self.model_type == 1:
            generated_ids = input_ids.copy()
            input_tensor = torch.tensor([input_ids], device=device)

            with torch.no_grad():
                for _ in range(max_new_tokens):
                    logits = self.forward(input_tensor)[:, -1, :]  # last token
                    logits[:, tokenizer.pad_token_id] = float('-inf')  # remove pad

                    # repetition penalty
                    for t in set(generated_ids):
                        logits[:, t] -= rep_penalty

                    # temperature sampling
                    logits = logits / temperature
                    probs = torch.softmax(logits, dim=-1)
                    next_token = torch.multinomial(probs, 1).item()
                    generated_ids.append(next_token)

                    # slide window
                    input_tensor = torch.tensor([generated_ids[-self.max_seq_len:]], device=device)

                    if next_token == tokenizer.eos_token_id:
                        break

            return tokenizer.decode(generated_ids, skip_special_tokens=True)

        # ED: encoder-decoder, encode once, decode autoregressively
        elif self.model_type == 2:
            encoder_input = torch.tensor([input_ids], device=device)
            generated_ids = []

            with torch.no_grad():
                # Encode
                encoder_input = torch.tensor([input_ids], device=device)  # [1, seq_len]
                encoder_embeds = self.token_embed(encoder_input)      # [1, seq_len, embed_dim]
                # encoder_embeds = encoder_embeds.transpose(0, 1)           # [seq_len, batch, embed_dim] for PyTorch MHA

                encoder_hidden = encoder_embeds
                
                for block in self.encoder:
                    encoder_hidden = block(encoder_hidden)
                
                # decoder_input = torch.tensor([[tokenizer.bos_token_id]], device=device)
                start_token = tokenizer.pad_token_id
                decoder_input = torch.tensor([[start_token]], device=device)

                for _ in range(max_new_tokens):
                    dec_out = self.token_embed(decoder_input)   # [1, seq, d_model]

                    for block in self.decoder:
                        dec_out = block(dec_out, encoder_hidden)

                    logits = self.head(self.ln_f(dec_out))[:, -1, :]
                    logits[:, tokenizer.pad_token_id] = -float("inf")

                    for t in set(generated_ids):
                        logits[:, t] -= rep_penalty

                    probs = torch.softmax(logits / temperature, dim=-1)
                    next_token = torch.multinomial(probs[0], 1).item()

                    generated_ids.append(next_token)

                    decoder_input = torch.tensor(
                        [[tokenizer.pad_token_id] + generated_ids],
                        device=device
                    )

                    if next_token == tokenizer.eos_token_id:
                        break
            
            return tokenizer.decode(generated_ids, skip_special_tokens=True)

@general_accelerator
def process_data(file_path, max_length, similarity_threshold):
    def yield_chunks(file_obj):
        buffer = ""
        for line in file_obj:
            buffer += line
            if "\n\n\n\n" in buffer:
                parts = buffer.split("\n\n\n\n")
                for part in parts[:-1]:
                    yield part.strip()
                buffer = parts[-1]  # carry over the remaining
        if buffer.strip():
            yield buffer.strip()  # last chunk

    with open(file_path, 'r', encoding='utf-8') as f:
        for i, chunk in enumerate(yield_chunks(f)):
            for i2, sequence in enumerate(chunk.split("\n")):
                generate_from_chunk(sequence, similarity_threshold, (i + 1) * (i2 + 1) == 1)

                if (i + 1) * (i2 + 1) >= max_length:
                    break

@general_accelerator
def generate_from_chunk(input_text, similarity_threshold, flag):
    qa_pairs = generate_qa_pairs(input_text, 50, similarity_threshold)
    qa_pairs = [[qa['question'], qa['answer']] for qa in qa_pairs]

    with open("./dataset.csv", "a", newline='', encoding='utf-8') as file:
        writer = csv.writer(file, quoting=csv.QUOTE_ALL)
        if flag:
            writer.writerow(["prompt", "completion"])
        writer.writerows(qa_pairs)


