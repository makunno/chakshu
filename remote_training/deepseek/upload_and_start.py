#!/usr/bin/env python3
"""Upload and start DeepSeek-R1-14B training"""
import paramiko
import base64

HOST = "login.npsf.cdac.in"
USER = "isea13"
PASSWORD = "eXYV_mnJ"

script = """#!/usr/bin/env python3
import os, json, argparse, torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, DataCollatorForSeq2Seq, Trainer
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset
import numpy as np

MODEL_NAME = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
OUTPUT_DIR = "models/soc-analyst-deepseek"
TRAINING_DATA = "training_data_enhanced_v2.json"

LORA_CONFIG = LoraConfig(
    r=16, 
    lora_alpha=32, 
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"], 
    lora_dropout=0.1, 
    bias="none", 
    task_type=TaskType.CAUSAL_LM
)

def get_training_args(epochs=2, max_steps=-1):
    args = TrainingArguments(
        output_dir=OUTPUT_DIR, 
        num_train_epochs=epochs, 
        per_device_train_batch_size=1, 
        gradient_accumulation_steps=4, 
        optim="adamw_torch", 
        learning_rate=2e-4, 
        weight_decay=0.01, 
        warmup_steps=30, 
        logging_steps=10, 
        save_steps=50, 
        save_total_limit=3, 
        max_grad_norm=1.0, 
        lr_scheduler_type="cosine", 
        report_to="none", 
        remove_unused_columns=False, 
        fp16=False, 
        bf16=True, 
        gradient_checkpointing=True, 
        dataloader_num_workers=8,
        local_rank=-1
    )
    if max_steps > 0: args.max_steps = max_steps
    return args

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--max_steps", type=int, default=-1)
    args = parser.parse_args()
    
    print("=== DEEPSEEK R1 TRAINING - 8 GPUs ===")
    
    if not torch.cuda.is_available(): 
        print("No GPU") 
        return
    print("GPUs available: " + str(torch.cuda.device_count()))
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    print("Loading data...")
    with open(TRAINING_DATA, "r") as f: data = json.load(f)
    print("Data: " + str(len(data)) + " examples")
    
    formatted = []
    for item in data:
        inst = item.get("instruction", "").strip()
        out = item.get("output", "").strip()
        if not out: continue
        txt = "### Instruction: " + inst + "\\n\\n### Response: " + out + "<|end_of_turn|>"
        formatted.append({"text": txt})
    
    print("Formatted: " + str(len(formatted)))
    ds = Dataset.from_list(formatted)
    
    def tk(examples):
        r = tokenizer(examples["text"], truncation=True, max_length=4096, padding="max_length")
        r["labels"] = r["input_ids"].copy()
        return r
    
    ds = ds.map(tk, batched=True, remove_columns=["text"])
    print("Tokenized: " + str(len(ds)))
    
    print("Loading model...")
    model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, torch_dtype=torch.bfloat16, device_map="auto", trust_remote_code=True)
    
    print("Applying LoRA...")
    model = get_peft_model(model, LORA_CONFIG)
    model.print_trainable_parameters()
    
    print("Training with all 8 GPUs...")
    trainer = Trainer(model=model, args=get_training_args(args.epochs, args.max_steps), train_dataset=ds, data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt", padding=True))
    trainer.train()
    
    print("Saving...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    print("DONE!")

if __name__ == "__main__": main()
"""

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, username=USER, password=PASSWORD)

import time
client.exec_command("pkill -f train.py")
time.sleep(2)

print("Creating deepseek_training directory...")
client.exec_command("mkdir -p deepseek_training")

encoded = base64.b64encode(script.encode('utf-8')).decode('utf-8')
client.exec_command("echo '" + encoded + "' | base64 -d > deepseek_training/train.py")

print("Verifying script...")
stdin, stdout, stderr = client.exec_command("python3 -m py_compile deepseek_training/train.py && echo OK")
result = stdout.read().decode()
print("Compile:", result)

if "OK" in result:
    print("Starting DeepSeek training with 8 GPUs...")
    cmd = "cd deepseek_training && CUDA_VISIBLE_DEVICES=0,1,2,3,4,5,6,7 nohup /nlsasfs/home/isea/isea13/soc_training/venv/bin/python train.py --epochs 2 > training.log 2>&1 &"
    client.exec_command(cmd)
    print("DeepSeek training started!")
else:
    print("Script compilation failed!")
    print("Error:", stderr.read().decode())

client.close()
print("Done!")
