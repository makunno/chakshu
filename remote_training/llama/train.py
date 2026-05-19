#!/usr/bin/env python3
import os, json, argparse, torch
os.environ["CUDA_VISIBLE_DEVICES"] = "0,1,2,3"
from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments, DataCollatorForSeq2Seq, Trainer
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset

parse = argparse.ArgumentParser()
parse.add_argument("--resume_from_checkpoint", type=str, default=None)
cli_args = parse.parse_args()

MODEL_NAME = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
OUTPUT_DIR = "models/soc-analyst-deepseek"
TRAINING_DATA = "training_data_enhanced_v2.json"

LORA_CONFIG = LoraConfig(r=16, lora_alpha=32, target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"], lora_dropout=0.1, bias="none", task_type=TaskType.CAUSAL_LM)

print("=== DEEPSEEK R1 TRAINING ===")
print("GPUs:", torch.cuda.device_count())
print("Resume from:", cli_args.resume_from_checkpoint)

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

print("Loading data...")
with open(TRAINING_DATA) as f: data = json.load(f)
print("Data:", len(data))

formatted = []
for item in data:
    inst = item.get("instruction", "").strip()
    out = item.get("output", "").strip()
    if out:
        txt = "### Instruction: " + inst + "\n\n### Response: " + out + "<|end_of_turn|>"
        formatted.append({"text": txt})
print("Formatted:", len(formatted))
ds = Dataset.from_list(formatted)

def tk(examples):
    r = tokenizer(examples["text"], truncation=True, max_length=4096, padding="max_length")
    r["labels"] = r["input_ids"].copy()
    return r

ds = ds.map(tk, batched=True, remove_columns=["text"])
print("Tokenized:", len(ds))

print("Loading model...")
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, torch_dtype=torch.bfloat16, device_map="auto", trust_remote_code=True)

print("Applying LoRA...")
model = get_peft_model(model, LORA_CONFIG)
model.print_trainable_parameters()

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR, 
    num_train_epochs=2, 
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
    dataloader_num_workers=0
)

print("Training...")
trainer = Trainer(model=model, args=training_args, train_dataset=ds, data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt", padding=True))
trainer.train(resume_from_checkpoint=cli_args.resume_from_checkpoint)

print("Saving...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print("DONE!")
