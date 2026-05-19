#!/usr/bin/env python3
"""
DeepSeek R1 Inference Server
Run on GPU server with: python inference_server.py
"""
import os
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import json

os.environ["CUDA_VISIBLE_DEVICES"] = "4,5"  # Use GPUs 4 and 5

MODEL_NAME = "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"

app = FastAPI(title="DeepSeek SOC Analyst API")

class Query(BaseModel):
    prompt: str
    max_length: int = 512
    temperature: float = 0.7

print("Loading DeepSeek model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    torch_dtype=torch.bfloat16,
    device_map="auto",
    trust_remote_code=True
)
model.eval()

print(f"Model loaded on {torch.cuda.device_count()} GPUs")

@app.post("/generate")
async def generate(query: Query):
    try:
        inputs = tokenizer(query.prompt, return_tensors="pt", padding=True).to(model.device)
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_length=query.max_length,
                temperature=query.temperature,
                do_sample=True,
                pad_token_id=tokenizer.pad_token_id
            )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        return {"response": response}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok", "gpus": torch.cuda.device_count()}

if __name__ == "__main__":
    print("Starting DeepSeek inference server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
