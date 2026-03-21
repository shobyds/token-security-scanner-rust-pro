"""Minimal Gradio App for HF Spaces - Phi-3-mini-128k-instruct"""
import gradio as gr
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import os

MODEL_ID = "microsoft/Phi-3-mini-128k-instruct"
HF_TOKEN = os.environ.get("HF_TOKEN", "")

print("Loading Phi-3 model...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, token=HF_TOKEN if HF_TOKEN else None)
tokenizer.pad_token = tokenizer.eos_token

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    device_map="auto",
    torch_dtype=torch.float16,
    trust_remote_code=True,
    low_cpu_mem_usage=True,
    token=HF_TOKEN if HF_TOKEN else None
)

print("✅ Model loaded!")


def chat(message, history):
    """Simple chat function"""
    prompt = f"<|user|>\n{message}<|end|>\n<|assistant|>\n"
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=500,
            temperature=0.2,
            do_sample=True,
            pad_token_id=tokenizer.pad_token_id
        )
    
    text = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()
    return text


# Create and launch Gradio interface
demo = gr.ChatInterface(fn=chat, title="Phi-3 Mini Chat")

# This is critical for HF Spaces - must call launch with these exact parameters
demo.launch(server_name="0.0.0.0", server_port=7860, share=False)
