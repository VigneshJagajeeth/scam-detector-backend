from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import re
import math

app = FastAPI()

class TextPayload(BaseModel):
    content: str
    source_type: str  # 'email', 'sms', 'chat'

# --- The Detection Logic ---

def calculate_perplexity(text):
    # In a real app, use GPT-2 or a small LLM to calc perplexity. 
    # AI text usually has LOWER perplexity (it's more predictable).
    # This is a mock function for the prototype.
    return len(set(text.split())) / len(text.split()) if text else 0

def detect_phishing_signals(text):
    score = 0
    flags = []
    
    # Keyword Analysis
    urgency_words = ['suspend', 'immediate', 'verify', '24 hours', 'unauthorized', 'lock']
    financial_words = ['credit card', 'bank', 'routing', 'social security', 'otp']
    
    for word in urgency_words:
        if word in text.lower():
            score += 10
            flags.append(f"Urgency detected: '{word}'")
            
    for word in financial_words:
        if word in text.lower():
            score += 15
            flags.append(f"Financial request: '{word}'")
            
    # Pattern Matching
    if re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text):
        score += 20
        flags.append("Contains URL (potential malicious link)")
        
    return score, flags

def detect_ai_syntax(text):
    # AI often writes in perfectly structured, slightly repetitive lists or overly polite robotic tones
    ai_score = 0
    signals = []
    
    if "kindly" in text.lower() and "immediately" in text.lower():
        ai_score += 20
        signals.append("Robotic phrasing detected")
        
    return ai_score, signals

@app.post("/analyze")
async def analyze_text(payload: TextPayload):
    text = payload.content
    
    phishing_score, phish_flags = detect_phishing_signals(text)
    ai_score, ai_flags = detect_ai_syntax(text)
    
    total_risk = phishing_score + ai_score
    
    verdict = "SAFE"
    if total_risk > 50:
        verdict = "HIGH RISK SCAM"
    elif total_risk > 20:
        verdict = "SUSPICIOUS"
        
    return {
        "verdict": verdict,
        "risk_score": total_risk,
        "analysis": {
            "phishing_signals": phish_flags,
            "ai_indicators": ai_flags
        },
        "recommendation": "Do not click links. Call your bank immediately." if total_risk > 20 else "Message appears safe."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
# This tells the app to look for your HTML file
@app.get("/")
def read_root():
    return FileResponse("index.html")
