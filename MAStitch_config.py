import os
from dotenv import load_dotenv

load_dotenv()

# API Keys and Environment Variables
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SERPER_API_KEY = os.environ.get("SERPER_API_KEY")

# Model Configuration
LLM_MODEL = os.environ.get("MODEL")
MODEL_LAA = LLM_MODEL
MODEL_GAA = LLM_MODEL

# ===== Global Monitoring Settings (tunable) =====
VALIDITY_ALERT_THRESHOLD: float = 75.0
CONFIDENCE_ALERT_THRESHOLD: float = 70.0
ESCALATING_RISK_SCORE: float = 45.0
