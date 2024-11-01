import os

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'default_fallback_key')
