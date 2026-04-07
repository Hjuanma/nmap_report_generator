"""Environment loader placeholder."""
import os
from dotenv import load_dotenv

load_dotenv()

def get_nvd_api_key() -> str:
    return os.getenv('NVD_API_KEY', '')

def get_output_format() -> str:
    return os.getenv('OUTPUT_FORMAT', 'md')