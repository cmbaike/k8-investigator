from openai import OpenAI


VLLM_MODEL = "Qwen/Qwen3-4B"

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="not-used",
)