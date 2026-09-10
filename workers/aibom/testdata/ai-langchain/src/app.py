"""A small RAG assistant — the shape of a real AI service."""
import os

from langchain_openai import ChatOpenAI
from langchain_community.vectorstores import Chroma
from transformers import AutoModelForCausalLM, AutoTokenizer
from sentence_transformers import SentenceTransformer

SYSTEM_PROMPT = """You are a helpful support assistant.
Answer only from the retrieved context. If unsure, say you do not know."""

llm = ChatOpenAI(model="gpt-4o", temperature=0.2, max_tokens=1024)

embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
store = Chroma(collection_name="support-docs", persist_directory="./chroma")

tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-3-8B")
local = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3-8B")


def answer(question: str) -> str:
    docs = store.similarity_search(question, k=4)
    context = "\n".join(d.page_content for d in docs)
    return llm.invoke(f"{SYSTEM_PROMPT}\n\nContext:\n{context}\n\nQ: {question}").content
