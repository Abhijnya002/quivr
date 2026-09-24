"""Quivr chatbot (Chainlit) wired to a local Ollama LLM + local FastEmbed embeddings.

Ollama exposes an OpenAI-compatible API at http://localhost:11434/v1, so we point
quivr's OpenAI-style LLM endpoint there. Embeddings stay local via FastEmbed.
Uploaded text is fed as a LangChain Document to bypass the MegaParse .txt processor.

Prereqs: `ollama serve` running and `ollama pull llama3.2` done.
Override the model with OLLAMA_MODEL.
"""
import os
from uuid import uuid4

import chainlit as cl
from langchain_core.documents import Document
from langchain_community.embeddings import FastEmbedEmbeddings

from quivr_core import Brain
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.config import LLMEndpointConfig, DefaultModelSuppliers

MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")

_llm = LLMEndpoint.from_config(
    LLMEndpointConfig(
        supplier=DefaultModelSuppliers.OPENAI,  # Ollama speaks the OpenAI API
        model=MODEL,
        llm_base_url=BASE_URL,
        llm_api_key="ollama",  # any non-empty string; Ollama ignores it
    )
)
_embedder = FastEmbedEmbeddings()


@cl.on_chat_start
async def on_chat_start():
    files = None
    while files is None:
        files = await cl.AskFileMessage(
            content=f"Upload a .txt file to begin (LLM: {MODEL} via Ollama).",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()

    file = files[0]
    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()

    docs = [Document(
        page_content=text,
        metadata={"index": 0, "original_file_name": file.name},
    )]
    brain = await Brain.afrom_langchain_documents(
        name="user_brain", langchain_documents=docs, llm=_llm, embedder=_embedder
    )
    cl.user_session.set("brain", brain)

    msg.content = f"Processing `{file.name}` done. Ask away!"
    await msg.update()


@cl.on_message
async def main(message: cl.Message):
    brain = cl.user_session.get("brain")
    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    msg = cl.Message(content="")
    await msg.send()
    async for chunk in brain.ask_streaming(message.content, run_id=uuid4()):
        await msg.stream_token(chunk.answer)
    await msg.update()
