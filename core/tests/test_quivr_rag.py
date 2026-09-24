# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m

from uuid import uuid4

import pytest
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.entities.models import ParsedRAGChunkResponse, RAGResponseMetadata
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


@pytest.fixture(scope="function")
def mock_chain_qa_stream(monkeypatch, chunks_stream_answer):
    class MockQAChain:
        async def astream_events(self, *args, **kwargs):
            default_metadata = {
                "langgraph_node": "generate",
                "is_final_node": False,
                "citations": None,
                "followup_questions": None,
                "sources": None,
                "metadata_model": None,
            }

            # Send all chunks except the last one
            for chunk in chunks_stream_answer[:-1]:
                yield {
                    "event": "on_chat_model_stream",
                    "metadata": default_metadata,
                    "data": {"chunk": chunk["answer"]},
                }

            # Send the last chunk
            yield {
                "event": "end",
                "metadata": {
                    "langgraph_node": "generate",
                    "is_final_node": True,
                    "citations": [],
                    "followup_questions": None,
                    "sources": [],
                    "metadata_model": None,
                },
                "data": {"chunk": chunks_stream_answer[-1]["answer"]},
            }

    def mock_qa_chain(*args, **kwargs):
        self = args[0]
        self.final_nodes = ["generate"]
        return MockQAChain()

    monkeypatch.setattr(QuivrQARAGLangGraph, "build_chain", mock_qa_chain)


@pytest.mark.base
@pytest.mark.asyncio
async def test_quivrqaraglanggraph(
    mem_vector_store, full_response, mock_chain_qa_stream, openai_api_key
):
    # Making sure the model
    llm_config = LLMEndpointConfig(model="gpt-4o")
    llm = LLMEndpoint.from_config(llm_config)
    retrieval_config = RetrievalConfig(llm_config=llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=mem_vector_store
    )

    stream_responses: list[ParsedRAGChunkResponse] = []

    # Making sure that we are calling the func_calling code path
    assert rag_pipeline.llm_endpoint.supports_func_calling()
    # LINEAJE: enforce() `chat_history` at agent->agent pre_agent_send — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.); AI_DAT_SEC_030 (Enforce minimum six-month log retention for high-risk AI systems); AI_AGENT_ACTIVITY_LOG (AI agent activity must be logged via OpenTelemetry.). Mask/block; do not remove without review. site_id='site:sha256:ec52f7ac9ed9e000efe4746ae00296a8b305de2bdbed976f710faf77748a16c9'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ec52f7ac9ed9e000efe4746ae00296a8b305de2bdbed976f710faf77748a16c9', phase='pre_agent_send', boundary={'source': 'agent_message', 'sink': 'agent_message'}, candidate_policies=[{'policy_id': 'AI_AGENT_ACTIVITY_LOG', 'guardrail_id': 'Emit Agent Activity via OpenTelemetry', 'policy_version': '2026.08.1'}], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='agent')
    try:
        chat_history = _gr_client.enforce(_gr_site, chat_history, content_type='application/json', variable_name='chat_history', source_file=__file__, before_line=72)
    except _gr_client.GuardrailUnavailableError:
        pass
    async for resp in rag_pipeline.answer_astream(
        "answer in bullet points. tell me something", chat_history, []
    ):
        stream_responses.append(resp)

    # This assertion passed
    assert all(
        not r.last_chunk for r in stream_responses[:-1]
    ), "Some chunks before last have last_chunk=True"
    assert stream_responses[-1].last_chunk

    # Let's check this assertion
    for idx, response in enumerate(stream_responses[1:-1]):
        assert (
            len(response.answer) > 0
        ), f"Sent an empty answer {response} at index {idx+1}"

    # Verify metadata
    default_metadata = RAGResponseMetadata().model_dump()
    assert all(
        r.metadata.model_dump() == default_metadata for r in stream_responses[:-1]
    )
    last_response = stream_responses[-1]
    # TODO(@aminediro) : test responses with sources
    assert last_response.metadata.sources == []
    assert last_response.metadata.citations == []

    # Assert whole response makes sense
    assert "".join([r.answer for r in stream_responses]) == full_response
