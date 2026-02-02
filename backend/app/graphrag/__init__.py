"""
GraphRAG module for AgentShield.

Implements a Graph Retrieval-Augmented Generation pipeline that converts
Neo4j session graphs into structured security analysis reports using LLM
providers (OpenAI, Anthropic).
"""

from __future__ import annotations

from app.graphrag.pipeline import GraphRAGPipeline

__all__: list[str] = [
    "GraphRAGPipeline",
]
