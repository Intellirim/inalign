"""
In-A-Lign Proxy Server.

AI Security + Efficiency Proxy.
Intercepts requests, blocks attacks, optimizes prompts, routes to best model.

Usage:
    # Start server
    python -m inalign.proxy.server

    # Or via CLI
    inalign start

    # Client just changes base URL
    openai.api_base = "http://localhost:8080/v1"
"""

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Optional, Any
from datetime import datetime

import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from inalign.proxy.context_extractor import ContextExtractor

logger = logging.getLogger("inalign.proxy")

# LLM API endpoints
LLM_ENDPOINTS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "google": "https://generativelanguage.googleapis.com",
}

# Model routing map (from user's model to optimized model)
MODEL_ROUTING = {
    # For simple tasks, route to cheaper models
    "gpt-4o": {"simple": "gpt-4o-mini", "complex": "gpt-4o"},
    "gpt-4": {"simple": "gpt-4o-mini", "complex": "gpt-4o"},
    "claude-3-opus": {"simple": "claude-3-5-haiku-latest", "complex": "claude-3-5-sonnet-latest"},
    "claude-3-sonnet": {"simple": "claude-3-5-haiku-latest", "complex": "claude-3-5-sonnet-latest"},
}


def create_proxy_app(
    target: str = "openai",
    guard_config: Optional[dict] = None,
    enable_security: bool = True,
    enable_optimizer: bool = True,
    enable_cache: bool = True,
) -> FastAPI:
    """
    Create proxy FastAPI application.

    Parameters
    ----------
    target : str
        Target LLM API ("openai" or "anthropic")
    guard_config : dict, optional
        Configuration for Guard
    enable_security : bool
        Enable security checks (injection detection)
    enable_optimizer : bool
        Enable prompt optimization and model routing
    enable_cache : bool
        Enable response caching

    Returns
    -------
    FastAPI
        Configured proxy application
    """
    app = FastAPI(
        title="In-A-Lign Proxy",
        description="AI Security + Efficiency Proxy",
        version="0.1.0",
    )

    # CORS for web clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Initialize security detectors
    injection_detector = None
    pii_detector = None
    if enable_security:
        # Try full InjectionDetector first (ML-powered)
        try:
            from app.detectors.injection.detector import InjectionDetector
            injection_detector = InjectionDetector(
                use_embeddings=False,  # Keep fast for proxy
                use_llm=False,         # Don't add latency
                use_local_ml=True,     # Fast local ML
                use_graphrag=True,     # Use graph for accuracy + false positive reduction
                use_intent_classifier=True,  # Reduce false positives
                use_transformer=False, # Disabled - too sensitive for normal coding
            )
            logger.info("Security: Full InjectionDetector enabled (ML + Rules + Intent)")
        except ImportError as e:
            # Fallback to LiteDetector
            try:
                from inalign.lite_detector import LiteDetector
                injection_detector = LiteDetector()
                logger.info("Security: LiteDetector enabled (fallback)")
            except ImportError:
                logger.warning("Security: No detector available")

        # Initialize PII Detector for sensitive data masking
        try:
            from app.detectors.pii.detector import PIIDetector
            pii_detector = PIIDetector()
            logger.info("Security: PIIDetector enabled (PII masking)")
        except ImportError:
            logger.warning("Security: PIIDetector not available")

    # Alias for backward compatibility
    security_detector = injection_detector

    # Initialize optimizer
    optimizer = None
    task_analyzer = None
    if enable_optimizer:
        try:
            from app.optimizer import AIAdvisor, TaskAnalyzer, PromptOptimizer
            optimizer = PromptOptimizer()
            task_analyzer = TaskAnalyzer()
            logger.info("Optimizer enabled")
        except ImportError:
            logger.warning("Optimizer not available, running without optimization")

    # Initialize Context Extractor - "Parasite Mode"
    context_extractor = ContextExtractor(cache_ttl_minutes=120)
    logger.info("Context Extractor enabled (Parasite Mode)")

    # HTTP client for forwarding
    http_client = httpx.AsyncClient(timeout=120.0)

    # Response cache
    response_cache: dict[str, Any] = {}
    CACHE_TTL = 3600  # 1 hour

    # Stats
    stats = {
        "total_requests": 0,
        "blocked_requests": 0,
        "forwarded_requests": 0,
        "cached_responses": 0,
        "tokens_saved": 0,
        "cost_saved_usd": 0.0,
        "optimizations_applied": 0,
        "pii_masked": 0,
        "attacks_blocked": 0,
        "security_features": {
            "injection_detector": "full" if injection_detector and hasattr(injection_detector, '_rule_detector') else "lite" if injection_detector else "disabled",
            "pii_detector": "enabled" if pii_detector else "disabled",
            "context_extractor": "enabled",
        },
    }

    def get_cache_key(body: dict) -> str:
        """Generate cache key from request body."""
        cache_data = json.dumps(body, sort_keys=True)
        return hashlib.md5(cache_data.encode()).hexdigest()

    def analyze_complexity(messages: list) -> str:
        """Analyze if task is simple or complex."""
        total_chars = sum(len(str(m.get("content", ""))) for m in messages)

        # Simple heuristics
        if total_chars < 200:
            return "simple"
        if total_chars > 1000:
            return "complex"

        # Check for code-related keywords
        text = " ".join(str(m.get("content", "")) for m in messages).lower()
        complex_keywords = ["implement", "refactor", "debug", "architect", "design", "complex", "algorithm"]
        if any(kw in text for kw in complex_keywords):
            return "complex"

        return "simple"

    def optimize_prompt(text: str) -> tuple[str, int]:
        """Optimize prompt and return (optimized_text, tokens_saved)."""
        if not optimizer:
            return text, 0

        try:
            result = optimizer.optimize(text, aggressive=False)
            return result.optimized, result.tokens_saved
        except Exception as e:
            logger.warning(f"Optimization failed: {e}")
            return text, 0

    def route_model(original_model: str, complexity: str) -> str:
        """Route to optimal model based on complexity."""
        if original_model in MODEL_ROUTING:
            return MODEL_ROUTING[original_model].get(complexity, original_model)
        return original_model

    @app.get("/health")
    async def health():
        """Health check endpoint."""
        return {"status": "healthy", "stats": stats}

    @app.get("/stats")
    async def get_stats():
        """Get proxy statistics."""
        return stats

    @app.get("/context")
    async def get_context_stats():
        """Get context extraction statistics (Parasite Mode)."""
        return context_extractor.get_stats()

    @app.get("/context/{session_id}")
    async def get_session_context(session_id: str):
        """Get detailed context for a specific session."""
        return context_extractor.get_full_context_dump(session_id)

    @app.get("/context/hints/{session_id}")
    async def get_session_hints(session_id: str):
        """Get optimization hints for a session."""
        if session_id not in context_extractor._contexts:
            return {"error": "Session not found"}
        ctx = context_extractor._contexts[session_id]
        return context_extractor.get_optimization_hints(ctx)

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def proxy_openai(
        path: str,
        request: Request,
        authorization: Optional[str] = Header(None),
    ):
        """
        Proxy requests to OpenAI API.

        Features:
        - Security: Injection detection and blocking
        - Efficiency: Prompt optimization, model routing, caching
        """
        # Skip if this is an Anthropic messages request
        if path == "messages":
            return await proxy_anthropic(request)

        stats["total_requests"] += 1
        start_time = time.time()
        optimization_info = {"applied": [], "tokens_saved": 0, "model_routed": False}

        # Get request body
        body = await request.body()
        body_json = None

        if body:
            try:
                body_json = json.loads(body)
            except:
                pass

        # Process chat completions
        if body_json and path == "chat/completions":
            messages = body_json.get("messages", [])
            original_model = body_json.get("model", "gpt-4o")

            # === STEP 1: Security Check (Injection Detection) ===
            if injection_detector:
                for msg in messages:
                    content = msg.get("content", "")
                    if isinstance(content, str) and content:
                        detection = await injection_detector.detect(content)
                        risk_score = detection.get("risk_score", 0.0)

                        # Only block clear attacks (risk >= 0.9) and skip very short messages
                        is_short_message = len(content.strip()) < 20
                        if risk_score >= 0.9 and not is_short_message:
                            stats["blocked_requests"] += 1
                            stats["attacks_blocked"] += 1
                            logger.warning(
                                f"[BLOCKED] {content[:50]}... | "
                                f"risk={risk_score:.2f}"
                            )
                            return JSONResponse(
                                status_code=400,
                                content={
                                    "error": {
                                        "message": "Request blocked by In-A-Lign security",
                                        "type": "security_error",
                                        "code": "attack_detected",
                                        "details": {
                                            "risk_score": risk_score,
                                            "threat_level": detection.get("risk_level", "unknown"),
                                            "threats_found": len(detection.get("threats", [])),
                                            "suggestion": "Your request contains patterns similar to known attacks. Please rephrase.",
                                        },
                                    }
                                },
                            )
                        elif risk_score >= 0.5:
                            # Medium risk - log warning but allow
                            logger.info(f"[WARNING] Medium risk ({risk_score:.2f}), allowing: {content[:30]}...")

            # === STEP 1.5: PII Masking for OpenAI ===
            if pii_detector:
                masked_messages = []
                pii_masked = 0
                for msg in messages:
                    content = msg.get("content", "")
                    if isinstance(content, str) and content:
                        pii_result = await pii_detector.detect(content)
                        pii_entities = pii_result.get("pii_entities", [])
                        if pii_entities:
                            pii_masked += len(pii_entities)
                            masked_messages.append({**msg, "content": pii_result.get("sanitized_text", content)})
                        else:
                            masked_messages.append(msg)
                    else:
                        masked_messages.append(msg)
                if pii_masked > 0:
                    body_json["messages"] = masked_messages
                    stats["pii_masked"] += pii_masked
                    logger.info(f"[PII][OpenAI] Masked {pii_masked} sensitive items")

            # === STEP 2: Cache Check ===
            if enable_cache and not body_json.get("stream", False):
                cache_key = get_cache_key(body_json)
                if cache_key in response_cache:
                    cached = response_cache[cache_key]
                    if time.time() - cached["timestamp"] < CACHE_TTL:
                        stats["cached_responses"] += 1
                        logger.info(f"[CACHE HIT] Returning cached response")
                        return JSONResponse(
                            status_code=200,
                            content=cached["response"],
                            headers={
                                "X-InALign-Cache": "HIT",
                                "X-InALign-Latency-Ms": str(int((time.time() - start_time) * 1000)),
                            },
                        )

            # === STEP 3: Prompt Optimization ===
            if enable_optimizer and optimizer:
                total_saved = 0
                optimized_messages = []
                for msg in messages:
                    content = msg.get("content", "")
                    if isinstance(content, str) and len(content) > 50:
                        optimized_content, saved = optimize_prompt(content)
                        total_saved += saved
                        optimized_messages.append({**msg, "content": optimized_content})
                    else:
                        optimized_messages.append(msg)

                if total_saved > 0:
                    body_json["messages"] = optimized_messages
                    stats["tokens_saved"] += total_saved
                    stats["optimizations_applied"] += 1
                    optimization_info["applied"].append("prompt_optimization")
                    optimization_info["tokens_saved"] = total_saved
                    logger.info(f"[OPTIMIZED] Saved {total_saved} tokens")

            # === STEP 4: Model Routing ===
            if enable_optimizer:
                complexity = analyze_complexity(messages)
                routed_model = route_model(original_model, complexity)
                if routed_model != original_model:
                    body_json["model"] = routed_model
                    optimization_info["model_routed"] = True
                    optimization_info["applied"].append(f"model_route:{original_model}->{routed_model}")
                    logger.info(f"[ROUTED] {original_model} -> {routed_model} (task: {complexity})")

            # Update body with optimizations
            body = json.dumps(body_json).encode()

        # Forward to target API
        target_url = f"{LLM_ENDPOINTS[target]}/v1/{path}"

        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        # Use client's API key or server's
        if not authorization:
            env_key = os.getenv("OPENAI_API_KEY")
            if env_key:
                headers["Authorization"] = f"Bearer {env_key}"

        try:
            response = await http_client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=request.query_params,
            )

            stats["forwarded_requests"] += 1

            # Handle streaming responses
            if response.headers.get("content-type", "").startswith("text/event-stream"):
                async def stream_response():
                    async for chunk in response.aiter_bytes():
                        yield chunk

                return StreamingResponse(
                    stream_response(),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                )

            # Regular response - cache it
            response_data = response.json() if response.content else None

            if enable_cache and response.status_code == 200 and body_json:
                cache_key = get_cache_key(body_json)
                response_cache[cache_key] = {
                    "response": response_data,
                    "timestamp": time.time(),
                }

            return JSONResponse(
                status_code=response.status_code,
                content=response_data,
                headers={
                    "X-InALign-Latency-Ms": str(int((time.time() - start_time) * 1000)),
                    "X-InALign-Cache": "MISS",
                    "X-InALign-Optimizations": ",".join(optimization_info["applied"]) or "none",
                    "X-InALign-Tokens-Saved": str(optimization_info["tokens_saved"]),
                },
            )

        except httpx.RequestError as e:
            logger.error(f"Proxy error: {e}")
            raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    @app.api_route("/v1/messages", methods=["POST"])
    async def proxy_anthropic(
        request: Request,
        x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    ):
        """
        Proxy requests to Anthropic Claude API.
        """
        stats["total_requests"] += 1

        # Get API key from header if not provided (for internal calls)
        if x_api_key is None:
            x_api_key = request.headers.get("x-api-key")

        body = await request.body()
        body_json = None

        if body:
            try:
                import json
                body_json = json.loads(body)
            except:
                pass

        # === STEP 1: Security Check (Injection Detection) ===
        logger.info(f"[ANTHROPIC] body_json={bool(body_json)}, injection_detector={bool(injection_detector)}")
        if body_json and injection_detector:
            messages = body_json.get("messages", [])
            logger.info(f"[ANTHROPIC] Found {len(messages)} messages")
            for msg in messages:
                content = msg.get("content", "")
                # Handle content that might be a list (multimodal)
                if isinstance(content, list):
                    content = " ".join(
                        c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"
                    )
                logger.info(f"[ANTHROPIC] Checking content: {content[:50]}...")
                if isinstance(content, str) and content:
                    detection = await injection_detector.detect(content)
                    risk_score = detection.get("risk_score", 0.0)
                    # Only block CLEAR attacks (risk >= 0.9) and skip short messages
                    # Short greetings like "안녕" should never be blocked
                    is_short_message = len(content.strip()) < 20
                    if risk_score >= 0.9 and not is_short_message:
                        stats["blocked_requests"] += 1
                        stats["attacks_blocked"] += 1
                        # Record security incident in context
                        sec_api_key = x_api_key if isinstance(x_api_key, str) else request.headers.get("x-api-key")
                        sec_session_id = context_extractor.get_session_id(dict(request.headers), sec_api_key)
                        context_extractor.record_security_incident(
                            session_id=sec_session_id,
                            threat_type=detection.get("risk_level", "unknown"),
                            risk_score=risk_score,
                            blocked=True,
                            context=content[:100]
                        )
                        print(f"[SECURITY] Blocked attack! Session={sec_session_id[:16]}... Risk={risk_score}")
                        return JSONResponse(
                            status_code=400,
                            content={
                                "type": "error",
                                "error": {
                                    "type": "security_error",
                                    "message": "Request blocked by In-A-Lign security",
                                    "details": {
                                        "risk_score": risk_score,
                                        "threat_level": detection.get("risk_level", "unknown"),
                                        "suggestion": "Your request contains patterns similar to known attacks. Please rephrase your request.",
                                    },
                                },
                            },
                        )
                    elif risk_score >= 0.5:
                        # Medium risk - log but allow through
                        print(f"[SECURITY] Warning: medium risk detected ({risk_score:.2f}), allowing through")

        # === STEP 2: PII Detection and Masking ===
        pii_masked_count = 0
        if body_json and pii_detector:
            messages = body_json.get("messages", [])
            masked_messages = []
            for msg in messages:
                content = msg.get("content", "")
                # Handle multimodal content (list format from Claude Code)
                if isinstance(content, list):
                    masked_content = []
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text = item.get("text", "")
                            pii_result = await pii_detector.detect(text)
                            pii_entities = pii_result.get("pii_entities", [])
                            if pii_entities:
                                pii_masked_count += len(pii_entities)
                                masked_text = pii_result.get("sanitized_text", text)
                                masked_content.append({**item, "text": masked_text})
                                logger.info(f"[PII] Masked {len(pii_entities)} PII entities: {[e['type'] for e in pii_entities]}")
                            else:
                                masked_content.append(item)
                        else:
                            masked_content.append(item)
                    masked_messages.append({**msg, "content": masked_content})
                elif isinstance(content, str) and content:
                    pii_result = await pii_detector.detect(content)
                    pii_entities = pii_result.get("pii_entities", [])
                    if pii_entities:
                        pii_masked_count += len(pii_entities)
                        masked_text = pii_result.get("sanitized_text", content)
                        masked_messages.append({**msg, "content": masked_text})
                        logger.info(f"[PII] Masked {len(pii_entities)} PII entities: {[e['type'] for e in pii_entities]}")
                    else:
                        masked_messages.append(msg)
                else:
                    masked_messages.append(msg)

            if pii_masked_count > 0:
                body_json["messages"] = masked_messages
                stats["pii_masked"] += pii_masked_count
                logger.info(f"[PII] Total masked: {pii_masked_count} sensitive data items")

        # === Context Extraction - "Parasite Mode" ===
        api_key_str = x_api_key if isinstance(x_api_key, str) else request.headers.get("x-api-key")
        session_id = context_extractor.get_session_id(
            dict(request.headers),
            api_key_str
        )
        system_prompt = body_json.get("system", "") if body_json else ""
        messages = body_json.get("messages", []) if body_json else []

        # Extract ALL context from the request
        project_ctx = context_extractor.extract(
            messages=messages,
            system_prompt=system_prompt,
            session_id=session_id,
        )

        # Get optimization hints based on extracted context
        hints = context_extractor.get_optimization_hints(project_ctx)
        print(f"[PARASITE] Session={session_id[:16]}... Language={project_ctx.language}, Frameworks={project_ctx.frameworks[:3]}")
        print(f"[PARASITE] Task={hints['context_summary'].get('dominant_task')}, Complexity={project_ctx.code_complexity}")

        # === Optimization for Anthropic ===
        optimization_info = {"applied": [], "tokens_saved": 0, "model_routed": False, "context": hints["context_summary"]}
        print(f"[DEBUG] Optimization check: body_json={bool(body_json)}, enable_optimizer={enable_optimizer}, optimizer={bool(optimizer)}")

        if body_json and enable_optimizer:
            messages = body_json.get("messages", [])
            original_model = body_json.get("model", "claude-3-5-sonnet-latest")

            # Prompt optimization
            print(f"[DEBUG] optimizer={bool(optimizer)}, messages count={len(messages)}")
            if optimizer:
                total_saved = 0
                optimized_messages = []
                for msg in messages:
                    content = msg.get("content", "")
                    print(f"[DEBUG] Message role={msg.get('role')}, content type={type(content).__name__}, len={len(str(content))}")

                    # Handle multimodal content (list format from Claude Code)
                    if isinstance(content, list):
                        optimized_content = []
                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "text":
                                text = item.get("text", "")
                                if len(text) > 30:
                                    optimized_text, saved = optimize_prompt(text)
                                    total_saved += saved
                                    optimized_content.append({**item, "text": optimized_text})
                                    if saved > 0:
                                        print(f"[DEBUG] Optimized multimodal: saved {saved} tokens")
                                else:
                                    optimized_content.append(item)
                            else:
                                optimized_content.append(item)
                        optimized_messages.append({**msg, "content": optimized_content})
                    elif isinstance(content, str) and len(content) > 30:
                        optimized_content, saved = optimize_prompt(content)
                        total_saved += saved
                        optimized_messages.append({**msg, "content": optimized_content})
                        if saved > 0:
                            print(f"[DEBUG] Optimized string: saved {saved} tokens")
                    else:
                        optimized_messages.append(msg)

                if total_saved > 0:
                    body_json["messages"] = optimized_messages
                    stats["tokens_saved"] += total_saved
                    stats["optimizations_applied"] += 1
                    optimization_info["applied"].append("prompt_optimization")
                    optimization_info["tokens_saved"] = total_saved
                    # Record tokens saved in context
                    context_extractor.record_tokens_saved(session_id, total_saved)
                    logger.info(f"[ANTHROPIC][OPTIMIZED] Saved {total_saved} tokens")

            # Model routing for Anthropic
            complexity = analyze_complexity(messages)
            routed_model = route_model(original_model, complexity)
            if routed_model != original_model:
                body_json["model"] = routed_model
                optimization_info["model_routed"] = True
                optimization_info["applied"].append(f"model_route:{original_model}->{routed_model}")
                logger.info(f"[ANTHROPIC][ROUTED] {original_model} -> {routed_model} (task: {complexity})")

            # Record model usage in context
            context_extractor.record_model_used(session_id, routed_model or original_model)

            # Update body with optimizations
            body = json.dumps(body_json).encode()

        # Forward to Anthropic
        target_url = "https://api.anthropic.com/v1/messages"

        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)  # Will be recalculated

        if not x_api_key:
            env_key = os.getenv("ANTHROPIC_API_KEY")
            if env_key:
                headers["x-api-key"] = env_key

        try:
            # Check if streaming is requested
            is_streaming = body_json and body_json.get("stream", False)

            if is_streaming:
                # Handle streaming response
                async def stream_response():
                    async with http_client.stream(
                        "POST",
                        target_url,
                        headers=headers,
                        content=body,
                    ) as response:
                        stats["forwarded_requests"] += 1
                        async for chunk in response.aiter_bytes():
                            yield chunk

                return StreamingResponse(
                    stream_response(),
                    media_type="text/event-stream",
                )
            else:
                # Regular request
                response = await http_client.post(
                    target_url,
                    headers=headers,
                    content=body,
                )

                stats["forwarded_requests"] += 1

                # Parse response safely
                try:
                    response_data = response.json() if response.content else None
                except json.JSONDecodeError:
                    response_data = {"raw": response.text}

                return JSONResponse(
                    status_code=response.status_code,
                    content=response_data,
                )

        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Upstream error: {str(e)}")

    @app.on_event("shutdown")
    async def shutdown():
        await http_client.aclose()

    return app


# CLI entry point
def main():
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser(description="In-A-Lign AI Proxy")
    parser.add_argument("--port", type=int, default=int(os.getenv("INALIGN_PROXY_PORT", "8080")))
    parser.add_argument("--host", default=os.getenv("INALIGN_PROXY_HOST", "0.0.0.0"))
    parser.add_argument("--no-security", action="store_true", help="Disable security checks")
    parser.add_argument("--no-optimizer", action="store_true", help="Disable optimization")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    args = parser.parse_args()

    security_status = "OFF" if args.no_security else "ON"
    optimizer_status = "OFF" if args.no_optimizer else "ON"
    cache_status = "OFF" if args.no_cache else "ON"

    print(f"""
================================================================
              In-A-Lign AI Proxy
         Security + Efficiency in One
================================================================

  Status: RUNNING
  URL: http://localhost:{args.port}/v1

  Security Features:
    Injection Detector:    [{security_status}] (ML + Rules + Intent)
    PII Masking:           [{security_status}] (Korean + Global)
    Context Extractor:     [ON] (Parasite Mode)

  Efficiency Features:
    Prompt Optimizer:      [{optimizer_status}]
    Model Routing:         [{optimizer_status}]
    Response Cache:        [{cache_status}]

----------------------------------------------------------------
  Setup for Claude Code:
    ANTHROPIC_BASE_URL=http://localhost:{args.port}

  Setup for Cursor / OpenAI clients:
    OPENAI_BASE_URL=http://localhost:{args.port}/v1

  Endpoints:
    /v1/chat/completions  - OpenAI-compatible
    /v1/messages          - Anthropic Claude
    /health               - Health check
    /stats                - Usage statistics (incl. security)
    /context              - Context extraction stats
================================================================
    """)

    app = create_proxy_app(
        enable_security=not args.no_security,
        enable_optimizer=not args.no_optimizer,
        enable_cache=not args.no_cache,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
