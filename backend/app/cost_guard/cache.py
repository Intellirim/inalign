"""
Response Cache - Caches LLM responses to avoid redundant API calls.

Features:
- Hash-based exact matching
- Semantic similarity matching (optional)
- TTL-based expiration
- Cache warming for common queries
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from collections import OrderedDict

logger = logging.getLogger("inalign.cost_guard.cache")


@dataclass
class CacheEntry:
    """Single cache entry."""
    key: str
    prompt_hash: str
    model: str
    response: str
    tokens_saved: int
    created_at: float
    expires_at: float
    hits: int = 0
    last_hit: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class CacheLookupResult:
    """Result of a cache lookup."""
    hit: bool
    response: Optional[str] = None
    tokens_saved: int = 0
    cache_key: Optional[str] = None
    age_seconds: float = 0.0


class ResponseCache:
    """
    LRU cache for LLM responses with TTL expiration.

    Features:
    - Exact hash matching on (system_prompt + user_message + model)
    - LRU eviction when capacity reached
    - TTL-based expiration
    - Statistics tracking
    """

    def __init__(
        self,
        max_entries: int = 10000,
        default_ttl_seconds: int = 3600,  # 1 hour
        enable_semantic: bool = False,
        semantic_threshold: float = 0.95,
    ):
        """
        Initialize the cache.

        Parameters
        ----------
        max_entries : int
            Maximum number of cache entries.
        default_ttl_seconds : int
            Default TTL for cache entries.
        enable_semantic : bool
            Enable semantic similarity matching (requires embeddings).
        semantic_threshold : float
            Minimum similarity score for semantic cache hits.
        """
        self.max_entries = max_entries
        self.default_ttl_seconds = default_ttl_seconds
        self.enable_semantic = enable_semantic
        self.semantic_threshold = semantic_threshold

        # LRU cache storage
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

        # Statistics
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expirations": 0,
            "tokens_saved": 0,
        }

        # Semantic embeddings cache (if enabled)
        self._embeddings: dict[str, list[float]] = {}
        self._embedder = None

        if enable_semantic:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("Semantic cache enabled with all-MiniLM-L6-v2")
            except ImportError:
                logger.warning("sentence-transformers not available, semantic cache disabled")
                self.enable_semantic = False

        logger.info(
            f"ResponseCache initialized (max={max_entries}, ttl={default_ttl_seconds}s, "
            f"semantic={enable_semantic})"
        )

    def _compute_hash(
        self,
        system_prompt: str,
        user_message: str,
        model: str,
    ) -> str:
        """Compute cache key hash."""
        content = f"{model}||{system_prompt}||{user_message}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _compute_embedding(self, text: str) -> Optional[list[float]]:
        """Compute text embedding for semantic matching."""
        if not self._embedder:
            return None
        try:
            return self._embedder.encode(text).tolist()
        except Exception as e:
            logger.warning(f"Embedding computation failed: {e}")
            return None

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        import math
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def get(
        self,
        system_prompt: str,
        user_message: str,
        model: str,
    ) -> CacheLookupResult:
        """
        Look up a cached response.

        Returns CacheLookupResult with hit=True if found.
        """
        cache_key = self._compute_hash(system_prompt, user_message, model)

        with self._lock:
            # Exact match lookup
            entry = self._cache.get(cache_key)

            if entry:
                if entry.is_expired():
                    # Expired - remove and return miss
                    self._cache.pop(cache_key, None)
                    self._stats["expirations"] += 1
                    self._stats["misses"] += 1
                    return CacheLookupResult(hit=False)

                # Cache hit!
                entry.hits += 1
                entry.last_hit = time.time()

                # Move to end (most recently used)
                self._cache.move_to_end(cache_key)

                self._stats["hits"] += 1
                self._stats["tokens_saved"] += entry.tokens_saved

                logger.debug(f"Cache HIT: {cache_key[:8]}... (hits={entry.hits})")

                return CacheLookupResult(
                    hit=True,
                    response=entry.response,
                    tokens_saved=entry.tokens_saved,
                    cache_key=cache_key,
                    age_seconds=time.time() - entry.created_at,
                )

            # Semantic similarity search (if enabled)
            if self.enable_semantic and self._embedder:
                query_embedding = self._compute_embedding(user_message)
                if query_embedding:
                    best_match = None
                    best_score = 0.0

                    for key, cached_entry in self._cache.items():
                        if cached_entry.is_expired():
                            continue
                        if cached_entry.model != model:
                            continue

                        cached_embedding = self._embeddings.get(key)
                        if cached_embedding:
                            score = self._cosine_similarity(query_embedding, cached_embedding)
                            if score > best_score and score >= self.semantic_threshold:
                                best_score = score
                                best_match = cached_entry

                    if best_match:
                        best_match.hits += 1
                        best_match.last_hit = time.time()
                        self._stats["hits"] += 1
                        self._stats["tokens_saved"] += best_match.tokens_saved

                        logger.debug(
                            f"Semantic cache HIT: similarity={best_score:.3f}"
                        )

                        return CacheLookupResult(
                            hit=True,
                            response=best_match.response,
                            tokens_saved=best_match.tokens_saved,
                            cache_key=best_match.key,
                            age_seconds=time.time() - best_match.created_at,
                        )

            self._stats["misses"] += 1
            return CacheLookupResult(hit=False)

    def set(
        self,
        system_prompt: str,
        user_message: str,
        model: str,
        response: str,
        tokens_used: int,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Cache a response.

        Returns the cache key.
        """
        cache_key = self._compute_hash(system_prompt, user_message, model)
        ttl = ttl_seconds or self.default_ttl_seconds
        now = time.time()

        entry = CacheEntry(
            key=cache_key,
            prompt_hash=cache_key,
            model=model,
            response=response,
            tokens_saved=tokens_used,
            created_at=now,
            expires_at=now + ttl,
            metadata=metadata or {},
        )

        with self._lock:
            # Evict oldest entries if at capacity
            while len(self._cache) >= self.max_entries:
                oldest_key = next(iter(self._cache))
                self._cache.pop(oldest_key)
                self._embeddings.pop(oldest_key, None)
                self._stats["evictions"] += 1

            self._cache[cache_key] = entry

            # Store embedding for semantic matching
            if self.enable_semantic and self._embedder:
                embedding = self._compute_embedding(user_message)
                if embedding:
                    self._embeddings[cache_key] = embedding

        logger.debug(f"Cached response: {cache_key[:8]}... (ttl={ttl}s)")
        return cache_key

    def invalidate(self, cache_key: str) -> bool:
        """Invalidate a specific cache entry."""
        with self._lock:
            if cache_key in self._cache:
                self._cache.pop(cache_key)
                self._embeddings.pop(cache_key, None)
                return True
        return False

    def invalidate_by_model(self, model: str) -> int:
        """Invalidate all cache entries for a specific model."""
        count = 0
        with self._lock:
            keys_to_remove = [
                k for k, v in self._cache.items() if v.model == model
            ]
            for key in keys_to_remove:
                self._cache.pop(key)
                self._embeddings.pop(key, None)
                count += 1
        logger.info(f"Invalidated {count} cache entries for model {model}")
        return count

    def clear(self) -> int:
        """Clear all cache entries. Returns count of cleared entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._embeddings.clear()
        logger.info(f"Cache cleared: {count} entries removed")
        return count

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        count = 0
        with self._lock:
            keys_to_remove = [
                k for k, v in self._cache.items() if v.is_expired()
            ]
            for key in keys_to_remove:
                self._cache.pop(key)
                self._embeddings.pop(key, None)
                count += 1
                self._stats["expirations"] += 1

        if count > 0:
            logger.debug(f"Cleaned up {count} expired cache entries")
        return count

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_rate = self._stats["hits"] / max(total_requests, 1)

            return {
                "entries": len(self._cache),
                "max_entries": self.max_entries,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "hit_rate": round(hit_rate, 4),
                "evictions": self._stats["evictions"],
                "expirations": self._stats["expirations"],
                "tokens_saved": self._stats["tokens_saved"],
                "semantic_enabled": self.enable_semantic,
            }

    def warm_cache(
        self,
        common_queries: list[dict[str, str]],
        model: str,
        response_generator: callable,
    ) -> int:
        """
        Warm cache with common queries.

        Parameters
        ----------
        common_queries : list
            List of {"system_prompt": str, "user_message": str} dicts.
        model : str
            Model to use for generating responses.
        response_generator : callable
            Async function to generate responses.

        Returns count of cached entries.
        """
        cached = 0
        for query in common_queries:
            system_prompt = query.get("system_prompt", "")
            user_message = query.get("user_message", "")

            # Check if already cached
            result = self.get(system_prompt, user_message, model)
            if result.hit:
                continue

            # Generate and cache response
            try:
                response, tokens = response_generator(system_prompt, user_message, model)
                self.set(
                    system_prompt=system_prompt,
                    user_message=user_message,
                    model=model,
                    response=response,
                    tokens_used=tokens,
                    metadata={"warmed": True},
                )
                cached += 1
            except Exception as e:
                logger.warning(f"Cache warming failed: {e}")

        logger.info(f"Cache warming complete: {cached} entries added")
        return cached
