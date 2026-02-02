"""
Pattern matching for session action sequences.

Uses sentence-transformer embeddings (when available) to find sessions or
attack signatures whose action sequences are semantically similar to a
given session.  Falls back to basic token-overlap similarity when the
``sentence-transformers`` package is not installed.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
from numpy.typing import NDArray

logger = logging.getLogger("agentshield.graphrag.pattern_matcher")

# Optional dependency -- gracefully degrade.
try:
    from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

    _HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    _HAS_SENTENCE_TRANSFORMERS = False
    logger.info(
        "sentence-transformers is not installed. "
        "PatternMatcher will use token-overlap similarity as fallback."
    )


class PatternMatcher:
    """
    Compare action sequences using cosine similarity over embeddings.

    Parameters
    ----------
    model_name:
        Hugging Face model ID for ``SentenceTransformer``.  Ignored when
        the library is unavailable.
    load_model:
        If ``True`` (default) and the library is available, load the model
        eagerly on construction.  Set to ``False`` to defer loading.
    """

    DEFAULT_MODEL: str = "all-MiniLM-L6-v2"

    def __init__(
        self,
        model_name: str | None = None,
        load_model: bool = True,
    ) -> None:
        self._model_name: str = model_name or self.DEFAULT_MODEL
        self._model: Any = None  # SentenceTransformer | None

        if _HAS_SENTENCE_TRANSFORMERS and load_model:
            self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_similar_sessions(
        self,
        current_sequence: str,
        stored_sequences: list[dict[str, Any]],
        min_score: float = 0.5,
    ) -> list[dict[str, Any]]:
        """
        Rank stored sessions by similarity to *current_sequence*.

        Parameters
        ----------
        current_sequence:
            The action-type sequence string for the session under analysis
            (e.g. ``"tool_call -> llm_call -> db_query"``).
        stored_sequences:
            List of dicts, each with at least ``session_id`` and ``sequence``
            string keys.
        min_score:
            Minimum similarity score to include in results.

        Returns
        -------
        list[dict]
            Sorted list of ``{"session_id": ..., "score": ...}`` dicts,
            highest score first.
        """
        if not current_sequence or not stored_sequences:
            return []

        current_embedding: NDArray[np.floating[Any]] = self._encode(current_sequence)

        results: list[dict[str, Any]] = []
        for item in stored_sequences:
            stored_seq: str = item.get("sequence", "")
            if not stored_seq:
                continue
            stored_embedding: NDArray[np.floating[Any]] = self._encode(stored_seq)
            score: float = float(self._cosine_similarity(current_embedding, stored_embedding))
            if score >= min_score:
                results.append(
                    {
                        "session_id": item.get("session_id", ""),
                        "score": round(score, 4),
                    }
                )

        results.sort(key=lambda r: r["score"], reverse=True)
        logger.debug(
            "find_similar_sessions: %d results (min_score=%.2f)",
            len(results),
            min_score,
        )
        return results

    def find_matching_signatures(
        self,
        action_sequence: str,
        signatures: list[dict[str, Any]],
        min_score: float = 0.5,
    ) -> list[dict[str, Any]]:
        """
        Match an action sequence against known attack signatures.

        Parameters
        ----------
        action_sequence:
            The session's action-type sequence string.
        signatures:
            List of dicts with at least ``signature_id``, ``name``, and
            ``pattern`` keys.
        min_score:
            Minimum similarity score to include in results.

        Returns
        -------
        list[dict]
            Sorted list of ``{"signature_id": ..., "name": ..., "score": ...}``
            dicts, highest score first.
        """
        if not action_sequence or not signatures:
            return []

        seq_embedding: NDArray[np.floating[Any]] = self._encode(action_sequence)

        results: list[dict[str, Any]] = []
        for sig in signatures:
            pattern: str = sig.get("pattern", "")
            if not pattern:
                continue
            sig_embedding: NDArray[np.floating[Any]] = self._encode(pattern)
            score: float = float(self._cosine_similarity(seq_embedding, sig_embedding))
            if score >= min_score:
                results.append(
                    {
                        "signature_id": sig.get("signature_id", ""),
                        "name": sig.get("name", ""),
                        "score": round(score, 4),
                    }
                )

        results.sort(key=lambda r: r["score"], reverse=True)
        logger.debug(
            "find_matching_signatures: %d matches (min_score=%.2f)",
            len(results),
            min_score,
        )
        return results

    # ------------------------------------------------------------------
    # Encoding & similarity
    # ------------------------------------------------------------------

    def _encode(self, text: str) -> NDArray[np.floating[Any]]:
        """
        Encode *text* into a dense vector.

        Uses the loaded SentenceTransformer model if available; otherwise
        falls back to a simple token-frequency vector.

        Returns
        -------
        numpy.ndarray
            1-D float array representing the text embedding.
        """
        if self._model is not None:
            embedding: NDArray[np.floating[Any]] = self._model.encode(
                text, convert_to_numpy=True, show_progress_bar=False
            )
            return embedding.flatten()

        # Fallback: bag-of-words frequency vector (deterministic ordering).
        return self._token_frequency_vector(text)

    @staticmethod
    def _cosine_similarity(
        a: NDArray[np.floating[Any]],
        b: NDArray[np.floating[Any]],
    ) -> float:
        """
        Compute the cosine similarity between two vectors.

        Returns 0.0 when either vector has zero magnitude.
        """
        norm_a: float = float(np.linalg.norm(a))
        norm_b: float = float(np.linalg.norm(b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load the SentenceTransformer model."""
        try:
            logger.info("Loading SentenceTransformer model: %s", self._model_name)
            self._model = SentenceTransformer(self._model_name)
            logger.info("SentenceTransformer model loaded successfully.")
        except Exception:
            logger.exception(
                "Failed to load SentenceTransformer model '%s'. "
                "Falling back to token-overlap similarity.",
                self._model_name,
            )
            self._model = None

    @staticmethod
    def _token_frequency_vector(text: str) -> NDArray[np.floating[Any]]:
        """
        Build a simple token-frequency vector as a fallback embedding.

        Tokens are produced by splitting on whitespace and punctuation-like
        delimiters (``->``, commas).  The resulting vocabulary is sorted
        alphabetically so that the vector dimensions are deterministic for
        any pair of texts compared within a single process lifetime.
        """
        normalized: str = text.lower().replace("->", " ").replace(",", " ")
        tokens: list[str] = normalized.split()

        # Build vocabulary from these tokens.
        vocab: dict[str, int] = {}
        for token in tokens:
            token = token.strip()
            if token:
                vocab[token] = vocab.get(token, 0) + 1

        if not vocab:
            return np.zeros(1, dtype=np.float64)

        sorted_keys: list[str] = sorted(vocab.keys())
        vector: NDArray[np.floating[Any]] = np.array(
            [float(vocab[k]) for k in sorted_keys],
            dtype=np.float64,
        )
        return vector
