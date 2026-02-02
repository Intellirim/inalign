"""
Pattern analysis prompt template.

Instructs the LLM to explain *why* a session matches known attack patterns
and how it compares to historical attacks recorded in the graph database.

Placeholders
------------
- ``{session_sequence}``   -- the action sequence of the current session.
- ``{matched_patterns}``   -- JSON list of matched pattern objects.
- ``{historical_attacks}`` -- summary of historically similar attack sessions.
"""

from __future__ import annotations

PATTERN_ANALYSIS_PROMPT: str = """\
You are an expert in AI agent security and behavioural analysis.

A security monitoring system has flagged a session whose action sequence
matches one or more known attack signatures. Your task is to analyse the
match and provide a detailed explanation.

=== Current Session Action Sequence ===
{session_sequence}

=== Matched Attack Patterns ===
{matched_patterns}

=== Historical Similar Attacks ===
{historical_attacks}

=== Instructions ===

1. **Match Explanation**
   For each matched pattern, explain:
   - Why the session's action sequence matches the pattern.
   - Which specific actions or sub-sequences contribute most to the match.
   - Whether the match is likely a true positive or a false positive, and why.

2. **Historical Comparison**
   - Compare the current session with the provided historical attacks.
   - Highlight similarities and differences in action ordering, timing, and
     targeted resources.
   - Estimate whether the current session is an evolution or repetition of a
     previously seen attack.

3. **Risk Assessment**
   - Provide an overall risk assessment considering pattern confidence and
     historical context.
   - Rate the risk as "critical", "high", "medium", or "low".

4. **Recommended Actions**
   - Suggest concrete steps the security team should take based on the
     pattern analysis.

=== Output Format ===

Respond ONLY with the JSON below. No additional text.

```json
{{
  "pattern_matches": [
    {{
      "pattern_name": "name",
      "confidence": 0.0,
      "explanation": "detailed explanation of why the session matches",
      "key_actions": ["action_id_1", "action_id_2"],
      "false_positive_likelihood": "low | medium | high"
    }}
  ],
  "historical_comparison": {{
    "most_similar_session_id": "session_id or null",
    "similarity_score": 0.0,
    "key_differences": ["difference 1", "difference 2"],
    "evolution_assessment": "description of whether this is new, repeated, or evolved"
  }},
  "risk_assessment": {{
    "level": "critical | high | medium | low",
    "reasoning": "explanation"
  }},
  "recommended_actions": [
    "action 1",
    "action 2"
  ]
}}
```
"""
