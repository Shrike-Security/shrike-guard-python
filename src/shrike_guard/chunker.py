"""Client-side chunking for large scan inputs.

When a scan prompt exceeds ``AUTO_CHUNK_THRESHOLD``, the SDK splits it on
natural boundaries (paragraph → line → hard cut), scans each chunk
sequentially, and aggregates the results. Sequential fail-fast: the loop
stops as soon as any chunk returns a ``block`` verdict.

Why chunk client-side:
    1. Small chunks land in the backend cascade's "small content" band —
       early-exit triggers sooner, Vertex L7 costs drop.
    2. A 90KB monolithic L7 call is subject to "lost in the middle" —
       per-chunk calls give each region full attention.
    3. Bidirectional cost win: fewer tokens billed to the customer, fewer
       billed to us.

Known limit (post-launch fix): each chunk carries the same session ID, so
L9 turn count inflates by chunk-count. Fix is a backend ``chunk_group``
field that collapses N chunk-scans into one L9 turn.

Mirrors platform/sdks/typescript/src/chunker.ts — keep the two SDKs
aligned when either shape changes.
"""

from typing import Any, Dict, List

# Chunk anything larger than this. Below the threshold, keep single-shot.
AUTO_CHUNK_THRESHOLD = 20 * 1024

# Target size per chunk. Sized to land in the backend cascade's small-content band.
CHUNK_TARGET_SIZE = 8 * 1024

_ACTION_RANK = {
    "allow": 0,
    "warn": 1,
    "require_approval": 2,
    "block": 3,
}


def chunk_content(content: str, target_size: int = CHUNK_TARGET_SIZE) -> List[str]:
    """Split content on natural boundaries into chunks of ~``target_size``.

    Preference order: double-newline paragraphs → single newlines → hard cut.
    Never returns zero chunks — callers can rely on ``len(chunks) >= 1``.
    """
    if len(content) <= target_size:
        return [content]

    paragraphs = _split_paragraphs(content)
    chunks: List[str] = []
    current = ""

    def flush() -> None:
        nonlocal current
        if current:
            chunks.append(current)
            current = ""

    for paragraph in paragraphs:
        if len(paragraph) > target_size:
            flush()
            chunks.extend(_split_oversized_paragraph(paragraph, target_size))
            continue
        if len(current) + len(paragraph) + 2 > target_size:
            flush()
        current = f"{current}\n\n{paragraph}" if current else paragraph

    flush()
    return chunks if chunks else [content]


def _split_paragraphs(content: str) -> List[str]:
    """Split on runs of 2+ newlines. No regex import needed for the SDK."""
    parts: List[str] = []
    current = ""
    i = 0
    while i < len(content):
        if content[i] == "\n":
            j = i
            while j < len(content) and content[j] == "\n":
                j += 1
            if j - i >= 2:
                parts.append(current)
                current = ""
                i = j
                continue
        current += content[i]
        i += 1
    parts.append(current)
    return parts


def _split_oversized_paragraph(paragraph: str, target_size: int) -> List[str]:
    """A paragraph too big to fit gets split on newlines, then hard cut."""
    lines = paragraph.split("\n")
    out: List[str] = []
    current = ""

    for line in lines:
        if len(line) > target_size:
            if current:
                out.append(current)
                current = ""
            for i in range(0, len(line), target_size):
                out.append(line[i : i + target_size])
            continue
        if len(current) + len(line) + 1 > target_size:
            out.append(current)
            current = ""
        current = f"{current}\n{line}" if current else line

    if current:
        out.append(current)
    return out


def aggregate_chunk_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-chunk scan results into a single canonical response.

    Rules:
        - safe = all chunks safe
        - action / refuse_tier = worst action (block > require_approval > warn > allow)
        - threat_type + reason = from first non-safe chunk, tagged with chunk index
        - violations = concatenated + deduplicated by (threat_type, severity, action)
        - session_state / correlation_patterns = from the last chunk (freshest L9 state)
        - recovery = from first non-safe chunk

    Empty input list returns a safe verdict — caller should never pass it.
    """
    if not results:
        return {"safe": True, "action": "allow", "refuse_tier": "allow"}
    if len(results) == 1:
        return results[0]

    worst_action = "allow"
    first_unsafe_idx = -1
    all_safe = True
    seen: set = set()
    deduped_violations: List[Dict[str, Any]] = []

    for i, r in enumerate(results):
        if not r.get("safe", True):
            all_safe = False
            if first_unsafe_idx == -1:
                first_unsafe_idx = i
        action = r.get("action") or r.get("refuse_tier") or "allow"
        if _ACTION_RANK.get(action, 0) > _ACTION_RANK.get(worst_action, 0):
            worst_action = action
        for v in r.get("violations") or []:
            key = (v.get("threat_type", ""), v.get("severity", ""), v.get("action", ""))
            if key not in seen:
                seen.add(key)
                deduped_violations.append(v)

    first = results[first_unsafe_idx] if first_unsafe_idx >= 0 else results[0]
    last = results[-1]

    aggregated: Dict[str, Any] = {
        "safe": all_safe,
        "action": worst_action,
        "refuse_tier": worst_action,
        "violations": deduped_violations,
    }

    for optional_key in ("session_state", "correlation_patterns", "session_risk_score"):
        if optional_key in last:
            aggregated[optional_key] = last[optional_key]

    if not all_safe:
        aggregated["threat_type"] = first.get("threat_type")
        aggregated["severity"] = first.get("severity")
        chunk_label = f"[chunk {first_unsafe_idx + 1} of {len(results)}]"
        first_reason = first.get("reason")
        aggregated["reason"] = (
            f"{chunk_label} {first_reason}"
            if first_reason
            else f"Unsafe content detected in chunk {first_unsafe_idx + 1} of {len(results)}"
        )
        if first.get("recovery"):
            aggregated["recovery"] = first["recovery"]
        if first.get("approval_info"):
            aggregated["approval_info"] = first["approval_info"]

    return aggregated
