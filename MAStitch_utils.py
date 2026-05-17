import json
from dotenv import load_dotenv

load_dotenv()


def _chunk_token_count(chunk: list) -> int:
    """Sum Total Tokens from LLM-Call events within a chunk."""
    total = 0
    for entry in chunk:
        if isinstance(entry, dict) and entry.get("Event Name") == "LLM-Call":
            total += int(entry.get("Total Tokens") or 0)
    return total


def create_log_chunks(log_path) -> tuple[list, list[int]]:
    """Create chunks from Agent-Started to closest Agent-Finished.

    Returns:
        chunks: list of event lists per agent execution
        token_counts: per-chunk sum of Total Tokens from LLM-Call events
    """
    with open(log_path, 'r', encoding='utf-8-sig') as f:
        full_log = json.load(f)
    chunks = []
    token_counts = []
    for i, entry in enumerate(full_log):
        if isinstance(entry, dict) and entry.get("Event Name") == "Agent-Started":
            chunk = [entry]
            for j in range(i + 1, len(full_log)):
                chunk.append(full_log[j])
                if isinstance(full_log[j], dict) and full_log[j].get("Event Name") == "Agent-Finished":
                    break
            chunks.append(chunk)
            token_counts.append(_chunk_token_count(chunk))

    return chunks, token_counts
