import json
from dotenv import load_dotenv

load_dotenv()


def create_log_chunks(log_path) -> tuple:
    """Create chunks from Agent-Started to closest Agent-Finished"""
    with open(log_path, 'r', encoding='utf-8-sig') as f:
        full_log = json.load(f)
    chunks = []
    for i, entry in enumerate(full_log):
        if isinstance(entry, dict) and entry.get("Event Name") == "Agent-Started":
            # Find closest Agent-Finished
            chunk = [entry]
            for j in range(i + 1, len(full_log)):
                chunk.append(full_log[j])
                if isinstance(full_log[j], dict) and full_log[j].get("Event Name") == "Agent-Finished":
                    break
            chunks.append(chunk)

    # rough estimate: ~4 characters per token
    token_counts = [len(json.dumps(c)) // 4 for c in chunks]
    return chunks, token_counts
