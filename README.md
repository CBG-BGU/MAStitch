# MAStitch - Multi-Agent System Security Monitoring

MAStitch is a security detection layer designed to detect anomalies, threats, and unauthorized activities in Multi-Agent
Systems (MASs). It uses an agentic architecture to analyze execution logs and identify potential security compromises.

## Architecture

The system employs a hierarchical analysis approach:

- **LAA (Local Analyst Agent)**: Evaluates individual execution chunks for security issues, anomalies, and deviations
- **GAA (Global Analyst Agent)**: Orchestrates decision-making across multiple chunks, tracking patterns and escalating
  threats

## Features

- **Parallel Processing**: Multi-threaded analysis of log chunks for efficient processing - multiple LAA instances
- **Adaptive Scoring**: Configurable thresholds for validity and confidence scoring.
- **Pattern Recognition**: Tracks recurring issues and escalating threats across execution chunks

## Prerequisites

Before running MAStitch, ensure you have:

1. **Python 3.11+** installed
2. **API Keys**:
    - OpenAI API key
    - Serper API key (for internet search functionality)
3. **System Configuration File**: A JSON file describing your expected system behavior (see Configuration section)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd mastitch
```

2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env` and fill in your API keys.

## Environment Variables

Create a `.env` file with the following variables:

```env
# API Keys
OPENAI_API_KEY=your_openai_api_key_here
SERPER_API_KEY=your_serper_api_key_here

# Model Configuration
MODEL=gpt-4.1-mini
```

### Environment Variable Descriptions

- `OPENAI_API_KEY`: Your OpenAI API key for LLM access
- `SERPER_API_KEY`: API key for Serper internet search tool
- `MODEL`: The LLM model to use (e.g., `gpt-4o-mini`, `gpt-4`, `gpt-3.5-turbo`)

## Configuration

### System Configuration File

Each target MAS needs a JSON config describing expected agents, tools, and workflows. Bundled examples:

| Application | Config |
|-------------|--------|
| Instagram marketing (CrewAI) | [`configuration_files/Instagram_config_file.json`](./configuration_files/Instagram_config_file.json) |
| Trip planner (LangGraph) | [`configuration_files/TripPlanner_LangGraph_config_file.json`](./configuration_files/TripPlanner_LangGraph_config_file.json) |

### Tunable Thresholds

You can adjust monitoring sensitivity in `MAStitch_config.py`:

```python
VALIDITY_ALERT_THRESHOLD: float = 75.0  # Chunk validity score threshold
CONFIDENCE_ALERT_THRESHOLD: float = 70.0  # Global confidence threshold
```

### Log File Format

MAStitch expects logs in a standardized JSON format from the **LumiMAS monitoring layer**. The system creates analysis
chunks based on agent execution boundaries:

**Required events for chunking:**

- `"Event Name": "Agent-Started"` - Marks the beginning of an agent execution chunk
- `"Event Name": "Agent-Finished"` - Marks the end of an agent execution chunk

## Usage

### Run bundled examples

Copy `.env.example` to `.env`, add your API keys, then from the repo root:

```python
from MAStitch_detection import analyze_log_file

# --- Instagram (CrewAI) ---
config_ig = "configuration_files/Instagram_config_file.json"
print(analyze_log_file("example_logs/Instegram_CrewAI/benign_log_Instegram", config_ig))       # 0 = benign
print(analyze_log_file("example_logs/Instegram_CrewAI/anomaly_log_IPI", config_ig))            # 1 = anomaly

# --- Trip planner (LangGraph) ---
config_trip = "configuration_files/TripPlanner_LangGraph_config_file.json"
print(analyze_log_file("example_logs/Trip_Planner_LangGraph/benign_log_Trip", config_trip))
print(analyze_log_file("example_logs/Trip_Planner_LangGraph/anomaly_log_DPI_Misinformation", config_trip))
# Other anomaly logs: anomaly_log_DPI_Backdoor, anomaly_log_DPI_Exhaustion
```

Returns **`0`** (benign) or **`1`** (anomaly). Prints progress and metrics to the console; on alert, writes `output/ALERT_<log_filename>.txt`. Each run uses OpenAI and Serper (costs apply).

## How It Works

1. **Log Chunking**: The system divides logs into chunks from `Agent-Started` to `Agent-Finished` events
2. **Parallel Analysis**: Each chunk is analyzed by an LAA agent in a separate thread
3. **Security Evaluation**: LAA agents score chunks (0-100) based on detected issues:
    - Prompt injection attempts
    - LLM knowledge exploitation
    - Configuration deviations
    - Unauthorized access
    - Data integrity issues
4. **Global Decision**: GAA orchestrator tracks patterns across chunks and triggers alerts when:
    - Any chunk scores ≥ validity threshold (default: 75)
    - Global confidence ≥ confidence threshold (default: 70)
5. **Alert Response**: Returns `1` if a threat is detected, `0` otherwise; alert details are written under `output/` (console output includes chunk scores and reasoning)

