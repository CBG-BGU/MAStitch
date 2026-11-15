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
cd <repository-folder>
```

2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root:

```bash
cp .env.example .env   # then fill in your keys
```

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

Before running analysis, you need a system configuration file that describes your expected Multi-Agent System behavior.
This file helps MAStitch distinguish normal operations from anomalies.
Example configurations are provided in `configuration_files/`, with matching benign/anomaly logs in `example_logs/`:

| Application | Framework | Config | Logs |
|---|---|---|---|
| Instagram Marketing | CrewAI | `Instagram_config_file.json` | `example_logs/Instagram_CrewAI/` |
| Trip Planner | LangGraph | `TripPlanner_LangGraph_config_file.json` | `example_logs/Trip_Planner_LangGraph/` |
| Trip Planner | CrewAI | `TripPlanner_config_file.json` | `example_logs/Trip_Planner_CrewAI/` |
| Game Builder | CrewAI | `GameBuilder_config_file.json` | `example_logs/GameBuilder/` |
| GenFIC Stories Generator | LangGraph | `GenFIC_config_file.json` | `example_logs/Genfic/` |
| Real Estate | CrewAI | `RealEstate_config_file.json` | `example_logs/RealEstate/` |

Log files are named `benign_log_*` (expected result: no alert) or `anomaly_log_*` (expected result: alert). Each Trip Planner folder contains one benign log and three anomaly logs, one per attack scenario: `DPI_Misinformation`, `DPI_Backdoor` and `DPI_Exhaustion`.

Run `python main.py` to evaluate all of them (note: each log triggers LLM calls).

### Tunable Thresholds

You can adjust monitoring sensitivity in `MAStitch_config.py`:

```python
VALIDITY_ALERT_THRESHOLD: float = 75.0  # Chunk validity score threshold
CONFIDENCE_ALERT_THRESHOLD: float = 70.0  # Global confidence threshold
ESCALATING_RISK_SCORE: float = 45.0  # Chunk score above which a chunk is flagged as escalating risk in the GAA memory
```

### Log File Format

MAStitch expects logs in a standardized JSON format from the **LumiMAS monitoring layer** ([arXiv:2508.12412](https://arxiv.org/abs/2508.12412)). The system creates analysis
chunks based on agent execution boundaries:

**Required events for chunking:**

- `"Event Name": "Agent-Started"` - Marks the beginning of an agent execution chunk
- `"Event Name": "Agent-Finished"` - Marks the end of an agent execution chunk

## Usage

### Basic Usage

```python
from MAStitch_detection import analyze_log_file

# Path to your execution log file (JSON format)
log_path = "/path/to/your/telemetry_log.json"

# Path to your system configuration file
config_path = "/path/to/your/system_config.json"

# Run analysis. Returns a tuple:
# (alert_raised, final_decision, seconds, token_usage, log_tokens)
# Alert details are written to ALERT_<log name>.txt in output_dir (default: ./alerts)
alert, *_ = analyze_log_file(log_path, config_path)

if alert:
    print("⚠️ SECURITY ALERT: Potential threat detected!")
else:
    print("✓ System operating normally")
```

## How It Works

1. **Log Chunking**: The system divides logs into chunks from `Agent-Started` to `Agent-Finished` events
2. **Parallel Analysis**: Each chunk is analyzed by an LAA agent in a separate thread
3. **Security Evaluation**: LAA agents score chunks (0-100) based on detected issues:
    - Prompt injection attempts
    - LLM knowledge exploitation
    - Configuration deviations
    - Unauthorized access
    - Data integrity issues
4. **Global Decision**: GAA orchestrator evaluates the chunks in log order and tracks patterns across them and triggers alerts when:
    - Any chunk scores ≥ validity threshold (default: 75)
    - Global confidence ≥ confidence threshold (default: 70)
5. **Alert Response**: `analyze_log_file` returns `True` as its first value if a threat was detected, `False` if benign

## Output

The method provides:

- **Chunk Evaluations**: Validity scores and detected issues per chunk
- **Global Decision**: Overall confidence score and alert status
- **Detailed Reasoning**: Explanations for scores and decisions

## Citation

If you use MAStitch, please cite the paper: <https://dl.acm.org/doi/10.65109/BMJZ4532>
