# Welcome to OpenAdapt.AI

**OpenAdapt.AI** is an open source **Generative Process Automation** platform that transforms desktop automation through machine learning. Record human demonstrations, train vision-language models, and deploy agents that adapt to any software environment.

## What is OpenAdapt.AI?

OpenAdapt.AI leverages advanced machine learning models to:

- **Observe and Learn**: Automatically learns from user interactions to generate automation scripts
- **Automate Intelligently**: Adapts to software changes, varying workflows, and complex environments
- **Ensure Privacy**: Built-in data protection with support for AWS Rekognition, Microsoft Presidio, and Private-ai.com

## Key Features

- **Generative Process Automation**: Automates tasks using generative AI models that learn from demonstrations
- **Cross-Platform Compatibility**: Works with browser apps (Chrome) and desktop applications
- **Audio Narration Transcription**: Converts spoken instructions into automation scripts
- **Flexible Model Providers**: Supports OpenAI, Anthropic, Google (online) and Ollama, vLLM (offline)
- **Open Source**: Developed transparently and collaboratively by the community
- **Privacy by Design**: Robust data handling mechanisms to protect user data

## Package Ecosystem

OpenAdapt.AI is built as a **modular ecosystem** of specialized packages:

| Package | Description | Status |
|---------|-------------|--------|
| [**openadapt**](https://github.com/OpenAdaptAI/openadapt) | Core platform - unified CLI, recording, training, evaluation | Production |
| [**openadapt-ml**](https://github.com/OpenAdaptAI/openadapt-ml) | ML engine for training GUI automation models | Active Development |
| [**openadapt-capture**](https://github.com/OpenAdaptAI/openadapt-capture) | Cross-platform screen and input event recording | Active Development |
| [**openadapt-grounding**](https://github.com/OpenAdaptAI/openadapt-grounding) | Visual grounding with OmniParser and UI-TARS | Active Development |
| [**openadapt-evals**](https://github.com/OpenAdaptAI/openadapt-evals) | Benchmark evaluation (WAA, WebArena) | Active Development |
| [**openadapt-viewer**](https://github.com/OpenAdaptAI/openadapt-viewer) | Reusable UI components for visualization | Active Development |
| [**openadapt-retrieval**](https://github.com/OpenAdaptAI/openadapt-retrieval) | Multimodal demo retrieval (Qwen3-VL, CLIP, FAISS) | Active Development |

### Architecture Overview

```
                    +-----------------+
                    |    openadapt    |  <-- Unified CLI and meta-package
                    +-----------------+
                             |
              +--------------+---------------+
              |              |               |
              v              v               v
    +----------------+ +-----------+ +----------------+
    |openadapt-capture| |openadapt-| |openadapt-evals |
    |   (recording)   | |    ml    | |  (benchmarks)  |
    +----------------+ | (training)| +----------------+
                       +-----------+
                             |
              +--------------+---------------+
              |              |               |
              v              v               v
    +----------------+ +----------------+ +----------------+
    |openadapt-viewer| |openadapt-      | |openadapt-      |
    |(visualization) | |   grounding    | |   retrieval    |
    +----------------+ | (perception)   | | (demo search)  |
                       +----------------+ +----------------+
```

## Getting Started

### Quick Start

```bash
# Install with pip
pip install openadapt

# Or use uv (recommended)
uv tool install openadapt

# Record a demonstration
openadapt capture start --name my-task
# ... perform the task ...
openadapt capture stop

# Train a model
openadapt train --capture ./captures/my-task

# Evaluate on benchmarks
openadapt eval run --benchmark waa-mock --tasks 20
```

### Individual Packages

Each package can be installed independently:

```bash
pip install openadapt           # Core CLI and unified interface
pip install openadapt-ml        # ML training engine
pip install openadapt-capture   # Screen recording
pip install openadapt-grounding # UI element localization
pip install openadapt-evals     # Benchmark evaluation
pip install openadapt-retrieval # Demo similarity search
```

See each package's README for detailed documentation.

## Contributing

We welcome contributions from everyone. Whether you are a developer, data scientist, tester, or just passionate about automation, there is a place for you here.

- **[Contributing Guide](https://github.com/OpenAdaptAI/openadapt/blob/main/CONTRIBUTING.md)**
- **[Code of Conduct](https://github.com/OpenAdaptAI/openadapt/blob/main/CODE_OF_CONDUCT.md)**

Join our [Community](https://github.com/OpenAdaptAI/openadapt/discussions) to discuss new ideas, report bugs, or seek help.

**Areas of interest:**
- Frontend development (React, visualization)
- Machine learning (model training, evaluation)
- Desktop integration (Windows, macOS, Linux)
- Benchmark development and evaluation
- Documentation and tutorials

## Implementation Consulting

Looking to implement OpenAdapt.AI in your organization? We offer expert consulting services for deployment, customization, and optimization.

Contact us at [sales@openadapt.ai](mailto:sales@openadapt.ai).

## Sponsors and Partners

OpenAdapt.AI is made possible by the support of our contributors and partners. If you are interested in sponsoring development, check out our [GitHub Sponsors page](https://github.com/sponsors/OpenAdaptAI).

## Contact

For general questions, feedback, or partnership inquiries: [contact@openadapt.ai](mailto:contact@openadapt.ai)

## Disclaimer

OpenAdapt.AI is currently in alpha. While functional, some features are still under development. Use with caution in production environments.
