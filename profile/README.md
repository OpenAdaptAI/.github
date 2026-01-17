# OpenAdapt.AI

**AI-First Process Automation for the Desktop Era**

OpenAdapt.AI is an open-source Generative Process Automation platform that transforms desktop automation through machine learning. Record human demonstrations, train vision-language models, and deploy agents that adapt to any software environment.

## 🎯 Core Capabilities

- **Learn by Demonstration**: Automatically learns from user interactions to generate automation scripts
- **Adaptive Intelligence**: Adapts to software changes and complex environments using multimodal models
- **Privacy-First**: Built-in data protection with PII/PHI detection and redaction
- **Cross-Platform**: Works with browsers and desktop applications across macOS and Windows
- **Multi-Model Support**: Integrates with OpenAI, Anthropic, Google, Ollama, and vLLM
- **Open Source**: Community-driven development with MIT licensing

## 🏗️ Ecosystem

### Core Platform

| Repository | Description | Language |
|------------|-------------|----------|
| **[OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt)** | Main platform orchestrating GUI automation with LMMs. Meta-package integrating all ecosystem components | Python |
| **[app](https://github.com/OpenAdaptAI/app)** | Desktop application providing user-friendly interface for workflow automation | Cross-platform |

### Modular Components

**Data Capture & Processing**
| Repository | Description | Language |
|------------|-------------|----------|
| **[openadapt-capture](https://github.com/OpenAdaptAI/openadapt-capture)** | Production-ready event streams with time-aligned media for GUI interaction recording | Python |
| **[openadapt-viewer](https://github.com/OpenAdaptAI/openadapt-viewer)** | HTML viewer components for visualization dashboards and benchmark results | Python |
| **[openadapt-web](https://github.com/OpenAdaptAI/openadapt-web)** | Web interface components for browser-based interaction | JavaScript |

**Machine Learning & Intelligence**
| Repository | Description | Language |
|------------|-------------|----------|
| **[openadapt-ml](https://github.com/OpenAdaptAI/openadapt-ml)** | ML training toolkit for multimodal GUI-action models | Python |
| **[openadapt-grounding](https://github.com/OpenAdaptAI/openadapt-grounding)** | UI element detection and localization with OmniParser integration | Python |
| **[openadapt-retrieval](https://github.com/OpenAdaptAI/openadapt-retrieval)** | Multimodal demo retrieval system for similarity search in GUI automation | Python |

**Evaluation & Quality**
| Repository | Description | Language |
|------------|-------------|----------|
| **[openadapt-evals](https://github.com/OpenAdaptAI/openadapt-evals)** | Evaluation infrastructure and benchmarks for GUI agent performance testing | Python |

**Privacy & Security**
| Repository | Description | Language |
|------------|-------------|----------|
| **[openadapt-privacy](https://github.com/OpenAdaptAI/openadapt-privacy)** | PII/PHI detection and redaction for GUI automation data with Presidio integration | Python |

**Execution & Runtime**
| Repository | Description | Language |
|------------|-------------|----------|
| **[openadapt-agent](https://github.com/OpenAdaptAI/openadapt-agent)** | Production execution engine with safety gates, audit logging, and human-in-the-loop confirmation | Python |
| **[openadapt-tray](https://github.com/OpenAdaptAI/openadapt-tray)** | System tray application for convenient access to platform features | Python |

**Observability**
| Repository | Description | Language |
|------------|-------------|----------|
| **[openadapt-telemetry](https://github.com/OpenAdaptAI/openadapt-telemetry)** | Error tracking and usage analytics with privacy filtering for platform monitoring | Python |

### Deployment & Integration Tools

| Repository | Description | Language |
|------------|-------------|----------|
| **[OpenAdapter](https://github.com/OpenAdaptAI/OpenAdapter)** | Effortless deployment platform for screenshot parsing and action models on AWS EC2 | Python |
| **[OmniMCP](https://github.com/OpenAdaptAI/OmniMCP)** | Model Context Protocol integration with OmniParser for AI UI interaction | Python |
| **[OpenCUA](https://github.com/OpenAdaptAI/OpenCUA)** | Open Foundations for Computer-Use Agents - standardized interfaces and protocols | Python |

### Development Tools & Libraries

| Repository | Description | Language |
|------------|-------------|----------|
| **[PydanticPrompt](https://github.com/OpenAdaptAI/PydanticPrompt)** | Library for documenting Pydantic models to generate structured LLM outputs | Python |

### Critical Dependencies

| Repository | Description | Language |
|------------|-------------|----------|
| **[atomacos](https://github.com/OpenAdaptAI/atomacos)** | macOS automation library (fork) - critical dependency for macOS support | Python |
| **[pynput](https://github.com/OpenAdaptAI/pynput)** | Input control library (fork) - critical dependency for cross-platform input handling | Python |

### Research & Experimentation

| Repository | Description | Language |
|------------|-------------|----------|
| **[OmniParser](https://github.com/OpenAdaptAI/OmniParser)** | Fork of Microsoft's OmniParser for screen parsing with OpenAdapt-specific modifications | Jupyter Notebook |
| **[SoM](https://github.com/OpenAdaptAI/SoM)** | Set-of-Mark visual prompting technique for precise UI element targeting | Research |

### Configuration & Infrastructure

| Repository | Description | Language |
|------------|-------------|----------|
| **[.github](https://github.com/OpenAdaptAI/.github)** | Organization-wide GitHub configuration, templates, and this profile README | - |

## 🚀 Quick Start

```bash
# Install core platform
pip install openadapt

# Or use uv for faster installation
uv pip install openadapt

# Record a demonstration
openadapt record

# Train a model
openadapt train

# Evaluate performance
openadapt eval
```

## 📚 Documentation

- **Website**: [openadapt.ai](https://openadapt.ai/)
- **Email**: info@openadapt.ai
- **Discord**: Join our community (link on website)
- **X/Twitter**: [@OpenAdaptAI](https://twitter.com/OpenAdaptAI)

## 🤝 Contributing

We welcome contributions across all repositories:

- **Frontend Development**: openadapt-web, openadapt-viewer, app
- **Machine Learning**: openadapt-ml, openadapt-grounding, openadapt-retrieval
- **Desktop Integration**: openadapt-tray, openadapt-capture
- **Privacy & Security**: openadapt-privacy
- **Agent Runtime**: openadapt-agent
- **Evaluation**: openadapt-evals
- **Documentation**: All repositories

See individual repository CONTRIBUTING.md files for specific guidelines.

## 📊 Project Status

OpenAdapt.AI is currently in **alpha**. While functional, some features are still under development. We're actively working towards production-ready releases across the ecosystem.

## 💼 Enterprise & Consulting

Professional implementation services and organizational consulting are available. Contact info@openadapt.ai for details.

## 💖 Sponsorship

Support OpenAdapt.AI development through [GitHub Sponsors](https://github.com/sponsors/OpenAdaptAI). Your contributions help maintain and expand this open-source ecosystem.

## 📄 License

All OpenAdapt.AI repositories are licensed under the MIT License unless otherwise specified. See individual repository LICENSE files for details.
