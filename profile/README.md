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

| Repository | Description | Status |
|------------|-------------|--------|
| **[OpenAdapt](https://github.com/OpenAdaptAI/OpenAdapt)** ⭐ | Main platform orchestrating GUI automation with LMMs. Meta-package integrating all ecosystem components | 🟢 Active |

### Modular Components

**Data Capture & Processing**
| Repository | Description | Status |
|------------|-------------|--------|
| **[openadapt-capture](https://github.com/OpenAdaptAI/openadapt-capture)** | Production-ready event streams with time-aligned media for GUI interaction recording | 🟢 Active |
| **[openadapt-viewer](https://github.com/OpenAdaptAI/openadapt-viewer)** | HTML viewer components for visualization dashboards and benchmark results | 🟢 Active |
| **[openadapt-web](https://github.com/OpenAdaptAI/openadapt-web)** | Web interface components for browser-based interaction | 🟢 Active |

**Machine Learning & Intelligence**
| Repository | Description | Status |
|------------|-------------|--------|
| **[openadapt-ml](https://github.com/OpenAdaptAI/openadapt-ml)** | ML training toolkit for multimodal GUI-action models | 🟢 Active |
| **[openadapt-grounding](https://github.com/OpenAdaptAI/openadapt-grounding)** | UI element detection and localization with OmniParser integration | 🟢 Active |
| **[openadapt-retrieval](https://github.com/OpenAdaptAI/openadapt-retrieval)** | Multimodal demo retrieval system for similarity search in GUI automation | 🟢 Active |

**Evaluation & Quality**
| Repository | Description | Status |
|------------|-------------|--------|
| **[openadapt-evals](https://github.com/OpenAdaptAI/openadapt-evals)** | Evaluation infrastructure and benchmarks for GUI agent performance testing | 🟢 Active |

**Privacy & Security**
| Repository | Description | Status |
|------------|-------------|--------|
| **[openadapt-privacy](https://github.com/OpenAdaptAI/openadapt-privacy)** | PII/PHI detection and redaction for GUI automation data with Presidio integration | 🟢 Active |

**Execution & Runtime**
| Repository | Description | Status |
|------------|-------------|--------|
| **[openadapt-agent](https://github.com/OpenAdaptAI/openadapt-agent)** | Production execution engine with safety gates, audit logging, and human-in-the-loop confirmation | 🟢 Active |

**Observability**
| Repository | Description | Status |
|------------|-------------|--------|
| **[openadapt-telemetry](https://github.com/OpenAdaptAI/openadapt-telemetry)** | Error tracking and usage analytics with privacy filtering for platform monitoring | 🟢 Active |

### Integration & Deployment Tools

| Repository | Description | Status |
|------------|-------------|--------|
| **[OpenAdapter](https://github.com/OpenAdaptAI/OpenAdapter)** | Effortless deployment platform for screenshot parsing and action models on AWS EC2 | 🟢 Active |
| **[OmniMCP](https://github.com/OpenAdaptAI/OmniMCP)** | Model Context Protocol integration with OmniParser for AI UI interaction (68 stars) | 🟢 Active |
| **[OmniMCP.web](https://github.com/OpenAdaptAI/OmniMCP.web)** | Web interface for OmniMCP server | 🟢 Active |

## 🤝 Community Contributions

OpenAdapt has contributed deployment infrastructure to major open-source projects:

### Microsoft OmniParser
- **[PR #52](https://github.com/microsoft/OmniParser/pull/52)**: Add Dockerfile and client.py; deploy to EC2 on AWS via Github Actions
- **Status**: Open (most commented PR in the repository)
- **Contribution**: Production deployment infrastructure with Docker, client library, and AWS automated deployment
- **Impact**: Enables production deployment of OmniParser for screen parsing tasks

### Microsoft Set-of-Mark (SoM)
- **[PR #19](https://github.com/microsoft/SoM/pull/19)**: Add Dockerfile and client.py; deploy to EC2 on AWS via Github Actions
- **Status**: Merged (first PR to the repository)
- **Contribution**: `deploy.py`, Gradio interface, client library, and AWS deployment automation
- **Impact**: Provided the foundation for SoM's production deployment capabilities

### Research Forks & Foundations

| Repository | Description | Status |
|------------|-------------|--------|
| **[OpenCUA](https://github.com/OpenAdaptAI/OpenCUA)** | Fork of Computer-Use Agents framework that cites OpenAdapt as foundational | 🟡 Fork |
| **[OmniParser](https://github.com/OpenAdaptAI/OmniParser)** | Fork of Microsoft's OmniParser with deployment enhancements | 🟡 Fork |
| **[SoM](https://github.com/OpenAdaptAI/SoM)** | Fork of Set-of-Mark visual prompting with deployment infrastructure | 🟡 Fork |

### Development Tools & Libraries

| Repository | Description |
|------------|-------------|
| **[PydanticPrompt](https://github.com/OpenAdaptAI/PydanticPrompt)** | Library for documenting Pydantic models to generate structured LLM outputs |

### Critical Dependencies

| Repository | Description |
|------------|-------------|
| **[atomacos](https://github.com/OpenAdaptAI/atomacos)** | macOS automation library (fork) - critical dependency for macOS support |
| **[pynput](https://github.com/OpenAdaptAI/pynput)** | Input control library (fork) - critical dependency for cross-platform input handling |

### Research & Experimentation

| Repository | Description |
|------------|-------------|
| **[OmniParser](https://github.com/OpenAdaptAI/OmniParser)** | Fork of Microsoft's OmniParser for screen parsing with OpenAdapt-specific modifications |
| **[SoM](https://github.com/OpenAdaptAI/SoM)** | Set-of-Mark visual prompting technique for precise UI element targeting |

### Configuration & Infrastructure

| Repository | Description |
|------------|-------------|
| **[.github](https://github.com/OpenAdaptAI/.github)** | Organization-wide GitHub configuration, templates, and this profile README |

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

- **Frontend Development**: openadapt-web, openadapt-viewer
- **Machine Learning**: openadapt-ml, openadapt-grounding, openadapt-retrieval
- **Data Capture**: openadapt-capture
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
