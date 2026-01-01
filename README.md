# AI-Pentest: AI-Powered Automated Penetration Testing Tool

An intelligent, automated penetration testing tool powered by Large Language Models (LLMs) that supports Web, Network, API, and Mobile application security testing.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is designed for **authorized penetration testing only**. Unauthorized access to computer systems is illegal. Users must:

- Obtain explicit written authorization before testing any target
- Comply with all applicable laws and regulations
- Use this tool only for legitimate security assessment purposes
- Accept full responsibility for their actions

The developers assume no liability for misuse of this tool.

## 🌟 Features

- **Multi-LLM Support**: Pluggable architecture supporting OpenAI GPT-4, Anthropic Claude, and local models (Ollama)
- **Comprehensive Testing**: Web applications, networks, APIs, and mobile applications
- **AI-Driven Reasoning**: ReAct-style agent (Reasoning + Action) for intelligent attack path planning
- **Safety First**: Built-in authorization checks, scope validation, and audit logging
- **Docker Isolation**: All tools execute in isolated containers for security
- **Real-time Streaming**: WebSocket support for live scan results
- **Extensible**: Plugin system for custom tools and LLM providers
- **Knowledge Base**: Integrated CVE database and MITRE ATT&CK framework

## 🏗️ Architecture

```
User Interface (CLI/API)
    ↓
Orchestration Layer (Auth/Session/Rate Limiting)
    ↓
AI Agent Core (Planning → Execution → Reflection)
    ↓
Tool Execution Layer (Web/Network/API/Mobile)
    ↓
Infrastructure Layer (Docker/Storage/Reporting)
```

## 📋 Requirements

- Python 3.11+
- Docker & Docker Compose
- PostgreSQL (for data storage)
- Redis (for caching and sessions)
- 8GB+ RAM recommended
- Linux/macOS/Windows (WSL2)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ai-pentest.git
cd ai-pentest
```

### 2. Set Up Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure LLM Provider

Create a `.env` file:

```bash
# OpenAI
OPENAI_API_KEY=your_openai_api_key

# Anthropic Claude
ANTHROPIC_API_KEY=your_anthropic_api_key

# Or use local models with Ollama (no API key needed)
```

### 4. Start Services

```bash
# Start Docker services (PostgreSQL, Redis, ChromaDB)
docker-compose up -d

# Run database migrations
python -m src.utils.db_migrate
```

### 5. Run Your First Scan

```bash
# CLI Mode
ai-pentest scan --target example.com --type web --auth-token YOUR_AUTH_TOKEN

# API Mode
uvicorn src.api.main:app --reload
```

## 📖 Usage

### CLI Commands

```bash
# Web application scan
ai-pentest scan --target https://example.com --type web --auth-token TOKEN

# Network scan
ai-pentest scan --target 192.168.1.0/24 --type network --auth-token TOKEN

# API security test
ai-pentest scan --target https://api.example.com --type api --auth-token TOKEN

# Generate report
ai-pentest report --scan-id SCAN_ID --format pdf

# Configure LLM provider
ai-pentest config --set llm.provider=anthropic
```

### API Endpoints

```bash
# Create scan
POST /api/v1/scans
{
  "target": "example.com",
  "type": "web",
  "auth_token": "YOUR_TOKEN"
}

# Get scan status
GET /api/v1/scans/{scan_id}

# Stream results (WebSocket)
WS /api/v1/scans/{scan_id}/stream
```

## 🔧 Configuration

Configuration files are located in the `config/` directory:

- `llm_config.yaml`: LLM provider settings
- `tools_config.yaml`: Tool execution settings
- `safety_config.yaml`: Security and authorization settings

## 🛠️ Supported Tools

### Web Application Testing
- SQLMap (SQL injection)
- Nikto (web server scanning)
- Custom XSS tester
- Directory brute-forcing

### Network Testing
- Nmap (port scanning, service detection)
- Masscan (fast port scanning)
- Service enumeration

### API Testing
- REST API security testing
- GraphQL security testing
- Authentication testing

### Mobile Testing
- MobSF integration (planned)
- APK analysis (planned)

## 🔌 Plugin Development

Create custom plugins to extend functionality:

```python
# plugins/my_plugin/plugin.py
from src.plugins.interface import BasePlugin

class MyPlugin(BasePlugin):
    def execute(self, target, params):
        # Your custom logic
        return results
```

See `docs/plugin_development.md` for details.

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest tests/unit/test_llm_providers.py
```

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [API Reference](docs/api_reference.md)
- [Plugin Development Guide](docs/plugin_development.md)
- [User Guide](docs/user_guide.md)
- [Safety Guidelines](docs/safety_guidelines.md)

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and code of conduct.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by [PentestGPT](https://arxiv.org/abs/2308.06782) research
- Built with [LangChain](https://github.com/langchain-ai/langchain)
- Integrates tools from the security community

## 📞 Support

- GitHub Issues: [Report bugs or request features](https://github.com/yourusername/ai-pentest/issues)
- Documentation: [Read the docs](https://ai-pentest.readthedocs.io)
- Community: [Join our Discord](https://discord.gg/ai-pentest)

## ⚡ Roadmap

- [x] Phase 1: Project infrastructure
- [ ] Phase 2: LLM abstraction layer
- [ ] Phase 3: Safety and authorization
- [ ] Phase 4: Tool execution framework
- [ ] Phase 5: AI agent core
- [ ] Phase 6: Knowledge base system
- [ ] Phase 7: CLI and API interfaces
- [ ] Phase 8: Plugin system
- [ ] Phase 9: Docker deployment
- [ ] Phase 10: Testing and documentation

---

**Remember:** Always obtain proper authorization before testing any system. Ethical hacking requires ethics.
