# Contributing to InALign

Thank you for your interest in contributing to InALign! This guide will help you get started.

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- Neo4j (optional, for graph features)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/in-a-lign/mcp-server.git
cd mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install with dev dependencies
pip install -e ".[dev,full]"

# Run tests
pytest tests/ -v
```

## How to Contribute

### Reporting Bugs

- Search [existing issues](https://github.com/in-a-lign/mcp-server/issues) first
- Open a new issue with:
  - Clear title and description
  - Steps to reproduce
  - Expected vs actual behavior
  - Python version and OS

### Suggesting Features

- Open an issue with the `enhancement` label
- Describe the use case and expected behavior
- Explain why this would benefit other users

### Submitting Code

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/your-feature
   ```
3. **Make your changes** following the code style below
4. **Write tests** for new functionality
5. **Run the test suite**:
   ```bash
   pytest tests/ -v
   ruff check .
   black --check .
   ```
6. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add new policy rule for X"
   ```
7. **Push** and open a **Pull Request**

## Code Style

- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type hints**: Encouraged but not mandatory
- **Docstrings**: For public functions and classes

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

## Project Structure

```
mcp-server/
  src/inalign_mcp/
    server.py           # MCP server entry point
    provenance.py       # Cryptographic audit trail
    policy.py           # Security policy engine
    scanner.py          # Regex threat detection
    graph_rag.py        # GraphRAG risk analysis
    graph_store.py      # Neo4j storage layer
    dashboard.py        # Web dashboard
    ...
  tests/
    test_integration.py
    test_mcp_tools.py
    ...
```

## Testing

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=inalign_mcp --cov-report=term-missing

# Specific test
pytest tests/test_integration.py -v -k "test_provenance"
```

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new features
- Update documentation if needed
- Ensure CI passes before requesting review
- Reference related issues in the PR description

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
