"""
In-A-Lign package setup.

Install with:
    pip install -e .
"""

from setuptools import setup, find_packages

setup(
    name="inalign",
    version="0.1.0",
    description="AI Security + Efficiency Proxy",
    author="In-A-Lign",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.20.0",
        "httpx>=0.24.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "inalign=inalign.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
