from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="inalign",
    version="0.1.0",
    author="InALign Team",
    author_email="team@inalign.io",
    description="Python SDK for InALign - AI Agent Security Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/inalign/inalign-python",
    packages=find_packages(exclude=["tests*", "examples*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "httpx>=0.25",
        "pydantic>=2.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21",
            "pytest-httpx>=0.22",
            "ruff>=0.1.0",
        ],
    },
)
