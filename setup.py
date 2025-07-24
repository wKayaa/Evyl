#!/usr/bin/env python3
"""
Setup script for Evyl Framework v2.0
"""

from setuptools import setup, find_packages
import os

# Read README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="evyl-framework",
    version="3.1.0",
    author="Evyl Team",
    author_email="contact@evyl.dev",
    description="Advanced Cloud Exploitation Framework for Authorized Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wKayaa/Evyl",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "evyl=evyl:main",
        ],
    },
    package_data={
        "": ["config/*.yaml", "config/*.txt", "paths/*.txt"],
    },
    include_package_data=True,
    keywords=[
        "security",
        "penetration-testing",
        "cloud-security",
        "kubernetes",
        "aws",
        "gcp",
        "azure",
        "credential-harvesting",
        "vulnerability-scanner",
        "red-team",
        "security-testing",
        "exploitation",
        "reconnaissance"
    ],
    project_urls={
        "Bug Reports": "https://github.com/wKayaa/Evyl/issues",
        "Source": "https://github.com/wKayaa/Evyl",
        "Documentation": "https://github.com/wKayaa/Evyl/wiki",
    },
)