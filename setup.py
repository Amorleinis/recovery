"""
Setup script for System Recovery Engine (Standalone)
"""

from setuptools import setup
from pathlib import Path

setup(
    name="system-recovery-engine",
    version="1.0.0",
    author="CyberGuard Industries - Lance Brady & AI Collaboration",
    author_email="lance.ceo@cyberguard-industries.com",
    description="Backup/restore, system rebuilds, and business continuity management by CyberGuard Industries",
    long_description=open("README.md").read() if Path("README.md").exists() else "",
    long_description_content_type="text/markdown",
    url="https://github.com/cyberguard-industries/system-recovery-engine",
    packages=['recovery'],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.26.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    license="Apache 2.0",
    keywords="system recovery, backup restore, disaster recovery, business continuity, cyberguard",
)
