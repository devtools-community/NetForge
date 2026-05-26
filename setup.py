from setuptools import setup, find_packages

setup(
    name="netforge",
    version="0.3.1",
    description="Lightweight pcap analysis toolkit for network forensics",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="netforge contributors",
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "netforge=netforge.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
