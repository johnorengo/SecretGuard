from setuptools import find_packages, setup

setup(
    name="secretguard",
    version="1.0.0",
    description="A lightweight DevSecOps CLI for detecting exposed secrets in source repositories.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="SecretGuard Contributors",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={"rules": ["patterns.json"]},
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "secretguard=secretguard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
