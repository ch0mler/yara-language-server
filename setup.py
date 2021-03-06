''' Build instructions for the yara-language-server package '''
from setuptools import setup, find_packages

DESCRIPTION="""
An implementation of the Language Server Protocol for the YARA pattern matching language
    https://microsoft.github.io/language-server-protocol/
"""

VERSION="0.0.4"

classifiers = [
    'Development Status :: 3 - Alpha',
    'Programming Language :: Python :: 3.7',
    'License :: OSI Approved :: Apache Software License',
]
entry_points = {
    "console_scripts": [
        "yara_server=yarals.run_server:main"
    ]
}

with open("README.md", "r", encoding="utf-8") as readme:
    long_description = readme.read()

setup(
    author="ch0mler",
    author_email="thomas@infosec-intern.com",
    classifiers=classifiers,
    description=DESCRIPTION,
    download_url="https://github.com/ch0mler/yara-language-server",
    entry_points=entry_points,
    license='Apache 2.0',
    long_description=long_description,
    long_description_content_type="text/markdown",
    name="yara-language-server",
    packages=find_packages(),
    package_data={"yarals": ["data/*.json"]},
    provides=["yarals"],
    python_requires=">=3.7",
    tests_require=["pytest", "pytest-asyncio", "pytest-timeout"],
    url="https://ch0mler.github.io/yara-language-server/",
    version=VERSION,
)
