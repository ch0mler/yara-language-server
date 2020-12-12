from setuptools import setup, find_packages

DESCRIPTION="""
An implementation of the Language Server Protocol for the YARA pattern matching language
    https://microsoft.github.io/language-server-protocol/
"""

classifiers = [
    'Development Status :: 3 - Alpha',
    'Programming Language :: Python :: 3.7',
]
entry_points = {
    "console_scripts": [
        "yara_server=yarals.run_server:main"
    ]
}

setup(
    author="ch0mler",
    author_email="thomas@infosec-intern.com",
    classifiers=classifiers,
    description=DESCRIPTION.split("\n")[0],
    download_url="https://github.com/ch0mler/yara-language-server",
    entry_points=entry_points,
    long_description=DESCRIPTION,
    long_description_content_type="text/plain",
    name="yara-language-server",
    packages=find_packages(),
    package_data={"yarals": ["data/*.json"]},
    provides=["yarals"],
    python_requires=">=3.7",
    tests_require=["pytest", "pytest-asyncio", "pytest-timeout"],
    url="https://ch0mler.github.io/yara-language-server/",
    version="0.0.1",
)
