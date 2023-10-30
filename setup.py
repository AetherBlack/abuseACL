
from os import path

import setuptools

import abuseACL

cwd = path.abspath(path.dirname(__file__))

with open(path.join(cwd, "README.md")) as f:
    long_description = f.read()

with open(path.join(cwd, "requirements.txt")) as f:
    requirements = f.read()


setuptools.setup(
    name="abuseACL",
    version=abuseACL.__version__,
    description="List vulnerable ACL.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AetherBlack/abuseACL",
    author="Aether",
    classifiers=[
        "Intended Audience :: Information Technology",
        "Programming Language :: Python :: 3"
    ],
    keywords="abuseACL ActiveDirectory AD",
    packages=setuptools.find_packages(),
    python_requires=">=3.6, <4",
    install_requires=requirements,
    entry_points={
        "console_scripts": ["abuseACL=abuseACL.__main__:main"]
    }
)
