from setuptools import setup, find_packages

setup(
    name="pman_tester",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "PyQt5>=5.15.6",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "pman_tester=pman_tester.p:main",
        ],
    },
    author="Tien Song Nguyen",
    author_email="tiennguyensong@gmail.com",
    description="A GUI-based API testing tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/tiennsloit/pman",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)