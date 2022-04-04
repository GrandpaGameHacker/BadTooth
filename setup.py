import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="badtooth",
    version="0.0.1",
    author="GrandpaGameHacker",
    author_email="itsthatguyagain3@gmail.com",
    description="A memory hacking package for windows games.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/grandpagamehacker/BadTooth",
    packages=setuptools.find_packages(),
    install_requires=['capstone', 'keystone-engine', 'pefile'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        "Programming Language :: Python :: 3.6",
        "Intended Audience :: Other Audience",
        "Topic :: Games/Entertainment",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows :: Windows 10"
    ],
    python_requires='>=3.6',
)