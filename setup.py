import setuptools

with open("README.md", "r") as readme:
    long_description = readme.read()

setuptools.setup(
    name="paillier-python",
    version="0.0.1",
    author="Vinicius E. Martins",
    author_email="vini9x@gmail.com",
    description="Simple python paillier encryption implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=["libnum"],
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Operating System :: GNU/Linux",
    ],
    python_requires=">=3.5",
)
