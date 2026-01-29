from setuptools import setup, find_packages

setup(
    name="sliver-nxc-module",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "sliver": ["**/*"],
        "nxc": ["**/*"],
    },
    include_package_data=True,
    install_requires=[
        "grpcio>=1.60.0",
        "protobuf>=4.25.0",
    ],
)
