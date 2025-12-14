from setuptools import setup, find_packages

setup(
    name="sliver-nxc-module",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "sliver": ["**/*"],
    },
    data_files=[
        ("nxc/modules", ["sliver_exec.py"]),
    ],
    include_package_data=True,
)
