Regenerating Protobuf Python Bindings
====================================

Use the project's Poetry-managed environment to regenerate Sliver protobuf bindings.

Quick steps

- Install dependencies (including dev dependencies):

  - `poetry install`

- Regenerate protobufs (two options):

  - Run via the Poetry console script (recommended):

    - `poetry run generate-protobuf`

  - Or run the generator directly with the Poetry-managed Python:

    - `poetry run python generate_protobuf.py`

Notes
- The generator writes Python files under `src/sliver/pb/`.
- Ensure you run the generator using the same Python environment you use to import the package (Poetry's environment). If you previously installed a published `sliver-py` package into the same environment it can shadow the local `src` package; uninstall it first (`pip uninstall sliver-py`).
- The generator requires `grpcio-tools` and `protobuf` to be available in the environment; they are listed in the project's dev dependencies.
