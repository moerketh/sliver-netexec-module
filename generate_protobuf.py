import os
from pathlib import Path

from grpc_tools import protoc

ROOT_DIR = Path(__file__).parent
IN_DIR = ROOT_DIR / "sliver-source/protobuf"
OUT_DIR = ROOT_DIR / "src/sliver/pb"

COMMON_PROTO_PATH = IN_DIR / "commonpb/common.proto"
SLIVER_PROTO_PATH = IN_DIR / "sliverpb/sliver.proto"
CLIENT_PROTO_PATH = IN_DIR / "clientpb/client.proto"
GRPC_PROTO_PATH = IN_DIR / "rpcpb/services.proto"

# Cleanup old files
def main() -> None:
    print("Removing old generated files...")
    for file in OUT_DIR.glob("**/*.py"):
        if file.name.split("_")[0] in ["common", "sliver", "client", "services"]:
            file.unlink()
            print(f"Removed {file}")

    print("Generating new files...")
    import grpc_tools
    proto_pyd = os.path.join(os.path.dirname(grpc_tools.__file__), "_proto")

    # Generate commonpb, sliverpb, clientpb together
    protoc.main(
        f"-I{proto_pyd} -I {IN_DIR} --python_out={OUT_DIR} {COMMON_PROTO_PATH} {SLIVER_PROTO_PATH} {CLIENT_PROTO_PATH}".split()
    )
    print("Generated common, sliver, client proto files")

    # Generate rpcpb
    protoc.main(
        f"-I{proto_pyd} -I {IN_DIR} --python_out={OUT_DIR} --grpc_python_out={OUT_DIR} {GRPC_PROTO_PATH}".split()
    )
    print(f"Generated {GRPC_PROTO_PATH.name}")

    # Rewrite imports for py files
    print("Rewriting imports for py files...")
    for file in OUT_DIR.glob("**/*.py"):
        if file.name.split("_")[0] in ["sliver", "client", "services"]:
            content = (
                file.read_text()
                .replace(
                    "from commonpb import common_pb2 as commonpb_dot_common__pb2",
                    "from sliver.pb.commonpb import common_pb2 as commonpb_dot_common__pb2",
                )
                .replace(
                    "from sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2",
                    "from sliver.pb.sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2",
                )
                .replace(
                    "from clientpb import client_pb2 as clientpb_dot_client__pb2",
                    "from sliver.pb.clientpb import client_pb2 as clientpb_dot_client__pb2",
                )
            )
            file.write_text(content)

    print("Done!")


if __name__ == "__main__":
    main()
