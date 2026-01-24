"""Test that protobuf bindings are generated correctly."""

import pytest

def test_generate_stage_req_exists():
    """Test that GenerateStageReq class is available in generated protobuf bindings."""
    from sliver_client.pb.clientpb import client_pb2

    # Check that it's a class
    assert hasattr(client_pb2.GenerateStageReq, '__init__')

    # Optionally, check some fields if known
    # For example, instantiate and check fields
    req = client_pb2.GenerateStageReq()
    assert hasattr(req, 'Profile')
    assert hasattr(req, 'Name')
    assert hasattr(req, 'AESEncryptKey')
    assert hasattr(req, 'AESEncryptIv')
    assert hasattr(req, 'RC4EncryptKey')
    assert hasattr(req, 'PrependSize')
    assert hasattr(req, 'CompressF')
    assert hasattr(req, 'Compress')