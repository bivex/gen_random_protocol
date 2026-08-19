"""
Unit and integration tests for Protocol Buffers (proto3) emitter and compiler integration.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from random import Random

from gen_protocol.adapters.emitters.protobuf import (
    PROTOBUF_RESERVED,
    ProtobufEmitter,
    prefix_enum_member,
    sanitize_proto_field_name,
    to_pascal_case,
    to_snake_case,
)
from gen_protocol.adapters.idl.yaml_loader import YamlSpecLoader
from gen_protocol.application.compiler_service import ProtocolCompilerService
from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.domain.models import Enum, Field, Message, Protocol
from gen_protocol.domain.types import PATTERNS


class TestProtobufEmitterUnit(unittest.TestCase):
    def setUp(self):
        self.fields = [
            Field(name="session_id", ctype="uint32_t", comment="Session identifier"),
            Field(name="flags", ctype="uint8_t", bits=3, comment="3-bit control flags"),
            Field(name="ratio", ctype="float", comment="Speed ratio"),
            Field(name="coords", ctype="double", array_size=3, comment="3D Coordinates"),
            Field(name="raw_buf", ctype="uint8_t", array_size=64, comment="Raw buffer"),
        ]
        self.msg1 = Message(
            name="TEST_MSG_CONNECT",
            opcode=0x0001,
            fields=self.fields,
            direction="C->S",
            description="Client connection request"
        )
        self.msg2 = Message(
            name="TEST_MSG_ACK",
            opcode=0x0002,
            fields=[Field(name="status", ctype="uint16_t", comment="Status code")],
            direction="S->C",
            description="Server acknowledgement"
        )
        self.enums = [
            Enum(name="TEST_STATUS_t", members=[("STATUS_OK", 0), ("STATUS_ERR", 1)])
        ]
        self.proto = Protocol(
            name="NEXUS_LINK",
            version_major=1,
            version_minor=2,
            version_patch=3,
            magic=0x12345678,
            pattern="rpc",
            seed="a" * 32,
            messages=[self.msg1, self.msg2],
            enums=self.enums,
            header_struct_name="nexus_link_hdr_t",
            max_payload_size=1024,
            endian="little",
            description="Nexus Link RPC Protocol",
            auth=None
        )

    def test_helpers(self):
        self.assertEqual(to_pascal_case("test_proto_msg_connect"), "TestProtoMsgConnect")
        self.assertEqual(to_pascal_case("MY_PROTO_STATUS_t"), "MyProtoStatus")
        self.assertEqual(to_pascal_case("CONNECT"), "Connect")
        self.assertEqual(to_snake_case("ConnectRequest"), "connect_request")
        self.assertEqual(to_snake_case("TEST_PROTO"), "test_proto")
        self.assertTrue(sanitize_proto_field_name("message").endswith("_val"))
        self.assertEqual(prefix_enum_member("OK", "MY_PROTO_STATUS"), "MY_PROTO_STATUS_OK")
        self.assertEqual(prefix_enum_member("STATUS_OK", "MY_PROTO_STATUS"), "MY_PROTO_STATUS_OK")

    def test_protobuf_header_and_options(self):
        emitter = ProtobufEmitter(self.proto)
        text = emitter.emit()

        self.assertIn('syntax = "proto3";', text)
        self.assertIn("package nexus_link;", text)
        self.assertIn('option go_package = "./nexus_linkpb";', text)
        self.assertIn('option java_package = "com.protocol.nexus_link";', text)
        self.assertIn('option csharp_namespace = "NexusLink";', text)
        self.assertIn("Magic       : 0x12345678", text)

    def test_protobuf_enums(self):
        emitter = ProtobufEmitter(self.proto)
        text = emitter.emit()

        self.assertIn("enum TestStatus {", text)
        self.assertIn("TEST_STATUS_OK = 0;", text)
        self.assertIn("TEST_STATUS_ERR = 1;", text)

    def test_protobuf_enum_without_zero_injects_unspecified(self):
        proto_no_zero = Protocol(
            name="TEST_NO_ZERO",
            version_major=1,
            version_minor=0,
            version_patch=0,
            magic=0xABCDEF01,
            pattern="reqrsp",
            seed="b" * 32,
            messages=[self.msg1],
            enums=[Enum(name="CODE_t", members=[("FIRST", 1), ("SECOND", 2)])],
            header_struct_name="test_hdr_t",
            max_payload_size=512,
            endian="big",
            description="Test with non-zero enums"
        )
        emitter = ProtobufEmitter(proto_no_zero)
        text = emitter.emit()

        self.assertIn("enum Code {", text)
        self.assertIn("CODE_UNSPECIFIED = 0;", text)
        self.assertIn("CODE_FIRST = 1;", text)
        self.assertIn("CODE_SECOND = 2;", text)

    def test_protobuf_enum_duplicate_values_allow_alias(self):
        proto_dup = Protocol(
            name="TEST_DUP",
            version_major=1,
            version_minor=0,
            version_patch=0,
            magic=0xABCDEF02,
            pattern="reqrsp",
            seed="c" * 32,
            messages=[self.msg1],
            enums=[Enum(name="MODE_t", members=[("DEFAULT", 0), ("NORMAL", 0), ("FAST", 1)])],
            header_struct_name="test_hdr_t",
            max_payload_size=512,
            endian="big",
            description="Test with duplicate enum values"
        )
        emitter = ProtobufEmitter(proto_dup)
        text = emitter.emit()

        self.assertIn("enum Mode {", text)
        self.assertIn("option allow_alias = true;", text)
        self.assertIn("MODE_DEFAULT = 0;", text)
        self.assertIn("MODE_NORMAL = 0;", text)
        self.assertIn("MODE_FAST = 1;", text)

    def test_protobuf_wire_header_and_auth(self):
        self.proto.auth = "hmac-sha256"
        emitter = ProtobufEmitter(self.proto)
        text = emitter.emit()

        self.assertIn("message Header {", text)
        self.assertIn("uint32 magic = 1;", text)
        self.assertIn("uint32 version = 2;", text)
        self.assertIn("uint32 opcode = 3;", text)
        self.assertIn("uint32 session_id = 4;", text)
        self.assertIn("uint32 sequence = 5;", text)
        self.assertIn("uint32 payload_len = 6;", text)
        self.assertIn("uint32 crc32 = 7;", text)
        self.assertIn("bytes auth_tag = 8;", text)

    def test_protobuf_message_types_and_fields(self):
        emitter = ProtobufEmitter(self.proto)
        text = emitter.emit()

        self.assertIn("message TestMsgConnect {", text)
        self.assertIn("uint32 session_id = 1;", text)
        self.assertIn("uint32 flags = 2;", text)
        self.assertIn("Bitfield width: 3 bits", text)
        self.assertIn("float ratio = 3;", text)
        self.assertIn("repeated double coords = 4;", text)
        self.assertIn("bytes raw_buf = 5;", text)
        self.assertIn("Fixed array size: 64 bytes", text)

    def test_protobuf_frame_envelope_and_service(self):
        emitter = ProtobufEmitter(self.proto)
        text = emitter.emit()

        self.assertIn("message Frame {", text)
        self.assertIn("Header header = 1;", text)
        self.assertIn("oneof payload {", text)
        self.assertIn("TestMsgConnect msg_test_msg_connect = 2;", text)
        self.assertIn("TestMsgAck msg_test_msg_ack = 3;", text)
        self.assertIn("bytes raw_payload = 4;", text)

        self.assertIn("service NexusLinkService {", text)
        self.assertIn("rpc Exchange (Frame) returns (Frame);", text)

    def test_protobuf_patterns_service_rpc(self):
        # Stream pattern
        proto_stream = Protocol(
            name="TEST_STREAM",
            version_major=1,
            version_minor=0,
            version_patch=0,
            magic=0x11223344,
            pattern="stream",
            seed="d" * 32,
            messages=[self.msg1],
            enums=[],
            header_struct_name="stream_hdr_t",
            max_payload_size=512,
            endian="little",
            description="Streaming protocol"
        )
        stream_text = ProtobufEmitter(proto_stream).emit()
        self.assertIn("rpc StreamFrames (stream Frame) returns (stream Frame);", stream_text)

        # PubSub pattern
        proto_pubsub = Protocol(
            name="TEST_PUBSUB",
            version_major=1,
            version_minor=0,
            version_patch=0,
            magic=0x55667788,
            pattern="pubsub",
            seed="e" * 32,
            messages=[self.msg1],
            enums=[],
            header_struct_name="pubsub_hdr_t",
            max_payload_size=512,
            endian="little",
            description="PubSub protocol"
        )
        pubsub_text = ProtobufEmitter(proto_pubsub).emit()
        self.assertIn("rpc Publish (Frame) returns (Frame);", pubsub_text)
        self.assertIn("rpc Subscribe (Frame) returns (stream Frame);", pubsub_text)


class TestProtobufCompilerIntegration(unittest.TestCase):
    def test_compile_from_spec_with_proto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "sample_out"
            service = ProtocolCompilerService(out_dir=out_path)
            proto = service.compile_from_spec(
                Path("sample_idl.yaml"),
                proto=True
            )
            proto_file = out_path / "my_proto.proto"
            self.assertTrue(proto_file.exists())
            content = proto_file.read_text()
            self.assertIn('syntax = "proto3";', content)
            self.assertIn("package my_proto;", content)
            self.assertIn("service MyProtoService", content)

    def test_generate_random_with_proto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "random_out"
            service = ProtocolCompilerService(out_dir=out_path)
            proto = service.generate_random(
                name_hint="TEST_PB_GEN",
                seed_hex="1234567890abcdef1234567890abcdef",
                proto=True
            )
            proto_file = out_path / "test_pb_gen.proto"
            self.assertTrue(proto_file.exists())
            content = proto_file.read_text()
            self.assertIn('syntax = "proto3";', content)
            self.assertIn("package test_pb_gen;", content)

    def test_generate_multichain_with_proto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            suite_dir = Path(tmpdir) / "suite_out"
            service = ProtocolCompilerService(out_dir=suite_dir)
            suite = service.generate_multichain(
                2,
                name_prefix="PB_CHAIN",
                seed_hex="fedcba0987654321fedcba0987654321",
                proto=True
            )
            for proto in suite.protocols:
                p_file = suite_dir / proto.name.lower() / f"{proto.name.lower()}.proto"
                self.assertTrue(p_file.exists())
                content = p_file.read_text()
                self.assertIn('syntax = "proto3";', content)


class TestProtocValidation(unittest.TestCase):
    def setUp(self):
        self.has_protoc = shutil.which("protoc") is not None

    def test_protoc_compiles_all_patterns(self):
        if not self.has_protoc:
            self.skipTest("protoc compiler not installed on system")

        with tempfile.TemporaryDirectory() as tmpdir:
            for pattern in PATTERNS:
                for idx in range(3):
                    seed = f"{pattern}_{idx:02d}_" + "1" * 20
                    gen = ProtocolGenerator(Random(idx + 1), seed)
                    proto = gen.generate(pattern=pattern)
                    pb_text = ProtobufEmitter(proto).emit()

                    p_file = Path(tmpdir) / f"{proto.name.lower()}.proto"
                    p_file.write_text(pb_text)

                    desc_file = Path(tmpdir) / f"{proto.name.lower()}.desc"
                    res = subprocess.run(
                        ["protoc", f"-I={tmpdir}", f"--descriptor_set_out={desc_file}", str(p_file)],
                        capture_output=True,
                        text=True
                    )
                    self.assertEqual(
                        res.returncode, 0,
                        f"protoc compilation failed for {proto.name} (pattern: {pattern}):\n{res.stderr}\nSchema:\n{pb_text}"
                    )

    def test_protoc_compiles_sample_idl(self):
        if not self.has_protoc:
            self.skipTest("protoc compiler not installed on system")

        proto = YamlSpecLoader().load(Path("sample_idl.yaml"))
        pb_text = ProtobufEmitter(proto).emit()

        with tempfile.TemporaryDirectory() as tmpdir:
            p_file = Path(tmpdir) / "sample.proto"
            p_file.write_text(pb_text)
            desc_file = Path(tmpdir) / "sample.desc"
            res = subprocess.run(
                ["protoc", f"-I={tmpdir}", f"--descriptor_set_out={desc_file}", str(p_file)],
                capture_output=True,
                text=True
            )
            self.assertEqual(res.returncode, 0, f"protoc failed on sample_idl.yaml:\n{res.stderr}")


if __name__ == "__main__":
    unittest.main()
