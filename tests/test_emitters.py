"""
Unit tests for C, Promela, JSON, YAML, and Markdown Emitters.
"""

import json
import unittest
from random import Random

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.domain.models import Enum, Field, Message, MultiChainSuite, Protocol
from gen_protocol.adapters.emitters.c_header import CHeaderEmitter
from gen_protocol.adapters.emitters.c_source import CSourceEmitter
from gen_protocol.adapters.emitters.promela import PromelaEmitter
from gen_protocol.adapters.emitters.markdown_doc import MarkdownDocEmitter
from gen_protocol.adapters.emitters.json_manifest import JsonManifestEmitter
from gen_protocol.adapters.emitters.yaml_spec import YamlSpecEmitter
from gen_protocol.adapters.emitters.protobuf import ProtobufEmitter
from gen_protocol.adapters.emitters.multichain_doc import MultiChainMarkdownEmitter
from gen_protocol.adapters.emitters.multichain_manifest import MultiChainManifestEmitter


class TestEmittersUnit(unittest.TestCase):
    def setUp(self):
        self.fields_msg1 = [
            Field(name="session_id", ctype="uint32_t", comment="Session ID"),
            Field(name="flags", ctype="uint8_t", bits=3, comment="3-bit flags"),
            Field(name="mode", ctype="uint8_t", bits=5, comment="5-bit mode"),
            Field(name="ratio", ctype="float", comment="Ratio"),
            Field(name="coords", ctype="double", array_size=3, comment="3D Coordinates"),
            Field(name="raw_buf", ctype="uint8_t", array_size=64, comment="Buffer"),
        ]
        self.msg1 = Message(
            name="TEST_PROTO_MSG_CONNECT",
            opcode=0x0001,
            fields=self.fields_msg1,
            direction="C->S",
            description="Client connect frame"
        )
        self.msg2 = Message(
            name="TEST_PROTO_MSG_ACK",
            opcode=0x0002,
            fields=[Field(name="status", ctype="uint16_t", comment="Status code")],
            direction="S->C",
            description="Server ack frame"
        )
        self.enums = [
            Enum(name="TEST_STATUS_t", members=[("STATUS_OK", 0), ("STATUS_ERR", 1)])
        ]
        self.proto_le = Protocol(
            name="TEST_LE",
            version_major=1,
            version_minor=2,
            version_patch=3,
            magic=0x12345678,
            pattern="reqrsp",
            seed="a"*32,
            messages=[self.msg1, self.msg2],
            enums=self.enums,
            header_struct_name="test_le_hdr_t",
            max_payload_size=1024,
            endian="little",
            description="Little-endian test protocol"
        )
        self.proto_be = Protocol(
            name="TEST_BE",
            version_major=2,
            version_minor=0,
            version_patch=0,
            magic=0x87654321,
            pattern="fsm",
            seed="b"*32,
            messages=[self.msg1, self.msg2],
            enums=self.enums,
            header_struct_name="test_be_hdr_t",
            max_payload_size=2048,
            endian="big",
            description="Big-endian test protocol"
        )

    def test_c_header_emitter_guards_and_macros(self):
        emitter = CHeaderEmitter(self.proto_le)
        header_text = emitter.emit()

        # Header guards
        self.assertIn("#ifndef TEST_LE_H_", header_text)
        self.assertIn("#define TEST_LE_H_", header_text)

        # Magic and Version
        self.assertIn("TEST_LE_MAGIC", header_text)
        self.assertIn("0x12345678U", header_text)
        self.assertIn("TEST_LE_VERSION_MAJOR", header_text)
        self.assertIn("TEST_LE_VERSION_MINOR", header_text)

        # Opcode defines
        self.assertIn("TEST_PROTO_MSG_CONNECT", header_text)
        self.assertIn("0x0001U", header_text)
        self.assertIn("TEST_PROTO_MSG_ACK", header_text)
        self.assertIn("0x0002U", header_text)

        # Bitfield macros
        self.assertIn("TEST_LE_GET_TEST_PROTO_MSG_CONNECT_FLAGS", header_text)
        self.assertIn("TEST_LE_SET_TEST_PROTO_MSG_CONNECT_FLAGS", header_text)
        self.assertIn("TEST_LE_GET_TEST_PROTO_MSG_CONNECT_MODE", header_text)

        # Float helpers guard
        self.assertIn("#ifndef PROTO_FLOAT_HELPERS_", header_text)
        self.assertIn("proto_f32_to_u32_", header_text)
        self.assertIn("proto_u64_to_f64_", header_text)

        # Packed wire header struct (22 bytes)
        self.assertIn("typedef struct PROTO_PACKED {", header_text)
        self.assertIn("magic;", header_text)
        self.assertIn("version;", header_text)
        self.assertIn("opcode;", header_text)
        self.assertIn("session_id;", header_text)
        self.assertIn("sequence;", header_text)
        self.assertIn("payload_len;", header_text)
        self.assertIn("crc32;", header_text)
        self.assertIn("test_le_hdr_t;", header_text)

    def test_c_source_emitter_functions(self):
        emitter = CSourceEmitter(self.proto_le)
        c_text = emitter.emit()

        # Check API functions exist
        self.assertIn("void test_le_hdr_init(", c_text)
        self.assertIn("void test_le_hdr_encode(", c_text)
        self.assertIn("void test_le_hdr_decode(", c_text)
        self.assertIn("int test_le_hdr_validate(", c_text)
        self.assertIn("uint32_t test_le_crc32(", c_text)
        self.assertIn("uint32_t test_le_frame_crc(", c_text)

        # Check error enum mapping in validation
        self.assertIn("return TEST_LE_HDR_ERR_MAGIC;", c_text)
        self.assertIn("return TEST_LE_HDR_ERR_VERSION;", c_text)
        self.assertIn("return TEST_LE_HDR_ERR_PAYLOAD_TOO_BIG;", c_text)
        self.assertIn("return TEST_LE_HDR_ERR_LEN_MISMATCH;", c_text)
        self.assertIn("return TEST_LE_HDR_ERR_CRC;", c_text)
        self.assertIn("return TEST_LE_HDR_ERR_OPCODE;", c_text)

        # Check payload encode/decode functions
        self.assertIn("void test_proto_msg_connect_encode(", c_text)
        self.assertIn("void test_proto_msg_connect_decode(", c_text)
        self.assertIn("void test_proto_msg_ack_encode(", c_text)
        self.assertIn("void test_proto_msg_ack_decode(", c_text)

    def test_promela_emitter_model(self):
        emitter = PromelaEmitter(self.proto_be)
        pml_text = emitter.emit()

        self.assertIn("mtype = {", pml_text)
        self.assertIn("TEST_PROTO_MSG_CONNECT,", pml_text)
        self.assertIn("TEST_PROTO_MSG_ACK", pml_text)
        self.assertIn("chan c2s", pml_text)
        self.assertIn("chan s2c", pml_text)
        self.assertIn("proctype FSMClient(", pml_text)
        self.assertIn("proctype FSMServer(", pml_text)
        self.assertIn("ltl prop_opcode_valid", pml_text)
        self.assertIn("ltl prop_no_chan_overflow", pml_text)

    def test_json_manifest_emitter(self):
        emitter = JsonManifestEmitter(self.proto_le)
        manifest_text = emitter.emit()
        data = json.loads(manifest_text)

        self.assertEqual(data["name"], "TEST_LE")
        self.assertEqual(data["magic"], "0x12345678")
        self.assertEqual(data["endian"], "little")
        self.assertEqual(len(data["messages"]), 2)
        self.assertEqual(data["messages"][0]["name"], "TEST_PROTO_MSG_CONNECT")
        self.assertEqual(data["messages"][0]["opcode"], "0x0001")

    def test_yaml_spec_emitter(self):
        emitter = YamlSpecEmitter(self.proto_le)
        yaml_text = emitter.emit()

        self.assertIn("name: TEST_LE", yaml_text)
        self.assertIn("endian: little", yaml_text)
        self.assertIn("pattern: reqrsp", yaml_text)
        self.assertIn("name: TEST_PROTO_MSG_CONNECT", yaml_text)
        self.assertIn("0x0001", yaml_text)

    def test_markdown_doc_emitter(self):
        emitter = MarkdownDocEmitter(self.proto_le)
        doc_text = emitter.emit()

        self.assertIn("# TEST_LE Binary Protocol Specification", doc_text)
        self.assertIn("## 2. Common Wire Header (22 Bytes)", doc_text)
        self.assertIn("`0x12345678`", doc_text)
        self.assertIn("TEST_PROTO_MSG_CONNECT", doc_text)
        self.assertIn("## 4. Message Payloads", doc_text)

    def test_protobuf_emitter(self):
        emitter = ProtobufEmitter(self.proto_le)
        proto_text = emitter.emit()

        self.assertIn('syntax = "proto3";', proto_text)
        self.assertIn("package test_le;", proto_text)
        self.assertIn("enum TestStatus", proto_text)
        self.assertIn("STATUS_OK = 0;", proto_text)
        self.assertIn("enum Opcode {", proto_text)
        self.assertIn("OPCODE_UNSPECIFIED = 0;", proto_text)
        self.assertIn("OPCODE_TEST_PROTO_MSG_CONNECT = 1;", proto_text)
        self.assertIn("message Header {", proto_text)
        self.assertIn("message TestProtoMsgConnect {", proto_text)
        self.assertIn("bytes raw_buf = 6;", proto_text)
        self.assertIn("message Frame {", proto_text)
        self.assertIn("oneof payload {", proto_text)
        self.assertIn("service TestLeService {", proto_text)
        self.assertIn("rpc Exchange (Frame) returns (Frame);", proto_text)

    def test_multichain_emitters(self):
        gen = ProtocolGenerator(Random(42), "42"*16)
        suite = gen.generate_multichain(2, name_prefix="TEST_CHAIN")

        doc_emitter = MultiChainMarkdownEmitter(suite)
        doc_text = doc_emitter.emit()
        self.assertIn("# MULTICHAIN_TEST_CHAIN MultiChain Protocol Suite Specification", doc_text)
        self.assertIn("[TEST_CHAIN_LINK_1] ---> [TEST_CHAIN_LINK_2]", doc_text)

        manifest_emitter = MultiChainManifestEmitter(suite)
        manifest_text = manifest_emitter.emit()
        manifest_data = json.loads(manifest_text)
        self.assertEqual(manifest_data["suite_name"], "MULTICHAIN_TEST_CHAIN")
        self.assertEqual(manifest_data["chain_count"], 2)
        self.assertEqual(len(manifest_data["protocols"]), 2)


if __name__ == "__main__":
    unittest.main()
