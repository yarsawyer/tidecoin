#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for Tidecoin v2 P2P protocol helpers."""

import random

from .crypto.bip324_cipher import FSChaCha20Poly1305
from .crypto.chacha20 import FSChaCha20
from .crypto.hkdf import hkdf_sha256
from .crypto.kyber_py.ml_kem.default_parameters import ML_KEM_512
from .messages import MAGIC_BYTES


CHACHA20POLY1305_EXPANSION = 16
HEADER_LEN = 1
IGNORE_BIT_POS = 7
LENGTH_FIELD_LEN = 3
MAX_GARBAGE_LEN = 4095
KEM_PUBLIC_KEY_LEN = 800
KEM_CIPHERTEXT_LEN = 768

SHORTID = {
    1: b"addr",
    2: b"block",
    3: b"blocktxn",
    4: b"cmpctblock",
    5: b"feefilter",
    6: b"filteradd",
    7: b"filterclear",
    8: b"filterload",
    9: b"getblocks",
    10: b"getblocktxn",
    11: b"getdata",
    12: b"getheaders",
    13: b"headers",
    14: b"inv",
    15: b"mempool",
    16: b"merkleblock",
    17: b"notfound",
    18: b"ping",
    19: b"pong",
    20: b"sendcmpct",
    21: b"tx",
    22: b"getcfilters",
    23: b"cfilter",
    24: b"getcfheaders",
    25: b"cfheaders",
    26: b"getcfcheckpt",
    27: b"cfcheckpt",
    28: b"addrv2",
}

# Dictionary which contains short message type ID for the P2P message
MSGTYPE_TO_SHORTID = {msgtype: shortid for shortid, msgtype in SHORTID.items()}


class EncryptedP2PState:
    """State for Tidecoin's ML-KEM based v2 transport in functional tests."""

    def __init__(self, *, initiating, net):
        self.initiating = initiating
        self.net = net
        self.peer = {}

        self.sent_garbage = b""
        self.received_garbage = b""
        self.received_prefix = b""

        self.tried_v2_handshake = False
        self.contents_len = -1
        self.found_garbage_terminator = False
        self.transport_version = b""

        self.ellswift_ours = b""
        self._dk_ours = b""
        self._v2_detected = initiating

    def _generate_garbage(self, garbage_len=None):
        if garbage_len is None:
            garbage_len = random.randrange(MAX_GARBAGE_LEN + 1)
        self.sent_garbage = random.randbytes(garbage_len)

    def generate_keypair_and_garbage(self, garbage_len=None):
        """Generates ML-KEM keypair + garbage; keeps legacy field name for tests."""
        ek, dk = ML_KEM_512.keygen()
        self.ellswift_ours = ek
        self._dk_ours = dk
        self._generate_garbage(garbage_len)
        return ek + self.sent_garbage

    def initiate_v2_handshake(self):
        """Initiator sends ML-KEM public key and garbage."""
        return self.generate_keypair_and_garbage()

    def respond_v2_handshake(self, response):
        """Responder waits for v1-prefix mismatch, then for full ML-KEM pubkey."""
        processed = 0
        v1_prefix = MAGIC_BYTES[self.net] + b"version\x00\x00\x00\x00\x00"

        if not self._v2_detected:
            while len(self.received_prefix) < len(v1_prefix):
                byte = response.read(1)
                if not byte:
                    return processed, b""
                processed += 1
                self.received_prefix += byte
                idx = len(self.received_prefix) - 1
                if byte != v1_prefix[idx:idx + 1]:
                    self._v2_detected = True
                    # Keep all bytes consumed so far. They are the beginning of
                    # the ML-KEM public key in v2 mode.
                    break
            if not self._v2_detected and len(self.received_prefix) == len(v1_prefix):
                return processed, -1

        need = KEM_PUBLIC_KEY_LEN - len(self.received_prefix)
        if need > 0:
            tail = response.read(need)
            self.received_prefix += tail
            processed += len(tail)
        if len(self.received_prefix) < KEM_PUBLIC_KEY_LEN:
            return processed, b""

        their_pk = self.received_prefix[:KEM_PUBLIC_KEY_LEN]
        shared_secret, ciphertext = ML_KEM_512.encaps(their_pk)
        self.initialize_v2_transport(shared_secret)
        self._generate_garbage()

        msg_to_send = ciphertext + self.sent_garbage
        msg_to_send += self.peer["send_garbage_terminator"]
        msg_to_send += self.v2_enc_packet(self.transport_version, aad=self.sent_garbage)
        return processed, msg_to_send

    def complete_handshake(self, response):
        """Initiator receives ciphertext and responds with terminator+version."""
        if not self.initiating:
            return 0, b""

        ciphertext = self.received_prefix + response.read(KEM_CIPHERTEXT_LEN - len(self.received_prefix))
        if len(ciphertext) != KEM_CIPHERTEXT_LEN:
            self.received_prefix = ciphertext
            return 0, b""

        shared_secret = ML_KEM_512.decaps(self._dk_ours, ciphertext)
        self.initialize_v2_transport(shared_secret)

        msg_to_send = self.peer["send_garbage_terminator"]
        msg_to_send += self.v2_enc_packet(self.transport_version, aad=self.sent_garbage)
        self.received_prefix = b""
        return KEM_CIPHERTEXT_LEN, msg_to_send

    def authenticate_handshake(self, response):
        """Authenticate garbage and first non-decoy version packet."""
        processed_length = 0

        if not self.found_garbage_terminator:
            received_garbage = response[:16]
            response = response[16:]
            processed_length = len(received_garbage)
            for _ in range(MAX_GARBAGE_LEN + 1):
                if len(received_garbage) >= 16 and received_garbage[-16:] == self.peer["recv_garbage_terminator"]:
                    self.found_garbage_terminator = True
                    self.received_garbage = received_garbage[:-16]
                    break
                if len(response) == 0:
                    return 0, True
                received_garbage += response[:1]
                processed_length += 1
                response = response[1:]
            else:
                return processed_length, False

        while not self.tried_v2_handshake:
            length, contents = self.v2_receive_packet(response, aad=self.received_garbage)
            if length == -1:
                return processed_length, False
            if length == 0:
                return processed_length, True
            processed_length += length
            self.received_garbage = b""
            if contents is not None:
                self.tried_v2_handshake = True
                return processed_length, True
            response = response[length:]

        return processed_length, True

    def initialize_v2_transport(self, shared_secret):
        """Derive stream/AEAD keys and session fields from shared secret."""
        peer = {}
        salt = b"tidecoin_v2_kem" + MAGIC_BYTES[self.net]
        for name in (
            "initiator_L",
            "initiator_P",
            "responder_L",
            "responder_P",
            "garbage_terminators",
            "session_id",
        ):
            peer[name] = hkdf_sha256(
                salt=salt,
                ikm=shared_secret,
                info=name.encode("utf-8"),
                length=32,
            )

        if self.initiating:
            self.peer["send_L"] = FSChaCha20(peer["initiator_L"])
            self.peer["send_P"] = FSChaCha20Poly1305(peer["initiator_P"])
            self.peer["send_garbage_terminator"] = peer["garbage_terminators"][:16]
            self.peer["recv_L"] = FSChaCha20(peer["responder_L"])
            self.peer["recv_P"] = FSChaCha20Poly1305(peer["responder_P"])
            self.peer["recv_garbage_terminator"] = peer["garbage_terminators"][16:]
        else:
            self.peer["send_L"] = FSChaCha20(peer["responder_L"])
            self.peer["send_P"] = FSChaCha20Poly1305(peer["responder_P"])
            self.peer["send_garbage_terminator"] = peer["garbage_terminators"][16:]
            self.peer["recv_L"] = FSChaCha20(peer["initiator_L"])
            self.peer["recv_P"] = FSChaCha20Poly1305(peer["initiator_P"])
            self.peer["recv_garbage_terminator"] = peer["garbage_terminators"][:16]

        self.peer["session_id"] = peer["session_id"]

    def v2_enc_packet(self, contents, aad=b"", ignore=False):
        """Encrypt one Tidecoin v2 packet."""
        assert len(contents) <= 2**24 - 1
        header = (ignore << IGNORE_BIT_POS).to_bytes(HEADER_LEN, "little")
        plaintext = header + contents
        aead_ciphertext = self.peer["send_P"].encrypt(aad, plaintext)
        enc_len = self.peer["send_L"].crypt(len(contents).to_bytes(LENGTH_FIELD_LEN, "little"))
        return enc_len + aead_ciphertext

    def v2_receive_packet(self, response, aad=b""):
        """Decrypt one Tidecoin v2 packet.

        Returns:
        1. bytes consumed or -1 on auth failure
        2. decrypted contents for non-decoy packets; None for decoy/incomplete
        """
        if self.contents_len == -1:
            if len(response) < LENGTH_FIELD_LEN:
                return 0, None
            enc_len = response[:LENGTH_FIELD_LEN]
            self.contents_len = int.from_bytes(self.peer["recv_L"].crypt(enc_len), "little")

        response = response[LENGTH_FIELD_LEN:]
        need = HEADER_LEN + self.contents_len + CHACHA20POLY1305_EXPANSION
        if len(response) < need:
            return 0, None

        aead_ciphertext = response[:need]
        plaintext = self.peer["recv_P"].decrypt(aad, aead_ciphertext)
        if plaintext is None:
            return -1, None

        header = plaintext[:HEADER_LEN]
        length = LENGTH_FIELD_LEN + need
        self.contents_len = -1
        if header[0] & (1 << IGNORE_BIT_POS):
            return length, None
        return length, plaintext[HEADER_LEN:]
