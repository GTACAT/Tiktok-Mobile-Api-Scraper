#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import time
import json
import random
import os
import gzip
import hashlib
import binascii
import ctypes
import re
from urllib.parse import urlencode, quote, parse_qs, urlparse
from typing import Dict, List, Any, Optional, Tuple
from base64 import b64encode
from struct import unpack
from os import urandom

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("ERROR: PyCryptodome library not found. Please install it: pip install pycryptodome")
    AES = None
    pad = None
    unpad = None

try:
    from curl_cffi.requests import Session as CurlSession
except ImportError:
    print("ERROR: The 'curl_cffi' library is required for the new secUid extraction.")
    print("Please install it with: pip install curl_cffi")
    CurlSession = None


INTERNAL_MAX_POST_LIMIT = 10000
DEFAULT_USER_AGENT_ANDROID = 'com.zhiliaoapp.musically/2023905050 (Linux; U; Android 9; en_US; SM-G975N; Build/PQ3A.190605.03202111;tt-ok/3.12.13.17)'

class PKCS7Padding:
    @staticmethod
    def pkcs7_padding_data_length(buffer, buffer_size, modulus):
        if buffer_size == 0:
            return 0
        if buffer_size % modulus != 0 or buffer_size < modulus:
            return 0
        padding_value = buffer[buffer_size-1]
        if padding_value < 1 or padding_value > modulus:
            return 0

        for i in range(1, padding_value + 1):
            if buffer_size - i < 0 or buffer[buffer_size - i] != padding_value:
                return 0
        return buffer_size - padding_value


    @staticmethod
    def pkcs7_padding_pad_buffer(buffer: bytearray, data_length: int, buffer_size: int, modulus: int) -> int:
        pad_byte = modulus - (data_length % modulus)
        if data_length + pad_byte > buffer_size:
            return -pad_byte
        for i in range(pad_byte):
            buffer[data_length+i] = pad_byte
        return pad_byte

    @staticmethod
    def padding_size(size: int, modulus: int = 16) -> int:
        mod = size % modulus
        if mod > 0:
            return size + (modulus - mod)
        return size

from enum import IntEnum, unique

class ProtoError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return repr(self.msg)

@unique
class ProtoFieldType(IntEnum):
    VARINT = 0
    FIXED64 = 1
    STRING = 2
    GROUPSTART = 3
    GROUPEND = 4
    FIXED32 = 5

class ProtoField:
    def __init__(self, idx, type_val, val):
        self.idx = idx
        self.type = type_val
        self.val = val

    def isAsciiStr(self):
        if (type(self.val) != bytes):
            return False
        try:
            for b_val in self.val:
                if not (0x20 <= b_val <= 0x7E or b_val in [0x09, 0x0A, 0x0D]):
                    return False
            return True
        except Exception:
            return False


    def __str__(self):
        if (self.type == ProtoFieldType.VARINT or \
            self.type == ProtoFieldType.FIXED32 or \
            self.type == ProtoFieldType.FIXED64):
            return '%d(%s): %d' % (self.idx, self.type.name, self.val)
        elif self.type == ProtoFieldType.STRING:
            if self.isAsciiStr():
                try:
                    return '%d(%s): "%s"' % (self.idx, self.type.name, self.val.decode('ascii'))
                except UnicodeDecodeError:
                    return '%d(%s): h"%s"' % (self.idx, self.type.name, self.val.hex())
            else:
                return '%d(%s): h"%s"' % (self.idx, self.type.name, self.val.hex())
        elif ((self.type == ProtoFieldType.GROUPSTART) or (self.type == ProtoFieldType.GROUPEND)):
            return '%d(%s): %s' % (self.idx, self.type.name, self.val)
        else:
            return '%d(UNKNOWN_TYPE_%s): %s' % (self.idx, self.type.value, self.val)


class ProtoReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def seek(self, pos):
        self.pos = pos

    def isRemain(self, length):
        return self.pos + length <= len(self.data)

    def read0(self):
        if not self.isRemain(1): raise ProtoError("Not enough data to read byte")
        ret = self.data[self.pos]
        self.pos += 1
        return ret & 0xFF

    def read(self, length):
        if not self.isRemain(length): raise ProtoError(f"Not enough data to read {length} bytes")
        ret = self.data[self.pos:self.pos+length]
        self.pos += length
        return ret

    def readFixed32(self):
        return int.from_bytes(self.read(4), byteorder='little', signed=False)

    def readFixed64(self):
        return int.from_bytes(self.read(8), byteorder='little', signed=False)

    def readVarint(self):
        vint = 0
        n = 0
        while True:
            byte = self.read0()
            vint |= ((byte & 0x7F) << (7 * n))
            if byte < 0x80:
                break
            n += 1
            if n > 10: raise ProtoError("Varint too long (max 10 bytes for 64-bit)")
        return vint

    def readString(self):
        str_len = self.readVarint()
        return self.read(str_len)

class ProtoWriter:
    def __init__(self):
        self.data = bytearray()

    def write0(self, byte):
        self.data.append(byte & 0xFF)

    def write(self, bytes_data):
        self.data.extend(bytes_data)

    def writeFixed32(self, fixed32_val):
        bs = fixed32_val.to_bytes(4, byteorder='little', signed=False)
        self.write(bs)

    def writeFixed64(self, fixed64_val):
        bs = fixed64_val.to_bytes(8, byteorder='little', signed=False)
        self.write(bs)

    def writeVarint(self, vint):
        while (vint >= 0x80):
            self.write0((vint & 0x7F) | 0x80)
            vint >>= 7
        self.write0(vint & 0x7F)

    def writeString(self, bytes_data):
        self.writeVarint(len(bytes_data))
        self.write(bytes_data)

    def toBytes(self):
        return bytes(self.data)

class ProtoBuf:
    def __init__(self, data=None):
        self.fields = list[ProtoField]()
        if (data != None):
            if (type(data) != bytes and type(data) != dict):
                raise ProtoError('unsupport type(%s) to protobuf' % (type(data)))
            if (type(data) == bytes) and (len(data) > 0):
                self.__parseBuf(data)
            elif (type(data) == dict) and (len(data) > 0):
                self.__parseDict(data)

    def __getitem__(self, idx_or_key):
        if isinstance(idx_or_key, str):
            raise NotImplementedError("String key access not directly supported from binary protobuf.")

        idx = int(idx_or_key)
        pf = self.get(idx)
        if (pf == None): return None
        if (pf.type != ProtoFieldType.STRING): return pf.val
        if (pf.val == None): return None
        try:
            return ProtoBuf(pf.val)
        except ProtoError:
            try:
                return pf.val.decode('utf-8')
            except UnicodeDecodeError:
                return pf.val


    def __parseBuf(self, bytes_data):
        reader = ProtoReader(bytes_data)
        while reader.isRemain(1):
            key = reader.readVarint()
            field_type_val = key & 0x7

            try:
                field_type = ProtoFieldType(field_type_val)
            except ValueError:
                 print(f"Warning: Unknown field type value {field_type_val} at pos {reader.pos-1}. Attempting to skip.")
                 if field_type_val == 0: reader.readVarint()
                 elif field_type_val == 1: reader.read(8)
                 elif field_type_val == 2: reader.readString()
                 elif field_type_val == 5: reader.read(4)
                 else: raise ProtoError(f"Cannot skip unknown field type value {field_type_val}")
                 continue

            field_idx = key >> 3
            if (field_idx == 0 ):
                break

            if (field_type == ProtoFieldType.FIXED32):
                self.put(ProtoField(field_idx, field_type, reader.readFixed32()))
            elif (field_type == ProtoFieldType.FIXED64):
                self.put(ProtoField(field_idx, field_type, reader.readFixed64()))
            elif (field_type == ProtoFieldType.VARINT):
                self.put(ProtoField(field_idx, field_type, reader.readVarint()))
            elif (field_type == ProtoFieldType.STRING):
                self.put(ProtoField(field_idx, field_type, reader.readString()))
            elif (field_type == ProtoFieldType.GROUPSTART or field_type == ProtoFieldType.GROUPEND):
                print(f"Warning: Group field type {field_type.name} encountered and skipped at index {field_idx}.")
            else:
                raise ProtoError('parse protobuf error, unhandled field type: %s' % (field_type.name))


    def toBuf(self):
        writer = ProtoWriter()
        for field in self.fields:
            key = (field.idx << 3) | (field.type.value & 7)
            writer.writeVarint(key)
            if field.type == ProtoFieldType.FIXED32:
                writer.writeFixed32(field.val)
            elif field.type == ProtoFieldType.FIXED64:
                writer.writeFixed64(field.val)
            elif field.type == ProtoFieldType.VARINT:
                writer.writeVarint(field.val)
            elif field.type == ProtoFieldType.STRING:
                writer.writeString(field.val)
            else:
                raise ProtoError('encode to protobuf error, unexpected field type: %s' % (field.type.name))
        return writer.toBytes()

    def dump(self, indent=0):
        prefix = "  " * indent
        for field in self.fields:
            if field.type == ProtoFieldType.STRING:
                try:
                    nested_pb = ProtoBuf(field.val)
                    print(f"{prefix}{field.idx}({field.type.name}): {{")
                    nested_pb.dump(indent + 1)
                    print(f"{prefix}}}")
                except (ProtoError, Exception):
                    if field.isAsciiStr():
                        try:
                            print(f"{prefix}{field.idx}({field.type.name}): \"{field.val.decode('ascii')}\"")
                        except UnicodeDecodeError:
                             print(f"{prefix}{field.idx}({field.type.name}): h\"{field.val.hex()}\" (ASCII decode failed)")
                    else:
                        print(f"{prefix}{field.idx}({field.type.name}): h\"{field.val.hex()}\"")
            else:
                 print(f"{prefix}{field}")


    def getList(self, idx):
        return [field for field in self.fields if field.idx == idx]

    def get(self, idx):
        for field in self.fields:
            if field.idx == idx:
                return field
        return None

    def getInt(self, idx, default_val=0):
        pf = self.get(idx)
        if (pf == None): return default_val
        if (pf.type == ProtoFieldType.VARINT or \
            pf.type == ProtoFieldType.FIXED32 or \
            pf.type == ProtoFieldType.FIXED64):
            return pf.val
        raise ProtoError("getInt(%d) -> type %s is not an integer type, value: %s" % (idx, pf.type, pf.val))

    def getBytes(self, idx):
        pf = self.get(idx)
        if (pf == None): return None
        if (pf.type == ProtoFieldType.STRING): return pf.val
        raise ProtoError("getBytes(%d) -> %s, value: %s" % (idx, pf.type, pf.val))

    def getUtf8(self, idx, default_val=None):
        bs = self.getBytes(idx)
        if (bs == None): return default_val
        try:
            return bs.decode('utf-8')
        except UnicodeDecodeError:
            print(f"Warning: Could not decode bytes for field {idx} as UTF-8. Returning raw bytes.")
            return bs


    def getProtoBuf(self, idx):
        bs = self.getBytes(idx)
        if (bs == None): return None
        return ProtoBuf(bs)

    def put(self, field: ProtoField):
        self.fields.append(field)

    def putFixed32(self, idx, fixed32_val):
        self.put(ProtoField(idx, ProtoFieldType.FIXED32, fixed32_val))

    def putFixed64(self, idx, fixed64_val):
        self.put(ProtoField(idx, ProtoFieldType.FIXED64, fixed64_val))

    def putVarint(self, idx, vint):
        self.put(ProtoField(idx, ProtoFieldType.VARINT, vint))

    def putBytes(self, idx, data):
        self.put(ProtoField(idx, ProtoFieldType.STRING, data))

    def putUtf8(self, idx, data_str):
        self.put(ProtoField(idx, ProtoFieldType.STRING, data_str.encode('utf-8')))

    def putProtoBuf(self, idx, data_pb):
        if not isinstance(data_pb, ProtoBuf): raise ProtoError("Value for putProtoBuf must be a ProtoBuf instance")
        self.put(ProtoField(idx, ProtoFieldType.STRING, data_pb.toBuf()))

    def __parseDict(self, data_dict):
        for k, v in data_dict.items():
            if not isinstance(k, int): raise ProtoError(f"Dictionary keys must be integers for field indices, got {k}")
            if (isinstance(v, int)):
                self.putVarint(k, v)
            elif (isinstance(v, str)):
                self.putUtf8(k, v)
            elif (isinstance(v, bytes)):
                self.putBytes(k, v)
            elif (isinstance(v, dict)):
                self.putProtoBuf(k, ProtoBuf(v))
            elif (isinstance(v, ProtoBuf)):
                self.putProtoBuf(k,v)
            else:
                raise ProtoError('unsupport type(%s) for value of key %s to protobuf' % (type(v), k))

    def toDict(self, out_dict_template=None):
        res_dict = {}
        for field in self.fields:
            val = field.val
            if field.type == ProtoFieldType.STRING:
                try:
                    nested_pb = ProtoBuf(field.val)
                    val = nested_pb.toDict()
                except (ProtoError, Exception):
                    try:
                        val = field.val.decode('utf-8')
                    except UnicodeDecodeError:
                        val = field.val.hex()

            if field.idx in res_dict:
                if not isinstance(res_dict[field.idx], list):
                    res_dict[field.idx] = [res_dict[field.idx]]
                res_dict[field.idx].append(val)
            else:
                res_dict[field.idx] = val
        return res_dict

class SM3Hash:
    def __init__(self) -> None:
        self.IV = [1937774191, 1226093241, 388252375, 3666478592, 2842636476, 372324522, 3817729613, 2969243214]
        self.TJ = [2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042]

    def __rotate_left(self, a: int, k: int) -> int:
        k = k % 32
        return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k))

    def __FFJ(self, X: int, Y: int, Z: int, j: int) -> int:
        if 0 <= j and j < 16: ret = X ^ Y ^ Z
        elif 16 <= j and j < 64: ret = (X & Y) | (X & Z) | (Y & Z)
        else: raise ValueError("j out of range for FFJ")
        return ret

    def __GGJ(self, X: int, Y: int, Z: int, j: int) -> int:
        if 0 <= j and j < 16: ret = X ^ Y ^ Z
        elif 16 <= j and j < 64: ret = (X & Y) | ((~X & 0xFFFFFFFF) & Z)
        else: raise ValueError("j out of range for GGJ")
        return ret

    def __P_0(self, X: int) -> int:
        return X ^ (self.__rotate_left(X, 9)) ^ (self.__rotate_left(X, 17))

    def __P_1(self, X: int) -> int:
        return X ^ (self.__rotate_left(X, 15)) ^ (self.__rotate_left(X, 23))

    def __CF(self, V_i: list, B_i: bytearray) -> list:
        W = []
        for i in range(16):
            W.append(int.from_bytes(B_i[i*4:(i+1)*4], 'big'))

        for j in range(16, 68):
            val = self.__P_1(W[j - 16] ^ W[j - 9] ^ (self.__rotate_left(W[j - 3], 15))) \
                  ^ (self.__rotate_left(W[j - 13], 7)) \
                  ^ W[j - 6]
            W.append(val & 0xFFFFFFFF)

        W_1 = [(W[j] ^ W[j + 4]) & 0xFFFFFFFF for j in range(64)]

        A, B, C, D, E, F, G, H = V_i
        for j in range(64):
            SS1 = self.__rotate_left(((self.__rotate_left(A, 12)) + E + (self.__rotate_left(self.TJ[j], j))) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ (self.__rotate_left(A, 12))
            TT1 = (self.__FFJ(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF
            TT2 = (self.__GGJ(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            D = C
            C = self.__rotate_left(B, 9)
            B = A
            A = TT1
            H = G
            G = self.__rotate_left(F, 19)
            F = E
            E = self.__P_0(TT2)
        return [(A ^ V_i[0]) & 0xFFFFFFFF, (B ^ V_i[1]) & 0xFFFFFFFF, (C ^ V_i[2]) & 0xFFFFFFFF,
                (D ^ V_i[3]) & 0xFFFFFFFF, (E ^ V_i[4]) & 0xFFFFFFFF, (F ^ V_i[5]) & 0xFFFFFFFF,
                (G ^ V_i[6]) & 0xFFFFFFFF, (H ^ V_i[7]) & 0xFFFFFFFF]

    def sm3_hash(self, msg: bytes) -> bytes:
        msg_bytearray = bytearray(msg)
        len1 = len(msg_bytearray)
        reserve1 = len1 % 64
        msg_bytearray.append(0x80)
        reserve1 += 1

        range_end = 56
        if reserve1 > range_end: range_end += 64
        for _ in range(reserve1, range_end): msg_bytearray.append(0x00)

        bit_length = len1 * 8
        msg_bytearray.extend(bit_length.to_bytes(8, 'big'))

        group_count = len(msg_bytearray) // 64
        V = list(self.IV)
        for i in range(group_count):
            B_i = msg_bytearray[i * 64 : (i + 1) * 64]
            V = self.__CF(V, B_i)

        res = b"".join(val.to_bytes(4, "big") for val in V)
        return res

class SimonCipher:
    def get_bit(self, val, pos):
        return 1 if val & (1 << pos) else 0

    def rotate_left(self, v, n):
        r = (v << n) | (v >> (64 - n))
        return r & 0xffffffffffffffff

    def rotate_right(self, v, n):
        r = (v << (64 - n)) | (v >> n)
        return r & 0xffffffffffffffff

    def key_expansion(self, key_input):
        key = list(key_input)
        tmp = 0
        for i in range(4, 72):
            tmp = self.rotate_right(key[i-1], 3)
            tmp = tmp ^ key[i-3]
            tmp = tmp ^ self.rotate_right(tmp, 1)
            not_key_i_4 = (key[i-4] ^ 0xFFFFFFFFFFFFFFFF)
            key[i] = not_key_i_4 ^ tmp ^ self.get_bit(0x3DC94C3A046D678B, (i - 4) % 62) ^ 3
            key[i] &= 0xFFFFFFFFFFFFFFFF
        return key

    def simon_dec(self, ct, k_input, c=0):
        tmp = 0
        f_val = 0
        key = [0] * 72
        key[0:4] = k_input[0:4]
        key = self.key_expansion(key)

        x_i = ct[0]
        x_i1 = ct[1]

        for i in range(71, -1, -1):
            tmp = x_i
            f_val = (self.rotate_left(x_i, 1) & self.rotate_left(x_i, 8)) ^ self.rotate_left(x_i, 2)

            x_i = x_i1 ^ f_val ^ key[i]
            x_i1 = tmp
        return [x_i, x_i1]

    def simon_enc(self, pt, k_input, c=0):
        tmp = 0
        f_val = 0
        key = [0] * 72
        key[0:4] = k_input[0:4]
        key = self.key_expansion(key)

        x_i = pt[0]
        x_i1 = pt[1]

        for i in range(72):
            tmp = x_i
            f_val = (self.rotate_left(x_i, 1) & self.rotate_left(x_i, 8)) ^ self.rotate_left(x_i, 2)
            x_i = x_i1 ^ f_val ^ key[i]
            x_i1 = tmp
        return [x_i, x_i1]


class Argus:
    @staticmethod
    def _encrypt_enc_pb(data_list, length):
        xor_array = data_list[:8]
        for i in range(8, length):
            data_list[i] ^= xor_array[i % 8]
        return bytes(data_list[::-1])

    @staticmethod
    def get_bodyhash(stub: Optional[str] = None) -> bytes:
        sm3_hasher = SM3Hash()
        if stub is None or len(stub) == 0:
            return sm3_hasher.sm3_hash(bytes(16))[0:6]
        else:
            return sm3_hasher.sm3_hash(bytes.fromhex(stub))[0:6]

    @staticmethod
    def get_queryhash(query: str) -> bytes:
        sm3_hasher = SM3Hash()
        if not isinstance(query, str):
            print("Warning: get_queryhash received non-string input, hashing empty bytes.")
            return sm3_hasher.sm3_hash(bytes(16))[0:6]
        return sm3_hasher.sm3_hash(query.encode('utf-8'))[0:6]


    @staticmethod
    def encrypt(xargus_bean: dict):
        pb = ProtoBuf(xargus_bean)
        protobuf_bytes = pb.toBuf()

        if AES is None or pad is None:
            raise RuntimeError("PyCryptodome is not installed or failed to import, cannot perform AES encryption for Argus.")

        padded_protobuf = pad(protobuf_bytes, AES.block_size)
        new_len = len(padded_protobuf)

        sign_key = b"\xac\x1a\xda\xae\x95\xa7\xaf\x94\xa5\x11J\xb3\xb3\xa9}\xd8\x00P\xaa\n91L@R\x8c\xae\xc9RV\xc2\x8c"
        sm3_hasher_for_key = SM3Hash()
        sm3_input_for_key = sign_key + b'\xf2\x81ao' + sign_key
        sm3_output = sm3_hasher_for_key.sm3_hash(sm3_input_for_key)

        simon_key_material = sm3_output[:32]
        simon_key_list = []
        for i in range(4):
            simon_key_list.append(int.from_bytes(simon_key_material[i*8:(i+1)*8], 'little'))

        simon_cipher = SimonCipher()
        enc_pb_bytearray = bytearray(new_len)

        for i in range(new_len // 16):
            pt_block = padded_protobuf[i*16 : (i+1)*16]
            pt_words = [
                int.from_bytes(pt_block[0:8], 'little'),
                int.from_bytes(pt_block[8:16], 'little')
            ]
            ct_words = simon_cipher.simon_enc(pt_words, simon_key_list, c=0)

            enc_pb_bytearray[i*16 : i*16+8] = ct_words[0].to_bytes(8, 'little')
            enc_pb_bytearray[i*16+8 : (i+1)*16] = ct_words[1].to_bytes(8, 'little')

        b_buffer_input = list(b"\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff" + enc_pb_bytearray)
        b_buffer = Argus._encrypt_enc_pb(b_buffer_input, new_len + 8)

        b_buffer_final_payload = b"\xa6n\xad\x9fw\x01\xd0\x0c\x18" + b_buffer + b"ao"

        aes_key = hashlib.md5(sign_key[:16]).digest()
        aes_iv = hashlib.md5(sign_key[16:]).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)

        encrypted_final_payload = cipher.encrypt(pad(b_buffer_final_payload, AES.block_size))

        return b64encode(b"\xf2\x81" + encrypted_final_payload).decode('utf-8')

    @staticmethod
    def get_sign(
        params_query_str: Optional[str] = None,
        stub_hex_str: Optional[str] = None,
        timestamp: int = 0,
        device_id: str = "",
        install_id: str = "",
        app_version: str = "",
        sdk_version_str: str = "v04.04.05-ov-android",
        sdk_version_int: int = 134744640,
        aid: int = 1233,
        license_id: int = 1611921764,
        platform: int = 0,
        sec_device_id: str = "",
        **kwargs
    ) -> str:
        if timestamp == 0: timestamp = int(time.time())

        if not device_id: raise ValueError("device_id is required for X-Argus")
        if not app_version: raise ValueError("app_version is required for X-Argus")
        if not install_id: raise ValueError("install_id (iid) is required for X-Argus")

        query_hash_input = params_query_str if params_query_str is not None else ""

        xargus_bean = {
            1: 0x20200929 << 1,
            2: 2,
            3: random.randint(0, 0x7FFFFFFF),
            4: str(aid),
            5: device_id,
            6: str(license_id),
            7: app_version,
            8: sdk_version_str,
            9: sdk_version_int,
            10: b'\x00' * 8,
            11: platform,
            12: timestamp << 1,
            13: Argus.get_bodyhash(stub_hex_str),
            14: Argus.get_queryhash(query_hash_input),
            15: {
                1: 1,
                2: 1,
                3: 1,
                7: 3348294860,
            },
            16: sec_device_id if sec_device_id else "",
            20: "none",
            21: 738,
            25: 2,
            26: install_id,
        }
        if "device_type" in kwargs and kwargs["device_type"]:
             xargus_bean[23] = {1: kwargs["device_type"]}

        return Argus.encrypt(xargus_bean)

class Ladon:
    def _md5bytes(self, data: bytes) -> str:
        m = hashlib.md5()
        m.update(data)
        return m.hexdigest()

    def _validate(self, num):
        return num & 0xFFFFFFFFFFFFFFFF

    def _encrypt_ladon_input(self, hash_table_bytes, input_data_bytes):
        data0 = int.from_bytes(input_data_bytes[:8], byteorder="little")
        data1 = int.from_bytes(input_data_bytes[8:], byteorder="little")

        for i in range(0x22):
            key_val = int.from_bytes(hash_table_bytes[i * 8 : (i + 1) * 8], byteorder="little")

            temp_ror_data1_8 = self._validate(((data1 & 0xFFFFFFFFFFFFFF00) >> 8) | ((data1 & 0x00000000000000FF) << 56))
            data1 = self._validate(key_val ^ self._validate(data0 + temp_ror_data1_8))

            temp_ror_data0_61 = self._validate(((data0 & 0x1FFFFFFFFFFFFFFF) << 3) | ((data0 & 0xE000000000000000) >> 61))
            data0 = self._validate(data1 ^ temp_ror_data0_61)

        output_data = bytearray(16)
        output_data[:8] = data0.to_bytes(8, byteorder="little")
        output_data[8:] = data1.to_bytes(8, byteorder="little")
        return bytes(output_data)

    def _encrypt_ladon(self, md5hex_bytes: bytes, data_bytes: bytes, size: int):
        _hash_table = bytearray(34 * 8)
        _hash_table[0:16] = md5hex_bytes

        k_minus_1 = int.from_bytes(_hash_table[8:16], "little")
        k_minus_2 = int.from_bytes(_hash_table[0:8], "little")

        for j in range(2, 34):
            ror_k_minus_1_8 = self._validate(((k_minus_1 & 0xFFFFFFFFFFFFFF00) >> 8) | ((k_minus_1 & 0x00000000000000FF) << 56))
            temp_val = self._validate(ror_k_minus_1_8 + k_minus_2)
            temp_val = self._validate(temp_val ^ (j - 2))

            ror_k_minus_2_61 = self._validate(((k_minus_2 & 0x1FFFFFFFFFFFFFFF) << 3) | ((k_minus_2 & 0xE000000000000000) >> 61))
            new_key = self._validate(temp_val ^ ror_k_minus_2_61)

            _hash_table[j*8 : (j+1)*8] = new_key.to_bytes(8, "little")

            k_minus_2 = k_minus_1
            k_minus_1 = new_key

        new_size = PKCS7Padding.padding_size(size)
        input_padded = bytearray(new_size)
        input_padded[:size] = data_bytes
        PKCS7Padding.pkcs7_padding_pad_buffer(input_padded, size, new_size, 16)

        output_encrypted = bytearray(new_size)
        for i in range(new_size // 16):
            block_to_encrypt = input_padded[i * 16 : (i + 1) * 16]
            encrypted_block = self._encrypt_ladon_input(_hash_table, block_to_encrypt)
            output_encrypted[i * 16 : (i + 1) * 16] = encrypted_block
        return output_encrypted

    def encrypt(self, timestamp: int, license_id: int = 1611921764, aid: int = 1233, random_bytes_val: Optional[bytes] = None) -> str:
        if random_bytes_val is None:
            random_bytes_val = urandom(4)

        data_str = f"{timestamp}-{license_id}-{aid}"
        keygen = random_bytes_val + str(aid).encode('utf-8')
        md5hex_str = self._md5bytes(keygen)
        md5hex_bytes = bytes.fromhex(md5hex_str)

        data_bytes = data_str.encode('utf-8')
        size = len(data_bytes)

        encrypted_data = self._encrypt_ladon(md5hex_bytes, data_bytes, size)

        output_final = bytearray(len(encrypted_data) + 4)
        output_final[:4] = random_bytes_val
        output_final[4:] = encrypted_data

        return b64encode(bytes(output_final)).decode('utf-8')

class XGorgon:
    def __init__(self):
        self.length = 20
        self.hex_str = [0x1e, 0x40, 0xe0, 0xd9, 0x93, 0x45, 0x00, 0xb4]

    def _int_to_hex_string(self, num: int, length: int = 2) -> str:
        return format(num, f'0{length}x')

    def _rc4_ksa_like(self) -> List[int]:
        sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + sbox[i] + self.hex_str[i % len(self.hex_str)]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox

    def _rc4_prga_xor(self, input_bytes: List[int], sbox_ksa: List[int]) -> List[int]:
        output_bytes = list(input_bytes)
        sbox = list(sbox_ksa)
        i_ptr = 0
        j_ptr = 0
        for idx in range(len(output_bytes)):
            i_ptr = (i_ptr + 1) % 256
            j_ptr = (sbox[i_ptr] + j_ptr) % 256
            sbox[i_ptr], sbox[j_ptr] = sbox[j_ptr], sbox[i_ptr]
            xor_key = sbox[(sbox[i_ptr] + sbox[j_ptr]) % 256]
            output_bytes[idx] ^= xor_key
        return output_bytes

    def _custom_byte_handle(self, input_bytes: List[int]) -> List[int]:
        output_bytes = list(input_bytes)
        for i in range(self.length):
            A = output_bytes[i]

            tmp_string_rev = self._int_to_hex_string(A)
            B = int(tmp_string_rev[1:] + tmp_string_rev[:1], 16)

            C = output_bytes[(i + 1) % self.length]
            D = B ^ C

            result_rbit = ''
            tmp_string_rbit = bin(D)[2:]
            while len(tmp_string_rbit) < 8: tmp_string_rbit = '0' + tmp_string_rbit
            for bit_idx in range(8): result_rbit += tmp_string_rbit[7 - bit_idx]
            E = int(result_rbit, 2)

            F = E ^ self.length
            G = ~F
            H = G & 0xFF
            output_bytes[i] = H
        return output_bytes

    def calculate(self, url_path_query: str, x_ss_stub: Optional[str], cookie_str: Optional[str], x_khronos_str: str) -> Dict[str, str]:
        gorgon_input = bytearray(20)

        url_md5_bytes = hashlib.md5(url_path_query.encode("utf-8")).digest()
        gorgon_input[0:4] = url_md5_bytes[0:4]

        if x_ss_stub and len(x_ss_stub) > 0:
            try:
                stub_md5_bytes = hashlib.md5(x_ss_stub.encode("utf-8")).digest()
                gorgon_input[4:8] = stub_md5_bytes[0:4]
            except Exception:
                 gorgon_input[4:8] = b'\x00\x00\x00\x00'
        else:
            gorgon_input[4:8] = b'\x00\x00\x00\x00'

        if cookie_str and len(cookie_str) > 0:
            cookie_md5_bytes = hashlib.md5(cookie_str.encode("utf-8")).digest()
            gorgon_input[8:12] = cookie_md5_bytes[0:4]
        else:
            gorgon_input[8:12] = b'\x00\x00\x00\x00'

        gorgon_input[12:16] = b'\x00\x00\x00\x00'

        khronos_int = int(x_khronos_str)
        gorgon_input[16:20] = khronos_int.to_bytes(4, 'big')

        sbox = self._rc4_ksa_like()
        xor_encrypted_gorgon = self._rc4_prga_xor(list(gorgon_input), sbox)
        handled_gorgon = self._custom_byte_handle(xor_encrypted_gorgon)

        final_gorgon_hex = "".join([self._int_to_hex_string(b) for b in handled_gorgon])

        prefix_bytes = [
            self.hex_str[7], self.hex_str[3],
            self.hex_str[1], self.hex_str[6]
        ]
        prefix_hex = "".join([self._int_to_hex_string(b) for b in prefix_bytes])

        x_gorgon_value = f"0404{prefix_hex}{final_gorgon_hex}"

        return {
            'X-Gorgon': x_gorgon_value,
            'X-Khronos': x_khronos_str
        }

class ByteBuf:
    def __init__(self, data, size=None):
        if data: self.mem = data
        if size is not None: self.data_size = size
        elif data is not None: self.data_size = len(data)
        else: raise ValueError("Either size or data must be provided")
        self.pos = 0
    def data(self): return self.mem
    def size(self): return self.data_size
    def remove_padding(self):
        padding_len = PKCS7Padding.pkcs7_padding_data_length(self.mem, self.data_size, 16)
        if padding_len == 0 and self.data_size > 0 and self.mem[self.data_size-1] > 16 :
            return self.data_size
        if padding_len == 0 and self.data_size == 0: return 0

        self.data_size = padding_len
        if isinstance(self.mem, bytearray):
            del self.mem[self.data_size:]
        else:
            self.mem = self.mem[:self.data_size]
        return self.data_size


API_BASE_URL_TEMPLATE = "https://api16-normal-c-{region}.tiktokv.com"
SEARCH_API_HOST = "search16-normal-no1a.tiktokv.eu"
CORE_API_HOST_V32 = "api32-core-no1a.tiktokv.eu"
VIDEO_DETAILS_HOST = "api16-normal-no1a.tiktokv.eu"
CURRENT_API_REGION = "alisg"
USER_POSTS_ENDPOINT_PATH = "/aweme/v1/aweme/post/"
VIDEO_DETAILS_ENDPOINT_PATH = "/aweme/v1/multi/aweme/detail/"
GENERAL_SEARCH_STREAM_PATH = "/aweme/v1/general/search/stream/"
USER_POSTS_V2_ENDPOINT_PATH = "/aweme/v1/aweme/post/"
VIDEO_DETAILS_MULTI_PATH = "/aweme/v1/multi/aweme/detail/"

REQUEST_TIMEOUT = 20
DEFAULT_REQUEST_DELAY_SEARCH_DETAILS = (0.4, 0.8)
DEFAULT_REQUEST_DELAY_USER_POSTS_PAGINATION = (0.6, 1.0)


class TikTokError(Exception):
    def __init__(self, message, status_code=None, response_text=None):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text

class TikTokAPIScraper:
    VIDEO_JSON_SAVE_PATH_CLASS_ATTR = "video_json_details"

    def __init__(self, device_params: Dict, proxies: Optional[List[str]] = None, user_agent: Optional[str] = None):
        self.session = requests.Session()
        self.base_device_params = device_params
        self.proxies = proxies or []
        self.user_agent = user_agent or DEFAULT_USER_AGENT_ANDROID

        self.xgorgon_generator = XGorgon()
        self.ladon_generator = Ladon()

        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        required_params = ["device_id", "iid", "app_name", "app_version", "channel",
                           "version_code", "manifest_version_code", "update_version_code",
                           "os_version", "device_type", "device_brand", "region", "aid"]

        for param in required_params:
            if param not in self.base_device_params or not self.base_device_params[param]:
                if isinstance(self.base_device_params.get(param), str) and "YOUR_" in self.base_device_params.get(param, ""):
                    pass
                else:
                    print(f"WARNING (Scraper Init): Device parameter '{param}' is missing or empty. Dynamic signatures might fail if not a placeholder.")


        if not os.path.exists(TikTokAPIScraper.VIDEO_JSON_SAVE_PATH_CLASS_ATTR):
            os.makedirs(TikTokAPIScraper.VIDEO_JSON_SAVE_PATH_CLASS_ATTR)
            print(f"INFO: Save directory '{TikTokAPIScraper.VIDEO_JSON_SAVE_PATH_CLASS_ATTR}' created.")

    def _get_random_proxy(self) -> Optional[Dict[str, str]]:
        if not self.proxies: return None
        proxy_url = random.choice(self.proxies)
        return {"http": proxy_url, "https": proxy_url}

    def _sign_request(self, method: str, url_full: str, query_params_dict: Dict, post_data_bytes: Optional[bytes]) -> Dict[str, str]:
        signed_headers = {}
        current_timestamp = int(time.time())
        current_timestamp_str = str(current_timestamp)

        signed_headers['X-Khronos'] = current_timestamp_str

        x_ss_stub_value = None
        if method.upper() == "POST" and post_data_bytes:
            x_ss_stub_value = hashlib.md5(post_data_bytes).hexdigest().upper()

        parsed_url = urlparse(url_full)
        path_query_for_gorgon = parsed_url.path
        if parsed_url.query:
            path_query_for_gorgon += "?" + parsed_url.query

        cookie_str_for_gorgon = self.base_device_params.get("cookie", "")

        try:
            gorgon_result = self.xgorgon_generator.calculate(
                url_path_query=path_query_for_gorgon,
                x_ss_stub=x_ss_stub_value,
                cookie_str=cookie_str_for_gorgon,
                x_khronos_str=current_timestamp_str
            )
            signed_headers['X-Gorgon'] = gorgon_result['X-Gorgon']
        except Exception as e:
            print(f"ERROR generating X-Gorgon: {e}")

        try:
            ladon_aid = int(self.base_device_params.get("aid", 1233))
            ladon_license_id = int(self.base_device_params.get("license_id", 1611921764))
            signed_headers['X-Ladon'] = self.ladon_generator.encrypt(
                timestamp=current_timestamp,
                aid=ladon_aid,
                license_id=ladon_license_id
            )
        except Exception as e:
            print(f"ERROR generating X-Ladon: {e}")

        try:
            query_string_for_argus = urlencode(query_params_dict)

            argus_params = {
                "params_query_str": query_string_for_argus,
                "stub_hex_str": x_ss_stub_value,
                "timestamp": current_timestamp,
                "device_id": self.base_device_params.get("device_id", ""),
                "install_id": self.base_device_params.get("iid", ""),
                "app_version": self.base_device_params.get("app_version", self.base_device_params.get("version_name","")),
                "sdk_version_str": self.base_device_params.get("sdk_version", "v04.04.05-ov-android"),
                "sdk_version_int": int(self.base_device_params.get("sdk_version_int", 134744640)),
                "aid": int(self.base_device_params.get("aid", 1233)),
                "license_id": int(self.base_device_params.get("license_id", 1611921764)),
                "platform": int(self.base_device_params.get("platform", 0)),
                "sec_device_id": self.base_device_params.get("sec_device_id", ""),
                "app_name": self.base_device_params.get("app_name"),
                "channel": self.base_device_params.get("channel"),
                "device_type": self.base_device_params.get("device_type"),
            }
            signed_headers['X-Argus'] = Argus.get_sign(**argus_params)
        except Exception as e:
            print(f"ERROR generating X-Argus: {e}")
            import traceback; traceback.print_exc()

        if "x-tt-token" in self.base_device_params and self.base_device_params["x-tt-token"] and "YOUR_" not in self.base_device_params["x-tt-token"]:
             signed_headers['X-TT-Token'] = self.base_device_params["x-tt-token"]
        elif "x-tt-token" in self.base_device_params and ("YOUR_" in self.base_device_params["x-tt-token"] or not self.base_device_params["x-tt-token"]):
             print("WARNING (_sign_request): X-TT-Token is a placeholder or empty in device_params. Dynamic requests requiring it may fail.")

        if x_ss_stub_value:
            signed_headers['x-ss-stub'] = x_ss_stub_value

        signed_headers['x-ss-req-ticket'] = str(int(time.time() * 1000))
        return signed_headers

    def _make_request_signed(self, method: str, base_url:str, url_path: str, query_params_dict: Optional[Dict] = None, post_data_dict: Optional[Dict] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        query_params_dict = query_params_dict or {}

        final_query_params = {}

        common_query_device_params = [
            "aid", "app_name", "version_code", "version_name", "manifest_version_code",
            "update_version_code", "device_platform", "os_version", "device_type",
            "device_brand", "ssmix", "channel", "device_id", "iid", "openudid", "cdid",
            "region", "sys_region", "app_language", "language", "timezone_name", "timezone_offset",
            "ac", "op_region", "residence", "mcc_mnc", "carrier_region"
        ]
        for p_key in common_query_device_params:
            if p_key in self.base_device_params:
                 final_query_params[p_key] = self.base_device_params[p_key]

        final_query_params.update(query_params_dict)


        if "_rticket" not in final_query_params:
            final_query_params["_rticket"] = str(int(time.time() * 1000))
        if "ts" not in final_query_params:
            final_query_params["ts"] = str(int(time.time()))

        if 'timezone_name' in final_query_params and final_query_params['timezone_name'] is not None:
            final_query_params['timezone_name'] = quote(str(final_query_params['timezone_name']))

        full_url_for_req = f"{base_url.rstrip('/')}/{url_path.lstrip('/')}"

        post_data_bytes = None
        request_content_type = None
        if method.upper() == "POST" and post_data_dict:
            post_data_bytes = urlencode(post_data_dict).encode('utf-8')
            request_content_type = 'application/x-www-form-urlencoded; charset=UTF-8'

        query_string_for_url = urlencode(final_query_params)
        url_full_with_query_for_signing = f"{full_url_for_req}?{query_string_for_url}" if query_string_for_url else full_url_for_req

        signature_headers = self._sign_request(
            method=method,
            url_full=url_full_with_query_for_signing,
            query_params_dict=final_query_params,
            post_data_bytes=post_data_bytes
        )

        all_headers = self.session.headers.copy()
        all_headers['Host'] = urlparse(base_url).hostname
        if request_content_type:
            all_headers['Content-Type'] = request_content_type

        all_headers.update(signature_headers)
        if 'cookie' in self.base_device_params:
            all_headers['cookie'] = self.base_device_params['cookie']

        current_proxy = self._get_random_proxy()

        try:
            response = self.session.request(
                method, full_url_for_req, params=final_query_params,
                data=post_data_bytes, headers=all_headers,
                proxies=current_proxy, timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 403:
                raise TikTokError(f"Access Denied (403). Proxy, IP, or signatures might be an issue. Response: {response.text[:200]}", response.status_code, response.text)

            try:
                data = response.json()
            except json.JSONDecodeError:
                if 200 <= response.status_code < 300:
                    print(f"Warning (Dynamic Sign): Successful HTTP status {response.status_code} but failed to decode JSON. Raw text: {response.text[:200]}")
                    return {"raw_text": response.text, "status_code": response.status_code, "message":"JSON Decode Error but HTTP OK"}, response.text
                response.raise_for_status()
                raise TikTokError(f"JSON Decode Error. Content: {response.text[:500]}", response.status_code, response.text)


            api_status_code = data.get("status_code")
            if api_status_code != 0 and api_status_code is not None:
                status_msg = data.get("status_msg", data.get("message", "Unknown API Error"))
                log_id_obj = data.get("log_pb", {})
                log_id = log_id_obj.get("impr_id", "N/A") if isinstance(log_id_obj, dict) else "N/A"

                if api_status_code == 1011 or api_status_code == 1012:
                     raise TikTokError(f"Captcha required: {status_msg} (Log ID: {log_id})", api_status_code, response.text)

                raise TikTokError(f"TikTok API Error: {status_msg} (Code: {api_status_code}, Log ID: {log_id})", api_status_code, response.text)

            return data, response.text

        except requests.exceptions.HTTPError as e:
            response_text_val = e.response.text if e.response is not None else None
            raise TikTokError(f"HTTP Error: {e}", e.response.status_code if e.response else None, response_text_val) from e
        except requests.exceptions.RequestException as e:
            raise TikTokError(f"Network Error: {e}") from e

    def search_hashtag_signed(self, keyword: str, offset: int, count: int) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        print(f"> Page (Offset {offset}): Searching for '{keyword}'...")

        post_data_dict = {
            "keyword": keyword,
            "offset": str(offset),
            "count": str(count),
            "enter_from": "general_search",
            "search_source": "video_title_challenge",
            "search_id": f"{int(time.time() * 1000)}{random.randint(1000, 9999)}",
            "query_correct_type": "1",
            "is_filter_search": "0",
            "publish_time": "0",
            "sort_type": "0",
            "search_context": json.dumps({"query_list": [], "search_scene_info": [], "feed_scene_info": []}),
        }
        
        specific_query_params = {}

        try:
            base_url = f"https://{SEARCH_API_HOST}" 
            url_path = "/aweme/v1/general/search/single/"

            parsed_data, raw_text = self._make_request_signed(
                method="POST",
                base_url=base_url,
                url_path=url_path,
                query_params_dict=specific_query_params,
                post_data_dict=post_data_dict
            )
            return parsed_data, raw_text

        except TikTokError as e:
            print(f"ERROR (search_hashtag_signed) searching for '{keyword}': {e}")
            return None, e.response_text
        except Exception as e:
            print(f"General ERROR (search_hashtag_signed) for '{keyword}': {e}")
            import traceback; traceback.print_exc()
            return None, None

    def get_video_details_signed(self, aweme_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        print(f"INFO (get_video_details_signed): Fetching details for aweme_id '{aweme_id}' using DYNAMIC signatures.")

        query_params_for_req = {
            "share_link_mode": self.base_device_params.get("share_link_mode", "0"),
            "share_scene": self.base_device_params.get("share_scene", "1"),
        }
        video_details_specific_params = [
            "cdid", "iid", "openudid", "channel", "aid", "app_name", "version_code", "version_name",
            "manifest_version_code", "update_version_code", "ab_version", "resolution", "dpi",
            "device_type", "device_brand", "language", "os_api", "os_version", "ac", "is_pad",
            "current_region", "app_type", "sys_region", "last_install_time", "mcc_mnc",
            "timezone_name", "carrier_region_v2", "residence", "app_language", "carrier_region",
            "timezone_offset", "host_abi", "locale", "ac2", "uoo", "op_region",
            "build_number", "region", "device_id"
        ]
        for key in video_details_specific_params:
            if key not in query_params_for_req and key in self.base_device_params:
                query_params_for_req[key] = self.base_device_params.get(key)


        post_payload_dict = {
            "aweme_ids": f"[{aweme_id}]",
            "request_source": "0",
        }

        try:
            parsed_data, raw_text = self._make_request_signed(
                method="POST",
                base_url=f"https://{VIDEO_DETAILS_HOST}",
                url_path=VIDEO_DETAILS_MULTI_PATH,
                query_params_dict=query_params_for_req,
                post_data_dict=post_payload_dict
            )

            if parsed_data and parsed_data.get("aweme_details") and isinstance(parsed_data["aweme_details"], list) and len(parsed_data["aweme_details"]) > 0:
                return parsed_data["aweme_details"][0], raw_text
            else:
                print(f"WARNING (get_video_details_signed): 'aweme_details' not found or empty for video {aweme_id}.")
                if parsed_data: print(f"DEBUG (get_video_details_signed): API Response (parsed): {parsed_data}")
                return None, raw_text
        except TikTokError as e:
            print(f"ERROR (get_video_details_signed) fetching details for {aweme_id}: {e}")
            return None, e.response_text
        except Exception as e:
            print(f"General ERROR (get_video_details_signed) for {aweme_id}: {e}")
            import traceback; traceback.print_exc()
            return None, None

    def get_user_sec_uid_from_profile_page(self, username: str) -> Optional[str]:
        if CurlSession is None:
            print("FATAL ERROR: The 'curl_cffi' library is required but not installed.")
            return None

        session = CurlSession()
        url = f"https://www.tiktok.com/@{username}"
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
            'Referer': 'https://www.tiktok.com/',
        }

        print(f"\n> Loading profile page for '{username}' to extract secUid...")

        try:
            response = session.get(url, headers=headers, timeout=20, impersonate="chrome110")
            response.raise_for_status()
            html_content = response.text

            match = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', html_content)

            if not match:
                print("> ERROR: Could not find the JSON data block in the HTML.")
                debug_filename = f"tiktok_page_{username}.html"
                with open(debug_filename, "w", encoding="utf-8") as f: f.write(html_content)
                print(f"> DEBUG: The received HTML content has been saved to '{debug_filename}' for analysis.")
                return None

            json_string = match.group(1)
            data = json.loads(json_string)

            user_data = data.get("__DEFAULT_SCOPE__", {}).get("webapp.user-detail", {}).get("userInfo", {}).get("user", {})
            sec_uid = user_data.get("secUid")

            if sec_uid:
                print(f"> SUCCESS: secUid '{sec_uid}' for user '{username}' extracted.")
                return sec_uid
            else:
                print("> WARNING: secUid could not be found in the JSON block.")
                return None
        except Exception as e:
            print(f"> ERROR extracting secUid from profile page: {e}")
            return None

    def get_user_posts(self, sec_user_id: str, count_per_req: int = 20, max_cursor: str = "0", max_total_posts: Optional[int] = None) -> List[Dict[str, Any]]:
        if max_total_posts is None:
            max_total_posts = INTERNAL_MAX_POST_LIMIT

        all_aweme_list: List[Dict[str, Any]] = []
        current_cursor = max_cursor
        has_more = True
        fetched_count_total = 0

        while has_more and fetched_count_total < max_total_posts:
            batch_count = min(count_per_req, max_total_posts - fetched_count_total)
            if batch_count <= 0: break

            print(f"> Requesting post batch: Cursor={current_cursor}, Count={batch_count}")
            url = f"https://{CORE_API_HOST_V32}{USER_POSTS_V2_ENDPOINT_PATH}"
            current_ts = str(int(time.time())); current_rticket = str(int(time.time() * 1000))
            querystring = {
                "source": "0", "user_avatar_shrink": "96_96", "video_cover_shrink": "248_330",
                "screen_reader_enable": "false", "sov_client_enable": "1",
                "max_cursor": current_cursor, "sec_user_id": sec_user_id, "count": str(batch_count),
                "sort_type": "0", "device_platform": "android", "os": "android", "ssmix": "a",
                "_rticket": current_rticket, "channel": "googleplay", "aid": "1233", "app_name": "musical_ly",
                "version_code": "400004", "version_name": "40.0.4", "manifest_version_code": "2024000040",
                "update_version_code": "2024000040", "ab_version": "40.0.4", "resolution": "1280*720",
                "dpi": "240", "device_type": "SM-G973N", "device_brand": "samsung", "language": "de",
                "os_api": "28", "os_version": "9", "ac": "wifi", "is_pad": "0", "current_region": "DE",
                "app_type": "normal", "sys_region": "DE", "last_install_time": "1747767039",
                "mcc_mnc": "26201", "timezone_name": quote("Europe/Berlin"), "carrier_region_v2": "262",
                "residence": "DE", "app_language": "de", "carrier_region": "DE", "timezone_offset": "3600",
                "host_abi": "arm64-v8a", "locale": "de-DE", "content_language": "de,en,", "ac2": "wifi5g",
                "uoo": "0", "op_region": "DE", "build_number": "40.0.4", "region": "DE", "ts": current_ts,
                "iid": "7506601045351581472", "device_id": "7502493035524752929"
            }
            headers = {
                "rpc-persist-pyxis-policy-v-tnc": "1", "accept-encoding": "gzip",
                "rpc-persist-pns-region-3": "DE|2921044|2950157", "rpc-persist-pns-region-2": "DE|2921044",
                "rpc-persist-pns-region-1": "DE|2921044", "x-tt-pba-enable": "1", "check_preload": "true",
                "x-tt-dm-status": "login=1;ct=1;rt=1", "x-ss-req-ticket": current_rticket, "sdk-version": "2",
                "x-tt-token": "056c66007f83cd381f509b2e8c734f12e802ad4a4c28f8a186f7b3eea1ee70951656c8ba638c8c9b384ecbde1a605e270e62b889d49dfcaa159919657b0459928e442310507975ec21e92b70be0ffbe882d36677a2d548c630896bcfd2dbe7c72db2--0a4e0a205f029eaedff8c5b1fd536b8317c2e288f9b2731d220ae285c2c55523fc2aa8f712207f0e7e6760ab71745e5cd4d7707a439a651fc86e11e1c3303699d54a8d85901c1801220674696b746f6b-3.0.0",
                "passport-sdk-version": "-1", "oec-vc-sdk-version": "3.0.9.i18n",
                "x-vc-bdturing-sdk-version": "2.3.11.i18n", "x-tt-request-tag": "n=0;nr=011;bg=0",
                "x-tt-store-region": "de", "x-tt-store-region-src": "uid",
                "user-agent": "com.zhiliaoapp.musically/2024000040 (Linux; U; Android 9; de_DE; SM-G973N; Build/PQ3A.190605.03202111;tt-ok/3.12.13.20)",
                "x-ladon": "cOEIBf4IlZF2ayFrkR/m4Coa4tDEQYCYZZ+X6KzqrKgq6x5K", "x-khronos": current_ts,
                "x-argus": "PmkRsFWuODCJ1vXFGB4hwoyGW24ZenSbwrShMrj7jccpzGxcpmOZAArZ7XFsyxOc9BWeEXnimArMpIoYAeX1Go5SiJldFWxp0YS3NG2JgHcn4MFs0IC/15oqpG8j0KiLdXURo5ZMIEszTN5OBCPILfTDw8xvuexYSf7nXw6iqUeCoj9rRHwPreZPjf2PQ/eRa9qWbo9NVr48NSUQO+M6p70bqgeOkF4z5/WoJEBzff08VcE1Gqt1/+EAgM76/QoEygqme3P75zGmCt7eE4Nf4Zw4n0F8sSF/QXDr4+JbPeoUKtZaj/RFfeJfff/v5yttNBaw4BKalqCqSMAkBlxSpqBFd0f6FIfp17Lqv/Z6CxGapEBOuRkNqGJZxks/1UjmePfeRj0fzS2LBHo7pPvNlS5J1QM93StpjIjbRoaEUQp0N9UDCIZ/X9R7/Ccye2oBBnwOx/BTd3seqLzjfhvgRPWpU7ZrHBvxBXw/tn80GuEpKYjuOAAH9SpiYkiVU3sfxCvoHTuQ+PzXHP6mliAj7RKAJbqHLR1KrLcTb8TEyceahFzSmQ2PTESwu7s0ZBFcn3WyWqmEVjm7E/Cb+RLsDmM7iiBvuTlxb0xmPXl/uVdDdVp+iid+xyEbuUhvgspGR2kV5bD5EtVPQrZUc7/8wz0LoRYyehSM/aNi8NrmGcXcUQ==",
                "x-gorgon": "84042076000088cb1ea1cb95933b99074c41574e01e319302535", "host": CORE_API_HOST_V32,
                "connection": "Keep-Alive", "cookie": "passport_csrf_token=c067f492fcf8b0c6932216f3de8efce9; passport_csrf_token_default=c067f492fcf8b0c6932216f3de8efce9; store-idc=no1a; tt-target-idc=eu-ttp2; multi_sids=7064424071320175621%3A6c66007f83cd381f509b2e8c734f12e8; cmpl_token=AgQQAPORF-RPsLI3DuQZ8N088n-smdfUv6MaYN_iHg; d_ticket=277a426d25d789150c6b44e75a179d6edaaf1; sid_guard=6c66007f83cd381f509b2e8c734f12e8%7C1747767059%7C15551999%7CSun%2C+16-Nov-2025+18%3A50%3A58+GMT; uid_tt=04c81a01479bb01ef0e025ec0e649ec5566196d15322e66b94353b5ce16fefc0; uid_tt_ss=04c81a01479bb01ef0e025ec0e649ec5566196d15322e66b94353b5ce16fefc0; sid_tt=6c66007f83cd381f509b2e8c734f12e8; sessionid=6c66007f83cd381f509b2e8c734f12e8; sessionid_ss=6c66007f83cd381f509b2e8c734f12e8; store-country-code=de; store-country-code-src=uid; install_id=7506601045351581472; ttreq=1$ac56a5846d3ce3c1d78f1a64b73a9cf107c6308e; msToken=8gl0vdcQTUJAIFvOTmLSTOKbcyAH1qwkuTd5QTmFTOJImPJZ8-cYv-B3m9DXqdp9zBD1XUxAU7633BdfxhNQsdYMcUmpW03v8Z0qs18KeHA=; store-country-sign=MEIEDIHJsPT1PBv4JdgkmwQgAKe6VaKTJoE3lhzSRqnEl6K7Zmv5FaYyV9IT700Uqo0EEL6mEyWbO-IFLg-dCaAkwWU; odin_tt=2e4d2e7b3827c4d18dbdf5095cbcdace12497ece271d146314da7f0a7e22548d43b45816929adefe667d2a545094f5b4c3c692c8387c29df2c6590869b7fbb42c1ae7f30b932dd07c410c7b921921c73"
            }
            current_proxy = self._get_random_proxy()
            try:
                response = requests.get(url, headers=headers, params=querystring, proxies=current_proxy, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()
                data = response.json()

                aweme_list_batch = data.get("aweme_list") or []

                if not aweme_list_batch:
                    has_more = False

                for item in aweme_list_batch:
                    if fetched_count_total < max_total_posts:
                        all_aweme_list.append(item)
                        fetched_count_total += 1
                    else:
                        has_more = False
                        break

                if not has_more and fetched_count_total > 0:
                    print(f"  > Reached max_total_posts ({max_total_posts}) limit or end of posts.")
                
                if not has_more:
                    break

                has_more_api = data.get("has_more")
                has_more = bool(has_more_api == 1 or str(has_more_api).lower() == 'true')

                next_cursor_val = data.get("max_cursor")
                if next_cursor_val is None or not has_more:
                    has_more = False
                    print(f"> API reports no more results (has_more={has_more_api}, next_cursor={next_cursor_val}).")
                else:
                    current_cursor = str(next_cursor_val)
                    print(f"> {len(aweme_list_batch)} posts received. Total: {fetched_count_total}. Next cursor: {current_cursor}")

                if not has_more: break
                time.sleep(random.uniform(DEFAULT_REQUEST_DELAY_USER_POSTS_PAGINATION[0], DEFAULT_REQUEST_DELAY_USER_POSTS_PAGINATION[1]))

            except requests.exceptions.RequestException as e:
                print(f"ERROR (get_user_posts) for sec_user_id '{sec_user_id}', Cursor '{current_cursor}': {e}")
                if hasattr(e, 'response') and e.response is not None: print(f"ERROR Response Content: {e.response.text[:500]}")
                has_more = False
            except json.JSONDecodeError as e:
                print(f"ERROR (get_user_posts) JSON Decode: {e}")
                has_more = False

        return all_aweme_list

    def get_video_details(self, aweme_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        print(f"   > Fetching details for aweme_id '{aweme_id}'...")
        url = f"https://{VIDEO_DETAILS_HOST}{VIDEO_DETAILS_MULTI_PATH}"
        current_ts = str(int(time.time()))
        current_rticket = str(int(time.time() * 1000))

        querystring = {
            "share_link_mode": "0", "share_scene": "1", "device_platform": "android", "os": "android",
            "ssmix": "a", "_rticket": current_rticket, "cdid": "9c79836d-aa9f-440f-887e-9c9051d8b391",
            "channel": "googleplay", "aid": "1233", "app_name": "musical_ly", "version_code": "390505",
            "version_name": "39.5.5", "manifest_version_code": "2023905050", "update_version_code": "2023905050",
            "ab_version": "39.5.5", "resolution": "1280*720", "dpi": "240", "device_type": "SM-G975N",
            "device_brand": "samsung", "language": "en", "os_api": "28", "os_version": "9", "ac": "wifi",
            "is_pad": "0", "current_region": "US", "app_type": "normal", "sys_region": "US",
            "last_install_time": "1745136763", "mcc_mnc": "310005", "timezone_name": quote("America/Chicago"),
            "carrier_region_v2": "310", "residence": "US", "app_language": "en", "carrier_region": "US",
            "timezone_offset": "-21600", "host_abi": "arm64-v8a", "locale": "en", "ac2": "wifi5g", "uoo": "0",
            "op_region": "US", "build_number": "39.5.5", "region": "US", "ts": current_ts,
            "iid": "7497644650690545430", "device_id": "7495300683626366507", "openudid": "846fd0c1e02da048"
        }
        payload_str = f"aweme_ids=%5B{aweme_id}%5D&request_source=0"

        headers = {
            'accept-encoding': 'gzip', 'connection': 'Keep-Alive',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'cookie': 'store-country-code-src=uid; store-idc=no1a; store-country-code=de; tt-target-idc=eu-ttp2',
            'host': VIDEO_DETAILS_HOST,
            'user-agent': 'com.zhiliaoapp.musically/2023905050 (Linux; U; Android 9; en; SM-G975N; Build/PQ3A.190605.03202111;tt-ok/3.12.13.17)',
            'x-argus': "nWWEOYXhK6lXlpxb5ZK/YsEr2/X7Pz2M43INvakx9btNN7IVv6NALeXzcMLbzxMVBeklZ7Q51bAjCRQABBZKaKeXJYquP/V/vvSc6b4zwF9mICJgM2uF64AEacSosUMIQC6gRMRek6+eg08IQ7HwyD/XRqyVTmO2L6/6FjGkBr010GYQyyAvsTSdEfcULPUimeKKXvFsA6PLvRnZ8VZVfmu6PMrW88ESwaMhsr81uDIucCphol8pjdECGvx06fWDYvM/ZnrRr0VMUHk2Hno6saHXpMPZ0I8Fil3hMXwBMWfHtSZGYSGcZU4dXqXnaut6QluPGUxNYbek4k5B9ccU2xxDIReTlK2Fyknk7Vs1LEvhUXxyqZDm9dody4S7X+lyS+0UKodMNFHDtuORfgMuIDI7QrvirgAE8r9mtxkFAWwtbDvlyBqVMjZzAjBo8rstVuVim3f9NBrB0bn/mjtiQubdiugX2W5ZH0QlmGlX0n8orxwCocZ47ObNZmi/fsGxPs+1D5iUelIRq820p28autNitvY40SlLJ736Ar5ZBbDmO737b8NxoT+bJZmdrb1AmSUfJOU2wt71UKMOhhFigQmCZ57ONdf7yPfDut6VlLX3Yp20jvgbV4iDff/1SrqZmnTkejNark2g2lwO+u0iQXnF5U6opxpGt8kE1AtFwXi0XFY0kbd2hAdH2RW2QUOKzj69ujvhYJoQU1iyMDDYjXAtN8uOa/uBrV8EbLyZypNnSOXKd1onl6p0mpnQF6+B0VA=",
            'x-ladon': "FnM8OKdFrFBZgHIPy/p6qDD1Uc748FQVEU+3lJiqIUsDvVhW",
            'x-tt-token': "05c8ff172b6e186f10cfdca3b3a0294ebc053c0fe2f35d4f1d9fdfaeb2a2490b0e9543b88457abab2cbc3c126a809c1665347650a2248d5ccaa5244de7b2e248d9d2316b44170cff5336bc9ab309dd9969c6a6e4690fb5d63955d09d15395e6a4cc88--0a4e0a20290555e95b42502b8fed319571c3936318b3e65a80d3c832fb5ffe4d36cc9b391220269401bcc237624e22444dec09347690d8a2bd72617a11a78b02bd1934addc4c1801220674696b746f6b-3.0.0"
        }
        
        current_proxy = self._get_random_proxy()
        raw_json_text_response = None

        try:
            response = requests.post(url, headers=headers, params=querystring, data=payload_str, proxies=current_proxy, timeout=REQUEST_TIMEOUT)
            raw_json_text_response = response.text

            response.raise_for_status()
            data = json.loads(raw_json_text_response)

            if data and data.get("aweme_details") and isinstance(data["aweme_details"], list) and len(data["aweme_details"]) > 0:
                return data["aweme_details"][0], raw_json_text_response
            else:
                print(f"   > WARNING: 'aweme_details' not found or empty for video {aweme_id}.")
                if data: print(f"   > DEBUG: API Response (parsed): {data}")
                return None, raw_json_text_response
        except requests.exceptions.HTTPError as e:
            print(f"   > HTTP ERROR for aweme_id '{aweme_id}': {e}")
            error_text_to_return = raw_json_text_response if raw_json_text_response is not None else (e.response.text if e.response is not None else None)
            if error_text_to_return: print(f"   > ERROR Response Content: {error_text_to_return[:500]}")
            return None, error_text_to_return
        except requests.exceptions.RequestException as e:
            print(f"   > Network ERROR for aweme_id '{aweme_id}': {e}")
            return None, None
        except json.JSONDecodeError as e_json:
            print(f"   > JSON Decode ERROR for aweme_id '{aweme_id}': {e_json}.")
            if raw_json_text_response: print(f"   > Content causing JSON error (first 500 chars): {raw_json_text_response[:500]}")
            return None, raw_json_text_response
        return None, raw_json_text_response

def load_proxies_from_file(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        print(f"\n[INFO] Proxy file not found at '{file_path}'. Continuing without proxies.")
        return []
    
    try:
        with open(file_path, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        
        if proxies:
            print(f"\n[INFO] Successfully loaded {len(proxies)} proxies from '{file_path}'.")
        else:
            print(f"\n[INFO] Proxy file '{file_path}' is empty. Continuing without proxies.")
        
        return proxies
    except Exception as e:
        print(f"\n[ERROR] Failed to read proxy file '{file_path}': {e}")
        return []

if __name__ == "__main__":
    print("="*60)
    print(" TikTok Mobile Scraper Framework ".center(60))
    print("="*60)
    
    SEARCH_COUNT_PER_REQUEST = 10
    USER_POSTS_COUNT_PER_REQUEST = 20

    current_device_params = {
        "device_platform": "android", "os": "android", "ssmix": "a", "cdid": "b1ff640c-183d-40ea-ae42-c231d0b57199",
        "channel": "googleplay", "aid": "1233", "app_name": "musical_ly", "version_code": "400303",
        "version_name": "40.3.3", "app_version": "40.3.3", "manifest_version_code": "2024003030",
        "update_version_code": "2024003030", "ab_version": "40.3.3", "resolution": "1280*720",
        "dpi": "240", "device_type": "SM-G970N", "device_brand": "samsung", "language": "de",
        "os_api": "28", "os_version": "9", "ac": "wifi", "is_pad": "0", "current_region": "DE",
        "app_type": "normal", "sys_region": "DE", "last_install_time": "1749482386", "mcc_mnc": "26201",
        "timezone_name": "Europe/Berlin", "carrier_region_v2": "262", "residence": "DE", "app_language": "de",
        "carrier_region": "DE", "timezone_offset": "3600", "host_abi": "arm64-v8a", "locale": "de-DE",
        "content_language": "de,en,", "ac2": "wifi5g", "uoo": "0", "op_region": "DE", "build_number": "40.3.3",
        "region": "DE", "iid": "7513968053311457056", "device_id": "7503239240252409377", 
        "openudid": "52f4e51da0e2ba7d",
        "user_agent": "com.zhiliaoapp.musically/2024003030 (Linux; U; Android 9; de_DE; SM-G970N; Build/PQ3A.190605.03202111;tt-ok/3.12.13.20)",
        "x-tt-token": "05c18c3b116a247a11162957ddc6a3f2f904091ec146dc667e9a6aa4ec8e2ea655e1d43967d09cf9a81d7c6c4e3c6cf82b0afc5739639168b010a067714930632da9dc27c411d36f359a50c05c310a55fb0637d0492bb820e11ac49364037a294a0bc--0a4e0a20570e98b6951f93a731646285079379dbe8b6c71800ac606cfc6d8def7a194a561220f976db23bf272986215077fb94fff7fdf75c9557ab79fe1d5898a90c4adb31201801220674696b746f6b-3.0.0",
        "cookie": "store-idc=no1a; tt-target-idc=eu-ttp2; multi_sids=7064424071320175621%3Ac18c3b116a247a11162957ddc6a3f2f9; cmpl_token=AgQQAPORF-RPsLI3DuQZ8N088kFFZmObf6MaYN9ybA; d_ticket=c1f4698053d06fab9a2afb51a4866b2ebcfc6; sid_guard=c18c3b116a247a11162957ddc6a3f2f9%7C1749482403%7C15552000%7CSat%2C+06-Dec-2025+15%3A20%3A03+GMT; uid_tt=46ba74aeb78761ee730b7ce4f8703795b0f0a84246ecdb9a755d0e7e622d1a71; uid_tt_ss=46ba74aeb78761ee730b7ce4f8703795b0f0a84246ecdb9a755d0e7e622d1a71; sid_tt=c18c3b116a247a11162957ddc6a3f2f9; sessionid=c18c3b116a247a11162957ddc6a3f2f9; sessionid_ss=c18c3b116a247a11162957ddc6a3f2f9; store-country-code=de; install_id=7513968053311457056; ttreq=1$1dc5576faffb1cca980f99c39157989a54e433aa; passport_csrf_token=63ae4bd8f17e6dd477b9432a1c002273; passport_csrf_token_default=63ae4bd8f17e6dd477b9432a1c002273; store-country-code-src=uid; odin_tt=ff47d7515eb7f6e5b8299ecc957af2840142e4eca98859638c19e9c83db66fdd75f32cb9f3549cf107cab0f1ae3b34c05d78a25fa45404e7d16d06749a5ad7aa0de8926618956d10f9b850733f41d08b; msToken=WBnhiXWbSJgHgqRXpkRFafZ1sQc0CZo8WJ5_9ZDba93vDQKHGEQ-yONSx_hii3gupFp7R4gNhXkX8V-pwXUUBa56oVPQde3XCmbxofWSLkUeJA55ZX9NFoA=; store-country-sign=MEIEDParkMzwQSAlzKXUMQQgR8C6JixFE-e-mk4c5SACv5u4RRwW_FGnyiGCPKJ9OAgEEMRzA0Ogksergf7G_IH4fbc",
        "license_id": 1611921764, "sdk_version": "v04.04.05-ov-android", "sdk_version_int": 134744640, 
        "platform": 0, "sec_device_id": ""
    }
    
    if "YOUR_CDID" in current_device_params["cdid"]:
        print("*"*70)
        print("WARNING: 'current_device_params' still contains placeholder values.")
        print("The dynamically signed hashtag search will most likely fail.")
        print("Please replace the 'YOUR_...' values with real data.")
        print("*"*70)

    proxies = load_proxies_from_file("proxy.txt")
    scraper = TikTokAPIScraper(device_params=current_device_params, proxies=proxies)

    while True:
        print("\n" + "="*60)
        print(" New Scrape Job ".center(60, "="))
        print("="*60)
        user_input_keyword_original = input("[CONFIG] Enter a username OR a hashtag (starting with #): ").strip()

        is_hashtag_search = user_input_keyword_original.startswith("#")

        if not user_input_keyword_original:
            print("\n! Invalid input. Please try again.")
            continue

        elif not is_hashtag_search:
            username_keyword_to_search = user_input_keyword_original
            
            print("\n--- Fetching User Profile ---")
            found_sec_uid_for_user_input = scraper.get_user_sec_uid_from_profile_page(username_keyword_to_search)

            if found_sec_uid_for_user_input:
                while True:
                    try:
                        max_posts_input_str = input(f"\n[CONFIG] How many posts to fetch for '{username_keyword_to_search}'? (Enter for all): ").strip()
                        if not max_posts_input_str or max_posts_input_str.lower() == 'all':
                            MAX_POSTS_TO_FETCH_CONFIG = INTERNAL_MAX_POST_LIMIT
                            print(f"> Attempting to fetch all posts (up to the API limit of {INTERNAL_MAX_POST_LIMIT}).")
                            break
                        MAX_POSTS_TO_FETCH_CONFIG = int(max_posts_input_str)
                        if MAX_POSTS_TO_FETCH_CONFIG <= 0:
                            print(f"> Invalid input. Defaulting to fetch all posts (up to {INTERNAL_MAX_POST_LIMIT}).")
                            MAX_POSTS_TO_FETCH_CONFIG = INTERNAL_MAX_POST_LIMIT
                        else:
                            print(f"> Will fetch a maximum of {MAX_POSTS_TO_FETCH_CONFIG} posts.")
                        break
                    except ValueError:
                        print("! Invalid input. Please enter a number or press Enter for 'all'.")
                
                print(f"\n--- Fetching Posts For '{username_keyword_to_search}' ---")
                user_posts_list = scraper.get_user_posts(
                    sec_user_id=found_sec_uid_for_user_input,
                    count_per_req=USER_POSTS_COUNT_PER_REQUEST,
                    max_total_posts=MAX_POSTS_TO_FETCH_CONFIG
                )

                if user_posts_list:
                    print(f"\n> Successfully fetched {len(user_posts_list)} posts.")
                    print(f"\n--- Fetching Details For {len(user_posts_list)} Posts ---")
                    for i, post_summary in enumerate(user_posts_list):
                        aweme_id = post_summary.get("aweme_id")
                        desc_summary = post_summary.get("desc", "")[:40].replace('\n', ' ')
                        print(f"[{i+1}/{len(user_posts_list)}] Processing Post (ID: {aweme_id}, Desc: '{desc_summary}...')")
                        if aweme_id:
                            details_dict, raw_json_str = scraper.get_video_details(aweme_id=aweme_id)
                            if details_dict:
                                print(f"   > Play Count: {details_dict.get('statistics', {}).get('play_count', 'N/A')}")
                                if raw_json_str:
                                    file_path = os.path.join(TikTokAPIScraper.VIDEO_JSON_SAVE_PATH_CLASS_ATTR, f"{aweme_id}_details.json")
                                    try:
                                        json_data_to_save = json.loads(raw_json_str)
                                        with open(file_path, 'w', encoding='utf-8') as f:
                                            json.dump(json_data_to_save, f, ensure_ascii=False, indent=4)
                                        print(f"   > Full JSON details saved to: {file_path}")
                                    except Exception as e_save:
                                        print(f"   > ERROR saving JSON file for {aweme_id}: {e_save}")
                            else:
                                print(f"   > No details received for Video ID {aweme_id}.")
                            time.sleep(random.uniform(DEFAULT_REQUEST_DELAY_SEARCH_DETAILS[0], DEFAULT_REQUEST_DELAY_SEARCH_DETAILS[1]))
                else:
                    print(f"\n> No posts found for '{username_keyword_to_search}' or an error occurred.")
            else:
                print(f"\n> Could not find user '{username_keyword_to_search}'. Cannot fetch posts.")
                
        elif is_hashtag_search:
            hashtag_keyword_to_search = user_input_keyword_original[1:]
            
            while True:
                try:
                    max_videos_input_str = input(f"\n[CONFIG] Maximum videos for hashtag '{user_input_keyword_original}'? (Enter for all): ").strip()
                    if not max_videos_input_str or max_videos_input_str.lower() == 'all':
                        MAX_VIDEOS_FOR_DETAILS_CONFIG = float('inf')
                        print("> Attempting to fetch all possible videos.")
                        break
                    MAX_VIDEOS_FOR_DETAILS_CONFIG = int(max_videos_input_str)
                    if MAX_VIDEOS_FOR_DETAILS_CONFIG < 0:
                        print("! Please enter a non-negative number.")
                        continue
                    print(f"> Will attempt to fetch up to {MAX_VIDEOS_FOR_DETAILS_CONFIG} videos.")
                    break
                except ValueError:
                    print("! Invalid input. Please enter a number or press Enter for 'all'.")
            
            print(f"\n--- Searching Hashtag: '{hashtag_keyword_to_search}' ---")
            
            found_aweme_ids_from_search = []
            current_offset = 0
            has_more = True
            
            while has_more and len(found_aweme_ids_from_search) < MAX_VIDEOS_FOR_DETAILS_CONFIG:
                count_per_request = 20
                
                search_data, raw_text = scraper.search_hashtag_signed(
                    keyword=hashtag_keyword_to_search,
                    offset=current_offset,
                    count=count_per_request
                )

                if not search_data:
                    print("> Pagination stopped due to an error or no data.")
                    break

                aweme_list = search_data.get("data") or []
                new_videos_count = 0
                
                if not aweme_list and current_offset > 0:
                    print("> Received an empty list of videos. Stopping pagination.")
                    break

                for item in aweme_list:
                    if len(found_aweme_ids_from_search) >= MAX_VIDEOS_FOR_DETAILS_CONFIG:
                        has_more = False
                        break
                    if item.get("type") == 1 and "aweme_info" in item:
                        aweme_id = item["aweme_info"].get("aweme_id")
                        if aweme_id and aweme_id not in found_aweme_ids_from_search:
                            found_aweme_ids_from_search.append(aweme_id)
                            new_videos_count += 1
                
                if new_videos_count > 0:
                    print(f"> Found {new_videos_count} new unique videos. Total: {len(found_aweme_ids_from_search)}")
                
                if not has_more:
                    print("> Maximum requested number of videos reached.")
                    break

                has_more_api = search_data.get("has_more", 0)
                has_more = bool(has_more_api == 1 or str(has_more_api).lower() == 'true')

                if not has_more:
                    print("> API reports no more results. Pagination finished.")
                    break
                
                current_offset = search_data.get("cursor", current_offset + count_per_request)
                time.sleep(random.uniform(1.5, 2.5))

            if found_aweme_ids_from_search:
                print(f"\n--- Fetching Details For {len(found_aweme_ids_from_search)} Videos ---")
                for i, aweme_id in enumerate(found_aweme_ids_from_search):
                    print(f"[{i+1}/{len(found_aweme_ids_from_search)}] Processing Video (ID: {aweme_id})...")
                    details_dict, raw_json_str = scraper.get_video_details(aweme_id=aweme_id)
                    if details_dict:
                        print(f"   > Desc: {details_dict.get('desc', 'N/A')}")
                        print(f"   > Play Count: {details_dict.get('statistics', {}).get('play_count', 'N/A')}")
                        if raw_json_str:
                            file_path = os.path.join(TikTokAPIScraper.VIDEO_JSON_SAVE_PATH_CLASS_ATTR, f"{aweme_id}_details.json")
                            try:
                                json_data_to_save = json.loads(raw_json_str)
                                with open(file_path, 'w', encoding='utf-8') as f:
                                    json.dump(json_data_to_save, f, ensure_ascii=False, indent=4)
                                print(f"   > Full JSON details saved to: {file_path}")
                            except Exception as e_save:
                                print(f"   > ERROR saving JSON file for {aweme_id}: {e_save}")
                    else:
                        print(f"   > No details received for Video ID {aweme_id}.")
                    time.sleep(random.uniform(DEFAULT_REQUEST_DELAY_SEARCH_DETAILS[0], DEFAULT_REQUEST_DELAY_SEARCH_DETAILS[1]))
            else:
                print("\n> No video IDs were extracted from the search.\n")

        print("\n--- All operations finished ---")
        
        next_action = input("\nPress Enter to start a new search, or type 'exit' to quit: ").strip().lower()
        if next_action == 'exit':
            break
            
    print("\nExiting script. Goodbye!")