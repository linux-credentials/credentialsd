import base64
import codecs
from enum import Enum
import struct
import unittest


class MajorType(Enum):
    PositiveInteger = 0,
    NegativeInteger = 1,
    ByteString = 2,
    TextString = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    SimpleOrFloat = 7,


class Parser:
    def __init__(self, cbor):
        self.data = memoryview(cbor).toreadonly()
        self.pos = 0

    def parse(self):
        value = self._read_value(self.data)
        return value

    def _read_value(self, buf):
        if len(buf) == 0:
            return None
        additional_info = buf[0] & 0b000_11111
        if additional_info < 24:
            argument = additional_info
            argument_len = 0
        elif additional_info == 24:
            argument_len = 1
            argument = struct.unpack('>B', buf[1:1+argument_len])[0]
        elif additional_info == 25:
            argument_len = 2
            argument = struct.unpack('>H', buf[1:1+argument_len])[0]
        elif additional_info == 26:
            argument_len = 4
            argument = struct.unpack('>I', buf[1:1+argument_len])[0]
        elif additional_info == 27:
            argument_len = 8
            argument = struct.unpack('>Q', buf[1:1+argument_len])[0]
        elif additional_info == 31:
            # Indefinite length for types 2-5
            argument = None
            argument_len = 0
        match buf[0] >> 5:
            case 0:
                major_type = MajorType.PositiveInteger
            case 1:
                major_type = MajorType.NegativeInteger
            case 2:
                major_type = MajorType.ByteString
            case 3:
                major_type = MajorType.TextString
            case 4:
                major_type = MajorType.Array
            case 5:
                major_type = MajorType.Map
            case 6:
                major_type = MajorType.Tag
            case 7:
                major_type = MajorType.SimpleOrFloat
        # advance beyond type info
        self.pos += 1
        self.pos += argument_len

        bytes_consumed = 0
        match major_type:
            case MajorType.PositiveInteger:
                value = argument

            case MajorType.NegativeInteger:
                value = -1 - argument

            case MajorType.ByteString:
                string_len = argument
                if string_len is None:
                    string_len = 0
                    # indefinite length
                    value = ""
                    while self.data[self.pos] != 0xff:
                        val = self._read_value(self.data[self.pos:])[0]
                        value += val
                    string_len = 1
                else:
                    value = self.data[self.pos:self.pos+string_len]
                bytes_consumed = string_len

            case MajorType.TextString:
                string_len = argument
                if string_len is None:
                    # indefinite length
                    value = ""
                    while self.data[self.pos] != 0xff:
                        val = self._read_value(self.data[self.pos:])
                        value += val
                    bytes_consumed = 1
                else:
                    value = codecs.utf_8_decode(self.data[self.pos:self.pos+string_len])[0]
                    bytes_consumed = string_len

            case MajorType.Map:
                value = {}
                if argument is None:
                    argument = 0
                    value = {}
                    while self.data[self.pos] != 0xff:
                        inner_key = self._read_value(self.data[self.pos:])
                        inner_value = self._read_value(self.data[self.pos:])
                        value[inner_key] = inner_value
                    bytes_consumed = 1
                else:
                    for _ in range(argument):
                        inner_key = self._read_value(self.data[self.pos:])
                        inner_value = self._read_value(self.data[self.pos:])
                        value[inner_key] = inner_value

            case MajorType.Array:
                value = []
                if argument is None:
                    argument = 0
                    value = []
                    while self.data[self.pos] != 0xff:
                        inner_value = self._read_value(self.data[self.pos:])
                        value.append(inner_value)
                    bytes_consumed = 1
                else:
                    for _ in range(argument):
                        inner_value = self._read_value(self.data[self.pos:])
                        value.append(inner_value)

            case MajorType.Tag:
                raise Exception("Tag support not implemented")

            case MajorType.SimpleOrFloat:
                if argument == 20:
                    value = False
                elif argument == 21:
                    value = True
                elif argument == 22:
                    value = None
                elif argument == 23:
                    value = None
                else:
                    raise Exception("Float parsing not implemented")

        self.pos += bytes_consumed
        return value


def load(cbor):
    parser = Parser(cbor)
    return parser.parse()
