import base64
import cbor
import json
import unittest
test_vectors = json.loads(r"""[
  {
    "cbor": "AA==",
    "hex": "00",
    "roundtrip": true,
    "decoded": 0
  },
  {
    "cbor": "AQ==",
    "hex": "01",
    "roundtrip": true,
    "decoded": 1
  },
  {
    "cbor": "Cg==",
    "hex": "0a",
    "roundtrip": true,
    "decoded": 10
  },
  {
    "cbor": "Fw==",
    "hex": "17",
    "roundtrip": true,
    "decoded": 23
  },
  {
    "cbor": "GBg=",
    "hex": "1818",
    "roundtrip": true,
    "decoded": 24
  },
  {
    "cbor": "GBk=",
    "hex": "1819",
    "roundtrip": true,
    "decoded": 25
  },
  {
    "cbor": "GGQ=",
    "hex": "1864",
    "roundtrip": true,
    "decoded": 100
  },
  {
    "cbor": "GQPo",
    "hex": "1903e8",
    "roundtrip": true,
    "decoded": 1000
  },
  {
    "cbor": "GgAPQkA=",
    "hex": "1a000f4240",
    "roundtrip": true,
    "decoded": 1000000
  },
  {
    "cbor": "GwAAAOjUpRAA",
    "hex": "1b000000e8d4a51000",
    "roundtrip": true,
    "decoded": 1000000000000
  },
  {
    "cbor": "G///////////",
    "hex": "1bffffffffffffffff",
    "roundtrip": true,
    "decoded": 18446744073709551615
  },
  {
    "cbor": "wkkBAAAAAAAAAAA=",
    "hex": "c249010000000000000000",
    "roundtrip": true,
    "decoded": 18446744073709551616
  },
  {
    "cbor": "O///////////",
    "hex": "3bffffffffffffffff",
    "roundtrip": true,
    "decoded": -18446744073709551616
  },
  {
    "cbor": "w0kBAAAAAAAAAAA=",
    "hex": "c349010000000000000000",
    "roundtrip": true,
    "decoded": -18446744073709551617
  },
  {
    "cbor": "IA==",
    "hex": "20",
    "roundtrip": true,
    "decoded": -1
  },
  {
    "cbor": "KQ==",
    "hex": "29",
    "roundtrip": true,
    "decoded": -10
  },
  {
    "cbor": "OGM=",
    "hex": "3863",
    "roundtrip": true,
    "decoded": -100
  },
  {
    "cbor": "OQPn",
    "hex": "3903e7",
    "roundtrip": true,
    "decoded": -1000
  },
  {
    "cbor": "9A==",
    "hex": "f4",
    "roundtrip": true,
    "decoded": false
  },
  {
    "cbor": "9Q==",
    "hex": "f5",
    "roundtrip": true,
    "decoded": true
  },
  {
    "cbor": "9g==",
    "hex": "f6",
    "roundtrip": true,
    "decoded": null
  },
  {
    "cbor": "YA==",
    "hex": "60",
    "roundtrip": true,
    "decoded": ""
  },
  {
    "cbor": "YWE=",
    "hex": "6161",
    "roundtrip": true,
    "decoded": "a"
  },
  {
    "cbor": "ZElFVEY=",
    "hex": "6449455446",
    "roundtrip": true,
    "decoded": "IETF"
  },
  {
    "cbor": "YiJc",
    "hex": "62225c",
    "roundtrip": true,
    "decoded": "\"\\"
  },
  {
    "cbor": "YsO8",
    "hex": "62c3bc",
    "roundtrip": true,
    "decoded": "ü"
  },
  {
    "cbor": "Y+awtA==",
    "hex": "63e6b0b4",
    "roundtrip": true,
    "decoded": "水"
  },
  {
    "cbor": "ZPCQhZE=",
    "hex": "64f0908591",
    "roundtrip": true,
    "decoded": "𐅑"
  },
  {
    "cbor": "gA==",
    "hex": "80",
    "roundtrip": true,
    "decoded": [

    ]
  },
  {
    "cbor": "gwECAw==",
    "hex": "83010203",
    "roundtrip": true,
    "decoded": [
      1,
      2,
      3
    ]
  },
  {
    "cbor": "gwGCAgOCBAU=",
    "hex": "8301820203820405",
    "roundtrip": true,
    "decoded": [
      1,
      [
        2,
        3
      ],
      [
        4,
        5
      ]
    ]
  },
  {
    "cbor": "mBkBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgYGBk=",
    "hex": "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
    "roundtrip": true,
    "decoded": [
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
      17,
      18,
      19,
      20,
      21,
      22,
      23,
      24,
      25
    ]
  },
  {
    "cbor": "oA==",
    "hex": "a0",
    "roundtrip": true,
    "decoded": {
    }
  },
  {
    "cbor": "omFhAWFiggID",
    "hex": "a26161016162820203",
    "roundtrip": true,
    "decoded": {
      "a": 1,
      "b": [
        2,
        3
      ]
    }
  },
  {
    "cbor": "gmFhoWFiYWM=",
    "hex": "826161a161626163",
    "roundtrip": true,
    "decoded": [
      "a",
      {
        "b": "c"
      }
    ]
  },
  {
    "cbor": "pWFhYUFhYmFCYWNhQ2FkYURhZWFF",
    "hex": "a56161614161626142616361436164614461656145",
    "roundtrip": true,
    "decoded": {
      "a": "A",
      "b": "B",
      "c": "C",
      "d": "D",
      "e": "E"
    }
  },
  {
    "cbor": "f2VzdHJlYWRtaW5n/w==",
    "hex": "7f657374726561646d696e67ff",
    "roundtrip": false,
    "decoded": "streaming"
  },
  {
    "cbor": "n/8=",
    "hex": "9fff",
    "roundtrip": false,
    "decoded": [

    ]
  },
  {
    "cbor": "nwGCAgOfBAX//w==",
    "hex": "9f018202039f0405ffff",
    "roundtrip": false,
    "decoded": [
      1,
      [
        2,
        3
      ],
      [
        4,
        5
      ]
    ]
  },
  {
    "cbor": "nwGCAgOCBAX/",
    "hex": "9f01820203820405ff",
    "roundtrip": false,
    "decoded": [
      1,
      [
        2,
        3
      ],
      [
        4,
        5
      ]
    ]
  },
  {
    "cbor": "gwGCAgOfBAX/",
    "hex": "83018202039f0405ff",
    "roundtrip": false,
    "decoded": [
      1,
      [
        2,
        3
      ],
      [
        4,
        5
      ]
    ]
  },
  {
    "cbor": "gwGfAgP/ggQF",
    "hex": "83019f0203ff820405",
    "roundtrip": false,
    "decoded": [
      1,
      [
        2,
        3
      ],
      [
        4,
        5
      ]
    ]
  },
  {
    "cbor": "nwECAwQFBgcICQoLDA0ODxAREhMUFRYXGBgYGf8=",
    "hex": "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
    "roundtrip": false,
    "decoded": [
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9,
      10,
      11,
      12,
      13,
      14,
      15,
      16,
      17,
      18,
      19,
      20,
      21,
      22,
      23,
      24,
      25
    ]
  },
  {
    "cbor": "v2FhAWFinwID//8=",
    "hex": "bf61610161629f0203ffff",
    "roundtrip": false,
    "decoded": {
      "a": 1,
      "b": [
        2,
        3
      ]
    }
  },
  {
    "cbor": "gmFhv2FiYWP/",
    "hex": "826161bf61626163ff",
    "roundtrip": false,
    "decoded": [
      "a",
      {
        "b": "c"
      }
    ]
  },
  {
    "cbor": "v2NGdW71Y0FtdCH/",
    "hex": "bf6346756ef563416d7421ff",
    "roundtrip": false,
    "decoded": {
      "Fun": true,
      "Amt": -2
    }
  }
]""")

class CborTests(unittest.TestCase):
    def test_execute_vectors(self):
        for i, tv in enumerate(test_vectors):
            with self.subTest(i=i, hex=tv['hex'], expected=json.dumps(tv['decoded']), major_type=format(int(tv['hex'][:2], 16), '08b')):
                data = base64.b64decode(tv['cbor'])
                if (data[0] >> 5) >= 6:
                    continue
                expected = tv['decoded']
                actual = cbor.load(data)
                self.assertEqual(expected, actual)
