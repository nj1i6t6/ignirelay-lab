"""IgniRelay wire reference implementations (lab Python, MASTER §6 B2).

Mirrors the App repo's frozen wire contracts byte-for-byte; invents nothing.
  - keys         : field_id / field_mac_key / lora_mac_key derivation
  - envelope_v3  : EventEnvelope v3 proto codec + 141-B canonical + verify
  - lora_v1      : LORA-WIRE v1 frame codec (encode/decode/mac/crc/replay)
"""
