from pathlib import Path


def read_vlq(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    while True:
        byte = data[offset]
        offset += 1
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, offset


def extract_pitchwheel_values(path: Path) -> list[int]:
    data = path.read_bytes()
    offset = 14  # MThd + length + six-byte format header
    values = []

    while offset < len(data):
        chunk_type = data[offset : offset + 4]
        chunk_length = int.from_bytes(data[offset + 4 : offset + 8], "big")
        chunk = data[offset + 8 : offset + 8 + chunk_length]
        offset += 8 + chunk_length

        if chunk_type != b"MTrk":
            continue

        cursor = 0
        running_status = None
        while cursor < len(chunk):
            _, cursor = read_vlq(chunk, cursor)

            if chunk[cursor] & 0x80:
                status = chunk[cursor]
                cursor += 1
                if status < 0xF0:
                    running_status = status
            else:
                if running_status is None:
                    raise ValueError("invalid running status")
                status = running_status

            if status == 0xFF:
                cursor += 1  # meta-event type
                length, cursor = read_vlq(chunk, cursor)
                cursor += length
            elif status in (0xF0, 0xF7):
                length, cursor = read_vlq(chunk, cursor)
                cursor += length
            else:
                event_type = status & 0xF0
                length = 1 if event_type in (0xC0, 0xD0) else 2
                event_data = chunk[cursor : cursor + length]
                cursor += length

                if event_type == 0xE0:
                    raw = event_data[0] | (event_data[1] << 7)
                    values.append(raw - 8192)

    return values


pitchwheel = extract_pitchwheel_values(
    Path(__file__).resolve().parents[1] / "challenge" / "1000-7.mid"
)

if len(pitchwheel) % 2:
    raise ValueError("pitchwheel event count is not even")

pairs = list(zip(pitchwheel[::2], pitchwheel[1::2]))
if not all(pair in {(2304, -2304), (-2304, 2304)} for pair in pairs):
    raise ValueError("unexpected pitchwheel pair")

bits = "".join("1" if pair == (2304, -2304) else "0" for pair in pairs)
decoded = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))

start = decoded.index(b"grodno{")
end = decoded.index(b"}", start) + 1
print(decoded[start:end].decode())
