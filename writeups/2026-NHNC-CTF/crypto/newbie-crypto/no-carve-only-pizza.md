---
ctf_name: "NHNC CTF 2026"
challenge_name: "newbie-crypto"
category: "crypto"
difficulty: "easy"
author: "no-carve-only-pizza"
date: "2026-07-04"
points: 100
tags: [AES-CTR, nonce-reuse, known-plaintext, stream-cipher]
---

# newbie-crypto

## 문제 설명

AES-CTR로 암호화된 여러 개의 티켓 ciphertext가 주어진다.  
게스트 티켓 4개와 관리자 티켓 1개가 같은 코드에서 생성되고, 관리자 티켓 안에 flag가 들어 있다.

제공 파일은 다음과 같다.

```text
dist/
├── chall.py
├── output.txt
└── public.txt
```

## 분석

`chall.py`를 보면 모든 티켓이 같은 `KEY`와 같은 `NONCE`로 암호화된다.

```python
KEY = get_random_bytes(16)
NONCE = b"ticket42"

def encrypt(ticket):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(ticket).hex()
```

AES-CTR은 블록 암호를 keystream 생성기로 사용하는 모드이다.  
평문을 직접 AES로 암호화하는 것이 아니라, nonce와 counter로 만든 keystream을 평문과 XOR한다.

```text
ciphertext = plaintext XOR keystream
plaintext  = ciphertext XOR keystream
```

따라서 같은 key와 nonce를 재사용하면 같은 keystream이 다시 나온다.  
이 상태에서 평문을 하나라도 알면 다음처럼 keystream을 복구할 수 있다.

```text
keystream = known_plaintext XOR known_ciphertext
```

문제는 게스트 티켓의 생성 방식과 참석자 목록을 모두 공개한다.

```python
ATTENDEES = [
    ("hsuan0223x", "H-0223"),
    ("NHNC", "T-0704"),
    (
        "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
        "N-0705",
    ),
    ("AI_WILL_SLOP", "C-114514"),
]

def make_guest_ticket(name, seat):
    return encode_ticket(
        {
            "event": "modern-crypto-101",
            "role": "guest",
            "name": name,
            "seat": seat,
            "note": "enjoy the workshop",
        }
    )
```

즉, `guest_cipher_*`의 평문은 전부 재구성할 수 있다.

## 풀이

게스트 티켓 평문을 `chall.py`와 같은 JSON 직렬화 방식으로 만든다.

```python
def encode_ticket(ticket):
    return json.dumps(ticket, separators=(",", ":")).encode()
```

그리고 각 게스트 ciphertext와 XOR해서 keystream을 복구한다.  
세 번째 게스트 이름이 길기 때문에 관리자 티켓 전체를 덮을 만큼 충분한 길이의 keystream을 얻을 수 있다.

```python
keystream = bytearray(max(len(cipher) for cipher in ciphers.values()))
known = [False] * len(keystream)

for index, (name, seat) in enumerate(ATTENDEES):
    plaintext = make_guest_ticket(name, seat)
    ciphertext = ciphers[f"guest_cipher_{index}"]
    for offset, (cipher_byte, plain_byte) in enumerate(zip(ciphertext, plaintext)):
        stream_byte = cipher_byte ^ plain_byte
        keystream[offset] = stream_byte
        known[offset] = True
```

이제 `admin_cipher`를 같은 keystream으로 XOR하면 관리자 티켓이 복호화된다.

```python
admin_plain = bytes(
    admin_cipher[i] ^ keystream[i]
    for i in range(len(admin_cipher))
)
print(admin_plain.decode())
```

전체 solve script는 다음과 같다.

```python
import json
import re
from pathlib import Path


ATTENDEES = [
    ("hsuan0223x", "H-0223"),
    ("NHNC", "T-0704"),
    (
        "this_chal_not_need_read_read_read_read_read_read_read_read_read_read_read",
        "N-0705",
    ),
    ("AI_WILL_SLOP", "C-114514"),
]


def encode_ticket(ticket):
    return json.dumps(ticket, separators=(",", ":")).encode()


def make_guest_ticket(name, seat):
    return encode_ticket(
        {
            "event": "modern-crypto-101",
            "role": "guest",
            "name": name,
            "seat": seat,
            "note": "enjoy the workshop",
        }
    )


output = Path("dist/output.txt").read_text()
ciphers = {
    match.group(1): bytes.fromhex(match.group(2))
    for match in re.finditer(r"(guest_cipher_\d+|admin_cipher) = ([0-9a-f]+)", output)
}

keystream = bytearray(max(len(cipher) for cipher in ciphers.values()))
known = [False] * len(keystream)

for index, (name, seat) in enumerate(ATTENDEES):
    plaintext = make_guest_ticket(name, seat)
    ciphertext = ciphers[f"guest_cipher_{index}"]
    for offset, (cipher_byte, plain_byte) in enumerate(zip(ciphertext, plaintext)):
        stream_byte = cipher_byte ^ plain_byte
        if known[offset] and keystream[offset] != stream_byte:
            raise ValueError(f"keystream mismatch at offset {offset}")
        keystream[offset] = stream_byte
        known[offset] = True

admin_cipher = ciphers["admin_cipher"]
admin_plain = bytes(admin_cipher[i] ^ keystream[i] for i in range(len(admin_cipher)))
print(admin_plain.decode())
```

실행 결과는 다음과 같다.

```text
{"event":"modern-crypto-101","role":"admin","name":"organizer","seat":"ROOT","note":"priority access granted","flag":"NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}"}
```

## 플래그

```text
NHNC{c7r_k3y57r34m5_5h0uld_n3v3r_r37urn}
```

## 배운 점

CTR 모드에서 nonce는 단순한 장식값이 아니다. 같은 key에서 nonce를 재사용하면 같은 keystream이 생성되고, 이는 multi-time pad 문제가 된다.

특히 JSON처럼 구조가 고정되어 있거나 일부 평문을 쉽게 예측할 수 있는 경우에는 `known_plaintext XOR ciphertext`만으로 keystream을 회수할 수 있다.
