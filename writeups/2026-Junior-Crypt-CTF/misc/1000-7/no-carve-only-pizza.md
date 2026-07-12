---
ctf_name: "Junior Crypt 2026 CTF"
challenge_name: "1000-7"
category: "misc"
difficulty: "medium"
author: "no-carve-only-pizza"
date: "2026-07-11"
tags: [MIDI, steganography, pitchwheel, binary, audio]
---

# 1000-7

## 문제 개요

- 대회: Junior Crypt 2026 CTF
- 문제명: 1000-7
- 분야: Misc / Steganography
- 난이도: Medium
- 출제자: `@vvanuss`
- 제공 파일: `1000-7.mid`
- Flag: `grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}`

문제 설명은 다음과 같다.

```text
Some melodies stay in your head.
Some leave something else behind.
```

`head`와 `behind`가 강조되어 있으므로 MIDI 헤더와 음악 이벤트 뒤에 숨은 데이터를 우선 확인했다.

## 파일 분석

`file`로 확인하면 표준 MIDI 파일이며 format 1, 두 개의 트랙, 480 PPQN을 사용한다.

```bash
file 1000-7.mid
```

```text
Standard MIDI data (format 1) using 2 tracks at 1/480
```

파일은 `MThd` 헤더와 두 개의 `MTrk` 청크로 구성되어 있다. 각 청크의 선언 길이를 계산하면 파일 전체 크기와 정확히 일치하므로, 파일 끝에 ZIP이나 별도 데이터를 단순히 덧붙인 형태는 아니다.

문자열을 확인하면 첫 트랙의 제목도 찾을 수 있다.

```text
Unravel - Tokyo Ghoul
```

## 숨겨진 채널 찾기

두 번째 트랙의 이벤트 종류를 세어 보면 일반적인 note on/off 이벤트 외에 pitch wheel 이벤트가 752개 존재한다.

pitch wheel 값을 확인하면 모든 이벤트가 다음 두 값 중 하나다.

```text
+2304
-2304
```

개수도 각각 376개로 같으며, 이벤트를 두 개씩 묶으면 가능한 조합은 정확히 두 종류뿐이다.

```text
(+2304, -2304)
(-2304, +2304)
```

임의의 자연스러운 pitch bend라기보다 두 상태를 표현하는 이진 데이터 구조다. 따라서 다음과 같이 비트로 대응시켰다.

```text
(+2304, -2304) -> 1
(-2304, +2304) -> 0
```

752개의 이벤트를 두 개씩 묶으면 376비트가 되고, 이는 정확히 47바이트다.

## 복호화

pitch wheel 쌍을 비트로 바꾸고 8비트씩 묶어 big-endian 정수로 변환한다.

```python
pairs = list(zip(pitchwheel[::2], pitchwheel[1::2]))
bits = "".join(
    "1" if pair == (2304, -2304) else "0"
    for pair in pairs
)
decoded = bytes(
    int(bits[i:i + 8], 2)
    for i in range(0, len(bits), 8)
)
print(decoded)
```

결과 앞뒤에는 비출력 바이트가 조금 포함되지만, 가운데에서 완전한 플래그를 확인할 수 있다.

```text
\xc0\xde*grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}\xc5\x11
```

풀이 스크립트는 외부 MIDI 라이브러리 없이 MIDI 청크와 VLQ를 직접 파싱하고, 플래그 부분만 찾아 출력하도록 작성했다.

```bash
python3 solve/solve.py
```

```text
grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}
```

## 플래그

```text
grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}
```

## 배운 점

MIDI는 소리 자체가 아니라 시간, 음표, velocity, pitch bend 같은 이벤트를 저장한다. 따라서 정상 음악을 유지하면서도 잘 사용하지 않는 이벤트나 파라미터의 패턴에 별도의 데이터를 숨길 수 있다.

이 문제에서는 pitch wheel 이벤트 하나를 곧바로 한 비트로 쓰지 않고, 부호가 반대인 두 이벤트의 순서를 이용해 한 비트를 표현했다. 이벤트 값의 종류뿐 아니라 반복 단위와 인접 이벤트 사이의 관계까지 확인하는 것이 핵심이었다.
