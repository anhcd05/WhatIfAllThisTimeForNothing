# ntlmv2-pcap

- **Category:** Forensics / Network (PCAP, bắt NTLMv2)
- **File đề:** `challenges/ntlmv2-pcap/capture.pcap` (34386 byte, md5 `d56dbbe52534fa3c26c4b90dc820c130`). Tải gốc: `capture.zip`, mật khẩu giải nén `setc`; PCAP ở local đã giải sẵn. Kèm `description.txt` và `analyze_pcap.py` (scapy, tự trích NTLMSSP).

## Tóm tắt đề

Nghi một vụ "inside job" trên máy `192.168.56.104`; credential có thể bị rò từ máy `192.168.56.33`. Nhiệm vụ: phân tích PCAP, xác định phương thức tấn công, khôi phục credential bị rò, và dựng flag.

Định dạng flag:

```
flag{<user>::<domain>:<16 hex>:<32 hex>:<620 hex>}
```

Cấu trúc này khớp **chính xác** định dạng hash **NetNTLMv2** của hashcat `-m 5600`: `user::DOMAIN:server_challenge:NTProofStr:blob`.

Toàn bộ phân tích là **tĩnh** (parse gói, đọc byte); **không chạy** chương trình nào.

## Phân tích (chi tiết: offset/trường thật)

### 1. Nhận diện tấn công

`strings capture.pcap` (thật) cho thấy: `WINDOMAIN`, `WINDOMAIN.LOCAL`, host `dcc02`, `cifs`. Protocol hierarchy có **NBNS/NetBIOS** rồi **SMB + NTLMSSP** — chữ ký kinh điển của **LLMNR/NBT-NS poisoning / SMB relay** (kiểu Responder): nạn nhân không phân giải được tên qua DNS → broadcast hỏi qua NBT-NS → kẻ tấn công trả lời giả "máy đó là tao" → nạn nhân kết nối và **gửi chứng thực NTLMv2**.

*Vì sao khớp dạng flag?* Vì `<user>::<domain>:<16hex>:<32hex>:<620hex>` chính là 4 trường của NetNTLMv2.

### 2. NTLMSSP — 3 bản tin

- **Type 1 (NEGOTIATE):** client đề nghị.
- **Type 2 (CHALLENGE):** server gửi **server challenge** 8 byte.
- **Type 3 (AUTHENTICATE):** client gửi **NTLMv2 response** (bằng chứng biết mật khẩu) kèm user/domain/workstation.

NTLMv2 response = **NTProofStr (16 byte đầu)** + **blob (phần còn lại)**. Để dựng hash offline cần: `username`, `domain`, `server challenge`, `NTProofStr`, `blob`.

### 3. Offset parse thật (từ `analyze_pcap.py`, dùng scapy)

Tìm chữ ký `NTLMSSP\x00` trong payload SMB (có TCP reassembly), đọc `MessageType` ở offset `+8`:

- **Type 2:** `server_challenge = payload[i+24 : i+32]` (8 byte).
- **Type 3:** mỗi trường là bộ (len 2 byte @ `off`, offset 4 byte @ `off+4`):
  - DomainName @ `28`, UserName @ `36`, Workstation @ `44`, **LM response @ `12`**, **NT response @ `20`**.
  - `user   = field(36).decode("utf-16le")`
  - `domain = field(28).decode("utf-16le")`
  - `ntresp = field(20).hex()` → `NTProofStr = ntresp[:32]`, `blob = ntresp[32:]`.

### 4. Giá trị khôi phục

- **User / domain:** `bob` / `WINDOMAIN`
- **Server challenge (16 hex):** `46f422cd882b169d`
- **NTProofStr (32 hex):** `4837e8d20080f19cc2762798c9373a8e`
- **Blob (620 hex):** `0101000000000000934f159ee807dc01…0000000000`

Blob giải mã ra target info: `WINDOMAIN`, `win10-2.windomain.local`, `cifs/dcc02` — khớp `strings`. **Kẻ phản bội:** `WINDOMAIN\bob`.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Nhận diện NTLMv2 capture:** NBNS/LLMNR + SMB + NTLMSSP → mô hình poisoning. VÌ SAO chắc chắn: dạng flag 4 cụm hex độ dài 16/32/620 trùng **1-1** layout hash NetNTLMv2 → đề đang yêu cầu dựng hash từ cặp Type 2 / Type 3.
- **Hiểu cấu trúc NTLMSSP:** Type 2 chứa `ServerChallenge` (8 byte @ offset 24 sau chữ ký); Type 3 chứa các cặp len/offset cho Domain/User/Workstation/LM/NT. `NtChallengeResponse = NTProofStr(16B) || blob`.
- **Dựng hash hashcat `-m 5600`:** `user::DOMAIN:serverchallenge:NTProofStr:blob`. VÌ SAO — vừa là flag, vừa là input để crack mật khẩu của `bob` nếu cần (ở đây flag chính là hash, không bắt buộc crack).

## Lời giải chi tiết (chạy lại được)

### Cách 1 — tshark (nhanh, chính xác)

```bash
# Server challenge (Type 2)
tshark -r capture.pcap -Y "ntlmssp.ntlmserverchallenge" \
       -T fields -e ntlmssp.ntlmserverchallenge | head -n1
# -> 46f422cd882b169d

# User, domain, NT response (Type 3)
tshark -r capture.pcap \
       -Y "ntlmssp.auth.username && ntlmssp.auth.ntresponse" \
       -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain \
       -e ntlmssp.auth.ntresponse
# -> bob   WINDOMAIN   4837e8d2...(652 hex)
```

Rồi ghép (bash):

```bash
SC=$(tshark -r capture.pcap -Y "ntlmssp.ntlmserverchallenge" \
     -T fields -e ntlmssp.ntlmserverchallenge | head -n1)
read USER DOMAIN NTRESP < <(tshark -r capture.pcap \
     -Y "ntlmssp.auth.username && ntlmssp.auth.ntresponse" \
     -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain \
     -e ntlmssp.auth.ntresponse | head -n1)
PROOF=${NTRESP:0:32}      # NTProofStr = 32 hex đầu
BLOB=${NTRESP:32}         # blob = phần còn lại (620 hex)
echo "flag{${USER}::${DOMAIN}:${SC}:${PROOF}:${BLOB}}"
echo "${USER}::${DOMAIN}:${SC}:${PROOF}:${BLOB}"   # dòng hashcat -m 5600
```

### Cách 2 — scapy tự động

`python3 analyze_pcap.py capture.pcap` — script tìm `NTLMSSP\x00`, đọc MessageType @+8, với Type 2 lấy `payload[i+24:i+32]`, với Type 3 đọc field theo offset (Domain@28, User@36, Host@44, NT@20) rồi in flag + dòng hashcat `-m 5600`. Lõi parse:

```python
sig = b"NTLMSSP\x00"
i = payload.find(sig)
mtype = int.from_bytes(payload[i+8:i+12], "little")
if mtype == 2:
    server_challenge = payload[i+24:i+32].hex()          # 8 byte
elif mtype == 3:
    def field(off):
        flen = int.from_bytes(payload[i+off:i+off+2], "little")
        foff = int.from_bytes(payload[i+off+4:i+off+8], "little")
        return payload[i+foff:i+foff+flen]
    user   = field(36).decode("utf-16le")
    domain = field(28).decode("utf-16le")
    ntresp = field(20).hex()
    ntproof, blob = ntresp[:32], ntresp[32:]
```

### Cách 3 — Wireshark GUI

Filter `ntlmssp`; mở gói CHALLENGE lấy `NTLM Server Challenge`; mở gói AUTHENTICATE lấy `User name`, `Domain name`, `NTLMv2 Response` (tách 16 byte đầu = NTProofStr, phần sau = blob).

### Crack mật khẩu (tùy chọn)

```bash
hashcat -m 5600 'BOB::WINDOMAIN:46f422cd882b169d:4837e8d20080f19cc2762798c9373a8e:0101...' rockyou.txt
```

## Flag

```
flag{bob::WINDOMAIN:46f422cd882b169d:4837e8d20080f19cc2762798c9373a8e:0101000000000000934f159ee807dc01c70a33e89710d3140000000002001200570049004e0044004f004d00410049004e0001000e00570049004e00310030002d00320004001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0003002e00770069006e00310030002d0032002e00770069006e0064006f006d00610069006e002e006c006f00630061006c0005001e00770069006e0064006f006d00610069006e002e006c006f00630061006c0007000800934f159ee807dc0106000400020000000800300030000000000000000000000000200000d680c970ffd7be19f29a3b7d61c7d3353ee63fdfa4fd83344a83f7681a6b65980a001000000000000000000000000000000000000900140063006900660073002f00640063006300300032000000000000000000}
```

"Kẻ phản bội" = `WINDOMAIN\bob`, người bị thu NTLMv2 credential qua NBNS/SMB. (Chuỗi `WINDOMAIN` là domain Windows trong đề, giữ nguyên.)

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu nhận diện:** PCAP có NBNS/LLMNR broadcast + SMB (445/139) + NTLMSSP; định dạng flag gồm nhiều cụm hex độ dài cố định (16 / 32 / ~600+).
- **Quy trình:**
  1. `tshark -r x.pcap -Y "ntlmssp"` hoặc Wireshark filter `ntlmssp` để khoanh phiên xác thực.
  2. Type 2 → `ntlmssp.ntlmserverchallenge` (server challenge, 16 hex).
  3. Type 3 → `ntlmssp.auth.username`, `ntlmssp.auth.domain`, `ntlmssp.auth.ntresponse`.
  4. Tách `ntresponse`: 32 hex đầu = NTProofStr, phần còn lại = blob.
  5. Ghép `user::DOMAIN:serverchallenge:NTProofStr:blob` → vừa là flag vừa là input hashcat `-m 5600`.
- **Công cụ:** Wireshark/tshark, scapy, hashcat/john (netntlmv2), pcredz (tự rút NetNTLMv2 từ pcap), Responder (để hiểu nguồn gốc traffic).
- **Bẫy hay gặp:** (a) nhầm **LM response** (field @12 / `ntlmssp.auth.lmresponse`) với **NT response** (@20); (b) quên TCP reassembly khiến NTLMSSP bị cắt giữa 2 gói; (c) có nhiều lần auth — phải bám đúng cặp **Type 2 + Type 3 cùng phiên** và đúng host của đề (`.104`/`.33`); (d) nhầm NTProofStr lấy từ field khác — nó là **32 hex đầu** của chính `ntresponse`, blob là phần còn lại.
- **Checklist ngắn:** filter ntlmssp → lấy challenge (Type 2) → lấy user/domain/ntresponse (Type 3) → cắt 32 / phần dư → ghép theo format.
