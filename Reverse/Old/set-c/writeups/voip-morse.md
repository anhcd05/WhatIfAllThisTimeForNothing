# voip-morse

- **Category:** Forensics / Network (VoIP + audio stego)
- **File đề:**
  - `challenges/voip-morse/packet.pcap` — 174067 byte, md5 `5e3824660031774d00d76b7241de6e68` (pcap microsecond, Ethernet, bắt một phiên gọi VoIP).
  - `challenges/voip-morse/sonic_visualiser.png` — 63279 byte (ảnh gợi ý: ảnh chụp spectrogram trong Sonic Visualiser).
  - `challenges/voip-morse/description.txt` — mô tả đề (tiếng Anh).

## Tóm tắt đề

Một cuộc gọi VoIP đã được bắt gói. Phần báo hiệu SIP trông hoàn toàn bình thường, cuộc gọi
ngắn và "vô thưởng vô phạt". Nhưng thông điệp thật **không nằm trong SIP header / metadata** mà
**giấu trong luồng media (RTP)**. Đề yêu cầu: xác định codec, trích audio, rồi "nghe kỹ" (thực
chất là **nhìn phổ**) để đọc ra flag. Định dạng: `flag{the message you found}`.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

Phân tích **tĩnh** bằng `strings` trên `packet.pcap` (không mở công cụ động nào cũng đã đủ manh
mối). Các bản tin SIP đọc được THẬT trong file:

```
INVITE sip:bob@10.0.0.2 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-69571
From: "Alice" <sip:alice@10.0.0.1>;tag=f1846
To:   <sip:bob@10.0.0.2>
CSeq: 1 INVITE
Allow: INVITE, ACK, BYE
m=audio 4000 RTP/AVP 0          <-- offer của Alice: media audio, payload type 0
a=rtpmap:0 PCMU/8000            <-- PT 0 = codec PCMU (G.711 µ-law), 8000 Hz
a=ptime:20                      <-- mỗi gói RTP = 20 ms tiếng
SIP/2.0 200 OK
 ... To: <sip:bob@10.0.0.2>;tag=t2231 ...
m=audio 5004 RTP/AVP 0          <-- answer của Bob: cổng 5004, cũng PT 0 (PCMU)
a=rtpmap:0 PCMU/8000
ACK sip:bob@10.0.0.2 SIP/2.0
BYE sip:bob@10.0.0.2 SIP/2.0
SIP/2.0 200 OK
```

Hằng số/tham số THẬT rút ra từ pcap:

| Thông số | Giá trị thật |
|---|---|
| Caller → Callee | Alice `10.0.0.1` → Bob `10.0.0.2` |
| Cổng SIP | UDP 5060 |
| Cổng RTP media | Alice gửi tới 4000, Bob gửi tới **5004** (từ dòng `m=audio`) |
| Codec | `a=rtpmap:0 PCMU/8000` → **RTP payload type 0 = G.711 µ-law, 8 kHz** |
| Packetization | `a=ptime:20` → 20 ms/gói → 160 mẫu µ-law/gói (8000 Hz × 0.02 s) |

Vì sao những giá trị này đủ để giải:
- **PT=0 (PCMU)**: báo cho ta biết payload RTP là G.711 µ-law — mỗi mẫu âm thanh là **1 byte**
  µ-law, giải về PCM16 bằng `audioop.ulaw2lin(data, 2)`.
- **ptime=20 / 8000 Hz**: mỗi gói chứa đúng 160 byte payload media; dùng để kiểm tra khi lọc
  gói (loại RTCP, loại gói lỗi).
- Phần SIP **không** chứa flag — đây là bẫy hướng người giải tập trung sai chỗ.

Khi ráp RTP → WAV, audio thu được **không phải giọng người** mà là chuỗi **tone bật/tắt**. Mở
trong Sonic Visualiser (xem `sonic_visualiser.png`) thì các chùm tone tạo thành **mã Morse**
(tone ngắn = chấm `.`, tone dài = gạch `-`, khoảng lặng = ngăn ký tự/từ). Chuỗi Morse THẬT:

```
-.-- ----- ..- .- .-. .  -.. .  -.-. --- -.. . -..  ...- ----- .---- .--.
  Y    0    U  A  R  E    D  E    C   O   D  E  D     V    0     1    P
```

Giải ra chuỗi (dùng leet `0`=O, `1`=I): `Y0UAREDECODEDV01P`.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Đọc SDP để xác định codec (`a=rtpmap`)** — VÌ không biết codec thì không biết cách giải
  payload RTP thành âm thanh. PT 0 = PCMU (µ-law), PT 8 = PCMA (A-law), các PT khác (Opus,
  G.729...) cần decoder tương ứng.
- **Reassemble RTP theo SSRC + sequence/timestamp** — VÌ gói mạng có thể tới sai thứ tự; không
  sắp lại thì âm thanh rối, Morse không đọc được. Lọc RTP = version 2 (`(byte0 >> 6) == 2`),
  header ≥ 12 byte, loại RTCP (PT 72–76).
- **Giải G.711 µ-law → PCM16 → WAV** — VÌ µ-law là nén logarit 8-bit; phải giãn về PCM tuyến
  tính 16-bit thì mới ghi WAV chuẩn để quan sát/nghe.
- **Audio stego kiểu Morse → xem spectrogram** — VÌ tai người khó phân biệt tone dài/ngắn,
  nhưng trên phổ thì chùm tone dài/ngắn hiện rõ ràng, đọc Morse rất dễ. Đề gợi ý "hidden in
  plain sound — decode it" và kèm sẵn ảnh Sonic Visualiser chính là dấu hiệu này.

## Lời giải chi tiết (bước + code/lệnh sạch, chạy lại được)

**Cách A — hoàn toàn bằng script (tái lập, không cần GUI).** Trích payload RTP PT=0, giải µ-law,
ghi WAV:

```python
# solve_voip.py  — chỉ XỬ LÝ DỮ LIỆU pcap, không chạy file nhị phân nào
# pip install scapy
import audioop, wave
from scapy.all import rdpcap, UDP, Raw

pkts = rdpcap("packet.pcap")
streams = {}                                   # SSRC -> list[(seq, payload)]
for p in pkts:
    if UDP in p and Raw in p:
        d = bytes(p[Raw].load)
        if len(d) < 12 or (d[0] >> 6) != 2:    # phải là RTP version 2
            continue
        pt = d[1] & 0x7F
        if pt < 64 or pt > 95:                  # loại RTCP (72..76), chỉ giữ media PT hợp lệ
            if pt != 0:                          # ở bài này media là PT 0 (PCMU)
                continue
        if pt != 0:
            continue
        seq  = int.from_bytes(d[2:4], "big")
        ssrc = int.from_bytes(d[8:12], "big")
        streams.setdefault(ssrc, []).append((seq, d[12:]))   # bỏ 12 byte header RTP

# gom tất cả stream, sắp theo sequence rồi nối payload µ-law
mulaw = b"".join(pl for ssrc in streams
                    for _, pl in sorted(streams[ssrc], key=lambda x: x[0]))

pcm = audioop.ulaw2lin(mulaw, 2)               # µ-law -> PCM16
with wave.open("out.wav", "wb") as w:
    w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
    w.writeframes(pcm)
print("wrote out.wav", len(pcm), "bytes PCM")
```

```bash
python3 solve_voip.py        # -> out.wav (mono, 16-bit, 8 kHz)
```

**Cách B — Wireshark GUI (nhanh nhất).**
1. Mở `packet.pcap` → `Telephony → VoIP Calls` → chọn cuộc gọi → `Play`/`Analyze`.
2. Hoặc `Telephony → RTP → RTP Streams` → chọn stream → `Analyze` → `Export → Audio (.wav)`
   (Wireshark tự nhận PCMU và decode G.711).

**Đọc Morse từ phổ.** Mở `out.wav` trong **Sonic Visualiser** (hoặc Audacity) → bật
Spectrogram. Đối chiếu với `sonic_visualiser.png`. Đọc tone ngắn/dài:

```
-.-- ----- ..- .- .-. .  -.. .  -.-. --- -.. . -..  ...- ----- .---- .--.
  Y    0    U  A  R  E    D  E    C   O   D  E  D     V    0     1    P
```

→ `Y0UAREDECODEDV01P` → ghép vào khung flag.

*(Muốn giải Morse tự động: phát hiện tone bằng ngưỡng năng lượng từng khung ~10–20 ms, phân loại
độ dài thành dot/dash theo ngưỡng thời lượng, rồi tra bảng Morse.)*

## Flag

flag{Y0UAREDECODEDV01P}

("You are decoded VoIP" — hợp với chủ đề "cuộc gọi im lặng nhưng mang thông điệp".)

## Gặp lại thì xử lý thế nào (playbook)

- **Nhận diện:** pcap có SIP/RTP; đề nói "nghe trong âm thanh / hidden in sound"; cuộc gọi
  ngắn bất thường; không có gì đáng chú ý trong SIP header.
- **Quy trình:**
  1. `strings pcap | grep -iE "rtpmap|INVITE|m=audio"` để lấy codec + cổng RTP.
  2. Đọc SDP `a=rtpmap:<PT> <codec>/<clock>` → chọn decoder đúng (PCMU/PCMA/Opus/G.729).
  3. Trích RTP theo SSRC + seq/timestamp → giải codec → xuất WAV (script, hoặc Wireshark
     `Telephony → RTP → Export Audio`).
  4. Nghe thử; nếu KHÔNG phải tiếng người → mở spectrogram.
  5. Phân loại tín hiệu trên phổ: tone bíp đều ngắn/dài → **Morse**; hai tần số chồng nhau →
     **DTMF**; dải quét ngang theo thời gian → **SSTV**; nhiễu đều → có thể là dữ liệu điều chế
     (FSK...).
- **Bẫy hay gặp:** chỉ soi SIP header mà bỏ qua RTP; export sai codec → WAV ra nhiễu; không sắp
  theo sequence → âm thanh rối; cố "nghe" Morse bằng tai thay vì nhìn phổ.
- **Checklist ngắn:** SDP codec? → export/decode WAV đúng codec? → nghe? → spectrogram? →
  Morse/DTMF/SSTV? → ghép flag.
