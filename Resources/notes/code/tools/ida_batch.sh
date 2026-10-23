#!/bin/bash
# usage: ida_batch.sh BIN [ANALYSIS_WAIT] [EXTRA_FUNCS...]   -> ~/algo_lab/pc/BIN/NAME.c va _log.txt
export DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority
BIN="$1"; AW="${2:-30}"; shift; shift
D=/home/kali/algo_lab/pc/$BIN; mkdir -p "$D"; LOG="$D/_log.txt"; [ -z "$ONLY" ] && : > "$LOG"
FNS="a85_encode adler32_hash aes128_decrypt_block aes128_encrypt_block aes128_key_expand b32_encode b58_encode b64_decode b64_encode chacha20_block chacha20_xor crc32_bitwise crc32_table djb2_hash fnv1a_hash hex_encode main md5_hash mix_chain op_add op_not op_reverse op_rol32 op_rol8 op_ror32 op_ror8 op_sub rc4_crypt rot13 salsa20_block salsa20_xor sha1_hash sha256_hash sha512_hash tea_decrypt tea_encrypt xor_repeat xor_single xtea_decrypt xtea_encrypt xxtea_decrypt xxtea_encrypt $*"
[ -n "$ONLY" ] && FNS="$ONLY"
pkill -TERM -x ida; sleep 2; pkill -KILL -x ida; sleep 1
rm -f /tmp/ida_work/$BIN.i64 /tmp/ida_work/$BIN.id0 /tmp/ida_work/$BIN.id1 /tmp/ida_work/$BIN.id2 /tmp/ida_work/$BIN.nam /tmp/ida_work/$BIN.til
cd /tmp/ida_work
setsid nohup /home/kali/ida-free-9.4/ida /tmp/ida_work/$BIN > /tmp/ida_$BIN.log 2>&1 < /dev/null &
sleep 12; xdotool key --clearmodifiers Return; sleep "$AW"
echo "[$(date +%T)] start $BIN" >> "$LOG"
copy_try() {
  xdotool mousemove 1000 450 click 1; sleep 0.5
  xdotool key --clearmodifiers ctrl+a; sleep 0.4
  xdotool key --clearmodifiers ctrl+c; sleep 0.6
  xclip -o -selection clipboard > "$1" 2>/dev/null
}
for NAME in $FNS; do
  OUT="$D/$NAME.c"; rm -f "$OUT"
  xclip -selection clipboard -i /dev/null
  xdotool mousemove 420 184 click 1; sleep 0.6
  xdotool key --clearmodifiers g; sleep 1.5
  xdotool type --delay 40 "$NAME"; sleep 0.6
  xdotool key --clearmodifiers Return; sleep 1.5
  xdotool mousemove 203 74 click 1; sleep 0.8
  xdotool mousemove 258 96 click 1; sleep 0.8
  xdotool mousemove 662 208 click 1; sleep 7
  ok=0
  for t in 1 2 3 4 5; do
    copy_try "$OUT"
    if head -3 "$OUT" | grep -q -w "$NAME"; then ok=1; break; fi
    sleep 6
  done
  echo "[$(date +%T)] $NAME ok=$ok bytes=$(wc -c < "$OUT" 2>/dev/null)" >> "$LOG"
done
echo "[$(date +%T)] done $BIN" >> "$LOG"
pkill -TERM -x ida; sleep 2; pkill -KILL -x ida