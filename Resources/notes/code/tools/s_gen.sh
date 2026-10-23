#!/bin/bash
# usage: s_gen.sh SUBNAME OUTFILE   (layout: chi IDA View-A + toi da 1 tab pseudocode)
export DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority
NAME="$1"; OUT="$2"
echo -n | xclip -selection clipboard
xdotool key Escape; sleep 0.4
xdotool mousemove 535 184 click 1; sleep 0.9      # dong tab Pseudocode-A neu con (neu khong: vo hai)
xdotool mousemove 141 184 click 1; sleep 0.9      # tab IDA View-A
xdotool mousemove 900 450 click 1; sleep 0.6
xdotool key --clearmodifiers g; sleep 2.5
xdotool type --delay 40 "$NAME"; sleep 3
xdotool key --clearmodifiers Return; sleep 2
xdotool mousemove 203 74 click 1; sleep 0.8
xdotool mousemove 258 96 click 1; sleep 0.8
xdotool mousemove 662 208 click 1; sleep "${WAIT:-9}"
xdotool mousemove 1000 450 click 1; sleep 0.5
xdotool key --clearmodifiers ctrl+a; sleep 0.4
xdotool key --clearmodifiers ctrl+c; sleep 0.6
xclip -o -selection clipboard > "$OUT"
wc -l < "$OUT" > "$OUT.n"
xdotool mousemove 1000 450 click 1; sleep 0.5     # bo chon