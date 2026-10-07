#!/bin/zsh
# usage: cut.sh <raw.mp4> <start> <end> <out.mp4>
# Trims a raw screen recording at real speed, scales it to the 1664x936 window used in the video,
# and dips the first and last 0.2s through white so every cut between scenes reads the same way.
raw=$1; a=$2; b=$3; out=$4; d=$(( b - a )); fo=$(( d - 0.2 ))
ffmpeg -v error -y -ss $a -t $d -i $raw -vf "scale=1664:936:flags=lanczos,unsharp=5:5:0.45:5:5:0.0,fade=t=in:st=0:d=0.2:c=white,fade=t=out:st=${fo}:d=0.2:c=white,fps=30" -c:v libx264 -preset slow -crf 15 -g 15 -pix_fmt yuv420p -an -movflags +faststart $out
echo "${out:t} $(ffprobe -v error -show_entries format=duration -of csv=p=0 $out)s $(( $(stat -f%z $out) / 1024 ))KB"
