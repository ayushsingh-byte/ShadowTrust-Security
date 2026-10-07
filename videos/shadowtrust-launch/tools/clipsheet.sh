#!/bin/zsh
# usage: clipsheet.sh <clip.mp4> <step seconds> <cols> <cell width>   Contact sheet of a clip, one frame every <step> seconds.
clip=$1; step=${2:-1.5}; cols=${3:-4}; w=${4:-470}
dir=${clip:r}.sheet; rm -rf $dir; mkdir -p $dir
dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 $clip)
t=0.3; i=0
while (( t < dur )); do ffmpeg -v error -y -ss $t -i $clip -frames:v 1 $dir/t$(printf '%05.1f' $t).png; t=$(( t + step )); i=$(( i + 1 )); done
node ${0:h}/sheet.js ${clip:r}-sheet.png $cols $w $dir/*.png >/dev/null && echo "${clip:t} ${dur}s -> ${clip:r}-sheet.png ($i frames)"
