#!/bin/bash
# recapture_all.sh
# ------------------
# Walks through capturing all 5 traffic labels in sequence, with
# countdowns and prompts so you don't have to retype commands.

set -e

IFACE="eth1"
VENV_PYTHON="venv/bin/python"

run_capture () {
    local label=$1
    local duration=$2
    local runs=$3
    local instructions=$4

    for i in $(seq 1 $runs); do
        echo ""
        echo "=================================================="
        echo " [$label] Run $i of $runs -- duration ${duration}s"
        echo " Instructions: $instructions"
        echo "=================================================="
        read -p "Press ENTER when you're ready to start this run (get the activity going FIRST, then press enter)... "
        sudo "$VENV_PYTHON" src/capture.py --label "$label" --duration "$duration" --iface "$IFACE"
        echo "[$label] Run $i complete. Current total for this label:"
        grep -c "$label" data/features.csv 2>/dev/null || echo "0 (file may not exist yet)"
    done
}

echo "This will guide you through recapturing all 5 traffic labels."
echo "Make sure your venv is activated and you're in the project root."
echo ""

run_capture "video_call" 180 3 "Start a video call (e.g. Google Meet) in WSL Firefox, THEN press enter."
run_capture "streaming" 90 4 "Start playing a YouTube video in WSL Firefox, THEN press enter."
run_capture "download" 120 4 "Start downloading a large file in WSL Firefox, THEN press enter."
run_capture "browsing" 60 3 "Start browsing a few different websites in WSL Firefox, THEN press enter."
run_capture "gaming" 60 3 "Start playing an online game in WSL Firefox, THEN press enter."

echo ""
echo "=================================================="
echo " All captures complete! Final dataset summary:"
echo "=================================================="
wc -l data/features.csv
echo ""
for label in video_call streaming download browsing gaming; do
    count=$(grep -c "$label" data/features.csv 2>/dev/null || echo 0)
    echo "  $label: $count"
done
echo ""
echo "Now run: python src/train.py"