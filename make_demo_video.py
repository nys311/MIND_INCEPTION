#!/usr/bin/env python3
"""
Render the demo storyboard to a video + GIF using headless Chrome and ffmpeg.

Each scene in assets/demo_storyboard.html (?frame=N) is screenshotted at
1280x720, then held for a few seconds and stitched into assets/demo.mp4 and a
README-embeddable assets/demo.gif. No browser automation library needed.

  python3 make_demo_video.py
"""
import re
import shutil
import subprocess
import pathlib

BASE = pathlib.Path(__file__).resolve().parent
ASSETS = BASE / "assets"
FRAMES = ASSETS / "frames"
STORYBOARD = ASSETS / "demo_storyboard.html"
SECONDS_PER_SCENE = 3.0
FPS = 25

CHROME = next((c for c in ("google-chrome", "google-chrome-stable", "chromium",
                           "chromium-browser") if shutil.which(c)), None)


def n_scenes():
    html = STORYBOARD.read_text()
    return len(set(re.findall(r'data-f="(\d+)"', html)))


def shoot(i):
    out = FRAMES / f"scene_{i:02d}.png"
    url = f"file://{STORYBOARD}?frame={i}"
    subprocess.run([CHROME, "--headless", "--no-sandbox", "--hide-scrollbars",
                    "--force-device-scale-factor=1", "--window-size=1280,720",
                    "--default-background-color=0a0c10ff",
                    f"--screenshot={out}", "--virtual-time-budget=1500", url],
                   check=True, capture_output=True)
    return out


def main():
    if not CHROME:
        raise SystemExit("no Chrome/Chromium found")
    if not shutil.which("ffmpeg"):
        raise SystemExit("ffmpeg not found")
    FRAMES.mkdir(parents=True, exist_ok=True)
    k = n_scenes()
    print(f"rendering {k} scenes with {CHROME}")
    for i in range(k):
        shoot(i)
        print(f"  scene {i} ok")

    # build an ffmpeg concat list holding each scene for SECONDS_PER_SCENE
    listf = FRAMES / "list.txt"
    lines = []
    for i in range(k):
        lines.append(f"file '{FRAMES / f'scene_{i:02d}.png'}'")
        lines.append(f"duration {SECONDS_PER_SCENE}")
    lines.append(f"file '{FRAMES / f'scene_{k-1:02d}.png'}'")  # last frame held
    listf.write_text("\n".join(lines))

    mp4 = ASSETS / "demo.mp4"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(listf),
                    "-vf", f"fps={FPS},format=yuv420p", "-movflags", "+faststart",
                    str(mp4)], check=True, capture_output=True)
    print(f"wrote {mp4} ({mp4.stat().st_size//1024} KB)")

    # GIF via a shared palette (crisp, small)
    pal = FRAMES / "palette.png"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(listf),
                    "-vf", "fps=12,scale=900:-1:flags=lanczos,palettegen", str(pal)],
                   check=True, capture_output=True)
    gif = ASSETS / "demo.gif"
    subprocess.run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(listf),
                    "-i", str(pal), "-lavfi",
                    "fps=12,scale=900:-1:flags=lanczos[x];[x][1:v]paletteuse",
                    str(gif)], check=True, capture_output=True)
    print(f"wrote {gif} ({gif.stat().st_size//1024} KB)")


if __name__ == "__main__":
    main()
