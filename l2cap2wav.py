#!/usr/bin/env python3
"""
l2cap2wav.py — Reconstruct audio from Bluetooth L2CAP/A2DP captures

Accepts either:
  - A raw pcap/pcapng file  (tshark is run automatically)
  - A pre-exported tshark text file (tab-separated fields)

Assumes:
  - The audio CID carries RTP-encapsulated SBC frames (A2DP media)
  - RTP header = 12 bytes, SBC frame count = 1 byte, then raw SBC frames
  - Codec: SBC (decoded via ffmpeg)

Usage:
  python3 l2cap2wav.py <capture.pcapng|profiles.txt> [audio_cid] [output.wav]

  audio_cid defaults to 0x0052 (typical A2DP dynamic CID)
  Pass 'auto' as audio_cid to scan all CIDs and pick the best candidate
"""

import sys
import subprocess
import shutil
import tempfile
from pathlib import Path


RTP_HEADER_SIZE = 12   # bytes
SBC_COUNT_SIZE  = 1    # byte (number of SBC frames in RTP payload)

PCAP_MAGIC_BYTES = {
    b'\xd4\xc3\xb2\xa1',  # pcap LE
    b'\xa1\xb2\xc3\xd4',  # pcap BE
    b'\x0a\x0d\x0d\x0a',  # pcapng
}


def is_pcap(path: Path) -> bool:
    """Detect pcap/pcapng by magic bytes."""
    try:
        magic = path.read_bytes()[:4]
        return magic in PCAP_MAGIC_BYTES
    except OSError:
        return False


def find_tshark() -> Path | None:
    """Locate tshark via PATH or common install locations."""
    via_path = shutil.which('tshark')
    if via_path:
        return Path(via_path)
    candidates = [
        Path(r'C:\Program Files\Wireshark\tshark.exe'),
        Path(r'C:\Program Files (x86)\Wireshark\tshark.exe'),
        Path('/usr/bin/tshark'),
        Path('/usr/local/bin/tshark'),
        Path('/Applications/Wireshark.app/Contents/MacOS/tshark'),
        Path('/bin/tshark'),
        Path('/opt/local/bin/tshark'),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def tshark_export(pcap: Path, out_txt: Path) -> None:
    """Run tshark to export L2CAP fields from a pcap to a text file."""
    tshark = find_tshark()
    if not tshark:
        print("[ERROR] tshark not found. Install Wireshark/tshark or export manually:")
        print("  tshark -r capture.pcapng -T fields \\")
        print("    -e frame.number -e btl2cap.cid \\")
        print("    -e btl2cap.length -e btl2cap.payload \\")
        print("    -Y btl2cap > profiles.txt")
        print("  If -r <file> fails on permissions: cat capture.pcapng | tshark -r - ...")
        sys.exit(1)

    print(f"  tshark found at: {tshark}")
    print(f"  Exporting L2CAP fields from {pcap.name}...")
    fields_args = [
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'btl2cap.cid',
        '-e', 'btl2cap.length',
        '-e', 'btl2cap.payload',
        '-Y', 'btl2cap',
    ]
    result = subprocess.run(
        [str(tshark), '-r', str(pcap), *fields_args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("  Direct -r <file> failed; retrying via stdin (cat | tshark -r -)...")
        cat = subprocess.Popen(['cat', str(pcap)], stdout=subprocess.PIPE)
        try:
            result = subprocess.run(
                [str(tshark), '-r', '-', *fields_args],
                stdin=cat.stdout,
                capture_output=True,
                text=True,
            )
        finally:
            if cat.stdout:
                cat.stdout.close()
            cat.wait()
    if result.returncode != 0:
        print(f"[ERROR] tshark failed:\n{result.stderr[-500:]}")
        sys.exit(1)

    out_txt.write_text(result.stdout)
    n_lines = result.stdout.count('\n')
    print(f"  Exported {n_lines} L2CAP packets → {out_txt.name}")


def sniff_best_cid(profiles_path: Path) -> str:
    """Scan all CIDs and return the one most likely to carry A2DP audio."""
    from collections import defaultdict
    cid_stats: dict[str, dict] = defaultdict(lambda: {'count': 0, 'total_len': 0})

    with open(profiles_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 4:
                continue
            cid = parts[1].lower()
            try:
                length = int(parts[2])
            except ValueError:
                continue
            cid_stats[cid]['count'] += 1
            cid_stats[cid]['total_len'] += length

    print("  CID scan results:")
    best_cid, best_score = '0x0052', 0
    for cid, s in sorted(cid_stats.items(), key=lambda x: -x[1]['count']):
        avg_len = s['total_len'] / s['count'] if s['count'] else 0
        # High packet count + large avg payload = likely media stream
        score = s['count'] * avg_len
        print(f"    {cid:>8}  packets={s['count']:>5}  avg_len={avg_len:>7.1f}  score={score:,.0f}")
        if score > best_score:
            best_score = score
            best_cid = cid

    print(f"  → Best candidate: {best_cid}")
    return best_cid


def parse_profiles(path: Path, audio_cid: str) -> tuple[bytearray, list[int]]:
    """Extract raw SBC bytestream from L2CAP profile export."""
    sbc_stream = bytearray()
    seq_numbers = []
    missing_seqs = []

    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 4 or parts[1].lower() != audio_cid.lower():
                continue

            try:
                raw = bytes.fromhex(parts[3])
            except ValueError:
                print(f"  [WARN] Frame {parts[0]}: invalid hex payload, skipping")
                continue

            # Validate RTP version
            if (raw[0] >> 6) != 2:
                print(f"  [WARN] Frame {parts[0]}: not RTP v2 (byte={raw[0]:#04x}), skipping")
                continue

            rtp_seq = int.from_bytes(raw[2:4], 'big')
            rtp_ts  = int.from_bytes(raw[4:8], 'big')
            n_frames = raw[RTP_HEADER_SIZE]

            # Check for out-of-order or missing packets
            if seq_numbers:
                expected = seq_numbers[-1] + 1
                if rtp_seq != expected:
                    missing = rtp_seq - expected
                    missing_seqs.append((rtp_seq, missing))
                    print(f"  [WARN] Gap before RTP seq {rtp_seq}: {missing} packet(s) missing")

            seq_numbers.append(rtp_seq)
            sbc_payload = raw[RTP_HEADER_SIZE + SBC_COUNT_SIZE:]
            sbc_stream.extend(sbc_payload)

    return sbc_stream, seq_numbers, missing_seqs


def detect_sbc_params(sbc_stream: bytes) -> dict:
    """Parse SBC frame header to extract codec parameters."""
    if len(sbc_stream) < 4 or sbc_stream[0] != 0x9c:
        return {}

    hdr = sbc_stream[1]
    sf_map  = {0: '16000', 1: '32000', 2: '44100', 3: '48000'}
    blk_map = {0: 4,  1: 8,  2: 12, 3: 16}
    cm_map  = {0: 'mono', 1: 'dual', 2: 'stereo', 3: 'joint_stereo'}
    sbn_map = {0: 4, 1: 8}
    am_map  = {0: 'loudness', 1: 'SNR'}

    return {
        'sample_rate': sf_map[(hdr >> 6) & 3],
        'blocks':      blk_map[(hdr >> 4) & 3],
        'channel_mode': cm_map[(hdr >> 2) & 3],
        'alloc_method': am_map[(hdr >> 1) & 1],
        'subbands':    sbn_map[hdr & 1],
        'bitpool':     sbc_stream[2],
    }


def decode_sbc_to_wav(sbc_path: Path, wav_path: Path) -> bool:
    """Use ffmpeg to decode raw SBC stream to WAV."""
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        print("[ERROR] ffmpeg not found — install it to decode SBC to WAV")
        print(f"  Raw SBC saved to: {sbc_path}")
        print("  You can also use: sbcdec (from bluez-tools) or VLC")
        return False

    result = subprocess.run(
        [ffmpeg, '-hide_banner', '-y', '-f', 'sbc', '-i', str(sbc_path), str(wav_path)],
        capture_output=True, text=True
    )

    if wav_path.exists() and wav_path.stat().st_size > 0:
        return True
    else:
        print(f"[ERROR] ffmpeg failed:\n{result.stderr[-500:]}")
        return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    audio_cid  = sys.argv[2] if len(sys.argv) > 2 else '0x0052'
    output_wav = Path(sys.argv[3]) if len(sys.argv) > 3 else input_path.with_suffix('.wav')
    output_sbc = output_wav.with_suffix('.sbc')

    print(f"╔══════════════════════════════════════╗")
    print(f"║   L2CAP A2DP SBC → WAV Extractor    ║")
    print(f"╚══════════════════════════════════════╝")
    print(f"Input : {input_path}")
    print(f"Output: {output_wav}\n")

    # --- Step 0: If input is a pcap, run tshark first ---
    profiles_path = input_path
    _tmpdir = None
    if is_pcap(input_path):
        print("[0/3] pcap/pcapng detected — running tshark export...")
        _tmpdir = tempfile.TemporaryDirectory()
        profiles_path = Path(_tmpdir.name) / 'profiles.txt'
        tshark_export(input_path, profiles_path)
        print()

    # --- Auto CID detection ---
    if audio_cid.lower() == 'auto':
        print("[CID] Scanning for best audio channel...")
        audio_cid = sniff_best_cid(profiles_path)
        print()

    print(f"CID   : {audio_cid}\n")

    # --- Step 1: Extract SBC stream ---
    print("[1/3] Parsing L2CAP packets...")
    sbc_stream, seqs, gaps = parse_profiles(profiles_path, audio_cid)

    if not sbc_stream:
        print(f"[ERROR] No packets found for CID {audio_cid}")
        sys.exit(1)

    print(f"  RTP packets  : {len(seqs)}")
    print(f"  Missing gaps : {len(gaps)}")
    print(f"  SBC bytes    : {len(sbc_stream):,}")

    # --- Step 2: Show SBC params ---
    print("\n[2/3] Detecting SBC parameters...")
    params = detect_sbc_params(bytes(sbc_stream))
    if params:
        duration_est = len(seqs) * 7 * params['blocks'] * params['subbands'] / int(params['sample_rate'])
        print(f"  Sample rate  : {params['sample_rate']} Hz")
        print(f"  Channel mode : {params['channel_mode']}")
        print(f"  Blocks       : {params['blocks']}")
        print(f"  Subbands     : {params['subbands']}")
        print(f"  Bitpool      : {params['bitpool']}")
        print(f"  Est. duration: {duration_est:.2f}s")

    # Write raw SBC (always useful for manual inspection)
    output_sbc.write_bytes(bytes(sbc_stream))
    print(f"  Raw SBC saved: {output_sbc}")

    # --- Step 3: Decode to WAV ---
    print("\n[3/3] Decoding SBC → WAV...")
    if decode_sbc_to_wav(output_sbc, output_wav):
        size_kb = output_wav.stat().st_size // 1024
        print(f"  Done! WAV saved: {output_wav} ({size_kb} KB)")
    else:
        sys.exit(1)

    if _tmpdir:
        _tmpdir.cleanup()


if __name__ == '__main__':
    main()
