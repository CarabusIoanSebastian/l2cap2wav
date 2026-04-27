# l2cap2wav

Reconstruct audio from Bluetooth L2CAP/A2DP packet captures. Accepts raw pcap/pcapng files directly — tshark is invoked automatically — and decodes SBC frames to WAV via ffmpeg.

---

## Usage

```bash
python3 l2cap2wav.py <input> [audio_cid] [output.wav]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `input` | *(required)* | pcap, pcapng, or pre-exported tshark text file |
| `audio_cid` | `0x0052` | L2CAP channel ID carrying the audio stream |
| `output.wav` | `<input>.wav` | Output WAV file path |

### Examples

```bash
# Simplest — pass the pcap directly, tshark runs automatically
python3 l2cap2wav.py capture.pcapng

# Unknown CID — scan all channels and pick the best candidate
python3 l2cap2wav.py capture.pcapng auto

# Specify CID and output path explicitly
python3 l2cap2wav.py capture.pcapng 0x0044 call_audio.wav

# Pre-exported tshark text file (skips tshark step)
python3 l2cap2wav.py profiles.txt 0x0052 output.wav
```

---

## How It Works

```
capture.pcapng
      │
      ▼
 is_pcap() check
      │
      ├─ yes → tshark exports L2CAP fields to temp file
      │
      ▼
Filter rows by CID  (or auto-detect best CID)
      │
      ▼
Strip RTP header (12 B) + SBC frame count (1 B)
      │
      ▼
Concatenate raw SBC frames  →  audio.sbc
      │
      ▼
ffmpeg -f sbc               →  audio.wav
```

Each L2CAP packet on the audio channel contains:

```
┌──────────────────────────┬─────────────┬────────────────────────────┐
│ RTP Header  (12 bytes)   │ Count (1 B) │ SBC Frames (N × frame)     │
│ v=2 PT=96 seq ts ssrc    │ typically 7 │ [9c][hdr][bp][crc][data]…  │
└──────────────────────────┴─────────────┴────────────────────────────┘
```

The script validates RTP v2, checks for sequence number gaps (dropped packets), auto-detects SBC parameters from the first frame header, and reports estimated duration before decoding.

---

## Finding the Right CID

L2CAP CIDs are dynamically negotiated per session, so the audio channel won't always be `0x0052`. Pass `auto` to let the script scan and score all CIDs automatically:

```bash
python3 l2cap2wav.py capture.pcapng auto
```

The scorer ranks by `packet_count × average_payload_size` — the media stream will have by far the highest score. Output looks like:

```
[CID] Scanning for best audio channel...
  CID scan results:
      0x0042  packets=    2  avg_len=    2.0  score=4
      0x0050  packets=    2  avg_len=    3.0  score=6
      0x0052  packets= 2757  avg_len=  650.0  score=1,792,050
  → Best candidate: 0x0052
```

You can also find it manually in Wireshark by looking for the AVDTP `Set Configuration` command, which appears before the audio stream and contains the negotiated CID and codec parameters.

---

## Output

Two files are written alongside the WAV:

| File | Description |
|------|-------------|
| `audio.wav` | Decoded PCM audio, ready to play |
| `audio.sbc` | Raw SBC bitstream — useful for alternative decoders or manual inspection |



## Supported Codecs

| Codec | Support |
|-------|---------|
| SBC | ✅ Full (mandatory A2DP codec) |
| AAC | ⚠️ Strip RTP header the same way, feed raw payload to ffmpeg |
| aptX / aptX-HD | ⚠️ Proprietary — requires a separate decoder |
| LDAC | ⚠️ Proprietary — requires a separate decoder |

---

The project takes inspiration from https://github.com/kevincartwright/ACDRpcap2wav
