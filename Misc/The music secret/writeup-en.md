# The music secret Writeup

## Overview

The only core attachment in this challenge is:

```text
stream.pcapng
```

At first glance it looks like a traffic challenge, but the actual solution is built from three layers:

1. the traffic gives the recovery method and the structural hints,
2. the audio carries the real signal,
3. the framing and error-correction layer turns that signal back into usable data.

So this is not a challenge about “listening to the song” or blindly searching strings. The main job is to take the hints from the capture seriously and follow them step by step.

The intended path is:

```text
PCAPNG
-> rebuild the two HTTP Range audio streams
-> derive the key from cache request order
-> compare the studio/cache WAV sample differences
-> recover the symbol period
-> find the sync word and frame structure
-> apply Hamming(7,4) correction and CRC16 validation
-> XOR the recovered bytes
-> base64-decode the result
-> obtain the flag
```

---

## 1. The capture already tells you how to approach it

Opening `stream.pcapng` in Wireshark and filtering for HTTP quickly reveals several useful requests:

- `/api/v1/incidents/INC-2407`
- `/api/v1/playback/session?track=7`
- `/edge/v1/assets/7/studio`
- `/edge/v1/assets/7/cache`
- `/api/v1/diagnostics/export`

The first two responses matter the most.

### Incident response

The incident record says:

```json
{
  "incident": "INC-2407",
  "track_id": 7,
  "alert": "edge cache checksum differs from studio archive",
  "capture": "sensor started late; spool quota stopped collection early",
  "recovery": "client range retries may cover truncated responses"
}
```

This is more than flavor text. It directly explains the shape of the problem:

1. the capture started late,
2. the capture stopped early,
3. some responses are truncated,
4. later Range retries must be used to fill the gaps.

### Playback session response

The playback metadata provides the next set of constraints:

```json
{
  "title": "Stream of Sound",
  "stream": "HTTP Range",
  "hint": "the rhythm remembers; order opens the cache",
  "bpm": 120,
  "subdivision": 2,
  "frame_sync_symbols": 8,
  "frame_fields": ["index", "length"],
  "frame_checksum": "crc16",
  "frame_order": "indexed"
}
```

The response headers reinforce the same direction:

```text
X-Key-Schedule: sha256(agent|id|csv(first-seen-range-start))
X-Stream-FEC: hamming-7-4
X-Frame-Sync: 8-symbol
X-Frame-Fields: index,length
X-Frame-Check: crc16
X-Frame-Order: indexed-blocks
X-Capture-State: late-start,quota-stop
```

At this point, several things are already fixed:

- the key comes from request order rather than from the audio itself,
- Hamming(7,4) is part of the data layer,
- frames have a sync word,
- `index` is needed to restore the final order,
- CRC16 is the check that will separate a correct decode from a plausible-looking mistake.

---

## 2. The first job is rebuilding the WAV files

The two important resources are:

- `/edge/v1/assets/7/studio`
- `/edge/v1/assets/7/cache`

Neither is downloaded in one piece. Both are fetched through repeated:

```http
Range: bytes=start-end
```

and answered with:

```http
206 Partial Content
Content-Range: bytes start-end/total
```

So the first instinct should not be to concatenate packet bodies. The data has to be rebuilt by offset.

Checking the capture confirms that this matters. There are incomplete objects such as:

```text
/edge/v1/assets/7/studio      2600 / 16384 bytes
/edge/v1/assets/7/cache       2600 / 16384 bytes
/api/v1/diagnostics/export    1900 / 65576 bytes
```

That means a naive reassembly will corrupt the audio.

The correct approach is:

- keep the requests, because they will be needed later for key derivation,
- do not trust incomplete bodies as final data,
- use overlapping or later retries to fill the missing offsets.

Once rebuilt by `Content-Range`, the result is two valid WAV files:

- `studio.wav`
- `edge-cache.wav`

Both are:

```text
mono IEEE float32 WAV
8000 Hz
```

That is important, because the later diffing only works if the samples are aligned point by point.

---

## 3. The key comes from request order

The challenge does not hide the key in the audio. It tells you where it comes from:

```text
sha256(agent|id|csv(first-seen-range-start))
```

These three parts are:

- `agent`: the User-Agent
- `id`: the track id
- `csv(first-seen-range-start)`: the ordered list of cache Range start offsets, keeping only the first occurrence of each

The last part is the most common place to make a mistake.

It is not:

- numerically sorted offsets,
- file-order offsets,
- or every `start` including duplicates.

The correct extraction is:

1. look only at `/edge/v1/assets/7/cache`,
2. scan the requests in capture order,
3. take the `start` from `Range: bytes=start-end`,
4. keep the first occurrence only.

In the provided capture, that produces:

```text
280 unique start values
```

The first ten are:

```text
3194880, 2686976, 3817472, 3932160, 1948160,
2244608, 1277952, 3096576, 1359872, 1949696
```

Combining the material gives:

```text
StreamClient/2.1|7|3194880,2686976,3817472,...
```

Hashing that string with SHA-256 yields the key used later for XOR.

In this challenge, the first eight bytes of the key are:

```text
a679df158ff5d930
```

That is a good checkpoint. If this value is wrong, there is no reason to trust any later decoding work.

---

## 4. Why the symbol period is 2000 samples

This step is not guesswork. The metadata already gives enough information:

- `bpm = 120`
- `subdivision = 2`

That means:

- 120 BPM = 2 beats per second
- subdivision 2 = 2 subunits per beat

So the stream carries:

```text
4 symbols per second
```

The WAV sample rate is:

```text
8000 Hz
```

Therefore one symbol spans:

```text
8000 / 4 = 2000 samples
```

The waveform differences later confirm the same number: the strong changes line up on a 2000-sample grid.

---

## 5. The real payload is in the difference between `studio` and `cache`

Neither audio track makes much sense on its own as a hiding place. The useful signal appears when the two WAV files are compared sample by sample.

After diffing them, a few things stand out:

- only a small subset of samples differs,
- the differences cluster into fixed-size blocks,
- the center region of each active block is far more stable than the rest.

In this challenge, the stable center window is around:

```text
30..34
```

The amplitudes in that narrow window naturally fall into four levels. After normalization, they look like:

```text
9, 19, 29, 39
```

These four levels can then be mapped into quaternary symbols.

This is the real turning point of the challenge. Once it is clear that the payload sits in the sample differences and that the center window is stable, the framing work becomes constrained instead of blind.

---

## 6. Sync word, frame header, and ordering

The metadata already tells us three important things:

- `frame_sync_symbols = 8`
- `frame_fields = ["index", "length"]`
- `frame_order = "indexed"`

So after extracting the quaternary symbol stream, the natural next step is to look for a stable 8-symbol pattern that repeats at frame boundaries.

The sync word in this challenge is:

```text
(3, 1, 0, 3, 2, 1, 0, 1)
```

Right after that pattern comes the frame header. Guided by the metadata, it can be interpreted as:

- `index`
- `length`

Once this is done, the out-of-order pieces can be rebuilt according to `index`, which matches `frame_order = indexed`.

So this step is not about inventing a frame structure from scratch. It is about matching the observed data to the exact structure that the challenge has already hinted at.

---

## 7. Why Hamming and CRC16 matter

The headers explicitly announce:

```text
X-Stream-FEC: hamming-7-4
```

So the bitstream cannot be treated as raw payload. It has to be decoded as Hamming(7,4) codewords and corrected back into usable nibbles.

Each frame also carries a CRC16. This is important for more than just a final check. In practice, it is what distinguishes the correct interpretation from a misleading one.

In this kind of challenge, it is easy to end up with a decode path that “looks almost right.” CRC16 is what removes that ambiguity.

Only after:

- the sync word is correct,
- the frame boundaries are correct,
- `index/length` are interpreted correctly,
- the Hamming layer is decoded correctly,

does the CRC16 begin to pass consistently.

So CRC16 is not a decorative detail here. It is the final piece that locks the whole chain into place.

---

## 8. Why the final output is base64

After reconstruction, the result is still not the flag in clear text. The recovered bytes are XOR-obfuscated.

This is where the key from the HTTP layer comes back into play. XORing the recovered bytes with the derived key produces data that clearly looks textual.

That text is base64. Decoding it yields the final flag:

```text
SCTF{stream_order_meets_noisy_rhythm}
```

---

## Final notes

Although this is a Misc challenge, the hints are not sparse at all. The key is to not treat them as unrelated fragments:

- the incident response tells you that the capture is incomplete, so Range reassembly matters,
- the playback metadata tells you the rhythm, sync length, frame fields, and checksum type,
- the audio difference gives you the real signal layer,
- Hamming and CRC16 filter the intermediate results down to the one correct decode path.

If the solve follows that structure, the challenge stays manageable. If the audio layer is attacked first without using the traffic hints, it becomes much more time-consuming than it needs to be.
