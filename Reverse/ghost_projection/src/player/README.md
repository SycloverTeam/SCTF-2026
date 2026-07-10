---
noteId: "17f280107c3711f19edf53c6950af6aa"
tags: []

---

# ghost_projection

## Run

```bash
chmod +x ghost_abyss_hardened
./ghost_abyss_hardened
```

## Docker

```bash
docker build -t ghost_projection .
docker run --rm -it ghost_projection
```

Non-interactive example:

```bash
printf 'your_flag_here\n' | docker run --rm -i ghost_projection /chal/ghost_abyss_hardened
```
