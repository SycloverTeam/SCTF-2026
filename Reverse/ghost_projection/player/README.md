# ghost_abyss_hardened

## Run

```bash
chmod +x ghost_abyss_hardened
./ghost_abyss_hardened
```

## Docker

```bash
docker build -t ghost-abyss-packed .
docker run --rm -it ghost-abyss-packed
```

Non-interactive example:

```bash
printf 'your_flag_here\n' | docker run --rm -i ghost-abyss-packed /chal/ghost_abyss_hardened
```
