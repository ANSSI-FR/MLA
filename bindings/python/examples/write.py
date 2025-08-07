#!/usr/bin/env python3

import mla

def main():
    config = mla.WriterConfig.without_encryption_without_signature()
    with mla.MLAWriter("example.mla", config) as archive:
        archive[mla.EntryName("hello.txt")] = b"Hello, MLA!"
        archive[mla.EntryName("data.bin")] = b"\x00\x01\x02"
    print("Archive written: example.mla")

if __name__ == "__main__":
    main()