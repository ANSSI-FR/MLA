#!/usr/bin/env python3

import mla

def main():
    sig_cfg = mla.SignatureConfig.without_signature_verification()
    config = mla.ReaderConfig.without_encryption(sig_cfg)
    with mla.MLAReader("example.mla", config) as archive:
        for name in archive.keys():
            print(f"{name.raw_content_to_escaped_string()}: {archive[name]}")

if __name__ == "__main__":
    main()