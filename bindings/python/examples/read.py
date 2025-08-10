#!/usr/bin/env python3

import mla


def main() -> None:
    sig_cfg: mla.SignatureConfig = mla.SignatureConfig.without_signature_verification()
    config: mla.ReaderConfig = mla.ReaderConfig.without_encryption(sig_cfg)
    with mla.MLAReader("example.mla", config) as archive:
        for name in archive.keys():
            # name is of type EntryName
            print(f"{name.raw_content_to_escaped_string()}: {archive[name].decode('utf-8')}")


if __name__ == "__main__":
    main()
