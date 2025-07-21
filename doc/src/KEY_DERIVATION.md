Key derivation
-

This feature can help setup a hierarchical key infrastructure.

`mlar` provides a subcommand `keyderive` to deterministically derive sub-keys from a given key along a derivation path (a bit like [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), except children public keys can't be derived from the parent one).

For instance, if one wants to derive the following scheme:
```ascii
root_key
    ├──["App X"]── key_app_x
    │   └──["v1.2.3"]── key_app_x_v1.2.3
    └──["App Y"]── key_app_y
```

One can use the following commands:
```bash
# Create the root key (--seed can be used if this key must be created deterministically)
mlar keygen root_key
# Create App keys
mlar keyderive root_key key_app_x --path-component "App X"
mlar keyderive root_key key_app_y --path-component "App Y"
# Create the v1.2.3 key of App X
mlar keyderive key_app_x key_app_x_v1.2.3 --path-component "v1.2.3"
```

At this point, let's consider an outage happened and keys have been lost.

One can recover all the keys from the `root_key` private key.
For instance, to recover the `key_app_v1.2.3`:
```bash
mlar keyderive root_key recovered_key --path-component "App X" --path-component "v1.2.3"
```

As such, if the `App X` owner only knows `key_app_x`, he can recover all of its subkeys, including `key_app_v1.2.3` but excluding `key_app_y`.

WARNING: This scheme does not provide any revocation mechanism. If a parent key is compromised, all of the key in its sub-tree must be considered compromised (ie. all past and futures key that can be obtained from it). The opposite is not true: a parent key remains safe if any of its children key is compromised.
