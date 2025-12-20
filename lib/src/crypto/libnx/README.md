These are the crypto bindings that will need to be used specifically when using libnx as the backend.

The original library for chiaki-ng uses openSSL as the backend in both cURL and for performing the streaming components to PSN

The original library for the switch port utilised mbedtls for this purpose, using a version of curl that was compiled with websockets and mbedtls as the vtls backend.

libNX has not had switch-mbedtls updated in awhile, and even then, the newer versions require custom patches to expose certain fields due to the changes in struct that moved several fields from public to private.

Rather than doing this, I chose to bring this in tree, as well as utilise [micro-ecc] for the ECDH curve https://github.com/kmackay/micro-ecc

Per [switchbrew](https://switchbrew.github.io/libnx/dir_2874fbf892ad5b8020be2442f929b820.html), as of time of writing (libnx v4.10.0), these are the following implementations that are provided and used here:

- AES-128-ECB
- HMAC-SHA256
- SHA-256
- CSRNG

and the following are implementations in-tree
- ECDH (secp256k1) for session key exchange from micro-ecc
- AES-128-CFB128
- GMAC

This portion will be for PSN connections.

cURL will then be compiled with WSS support and libNX as the TLS backend which will keep us as in-line as possible with the current switch homebrew practices