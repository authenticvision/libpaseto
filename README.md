# C library for PASETO
libpaseto is a C implementation of [Platform-Agnostic Security Tokens](https://github.com/paragonie/paseto). Currently, it only supports encryption and decryption of V2 local tokens.

## Building
libpaseto currently only depends on [libsodium](https://libsodium.org/). libpaseto uses CMake and can be built using the following commands:

```
mkdir build
cd build
cmake ..
make
```

## Usage
- Initialize the library: `paseto_init()`
- Load a key using `paseto_v2_load_symmetric_key_base64` or `paseto_v2_load_symmetric_key_hex` (if not already present in binary form)
- Encrypt or decrypt a token using `paseto_v2_encrypt` or `paseto_v2_decrypt` respectively

Refer to [example.c](example.c) for a detailed example.

## License
libpaseto is published under the [3-clause BSD license](LICENSE) and makes use of libsodium which is published under the [ISC license](libsodium.LICENSE).
