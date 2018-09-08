# C library for PASETO
*libpaseto* is a C implementation of
[Platform-Agnostic Security Tokens](https://github.com/paragonie/paseto).
*It only supports v2 public and private tokens.* v1 is not supported.

## Building
*libpaseto* only depends on [libsodium](https://libsodium.org/) and uses CMake.
It can be built using the following commands:

```
mkdir build
cd build
cmake ..
make
```

## Usage overview
- Initialize the library: `paseto_init`
- Load a key using `paseto_v2_{local,public}_load_...`
- Encrypt or sign a message using `paseto_v2_local_encrypt` or
  `paseto_v2_public_sign` respectively
- Decrypt or verify a token using `paseto_v2_local_decrypt` or
  `paseto_v2_public_verify` respectively. They will return the decoded message
  on success, a null pointer otherwise.
- Clean up returned results using `paseto_free`

Refer to [example.c](example.c) for a detailed example.

## License
libpaseto is published under the [3-clause BSD license](LICENSE) and makes use
of libsodium which is published under the [ISC license](libsodium.LICENSE).
