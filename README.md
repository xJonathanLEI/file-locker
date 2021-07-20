# File Locker

A simple AES-based file encryptor/decryptor written in Rust. A "legacy" mode is provided for decrypting files encrypted by the [legacy file locker](https://github.com/xJonathanLEI/FileLocker).

## Encrypting a File

```sh
$ file-locker lock /path/to/file
```

## Decrypting a File

```sh
$ file-locker unlock /path/to/file
```

## License

[MIT](./LICENSE)
