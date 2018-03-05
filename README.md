# `secretstream-stream`

> High-level node.js stream of `libsodium` `crypto_secretstream`

## Usage

```js
var secretstream = require('secretstream-stream')

// Parameters
var blockSize = 512 - exports.ABYTES // Will ensure blocks of 512 bytes
var header = Buffer.alloc(secretstream.HEADERBYTES)
var key = Buffer.alloc(secretstream.KEYBYTES)

// Initialise
sodium.randombytes_buf(header)
sodium.randombytes_buf(key)

// Write some data on the encrypt side
var enc = secretstream.encrypt(blockSize, header, key)
enc.write('Hello world!')

// Setup the decrypt side
var dec = secretstream.encrypt(blockSize, header, key)
dec.on('data', d => console.log('rx:', d.toString()))

enc.pipe(dec)
```

## API

### `var enc = secretstream.encrypt(blocksize, header, key)`

### `var dec = secretstream.decrypt(blocksize, header, key, [max = Infinity])`

## Install

```sh
npm install secretstream-stream
```

## License

[ISC](LICENSE)
