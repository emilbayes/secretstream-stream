var secretstream = require('.')
var sodium = require('sodium-native')

// Parameters
var blockSize = 512 - secretstream.ABYTES // Will ensure blocks of 512 bytes
var header = Buffer.alloc(secretstream.HEADERBYTES)
var key = Buffer.alloc(secretstream.KEYBYTES)

// Initialise
sodium.randombytes_buf(header)
sodium.randombytes_buf(key)

// Write some data on the encrypt side
var enc = secretstream.encrypt(blockSize, header, key)
enc.write('Hello world!')

// Setup the decrypt side
var dec = secretstream.decrypt(blockSize, header, key)
dec.on('data', d => console.log('rx:', d.toString()))

enc.pipe(dec)
