var secretstream = require('.')
var sodium = require('sodium-native')

// Parameters
var header = Buffer.alloc(secretstream.HEADERBYTES)
var key = Buffer.alloc(secretstream.KEYBYTES)

// Initialise
sodium.randombytes_buf(key)

// Init encryption side, writing into header Buffer, which needs to be shared
// with decryption side
var tx = secretstream.encrypt(header, key)
var ciphertext = tx.encrypt(secretstream.TAG_MESSAGE, Buffer.from('Hello world!'))

// Setup the decrypt side
var rx = secretstream.decrypt(header, key)
var plaintext = rx.decrypt(ciphertext)

console.log(plaintext.equals(Buffer.from('Hello world!')), rx.decrypt.tag.equals(secretstream.TAG_MESSAGE))

rx.destroy()
tx.destroy()
