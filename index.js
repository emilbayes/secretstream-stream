var sodium = require('sodium-native')
var assert = require('nanoassert')

exports.KEYBYTES = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
exports.ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
exports.HEADERBYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES

// consts to make code more readable
exports.TAG_PUSH = sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH
exports.TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
exports.TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
exports.TAG_REKEY = sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY

exports.encrypt = function (header, key) {
  assert(Buffer.isBuffer(header), 'header must be Buffer')
  assert(header.byteLength >= exports.HEADERBYTES, 'header must be at least HEADERBYTES (' + exports.HEADERBYTES + ') long')

  assert(Buffer.isBuffer(key), 'key must be Buffer')
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES (' + exports.KEYBYTES + ') long')

  var state = sodium.crypto_secretstream_xchacha20poly1305_state_new()
  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)

  function encrypt (tag, plaintext, ad, ciphertext, offset) {
    if (ciphertext == null) ciphertext = Buffer.alloc(encryptionLength(plaintext))
    if (offset == null) offset = 0

    encrypt.bytes = sodium.crypto_secretstream_xchacha20poly1305_push(state, ciphertext.subarray(offset), plaintext, ad, tag)

    return ciphertext
  }

  encrypt.bytes = 0

  function encryptionLength (plaintext) {
    return plaintext.byteLength + exports.ABYTES
  }

  return {
    encrypt,
    encryptionLength
  }
}

exports.decrypt = function (header, key) {
  assert(Buffer.isBuffer(header), 'header must be Buffer')
  assert(header.byteLength >= exports.HEADERBYTES, 'header must be at least HEADERBYTES (' + exports.HEADERBYTES + ') long')

  assert(Buffer.isBuffer(key), 'key must be Buffer')
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES (' + exports.KEYBYTES + ') long')

  var state = sodium.crypto_secretstream_xchacha20poly1305_state_new()
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)

  function decrypt (ciphertext, ad, plaintext, offset) {
    if (plaintext == null) plaintext = Buffer.alloc(decryptionLength(ciphertext))
    if (offset == null) offset = 0

    decrypt.bytes = sodium.crypto_secretstream_xchacha20poly1305_pull(state, plaintext.subarray(offset), decrypt.tag, ciphertext, ad)

    return plaintext
  }

  decrypt.tag = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_TAGBYTES)
  decrypt.bytes = 0

  function decryptionLength (ciphertext) {
    return ciphertext.byteLength - exports.ABYTES
  }

  return {
    decrypt,
    decryptionLength
  }
}
