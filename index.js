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

exports.keygen = function (key) {
  if (key == null) key = sodium.sodium_malloc(exports.KEYBYTES)
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES')

  sodium.crypto_secretstream_xchacha20poly1305_keygen(key)

  return key
}

exports.encrypt = function (header, key) {
  assert(header instanceof Uint8Array, 'header must be Buffer')
  assert(header.byteLength >= exports.HEADERBYTES, 'header must be at least HEADERBYTES (' + exports.HEADERBYTES + ') long')

  assert(key instanceof Uint8Array, 'key must be Buffer')
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES (' + exports.KEYBYTES + ') long')

  var destroyed = false
  var state = sodium.sodium_malloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES)
  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)

  function encrypt (tag, plaintext, ad = null, ciphertext, offset) {
    assert(destroyed === false, 'state already destroyed')
    assert(tag instanceof Uint8Array && tag.byteLength === 1, 'tag must be a valid tag')
    assert(plaintext instanceof Uint8Array, 'plaintext must be Buffer')
    if (ciphertext == null) ciphertext = new Uint8Array(encryptionLength(plaintext))
    if (offset == null) offset = 0

    encrypt.bytes = sodium.crypto_secretstream_xchacha20poly1305_push(state, ciphertext.subarray(offset), plaintext, ad, tag)

    return ciphertext
  }

  encrypt.bytes = 0

  function encryptionLength (plaintext) {
    assert(plaintext instanceof Uint8Array, 'plaintext must be Buffer')

    return plaintext.byteLength + exports.ABYTES
  }

  function destroy () {
    assert(destroyed === false, 'state already destroyed')
    sodium.sodium_free(state)
    state = null // Should memzero when we have buffer trick in sodium-native
    encrypt.bytes = null

    destroyed = true
  }

  return {
    encrypt,
    encryptionLength,
    destroy
  }
}

exports.decrypt = function (header, key) {
  assert(header instanceof Uint8Array, 'header must be Buffer')
  assert(header.byteLength >= exports.HEADERBYTES, 'header must be at least HEADERBYTES (' + exports.HEADERBYTES + ') long')

  assert(key instanceof Uint8Array, 'key must be Buffer')
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES (' + exports.KEYBYTES + ') long')

  var destroyed = false
  var state = sodium.sodium_malloc(sodium.crypto_secretstream_xchacha20poly1305_STATEBYTES)
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)

  function decrypt (ciphertext, ad = null, plaintext, offset) {
    assert(destroyed === false, 'state already destroyed')
    assert(ciphertext instanceof Uint8Array, 'ciphertext must be Buffer')
    if (plaintext == null) plaintext = new Uint8Array(decryptionLength(ciphertext))
    if (offset == null) offset = 0

    decrypt.bytes = sodium.crypto_secretstream_xchacha20poly1305_pull(state, plaintext.subarray(offset), decrypt.tag, ciphertext, ad)

    return plaintext
  }

  decrypt.tag = new Uint8Array(sodium.crypto_secretstream_xchacha20poly1305_TAGBYTES)
  decrypt.bytes = 0

  function decryptionLength (ciphertext) {
    assert(ciphertext instanceof Uint8Array, 'ciphertext must be Buffer')

    return ciphertext.byteLength - exports.ABYTES
  }

  function destroy () {
    assert(destroyed === false, 'state already destroyed')
    sodium.sodium_free(state)
    state = null // Should memzero when we have buffer trick in sodium-native
    decrypt.tag = null
    decrypt.bytes = null

    destroyed = true
  }

  return {
    decrypt,
    decryptionLength,
    destroy
  }
}
