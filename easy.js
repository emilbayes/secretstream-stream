var sodium = require('sodium-native')
var readBytes = require('read-bytes-stream')
var through = require('through2')
var pumpify = require('pumpify')
var secretStream = require('.')

exports.KEYBYTES = secretStream.KEYBYTES
exports.ABYTES = secretStream.ABYTES
exports.HEADERBYTES = secretStream.HEADERBYTES

exports.encrypt = function (blockSize, key) {
  var header = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
  sodium.randombytes_buf(header)

  var writeHeader = through()
  writeHeader.write(header)

  return pumpify(secretStream.encrypt(blockSize, header, key), writeHeader)
}

exports.decrypt = function (blockSize, key, max) {
  return readBytes(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES, function (header, swap) {
    if (header.byteLength < sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) return swap(new Error('Invalid header'))

    return swap(null, secretStream.decrypt(blockSize, header, key, max))
  })
}
