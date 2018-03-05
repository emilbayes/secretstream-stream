var sodium = require('sodium-native')
var through = require('through2')
var blockStream = require('block-stream2')
var pumpify = require('pumpify')
var assert = require('nanoassert')

exports.KEYBYTES = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
exports.ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
exports.HEADERBYTES = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES

// consts to make code more readable
var TAG_PUSH = sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH
var TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
var TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
var TAG_REKEY = sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY

exports.encrypt = function secretTxStream (blockSize, header, key) {
  assert(Number.isSafeInteger(blockSize), 'blockSize must be safe integer')
  assert(blockSize > 0, 'blockSize must be larger 0')

  assert(Buffer.isBuffer(header), 'header must be Buffer')
  assert(header.byteLength >= exports.HEADERBYTES, 'header must be at least HEADERBYTES (' + exports.HEADERBYTES + ') long')

  assert(Buffer.isBuffer(key), 'key must be Buffer')
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES (' + exports.KEYBYTES + ') long')

  var state = sodium.crypto_secretstream_xchacha20poly1305_state_new()
  sodium.crypto_secretstream_xchacha20poly1305_init_push(state, header, key)

  return through.obj(send, finish)

  function send (message, _, cb) {
    var shouldRekey = message.rekey === true

    if (Buffer.isBuffer(message) === false) message = Buffer.from(message, _)

    var chunks = chunkAndPad(blockSize, message)

    for (var i = 0, last = chunks.length - 1; i <= last; i++) {
      var cbuf = Buffer.alloc(chunks[i].byteLength + exports.ABYTES)
      var tag = i !== last ? TAG_MESSAGE : shouldRekey === true ? TAG_REKEY : TAG_PUSH

      var mlen = sodium.crypto_secretstream_xchacha20poly1305_push(state, cbuf, chunks[i], null, tag)

      this.push(cbuf)
    }

    cb()
  }

  function finish (cb) {
    var cbuf = Buffer.alloc(blockSize + exports.ABYTES)
    var mlen = sodium.crypto_secretstream_xchacha20poly1305_push(state, cbuf, Buffer.alloc(blockSize), null, TAG_FINAL)

    this.push(cbuf)

    cb()
  }
}

exports.decrypt = function secretRxStream (blockSize, header, key, max) {
  assert(Number.isSafeInteger(blockSize), 'blockSize must be safe integer')
  assert(blockSize > 0, 'blockSize must be larger 0')

  assert(Buffer.isBuffer(header), 'header must be Buffer')
  assert(header.byteLength >= exports.HEADERBYTES, 'header must be at least HEADERBYTES (' + exports.HEADERBYTES + ') long')

  assert(Buffer.isBuffer(key), 'key must be Buffer')
  assert(key.byteLength >= exports.KEYBYTES, 'key must be at least KEYBYTES (' + exports.KEYBYTES + ') long')

  assert(max == null ? true : max > 0, 'max should be larger 0')

  var state = sodium.crypto_secretstream_xchacha20poly1305_state_new()
  sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)

  var limit = max || Infinity

  var cnt = 0
  var concatBuf = []

  return pumpify(blockStream(blockSize + exports.ABYTES), through.obj(receive))

  function receive (chunk, _, cb) {
    var tag = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_TAGBYTES)
    var message = Buffer.alloc(chunk.byteLength - exports.ABYTES)

    try {
      var clen = sodium.crypto_secretstream_xchacha20poly1305_pull(state, message, tag, chunk, null)
    } catch (ex) {
      return cb(ex)
    }

    if (tag.equals(TAG_MESSAGE)) {

      concatBuf.push(message)
      cnt += message.byteLength
    }

    if (tag.equals(TAG_PUSH) ||
        tag.equals(TAG_REKEY)) {
      this.push(concatAndUnpad(blockSize, concatBuf.concat(message), cnt + message.byteLength))
      concatBuf = []
      cnt = 0
    }

    if (tag.equals(TAG_FINAL)) {
      this.push(null)
    }

    if (cnt > limit) return cb(new Error('Reached recv limit'))

    cb()
  }
}


function chunkAndPad (bs, buf) {
  var blocks = Math.ceil(Math.max(buf.byteLength / bs, 1)) // at least 1 block
  var padBuf = Buffer.alloc(blocks * bs)

  padBuf.set(buf)
  var padLen = sodium.sodium_pad(padBuf, buf.byteLength, bs)

  var offset = 0
  var chunks = []
  while(offset < padLen) {
    chunks.push(padBuf.slice(offset, offset + bs))
    offset += bs
  }

  return chunks
}

function concatAndUnpad (bs, list, size) {
  var buf = Buffer.concat(list)

  var unpadLen = sodium.sodium_unpad(buf, buf.byteLength, bs)

  return buf.slice(0, unpadLen)
}
