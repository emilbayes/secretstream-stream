var test = require('tape')
var sodium = require('sodium-native')
var secretStream = require('./easy')
var pump = require('pump')
var choppa = require('choppa')
var through = require('through2')

test('happy case', function (assert) {
  var key = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)

  sodium.randombytes_buf(key)

  var wireSize = 512
  var blockSize = wireSize - sodium.crypto_secretstream_xchacha20poly1305_ABYTES

  var src = secretStream.encrypt(blockSize, key)
  var dest = secretStream.decrypt(blockSize, key)

  pump(src, assertChunks(assert, wireSize), choppa(0), dest, assertMessage(), function (err) {
    assert.error(err, 'should not error')
    assert.end()
  })

  var shortMessage = Buffer.from('Hello world')
  var longMessage = Buffer.alloc(2048).fill('Looooong message')

  var msgTypes = [shortMessage, longMessage]
  var messages = []

  while (messages.length < 100) {
    var msg = msgTypes[Math.random() * 2 | 0]
    messages.push(msg)
    src.write(msg)
  }

  messages.push(shortMessage)
  src.end(shortMessage)

  function assertMessage () {
    var messagesSeen = 0
    return through(function (msg, _, cb) {
      if (!msg.equals(messages[messagesSeen])) assert.fail(`Expected: ${msg}\nActual: ${messages[messagesSeen]}`)
      messagesSeen++
      cb()
    })
  }
})

test('bad key', function (assert) {
  var key1 = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
  var key2 = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)

  sodium.randombytes_buf(key1)
  sodium.randombytes_buf(key2)

  var wireSize = 512
  var blockSize = wireSize - sodium.crypto_secretstream_xchacha20poly1305_ABYTES

  var src = secretStream.encrypt(blockSize, key1)
  var dest = secretStream.decrypt(blockSize, key2)

  pump(src, assertChunks(assert, wireSize), choppa(0), dest, function (err) {
    assert.ok(err, 'should have error')
    assert.end()
  })

  src.end(Buffer.from('Lost transmission'))
})

test('mismatching blocksize', function (assert) {
  var key = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)

  sodium.randombytes_buf(key)

  var wireSize = 512
  var blockSize = wireSize - sodium.crypto_secretstream_xchacha20poly1305_ABYTES

  var src = secretStream.encrypt(blockSize + 1, key)
  var dest = secretStream.decrypt(blockSize, key)

  pump(src, assertChunks(assert, wireSize + 1), choppa(0), dest, function (err) {
    assert.ok(err, 'should have error')
    assert.end()
  })

  src.end(Buffer.from('Lost transmission'))
})

function assertChunks (assert, wireSize) {
  var chunksSeen = 0
  return through(function (chunk, _, cb) {
    if (chunksSeen === 0 && chunk.byteLength != sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
      assert.fail(`assertChunks: ${chunk.byteLength} != ${sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES}`)
    }
    else if (chunksSeen > 0 && chunk.byteLength != wireSize) {
      assert.fail(`assertChunks: ${chunk.byteLength} != ${wireSize}`)
    }

    chunksSeen++
    cb(null, chunk)
  })
}

test('mismatching blocksize', function (assert) {
  var key = Buffer.alloc(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)

  sodium.randombytes_buf(key)

  var wireSize = 512
  var blockSize = wireSize - sodium.crypto_secretstream_xchacha20poly1305_ABYTES

  var src = secretStream.encrypt(blockSize, key)
  var dest = secretStream.decrypt(blockSize + 1, key)

  pump(src, assertChunks(assert, wireSize), choppa(0), dest, function (err) {
    assert.ok(err, 'should have error')
    assert.end()
  })

  src.write(Buffer.from('Lost transmission'))
  src.end(Buffer.from('Lost transmission'))
})

function assertChunks (assert, wireSize) {
  var chunksSeen = 0
  return through(function (chunk, _, cb) {
    if (chunksSeen === 0 && chunk.byteLength != sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
      assert.fail(`assertChunks: ${chunk.byteLength} != ${sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES}`)
    }
    else if (chunksSeen > 0 && chunk.byteLength != wireSize) {
      assert.fail(`assertChunks: ${chunk.byteLength} != ${wireSize}`)
    }

    chunksSeen++
    cb(null, chunk)
  })
}
