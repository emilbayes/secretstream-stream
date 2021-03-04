var test = require('tape')
var secretstream = require('.')

test('simple', function (assert) {
  var key = secretstream.keygen()
  var header = new Uint8Array(secretstream.HEADERBYTES)

  var initKeyCopy = Buffer.from(key)
  var tx = secretstream.encrypt(header, key)
  assert.ok(header.some(b => b > 0), 'did fill header')
  assert.same(key, initKeyCopy)

  var headerCopy = new Uint8Array(header)
  var keyCopy = Buffer.from(key)
  var rx = secretstream.decrypt(header, key)

  assert.same(header, headerCopy)
  assert.same(key, keyCopy)

  var msg = new TextEncoder().encode('Hello world')

  var ciphertext = tx.encrypt(secretstream.TAG_PUSH, msg)
  assert.equal(tx.encrypt.bytes, msg.byteLength + secretstream.ABYTES)

  var plaintext = rx.decrypt(ciphertext)
  assert.equal(rx.decrypt.bytes, msg.byteLength)
  assert.same(rx.decrypt.tag, new Uint8Array(secretstream.TAG_PUSH))
  assert.same(plaintext, msg)

  assert.end()
})
