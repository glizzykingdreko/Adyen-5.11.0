let {sjcl} = require("./sjcl")

var AESKey = function() {};
AESKey.prototype = {
    constructor: AESKey,
    key: function() {
        this._key = this._key || sjcl.random.randomWords(8, 6);
        return this._key
    },
    encrypt: function(text) {
        return this.encryptWithIv(text, sjcl.random.randomWords(3, 6))
    },
    encryptWithIv: function(text, iv) {
        var aes, bits, cipher, cipherIV;
        aes = new sjcl.cipher.aes(this.key());
        bits = sjcl.codec.utf8String.toBits(text);
        cipher = sjcl.mode.ccm.encrypt(aes, bits, iv);
        cipherIV = sjcl.bitArray.concat(iv, cipher);
        return sjcl.codec.base64.fromBits(cipherIV)
    }
}

module.exports = { AESKey }