let {sjcl} = require("./sjcl")
let {RSAKey} = require("./rsa")
let {AESKey} = require("./aes")

var Encryption = function (key, options) {
    try {
        if (options.randomBytes) {
            sjcl.random.addEntropy(options.randomBytes, 1024, "crypto.randomBytes")
        }
        sjcl.random.startCollectors()
    } catch (e) { }
    this.key = key;
    this.options = options || {};
    if (typeof this.options.numberIgnoreNonNumeric === "undefined") {
        this.options.numberIgnoreNonNumeric = true
    }
    if (typeof this.options.cvcIgnoreFornumber !== "undefined") {
        delete this.options.cvcIgnoreFornumber
    }
    if (typeof this.options.fourDigitCvcForBins === "undefined") {
        this.options.fourDigitCvcForBins = "34,37"
    }
    if (typeof this.options.cvcLengthFornumber !== "undefined") {
        delete this.options.cvcLengthFornumber
    }
    if (typeof this.options.cvcIgnoreBins === "string") {
        var binsToIgnore = [];
        this.options.cvcIgnoreBins.replace(/\d+/g, function (m) {
            if (m.length > 0 && !isNaN(parseInt(m, 10))) {
                binsToIgnore.push(m)
            }
            return m
        });
        if (binsToIgnore.length > 0) {
            this.options.cvcIgnoreFornumber = new RegExp("^\\s*(" + binsToIgnore.join("|") + ")")
        }
    } else {
        if (typeof this.options.cvcIgnoreBins !== "undefined") {
            delete this.options.cvcIgnoreBins
        }
    }
    if (typeof this.options.fourDigitCvcForBins === "string") {
        var cvcGroups = [];
        this.options.fourDigitCvcForBins.replace(/\d+/g, function (m) {
            if (m.length > 0 && !isNaN(parseInt(m, 10))) {
                cvcGroups.push(m)
            }
            return m
        });
        if (cvcGroups.length > 0) {
            this.options.cvcLengthFornumber = {
                matcher: new RegExp("^\\s*(" + cvcGroups.join("|") + ")"),
                requiredLength: 4
            }
        }
    }
    delete this.options.fourDigitCvcForBins;
    // evLog("initializeCount")
};
Encryption.prototype.createRSAKey = function () {
    var k = this.key.split("|");
    if (k.length !== 2) {
        throw "Malformed public key"
    }
    var exp = k[0];
    var mod = k[1];
    var rsa = new RSAKey();
    rsa.setPublic(mod, exp);
    return rsa
}
    ;
Encryption.prototype.createAESKey = function () {
    return new AESKey()
}
    ;
Encryption.prototype.encrypt = function (original) {
    var data = {};
    for (var i in original) {
        if (original.hasOwnProperty(i)) {
            data[i] = original[i]
        }
    }
    var rsa, aes, cipher, keybytes, encrypted, prefix, validationObject = {};
    if (typeof data.number !== "undefined") {
        validationObject.number = data.number
    }
    if (typeof data.cvc !== "undefined") {
        validationObject.cvc = data.cvc
    }
    if (typeof data.expiryMonth !== "undefined") {
        validationObject.month = data.expiryMonth
    }
    if (typeof data.expiryYear !== "undefined") {
        validationObject.year = data.expiryYear
    }
    if (typeof data.holderName !== "undefined") {
        validationObject.holderName = data.holderName
    }
    if (typeof data.generationtime !== "undefined") {
        validationObject.generationtime = data.generationtime
    }
    if (this.options.enableValidations !== false && this.validate(validationObject).valid === false) {
        return false
    }
    for (var s = 0; s < 11; s++) {
        if (sjcl.random && sjcl.random.isReady(s)) {
            // evLog("set", "sjclStrength", s)
        } else {
            break
        }
    }
    // evLog("extend", data);
    rsa = this.createRSAKey();
    aes = this.createAESKey();
    cipher = aes.encrypt(JSON.stringify(data));
    keybytes = sjcl.codec.bytes.fromBits(aes.key());
    encrypted = rsa.encrypt_b64(keybytes);
    prefix = "adyenjs_0_1_25$";
    return [prefix, encrypted, "$", cipher].join("")
}
    ;
Encryption.prototype.validate = function (data) {
    var result = {};
    result.valid = true;
    if (typeof data !== "object") {
        result.valid = false;
        return result
    }
    for (var field in data) {
        if (!data.hasOwnProperty(field) || typeof data[field] === "undefined") {
            continue
        }
        var val = data[field];
        if (this.options[field + "IgnoreNonNumeric"]) {
            val = val.replace(/\D/g, "")
        }
        if (this.options[field + "SkipValidation"]) {
            continue
        }
        for (var relatedField in data) {
            if (data.hasOwnProperty(relatedField)) {
                var possibleOption = this.options[field + "IgnoreFor" + relatedField];
                var lengthOption = this.options[field + "LengthFor" + relatedField];
                if (possibleOption && data[relatedField].match(possibleOption)) {
                    result[field] = true;
                    continue
                } else {
                    if (lengthOption && lengthOption.matcher && lengthOption.requiredLength && data[relatedField].match(lengthOption.matcher)) {
                        if (val.length !== lengthOption.requiredLength) {
                            result[field] = false;
                            continue
                        }
                    }
                }
            }
        }
        if (result.hasOwnProperty(field)) {
            result.valid = result.valid && result[field];
            continue
        }
        switch (field) {
            case "number":
                result.number = validations.numberCheck(val);
                result.luhn = result.number;
                result.valid = result.valid && result.number;
                break;
            case "expiryYear":
            case "year":
                result.year = validations.yearCheck(val);
                result.expiryYear = result.year;
                result.valid = result.valid && result.year;
                break;
            case "cvc":
                result.cvc = validations.cvcCheck(val);
                result.valid = result.valid && result.cvc;
                break;
            case "expiryMonth":
            case "month":
                result.month = validations.monthCheck(val);
                result.expiryMonth = result.month;
                result.valid = result.valid && result.month;
                break;
            case "holderName":
                result.holderName = validations.holderNameCheck(val);
                result.valid = result.valid && result.holderName;
                break;
            case "generationtime":
                result.generationtime = validations.generationTimeCheck(val);
                result.valid = result.valid && result.generationtime;
                break;
            default:
                result.unknown = result.unknown || [];
                result.unknown.push(field);
                result.valid = false
        }
    }
    return result
}
    ;
Encryption.prototype.monitor = function (field, node) {
    if (typeof field !== "string" || (field !== "number" && field !== "cvc" && field !== "holderName")) {
        throw new Error("invalid fieldname. Expected 'number', 'cvc' or 'holderName', but received '" + field + "'")
    }
    // evLog("bind", node, field)
}
    ;

module.exports = { Encryption }