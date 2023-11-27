const {Encryption} = require('./helpers/encryption');

function getCurrentTimestamp() {
    return new Date().toISOString();
}

function encryptCardData(
    card, 
    month, 
    year, 
    cvc,
    adyenKey,
    options={
        "enableValidations": false,
        "randomBytes": null,
        "numberIgnoreNonNumeric": true
    },
) {
    if (!card || !month || !year || !cvc) {
        throw new Error('Missing card details');
    }

    // Check if year is in 4 digits
    if (year.length !== 4) {
        throw new Error('Invalid year');
    }

    if (!adyenKey) {
        throw new Error('Missing Adyen key');
    }

    let encryptor = new Encryption(
        adyenKey,
        options
    )
    // Convert card from 4242424242424242 to 4242 4242 4242 4242
    const cardNumber = card.replace(/(.{4})/g, '$1 ').trim();
    
    return {
        encryptedCardNumber: encryptor.encrypt({
            "number": cardNumber,
            "generationtime": getCurrentTimestamp(),
        }),
        encryptedExpiryMonth: encryptor.encrypt({
            "expiryMonth": month,
            "generationtime": getCurrentTimestamp(),
        }),
        encryptedExpiryYear: encryptor.encrypt({
            "expiryYear": year,
            "generationtime": getCurrentTimestamp(),
        }),
        encryptedSecurityCode: encryptor.encrypt({
            "cvc": cvc,
            "generationtime": getCurrentTimestamp(),
        }),
    };

}

module.exports = encryptCardData;