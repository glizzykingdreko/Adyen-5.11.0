# Adyen-5.11.0

The `adyen-5.11.0` npm module is an implementation of Adyen's v5.11.0 encryption method for Node.js, reverting back to the "old style adyen encryption." Unlike the 4.xx versions, this module simplifies the process by not requiring the public key, URL, and click/movement data in the encrypted JSON. However, most sites using Adyen still require generating RiskData based on their 1.0.0 version of fingerprinting, with some modifications to hash functions. Check out my solution for Adyen RiskData at [glizzykingdreko/Adyen-riskData](https://github.com/glizzykingdreko/Adyen-riskData).

For previous versions of Adyen encryption methods, see my other repositories:
- [Adyen-4.5.0](https://github.com/glizzykingdreko/adyen-4.5.0)
- [Adyen-4.4.1](https://github.com/glizzykingdreko/adyen-4.4.1)

## Table of Contents
- [Adyen-5.11.0](#adyen-5110)
  - [Table of Contents](#table-of-contents)
  - [Differences from the 4.xx Versions](#differences-from-the-4xx-versions)
  - [Resources](#resources)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Contributing](#contributing)
  - [License](#license)
  - [Credits](#credits)

## Differences from the 4.xx Versions
The main difference in the 5.11.0 version is the return to the simpler encryption method used in previous versions of Adyen's encryption. This version doesn't require additional data like public key, URL, and user interactions for encrypting card data. For RiskData generation, Adyen still uses a modified version of [fingerprintjs2](https://github.com/LukasDrgon/fingerprintjs2).

## Resources

- Learn more about Adyen's encryption method [here](https://docs.takionapi.tech/adyen)

## Installation

Install via npm:
```bash
npm install adyen-5.11.0
```

## Usage

To use the module, simply require it and call the necessary functions. Example usage:

```javascript
const encryptCardData = require('adyen-5.11.0');

// Example card data
const cardData = {
  number: '4242424242424242',
  expiryMonth: '12',
  expiryYear: '2023',
  cvc: '123'
};

// Encrypt the card data
const encryptedData = encryptCardData(
    cardData.number,
    cardData.expiryMonth,
    cardData.expiryYear,
    cardData.cvc,
    'adyenKey'
);
console.log(encryptedData);
```
Please note that you need to replace `adyenKey` with the actual website's Adyen key.

## Contributing

We appreciate any contributions you might make. Please feel free to submit a pull request, issue, or suggestion.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more information.

## Credits

- [GlizzyKingDreko](https://github.com/GlizzyKingDreko) - Developer