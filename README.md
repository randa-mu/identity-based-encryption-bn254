# identity-based-encryption-bn254
![build](https://github.com/randa-mu/identity-based-encryption-bn254/actions/workflows/build.yml/badge.svg)

A typescript library for encrypting messages to a specific identity in a threshold setting.

## Quickstart

### Install
Install the javascript and the types like so:
`npm install identity-based-encryption-bn254`

### Instantiate
Create an instance of the IBE class, optionally configuring your options (which is only necessary when using custom DSTs).
```typescript
// import
import { IBE } from "identity-based-encryption-bn254"

const ibe = new IBE()
```
### Encrypt a message

```typescript
// get the public key for your signer (the lib also provides some convenience functions for creating from a secret key)
const publicKey = IBE.parsePublicKey(<some-bytes-here>)

// define the message your signer should sign in order to create an encryption key
const identity = ibe.createIdentity("alice@example.com") 

// encode your plaintext message
const message = new TextEncoder().encode("hello world") // or you can use a Buffer in node

// huzzah - you have a ciphertext!
const ciphertext = ibe.encrypt(message, identity, publicKey)
```

### Decrypt a message
```typescript

// get a signature over the identity from somewhere - this will act as the decryption key
const signature = ..

// you should now have a plaintext! if the signature wasn't valid or for the correct identity, this will throw an error
const plaintext = ibe.decrypt(ciphertext, signature)

```


## Usage with blocklock
For usage with [blocklock](https://github.com/randa-mu/blocklock-solidity) set the IBE opts depending on the chain you're using, e.g. for chainId of 1:
```javascript
const IBE_OPTS = {
  hash: keccak_256,
  k: 128,
  expand_fn: "xmd",
  dsts: {
    H1_G1: Buffer.from(`BLOCKLOCK_BN254G1_XMD:KECCAK-256_SVDW_RO_H1_0x0000000000000000000000000000000000000000000000000000000000000001_`),
    H2: Buffer.from(`BLOCKLOCK_BN254_XMD:KECCAK-256_H2_0x0000000000000000000000000000000000000000000000000000000000000001_`),
    H3: Buffer.from(`BLOCKLOCK_BN254_XMD:KECCAK-256_H3_0x0000000000000000000000000000000000000000000000000000000000000001_`),
    H4: Buffer.from(`BLOCKLOCK_BN254_XMD:KECCAK-256_H4_0x0000000000000000000000000000000000000000000000000000000000000001_`),
  },
}
```


## Acknowledgements
Thanks to @azixus, @kevincharm and @paulmillr for building the libs this was built on top of. Thanks to the [Filecoin Foundation](https://fil.org/) and [Scroll](https://scroll.io/) for funding this work in part.