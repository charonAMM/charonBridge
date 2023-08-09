
<b>charon bridge</b>

For more information, check out the [whitepaper](https://github.com/charonAMM/charonBridge/blob/main/CharonBridge.pdf)

## Setting up and testing

The build step compiles the circuit, does untrusted setup, generates verifier contract, and compiles all the contracts. It could take a while at the build step.


First install circom:

[https://docs.circom.io/getting-started/installation/#installing-circom](https://docs.circom.io/getting-started/installation/#installing-circom)


then:

```sh
npm i
npm run build
npx hardhat test
```

## Donations

ETH - 0x92683a09B64148369b09f96350B6323D37Af6AE3