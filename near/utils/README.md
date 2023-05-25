# Fast bridge utils
It is a set of helper utils that simplify the interactions with fast bridge contracts

### Encode transfer message
To encode a transfer message from json into base64 format run:
```
cargo run -- encode-transfer-msg -m <JSON_MESSAGE>
```

Example:
```
cargo run -- encode-transfer-msg -m '{"valid_till":1675738327000000000,"transfer":{"token_near":"token.test1-dev.testnet","token_eth":"b2d75c5a142a68bda438e6a318c7fbb2242f9693","amount":"90"},"fee":{"token":"token.test1-dev.testnet","amount":"10"},"recipient":"2a23e0fa3afe77aff5dc6c6a007e3a10c1450633"}'
```

### Decode transfer message
To decode a transfer message from base64 into json run:
```
cargo run -- decode-transfer-msg -m <BASE64_MESSAGE>
```

Example:
```
cargo run -- decode-transfer-msg -m 'AKZXRSFrQRcXAAAAdG9rZW4udGVzdDEtZGV2LnRlc3RuZXSy11xaFCpovaQ45qMYx/uyJC+Wk1oAAAAAAAAAAAAAAAAAAAAXAAAAdG9rZW4udGVzdDEtZGV2LnRlc3RuZXQKAAAAAAAAAAAAAAAAAAAAKiPg+jr+d6/13GxqAH46EMFFBjMA'
```
