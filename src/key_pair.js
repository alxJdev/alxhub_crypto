export class KeyPair {
    publicKey;
    privateKey;

    SetPublicKey(publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    SetPrivateKey(privateKey) {
        this.privateKey = privateKey;
        return this;
    }
}