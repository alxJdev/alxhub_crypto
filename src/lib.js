import {Crypto} from "./crypto.js";

const msg = "SomeTestMessage";
const keypair = await Crypto.GenerateKeyPair();
console.log(keypair);
const aes_object = await Crypto.EncryptAES(msg);
if (!aes_object) {
    throw new Error();
}
const aes_msg = await Crypto.DecryptAES(aes_object);
if (aes_msg !== msg) {
    throw new Error();
}
const rsa_string = await Crypto.EncryptRSA(msg, keypair.publicKey);
if (!rsa_string) {
    throw new Error();
}
const rsa_msg = await Crypto.DecryptRSA(rsa_string, keypair.privateKey);
if (rsa_msg !== msg) {
    throw new Error();
}