import {compare, hash} from "bcrypt";
import * as crypto from "node:crypto";
import * as buffer from "node:buffer";
import {KeyPair} from "./key_pair.js";
import {AESData} from "./aes_data.js";

export class Crypto {
    /**
     * @param password
     * @return {Promise<string>}
     * @constructor
     */
    static async HashPassword(password) {
        const salt = 10;
        return await hash(password, salt);
    }

    /**
     * @param password
     * @param passwordHash
     * @return {Promise<boolean>}
     * @constructor
     */
    static async ComparePassword(password, passwordHash) {
        return await compare(password, passwordHash);
    }

    static async EncryptRSA(msg, publicKey) {
        return crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_PADDING,
        }, Buffer.from(msg, "utf8")).toString("base64");
    }

    static async DecryptRSA(msg, privateKey) {
        return crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING,
        }, Buffer.from(msg, "base64")).toString("utf8");
    }

    static async EncryptAES(msg) {
        const aes_key = crypto.randomBytes(32).toString("base64");
        const aes_iv = crypto.randomBytes(16).toString("base64");
        const cypher = crypto.createCipheriv("aes-256-gcm", Buffer.from(aes_key, "base64"), Buffer.from(aes_iv, "base64"));
        let aes_encrypted = cypher.update(msg, "utf8", "base64");
        aes_encrypted += cypher.final("base64");
        return new AESData()
            .SetKey(aes_key)
            .SetIv(aes_iv)
            .SetMsg(aes_encrypted);
    }

    /**
     * @param data AESData
     * @return {Promise<string>}
     */
    static async DecryptAES(data) {
        const cypher = crypto.createCipheriv("aes-256-gcm", Buffer.from(data.key, "base64"), Buffer.from(data.iv, "base64"));
        let decrypted = cypher.update(data.msg, "base64", "utf8");
        decrypted += cypher.final("utf8");
        return decrypted;
    }

    /**
     * @return {Promise<KeyPair>}
     */
    static async GenerateKeyPair() {
        const keys = crypto.generateKeyPairSync("rsa", {
            modulusLength: 8192,
            publicKeyEncoding: {
                type: "pkcs1",
                format: "pem",
            },
            privateKeyEncoding: {
                type: "pkcs1",
                format: "pem",
            },
        });
        return new KeyPair()
            .SetPublicKey(keys.publicKey)
            .SetPrivateKey(keys.privateKey);
    }
}