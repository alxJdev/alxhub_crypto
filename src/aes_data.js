export class AESData {
    key;
    iv;
    msg;

    SetKey(key) {
        this.key = key;
        return this;
    }

    SetIv(iv) {
        this.iv = iv;
        return this;
    }

    SetMsg(msg) {
        this.msg = msg;
        return this;
    }
}