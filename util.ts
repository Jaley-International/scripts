import forge, {Hex} from "node-forge";
import assert from "assert";

export function randomBytes(count: number): Hex {
    return forge.util.bytesToHex(forge.random.getBytesSync(count));
}

export function addPadding(str: string, length: number): string {
    assert(str.length <= length);
    while (str.length < length)
        str += "_";
    return str;
}

export function sha256(str: string): Hex {
    return forge.md.sha256.create().update(str).digest().toHex();
}
export function sha512(str: string): Hex {
    return forge.md.sha512.create().update(str).digest().toHex();
}

export function pbkdf2(password: string, salt: string): Promise<Hex> {
    return new Promise((resolve, reject) => {
        forge.pkcs5.pbkdf2(password, salt, 100000, 64, (err, derivedKey) => {
            if (err || !derivedKey)
                reject(err);
            else
                resolve(forge.util.bytesToHex(derivedKey));
        });
    });
}

export function encrypt(operation: "AES-CTR" | "AES-GCM", key: Hex, iv: string, str: string): Hex {
    const cipher = forge.cipher.createCipher(operation, forge.util.hexToBytes(key));
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(str));
    cipher.finish();
    return cipher.output.toHex();
}

export async function generateKeyPair(): Promise<forge.pki.KeyPair> {
    return new Promise((resolve, reject) => {
        forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {
            if (err)
                reject(err);
            resolve(keypair);
        });
    });
}

export function rsaSign(key: string, value: string): Hex {
    const privateKey = forge.pki.privateKeyFromPem(key);
    const digest = forge.md.sha256.create();
    digest.update(value);
    return forge.util.bytesToHex(privateKey.sign(digest));
}

export function truncateKey(key: string): string {
    key = key.replace(/-.*-/g, "");
    key = key.replace(/[\n\r]/g, "");
    return key.substring(0, 20) + "..." + key.substring(key.length - 20, key.length);
}

export function hexToBase64Url(hex: Hex): string {
    return Buffer.from(hex, 'hex')
        .toString('base64')
        .replace(/\//g, '-')
        .replace(/\+/g, '_')
        .replace('=', '');
}
