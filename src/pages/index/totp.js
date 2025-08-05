/**
 * TOTP (Time-based One-Time Password) Implementation
 * RFC 6238 compliant implementation in pure JavaScript
 */

class TOTP {
    constructor(secret, options = {}) {
        this.secret = secret;
        this.digits = options.digits || 6;
        this.period = options.period || 30;
        this.algorithm = options.algorithm || 'SHA-1';
    }

    /**
     * Generate TOTP code for current time
     */
    generate(timestamp = Date.now()) {
        const counter = Math.floor(timestamp / 1000 / this.period);
        return this.generateHOTP(counter);
    }

    /**
     * Generate HOTP code for given counter
     */
    generateHOTP(counter) {
        const key = this.base32Decode(this.secret);
        const counterBuffer = this.intToBytes(counter);
        const hmac = this.hmac(key, counterBuffer);
        
        // Dynamic truncation
        const offset = hmac[hmac.length - 1] & 0x0f;
        const code = ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);
        
        return (code % Math.pow(10, this.digits)).toString().padStart(this.digits, '0');
    }

    /**
     * Verify TOTP code
     */
    verify(token, window = 1, timestamp = Date.now()) {
        const currentCounter = Math.floor(timestamp / 1000 / this.period);
        
        for (let i = -window; i <= window; i++) {
            const testCounter = currentCounter + i;
            if (this.generateHOTP(testCounter) === token) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get remaining seconds until next code generation
     */
    getRemainingSeconds(timestamp = Date.now()) {
        const elapsed = Math.floor(timestamp / 1000) % this.period;
        return this.period - elapsed;
    }

    /**
     * HMAC implementation
     */
    hmac(key, data) {
        const blockSize = 64;
        
        if (key.length > blockSize) {
            key = this.sha1(key);
        }
        
        if (key.length < blockSize) {
            const newKey = new Uint8Array(blockSize);
            newKey.set(key);
            key = newKey;
        }
        
        const oKeyPad = new Uint8Array(blockSize);
        const iKeyPad = new Uint8Array(blockSize);
        
        for (let i = 0; i < blockSize; i++) {
            oKeyPad[i] = key[i] ^ 0x5c;
            iKeyPad[i] = key[i] ^ 0x36;
        }
        
        const innerData = new Uint8Array(iKeyPad.length + data.length);
        innerData.set(iKeyPad);
        innerData.set(data, iKeyPad.length);
        
        const innerHash = this.sha1(innerData);
        
        const outerData = new Uint8Array(oKeyPad.length + innerHash.length);
        outerData.set(oKeyPad);
        outerData.set(innerHash, oKeyPad.length);
        
        return this.sha1(outerData);
    }

    /**
     * SHA-1 implementation
     */
    sha1(data) {
        const h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        const ml = data.length * 8;
        
        // Pre-processing
        const paddedData = new Uint8Array(Math.ceil((data.length + 9) / 64) * 64);
        paddedData.set(data);
        paddedData[data.length] = 0x80;
        
        // Append length as 64-bit big-endian
        const view = new DataView(paddedData.buffer);
        view.setUint32(paddedData.length - 4, ml, false);
        
        // Process chunks
        for (let chunk = 0; chunk < paddedData.length; chunk += 64) {
            const w = new Array(80);
            
            // Break chunk into sixteen 32-bit words
            for (let i = 0; i < 16; i++) {
                w[i] = view.getUint32(chunk + i * 4, false);
            }
            
            // Extend words
            for (let i = 16; i < 80; i++) {
                w[i] = this.rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }
            
            let [a, b, c, d, e] = h;
            
            for (let i = 0; i < 80; i++) {
                let f, k;
                if (i < 20) {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                
                const temp = this.add32(this.add32(this.rotateLeft(a, 5), f), this.add32(this.add32(e, w[i]), k));
                e = d;
                d = c;
                c = this.rotateLeft(b, 30);
                b = a;
                a = temp;
            }
            
            h[0] = this.add32(h[0], a);
            h[1] = this.add32(h[1], b);
            h[2] = this.add32(h[2], c);
            h[3] = this.add32(h[3], d);
            h[4] = this.add32(h[4], e);
        }
        
        // Convert to bytes
        const result = new Uint8Array(20);
        const resultView = new DataView(result.buffer);
        for (let i = 0; i < 5; i++) {
            resultView.setUint32(i * 4, h[i], false);
        }
        
        return result;
    }

    /**
     * Base32 decoder
     */
    base32Decode(encoded) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        const cleanInput = encoded.replace(/=+$/, '').toUpperCase();
        const decoded = [];
        let bits = 0;
        let value = 0;
        
        for (const char of cleanInput) {
            const index = alphabet.indexOf(char);
            if (index === -1) continue;
            
            value = (value << 5) | index;
            bits += 5;
            
            if (bits >= 8) {
                decoded.push((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        
        return new Uint8Array(decoded);
    }

    /**
     * Convert integer to byte array (big-endian)
     */
    intToBytes(value) {
        const result = new Uint8Array(8);
        for (let i = 7; i >= 0; i--) {
            result[i] = value & 0xff;
            value = Math.floor(value / 256);
        }
        return result;
    }

    /**
     * Rotate left (32-bit)
     */
    rotateLeft(value, amount) {
        return ((value << amount) | (value >>> (32 - amount))) >>> 0;
    }

    /**
     * Add two 32-bit numbers
     */
    add32(a, b) {
        return (a + b) >>> 0;
    }

    /**
     * Generate QR code URL for Google Authenticator
     */
    getQRCodeURL(label, issuer) {
        const params = new URLSearchParams({
            secret: this.secret,
            issuer: issuer || 'TOTP',
            algorithm: this.algorithm,
            digits: this.digits,
            period: this.period
        });
        
        const uri = `otpauth://totp/${encodeURIComponent(label)}?${params}`;
        return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(uri)}`;
    }
}

// Usage examples:

// Generate random base32 secret
function generateSecret(length = 32) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += alphabet[Math.floor(Math.random() * alphabet.length)];
    }
    return result;
}

// Example usage:
// const secret = generateSecret();
// const totp = new TOTP(secret);
// const code = totp.generate();
// const isValid = totp.verify(code);
// const remaining = totp.getRemainingSeconds();

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TOTP, generateSecret };
}