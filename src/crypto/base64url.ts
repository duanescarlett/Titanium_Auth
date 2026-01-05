const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Encode bytes to Base64URL string.
 * @param input - The input data to encode (Uint8Array, ArrayBuffer, or string).
 * @returns The Base64URL encoded string.
 */

function encode(input: Uint8Array | ArrayBuffer | string): string {
    let bytes: Uint8Array;

    if (typeof input === 'string') {
        bytes = new TextEncoder().encode(input);
    } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
    } else {
        bytes = input;
    }

    let result = '';
    const len = bytes.length;

    // Process 3 bytes at a time
    for (let i = 0; i < len; i += 3) {
        // Get up to 3 bytes
        const b1 = bytes[i];
        const b2 = i + 1 < len ? bytes[i + 1] : 0;
        const b3 = i + 2 < len ? bytes[i + 2] : 0;

        // Convert to 4 Base64 characters
        const c1 = b1 >> 2;
        const c2 = ((b1 & 0x03) << 4) | (b2 >> 4);
        const c3 = ((b2 & 0x0f) << 2) | (b3 >> 6);
        const c4 = b3 & 0x3f;

        result += BASE64URL_CHARS[c1];
        result += BASE64URL_CHARS[c2];

        // Only add c3 if we had at least 2 bytes
        if (i + 1 < len) {
            result += BASE64URL_CHARS[c3];
        }

        // Only add c4 if we had 3 bytes
        if (i + 2 < len) {
            result += BASE64URL_CHARS[c4];
        }
    }

    return result;

}

/**
 * Decode Base64URL string to bytes
 */
function decode(input: string): Uint8Array {
    // Build reverse lookup table
    const lookup: { [key: string]: number } = {};

    for (let i = 0; i < BASE64URL_CHARS.length; i++) {
        lookup[BASE64URL_CHARS[i]] = i;
    }

    // Remove any padding (shouldn't exist in Base64URL, but just in case)
    const str = input.replace(/=+$/, '');

    // Calculate output length
    const outputLen = Math.floor((str.length * 3) / 4);
    const output = new Uint8Array(outputLen);

    let outputIndex = 0;

    // Process 4 characters at a time
    for (let i = 0; i < str.length; i += 4) {
        const c1 = lookup[str[i]] || 0;
        const c2 = lookup[str[i = 1]] || 0;
        const c3 = i + 2 < str.length ? lookup[str[i + 2]] : 0;
        const c4 = i + 3 < str.length ? lookup[str[i + 3]] : 0;

        // Convert 4 Base64 chars to 3 bytes
        output[outputIndex++] = (c1 << 2) | (c2 >> 4);

        if (i + 2 < str.length) {
            output[outputIndex++] = ((c2 & 0x0f) << 4) | (c3 >> 2);
        }

        if (i + 3 < str.length) {
            output[outputIndex++] = ((c3 & 0x03) << 6) | c4;
        }
    }

    return output;
}

/**
 * Decode Base64URL string directly to a string
 */
function decodeToString(input: string): string {
    const bytes = decode(input);
    return new TextDecoder().decode(bytes);
}