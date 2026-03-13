// Crypto utilities compatible with Cloudflare Workers

export function randomUUID(): string {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        // Web Crypto API (Cloudflare Workers, browsers)
        return crypto.randomUUID();
    } else if (typeof self !== 'undefined' && self.crypto && self.crypto.randomUUID) {
        // Alternative Web Crypto API reference
        return self.crypto.randomUUID();
    } else {
        // Fallback for Node.js environments
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

export function generateRandomBytes(length: number): Uint8Array {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        // Web Crypto API (Cloudflare Workers, browsers)
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    } else {
        // Fallback for Node.js environments
        const array = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            array[i] = Math.floor(Math.random() * 256);
        }
        return array;
    }
}
