// Utility functions for the SAT service

export function formatBase64(data: string): string {
    if (data.includes(',')) {
        return data.split(',')[1];
    }
    return data;
}

export function bufferToBase64(buffer: Buffer): string {
    return `data:application/octet-stream;base64,${buffer.toString('base64')}`;
}

export function formatDate(date: Date): string {
    return date.toISOString().split('T')[0];
}

export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
