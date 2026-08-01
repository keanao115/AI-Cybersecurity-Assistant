import cryptoModule from 'crypto';
export const crypto = {
    randomUUID: () => {
        if (typeof cryptoModule.randomUUID === 'function') {
            return cryptoModule.randomUUID();
        }
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
            const r = (Math.random() * 16) | 0;
            const v = c === 'x' ? r : (r & 0x3) | 0x8;
            return v.toString(16);
        });
    }
};
