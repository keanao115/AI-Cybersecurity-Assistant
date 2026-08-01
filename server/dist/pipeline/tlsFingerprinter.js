import crypto from 'crypto';
export function extractTlsFingerprint(tlsVersion = 0x0303, ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f], extensions = [0, 23, 65281, 10, 11, 16, 5, 13], curves = [29, 23, 24], pointFormats = [0], sni = 'api.corp.internal') {
    // JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats
    const ja3String = `${tlsVersion},${ciphers.join('-')},${extensions.join('-')},${curves.join('-')},${pointFormats.join('-')}`;
    const ja3 = crypto.createHash('md5').update(ja3String).digest('hex');
    // JA4 format: t13d150500_ciphers_extensions
    const protoChar = 't';
    const verStr = tlsVersion === 0x0304 ? '13' : '12';
    const sniType = sni ? 'd' : 'i';
    const cipherCountStr = ciphers.length.toString().padStart(2, '0');
    const extCountStr = extensions.length.toString().padStart(2, '0');
    const alpnStr = '00';
    const firstPart = `${protoChar}${verStr}${sniType}${cipherCountStr}${extCountStr}${alpnStr}`;
    const cipherHash = crypto.createHash('sha256').update(ciphers.join(',')).digest('hex').substring(0, 12);
    const extHash = crypto.createHash('sha256').update(extensions.join(',')).digest('hex').substring(0, 12);
    const ja4 = `${firstPart}_${cipherHash}_${extHash}`;
    return {
        ja3,
        ja3String,
        ja4,
        sni,
        alpn: 'h2,http/1.1',
        tlsVersion: tlsVersion === 0x0304 ? 'TLS 1.3' : 'TLS 1.2',
        cipherSuiteCount: ciphers.length,
    };
}
