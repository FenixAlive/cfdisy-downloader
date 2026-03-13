// @ts-nocheck
import forge from 'node-forge';
import { randomUUID } from './crypto-utils.js';
import { SignedXml } from 'xml-crypto';
import axios from 'axios';

export class SATService {
    private static AUTH_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc';
    private static SOLICITA_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc';
    private static VERIFICA_URL = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc';
    private static DESCARGA_URL = 'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc';

    private static nospaces(xml: string): string {
        return xml
            .replace(/^\s+/gm, '') // Remove horizontal spaces at beginning
            .replace(/\s+\r?\n/g, '') // Remove horizontal spaces + optional CR + LF
            .replace(/\r?\n/g, '') // Remove remaining newlines
            .replace(/>\s+</g, '><') // Remove spaces between tags
            .trim();
    }

    static async parseCredentials(cerInput: any, keyInput: any, password: string) {
        try {
            if (!cerInput || !keyInput) {
                throw new Error('Certificado o Llave no proporcionados.');
            }

            const toBinary = (input: any) => {
                if (Buffer.isBuffer(input)) return input.toString('binary');
                if (typeof input === 'string') {
                    // Si es un Data URL (Vite/Astro FileReader result), quitar prefijo
                    const base64 = input.includes(',') ? input.split(',')[1] : input;
                    return Buffer.from(base64, 'base64').toString('binary');
                }
                return Buffer.from(input).toString('binary');
            };

            console.log('SATService: Pasando buffers a binary string...');
            const cerBinary = toBinary(cerInput);
            const keyBinary = toBinary(keyInput);

            console.log('SATService: Parseando ASN1 del certificado...');
            const asn1Cer = forge.asn1.fromDer(cerBinary);
            const cert = forge.pki.certificateFromAsn1(asn1Cer);
            
            console.log('SATService: Extrayendo RFC...');
            // El RFC suele estar en x500UniqueIdentifier (OID 0.9.2342.19200300.100.1.1) o serialNumber
            // Pero a veces forge mezcla atributos. Buscamos específicamente un patrón de RFC (12-13 chars ALFANUMÉRICOS)
            const findRfc = () => {
                for (const attr of cert.subject.attributes) {
                    const val = (attr.value || '').toString().trim();
                    // Patrón simple: 12 o 13 caracteres, mayúsculas y números, sin espacios
                    if (/^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$/.test(val)) return val;
                }
                // Fallback: buscar en x500UniqueIdentifier específicamente si no hubo match por patrón
                const uniqueId = cert.subject.getField('x500UniqueIdentifier');
                if (uniqueId) return uniqueId.value;
                return null;
            };

            const rfc = findRfc() || '';
            console.log('SATService: RFC detectado:', rfc);

            console.log('SATService: Parseando ASN1 de la llave...');
            const asn1Key = forge.asn1.fromDer(keyBinary);
            
            console.log('SATService: Intentando descifrar PKCS#8...');
            const decryptedAsn1 = forge.pki.decryptPrivateKeyInfo(asn1Key, password);
            
            if (!decryptedAsn1) {
                throw new Error('No se pudo descifrar la llave. La contraseña es incorrecta o el formato no es PKCS#8.');
            }

            console.log('SATService: Decrypted ASN1 type:', decryptedAsn1.type, 'tagClass:', decryptedAsn1.tagClass);
            
            let privateKey: any;
            try {
                // Intento 1: Como PrivateKeyInfo (PKCS#8)
                privateKey = forge.pki.privateKeyFromPrivateKeyInfo(decryptedAsn1);
                console.log('SATService: Éxito con privateKeyFromPrivateKeyInfo');
            } catch (pk8Error) {
                console.log('SATService: privateKeyFromPrivateKeyInfo falló, intentando privateKeyFromAsn1...');
                try {
                    // Intento 2: Como RSAPrivateKey (PKCS#1) o ASN1 directo
                    privateKey = forge.pki.privateKeyFromAsn1(decryptedAsn1);
                    console.log('SATService: Éxito con privateKeyFromAsn1');
                } catch (pk1Error) {
                    console.error('SATService: Ambos métodos de parseo fallaron.');
                    throw new Error('La llave se descifró pero el formato interno no es reconocido como RSA válido.');
                }
            }
            
            if (!privateKey || (!privateKey.n && !privateKey.privateKey)) {
                throw new Error('La llave resultante no contiene los componentes RSA esperados.');
            }

            console.log('SATService: Generando PEMs y seriales...');
            // El serial del SAT suele venir en hex representando caracteres ASCII (ej: 3030... -> 00...)
            let certSerial = cert.serialNumber;
            if (/^[0-9a-fA-F]+$/.test(certSerial)) {
                try {
                    const hex = certSerial.length % 2 !== 0 ? '0' + certSerial : certSerial;
                    const bytes = Buffer.from(hex, 'hex').toString('utf8');
                    // Si el resultado parece una cadena de dígitos, lo usamos
                    if (/^[0-9]+$/.test(bytes)) {
                        certSerial = bytes;
                    }
                } catch (e) {
                    console.log('SATService: No se pudo convertir serial hex, se usará raw.');
                }
            }
            // Limpiar ceros a la izquierda (el SAT a veces los omite en el XML pero están en el cert)
            certSerial = certSerial.replace(/^0+/g, '');
            console.log('SATService: Serial detectado:', certSerial);
            
            const certBase64 = Buffer.from(cerBinary, 'binary').toString('base64');
            const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
            
            // Re-procesar el issuer. Mapear OIDs comunes del SAT que forge no conoce
            const oidMap: Record<string, string> = {
                '2.5.4.45': 'x500UniqueIdentifier',
                '0.9.2342.19200300.100.1.1': 'x500UniqueIdentifier',
                '2.5.4.5': 'serialNumber'
            };

            const certIssuer = cert.issuer.attributes
                .map((a: any) => {
                    const name = a.shortName || oidMap[a.type] || a.name || 'OID.' + a.type;
                    return `${name}=${a.value}`;
                })
                .reverse()
                .join(',');
            console.log('SATService: Issuer detectado:', certIssuer);

            console.log('SATService: Credenciales procesadas con éxito.');
            return {
                rfc,
                certSerial,
                certBase64,
                privateKeyPem,
                certIssuer
            };
        } catch (e: any) {
            console.error('ERROR en SATService.parseCredentials:', e);
            throw new Error(`Error al procesar archivos: ${e.message || 'Error desconocido'}`);
        }
    }

    static async getAccessToken(creds: any): Promise<string> {
        const now = new Date();
        const created = now.toISOString().split('.')[0] + 'Z';
        const expires = new Date(now.getTime() + 300000).toISOString().split('.')[0] + 'Z';
        
        // Estructura mínima idéntica a phpcfdi
        const xml = `<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><S:Header><o:Security S:mustUnderstand="1"><u:Timestamp u:Id="_0"><u:Created>${created}</u:Created><u:Expires>${expires}</u:Expires></u:Timestamp><o:BinarySecurityToken u:Id="_1" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">${creds.certBase64}</o:BinarySecurityToken></o:Security></S:Header><S:Body><Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/></S:Body></S:Envelope>`;

        const sig = new SignedXml({
            privateKey: creds.privateKeyPem,
            signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
            idAttributes: ['u:Id', 'Id']
        });

        // phpcfdi SOLO firma el Timestamp
        sig.addReference({
            xpath: "//*[local-name()='Timestamp' and (@*[local-name()='Id']='_0')]",
            transforms: ['http://www.w3.org/2001/10/xml-exc-c14n#'],
            digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1'
        });

        const keyInfo = `<o:SecurityTokenReference><o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#_1"/></o:SecurityTokenReference>`;
        sig.keyInfoProvider = {
            getKeyInfo: () => `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">${keyInfo}</KeyInfo>`
        } as any;
        
        sig.computeSignature(xml, { 
            location: { reference: "//*[local-name()='Security']", action: "append" }
        });

        let signedXml = sig.getSignedXml();

        // Limpieza de Namespaces redundantes de xml-crypto
        signedXml = signedXml.replace('<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">', '<SignedInfo>');

        // Reparación de etiquetas vacías si xml-crypto las genera cortas (/>)
        // El SAT a veces prefiere etiquetas de cierre explícitas
        signedXml = signedXml.replace(
            /<CanonicalizationMethod Algorithm="http:\/\/www.w3.org\/2001\/10\/xml-exc-c14n#"\/>/g,
            '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>'
        );
        signedXml = signedXml.replace(
            /<Transform Algorithm="http:\/\/www.w3.org\/2001\/10\/xml-exc-c14n#"\/>/g,
            '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>'
        );

        // Garantizar KeyInfo (xml-crypto v6 suele ponerlo)
        if (!signedXml.includes('<KeyInfo>')) {
            const ki = `<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">${keyInfo}</KeyInfo>`;
            signedXml = signedXml.replace('</SignatureValue>', `</SignatureValue>${ki}`);
        }

        console.log('Sending Auth Request to SAT (Minimal WSS 1.0)...');
        const response = await axios.post(this.AUTH_URL, signedXml, {
            headers: { 
                'Content-Type': 'text/xml; charset=utf-8', 
                'SOAPAction': 'http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica' 
            }
        });

        const tokenMatch = response.data.match(/AutenticaResult>(.*?)<\/AutenticaResult/);
        if (!tokenMatch) throw new Error('Auth Failed');
        return tokenMatch[1];
    }

    private static manualSign(toDigest: string, creds: any, uri: string = ''): string {
        const hash = forge.md.sha1.create();
        hash.update(toDigest, 'utf8');
        const digestValue = Buffer.from(hash.digest().getBytes(), 'binary').toString('base64');

        const signedInfoWithNamespace = this.nospaces(`
            <SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>
                <Reference URI="${uri}">
                    <Transforms>
                        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>
                    </Transforms>
                    <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>
                    <DigestValue>${digestValue}</DigestValue>
                </Reference>
            </SignedInfo>
        `);

        const privKey = forge.pki.privateKeyFromPem(creds.privateKeyPem);
        const md = forge.md.sha1.create();
        md.update(signedInfoWithNamespace, 'utf8');
        const signatureValue = Buffer.from(privKey.sign(md), 'binary').toString('base64');

        const certificate = creds.certBase64.replace(/\r?\n/g, '');
        const keyInfo = `<KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>${creds.certIssuer}</X509IssuerName><X509SerialNumber>${creds.certSerial}</X509SerialNumber></X509IssuerSerial><X509Certificate>${certificate}</X509Certificate></X509Data></KeyInfo>`;

        const signedInfoFinal = signedInfoWithNamespace.replace(' xmlns="http://www.w3.org/2000/09/xmldsig#"', '');

        return this.nospaces(`
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                ${signedInfoFinal}
                <SignatureValue>${signatureValue}</SignatureValue>
                ${keyInfo}
            </Signature>
        `);
    }


    static async solicitarDescarga(creds: any, token: string, options: any) {
        const rfcAttr = options.type === 'emitidas' ? 'RfcEmisor' : 'RfcReceptor';
        const method = options.type === 'emitidas' ? 'SolicitaDescargaEmitidos' : 'SolicitaDescargaRecibidos';
        const soapAction = `http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/${method}`;

        const attrs = [
            `EstadoComprobante="Vigente"`,
            `FechaFinal="${options.end}T23:59:59"`,
            `FechaInicial="${options.start}T00:00:00"`,
            `${rfcAttr}="${creds.rfc}"`,
            `RfcSolicitante="${creds.rfc}"`,
            `TipoSolicitud="CFDI"`
        ].sort().join(' ');

        const toDigest = this.nospaces(`<des:${method} xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:solicitud ${attrs}></des:solicitud></des:${method}>`);
        const signature = this.manualSign(toDigest, creds, '');

        const signedXml = this.nospaces(`
            <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
                <S:Header/>
                <S:Body>
                    <des:${method}>
                        <des:solicitud ${attrs}>
                            ${signature}
                        </des:solicitud>
                    </des:${method}>
                </S:Body>
            </S:Envelope>
        `);

        console.log('Token obtenido. Esperando 3 segundos para propagación...');
        await new Promise(r => setTimeout(r, 3000));

        console.log('Enviando solicitud de descarga (v1.5 + SHA1)...');
        const response = await axios.post(this.SOLICITA_URL, signedXml, {
            headers: { 
                'Content-Type': 'text/xml; charset=utf-8', 
                'SOAPAction': soapAction, 
                'Authorization': `WRAP access_token="${token}"` 
            }
        });

        const idMatch = response.data.match(/IdSolicitud="(.*?)"/);
        if (!idMatch) {
            console.error('XML Enviado:', signedXml);
            console.error('Respuesta SAT:', response.data);
            const statusMatch = response.data.match(/CodEstatus="(.*?)"/);
            const mensajeMatch = response.data.match(/Mensaje="(.*?)"/);
            const errorMsg = mensajeMatch ? mensajeMatch[1] : 'Solicitud rechazada.';
            throw new Error(`SAT Error [${statusMatch?.[1]}]: ${errorMsg}`);
        }
        return idMatch[1];
    }

    static async verificarSolicitud(creds: any, token: string, idSolicitud: string) {
        const toDigest = this.nospaces(`<des:VerificaSolicitudDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:solicitud IdSolicitud="${idSolicitud}" RfcSolicitante="${creds.rfc}"></des:solicitud></des:VerificaSolicitudDescarga>`);
        const signature = this.manualSign(toDigest, creds, '');
        
        const signedXml = this.nospaces(`
            <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
                <S:Header/>
                <S:Body>
                    <des:VerificaSolicitudDescarga>
                        <des:solicitud IdSolicitud="${idSolicitud}" RfcSolicitante="${creds.rfc}">
                            ${signature}
                        </des:solicitud>
                    </des:VerificaSolicitudDescarga>
                </S:Body>
            </S:Envelope>
        `);
        
        const response = await axios.post(this.VERIFICA_URL, signedXml, {
            headers: { 'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': 'http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga', 'Authorization': `WRAP access_token="${token}"` }
        });

        const estadoMatch = response.data.match(/EstadoSolicitud="(.*?)"/);
        const codEstatusMatch = response.data.match(/CodEstatus="(.*?)"/);
        const codEstSolMatch = response.data.match(/CodigoEstadoSolicitud="(.*?)"/);
        const numCfdisMatch = response.data.match(/NumeroCFDIs="(.*?)"/);
        const paqueteMatch = response.data.match(/IdsPaquetes>.*?([^<]+).*?<\/IdsPaquetes/); 
        
        return {
            estado: estadoMatch ? estadoMatch[1] : '?',
            codEstatus: codEstatusMatch ? codEstatusMatch[1] : '?',
            codigoEstadoSolicitud: codEstSolMatch ? codEstSolMatch[1] : '?',
            numeroCfdis: numCfdisMatch ? parseInt(numCfdisMatch[1], 10) : 0,
            paqueteId: paqueteMatch ? paqueteMatch[1].trim() : null
        };
    }

    static async descargarPaquete(creds: any, token: string, paqueteId: string) {
        const toDigest = this.nospaces(`<des:PeticionDescargaMasivaTercerosEntrada xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx"><des:peticionDescarga IdPaquete="${paqueteId}" RfcSolicitante="${creds.rfc}"></des:peticionDescarga></des:PeticionDescargaMasivaTercerosEntrada>`);
        const signature = this.manualSign(toDigest, creds, '');

        const signedXml = this.nospaces(`
            <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">
                <S:Header/>
                <S:Body>
                    <des:PeticionDescargaMasivaTercerosEntrada>
                        <des:peticionDescarga IdPaquete="${paqueteId}" RfcSolicitante="${creds.rfc}">
                            ${signature}
                        </des:peticionDescarga>
                    </des:PeticionDescargaMasivaTercerosEntrada>
                </S:Body>
            </S:Envelope>
        `);
        
        const response = await axios.post(this.DESCARGA_URL, signedXml, {
            headers: { 
                'Content-Type': 'text/xml; charset=utf-8', 
                'SOAPAction': 'http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar', 
                'Authorization': `WRAP access_token="${token}"` 
            }
        });

        const zipMatch = response.data.match(/Paquete>(.*?)<\/Paquete/);
        if (!zipMatch) {
            console.error('Download Fail Response:', response.data);
        }
        return zipMatch ? zipMatch[1] : null;
    }




}
