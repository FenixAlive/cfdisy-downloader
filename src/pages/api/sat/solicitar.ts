import { SATService } from '../../../lib/sat-service-simple';

export const POST = async ({ request }: { request: Request }) => {
    try {
        const data = await request.formData();
        const cer = data.get('cer') as File;
        const key = data.get('key') as File;
        const password = data.get('password') as string;

        console.log('API Solicitar: Recibido CER', cer?.name, cer?.size);
        console.log('API Solicitar: Recibido KEY', key?.name, key?.size);

        if (!cer || cer.size === 0 || !key || key.size === 0 || !password) {
            return new Response(JSON.stringify({ success: false, message: 'Faltan archivos (CER/KEY) o contraseña.' }), { status: 400 });
        }

        const dateStart = data.get('dateStart') as string;
        const dateEnd = data.get('dateEnd') as string;
        const type = data.get('type') as 'emitidas' | 'recibidas';
        const rfcManual = data.get('rfc') as string;
        const saveCreds = data.get('saveCreds') === 'true';

        const cerBuffer = new Uint8Array(await cer.arrayBuffer());
        const keyBuffer = new Uint8Array(await key.arrayBuffer());

        // Función para convertir Uint8Array a base64
        const uint8ArrayToBase64 = (bytes: Uint8Array): string => {
            let binaryString = '';
            for (let i = 0; i < bytes.length; i++) {
                binaryString += String.fromCharCode(bytes[i]);
            }
            return btoa(binaryString);
        };

        // 1. Parsear credenciales
        const creds = await SATService.parseCredentials(cerBuffer, keyBuffer, password);
        (global as any).lastSatCreds = creds; // Persistir para esta sesión local
        
        // 2. Obtener Token
        const token = await SATService.authenticate(creds);

        // 3. Solicitar Descarga
        const result = await SATService.solicitarDescarga(creds, token, {
            dateStart: dateStart,
            dateEnd: dateEnd,
            type: type,
            rfc: rfcManual || creds.rfc
        });

        return new Response(JSON.stringify({ 
            success: true, 
            requestId: result.idSolicitud,
            rfc: rfcManual || creds.rfc,
            saveCredentials: saveCreds ? {
                cerBase64: `data:application/x-x509-ca-cert;base64,${uint8ArrayToBase64(cerBuffer)}`,
                keyBase64: `data:application/pkcs8;base64,${uint8ArrayToBase64(keyBuffer)}`,
                password: password,
                cerName: cer.name,
                keyName: key.name
            } : null
        }));
    } catch (error: any) {
        console.error(error);
        return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }
};
