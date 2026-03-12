import { SATService } from '../../../lib/sat-service';

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

        const cerBuffer = Buffer.from(await cer.arrayBuffer());
        const keyBuffer = Buffer.from(await key.arrayBuffer());

        // 1. Parsear credenciales
        const creds = await SATService.parseCredentials(cerBuffer, keyBuffer, password);
        (global as any).lastSatCreds = creds; // Persistir para esta sesión local
        
        // 2. Obtener Token
        const token = await SATService.getAccessToken(creds);

        // 3. Solicitar Descarga
        const requestId = await SATService.solicitarDescarga(creds, token, {
            start: dateStart,
            end: dateEnd,
            type: type,
            rfcSolicitante: rfcManual || creds.rfc
        });

        return new Response(JSON.stringify({ 
            success: true, 
            requestId,
            rfc: rfcManual || creds.rfc 
        }));
    } catch (error: any) {
        console.error(error);
        return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }
};
