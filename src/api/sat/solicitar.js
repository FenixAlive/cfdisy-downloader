import { SATService } from '../lib/sat-service.js';
import { randomUUID } from 'crypto';

export async function POST({ request }) {
    try {
        const formData = await request.formData();
        const cer = formData.get('cer');
        const key = formData.get('key');
        const password = formData.get('password');
        const dateStart = formData.get('dateStart');
        const dateEnd = formData.get('dateEnd');
        const type = formData.get('type');
        const rfc = formData.get('rfc');
        const saveCreds = formData.get('saveCreds') === 'true';

        if (!cer || !key || !password || !dateStart || !dateEnd || !type) {
            return Response.json({ success: false, message: 'Faltan campos requeridos' }, { status: 400 });
        }

        // Convertir archivos a buffers
        const cerBuffer = Buffer.from(await cer.arrayBuffer());
        const keyBuffer = Buffer.from(await key.arrayBuffer());

        // Parsear credenciales
        const credentials = await SATService.parseCredentials(cerBuffer, keyBuffer, password.toString());
        
        // Guardar credenciales si se solicita
        if (saveCreds && credentials.rfc) {
            const cerBase64 = Buffer.from(cerBuffer).toString('base64');
            const keyBase64 = Buffer.from(keyBuffer).toString('base64');
            
            // Aquí guardaríamos en localStorage del lado del cliente
            // Pero como estamos en el servidor, devolvemos las credenciales para que el cliente las guarde
            const credentialsToSave = {
                cerBase64: `data:application/x-x509-ca-cert;base64,${cerBase64}`,
                keyBase64: `data:application/pkcs8;base64,${keyBase64}`,
                password: password.toString(),
                cerName: cer.name,
                keyName: key.name
            };
        }
        
        // Formatear fechas
        const formatDate = (dateStr) => {
            const [year, month, day] = dateStr.split('-');
            return `${day}/${month}/${year}`;
        };

        const result = await SATService.solicitarDescarga(
            credentials,
            credentials.token, // El token viene de las credenciales parseadas
            {
                type: type.toString(),
                rfc: rfc?.toString() || credentials.rfc,
                dateStart: formatDate(dateStart.toString()),
                dateEnd: formatDate(dateEnd.toString())
            }
        );

        if (result && result.idSolicitud) {
            return Response.json({
                success: true,
                requestId: result.idSolicitud,
                rfc: credentials.rfc,
                saveCredentials: saveCreds ? {
                    cerBase64: `data:application/x-x509-ca-cert;base64,${Buffer.from(cerBuffer).toString('base64')}`,
                    keyBase64: `data:application/pkcs8;base64,${Buffer.from(keyBuffer).toString('base64')}`,
                    password: password.toString(),
                    cerName: cer.name,
                    keyName: key.name
                } : null
            });
        } else {
            return Response.json({
                success: false,
                message: 'Error al crear solicitud',
                rfc: credentials.rfc,
                saveCredentials: saveCreds ? {
                    cerBase64: `data:application/x-x509-ca-cert;base64,${Buffer.from(cerBuffer).toString('base64')}`,
                    keyBase64: `data:application/pkcs8;base64,${Buffer.from(keyBuffer).toString('base64')}`,
                    password: password.toString(),
                    cerName: cer.name,
                    keyName: key.name
                } : null
            }, { status: 400 });
        }

    } catch (error) {
        console.error('Error en /api/sat/solicitar:', error);
        
        // Intentar guardar credenciales incluso si hay error
        try {
            const formData = await request.formData();
            const cer = formData.get('cer');
            const key = formData.get('key');
            const password = formData.get('password');
            const rfc = formData.get('rfc');
            const saveCreds = formData.get('saveCreds') === 'true';

            if (saveCreds && cer && key && password) {
                const cerBuffer = Buffer.from(await cer.arrayBuffer());
                const keyBuffer = Buffer.from(await key.arrayBuffer());
                
                return Response.json({
                    success: false,
                    message: error.message || 'Error interno del servidor',
                    saveCredentials: {
                        cerBase64: `data:application/x-x509-ca-cert;base64,${Buffer.from(cerBuffer).toString('base64')}`,
                        keyBase64: `data:application/pkcs8;base64,${Buffer.from(keyBuffer).toString('base64')}`,
                        password: password.toString(),
                        cerName: cer.name,
                        keyName: key.name
                    }
                }, { status: 500 });
            }
        } catch (saveError) {
            console.error('Error al guardar credenciales:', saveError);
        }
        
        return Response.json({
            success: false,
            message: error.message || 'Error interno del servidor'
        }, { status: 500 });
    }
}
