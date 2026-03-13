import { SATService } from '../lib/sat-service.js';

export async function POST({ request }) {
    try {
        const { packageId, cerBase64, keyBase64, password } = await request.json();

        if (!packageId || !cerBase64 || !keyBase64 || !password) {
            return Response.json({ success: false, message: 'Faltan campos requeridos' }, { status: 400 });
        }

        // Convertir base64 a buffers
        const cerBuffer = Buffer.from(cerBase64.split(',')[1], 'base64');
        const keyBuffer = Buffer.from(keyBase64.split(',')[1], 'base64');

        // Parsear credenciales
        const credentials = await SATService.parseCredentials(cerBuffer, keyBuffer, password);

        // Descargar XMLs
        const result = await SATService.descargarPaquete(credentials, credentials.token, packageId);

        return Response.json({
            success: true,
            count: result.xmls.length,
            xmls: result.xmls
        });

    } catch (error) {
        console.error('Error en /api/sat/descargar:', error);
        return Response.json({
            success: false,
            message: error.message || 'Error interno del servidor'
        }, { status: 500 });
    }
}
