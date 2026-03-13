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

        if (!cer || !key || !password || !dateStart || !dateEnd || !type) {
            return Response.json({ success: false, message: 'Faltan campos requeridos' }, { status: 400 });
        }

        // Convertir archivos a buffers
        const cerBuffer = Buffer.from(await cer.arrayBuffer());
        const keyBuffer = Buffer.from(await key.arrayBuffer());

        // Parsear credenciales
        const credentials = await SATService.parseCredentials(cerBuffer, keyBuffer, password.toString());
        
        // Crear solicitud
        const requestId = randomUUID().replace(/-/g, '').substring(0, 20);
        
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
                rfc: credentials.rfc
            });
        } else {
            return Response.json({
                success: false,
                message: 'Error al crear solicitud'
            }, { status: 400 });
        }

    } catch (error) {
        console.error('Error en /api/sat/solicitar:', error);
        return Response.json({
            success: false,
            message: error.message || 'Error interno del servidor'
        }, { status: 500 });
    }
}
