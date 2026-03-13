import { SATService } from '../../../lib/sat-service-simple';

export const POST = async ({ request }: { request: Request }) => {
    const url = new URL(request.url);
    const idParam = url.searchParams.get('id');

    try {
        const body = await request.json().catch(() => ({}));
        const id = body.id || idParam;
        const { cerBase64, keyBase64, password } = body;

        if (!id) {
            return new Response(JSON.stringify({ success: false, message: 'ID de solicitud requerido.' }), { status: 400 });
        }

        let creds = (global as any).lastSatCreds;

        // Si se proporcionan credenciales en el cuerpo (base64 o data url), las procesamos
        if (cerBase64 && keyBase64 && password) {
            try {
                creds = await SATService.parseCredentials(cerBase64, keyBase64, password);
                (global as any).lastSatCreds = creds; // Actualizar caché
            } catch (e: any) {
                console.error('Error al procesar credenciales enviadas:', e);
            }
        }

        if (!creds) {
            throw new Error('Credenciales no encontradas en sesión local y no proporcionadas en la solicitud. Reintente la solicitud.');
        }

        const token = await SATService.authenticate(creds);
        const status = await SATService.verificarSolicitud(creds, token, id);

        const isReady = (status.estado == '3' || status.estado == 'ready') && status.paqueteId;
        const isEmpty = status.estado == '3' && status.codigo == '5004';
        
        let finalStatus = 'pending';
        if (isReady) finalStatus = 'ready';
        else if (isEmpty) finalStatus = 'empty';

        return new Response(JSON.stringify({ 
            success: true, 
            status: finalStatus,
            packageId: status.paqueteId,
            message: isEmpty ? 'No se encontraron comprobantes para este periodo.' : undefined
        }));
    } catch (error: any) {
        return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }
};
