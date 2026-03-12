import { SATService } from '../../../lib/sat-service';

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

        // Si se proporcionan credenciales en el cuerpo (base64), las procesamos
        if (cerBase64 && keyBase64 && password) {
            try {
                const cleanCer = cerBase64.includes(',') ? cerBase64.split(',')[1] : cerBase64;
                const cleanKey = keyBase64.includes(',') ? keyBase64.split(',')[1] : keyBase64;
                
                const cerBuffer = Buffer.from(cleanCer, 'base64');
                const keyBuffer = Buffer.from(cleanKey, 'base64');
                
                creds = await SATService.parseCredentials(cerBuffer, keyBuffer, password);
                (global as any).lastSatCreds = creds; // Actualizar caché
            } catch (e: any) {
                console.error('Error al procesar credenciales enviadas:', e);
            }
        }

        if (!creds) {
            throw new Error('Credenciales no encontradas en sesión local y no proporcionadas en la solicitud. Reintente la solicitud.');
        }

        const token = await SATService.getAccessToken(creds);
        const status = await SATService.verificarSolicitud(creds, token, id);

        return new Response(JSON.stringify({ 
            success: true, 
            status: status.estado === '3' ? 'ready' : 'pending', // 3 = Terminado
            packageId: status.paqueteId 
        }));
    } catch (error: any) {
        return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }
};

