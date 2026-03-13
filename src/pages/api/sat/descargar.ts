import { SATService } from '../../../lib/sat-service-simple';

export const POST = async ({ request }: { request: Request }) => {
    try {
        const body = await request.json();
        const { packageId, cerBase64, keyBase64, password } = body;

        if (!packageId) {
            return new Response(JSON.stringify({ success: false, message: 'ID de paquete requerido.' }), { status: 400 });
        }

        if (!cerBase64 || !keyBase64 || !password) {
            return new Response(JSON.stringify({ success: false, message: 'Credenciales requeridas (cerBase64, keyBase64, password).' }), { status: 400 });
        }

        const creds = await SATService.parseCredentials(cerBase64, keyBase64, password);
        const token = await SATService.authenticate(creds);
        const result = await SATService.descargarPaquete(creds, token, packageId);

        if (!result.xmls || result.xmls.length === 0) throw new Error('El SAT no devolvió el contenido del paquete (puede estar aún procesándose internamente).');

        // Retornar los XMLs directamente sin procesar ZIP
        return new Response(JSON.stringify({ 
            success: true, 
            count: result.xmls.length,
            xmls: result.xmls 
        }));
    } catch (error: any) {
        console.error('Error en API Descargar:', error);
        return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }
};
