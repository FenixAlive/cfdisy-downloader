import { SATService } from '../../../lib/sat-service';
import AdmZip from 'adm-zip';

export const POST = async ({ request }: { request: Request }) => {
    try {
        const body = await request.json();
        const { packageId, cerBase64, keyBase64, password } = body;

        if (!packageId) {
            return new Response(JSON.stringify({ success: false, message: 'ID de paquete requerido.' }), { status: 400 });
        }

        let creds = (global as any).lastSatCreds;
        
        // Si el cliente manda credenciales (base64 o data url), las usamos
        if (cerBase64 && keyBase64 && password) {
            creds = await SATService.parseCredentials(cerBase64, keyBase64, password);
            (global as any).lastSatCreds = creds;
        }

        if (!creds) throw new Error('Credenciales no encontradas. Reintente la solicitud desde el inicio.');

        const token = await SATService.getAccessToken(creds);
        const base64Zip = await SATService.descargarPaquete(creds, token, packageId);

        if (!base64Zip) throw new Error('El SAT no devolvió el contenido del paquete (puede estar aún procesándose internamente).');

        const zipBuffer = Buffer.from(base64Zip, 'base64');
        const zip = new AdmZip(zipBuffer);
        const zipEntries = zip.getEntries();

        const xmls = zipEntries
            .filter((entry: any) => entry.entryName.endsWith('.xml'))
            .map((entry: any) => ({
                name: entry.entryName,
                content: entry.getData().toString('utf8')
            }));

        return new Response(JSON.stringify({ 
            success: true, 
            count: xmls.length,
            xmls: xmls 
        }));
    } catch (error: any) {
        console.error('Error en API Descargar:', error);
        return new Response(JSON.stringify({ success: false, message: error.message }), { status: 500 });
    }
};
