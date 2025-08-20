import si from 'systeminformation';
import crypto from 'crypto';

export async function getHWID(): Promise<string> {
    const system = await si.system();
    const base = `${system.uuid}-${system.serial}-${system.model}`;
    return crypto.createHash('sha256').update(base).digest('hex');
}
