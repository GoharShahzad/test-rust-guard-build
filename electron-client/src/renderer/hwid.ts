import { getNativeHWID } from '../main-secure/native';

export function getHWID(): string {
    return getNativeHWID() ?? 'UNKNOWN_HWID';
}
