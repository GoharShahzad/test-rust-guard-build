import { contextBridge } from 'electron';
import * as license from './main-secure/license-core';

contextBridge.exposeInMainWorld('license', {
    activate: license.activate,
    heartbeat: license.heartbeat,
    deactivate: license.deactivate,
    isValid: license.isValid
});
