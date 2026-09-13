/**
 * 核心版入口
 */

import { EchoMarkLedger, SAVE_FORMAT_VERSION } from './core/engine.js';
import { QuadStorage } from './core/storage.js';
import { captureRuntimeContext, deepFreeze, detectDebugSignals } from './core/utils.js';
import { destroyIdentity } from './core/keystore.js';
import { migrateV1ToV2, verifyV1Save } from './migrate.js';

const EchoMarkSys = Object.freeze({
    EchoMarkLedger,
    QuadStorage,
    SAVE_FORMAT_VERSION,
    // 宿主确实可能用到的少数辅助
    captureRuntimeContext,
    deepFreeze,
    detectDebugSignals,
    // 存档迁移与重置
    migrateV1ToV2,
    verifyV1Save,
    destroyIdentity,
});

function exposeGlobal(namespace) {
    if (typeof window === 'undefined') return;
    try {
        Object.defineProperty(window, 'EchoMarkSys', {
            value: namespace, writable: false, configurable: false, enumerable: true,
        });
    } catch {
        
    }
}

exposeGlobal(EchoMarkSys);

export {
    EchoMarkLedger, QuadStorage, SAVE_FORMAT_VERSION,
    captureRuntimeContext, deepFreeze, detectDebugSignals,
    migrateV1ToV2, verifyV1Save, destroyIdentity,
    EchoMarkSys,
};
export default EchoMarkSys;
