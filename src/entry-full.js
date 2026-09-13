/**
 * 完整版入口（核心 + L1–L6 运行时防护）
 * ============================================================================
 * security.js 通过 import 显式依赖
 * core/engine.js 与 core/storage.js，由打包器决定求值顺序。
 */

import { EchoMarkLedger, SAVE_FORMAT_VERSION } from './core/engine.js';
import { QuadStorage } from './core/storage.js';
import { captureRuntimeContext, deepFreeze, detectDebugSignals, debuggerTrapDetect } from './core/utils.js';
import { destroyIdentity } from './core/keystore.js';
import { migrateV1ToV2, verifyV1Save } from './migrate.js';
import {
    sealZeroTrustSystem, quickSeal, maximumSeal, protectEngineInstance, getSecurityReport,
    SecurityLevel, SecurityEventBus, FingerprintEngine, AntiHookEngine, SealingSystem,
    SecureEngineProxy, DebugCountermeasures, StorageHardening,
    securityBus, fingerprintEngine, antiHookEngine, sealingSystem,
    debugCountermeasures, storageHardening,
} from './extend/security.js';

const EchoMarkSys = Object.freeze({
    EchoMarkLedger,
    QuadStorage,
    SAVE_FORMAT_VERSION,
    captureRuntimeContext,
    deepFreeze,
    detectDebugSignals,
    debuggerTrapDetect,
    migrateV1ToV2,
    verifyV1Save,
    destroyIdentity,
    // 安全扩展
    sealZeroTrustSystem,
    quickSeal,
    maximumSeal,
    protectEngineInstance,
    getSecurityReport,
    SecurityLevel,
    SecurityEventBus,
    FingerprintEngine,
    AntiHookEngine,
    SealingSystem,
    SecureEngineProxy,
    DebugCountermeasures,
    StorageHardening,
    securityBus,
    fingerprintEngine,
    antiHookEngine,
    sealingSystem,
    debugCountermeasures,
    storageHardening,
});

if (typeof window !== 'undefined') {
    try {
        Object.defineProperty(window, 'EchoMarkSys', {
            value: EchoMarkSys, writable: false, configurable: false, enumerable: true,
        });
    } catch {  }
}

export {
    EchoMarkLedger, QuadStorage, SAVE_FORMAT_VERSION,
    captureRuntimeContext, deepFreeze, detectDebugSignals, debuggerTrapDetect,
    migrateV1ToV2, verifyV1Save, destroyIdentity,
    sealZeroTrustSystem, quickSeal, maximumSeal, protectEngineInstance, getSecurityReport,
    SecurityLevel, SecurityEventBus, FingerprintEngine, AntiHookEngine, SealingSystem,
    SecureEngineProxy, DebugCountermeasures, StorageHardening,
    securityBus, fingerprintEngine, antiHookEngine, sealingSystem,
    debugCountermeasures, storageHardening,
    EchoMarkSys,
};
export default EchoMarkSys;
