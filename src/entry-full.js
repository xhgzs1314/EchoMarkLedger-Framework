import { EchoMarkLedger } from './core/engine.js';
import { QuadStorage } from './core/storage.js';
import { 
  sha256, sha256Sync, generateNonce, fisherYatesShuffle,
  deriveRandomFromSeed, captureRuntimeContext, deepEqual,
  serializeForHash, antiDebugDetection, deepFreeze,
  deriveDynamicSalt, deriveOffset, safeStringify, computeSlotPosition
} from './core/utils.js';
import {
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
  storageHardening
} from './extend/security.js';
const coreExports = {
  EchoMarkLedger,
  QuadStorage,
  sha256,
  sha256Sync,
  generateNonce,
  fisherYatesShuffle,
  deriveRandomFromSeed,
  captureRuntimeContext,
  deepEqual,
  serializeForHash,
  antiDebugDetection,
  deepFreeze,
  deriveDynamicSalt,
  deriveOffset,
  safeStringify,
  computeSlotPosition
};
const securityExports = {
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
  storageHardening
};
const allExports = {
  ...coreExports,
  ...securityExports,
  EchoMarkLedger,
  QuadStorage
};
if (typeof window !== 'undefined') {
  window.EchoMarkLedger = EchoMarkLedger;
  window.QuadStorage = QuadStorage;
  window.sha256 = sha256;
  window.sha256Sync = sha256Sync;
  window.generateNonce = generateNonce;
  window.fisherYatesShuffle = fisherYatesShuffle;
  window.deriveRandomFromSeed = deriveRandomFromSeed;
  window.captureRuntimeContext = captureRuntimeContext;
  window.deepEqual = deepEqual;
  window.serializeForHash = serializeForHash;
  window.antiDebugDetection = antiDebugDetection;
  window.deepFreeze = deepFreeze;
  window.deriveDynamicSalt = deriveDynamicSalt;
  window.deriveOffset = deriveOffset;
  window.safeStringify = safeStringify;
  window.computeSlotPosition = computeSlotPosition;
  window.sealZeroTrustSystem = sealZeroTrustSystem;
  window.quickSeal = quickSeal;
  window.maximumSeal = maximumSeal;
  window.protectEngineInstance = protectEngineInstance;
  window.getSecurityReport = getSecurityReport;
  window.SecurityLevel = SecurityLevel;
  window.SecurityEventBus = SecurityEventBus;
  window.FingerprintEngine = FingerprintEngine;
  window.AntiHookEngine = AntiHookEngine;
  window.SealingSystem = SealingSystem;
  window.SecureEngineProxy = SecureEngineProxy;
  window.DebugCountermeasures = DebugCountermeasures;
  window.StorageHardening = StorageHardening;
  window.securityBus = securityBus;
  window.fingerprintEngine = fingerprintEngine;
  window.antiHookEngine = antiHookEngine;
  window.sealingSystem = sealingSystem;
  window.debugCountermeasures = debugCountermeasures;
  window.storageHardening = storageHardening;
  window.EchoMarkSys = allExports;
}
export {
  EchoMarkLedger,
  QuadStorage,
  sha256,
  sha256Sync,
  generateNonce,
  fisherYatesShuffle,
  deriveRandomFromSeed,
  captureRuntimeContext,
  deepEqual,
  serializeForHash,
  antiDebugDetection,
  deepFreeze,
  deriveDynamicSalt,
  deriveOffset,
  safeStringify,
  computeSlotPosition,
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
  storageHardening
};