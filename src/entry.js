import { EchoMarkLedger } from './core/engine.js';
import { QuadStorage } from './core/storage.js';
import { 
  sha256, sha256Sync, generateNonce, fisherYatesShuffle,
  deriveRandomFromSeed, captureRuntimeContext, deepEqual,
  serializeForHash, antiDebugDetection, deepFreeze,
  deriveDynamicSalt, deriveOffset, safeStringify, computeSlotPosition
} from './core/utils.js';
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
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
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
}