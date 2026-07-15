/**
 * Re-exports the canonical `E2EError` class from `E2EEncryptionService`
 * so the extracted Path-B sub-modules can throw without taking a hard
 * dependency on the orchestrator's full export surface.
 *
 * Once `E2EEncryptionService` is itself refactored down to a thin
 * orchestrator (Path B Phase C), the class definition can move into
 * this file and the orchestrator imports here instead. For now this is
 * a one-line shim so the extraction is non-invasive.
 */

export { E2EError } from '../E2EEncryptionService.types';
