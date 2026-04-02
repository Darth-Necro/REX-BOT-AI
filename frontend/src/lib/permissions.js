/**
 * permissions.js — map backend capabilities objects to boolean UI flags.
 *
 * Every backend module may return a `capabilities` object describing which
 * mutations are supported. This module provides safe accessor helpers so
 * components never have to null-check deep paths.
 *
 * Rule: if the backend did not report a capability, the UI MUST assume it
 * is unavailable (deny-by-default).
 */

/**
 * Safely check whether a capability flag is explicitly true.
 * @param {Object|null|undefined} caps  Capabilities object from backend.
 * @param {string} key  Capability name.
 * @returns {boolean}
 */
export function can(caps, key) {
  if (!caps || typeof caps !== 'object') return false;
  return caps[key] === true;
}

/**
 * Map firewall capabilities.
 * @param {Object} caps
 * @returns {{ canCreate: boolean, canDelete: boolean, canPanic: boolean, canRestore: boolean }}
 */
export function firewallPermissions(caps) {
  return {
    canCreate: can(caps, 'create_rule'),
    canDelete: can(caps, 'delete_rule'),
    canPanic: can(caps, 'panic'),
    canRestore: can(caps, 'panic_restore'),
  };
}

/**
 * Map knowledge base capabilities.
 * @param {Object} caps
 * @returns {{ canEdit: boolean, canRevert: boolean }}
 */
export function kbPermissions(caps) {
  return {
    canEdit: can(caps, 'edit'),
    canRevert: can(caps, 'revert'),
  };
}

/**
 * Map scheduler capabilities.
 * @param {Object} caps
 * @returns {{ canUpdateSchedule: boolean, canTogglePower: boolean }}
 */
export function schedulerPermissions(caps) {
  return {
    canUpdateSchedule: can(caps, 'update_schedule'),
    canTogglePower: can(caps, 'toggle_power'),
  };
}

/**
 * Map plugin capabilities.
 * @param {Object} caps
 * @returns {{ canInstall: boolean, canRemove: boolean }}
 */
export function pluginPermissions(caps) {
  return {
    canInstall: can(caps, 'install'),
    canRemove: can(caps, 'remove'),
  };
}

/**
 * Map notification capabilities.
 * @param {Object} caps
 * @returns {{ canSave: boolean, canTest: boolean }}
 */
export function notificationPermissions(caps) {
  return {
    canSave: can(caps, 'save'),
    canTest: can(caps, 'test'),
  };
}

/**
 * Map privacy capabilities.
 * @param {Object} caps
 * @returns {{ canAudit: boolean }}
 */
export function privacyPermissions(caps) {
  return {
    canAudit: can(caps, 'audit'),
  };
}
