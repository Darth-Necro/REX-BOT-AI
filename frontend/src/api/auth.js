/**
 * Auth API -- login request with response normalization.
 *
 * The backend returns { access_token, token_type, expires_in }.
 * We normalize to a plain { token, expiresIn } shape and reject
 * blank / missing tokens before they ever reach the store.
 */

import api from './client';

/**
 * Fetch the current auth state from the backend.
 * @returns {Promise<string>} 'setup_required' or 'active'
 */
export async function getAuthState() {
  const res = await api.get('/auth/auth-state');
  return res.data?.state || 'active';
}

/**
 * Set the initial admin password during first-run setup.
 * @param {string} newPassword  The new admin password.
 * @returns {Promise<{ token: string, expiresIn: number }>}
 */
export async function setup(newPassword) {
  if (!newPassword || typeof newPassword !== 'string' || newPassword.trim().length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  const res = await api.post('/auth/setup', { new_password: newPassword });
  const data = res.data;
  const token = data?.access_token || data?.token || '';

  if (!token || typeof token !== 'string' || token.trim() === '') {
    throw new Error('Server returned an empty or invalid token');
  }

  return {
    token,
    expiresIn: data?.expires_in ?? 14400,
  };
}

/**
 * Authenticate with the backend.
 * @param {string} password  Plain-text password.
 * @returns {Promise<{ token: string, expiresIn: number }>}
 */
export async function login(password) {
  if (!password || typeof password !== 'string' || password.trim() === '') {
    throw new Error('Password is required');
  }

  const res = await api.post('/auth/login', { password });
  const data = res.data;

  // Backend may return `access_token` or `token` depending on version
  const token = data?.access_token || data?.token || '';

  if (!token || typeof token !== 'string' || token.trim() === '') {
    throw new Error('Server returned an empty or invalid token');
  }

  return {
    token,
    expiresIn: data?.expires_in ?? 14400,
  };
}
