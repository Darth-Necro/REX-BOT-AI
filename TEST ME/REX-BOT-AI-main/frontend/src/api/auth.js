/**
 * Auth API -- login request with response normalization.
 *
 * The backend returns { access_token, token_type, expires_in }.
 * We normalize to a plain { token, expiresIn } shape and reject
 * blank / missing tokens before they ever reach the store.
 */

import api from './client';

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
