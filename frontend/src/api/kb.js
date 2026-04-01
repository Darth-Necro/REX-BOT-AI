/**
 * Knowledge Base API module.
 * Wraps /api/knowledge endpoints for REX's editable knowledge base.
 */
import api from './client';

/**
 * GET /api/knowledge
 * @returns {Promise<{ content: string, version: number, updatedAt: string|null, capabilities: Object }>}
 */
export async function getKnowledgeBase() {
  const res = await api.get('/knowledge');
  const data = res.data ?? {};
  return {
    content: typeof data.content === 'string' ? data.content : '',
    version: Number.isFinite(data.version) ? data.version : 0,
    updatedAt: data.updated_at ?? data.updatedAt ?? null,
    capabilities: data.capabilities ?? {},
  };
}

/**
 * GET /api/knowledge/history
 * @param {Object} [params]  Optional query params (limit, offset).
 * @returns {Promise<{ history: Array }>}
 */
export async function getKnowledgeBaseHistory(params = {}) {
  const res = await api.get('/knowledge/history', { params });
  const data = res.data ?? {};
  const list = data.history ?? data ?? [];
  return { history: Array.isArray(list) ? list : [] };
}

/**
 * PUT /api/knowledge
 * @param {string} content  New knowledge base content.
 * @returns {Promise<Object>} Updated record.
 */
export async function updateKnowledgeBase(content) {
  if (typeof content !== 'string') throw new Error('Content must be a string');
  const res = await api.put('/knowledge', { content });
  return res.data;
}

/**
 * POST /api/knowledge/revert
 * @param {number} version  Version number to revert to.
 * @returns {Promise<Object>}
 */
export async function revertKnowledgeBase(version) {
  if (!Number.isFinite(version)) throw new Error('Version must be a number');
  const res = await api.post('/knowledge/revert', { version });
  return res.data;
}
