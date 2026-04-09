/**
 * Knowledge Base API module.
 * Wraps /api/knowledge endpoints for REX's editable knowledge base.
 */
import api from './client';

/**
 * GET /api/knowledge-base
 * @returns {Promise<{ content: string, version: number, updatedAt: string|null, capabilities: Object }>}
 */
export async function getKnowledgeBase() {
  const res = await api.get('/knowledge-base');
  const data = res.data ?? {};
  return {
    content: typeof data.content === 'string' ? data.content : '',
    version: Number.isFinite(data.version) ? data.version : 0,
    updatedAt: data.updated_at ?? data.updatedAt ?? null,
    capabilities: data.capabilities ?? {},
  };
}

/**
 * GET /api/knowledge-base/history
 * @param {Object} [params]  Optional query params (limit, offset).
 * @returns {Promise<{ history: Array }>}
 */
export async function getKnowledgeBaseHistory(params = {}) {
  const res = await api.get('/knowledge-base/history', { params });
  const data = res.data ?? {};
  const list = data.commits ?? data.history ?? data ?? [];
  return { history: Array.isArray(list) ? list : [] };
}

/**
 * PUT /api/knowledge-base
 * @param {string} content  New knowledge base content.
 * @returns {Promise<Object>} Updated record.
 */
export async function updateKnowledgeBase(content) {
  if (typeof content !== 'string') throw new Error('Content must be a string');
  const res = await api.put('/knowledge-base', { content });
  return res.data;
}

/**
 * POST /api/knowledge-base/revert/{commitHash}
 * @param {string} commitHash  Git commit hash to revert to.
 * @returns {Promise<Object>}
 */
export async function revertKnowledgeBase(commitHash) {
  if (!commitHash) throw new Error('Commit hash is required');
  const res = await api.post(`/knowledge-base/revert/${encodeURIComponent(commitHash)}`);
  return res.data;
}
