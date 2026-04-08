/**
 * Agent API -- action registry and scope endpoints.
 */
import api from './client';

export async function getAgentActions() {
  const res = await api.get('/agent/actions');
  const d = res.data || {};
  return {
    actions: Array.isArray(d.actions) ? d.actions : [],
    count: d.count ?? 0,
  };
}

export async function getAgentActionsByDomain(domain) {
  const res = await api.get(`/agent/actions/${encodeURIComponent(domain)}`);
  const d = res.data || {};
  return {
    domain: d.domain || domain,
    actions: Array.isArray(d.actions) ? d.actions : [],
    count: d.count ?? 0,
  };
}

export async function getAgentScope() {
  const res = await api.get('/agent/scope');
  const d = res.data || {};
  return {
    securityKeywordsCount: d.security_keywords_count ?? 0,
    outOfScopePatternsCount: d.out_of_scope_patterns_count ?? 0,
    description: d.description || '',
  };
}
