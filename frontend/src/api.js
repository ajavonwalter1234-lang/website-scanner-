const TOKEN_KEY = 'safe-scanner-token';

export function getToken() {
  return window.sessionStorage.getItem(TOKEN_KEY) || '';
}

export function setToken(value) {
  const clean = value.trim();
  if (clean) window.sessionStorage.setItem(TOKEN_KEY, clean);
  else window.sessionStorage.removeItem(TOKEN_KEY);
}

async function request(path, options = {}) {
  const token = getToken();
  if (!token) throw new Error('Connect with an API token to continue.');
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${token}`);
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  let response;
  try {
    response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  } catch {
    throw new Error('The scanner API could not be reached. Check that the API and worker are running.');
  }
  if (response.status === 204) return null;
  let payload;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try { payload = await response.json(); } catch { payload = null; }
  } else {
    payload = await response.text().catch(() => '');
  }
  if (!response.ok) {
    const detail = payload?.detail || payload?.error || `Request failed (${response.status})`;
    throw new Error(typeof detail === 'string' ? detail : 'The request could not be completed.');
  }
  return payload;
}

export const api = {
  listScans: () => request('/api/scans'),
  getScan: (id) => request(`/api/scans/${encodeURIComponent(id)}`),
  getFindings: (id) => request(`/api/scans/${encodeURIComponent(id)}/findings`),
  createScan: (data) => request('/api/scans', { method: 'POST', body: JSON.stringify(data) }),
  deleteScan: (id) => request(`/api/scans/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  createChallenge: (hostname) => request('/api/ownership/challenges', { method: 'POST', body: JSON.stringify({ hostname }) }),
  verifyOwnership: (hostname) => request('/api/ownership/verify', { method: 'POST', body: JSON.stringify({ hostname }) }),
  ownershipStatus: (hostname) => request(`/api/ownership?hostname=${encodeURIComponent(hostname)}`),
  downloadReport: async (id, format) => {
    const token = getToken();
    const response = await fetch(`/api/scans/${encodeURIComponent(id)}/report?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
      credentials: 'same-origin',
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new Error(payload?.detail || `Could not download report (${response.status})`);
    }
    return response.blob();
  },
};
