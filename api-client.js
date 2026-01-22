// Configuration de l'API Backend
// En développement: http://localhost:3001
// En production: https://votre-backend.com

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';

// Client API pour UCO AND CO
const api = {
  // ===== AUTH =====
  loginAdmin: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/admin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  },

  loginCollector: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/collector`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  },

  loginOperator: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/operator`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  },

  loginRestaurant: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/restaurant`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    return response.json();
  },

  // ===== COLLECTORS =====
  registerCollector: async (data) => {
    const response = await fetch(`${API_BASE_URL}/collectors/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  getPendingCollectors: async () => {
    const response = await fetch(`${API_BASE_URL}/collectors/pending`);
    return response.json();
  },

  getApprovedCollectors: async () => {
    const response = await fetch(`${API_BASE_URL}/collectors/approved`);
    return response.json();
  },

  approveCollector: async (id) => {
    const response = await fetch(`${API_BASE_URL}/collectors/${id}/approve`, {
      method: 'POST'
    });
    return response.json();
  },

  rejectCollector: async (id) => {
    const response = await fetch(`${API_BASE_URL}/collectors/${id}/reject`, {
      method: 'POST'
    });
    return response.json();
  },

  deleteCollector: async (id) => {
    const response = await fetch(`${API_BASE_URL}/collectors/${id}`, {
      method: 'DELETE'
    });
    return response.json();
  },

  // ===== OPERATORS =====
  registerOperator: async (data) => {
    const response = await fetch(`${API_BASE_URL}/operators/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  getPendingOperators: async () => {
    const response = await fetch(`${API_BASE_URL}/operators/pending`);
    return response.json();
  },

  getApprovedOperators: async () => {
    const response = await fetch(`${API_BASE_URL}/operators/approved`);
    return response.json();
  },

  approveOperator: async (id) => {
    const response = await fetch(`${API_BASE_URL}/operators/${id}/approve`, {
      method: 'POST'
    });
    return response.json();
  },

  rejectOperator: async (id) => {
    const response = await fetch(`${API_BASE_URL}/operators/${id}/reject`, {
      method: 'POST'
    });
    return response.json();
  },

  deleteOperator: async (id) => {
    const response = await fetch(`${API_BASE_URL}/operators/${id}`, {
      method: 'DELETE'
    });
    return response.json();
  },

  // ===== RESTAURANTS =====
  registerRestaurant: async (data) => {
    const response = await fetch(`${API_BASE_URL}/restaurants/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  getPendingRestaurants: async () => {
    const response = await fetch(`${API_BASE_URL}/restaurants/pending`);
    return response.json();
  },

  getRestaurants: async () => {
    const response = await fetch(`${API_BASE_URL}/restaurants`);
    return response.json();
  },

  getRestaurantByQR: async (qrCode) => {
    const response = await fetch(`${API_BASE_URL}/restaurants/qr/${encodeURIComponent(qrCode)}`);
    if (!response.ok) return null;
    return response.json();
  },

  approveRestaurant: async (id, data) => {
    const response = await fetch(`${API_BASE_URL}/restaurants/${id}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  rejectRestaurant: async (id) => {
    const response = await fetch(`${API_BASE_URL}/restaurants/${id}/reject`, {
      method: 'POST'
    });
    return response.json();
  },

  addRestaurant: async (data) => {
    const response = await fetch(`${API_BASE_URL}/restaurants`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  updateRestaurant: async (id, data) => {
    const response = await fetch(`${API_BASE_URL}/restaurants/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  deleteRestaurant: async (id) => {
    const response = await fetch(`${API_BASE_URL}/restaurants/${id}`, {
      method: 'DELETE'
    });
    return response.json();
  },

  // ===== COLLECTIONS =====
  createCollection: async (data) => {
    const response = await fetch(`${API_BASE_URL}/collections`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  getCollections: async () => {
    const response = await fetch(`${API_BASE_URL}/collections`);
    return response.json();
  },

  getCollectionsByCollector: async (collectorId) => {
    const response = await fetch(`${API_BASE_URL}/collections/collector/${collectorId}`);
    return response.json();
  },

  getCollection: async (id) => {
    const response = await fetch(`${API_BASE_URL}/collections/${encodeURIComponent(id)}`);
    return response.json();
  },

  // ===== TOURNEES =====
  createTournee: async (data) => {
    const response = await fetch(`${API_BASE_URL}/tournees`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  getTournee: async (collectorId, date) => {
    const response = await fetch(`${API_BASE_URL}/tournees/${collectorId}/${date}`);
    if (!response.ok) return null;
    return response.json();
  },

  updateTournee: async (tourneeId, data) => {
    const response = await fetch(`${API_BASE_URL}/tournees/${encodeURIComponent(tourneeId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    return response.json();
  },

  // ===== SETTINGS =====
  getSettings: async () => {
    const response = await fetch(`${API_BASE_URL}/settings`);
    return response.json();
  },

  saveSettings: async (settings) => {
    const response = await fetch(`${API_BASE_URL}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    return response.json();
  },

  // ===== STATISTICS =====
  getStatistics: async () => {
    const response = await fetch(`${API_BASE_URL}/statistics`);
    return response.json();
  },

  // ===== HEALTH CHECK =====
  healthCheck: async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }
};

export default api;
export { API_BASE_URL };
