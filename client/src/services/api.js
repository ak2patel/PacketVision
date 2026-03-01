import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Analysis endpoints
export const uploadPcap = (file, onProgress) => {
  const formData = new FormData();
  formData.append('pcap', file);

  return api.post('/analysis/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress) {
        onProgress(Math.round((e.loaded * 100) / e.total));
      }
    },
  });
};

export const getAnalysis = (id) => api.get(`/analysis/${id}`);
export const getAnalyses = () => api.get('/analysis');
export const exportFilteredPcap = (id) => {
  window.open(`${API_BASE}/analysis/${id}/export`, '_blank');
};

// Rules endpoints
export const getRules = () => api.get('/rules');
export const createRule = (rule) => api.post('/rules', rule);
export const updateRule = (id, rule) => api.put(`/rules/${id}`, rule);
export const deleteRule = (id) => api.delete(`/rules/${id}`);

export default api;
