import { useEffect, useState } from 'react';
import { HiOutlineShieldCheck, HiOutlinePlus, HiOutlineTrash, HiOutlinePencil, HiOutlineX } from 'react-icons/hi';
import { getRules, createRule, updateRule, deleteRule } from '../services/api';
import './Rules.css';

const RULE_TYPES = [
  { value: 'ip', label: 'IP Address', placeholder: 'e.g. 192.168.1.50' },
  { value: 'domain', label: 'Domain', placeholder: 'e.g. facebook.com' },
  { value: 'app', label: 'Application', placeholder: 'e.g. YouTube' },
];

function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [form, setForm] = useState({ type: 'ip', value: '', description: '' });
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await getRules();
      setRules(res.data);
    } catch (err) {
      console.error('Failed to fetch rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setForm({ type: 'ip', value: '', description: '' });
    setEditingId(null);
    setShowForm(false);
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.value.trim()) {
      setError('Value is required');
      return;
    }

    setSaving(true);
    setError('');

    try {
      if (editingId) {
        const res = await updateRule(editingId, form);
        setRules(prev => prev.map(r => r._id === editingId ? res.data : r));
      } else {
        const res = await createRule(form);
        setRules(prev => [res.data, ...prev]);
      }
      resetForm();
    } catch (err) {
      const msg = err.response?.data?.error || 'Failed to save rule';
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleEdit = (rule) => {
    setForm({ type: rule.type, value: rule.value, description: rule.description || '' });
    setEditingId(rule._id);
    setShowForm(true);
    setError('');
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this rule?')) return;
    try {
      await deleteRule(id);
      setRules(prev => prev.filter(r => r._id !== id));
    } catch (err) {
      console.error('Failed to delete:', err);
    }
  };

  const handleToggle = async (rule) => {
    try {
      const res = await updateRule(rule._id, { ...rule, active: !rule.active });
      setRules(prev => prev.map(r => r._id === rule._id ? res.data : r));
    } catch (err) {
      console.error('Failed to toggle:', err);
    }
  };

  const currentType = RULE_TYPES.find(t => t.value === form.type);

  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Block Rules</h2>
        <p>Manage rules to filter traffic by IP, domain, or application</p>
      </div>

      {/* Add Rule Button */}
      {!showForm && (
        <button className="btn btn-primary" onClick={() => setShowForm(true)} style={{ marginBottom: 20 }}>
          <HiOutlinePlus /> Add Rule
        </button>
      )}

      {/* Add / Edit Form */}
      {showForm && (
        <div className="card rule-form" style={{ marginBottom: 20 }}>
          <div className="card-header">
            <h3>{editingId ? 'Edit Rule' : 'Add New Rule'}</h3>
            <button className="btn btn-sm btn-secondary" onClick={resetForm}>
              <HiOutlineX /> Cancel
            </button>
          </div>

          <form onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Rule Type</label>
                <select
                  className="input"
                  value={form.type}
                  onChange={(e) => setForm({ ...form, type: e.target.value })}
                >
                  {RULE_TYPES.map(t => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>

              <div className="form-group" style={{ flex: 2 }}>
                <label>Value</label>
                <input
                  className="input"
                  placeholder={currentType?.placeholder}
                  value={form.value}
                  onChange={(e) => setForm({ ...form, value: e.target.value })}
                />
              </div>

              <div className="form-group" style={{ flex: 2 }}>
                <label>Description (optional)</label>
                <input
                  className="input"
                  placeholder="Why block this?"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </div>
            </div>

            {error && <div className="form-error">{error}</div>}

            <div style={{ marginTop: 16 }}>
              <button className="btn btn-primary" type="submit" disabled={saving}>
                {saving ? 'Saving...' : editingId ? 'Update Rule' : 'Create Rule'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Rules List */}
      {loading ? (
        <div className="stats-grid">
          {[1, 2, 3].map(i => <div key={i} className="card"><div className="skeleton" style={{ height: 50 }} /></div>)}
        </div>
      ) : rules.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon"><HiOutlineShieldCheck /></div>
          <h3>No Rules Configured</h3>
          <p>Add block rules to filter specific IPs, domains, or applications from your analysis results.</p>
        </div>
      ) : (
        <div className="rules-list">
          {rules.map((rule) => (
            <div key={rule._id} className={`card rule-item ${!rule.active ? 'rule-disabled' : ''}`}>
              <div className="rule-info">
                <span className={`badge badge-${rule.type === 'ip' ? 'orange' : rule.type === 'domain' ? 'blue' : 'purple'}`}>
                  {rule.type.toUpperCase()}
                </span>
                <span className="rule-value">{rule.value}</span>
                {rule.description && <span className="rule-desc">{rule.description}</span>}
              </div>

              <div className="rule-actions">
                {/* Toggle Switch */}
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={rule.active}
                    onChange={() => handleToggle(rule)}
                  />
                  <span className="toggle-slider"></span>
                </label>

                <button className="btn btn-sm btn-secondary" onClick={() => handleEdit(rule)}>
                  <HiOutlinePencil />
                </button>
                <button className="btn btn-sm btn-danger" onClick={() => handleDelete(rule._id)}>
                  <HiOutlineTrash />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Info Card */}
      <div className="card" style={{ marginTop: 24, background: 'var(--bg-card)' }}>
        <h3 style={{ fontSize: '0.95rem', marginBottom: 8 }}>ℹ️ How Rules Work</h3>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', lineHeight: 1.7 }}>
          Block rules are applied during analysis. When a packet matches a rule, it is marked as <strong>blocked</strong>
          and excluded from the filtered export. Rules can match by:
        </p>
        <ul style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', lineHeight: 1.8, paddingLeft: 20, marginTop: 8 }}>
          <li><strong>IP Address</strong> — matches source or destination IP</li>
          <li><strong>Domain</strong> — matches SNI or HTTP Host (partial match)</li>
          <li><strong>Application</strong> — matches classified app type (e.g. YouTube, Facebook)</li>
        </ul>
      </div>
    </div>
  );
}

export default Rules;
