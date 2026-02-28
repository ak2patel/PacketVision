import { useState, useMemo } from 'react';
import { HiOutlineSearch, HiOutlineChevronLeft, HiOutlineChevronRight } from 'react-icons/hi';
import './PacketTable.css';

const ROWS_PER_PAGE = 25;

function PacketTable({ packets = [] }) {
  const [filter, setFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('all');
  const [sortField, setSortField] = useState('index');
  const [sortDir, setSortDir] = useState('asc');
  const [page, setPage] = useState(0);

  // Get unique protocols for dropdown
  const protocols = useMemo(() => {
    const set = new Set(packets.map(p => p.protocolName).filter(Boolean));
    return ['all', ...Array.from(set).sort()];
  }, [packets]);

  // Filter & sort
  const filtered = useMemo(() => {
    let result = packets;

    if (protocolFilter !== 'all') {
      result = result.filter(p => p.protocolName === protocolFilter);
    }

    if (filter) {
      const q = filter.toLowerCase();
      result = result.filter(p =>
        (p.srcIp && p.srcIp.includes(q)) ||
        (p.destIp && p.destIp.includes(q)) ||
        (p.sni && p.sni.toLowerCase().includes(q)) ||
        (p.appType && p.appType.toLowerCase().includes(q)) ||
        (p.protocolName && p.protocolName.toLowerCase().includes(q))
      );
    }

    result = [...result].sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (typeof aVal === 'string') aVal = aVal.toLowerCase();
      if (typeof bVal === 'string') bVal = bVal.toLowerCase();
      if (aVal < bVal) return sortDir === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [packets, filter, protocolFilter, sortField, sortDir]);

  const totalPages = Math.ceil(filtered.length / ROWS_PER_PAGE);
  const pageData = filtered.slice(page * ROWS_PER_PAGE, (page + 1) * ROWS_PER_PAGE);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const sortIcon = (field) => {
    if (sortField !== field) return '';
    return sortDir === 'asc' ? ' ↑' : ' ↓';
  };

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="card-header">
        <h3>📋 Packets ({packets.length})</h3>
      </div>

      {/* Filters */}
      <div className="table-filters">
        <div className="search-box">
          <HiOutlineSearch />
          <input
            className="input"
            placeholder="Filter by IP, domain, app..."
            value={filter}
            onChange={(e) => { setFilter(e.target.value); setPage(0); }}
          />
        </div>
        <select
          className="input"
          value={protocolFilter}
          onChange={(e) => { setProtocolFilter(e.target.value); setPage(0); }}
          style={{ width: 130 }}
        >
          {protocols.map(p => (
            <option key={p} value={p}>{p === 'all' ? 'All Protocols' : p}</option>
          ))}
        </select>
        <span className="filter-count">{filtered.length} results</span>
      </div>

      {/* Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th onClick={() => handleSort('index')} className="sortable">#{ sortIcon('index')}</th>
              <th onClick={() => handleSort('srcIp')} className="sortable">Source{sortIcon('srcIp')}</th>
              <th onClick={() => handleSort('destIp')} className="sortable">Destination{sortIcon('destIp')}</th>
              <th onClick={() => handleSort('protocolName')} className="sortable">Protocol{sortIcon('protocolName')}</th>
              <th onClick={() => handleSort('length')} className="sortable">Length{sortIcon('length')}</th>
              <th onClick={() => handleSort('sni')} className="sortable">Domain/SNI{sortIcon('sni')}</th>
              <th onClick={() => handleSort('appType')} className="sortable">App{sortIcon('appType')}</th>
              <th>Flags</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {pageData.map((pkt, i) => (
              <tr key={i} className={pkt.blocked ? 'row-blocked' : ''}>
                <td className="mono">{pkt.index}</td>
                <td className="mono">{pkt.srcIp}:{pkt.srcPort}</td>
                <td className="mono">{pkt.destIp}:{pkt.destPort}</td>
                <td><span className={`badge badge-${pkt.protocolName === 'TCP' ? 'blue' : pkt.protocolName === 'UDP' ? 'purple' : 'cyan'}`}>{pkt.protocolName}</span></td>
                <td className="mono">{pkt.length}</td>
                <td className="mono domain-cell">{pkt.sni || '—'}</td>
                <td>{pkt.appType !== 'Unknown' ? <span className="badge badge-green">{pkt.appType}</span> : <span className="text-muted">—</span>}</td>
                <td className="mono">{pkt.tcpFlags || '—'}</td>
                <td>{pkt.blocked ? <span className="badge badge-red">BLOCKED</span> : <span className="badge badge-green">OK</span>}</td>
              </tr>
            ))}
            {pageData.length === 0 && (
              <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>No packets match your filter</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="pagination">
          <button className="btn btn-sm btn-secondary" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
            <HiOutlineChevronLeft /> Prev
          </button>
          <span className="page-info">Page {page + 1} of {totalPages}</span>
          <button className="btn btn-sm btn-secondary" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}>
            Next <HiOutlineChevronRight />
          </button>
        </div>
      )}
    </div>
  );
}

export default PacketTable;
