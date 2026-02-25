import { HiOutlineShieldCheck } from 'react-icons/hi';

function Rules() {
  return (
    <div className="animate-in">
      <div className="page-header">
        <h2>Block Rules</h2>
        <p>Manage rules to filter traffic by IP, domain, or application</p>
      </div>

      <div className="empty-state">
        <div className="empty-icon"><HiOutlineShieldCheck /></div>
        <h3>No Rules Configured</h3>
        <p>Add block rules to filter specific IPs, domains, or applications from your analysis results.</p>
      </div>
    </div>
  );
}

export default Rules;
