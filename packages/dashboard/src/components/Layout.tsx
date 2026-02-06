import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>AI Authority</h1>
          <span className="subtitle">Reviewer Dashboard</span>
        </div>
        <nav className="sidebar-nav">
          <div className="nav-section">
            <span className="nav-section-title">Overview</span>
            <Link to="/" className={`nav-item ${isActive('/') ? 'active' : ''}`}>
              <span className="nav-icon">📊</span>
              Dashboard
            </Link>
            <Link to="/agents" className={`nav-item ${isActive('/agents') ? 'active' : ''}`}>
              <span className="nav-icon">🤖</span>
              Agents
            </Link>
          </div>
          <div className="nav-section">
            <span className="nav-section-title">Detection</span>
            <Link to="/cases" className={`nav-item ${isActive('/cases') ? 'active' : ''}`}>
              <span className="nav-icon">📋</span>
              Cases
            </Link>
            <Link to="/forensics" className={`nav-item ${isActive('/forensics') ? 'active' : ''}`}>
              <span className="nav-icon">🔬</span>
              Forensics
            </Link>
          </div>
          <div className="nav-section">
            <span className="nav-section-title">Actions</span>
            <Link to="/interventions" className={`nav-item ${isActive('/interventions') ? 'active' : ''}`}>
              <span className="nav-icon">⚡</span>
              Interventions
            </Link>
            <Link to="/appeals" className={`nav-item ${isActive('/appeals') ? 'active' : ''}`}>
              <span className="nav-icon">⚖️</span>
              Appeals
            </Link>
          </div>
          <div className="nav-section">
            <span className="nav-section-title">Compliance</span>
            <Link to="/audits" className={`nav-item ${isActive('/audits') ? 'active' : ''}`}>
              <span className="nav-icon">📝</span>
              Audits
            </Link>
            <Link to="/fairness" className={`nav-item ${isActive('/fairness') ? 'active' : ''}`}>
              <span className="nav-icon">⚖️</span>
              Fairness
            </Link>
          </div>
        </nav>
        <div className="sidebar-footer">
          <div className="user-info">
            <div className="user-avatar">R</div>
            <div className="user-details">
              <span className="user-name">Reviewer</span>
              <span className="user-role">Senior Reviewer</span>
            </div>
          </div>
        </div>
      </aside>
      <main className="main-content">
        {children}
      </main>
    </div>
  );
};
