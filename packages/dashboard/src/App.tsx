import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Cases } from './pages/Cases';
import { CaseDetail } from './pages/CaseDetail';
import { Interventions } from './pages/Interventions';
import { Appeals } from './pages/Appeals';
import { Agents } from './pages/Agents';
import { Forensics } from './pages/Forensics';
import { Audits } from './pages/Audits';
import { Fairness } from './pages/Fairness';

export const App: React.FC = () => {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/cases" element={<Cases />} />
        <Route path="/cases/:caseId" element={<CaseDetail />} />
        <Route path="/interventions" element={<Interventions />} />
        <Route path="/appeals" element={<Appeals />} />
        <Route path="/forensics" element={<Forensics />} />
        <Route path="/audits" element={<Audits />} />
        <Route path="/fairness" element={<Fairness />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
};
