/** Routes: workspace chooser, approval console (/app/*), publisher portal (/publisher/*). */
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { ActivityPage } from './pages/app/ActivityPage';
import { Devices } from './pages/app/Devices';
import { Governance } from './pages/app/Governance';
import { Overview } from './pages/app/Overview';
import { Releases } from './pages/app/Releases';
import { Scenarios } from './pages/app/Scenarios';
import { Landing } from './pages/Landing';
import { PubIdentity } from './pages/publisher/PubIdentity';
import { PubReleases } from './pages/publisher/PubReleases';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/app" element={<AppShell workspace="approver" />}>
          <Route index element={<Overview />} />
          <Route path="releases" element={<Releases />} />
          <Route path="devices" element={<Devices />} />
          <Route path="activity" element={<ActivityPage />} />
          <Route path="governance" element={<Governance />} />
          <Route path="scenarios" element={<Scenarios />} />
        </Route>
        <Route path="/publisher" element={<AppShell workspace="publisher" />}>
          <Route index element={<PubReleases />} />
          <Route path="new" element={<PubReleases openForm />} />
          <Route path="identity" element={<PubIdentity />} />
        </Route>
        {/* old entry points */}
        <Route path="/approve" element={<Navigate to="/app/releases" replace />} />
        <Route path="/publish" element={<Navigate to="/publisher" replace />} />
        <Route path="/story" element={<Navigate to="/app/scenarios" replace />} />
        <Route path="/demo" element={<Navigate to="/app/scenarios" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
