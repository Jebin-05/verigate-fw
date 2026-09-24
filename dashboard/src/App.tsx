/** Routes: the front door, the two portals, and the demonstration drills. */
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import { Approver } from './pages/Approver';
import { Drills } from './pages/Drills';
import { Landing } from './pages/Landing';
import { Publisher } from './pages/Publisher';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route element={<Shell role="Publisher portal" />}>
          <Route path="/publish" element={<Publisher />} />
        </Route>
        <Route element={<Shell role="Approval console" />}>
          <Route path="/approve" element={<Approver />} />
        </Route>
        <Route element={<Shell role="Security drills" />}>
          <Route path="/demo" element={<Drills />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
