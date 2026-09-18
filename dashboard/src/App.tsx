/** Operator console routes (pages listed in dashboard/README.md). */
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Attacks } from './pages/Attacks';
import { Fleet } from './pages/Fleet';
import { Models } from './pages/Models';
import { Policy } from './pages/Policy';
import { Publishers } from './pages/Publishers';
import { Releases } from './pages/Releases';
import { Verdicts } from './pages/Verdicts';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/releases" replace />} />
          <Route path="/releases" element={<Releases />} />
          <Route path="/verdicts" element={<Verdicts />} />
          <Route path="/fleet" element={<Fleet />} />
          <Route path="/publishers" element={<Publishers />} />
          <Route path="/models" element={<Models />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/attacks" element={<Attacks />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
