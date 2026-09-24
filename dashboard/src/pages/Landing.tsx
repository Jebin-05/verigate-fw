/** Workspace chooser. */
import { Link } from 'react-router-dom';

export function Landing() {
  return (
    <div className="gate">
      <div className="card">
        <h1>VeriGate</h1>
        <p>Firmware update gate for IoT fleets. Choose your workspace.</p>
        <div className="choices">
          <Link className="choice" to="/app">
            <b>Approval console</b>
            <span>
              Releases, inspection reports, devices, live activity, governance, scenarios.
            </span>
          </Link>
          <Link className="choice" to="/publisher">
            <b>Publisher portal</b>
            <span>Publish releases, track their status and installs, withdraw.</span>
          </Link>
        </div>
        <p className="foot">
          Roles are separated by workspace in this prototype; sign-in is out of scope.
        </p>
      </div>
    </div>
  );
}
