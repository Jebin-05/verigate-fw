/** Front door: choose the portal for your job. Nothing else is shown here. */
import { Link } from 'react-router-dom';

export function Landing() {
  return (
    <div className="landing">
      <div className="landing-head">
        <span className="brand">VeriGate</span>
        <h1>Firmware updates, checked before they reach a device.</h1>
        <p className="reading">
          Every release is signed, registered on a blockchain and inspected by an automated gate
          before any device installs it. Choose the portal for what you do.
        </p>
      </div>
      <div className="doors">
        <Link className="door" to="/publish">
          <span className="for">For the people who make the firmware</span>
          <h2>I publish firmware</h2>
          <p>Upload a build and its ingredient list. It is signed, registered and inspected.</p>
          <ul>
            <li>See whether each release was approved, held for review, or rejected</li>
            <li>See how many devices have installed it</li>
            <li>Withdraw a release you no longer stand behind</li>
          </ul>
          <span className="go">Open the publisher portal</span>
        </Link>
        <Link className="door" to="/approve">
          <span className="for">For the people who run the devices</span>
          <h2>I approve updates</h2>
          <p>Watch releases arrive and see exactly why each one passed or failed.</p>
          <ul>
            <li>Read the inspection report for any release, in plain words</li>
            <li>Verify a decision against the blockchain yourself</li>
            <li>Follow your devices and the live activity as it happens</li>
          </ul>
          <span className="go">Open the approval console</span>
        </Link>
      </div>
      <div className="landing-foot">
        <span>Presenting the system? </span>
        <Link to="/demo">Run a security drill and watch the gate catch it</Link>
      </div>
    </div>
  );
}
