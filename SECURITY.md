# Security policy

This is a research prototype. It is **not** production software.

- Report vulnerabilities in the prototype by opening a private security advisory on GitHub.
- `src/verigate/attacks/` contains scripts that deliberately produce tampered firmware and replayed
  transactions **against the local emulated fleet only**. They must never be pointed at real devices
  or public networks other than the designated test network.
- Keys in `.env.example` are Hardhat's public well-known test keys. Real keys live only in `.env`
  (git-ignored) or GitHub Actions secrets.
