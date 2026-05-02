# Changelog

## [1.0.0] - 2026-03-14
### Added
- Initial release
- 17-tab React.js dashboard
- topology_api.py POX module with 30+ REST endpoints
- SIEM detection: SYN flood, port scan, ARP flood, MAC spoofing...
- Simulate tab with 7 attack scenarios
- Net Calc tab with subnet calculator
- Export system: JSON, CSV, SVG, TXT

## [1.1.0] - 2026-05-02
### Changed
- Complete UI redesign: sidebar nav, M3 logo, toast notifications, animations
- Alerts tab split into Active / Blocked / Dismissed sub-tabs
- Stats bar now reads live data (packets, bandwidth, threats)
- Uptime rainbow gradient color
### Added
- 15 protocol detection (HTTP, HTTPS, DNS, SSH, DHCP, FTP, OpenFlow...)
- Link up/down events logged automatically
- Unblock button on every blocked host
- Dismissed alerts audit trail
### Fixed
- BW sparkline crash (Object.values.slice TypeError)
- Playbook input field disappearing on click
- pbVals useState hook rules violation

