# Release-Blocking Severity Taxonomy

## Overview

This document defines the severity classification for security issues and determines which issues block releases of the solid-sidecar project.

## Severity Levels

### Critical (CVSS 9.0-10.0)

**Description**: Vulnerabilities that can be exploited to cause severe, immediate, and widespread damage to the system or its users.

**Examples**:
- Remote Code Execution (RCE)
- Complete authentication bypass
- Privilege escalation to root/system level
- Unauthorized access to all user data
- Persistent compromise of the entire system
- Memory corruption leading to arbitrary code execution

**Release Blocking**: **YES** - Blocks ALL releases (patch, minor, major)

**SLA**: 24 hours for initial fix, 7 days for complete remediation

**Response**:
- Immediate patch release if vulnerability is public
- Emergency security advisory
- Full regression testing
- Backport to all supported versions

### High (CVSS 7.0-8.9)

**Description**: Vulnerabilities that can be exploited to cause significant damage but require specific conditions or have limited scope.

**Examples**:
- Denial of Service (DoS) against the service
- Unauthorized access to sensitive information
- Partial authentication bypass
- Limited authorization bypass
- Temporary compromise of the system
- Information disclosure affecting multiple users

**Release Blocking**: **YES** - Blocks minor and major releases

**SLA**: 7 days for initial fix, 30 days for complete remediation

**Response**:
- Included in next scheduled minor/major release
- Security advisory for public issues
- Regression testing required
- Consider backporting to recent versions

### Medium (CVSS 4.0-6.9)

**Description**: Vulnerabilities with moderate impact that typically require user interaction or have limited scope.

**Examples**:
- Information disclosure requiring user interaction
- Limited data modification
- Local privilege escalation
- Race conditions with limited impact
- Side-channel information leaks
- Incomplete input validation with low impact

**Release Blocking**: **NO** - Does not block releases

**SLA**: 30-90 days for fix

**Response**:
- Included in next scheduled release
- Documented in release notes
- No backporting required (unless critical)

### Low (CVSS 0.1-3.9)

**Description**: Vulnerabilities with minimal impact that do not pose significant risk.

**Examples**:
- Informational findings
- Best practice violations
- Theoretical vulnerabilities with no practical exploit
- Documentation issues with security implications
- Non-sensitive information disclosure

**Release Blocking**: **NO** - Does not block releases

**SLA**: Next scheduled release

**Response**:
- Fixed when convenient
- May be deferred to future releases
- No security advisory required

## CVSS Scoring

The project uses the Common Vulnerability Scoring System (CVSS) v4.0 for severity classification. Security issues are scored based on:

- **Attack Vector**: Network, Adjacent, Local, Physical
- **Attack Complexity**: Low, High
- **Privileges Required**: None, Low, High
- **User Interaction**: None, Required
- **Scope**: Unchanged, Changed
- **Impact**: High, Low on Confidentiality, Integrity, Availability

### CVSS v4.0 Base Score Ranges

| Severity | CVSS Score Range |
|----------|------------------|
| Critical | 9.0 - 10.0 |
| High | 7.0 - 8.9 |
| Medium | 4.0 - 6.9 |
| Low | 0.1 - 3.9 |

## Release Blocking Matrix

| Severity | Patch Release | Minor Release | Major Release |
|----------|---------------|---------------|---------------|
| Critical | BLOCKS | BLOCKS | BLOCKS |
| High | Does not block* | BLOCKS | BLOCKS |
| Medium | Does not block | Does not block | Does not block |
| Low | Does not block | Does not block | Does not block |

*High severity issues in patch releases: Fix is included in the patch release that addresses the issue, but does not block other patch releases.

## Security Fix Release Process

### Critical Vulnerabilities
1. **Discovery**: Vulnerability reported or discovered
2. **Triage**: Verify and classify within 24 hours
3. **Fix**: Develop fix within 24 hours
4. **Test**: Full regression testing
5. **Release**: Emergency patch release within 7 days
6. **Disclose**: Coordinated disclosure with CVE assignment
7. **Backport**: Apply fix to all supported versions

### High Vulnerabilities
1. **Discovery**: Vulnerability reported or discovered
2. **Triage**: Verify and classify within 48 hours
3. **Fix**: Develop fix within 7 days
4. **Test**: Regression testing
5. **Release**: Include in next scheduled minor/major release
6. **Disclose**: Coordinated disclosure
7. **Backport**: Consider backporting to recent versions

### Medium Vulnerabilities
1. **Discovery**: Vulnerability reported or discovered
2. **Triage**: Verify and classify within 1 week
3. **Fix**: Include in development for next release
4. **Release**: Include in next scheduled release
5. **Disclose**: Document in release notes

## Special Cases

### Zero-Day Vulnerabilities
- **Classification**: Automatically Critical
- **Action**: Immediate emergency response
- **SLA**: 24 hours for initial mitigation
- **Disclosure**: Coordinated with affected parties

### Supply Chain Vulnerabilities
- **Classification**: Based on impact to solid-sidecar
- **Action**: Update dependency or apply workaround
- **SLA**: Depends on criticality of affected dependency
- **Disclosure**: Follow upstream disclosure (if applicable)

### False Positives
- **Verification**: Security team verifies all reports
- **Action**: Document as non-vulnerability
- **Disclosure**: Notify reporter with explanation

## Release Checklist

Before releasing, verify:

### For ALL releases:
- [ ] No Critical severity issues open
- [ ] No High severity issues open (for minor/major releases)
- [ ] All security fixes have been tested
- [ ] Release notes include security fixes
- [ ] CVE assignments requested (for eligible vulnerabilities)

### For Patch Releases:
- [ ] Addresses specific Critical or High severity issue
- [ ] Backported to all affected versions
- [ ] Security advisory prepared

### For Minor/Major Releases:
- [ ] No Critical severity issues open
- [ ] No High severity issues open
- [ ] Security regression tests passing
- [ ] Dependency audit completed

## Security Fix Verification

All security fixes must include:
1. **Test Case**: Reproduces the vulnerability
2. **Fix**: Corrects the vulnerability
3. **Regression Test**: Prevents future regressions
4. **Documentation**: Updates to reflect changes
5. **Review**: Security team review

## Tracking

Security issues are tracked in:
- GitHub Issues with `security` label
- Private security advisory for unreleased vulnerabilities
- Release notes for fixed vulnerabilities

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-07-04 | Initial version |
