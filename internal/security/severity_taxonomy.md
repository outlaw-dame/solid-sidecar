# Security Severity Taxonomy

## Phase 26: Security Audit and Formal Hardening

This document defines the severity taxonomy used by the Solid Sidecar project to classify security vulnerabilities and issues. This taxonomy determines release blocking criteria, response priorities, and disclosure timelines.

---

## 1. Overview

The severity taxonomy provides a consistent framework for evaluating and prioritizing security issues. It is based on:
- **Impact**: The potential effect of a vulnerability if exploited
- **Exploitability**: How easy it is to exploit the vulnerability
- **Scope**: The range of components or systems affected
- **Business Impact**: The effect on the Solid ecosystem and users

This taxonomy aligns with common industry standards (CVSS, OWASP Risk Rating) while being tailored to the Solid Sidecar's specific threat model and deployment context.

---

## 2. Severity Levels

### 2.1 Critical Severity

**Release Blocking**: Yes - Must be fixed before any stable release
**Response SLA**: 24-48 hours for initial response, 7 days for fix
**Disclosure Timeline**: 7-14 days after fix

#### Definition

Critical vulnerabilities are those that:
- Allow **remote code execution** on the server or client
- Enable **complete system compromise** (full administrative control)
- Result in **massive data breaches** affecting all users
- Can be exploited **without authentication** and **without user interaction**
- Have **wormable** characteristics (self-propagating)

#### Examples
- Remote code execution vulnerabilities (RCE)
- Authentication bypass that grants full admin access
- SQL injection that allows database takeover
- Deserialization vulnerabilities leading to code execution
- Memory corruption vulnerabilities (buffer overflows, use-after-free, etc.)
- Complete confidentiality loss (all data exposed)
- Complete integrity loss (all data can be modified)
- Complete availability loss (permanent denial of service)

#### Impact Scores (CVSS v3.1)
- Base Score: 9.0 - 10.0
- Temporal Score: 8.5 - 10.0
- Environmental Score: 8.5 - 10.0

#### Response Protocol
1. **Immediate Triage**: Security team lead and project lead notified within 1 hour
2. **Emergency Response**: Dedicated response team assembled
3. **Emergency Fix**: Hotfix developed and tested
4. **Emergency Release**: Out-of-band release if necessary
5. **Emergency Communication**: Users notified via all available channels
6. **Post-Mortem**: Incident review within 48 hours of resolution

---

### 2.2 High Severity

**Release Blocking**: Yes - Must be fixed before any stable release
**Response SLA**: 48 hours for initial response, 14 days for fix
**Disclosure Timeline**: 14-30 days after fix

#### Definition

High vulnerabilities are those that:
- Allow **unauthorized data access** (read sensitive data)
- Enable **privilege escalation** (gain higher privileges than intended)
- Result in **significant data modification or deletion**
- Cause **significant denial of service** (service unavailable for extended period)
- Can be exploited with **minimal authentication** or **minimal user interaction**
- Affect **core security mechanisms** (authentication, authorization, encryption)

#### Examples
- Authentication bypass (gaining access to other users' data)
- Authorization bypass (accessing resources without proper permissions)
- Stored cross-site scripting (XSS) in admin interfaces
- Cross-site request forgery (CSRF) in sensitive operations
- Information disclosure (sensitive data exposure)
- Directory traversal attacks
- Weak cryptographic implementation (predictable tokens, weak hashing)
- Significant denial of service (service down for hours)
- Partial confidentiality loss
- Partial integrity loss
- Partial availability loss

#### Impact Scores (CVSS v3.1)
- Base Score: 7.0 - 8.9
- Temporal Score: 7.0 - 8.4
- Environmental Score: 7.0 - 8.4

#### Response Protocol
1. **Priority Triage**: Security team notified within 4 hours
2. **Dedicated Resources**: At least one developer assigned full-time
3. **Fix Development**: Fix developed and tested
4. **Release Planning**: Included in next scheduled release or out-of-band if critical
5. **Communication**: Users notified via security advisory
6. **Post-Mortem**: Incident review within 1 week of resolution

---

### 2.3 Medium Severity

**Release Blocking**: No - Can be included in regular releases
**Response SLA**: 1 week for initial response, 30 days for fix
**Disclosure Timeline**: 30-60 days after fix

#### Definition

Medium vulnerabilities are those that:
- Require **specific conditions** to exploit
- Have **limited impact** (affects specific users or data)
- Require **user interaction** or **social engineering**
- Affect **non-core components** or **less sensitive data**
- Have **mitigating factors** that reduce risk
- Are **difficult to exploit** reliably

#### Examples
- Reflected cross-site scripting (XSS) requiring user interaction
- Information disclosure with limited data exposure
- Race conditions with limited window
- Timing attacks
- Side-channel information leaks
- Limited denial of service (temporary impact)
- Weak default configuration (but can be hardened)
- Missing security headers
- Insufficient logging for security events

#### Impact Scores (CVSS v3.1)
- Base Score: 4.0 - 6.9
- Temporal Score: 3.7 - 6.9
- Environmental Score: 3.7 - 6.9

#### Response Protocol
1. **Standard Triage**: Security team notified within 1 week
2. **Fix Development**: Fix included in next major or minor release
3. **Communication**: Included in release notes
4. **Post-Mortem**: Retrospective in team meeting

---

### 2.4 Low Severity

**Release Blocking**: No - Can be addressed in regular maintenance
**Response SLA**: 2 weeks for initial response, no strict deadline for fix
**Disclosure Timeline**: With next scheduled release

#### Definition

Low vulnerabilities are those that:
- Have **minimal impact** if exploited
- Require **unusual conditions** to exploit
- Affect **non-sensitive data** or **non-production systems**
- Are **theoretical** with no practical exploit path
- Have **significant mitigating factors**

#### Examples
- Theoretical vulnerabilities with no known exploit
- Information disclosure with no sensitive data
- Denial of service requiring unusual configuration
- Missing best practice implementations
- Non-security bugs in security-related code
- Documentation issues related to security
- Cosmetic security issues

#### Impact Scores (CVSS v3.1)
- Base Score: 0.1 - 3.9
- Temporal Score: 0.1 - 3.6
- Environmental Score: 0.1 - 3.6

#### Response Protocol
1. **Backlog Triage**: Security team reviews during regular meetings
2. **Fix Development**: Addressed when resources permit
3. **Communication**: May be included in release notes if fixed

---

### 2.5 Informational / Not a Vulnerability

**Release Blocking**: No
**Response SLA**: 1 month for review
**Disclosure**: Not applicable

#### Definition

These are findings that do not represent actual vulnerabilities but may be of interest:
- Security-related feature requests
- Enhancements to security mechanisms
- Questions about security implementation
- Reports of vulnerabilities in out-of-scope components
- False positives

#### Examples
- Request for additional security features
- Suggestion for improved security documentation
- Report of vulnerability in test code
- Report of vulnerability in development dependencies
- Misconfiguration reports (not code issues)

#### Response Protocol
1. **Acknowledgment**: Security team acknowledges within 1 month
2. **Review**: Security team reviews and categorizes
3. **Communication**: Reporter informed of categorization
4. **Tracking**: Tracked as enhancement or documentation task

---

## 3. Severity Determination Process

### 3.1 Initial Assessment

When a vulnerability is reported or discovered:

1. **Identify the vulnerability type** and affected components
2. **Gather information** about exploitability and impact
3. **Consult CVSS calculator** for preliminary scoring
4. **Consider Solid-specific context** (deployment patterns, user base, etc.)
5. **Assign preliminary severity**

### 3.2 Detailed Analysis

1. **Reproduce the vulnerability** in a controlled environment
2. **Determine exact impact**:
   - What data can be accessed/modified?
   - What privileges can be gained?
   - What is the scope of affect?
3. **Determine exploitability**:
   - What access is required?
   - What user interaction is required?
   - How reliable is the exploit?
4. **Consider mitigating factors**:
   - Are there existing protections?
   - What is the likelihood of exploitation?
   - What is the potential blast radius?

### 3.3 Severity Review Meeting

For non-trivial vulnerabilities, a severity review meeting is held with:
- Security team lead
- Relevant engineering team members
- Product owner (if applicable)

The meeting will:
- Review the vulnerability details
- Discuss impact and exploitability
- Consider contextual factors
- Finalize severity classification
- Determine release blocking status

### 3.4 Documentation

The final severity determination is documented with:
- Vulnerability description
- Impact analysis
- Exploitability analysis
- Severity justification
- Release blocking decision
- Timeline for fix and disclosure

---

## 4. Solid-Specific Context

When determining severity for Solid Sidecar, we consider the following context:

### 4.1 Deployment Patterns
- **Sidecar architecture**: Vulnerabilities may affect all pods in a cluster
- **Multi-tenant**: Vulnerabilities may allow cross-tenant access
- **Data sensitivity**: Solid pods often contain highly sensitive personal data
- **Network exposure**: Sidecars are often exposed to the internet

### 4.2 User Base
- **Privacy expectations**: Solid users expect strong privacy protections
- **Data sensitivity**: Personal data, social graphs, sensitive documents
- **Compliance requirements**: GDPR, CCPA, and other privacy regulations

### 4.3 Threat Model
- **Adversary capabilities**: Well-resourced attackers (nation states, organized crime)
- **Attack surface**: Large (many protocols, many integrations)
- **Defense in depth**: Multiple layers of security controls

### 4.4 Impact Amplification

Certain vulnerability types may be upgraded in severity due to Solid-specific factors:
- **Authentication/Authorization bypass**: +1 severity level (due to privacy impact)
- **Cross-pod attacks**: +1 severity level (due to multi-tenant impact)
- **Data exfiltration**: +1 severity level (due to privacy regulations)
- **Long-lived tokens**: +1 severity level (due to persistent access)

---

## 5. CVSS Mapping

We use CVSS v3.1 as a guideline, but our final severity may differ based on Solid-specific context.

### 5.1 CVSS Vector Components

| Component | Description | Solid-Specific Notes |
|-----------|-------------|---------------------|
| AV | Attack Vector | Network (N) is most common for Solid |
| AC | Attack Complexity | Consider deployment context |
| PR | Privileges Required | Many Solid attacks require no privileges |
| UI | User Interaction | Consider Solid app usage patterns |
| S | Scope | Changed (C) is common in multi-tenant contexts |
| C | Confidentiality Impact | High (H) for personal data |
| I | Integrity Impact | High (H) for personal data modification |
| A | Availability Impact | High (H) for service denial |

### 5.2 CVSS to Severity Mapping

| CVSS Base Score | Solid Severity | Notes |
|-----------------|----------------|-------|
| 9.0 - 10.0 | Critical | Always Critical |
| 7.0 - 8.9 | High | Usually High, may be Critical with context |
| 4.0 - 6.9 | Medium | Usually Medium, may be High with context |
| 0.1 - 3.9 | Low | Usually Low, may be Medium with context |

### 5.3 Contextual Adjustments

We may adjust severity based on:
- **Data sensitivity**: Privacy-related vulnerabilities may be upgraded
- **Multi-tenant impact**: Cross-tenant vulnerabilities may be upgraded
- **Deployment scale**: Vulnerabilities affecting many users may be upgraded
- **Compliance impact**: Vulnerabilities affecting compliance may be upgraded
- **Exploit availability**: Public exploits may trigger urgency escalation

---

## 6. Release Blocking Criteria

### 6.1 Automatic Release Blocking

The following severity levels automatically block stable releases:
- **Critical**: Always blocks
- **High**: Always blocks

### 6.2 Conditional Release Blocking

Medium severity vulnerabilities may block releases if:
- They affect **core security mechanisms** (authentication, authorization)
- They have **public exploits** available
- They are **being actively exploited**
- They affect **compliance requirements**
- The **release manager** determines they pose significant risk

### 6.3 Release Blocking Process

1. **Identify blocking vulnerabilities**: Security team reviews all known vulnerabilities
2. **Assess risk**: Determine if vulnerability meets blocking criteria
3. **Notify release team**: Release manager informed of blocking issues
4. **Develop fix**: Fix is prioritized and developed
5. **Verify fix**: Fix is tested and verified
6. **Update release**: Blocking issues are resolved before release

### 6.4 Release Blocking Waivers

A vulnerability may be waived from blocking a release if:
- **Risk acceptance**: Risk is formally accepted by project leadership
- **Mitigations**: Effective mitigations are available and documented
- **Timeline**: Fix is planned for immediate follow-up release
- **Limited exposure**: Vulnerability has limited scope or impact

Waivers must be:
- **Documented**: Reasoning and acceptance recorded
- **Approved**: Signed off by security lead and project lead
- **Time-limited**: Valid for specific release only
- **Communicated**: Users informed of known issues

---

## 7. Severity Escalation and De-escalation

### 7.1 Escalation Criteria

Severity may be escalated if:
- New information reveals **greater impact** than initially assessed
- **Exploit becomes public** before fix is available
- **Active exploitation** is detected
- **Compliance impact** is greater than initially assessed
- **User reports** indicate higher impact than expected

### 7.2 De-escalation Criteria

Severity may be de-escalated if:
- **Mitigating factors** are discovered that reduce impact
- **Fix complexity** is higher than initially assessed
- **Exploit reliability** is lower than initially assessed
- **Scope** is more limited than initially assessed

### 7.3 Change Process

Severity changes require:
1. **New assessment**: Complete re-evaluation of the vulnerability
2. **Stakeholder review**: Security team and relevant engineering teams
3. **Documentation**: Updated severity determination with justification
4. **Communication**: All stakeholders notified of change
5. **Tracking**: Change logged in vulnerability database

---

## 8. Severity in Practice

### 8.1 Example Scenarios

| Scenario | CVSS | Solid Severity | Reasoning |
|----------|------|----------------|-----------|
| RCE in DID parser | 9.8 | Critical | Complete compromise, no auth required |
| Auth bypass via malformed token | 8.1 | Critical | Allows access to all user data |
| SQL injection in policy engine | 7.5 | High | Requires auth, but allows data exfiltration |
| XSS in admin console | 6.1 | High | Stored XSS, affects admins |
| Reflected XSS | 5.4 | Medium | Requires user interaction |
| Missing rate limiting | 4.3 | Medium | Could lead to DoS |
| Missing security header | 2.0 | Low | Low impact |
| Typosquatting dependency | 1.0 | Low | Easy to detect and fix |

### 8.2 Solid-Specific Upgrades

| Base Severity | Solid Context | Solid Severity | Reasoning |
|---------------|---------------|----------------|-----------|
| High | Affects authn/authz | Critical | Privacy impact |
| Medium | Cross-pod attack | High | Multi-tenant impact |
| Low | Data exfiltration | Medium | Compliance impact |
| High | Long-lived tokens | Critical | Persistent access |

### 8.3 Solid-Specific Downgrades

| Base Severity | Solid Context | Solid Severity | Reasoning |
|---------------|---------------|----------------|-----------|
| Medium | Test code only | Low | Not in production |
| High | Development dependency | Medium | Not in production |
| Critical | Requires physical access | High | Not remote exploitable |

---

## 9. Tracking and Metrics

### 9.1 Severity Metrics

We track the following metrics related to severity:
- **Severity distribution**: Count of vulnerabilities by severity level
- **Average time to triage**: By severity level
- **Average time to fix**: By severity level
- **Average time to disclosure**: By severity level
- **Release blocking rate**: Percentage of releases blocked by vulnerabilities
- **False positive rate**: Vulnerabilities initially classified but later determined to be non-issues

### 9.2 Reporting

Monthly security reports include:
- Vulnerability count by severity
- Average time to resolution by severity
- Release blocking vulnerabilities and status
- Severity classification accuracy

### 9.3 Continuous Improvement

We continuously improve our severity classification through:
- **Post-incident reviews**: Analyze if severity was correctly assigned
- **Industry benchmarking**: Compare with peer projects
- **Training**: Regular training for security team on severity classification
- **Feedback**: Collect feedback from reporters and users

---

## 10. Related Documents

- [Vulnerability Disclosure Policy](vulnerability_disclosure.md) - How vulnerabilities are reported and disclosed
- [Security Audit Checklist](audit_checklist.md) - Comprehensive audit checklist
- [Dependency Audit](dependency_audit.go) - Dependency vulnerability scanning
- [Secret Scanning](secret_scanning.go) - Secret detection and redaction
- [Threat Model](threat_model.go) - STRIDE-based threat models

---

## Appendix: Quick Reference

### Severity Decision Tree

```
Is the vulnerability exploitable without authentication AND allows RCE or complete compromise?
  ├─ Yes → Critical
  └─ No
      ├─ Does it allow unauthorized data access or significant privilege escalation?
      │   ├─ Yes → High
      │   └─ No
      │       ├─ Does it require specific conditions but has significant impact?
      │       │   ├─ Yes → Medium
      │       │   └─ No
      │       │       ├─ Does it have minimal impact or is theoretical?
      │       │       │   ├─ Yes → Low
      │       │       │   └─ No → Not a Vulnerability
      │       │       └─ (Consider Solid-specific context for upgrades)
      └─ (Consider release blocking criteria)
```

### Release Blocking Quick Check

```
Severity == Critical? → Block release
Severity == High? → Block release
Severity == Medium? → Check if affects authn/authz, has public exploit, or is actively exploited → Block release
Severity == Low? → Do not block release
```

### Response Timeline Quick Check

| Severity | Initial Response | Fix Deadline | Disclosure Timeline |
|----------|------------------|--------------|---------------------|
| Critical | 24-48 hours | 7 days | 7-14 days |
| High | 48 hours | 14 days | 14-30 days |
| Medium | 1 week | 30 days | 30-60 days |
| Low | 2 weeks | No strict deadline | With next release |
