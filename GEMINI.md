# Aether Threat & Forensic Scanner - Google Antigravity & Gemini Workspace Rules

This document defines the hierarchical workspace rules and constraints automatically enforced by **Google Antigravity** (IDE, CLI, App) and **Gemini Code Assist** in `Aether`.

---

## Project Overview & Technical Stack
- **Project**: Aether Threat & Forensic Scanner
- **Primary Stack**: Go 1.22+ (cmd/aether, internal/scanner, internal/yara) + Vue/React Portfolio UI
- **Verification Command**: `go test ./... (in root) | npm test (in portfolio)`
- **Role & Purpose**: High-performance Linux threat detection and triage scanner utilizing native Go heuristics and static YARA-X rules.

### Environment Guidelines
- Adhere strictly to the forensic safety and read-only invariants in AGENTS.md.
- Static analysis only; never execute untrusted sample binaries.
- Persist offline self-contained HTML report requirements with strict CSP nonces.

---

## Core AI Interaction & Workflow Protocol

### 1. Language & Communication
- **Multilingual Comprehension**: Understand instructions and concepts expressed in **Hinglish, Hindi, or English**.
- Respond with clear, professional technical English while honoring vocabulary and intent from Hinglish/Hindi prompts.

### 2. Architecture-First & Investigation
- **Inspect Before Proposing**: Thoroughly examine the existing codebase, file layout, dependencies, and architecture before proposing changes.
- **Clarification Protocol**: Identify the actual objective and proactively ask clarifying questions whenever key technical details, requirements, or constraints are missing.

### 3. Professional Technical Specification
- **Prompt Transformation**: Convert informal descriptions or brief requests into a structured, comprehensive technical specification before planning.
- Every comprehensive plan must cover:
  1. Functional Requirements
  2. Technical Constraints
  3. Architecture & Data Flow
  4. Security & Privilege Boundaries
  5. Performance & Resource Bounds
  6. Edge Cases & Error Handling
  7. Verification Strategy & Test Cases
  8. Acceptance Criteria

### 4. Strict Approval Gate & Scope Control
- **No Unsolicited Modifications**: My initial idea or request is **NOT permission to modify code or execute modifying commands**.
- **Approval Protocol**: Present the complete proposed prompt and implementation plan first, then **wait for explicit user approval** before touching any implementation files or running mutating commands.
- **Revision Protocol**: If changes are requested on the plan, revise the proposed specification and request approval again.
- **Strict Scope**: Implement strictly the agreed scope. Approval of a plan is not permission to implement future or out-of-scope tasks.

### 5. Code Quality & Truthful Verification
- **No Unnecessary Rewrites**: Preserve existing working architecture, comments, style, and structure. Do not perform gratuitous refactors.
- **No Unsupported Assumptions**: Verify against real files rather than hallucinating paths, imports, or APIs.
- **Truthful Testing**: Run relevant automated test suites and report genuine, unvarnished test results, modified files, limitations, and unverified behavior. **Never fabricate test results**.

### 6. Safe & Authorized Cybersecurity Practice
- **Containment**: All testing must follow safe, authorized, and strictly contained cybersecurity practices.
- **Zero Insecure Defaults**: Never introduce hardcoded credentials, world-writable permissions, unauthenticated backdoors, or unmonitored external network connections.
- **No Secret Exposure**: Never log, expose, or commit secrets, tokens, API keys, or private key material.

