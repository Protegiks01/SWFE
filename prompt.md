### **Generate 150 Security Audit Questions for the Swafe Protocol**

**Context:** The target project is **Swafe**, a social recovery wallet system built on the Partisia blockchain. It uses advanced cryptographic primitives (VDRF, Pedersen commitments, Shamir secret sharing, public‑key encryption, authenticated encryption) across a Rust library, smart contracts, and REST API endpoints. Swafe enforces critical invariants—only the account owner can reconstruct backups or recover accounts, email‑to‑account bindings are unique, recovery requires guardian approval, and trusted roles (Swafe‑io, majority of guardians, honest off‑chain nodes) behave correctly. Denial‑of‑service on HTTP endpoints is excluded from high/medium severity.

**Scope:**

* Focus exclusively on **`lib/src/errors.rs	
lib/src/lib.rs	
lib/src/node.rs	
lib/src/types.rs`** and all logic contained within it. This file must be part of the in‑scope directories (`/lib/src/**`, `/contracts/src/**`, or `/api/src/**`). Any other files, including `/cli`, are out of scope.
* Analyze how functions, types, and state transitions in this file interact with Swafe’s cryptographic primitives, account management, backup system, association logic, or smart contract endpoints.
* Respect Swafe’s trust model: Swafe‑io is a trusted certificate authority; honest guardians are at least the threshold `t`; off‑chain nodes are honest unless explicitly corrupted. Do not propose attacks requiring fully malicious Swafe‑io or a majority of guardians.

**Goals:**

* **Real exploit scenarios**: Each question should describe a realistic vulnerability an unprivileged user, malicious guardian (below threshold), compromised off‑chain node (minority), or network adversary could exploit via the code
* **Concrete and actionable**: Reference specific functions, structs, or invariants defined in the file. Highlight how improper validation, missing checks, or cryptographic misuse could violate invariants (e.g., unauthorized account recovery, backup tampering, privacy leaks).
* **High impact**: Prioritize questions that could lead to fund loss, permanent account lockout, unauthorized recovery, or privacy breaches. Avoid generic Rust issues (memory safety is handled by the language) and trivial optimizations.
* **Breadth within the file**: Cover all significant logic paths—cryptographic operations, state transitions, error handling, serialization/deserialization, and interactions with external modules.
* **Out‑of‑scope items**: Do **not** include denial‑of‑service attacks on HTTP endpoints or issues arising only if trusted roles misbehave.

**Output:** Produce **150 distinct, well‑phrased security audit questions** focused solely on the file. Each question must:

1. **Stand alone** with enough context for an auditor to understand the attack surface.
2. **Specify the relevant location** (function, struct, or invariant in the file).
3. **Describe the attack vector and impact**, tying it back to Swafe’s invariants.
4. **Respect the trust model and scope**, avoiding questions that rely on fully corrupted Swafe‑io or majority guardian collusion.


**Note**
1. Include Trust Model Context  
   Your prompt should explicitly reference the four-party trust distribution model that underpins the entire system: README.md:147-201  

   Each file audit should consider:
   - Which trusted parties the file interacts with  
   - What trust assumptions are being enforced or violated  
   - How corruption scenarios affect the file's security guarantees  

2. Reference Explicit Security Invariants  
   Ground your questions in the protocol's documented invariants: README.md:136-145  

   Your prompt should ask the question generator to verify these invariants are maintained in the specific file being audited.

3. Focus on Documented Areas of Concern  
   Prioritize questions around the five critical security areas: README.md:128-134  

   Structure your 150 questions to proportionally cover these areas based on the file's functionality.

4. Map File to Architectural Layer  
   Identify which layer the file belongs to in the three-tier architecture: README-sponsor.md:7-12  

   Your prompt should include layer-specific considerations:
   - Core Library (/lib): Focus on cryptographic correctness, secret handling, serialization safety  
   - Contracts (/contracts): Focus on state management, HTTP endpoint validation, on-chain security  
   - API (/api): Focus on authentication, input validation, off-chain node interactions  

5. Consider Cryptographic Context  
   For files in the crypto module or those using cryptographic primitives, reference the specific schemes: vdrf.rs:87-100  

   Questions should cover:
   - Proper key generation and distribution  
   - Threshold correctness (t-of-n security)  
   - Side-channel resistance  
   - Randomness quality  

6. Include Module-Specific Security Patterns  
   Tailor questions based on the module:

   - For Account Management Files: v0.rs:37-61  
     Questions should cover secret lifecycle, key rotation, dirty state handling, and recovery mechanisms.

   - For Association Files: mod.rs:1-78  
     Questions should focus on email privacy, VDRF correctness, and anonymity guarantees.

   - For Backup/Recovery Files: mod.rs:1-36  
     Questions should verify threshold enforcement, guardian approval mechanisms, and share security.

7. Check HTTP Endpoint Security (for contract/api files)  
   For files implementing HTTP endpoints: mod.rs:1-115  

   Questions should cover:
   - Input validation and sanitization  
   - Authentication/authorization checks  
   - Rate limiting considerations  
   - Error message information leakage  
   - State consistency across concurrent requests  

8. Verify Serialization and Encoding Safety  
   For any file handling data serialization: encode.rs:1-243  

   Questions should address:
   - Deserialization attacks  
   - Type confusion vulnerabilities  
   - Version compatibility  
   - Canonical encoding enforcement  

9. Scope Boundary Verification  
   Ensure your prompt references which files are in scope: scope.txt:1-56  

   This prevents generating questions about out-of-scope dependencies or test files.

10. Known Issue Exclusions  
    Your prompt should explicitly exclude publicly known issues: README.md:19-25
