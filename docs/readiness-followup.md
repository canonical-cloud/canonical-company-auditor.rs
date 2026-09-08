# Readiness follow-up: draft safety and assessor planning

This change preserves catalog 2026-09-07.1, the response v1 contract, all independent framework answers, and existing Rust/JavaScript report semantics. It does not perform a customer audit, verify evidence contents or add durable answer storage.

## Safer worksheet editing

Import replacement now checks every answer field, including owner, evidence reference/date, reviewer and remediation date, even when the declaration remains unanswered. Cancel preserves current edits. Imports are serialized; worksheet controls are disabled while a file is read and validated, and restored after success, cancellation or failure. Invalid files never replace the current packet.

Native input validity is checked before export and printing. Invalid drafts do not retain an old summary, and all questions become visible until invalid fields are corrected. Input-time errors do not steal keyboard focus; action errors remain announced. Date bounds and opaque-reference patterns supplement, not replace, the existing semantic validator.

The question view can show all, unanswered, declared gaps, unknown evidence, pending review, or overdue actions. These are display filters only: counts, JSON/Markdown exports and printed packets include the complete framework. Filtering cannot remove questions from the denominator or complete another framework.

## Assessor workpaper export

The worksheet's **Export assessor workpaper** button produces an independent Markdown planning template for the selected framework, edition and assessment context. It adds engagement authorization, applicability/program selection, evidence requests, population completeness, sampling rationale, authorized test steps, expected/observed behavior, provenance, limitations, findings, remediation and retest fields.

Every assessor outcome starts **not assessed** and every independent review starts **pending**, regardless of customer declarations or typed reviewer names. The template labels the existing declaration, owner and opaque artifact reference as unverified. It deliberately does not copy free-form customer notes or self-reported reviewer names into an assessor conclusion. It does not certify readiness or provide a universal sample size. Expand the ten broad intake prompts using the applicable full requirement program and appropriately qualified reviewers; issue #6 remains open for that work.

This new workpaper export is available in the browser/shared JavaScript library. The Rust CLI continues to export readiness questionnaires and reports using its existing commands; no new workpaper CLI flag is introduced here.

Assessment-planning reference: NIST SP 800-53A Rev. 5, https://csrc.nist.gov/pubs/sp/800/53/a/r5/final . The methods, depth and coverage must be adapted to the actual engagement. Refer to readiness/methodology.md; this is not a cross-framework control mapping.

## Private CLI output boundaries

The shared Rust file writer creates new output files with Unix mode 0600 (further restricted by umask). Audit-package directories are created non-recursively with mode 0700. Existing files/directories and final-component symlinks are refused; the writer does not truncate existing packets. These protections cover readiness, assessment, audit, prompt and package file outputs. stdout behavior is unchanged.

Windows uses inherited filesystem ACLs: select a protected parent directory; this change does not install Windows ACLs or claim equivalent Unix permissions there. On every platform, choose a trusted parent path. Final-component create-new protection does not defend against a maliciously replaced parent directory. Exports are not encrypted. An I/O failure may leave a restrictive partial file or packet directory; inspect it and choose a new destination rather than blindly overwriting. Atomic file creation is not a claim that a multi-document packet is transactionally published.

Browser downloads are outside the Rust writer and use the browser/OS download permissions; verify the download and move it into approved protected storage. Never commit customer response packets or expose them in CI logs.

Implementation references: https://doc.rust-lang.org/std/fs/struct.OpenOptions.html and https://doc.rust-lang.org/std/os/unix/fs/trait.OpenOptionsExt.html .

## Regression coverage

The additional hermetic Node suite checks all answer-field edit guards, overlapping/failing/cancelled import operations, filters without denominator mutation, framework/context/version rejection, workpaper escaping, and unassessed reviewer outcomes. The existing real-catalog and Rust/JavaScript golden tests are retained unchanged. Rust tests additionally cover Unicode output, create-new directories, eight concurrent writers, Unix permissions and existing/dangling symlinks. Real-server browser coverage belongs in the consuming web-server PR before its source pin is merged.
