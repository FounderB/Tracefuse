//! Built-in rule catalog for `tracefuse explain` and doctor summaries.

use crate::FindingSeverity;

#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub id: &'static str,
    pub detector: &'static str,
    pub title: &'static str,
    pub default_severity: FindingSeverity,
    pub summary: &'static str,
    pub why: &'static str,
    pub remediation: &'static str,
    pub references: &'static [&'static str],
}

/// Stable rule ids used by explain + severity overrides.
pub fn all_rules() -> &'static [RuleInfo] {
    &[
        RuleInfo {
            id: "secrets/private-key-material",
            detector: "secrets",
            title: "Private key material",
            default_severity: FindingSeverity::Critical,
            summary: "PEM/OpenSSH private key header found in a tracked file.",
            why: "Private keys in source control are harvested by scanners and leak into forks, CI logs, and backups.",
            remediation: "Remove the key, rotate anything that used it, and load keys from a secrets manager.",
            references: &["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key"],
        },
        RuleInfo {
            id: "secrets/aws-access-key-id",
            detector: "secrets",
            title: "AWS access key id",
            default_severity: FindingSeverity::Critical,
            summary: "AWS-style access key id (AKIA… / ASIA…) detected.",
            why: "Cloud access keys in repos enable account takeover.",
            remediation: "Deactivate the key in IAM, rotate replacements, prefer short-lived credentials (OIDC / roles).",
            references: &["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
        },
        RuleInfo {
            id: "secrets/github-personal-access-token",
            detector: "secrets",
            title: "GitHub personal access token",
            default_severity: FindingSeverity::Critical,
            summary: "GitHub PAT (ghp_ / github_pat_) found in content.",
            why: "PATs grant API and git access; leaked tokens are abused within minutes.",
            remediation: "Revoke the token in GitHub settings and use Actions secrets or OIDC apps.",
            references: &["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"],
        },
        RuleInfo {
            id: "secrets/stripe-live-secret-key",
            detector: "secrets",
            title: "Stripe live secret key",
            default_severity: FindingSeverity::Critical,
            summary: "Stripe live secret key (sk_live_…) detected.",
            why: "Live Stripe keys can move money and access customer data.",
            remediation: "Roll the key in the Stripe dashboard and load it from a secret store.",
            references: &["https://stripe.com/docs/keys"],
        },
        RuleInfo {
            id: "secrets/gcp-api-key",
            detector: "secrets",
            title: "GCP API key",
            default_severity: FindingSeverity::High,
            summary: "Google Cloud API key (AIza…) shape detected.",
            why: "Unrestricted GCP API keys can burn quota or abuse billed APIs.",
            remediation: "Restrict and rotate the key; prefer service accounts with least privilege.",
            references: &["https://cloud.google.com/docs/authentication/api-keys"],
        },
        RuleInfo {
            id: "secrets/slack-token",
            detector: "secrets",
            title: "Slack token",
            default_severity: FindingSeverity::High,
            summary: "Slack bot/user token (xox…) or incoming webhook URL detected.",
            why: "Slack tokens let attackers post as bots or pivot into workspace integrations.",
            remediation: "Revoke the token/webhook in Slack admin and store replacements as CI secrets.",
            references: &["https://api.slack.com/authentication/best-practices"],
        },
        RuleInfo {
            id: "ci/pull-request-target",
            detector: "ci",
            title: "pull_request_target trigger",
            default_severity: FindingSeverity::High,
            summary: "Workflow triggers on pull_request_target.",
            why: "Fork PRs can run with write secrets if checkout of untrusted code is misconfigured.",
            remediation: "Prefer pull_request. If you must use pull_request_target, never checkout untrusted code with write secrets.",
            references: &["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
        },
        RuleInfo {
            id: "ci/oidc-misuse",
            detector: "ci",
            title: "OIDC / id-token misuse pattern",
            default_severity: FindingSeverity::High,
            summary: "Workflow requests OIDC (id-token: write) in a risky permission or trigger context.",
            why: "Combining OIDC minting with pull_request_target or write-all can issue cloud creds to untrusted workflows.",
            remediation: "Use least-privilege permissions, pin audiences, avoid write-all, and never mint tokens on pull_request_target with untrusted checkout.",
            references: &["https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"],
        },
        RuleInfo {
            id: "ci/curl-bash",
            detector: "ci",
            title: "curl|bash in CI workflow",
            default_severity: FindingSeverity::High,
            summary: "Workflow pipes remote content into a shell.",
            why: "Remote installers can change under you and execute arbitrary code in CI.",
            remediation: "Pin actions by SHA, verify checksums, avoid piping curl to bash.",
            references: &["https://blog.gitguardian.com/github-actions-security-cheat-sheet/"],
        },
        RuleInfo {
            id: "ci/plaintext-secret",
            detector: "ci",
            title: "Plaintext secret in workflow env",
            default_severity: FindingSeverity::Critical,
            summary: "Workflow embeds a secret-like value in plaintext env.",
            why: "Plaintext secrets in YAML are visible in the repo and fork history.",
            remediation: "Move values to GitHub Actions secrets / OIDC.",
            references: &["https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions"],
        },
        RuleInfo {
            id: "scripts/lifecycle",
            detector: "scripts",
            title: "Dangerous npm lifecycle script",
            default_severity: FindingSeverity::High,
            summary: "Lifecycle script (postinstall/preinstall/…) runs a high-risk installer pattern.",
            why: "Lifecycle hooks run on install for every consumer of the package.",
            remediation: "Remove remote installers from lifecycle scripts; vendor tools or use audited packages.",
            references: &["https://blog.npmjs.org/post/185836079580/plot-to-steal-cryptocurrency-foiled-by-the-npm"],
        },
        RuleInfo {
            id: "dockerfile/latest",
            detector: "dockerfile",
            title: "Unpinned or :latest base image",
            default_severity: FindingSeverity::Medium,
            summary: "FROM uses a floating tag.",
            why: "Floating tags make builds non-reproducible and surprise-break or surprise-patch.",
            remediation: "Pin to a digest (image@sha256:…) or immutable version tag.",
            references: &["https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-digest"],
        },
        RuleInfo {
            id: "dockerfile/env-secret",
            detector: "dockerfile",
            title: "Secret-like value in ENV",
            default_severity: FindingSeverity::High,
            summary: "Dockerfile ENV appears to embed a credential.",
            why: "ENV values bake into image layers and history.",
            remediation: "Pass secrets at runtime via orchestrator secrets / BuildKit secret mounts.",
            references: &["https://docs.docker.com/build/building/secrets/"],
        },
        RuleInfo {
            id: "dockerfile/curl-pipe-shell",
            detector: "dockerfile",
            title: "curl|sh in Dockerfile RUN",
            default_severity: FindingSeverity::High,
            summary: "Dockerfile RUN pipes curl/wget into a shell.",
            why: "Image builds inherit the same remote-code risk as CI curl|bash installers.",
            remediation: "Vendor installers and verify checksums/signatures — never curl|sh in image builds.",
            references: &["https://owasp.org/www-project-docker-top-10/"],
        },
        RuleInfo {
            id: "lockfile/npm-missing",
            detector: "lockfile",
            title: "package.json without a lockfile",
            default_severity: FindingSeverity::Medium,
            summary: "Manifest present but no lockfile.",
            why: "Installs are non-reproducible and vulnerable to registry drift.",
            remediation: "Commit a lockfile and install with npm ci / yarn --frozen-lockfile / pnpm i --frozen-lockfile.",
            references: &[],
        },
        RuleInfo {
            id: "env_files/credential",
            detector: "env_files",
            title: "Credential / env file present",
            default_severity: FindingSeverity::Medium,
            summary: "Sensitive-looking file (.env, PEM, credentials JSON) is present.",
            why: "Env and key files are frequent leak vectors when committed.",
            remediation: "Gitignore secrets, keep .env.example templates, load real values from a secret manager.",
            references: &[],
        },
        RuleInfo {
            id: "deps/dangerous",
            detector: "deps",
            title: "Risky / known-bad dependency pattern",
            default_severity: FindingSeverity::High,
            summary: "Dependency name matches a high-risk or typosquat heuristic.",
            why: "Malicious or lookalike packages execute install scripts and steal secrets.",
            remediation: "Remove the package and verify the intended name on the registry.",
            references: &["https://socket.dev/blog"],
        },
    ]
}

pub fn list_rule_ids() -> Vec<&'static str> {
    all_rules().iter().map(|r| r.id).collect()
}

pub fn find_rule(query: &str) -> Option<&'static RuleInfo> {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return None;
    }
    all_rules()
        .iter()
        .find(|r| r.id.eq_ignore_ascii_case(&q))
        .or_else(|| {
            all_rules().iter().find(|r| {
                r.id.to_ascii_lowercase().contains(&q)
                    || r.title.to_ascii_lowercase().contains(&q)
                    || r.detector.eq_ignore_ascii_case(&q)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_resolves_aliases() {
        assert!(find_rule("ci/pull-request-target").is_some());
        assert!(find_rule("pull_request_target").is_some() || find_rule("pull-request").is_some());
        assert!(find_rule("stripe").is_some());
        assert!(find_rule("oidc").is_some());
        assert!(find_rule("gcp").is_some());
        assert!(find_rule("no-such-rule-xyz").is_none());
    }
}
