# Playbook — Cloud-Only Engagement

Assumes credentials or a foothold inside a cloud tenant. Objective is normally data access or tenant admin.

## Prerequisites

- [ ] Scope names the account/subscription/project IDs
- [ ] Credentials characterized: user, role, service principal, managed identity, key
- [ ] Read-only enumeration agreed unless RoE says otherwise

## Phase 0 — Identity

```bash
# AWS
aws sts get-caller-identity
# Azure
az account show
# GCP
gcloud auth list; gcloud config list
```

- [ ] Who am I, what is my principal type
- [ ] Which policies/roles are attached
- [ ] Is there an instance metadata service reachable

## Phase 1 — Enumeration

```bash
enumerate-iam --access-key $AK --secret-key $SK        # AWS
prowler aws -M json-ocsf -o prowler/                    # posture
roadrecon gather; roadrecon gui                         # Azure
gcloud projects list; gcloud iam service-accounts list  # GCP
```

- [ ] Users, groups, roles, policies
- [ ] Storage buckets/containers and their ACLs
- [ ] Compute inventory, public IPs, security groups
- [ ] Secrets: Secrets Manager, Key Vault, Secret Manager
- [ ] Logging and detection status (CloudTrail, GuardDuty, Defender)

## Phase 2 — Privilege escalation

Map permissions to escalation primitives (`references/cloud-container.md`).

| Cloud | Fastest path |
| --- | --- |
| AWS | `iam:CreatePolicyVersion` / `PassRole` + `RunInstances` / Lambda |
| Azure | App registration credential add / managed identity / role assignment write |
| GCP | `setIamPolicy` / `actAs` + `compute.instances.create` |

```bash
# AWS: who can do what
python3 enumerate-iam.py --access-key $AK --secret-key $SK
# Azure: current role assignments
az role assignment list --assignee <object-id> --all
```

- [ ] Enumerate before exploiting — do not guess permissions
- [ ] Prefer the path that leaves no persistent artifact
- [ ] Record the exact API call that granted escalation

## Phase 3 — Workload identity

- [ ] IMDS reachable → `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- [ ] Azure IMDS → `Metadata:true` token request
- [ ] GCP metadata → `Metadata-Flavor: Google`
- [ ] Container/K8s service account tokens
- [ ] CI/CD OIDC trust relationships

## Phase 4 — Data access

- [ ] Prove access with a count or a single redacted object
- [ ] Never bulk download; hash or list instead
- [ ] Check versioning and deleted objects for sensitive history
- [ ] Screenshot the console or CLI output with timestamps

## Phase 5 — Persistence assessment (report only unless approved)

Document what persistence is *possible*, do not deploy it unless the RoE explicitly allows and the client asked for it.

- [ ] New access key / app credential
- [ ] Role trust modification
- [ ] Lambda/Function update
- [ ] IAM policy attachment

## Phase 6 — Cleanup

- [ ] Remove any credential or policy you created
- [ ] Verify removal with a second API call
- [ ] `cleanup.md` updated

## Decision points

- **No escalation path from current identity?** Pivot to workload identity (IMDS, CI runner, container).
- **Metadata service blocked?** Look for SSRF in any reachable app, or a CI job with cloud creds.
- **Detection is on?** Switch to read-only enumeration and slow the rate; the report matters more than stealth.

## Exit criteria

Objective data access proven, or every reachable identity exhausted, or window closed.
