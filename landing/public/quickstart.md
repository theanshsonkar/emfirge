# Quickstart. From install to your first check.

Four steps. You run the CLI, sign in, give emfirge a read-only role in your AWS account, and try one change on a branch. Nothing you do here can change your cloud.

Human version: https://emfirge.cloud/quickstart/

*Figure 1. The four steps. Only the last one touches a branch; the role in step 3 is the only thing that can reach your AWS, and it is read-only.*

## 1. Install

**One command. There is nothing to install globally.**

Terminal:

```
npx emfirge --help
```

You need Node.js 20 or later. The npm package is `emfirge` and the command is `emfirge`. The list of commands comes from the server, so the help is always current. Agents add `-y` to skip npx's first-run prompt: `npx -y emfirge ...`.

Prefer a permanent command? `npm install -g emfirge` puts `emfirge` on your PATH. The CLI is a thin client: the engine is hosted, and the CLI only signs in, tokenizes identifiers on your machine, sends the command and prints the answer.

## 2. Sign in

**Your browser opens, you sign in with GitHub or Google, and the CLI keeps the session on your machine.**

Terminal:

```
npx emfirge login
npx emfirge logout   # to sign out of this device
```

Emfirge never asks for your AWS access keys. The only thing it holds that can reach your account is the role in step 3. In CI, where no browser can open, set `EMFIRGE_API_KEY` instead.

## 3. Create the read-only role

**One CloudFormation click. The role can read your account's configuration and nothing else.**

`connect` prints a link that opens the CloudFormation console with the template already filled in, including an ExternalId that is unique to you. Read the template, tick the IAM acknowledgement, click **Create stack**, and copy the `RoleArn` from the stack's Outputs. Then take the first scan with that ARN.

Terminal:

```
npx emfirge connect
# open the link, create the stack, copy the RoleArn from its Outputs
emfirge context --refresh --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnlyRole --region us-east-1
emfirge context inventory
```

> The account ID is a placeholder. A scan can take 30 to 60 seconds on a real account, and the CLI waits up to 240 seconds. Scans are limited per AWS account per day; the reply says how many remain.

### What the role can do

It carries AWS's managed `SecurityAudit` policy plus a short list of extra read actions: CloudWatch metrics (for usage evidence), IAM Access Analyzer policy checks, and a handful of List, Describe and Get calls. It lists secret names; it has no permission to read their values. The full list is [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml), and a summary is on [Security & privacy](https://emfirge.cloud/security.md#role).

### What it cannot do

It has no write permission of any kind. It cannot create, change or delete a resource, read S3 object contents, or read a secret's value.

### Revoking it

Delete the CloudFormation stack. The role disappears and access ends immediately. Removing the CLI from your machine does not remove the role, so delete the stack too.

## 4. Your first check

**Open a branch, put a change on it, and ask what it did. Production is never touched.**

Here an agent is about to open SSH to the world on a security group. It tries that on a branch first.

Terminal:

```
emfirge branch open --analysis ANALYSIS_ID --name first-try
emfirge try BRANCH_ID --aws-cli "aws ec2 authorize-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0"
emfirge check BRANCH_ID --human
```

`try` answers with what it applied and a verdict, because the change came in as an AWS CLI command:

emfirge try (abridged output from the engine's synthetic test account):

```
{
  "applied": [ "calls[0] ec2.AuthorizeSecurityGroupIngress" ],
  "rejected": [], "unmodeled": [], "unknown_fields": [],
  "verdict": {
    "decision": "block",
    "reasons": [
      { "level": "block", "code": "introduced_critical_finding", "resources": ["SG_001"] },
      { "level": "block", "code": "introduced_critical_exposure", "resources": ["EC2_001"] },
      { "level": "warn", "code": "new_exposure", "resources": ["EC2_001"] }
    ]
  }
}
```

`check` lists the facts, and what it could not check:

emfirge check --human (abridged output from the same account):

```
Branch check: BRANCH_ID (2 change(s))
- data: 0 fact(s), 4 unknown
- exposure: 1 fact(s), 1 unknown
    fact: {"resource_id":"EC2_001","resource_type":"ec2_instance","change":"newly_exposed","protocol":"tcp","ports":[22,22],"so...
    unknown (not checked, not safe): {"topic":"observed_traffic","reason":"observed traffic, host firewalls and application-level controls are not collect...
- money: 0 fact(s), 1 unknown
- availability: 0 fact(s), 3 unknown
- control: 0 fact(s), 2 unknown
- outside_world: 0 fact(s), 2 unknown
changed settings: 3 (1 judged by a check, 2 not judged)
Changed, not judged:
    security_group SG_002: attached_instances
    security_group SG_002: attached_to
```

> Identifiers are tokens (SG_001, EC2_001) because privacy defaults to strict: your agent's model never sees the real IDs. The reason codes and fact kinds are the engine's real ones; the account is synthetic. Exit code is 0 for both: a finding is not an error.

A fact is about the change, not an error. The agent reads it, changes its plan (say, a narrower CIDR or Session Manager instead of SSH), opens a new branch and checks again. See [the CLI reference](https://emfirge.cloud/cli.md#check) for every flag.

## Tell your agent

**Skip the typing. Give your agent this prompt and it reads the page written for it.**

Setup prompt:

```
Set up emfirge in this project. Read https://emfirge.cloud/index.md and follow it.
```

Open the setup prompt in an agent: Claude (https://claude.ai/new?q=Set%20up%20emfirge%20in%20this%20project.%20Read%20https%3A%2F%2Femfirge.cloud%2Findex.md%20and%20follow%20it.), ChatGPT (https://chatgpt.com/?q=Set%20up%20emfirge%20in%20this%20project.%20Read%20https%3A%2F%2Femfirge.cloud%2Findex.md%20and%20follow%20it.), or Cursor.

The deep links open Claude, ChatGPT or Cursor with the prompt filled in. Any agent that can run a shell command works: Claude Code, Codex, Cursor, Gemini CLI. If your client prefers MCP, see the [MCP adapter](https://emfirge.cloud/cli.md#mcp-adapter).

## Next steps

- [How it works](https://emfirge.cloud/how-it-works.md): branches, the six checks, and the record.
- [CLI reference](https://emfirge.cloud/cli.md): every verb, flag and exit code.
- [Coverage](https://emfirge.cloud/coverage.md): which resources a branch can change today.
- [Security & privacy](https://emfirge.cloud/security.md): exactly what the role, the engine and your machine hold.

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
