# Quickstart. From install to your first check.

Four steps. You install the CLI, sign in, give emfirge a read-only role in your AWS account, and try one change on a branch. Nothing you do here can change your cloud.

Human version: https://emfirge.cloud/quickstart/

*Figure 1. The four steps. Only the last one touches a branch; the role in step 3 is the only thing that can reach your AWS, and it is read-only.*

## 1. Install

**One command. There is nothing to install globally.**

Terminal:

```
npx @emfirge/cli@latest connect
```

You need Node.js 20 or later. `connect` walks through steps 2 and 3 in one go; each step is also its own command (`emfirge login`, then the role link), so an agent or CI job can run them one at a time.

Prefer a permanent command? `npm install -g @emfirge/cli` gives you `emfirge` on your PATH. The CLI is a thin client: the engine is hosted, and the CLI only signs in, tokenizes identifiers on your machine, sends the verb and prints the answer.

## 2. Sign in

**Your browser opens, you sign in with GitHub or Google, and the CLI keeps the session on your machine.**

Terminal:

```
emfirge login
emfirge logout   # to sign out of this device
```

Emfirge never asks for your AWS access keys. The only thing it holds that can reach your account is the role in step 3.

## 3. Create the read-only role

**One CloudFormation click. The role can read your account's configuration and nothing else.**

`connect` prints a link that opens the CloudFormation console with the template already filled in, including an ExternalId that is unique to you. Read the template, click **Create stack**, and paste back (or let the CLI detect) the role ARN.

emfirge connect (example output):

```
$ emfirge connect
  signed in as you@example.com
  Create the read-only role (review it, then click Create stack):
  https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL=…&stackName=emfirge-readonly&param_ExternalId=…
  waiting for the role…  found arn:aws:iam::123456789012:role/EmfirgeReadOnlyRole
  reading us-east-1…     214 resources, 612 relationships
  ready. Try: emfirge branch new first-try
```

> Example output. The account ID is a placeholder and the counts are illustrative.

### What the role can do

It carries AWS's managed `SecurityAudit` policy plus a short list of extra read actions: CloudWatch metrics (for usage evidence), IAM Access Analyzer policy checks, and a handful of List and Describe calls. It lists secret names; it has no permission to read their values. The full list is [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml), and a summary is on [Security & privacy](https://emfirge.cloud/security.md#role).

### What it cannot do

It has no write permission of any kind. It cannot create, change or delete a resource, read S3 object contents, or read a secret's value.

### Revoking it

Delete the CloudFormation stack. The role disappears and access ends immediately. Removing the CLI from your machine does not remove the role, so delete the stack too.

## 4. Your first check

**Open a branch, put a change on it, and ask what it would do. Production is never touched.**

Here an agent is about to open SSH to the world on a security group. It tries that on a branch first.

Terminal (example):

```
$ emfirge branch new first-try
  branch first-try  #1   base: scan of us-east-1 (live)   0 changes

$ emfirge try --aws-cli "aws ec2 authorize-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0"
  applied 1 of 1   unmodeled 0   rejected 0

$ emfirge check
  verdict  BLOCK   branch first-try #1   1 change

  exposure       block  introduced_critical_exposure
                 SSH (22) is open to 0.0.0.0/0 on SG_001, which EC2_001 uses
  data           pass
  money          pass   +$0.00/month, no priced resource changed
  availability   pass
  control        pass
  outside world  pass

  exit 2
```

> Example output. Identifiers are tokens (SG_001, EC2_001) because privacy defaults to strict: your agent's model never sees the real IDs. The reason code is a real one from the engine.

A block is a fact about the change, not an error. The agent reads it, changes its plan (say, a narrower CIDR or Session Manager instead of SSH), opens a new branch and checks again. Only a change that passes goes back to you to apply. See [the CLI reference](https://emfirge.cloud/cli.md#check) for every flag.

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
