# Set up. What you do, once.

Give emfirge to your agent, approve two things only you can approve, and you are done. Your agent does the rest: it branches, tries a change, checks it, fixes its plan and hands back. Nothing you do here can change your cloud.

Human version: https://emfirge.cloud/quickstart/

*Figure 1. Your four steps. Your agent runs every command; you paste one prompt, approve a sign-in, click once in AWS and then ask as usual. The role in step 3 is the only thing that can reach your AWS, and it is read-only.*

## 1. Paste the prompt

**Give this to your agent. It runs every command and reads the reference written for it.**

Setup prompt:

```
Set up emfirge for my AWS account and use it for every AWS change from now on.
emfirge is a CLI. Run it as `npx -y emfirge <command>` (Node.js 20 or later). Run `npx -y emfirge guide` first; the full reference is https://emfirge.cloud/cli.md.

1. Run `login`. It opens my browser so I can sign in with GitHub or Google. If it does not open, show me the address it prints, then wait for me.
2. Run `connect` and show me the link it prints. I will create the read-only role and send you the role ARN. Ask me which AWS region to use.
3. Run `context --refresh --role-arn ARN --region REGION`, then `context inventory`. Keep the role ARN: later steps need it.

Before any AWS change: open a branch (`branch open`), try the change on it (`try`), and read `check`. Never apply a change that did not pass. If it fails, fix your plan and try again on the branch. Ask me before `check --policy` or `check --evidence`: they cost money. When a change passes, apply it with your own access, run `report`, and tell me what changed.
```

Open the setup prompt in an agent: Claude (https://claude.ai/new?q=Set%20up%20emfirge%20for%20my%20AWS%20account%20and%20use%20it%20for%20every%20AWS%20change%20from%20now%20on.%0Aemfirge%20is%20a%20CLI.%20Run%20it%20as%20%60npx%20-y%20emfirge%20%3Ccommand%3E%60%20(Node.js%2020%20or%20later).%20Run%20%60npx%20-y%20emfirge%20guide%60%20first%3B%20the%20full%20reference%20is%20https%3A%2F%2Femfirge.cloud%2Fcli.md.%0A%0A1.%20Run%20%60login%60.%20It%20opens%20my%20browser%20so%20I%20can%20sign%20in%20with%20GitHub%20or%20Google.%20If%20it%20does%20not%20open%2C%20show%20me%20the%20address%20it%20prints%2C%20then%20wait%20for%20me.%0A2.%20Run%20%60connect%60%20and%20show%20me%20the%20link%20it%20prints.%20I%20will%20create%20the%20read-only%20role%20and%20send%20you%20the%20role%20ARN.%20Ask%20me%20which%20AWS%20region%20to%20use.%0A3.%20Run%20%60context%20--refresh%20--role-arn%20ARN%20--region%20REGION%60%2C%20then%20%60context%20inventory%60.%20Keep%20the%20role%20ARN%3A%20later%20steps%20need%20it.%0A%0ABefore%20any%20AWS%20change%3A%20open%20a%20branch%20(%60branch%20open%60)%2C%20try%20the%20change%20on%20it%20(%60try%60)%2C%20and%20read%20%60check%60.%20Never%20apply%20a%20change%20that%20did%20not%20pass.%20If%20it%20fails%2C%20fix%20your%20plan%20and%20try%20again%20on%20the%20branch.%20Ask%20me%20before%20%60check%20--policy%60%20or%20%60check%20--evidence%60%3A%20they%20cost%20money.%20When%20a%20change%20passes%2C%20apply%20it%20with%20your%20own%20access%2C%20run%20%60report%60%2C%20and%20tell%20me%20what%20changed.), ChatGPT (https://chatgpt.com/?q=Set%20up%20emfirge%20for%20my%20AWS%20account%20and%20use%20it%20for%20every%20AWS%20change%20from%20now%20on.%0Aemfirge%20is%20a%20CLI.%20Run%20it%20as%20%60npx%20-y%20emfirge%20%3Ccommand%3E%60%20(Node.js%2020%20or%20later).%20Run%20%60npx%20-y%20emfirge%20guide%60%20first%3B%20the%20full%20reference%20is%20https%3A%2F%2Femfirge.cloud%2Fcli.md.%0A%0A1.%20Run%20%60login%60.%20It%20opens%20my%20browser%20so%20I%20can%20sign%20in%20with%20GitHub%20or%20Google.%20If%20it%20does%20not%20open%2C%20show%20me%20the%20address%20it%20prints%2C%20then%20wait%20for%20me.%0A2.%20Run%20%60connect%60%20and%20show%20me%20the%20link%20it%20prints.%20I%20will%20create%20the%20read-only%20role%20and%20send%20you%20the%20role%20ARN.%20Ask%20me%20which%20AWS%20region%20to%20use.%0A3.%20Run%20%60context%20--refresh%20--role-arn%20ARN%20--region%20REGION%60%2C%20then%20%60context%20inventory%60.%20Keep%20the%20role%20ARN%3A%20later%20steps%20need%20it.%0A%0ABefore%20any%20AWS%20change%3A%20open%20a%20branch%20(%60branch%20open%60)%2C%20try%20the%20change%20on%20it%20(%60try%60)%2C%20and%20read%20%60check%60.%20Never%20apply%20a%20change%20that%20did%20not%20pass.%20If%20it%20fails%2C%20fix%20your%20plan%20and%20try%20again%20on%20the%20branch.%20Ask%20me%20before%20%60check%20--policy%60%20or%20%60check%20--evidence%60%3A%20they%20cost%20money.%20When%20a%20change%20passes%2C%20apply%20it%20with%20your%20own%20access%2C%20run%20%60report%60%2C%20and%20tell%20me%20what%20changed.), or Cursor.

Copy it, or open it in Claude, ChatGPT or Cursor with the arrow. Your agent needs to be able to run commands on your machine (Claude Code, Codex, Cursor's agent, Gemini CLI): a plain chat window cannot run `npx`. It needs Node.js 20 or later. If your client prefers MCP, see the [MCP adapter](https://emfirge.cloud/cli.md#mcp-adapter).

The prompt points your agent to the full reference at [/cli.md](https://emfirge.cloud/cli.md), the same page as [CLI reference](https://emfirge.cloud/cli.md). You do not need to read it.

## 2. Approve sign-in

**Your agent shows you a link. You sign in with GitHub or Google.**

Your agent runs `emfirge login`. That opens your browser to a sign-in page served on your own machine, where you choose GitHub or Google. If the browser does not open, your agent shows you the address to open. You have 5 minutes. The session is kept in `~/.emfirge/credentials.json` on your machine, so your agent does not need you again unless the sign-in expires.

> The sign-in page lives on the machine where the command runs, so your browser and your agent must be on the same machine. If your agent runs in a remote sandbox, you cannot reach it.

Emfirge never asks for your AWS access keys. The only thing it holds that can reach your account is the role in step 3.

## 3. Create the read-only role

**One click in AWS, then give your agent the role ARN. The role can read your account's configuration and nothing else.**

Your agent runs `emfirge connect` and shows you a link. It opens the CloudFormation console with the template already filled in, including an ExternalId that is unique to you. You do this part because it is your AWS account: emfirge has no access to it until the role exists.

- Open the link. Read the template if you like.
- Tick the IAM acknowledgement and click **Create stack**. It takes about 30 seconds.
- When the stack says `CREATE_COMPLETE`, open its **Outputs** tab and copy the `RoleArn`.
- Paste the `RoleArn` to your agent and tell it which AWS region to look at. Your agent asks if you forget.

`connect` does not find the role by itself, so your agent needs the ARN from you. It then takes the first scan with it. A scan can take 30 to 60 seconds on a real account. Scans are limited per AWS account per day; your agent sees how many remain.

### What the role can do

It carries AWS's managed `SecurityAudit` policy plus a short list of extra read actions: CloudWatch metrics (for usage evidence), IAM Access Analyzer policy checks, and a handful of List, Describe and Get calls. It lists secret names; it has no permission to read their values. The full list is [iam-role.yaml](https://github.com/theanshsonkar/emfirge/blob/main/iam-role.yaml), and a summary is on [Security & privacy](https://emfirge.cloud/security.md#role).

### What it cannot do

It has no write permission of any kind. It cannot create, change or delete a resource, read S3 object contents, or read a secret's value.

### Revoking it

Delete the CloudFormation stack. The role disappears and access ends immediately. Removing emfirge from your machine does not remove the role, so delete the stack too.

## 4. Done: ask as usual

**Ask your agent to change your AWS the way you always do. It handles the rest.**

Before it touches anything real, your agent opens a branch, tries the change on it, checks it and fixes its own plan until the check is clean. Then it applies the change with its own AWS access and tells you what it did. Emfirge never applies anything.

From here you do two things. You read what your agent hands back, and you decide. Your agent should also ask you before a check that costs money (IAM Access Analyzer policy checks, and reads of CloudTrail and CloudWatch use): those show an estimate first and run only after you agree.

> Emfirge is advisory today. It does not stop an agent that has its own AWS credentials, so the prompt tells your agent never to apply a change that did not pass.

## What you'll see

**A short message from your agent, with the facts emfirge gave it.**

Here your agent was asked to open SSH to the world on a security group. It tried that on a branch first.

Your agent's message (abridged and real-shaped; the wording is your agent's):

```
I tried opening SSH (port 22) to 0.0.0.0/0 on SG_001 on a branch first.
emfirge says: block.
  introduced_critical_finding    SG_001
  introduced_critical_exposure   EC2_001
  exposure: EC2_001 newly exposed on tcp 22 from 0.0.0.0/0
  not checked (so not safe): observed traffic, host firewalls
I did not apply it. I changed my plan, opened a new branch and checked again.
```

When a change passes, your agent applies it and runs `emfirge report`. The hand-back ties the exact calls it applied to the verdict they were judged with:

The hand-back, from emfirge report --verify (abridged output from the engine's synthetic test account):

```
{
  "kind": "aws-api-calls",
  "calls": [ { "change_index": 0, "service": "ec2", "operation": "AuthorizeSecurityGroupIngress", … }, … ],
  "input_sha256": "3c467190…",
  "verdict": "warn",
  "verdict_id": "f7dc5a85…",
  "verification": { "ok": true, "verdict": "warn", "verdict_id": "f7dc5a85…" }
}
```

> Names appear as tokens such as SG_001 and EC2_001, because privacy defaults to strict: your agent's model never sees the real identifiers. The map from token to name stays in `~/.emfirge/tokens.json` on your machine. A finding is not an error: a block still exits 0, and your agent reads it as a fact about its plan.

[How the loop works](https://emfirge.cloud/how-it-works.md#loop)

## Without an agent

### Prefer to set it up yourself?

The commands your agent runs are the same ones you can run. You need Node.js 20 or later. Agents add `-y` to skip npx's first-run prompt: `npx -y emfirge ...`.

Terminal:

```
npx emfirge --help
npx emfirge login      # sign in with GitHub or Google in your browser
npx emfirge connect    # print the link that creates the read-only role
```

Open the link, create the stack, copy the `RoleArn` from its Outputs, then take the first scan with it. The account ID below is a placeholder.

Terminal:

```
emfirge context --refresh --role-arn arn:aws:iam::123456789012:role/EmfirgeReadOnlyRole --region us-east-1
emfirge context inventory
```

Then try a change on a branch and ask what it did. Production is never touched.

Terminal:

```
emfirge branch open --analysis ANALYSIS_ID --name first-try
emfirge try BRANCH_ID --aws-cli "aws ec2 authorize-security-group-ingress --group-id SG_001 --protocol tcp --port 22 --cidr 0.0.0.0/0"
emfirge check BRANCH_ID --human
```

`npm install -g emfirge` puts `emfirge` on your PATH. In CI, where no browser can open, set `EMFIRGE_API_KEY` instead of running `login`. Every verb, flag and exit code is in the [CLI reference](https://emfirge.cloud/cli.md).

## Next steps

- [How it works](https://emfirge.cloud/how-it-works.md): the loop your agent runs, the six checks and the record.
- [Coverage](https://emfirge.cloud/coverage.md): which resources a branch can change today.
- [Security & privacy](https://emfirge.cloud/security.md): exactly what the role, the engine and your machine hold.
- [FAQ](https://emfirge.cloud/faq.md): do I need to learn the CLI, and what do I actually do.
- [CLI reference](https://emfirge.cloud/cli.md): the reference your agent reads.

---

All pages as markdown: https://emfirge.cloud/llms.txt. Source: https://github.com/theanshsonkar/emfirge. Contact: ansh@emfirge.cloud.
