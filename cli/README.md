# emfirge

The harness between AI agents and your cloud. Read-only by design.

You run two commands, once:

```
npx emfirge login
npx emfirge connect
```

Then you talk to your agent as usual. The agent uses `emfirge context`,
`emfirge branch`, `emfirge try` and `emfirge check` to see what is true in your
AWS, try a change on a branch, and see what it would break before it touches
anything real. Agents add `-y` to skip npx's first-run prompt: `npx -y emfirge ...`.

## Using Emfirge where browser sign-in can't work

A cloud agent session or CI has no browser, and `emfirge login` needs one (it waits for a callback on 127.0.0.1).
Sign in once on your own computer, which has a browser (`emfirge login`), then make a key for your own project there.
Creating keys needs that browser sign-in: a call made with an API key is refused, so a leaked key cannot make more keys.

```
emfirge key create --name ci
```

The key is shown once. Store it as `EMFIRGE_API_KEY` in your environment's secret settings. Never paste it into a chat
or commit it. Where the key is set, the CLI uses it and skips browser sign-in. `emfirge key list` shows your keys
(never the key itself); `emfirge key revoke KEY_ID` stops one at once. `list` and `revoke` also work with a key. A project can hold 10 active keys.
`key create` is the only command that prints a key; every other output masks `emf_...` values.

The list of commands comes from the Emfirge server, so a new command shows up
in `emfirge --help` without you installing anything. A copy of the list is built
in for when the server cannot be reached. Run `npx emfirge@latest` only when
emfirge tells you to (exit code 6: "needs a newer emfirge").

The code is built from the same source as the Emfirge MCP server (`mcp/src/cli` in the
repository). This package is one self-contained file with no dependencies.
