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

The list of commands comes from the Emfirge server, so a new command shows up
in `emfirge --help` without you installing anything. A copy of the list is built
in for when the server cannot be reached. Run `npx emfirge@latest` only when
emfirge tells you to (exit code 6: "needs a newer emfirge").

All the code lives in [`@emfirge/mcp`](https://www.npmjs.com/package/@emfirge/mcp);
this package only gives it the short name.
