# Emfirge site (emfirge.cloud)

The website served at emfirge.cloud. Next.js 16, React 19, Tailwind v4. It replaced the old docs site in this folder.
Page content lives in `src/content/*.ts`; facts and sources are in [FACTS.md](./FACTS.md).

## Run

```bash
npm install
npm run dev      # http://localhost:3000
npm run build    # writes the .md files and llms.txt into public/ (prebuild), then next build
npm start        # serve the build (set EMFIRGE_BACKEND_URL; see below)
```

`npm run gen` writes `public/<page>.md`, `public/index.md` and `public/llms.txt` from `src/content`. `prebuild` runs it, so
`npm run build` on Vercel always regenerates them.

## Not a static export

`next.config.ts` has no `output: "export"`, because the site must proxy the API:

- `/api/:path*` is rewritten to `${EMFIRGE_BACKEND_URL ?? "http://localhost:3000"}/:path*`. The CLI and the MCP adapter call
  `https://emfirge.cloud/api`, so set `EMFIRGE_BACKEND_URL` in the deployment environment.
- Old docs URLs (`/docs/...`, `/connect`, `/security.html`, `/guide`) are permanent redirects to the new pages. The table is in
  `next.config.ts`.
- `trailingSlash` is on, but `skipTrailingSlashRedirect` is set so `/api/project` is proxied as sent instead of being redirected to
  `/api/project/`. A slashless page URL (`/quickstart`) serves the page; its canonical link is the slash form.
- The rewrite target is read when `next build` runs, so `EMFIRGE_BACKEND_URL` must be set at build time, not only at runtime.

## Vercel

Project `emfirge-docs`, root directory `site`, framework Next.js, build command `npm run build`, no output directory override.

## Status

Every statement is checked against the merged code; the sources are in [FACTS.md](./FACTS.md). See
[DESIGN.md](./DESIGN.md) for the spec and the short list of things that are still not built or not decided.
