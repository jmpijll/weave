# Contributing to Weave

## Prerequisites

- Node.js `24.12.0` or newer; CI uses the pinned `24.12.0` release.

Use `npm exec --yes --package=pnpm@10.13.1 -- pnpm` so the repository's
pinned pnpm version is used without a global install.

## Checks

Before opening a pull request, run:

```sh
npm exec --yes --package=pnpm@10.13.1 -- pnpm install
npm exec --yes --package=pnpm@10.13.1 -- pnpm check
npm exec --yes --package=pnpm@10.13.1 -- pnpm test
```

The combined command is `npm exec --yes --package=pnpm@10.13.1 -- pnpm verify`;
deployment tooling should call that command rather than duplicating the checks.

`check` type-checks the protocol package and all three consumers without
emitting build output. `test` verifies workspace links, executes the server and
daemon entry points, checks the client stub's protocol import, and keeps Node's
type-stripping restriction on non-erasable syntax visible.

## Protocol types

`packages/protocol` is imported by the server, daemon, and client. Keep the
package's source erasable by using string-literal unions and `as const` values;
do not add `enum` or `namespace` declarations. If a relative TypeScript import
is needed, include its explicit `.ts` extension.
