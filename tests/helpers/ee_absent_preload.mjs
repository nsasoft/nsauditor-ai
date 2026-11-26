// A PRELOAD FOR A SPAWNED CLI (`node --import <this> cli.mjs …`): the Enterprise package does not resolve, whatever the
// checkout holds. Every resolution of `@nsasoft/nsauditor-ai-ee` (or a path inside it) fails with ERR_MODULE_NOT_FOUND —
// the code Node gives a package that is not installed — so the real CLI runs exactly as on a Community-only install.
// Driven before use: with it, `scan --plugins …,1023` exits 2 naming 1023 and writes no record; without it, on a checkout
// where Enterprise resolves, the same command writes one.
// A `.mjs` under tests/helpers/, never `*.test.mjs`: the suite glob does not run it.
import { registerHooks } from 'node:module';

const EE = '@nsasoft/nsauditor-ai-ee';
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === EE || specifier.startsWith(`${EE}/`)) {
      throw Object.assign(new Error(`Cannot find package '${specifier}' (made absent by tests/helpers/ee_absent_preload.mjs)`),
        { code: 'ERR_MODULE_NOT_FOUND' });
    }
    return nextResolve(specifier, context);
  },
});
