#!/usr/bin/env node
// The command npm installs. It imports main(), so cli.mjs is never the entry point here: a rejection goes to cli.mjs's
// own exitOnMainRejection, the one copy of the exit-code mapping (a flag refusal exits 2; anything else exits 1).
import { main, exitOnMainRejection } from '../cli.mjs';
main().catch((err) => exitOnMainRejection(err));
