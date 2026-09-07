// Private subprocess entrypoint. NOT a hostile-code sandbox; fd 3 is untrusted.
import { writeFileSync } from 'node:fs';
import { inspectBindings } from './runtime-probe.mjs';
try {
  const bindings = await import(process.env.CANONICAL_PROBE_CHILD_MODULE);
  const result = inspectBindings(process.env.CANONICAL_PROBE_CHILD_TARGET, bindings, Number(process.env.CANONICAL_PROBE_CHILD_MAXIMUM));
  writeFileSync(3, JSON.stringify(result));
  process.exit(0);
} catch {
  process.exit(1);
}
