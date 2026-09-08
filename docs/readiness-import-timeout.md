# Stalled draft-file reads

Worksheet draft imports have a five-second asynchronous read deadline, in addition to the existing 1 MiB input cap. A stalled read restores the editing/export controls and preserves current answers. A later completion of that old read is ignored and cannot replace a newer draft. A failed read uses a fixed message rather than reflecting filesystem error text.

This deadline bounds how long the worksheet waits; it does not cancel the browser or operating system's underlying file operation, preempt synchronous JavaScript, or establish a security sandbox. Save a file to approved local storage before retrying a slow remote-file import. Verify exported files before leaving; answers remain tab-memory only.

The consuming web-server's real Chromium regression test deliberately stalls a File read, exercises the deadline, exports the preserved answers, imports a newer packet and releases the old read afterwards to verify it cannot overwrite that newer state.
