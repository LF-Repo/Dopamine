void initSpawnHooks(void);

// Rename systemhook.dylib to a per-jailbreak random name and point
// gHookDylibPath at it. Called once from launchdhook's initializer, before any
// process can be spawned with it.
//
// Why: hidejb already rewrites the *in-process* view of this image to a benign
// path (/usr/lib/libSystem.B.N.dylib), so dyld enumeration no longer reveals it.
// What remained visible was the real file on disk, which a detector could find
// by looking for a fixed name under the jailbreak root. The random name removes
// that fixed target without touching the file layout or the injection mechanism.
//
// Safe to fail: if the rename cannot be done, gHookDylibPath keeps the legacy
// path and injection works exactly as before.
void initHookDylibPath(void);