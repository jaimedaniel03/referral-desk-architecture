import { defineConfig } from 'vitest/config';
// /excerpts holds read-only production artifacts (they import the private app);
// only /tests is runnable here.
export default defineConfig({ test: { include: ['tests/**/*.test.ts'], globals: true } });
