import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['**/*.test.ts', '**/*.spec.ts', '**/node_modules/**'],
      reporter: ['text', 'html', 'json-summary', 'json'],
      reportsDirectory: './coverage',
      thresholds: { lines: 100, functions: 100, statements: 100, branches: 100 },
    },
  },
})
