import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        // Two projects: tsconfig.json covers src/, tsconfig.node.json covers
        // the build tooling. Type-checked lint rules need every linted file to
        // belong to a project, and vite.config.ts belongs to neither by default.
        project: ['./tsconfig.json', './tsconfig.node.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],

      // Server data comes from a generated OpenAPI client; a floating promise
      // in a data path is a silently dropped error the user never sees.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // API responses are typed. Reaching for `any` here means the generated
      // types are wrong, and fixing them is the actual work.
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
);
