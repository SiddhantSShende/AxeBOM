/// <reference types="vite/client" />

/**
 * A LOCAL OVERRIDE for OIDC configuration. Not how it is normally supplied.
 *
 * ⚠ THE DEPLOYED APP FETCHES ITS CONFIGURATION FROM GET /api/v1/auth/config.
 *
 * The client id and project id are produced by `axebom iam bootstrap` and
 * differ per ZITADEL instance, so compiling them in would mean one frontend
 * image per environment — and the image is built without build args, so the
 * compiled-in value was the empty string and the container could not sign
 * anybody in at all. See src/lib/auth.ts.
 *
 * These exist only for `npm run dev` against an instance with no gateway in
 * front of it. Setting them BYPASSES the endpoint, so a stale value here is a
 * login that fails in development and works everywhere else.
 *
 * Nothing secret may appear here regardless: a Vite variable is public the
 * moment the bundle is served. An OIDC client id is not a secret — the
 * application is registered with AUTH_METHOD_NONE precisely because a browser
 * cannot hold one — and neither is a project id.
 */
interface ImportMetaEnv {
  /** Origin serving ZITADEL. Defaults to the app's own origin. */
  readonly VITE_OIDC_ISSUER?: string;
  /** The SPA application's client id. Both this and the project id, or neither. */
  readonly VITE_OIDC_CLIENT_ID?: string;
  /** The ZITADEL project id, needed for the audience scope and the roles claim. */
  readonly VITE_OIDC_PROJECT_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
