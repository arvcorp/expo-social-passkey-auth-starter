# Expo Social & Passkey Auth Starter

A portable authentication module for an Expo mobile app with an Express/PostgreSQL server. It supports:

- Google Sign-In: Android native Play Services and iOS/web OAuth flow
- Apple Sign In: native iOS
- Passkeys: registration, sign-in, credential management, iOS associated domains, and Android asset links

It deliberately contains **no credentials, app identifiers, domains, users, or production configuration**.

## Quick start

1. Copy this entire `auth-starter/` directory into the target project.
2. Run the SQL files in `db/` against the target PostgreSQL database.
3. Install the packages listed in [Dependencies](#dependencies).
4. Implement the small `AuthUserStore` adapter required by `server/auth-routes.ts`.
5. Mount `createAuthRouter()` and `createPasskeyAssociationRouter()` in the target Express app.
6. Add the mobile helpers from `mobile/` to the Expo project.
7. Replace all placeholder values in `.env.example` and `mobile/app.json.fragment.json`.
8. Build an Android/iOS native binary. Expo Go cannot test Apple Sign In or passkeys.

## Folder layout

```text
auth-starter/
├── db/
│   ├── 001_social_auth.sql
│   └── 002_passkey_credentials.sql
├── mobile/
│   ├── app.json.fragment.json
│   ├── auth-client.ts
│   └── use-google-sign-in.ts
├── server/
│   └── auth-routes.ts
├── .env.example
└── README.md
```

## Dependencies

### Server

```sh
npm install @simplewebauthn/server apple-signin-auth express express-session google-auth-library pg
```

### Expo mobile app

```sh
npx expo install expo-apple-authentication expo-auth-session expo-web-browser
npm install @react-native-google-signin/google-signin react-native-passkey
```

Use `npx expo install` for Expo packages so their versions match the target Expo SDK.

## Server integration

`server/auth-routes.ts` intentionally does not import an app-specific user model. Instead, implement its `AuthUserStore` interface with the target app's existing database layer:

```ts
import express from "express";
import session from "express-session";
import { Pool } from "pg";
import {
  createAuthRouter,
  createPasskeyAssociationRouter,
  type AuthUserStore,
} from "./auth-starter/server/auth-routes";

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Configure a real persistent session store in production, such as PostgreSQL or Redis.
app.use(session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
}));

const userStore: AuthUserStore = {
  // Implement these methods with the target app's users table/repository.
  findByProvider: async () => null,
  findByEmail: async () => null,
  createSocialUser: async () => {
    throw new Error("Implement createSocialUser for this project");
  },
  findById: async () => null,
};

const config = {
  googleClientIds: process.env.GOOGLE_CLIENT_IDS!.split(",").map((value) => value.trim()),
  appleClientId: process.env.APPLE_CLIENT_ID!,
  passkeyRpId: process.env.PASSKEY_RPID!,
  passkeyRpName: process.env.PASSKEY_RP_NAME || "Your App",
  passkeyOrigins: process.env.PASSKEY_ORIGINS!.split(",").map((value) => value.trim()),
  appleAppId: process.env.APPLE_APP_ID!,
  androidPackageName: process.env.ANDROID_PACKAGE_NAME!,
  androidCertificateFingerprints: process.env.ANDROID_CERTIFICATE_FINGERPRINTS!
    .split(",")
    .map((value) => value.trim()),
};

app.use("/api/auth", createAuthRouter({ pool, userStore, config }));
app.use(createPasskeyAssociationRouter(config));
```

The auth module creates a session after a verified sign-in. Regenerate the session ID at login if your existing session layer supports it.
It installs its own `application/json` parser for its routes, so the Google, Apple, and passkey POST bodies work even when the host has not added a global JSON parser.

## Starter smoke test

After copying the folder into a TypeScript project with the listed server dependencies, run:

```sh
npx tsx --test auth-starter/server/auth-routes.smoke.test.ts
```

This starts an isolated Express app and confirms JSON requests reach the Google, Apple, passkey registration, and passkey sign-in POST routes. It deliberately uses malformed credentials and never contacts a real provider.

## Mobile integration

- Use `createAuthRequest()` from `mobile/auth-client.ts` with the target app's API base URL.
- Use `useGoogleSignIn()` from `mobile/use-google-sign-in.ts` for the Google button.
- Call `signInWithApple()`, `signInWithPasskey()`, and `registerPasskey()` from your screen or profile settings.
- After a successful response, save the returned user through the target app's own auth/session context.

The request helper uses `credentials: "include"`. If the target React Native app uses a custom HTTP client or bearer-token authentication, pass an adapter that preserves the server session correctly.

## Google setup

1. Create separate Google OAuth clients for web, iOS, and Android.
2. Register the target Android package name and signing certificate SHA-1/SHA-256 with the Android client.
3. Register the target iOS bundle identifier with the iOS client.
4. Put only public client IDs in the Expo build environment:
   - `EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID`
   - `EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID`
   - `EXPO_PUBLIC_GOOGLE_ANDROID_CLIENT_ID`
5. Set the same IDs, comma-separated, in the server-only `GOOGLE_CLIENT_IDS` variable.
6. Add the iOS reversed client URL scheme to the Google Sign-In Expo plugin config.

Android uses the native Play Services flow. Do not use a browser custom-scheme redirect for Android OAuth; Google blocks that pattern for Android clients.

## Apple setup

1. In Apple Developer, enable **Sign in with Apple** for the target iOS App ID.
2. Use that bundle identifier as `APPLE_CLIENT_ID` when the app uses native Apple Sign In.
3. Add `expo-apple-authentication` to the target app.
4. Test on a real iOS device or TestFlight. Apple Sign In does not work in Expo Go.
5. Apple supplies a user's name and email only on the first consent. Persist them immediately and support Apple relay email addresses.

## Passkey setup

Passkeys are tied to a real HTTPS domain and native app identity. They are unavailable in Expo Go.

1. Choose one HTTPS domain, such as `auth.example.com`, and set it as `PASSKEY_RPID`.
2. Set `PASSKEY_ORIGINS` to `https://auth.example.com` plus any valid native Android origin required by the passkey library.
3. Set `APPLE_APP_ID` to `<APPLE_TEAM_ID>.<IOS_BUNDLE_IDENTIFIER>`.
4. Add `webcredentials:auth.example.com` to iOS associated domains.
5. Serve `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json` from the same domain. The supplied association router handles both.
6. Set `ANDROID_PACKAGE_NAME` and every applicable signing fingerprint in `ANDROID_CERTIFICATE_FINGERPRINTS`, including the Play App Signing fingerprint when using Google Play.
7. Build and install a native development, preview, or production build. Test registration, sign-out/sign-in, deletion, and recovery.

The domain, iOS bundle ID, Android package ID, and signing fingerprints must match exactly.

## Security requirements

- Never commit `.env` files, provider secrets, private keys, session secrets, or production app identifiers.
- Fail startup when required server configuration is missing; do not use a fallback session secret.
- Use a persistent session store (PostgreSQL or Redis), `httpOnly` cookies, HTTPS in production, and deliberate `sameSite` cookie settings.
- Verify Google ID tokens server-side. Do **not** trust a client-supplied profile object.
- Verify Apple identity tokens server-side against the expected audience.
- Keep WebAuthn challenges in the server session and validate origin, RP ID, public key, and signature counter.
- Apply rate limits to every authentication endpoint in the host app.
- Do not automatically link a social identity to a matching email address. Provider linking must require the user to already be authenticated and to explicitly confirm the action.

## Publishing this starter

This folder is designed to be copied into a new Replit project or moved into its own repository. Before making a public repository or template:

1. Search the entire starter for real domains, bundle IDs, client IDs, secrets, and branding.
2. Keep `.env.example` as placeholders only.
3. Publish the `auth-starter/` folder as the repository root, or copy it into the target project.
4. Follow this guide with fresh provider credentials and a fresh native build for every target app.