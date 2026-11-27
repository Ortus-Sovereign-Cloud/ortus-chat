import { execSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { defineConfig } from "@playwright/test";

// A throwaway certificate, so the program federates (Matrix) and the
// screens offer sharing with partners; nothing connects to it.
const federation = "test-results/federation";
if (!existsSync(`${federation}/cert.pem`)) {
  mkdirSync(federation, { recursive: true });
  execSync(`openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -keyout ${federation}/key.pem -out ${federation}/cert.pem`, { stdio: "ignore" });
}

// The tests drive a real program with the core and this crate's apps
// (examples/dev.rs), on SQLite in a throwaway directory.
const port = Number(process.env.ORTUS_E2E_PORT ?? 7987);
const binary = process.env.ORTUS_E2E_BINARY ?? "../target/debug/examples/dev";

export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  globalSetup: "./e2e/global-setup.ts",
  use: { baseURL: `http://localhost:${port}`, viewport: { width: 1440, height: 900 }, colorScheme: "dark", timezoneId: "UTC", storageState: "test-results/owner.json" },
  // The escrow spec last, alone: it sets and changes the organisation's
  // escrow key, which a recovery set-up meanwhile would see change, and it
  // gives the owner cross-signing keys the other specs do not expect. It
  // needs the owner's strong sign-in from set-up (ten minutes).
  projects: [
    { name: "chromium", testIgnore: /escrow\.spec\.ts/, use: { browserName: "chromium" } },
    { name: "escrow", testMatch: /escrow\.spec\.ts/, dependencies: ["chromium"], use: { browserName: "chromium" } },
  ],
  webServer: [
    {
      command: `rm -rf test-results/data && ${binary}`,
      env: {
        ORTUS_ROLES: "web,worker",
        ORTUS_WEB_PORT: String(port),
        ORTUS_DATA_DIR: "test-results/data",
        ORTUS_FEDERATION_TLS_CERT: `${federation}/cert.pem`,
        ORTUS_FEDERATION_TLS_KEY: `${federation}/key.pem`,
        ORTUS_FEDERATION_LISTEN: "127.0.0.1:0",
        ORTUS_SETUP_TOKEN: "e2e-setup-token",
        ORTUS_PUBLIC_URL: `http://localhost:${port}`,
      },
      url: `http://127.0.0.1:${port}/api/v1/health`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
