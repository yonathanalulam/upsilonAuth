import { defineConfig, devices } from "@playwright/test";

const externalBaseURL = process.env.PLAYWRIGHT_BASE_URL;

export default defineConfig({
  testDir: "./tests",
  webServer: externalBaseURL ? undefined : {
    command: "npm run start -- --hostname 0.0.0.0 --port 3100",
    url: "http://localhost:3100",
    reuseExistingServer: false,
  },
  use: {
    baseURL: externalBaseURL ?? "http://localhost:3100",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile",
      use: { ...devices["Desktop Chrome"], viewport: { width: 390, height: 844 }, isMobile: true },
    },
  ],
});
