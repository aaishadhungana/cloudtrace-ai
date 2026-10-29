import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0b1220",
        panel: "#111a2b",
        line: "#1f2a3d",
        accent: "#38bdf8",
      },
    },
  },
  plugins: [],
};

export default config;