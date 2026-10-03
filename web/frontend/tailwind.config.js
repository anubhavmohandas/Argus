/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Argus dossier palette — dark terminal feel
        base: "#0b0e14",
        panel: "#11151f",
        panel2: "#161b27",
        edge: "#232a3a",
        ink: "#e6e9ef",
        mute: "#8a93a6",
        accent: "#5eead4", // argus teal
        // severity scale
        critical: "#ff4d6d",
        high: "#ff8a4c",
        medium: "#ffd43b",
        low: "#4cc9f0",
        info: "#6b7280",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
