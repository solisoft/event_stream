/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/views/**/*.{html,slv,erb}",
    "./public/js/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        paper: "#F3F4F1",
        ink: "#141821",
        graphite: "#4B5361",
        rule: "#D9DCD7",
        cobalt: "#2340D8",
        commit: "#17845A",
      },
      fontFamily: {
        display: ['"IBM Plex Sans Condensed"', '"Arial Narrow"', "sans-serif"],
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      maxWidth: {
        site: "1240px",
      },
    },
  },
  plugins: [],
}
