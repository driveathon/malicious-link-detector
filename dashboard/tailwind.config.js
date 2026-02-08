/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                background: "#0a0a0c",
                card: "#121214",
                primary: "#3b82f6",
                danger: "#ef4444",
                success: "#22c55e",
                warning: "#f59e0b",
            },
            backdropBlur: {
                xs: '2px',
            }
        },
    },
    plugins: [],
}
