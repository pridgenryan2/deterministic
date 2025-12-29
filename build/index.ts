await Bun.build({
    entrypoints: ["src/index.ts"],
    outdir: "dist",
    drop: ["console", "debugger"],
    target: "bun",
    minify: true
})