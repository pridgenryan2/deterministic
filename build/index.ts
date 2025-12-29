type PackageJson = {
  name?: string;
  version?: string;
};

const runCommand = async (command: string, args: string[]) => {
  const proc = Bun.spawn([command, ...args], {
    stdout: "inherit",
    stderr: "inherit"
  });
  const exitCode = await proc.exited;
  if (exitCode !== 0) {
    throw new Error(`Command failed: ${command} ${args.join(" ")}`);
  }
};

const buildResult = await Bun.build({
  entrypoints: ["src/index.ts"],
  outdir: "dist",
  drop: ["console", "debugger"],
  target: "bun",
  minify: true
});

if (!buildResult.success) {
  throw new Error("Build failed");
}

const packageJson = (await Bun.file("package.json").json()) as PackageJson;
const packageName = packageJson.name ?? "package";
const packageVersion = packageJson.version ?? "0.0.0";
const safeName = packageName.replace(/^@/, "").replace(/\//g, "-");
const archiveName = `${safeName}-${packageVersion}.tgz`;
const stagingDir = "package";

await runCommand("rm", ["-rf", stagingDir]);
await runCommand("mkdir", ["-p", `${stagingDir}/dist`]);
await runCommand("cp", ["package.json", `${stagingDir}/`]);
await runCommand("cp", ["-R", "dist/.", `${stagingDir}/dist/`]);
await runCommand("tar", ["-czf", archiveName, "-C", stagingDir, "."]);
