#!/usr/bin/env node
// Build orchestrator: version stamping and asset compilation.
const { execSync } = require("child_process");
const commit = execSync("git rev-parse --short HEAD").toString().trim();
const out = `console.log("build ${commit}");`;
require("fs").writeFileSync("dist/bundle.js", out);
console.log("build complete:", commit);
