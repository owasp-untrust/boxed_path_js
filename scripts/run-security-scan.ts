#!/usr/bin/env node
import { scanProject } from '../src/enforce.js';

console.log("==================================================");
console.log("🛡️  UNTRUST-TS: BUILD-TIME SECURITY ENFORCEMENT");
console.log("==================================================");

const hasViolations = scanProject('./src') || scanProject('./tests') || scanProject('./');

if (hasViolations) {
    console.error("\n❌ ARCHITECTURAL ERROR: Illegal native imports detected.");
    console.error("The build is blocked. Please use 'untrust-ts' wrappers.");
    process.exit(1); // Non-zero exit code kills the build process
} else {
    console.log("\n✅ ARCHITECTURE VERIFIED: No bypasses found.");
    process.exit(0);
}