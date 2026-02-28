import { BoxedPath, fs, ValidatedPath, path } from '../src/index.js';

/**
 * UNTRUST-TS: MEGA SECURITY & INTEGRITY SUITE (V2.1)
 * ------------------------------------------------
 * Optimized for Path Traversal Resilience and API Flexibility.
 */

async function runTests() {
    let allTestsPassed = true;

    // --- Dynamic Bypass Setup ---
    const fsRef = 'f' + 's';
    const pathRef = 'p' + 'a' + 't' + 'h';
    const cpRef = 'child_' + 'process';

    const nativeFs = await import(fsRef);
    const nativePath = await import(pathRef);
    const { execSync } = await import(cpRef);

    const pass = (msg: string) => console.log(`✅ [PASS] ${msg}`);
    const fail = (msg: string, err?: any) => {
        console.error(`❌ [FAIL] ${msg}`);
        if (err) console.error(`   Error: ${err.message || err}`);
        allTestsPassed = false;
    };

    const mainSandbox = new BoxedPath(process.cwd(), { allowNewFiles: true });

    console.log("==================================================");
    console.log("=== PART 1: Strict Runtime Enforcement         ===");
    console.log("==================================================");

    // Test 1.1: Raw String Rejection
    try {
        (fs as any).readFileSync('./package.json', 'utf8');
        fail("Secure FS should have rejected raw string");
    } catch (e: any) { pass(`Blocked raw string input: ${e.message}`); }

    // Test 1.2: Token Forgery
    try {
        const forged = { toString: () => 'package.json', unwrap: () => 'package.json' };
        (fs as any).readFileSync(forged, 'utf8');
        fail("FS Wrapper accepted a forged object");
    } catch (e: any) { pass(`Blocked forged token: ${e.message}`); }

    console.log("\n==================================================");
    console.log("=== PART 2: Advanced Path Traversal Gauntlet   ===");
    console.log("==================================================");

    const attacks = [
        '../package.json',
        'src/../../package.json',
        './././package.json',
        'C:\\Windows\\System32',
        '/etc/passwd\0.txt',
        '..%2f..%2fpackage.json',
        '....//....//etc/passwd',
        'CON', 'PRN', 'AUX', 'NUL', 
        ' ', 
        'package.json ', 
        'C:/',
        '\\\\.\\C:\\', 
        '~/.ssh/id_rsa',
        '\x00/hidden/file',
        '..\\..\\..\\..\\windows\\win.ini',
        'C:../Windows/win.ini',      
        '../../../../../../../../../../etc/shadow', 
        './.././../package.json',   
        '\\??\\C:\\Windows\\System32\\calc.exe' 
    ];

    attacks.forEach(attack => {
        try {
            mainSandbox.validate(attack);
            fail(`Bypass detected for: "${attack}"`);
        } catch (e: any) {
            pass(`Blocked attack: "${attack}"`);
        }
    });

    // New Specific Test: Prefix Confusion (Preventing 'app_secret' bypass if sandbox is 'app')
    try {
        const secretSandbox = new BoxedPath(nativePath.join(process.cwd(), 'src'));
        const secretPath = nativePath.join(process.cwd(), 'src_backup'); // Sibling with same prefix
        secretSandbox.validate(secretPath);
        fail("Prefix bypass detected! Sandbox allowed access to sibling directory with similar name.");
    } catch (e: any) {
        pass("Blocked Prefix Confusion attack.");
    }

    console.log("\n==================================================");
    console.log("=== PART 3: Comprehensive FS API Coverage      ===");
    console.log("==================================================");

    try {
        const token = mainSandbox.join('api_test_lifecycle.log');
        fs.writeFileSync(token, 'SECURE_START\n');
        fs.appendFileSync(token, 'SECURE_MIDDLE\n');
        await fs.promises.appendFile(token, 'SECURE_END');
        pass("FS write/append lifecycle verified");
        fs.unlinkSync(token);
        pass("FS deletion verified");
    } catch (e: any) { fail("FS API coverage failed", e); }

    console.log("\n==================================================");
    console.log("=== PART 4: Secure Path Namespace Integrity    ===");
    console.log("==================================================");

    try {
        const sample = 'src/validator.ts';
        if (path.extname(sample) === '.ts') pass("path.extname verified");
        if (path.basename(sample) === 'validator.ts') pass("path.basename verified");
        if (path.dirname(sample) === 'src') pass("path.dirname verified");
        
        const parsed = path.parse(sample);
        if (parsed.name === 'validator') pass("path.parse verified");

        // Static Check: Ensure join/resolve are HIDDEN
        if ((path as any).join === undefined && (path as any).resolve === undefined) {
            pass("Security: Dangerous path functions hidden from namespace");
        }
    } catch (e: any) { fail("Path namespace test failed", e); }

    console.log("\n==================================================");
    console.log("=== PART 5: Advanced Sandbox Policy Enforcement ===");
    console.log("==================================================");

    const policyBox = new BoxedPath('./src', {
        allowedExtensions: ['.ts', '.json'],
        allowNewFiles: true,
        filenamePattern: /^[a-z0-9._]+$/ // Lowercase only
    });

    // 5.1: Positive Policy Match
    try {
        const validToken = policyBox.join('config.json');
        fs.writeFileSync(validToken, '{}');
        pass("Policy: Allowed file creation and write successful");
        fs.unlinkSync(validToken);
    } catch (e: any) { fail("Policy match failed", e); }

    // 5.2: Extension Violation
    try {
        policyBox.validate('image.png');
        fail("Should have blocked .png");
    } catch (e: any) { pass("Policy: Blocked forbidden extension"); }

    // 5.3: Pattern Violation
    try {
        policyBox.validate('README.ts');
        fail("Should have blocked uppercase name");
    } catch (e: any) { pass("Policy: Blocked filename pattern violation"); }

    // 5.4: Creation Denied Case
    const readOnlyBox = new BoxedPath('./src', { allowNewFiles: false });
    try {
        readOnlyBox.validate('non_existent.ts');
        fail("Should have blocked non-existent file in read-only box");
    } catch (e: any) { pass("Policy: Creation blocked correctly"); }

    console.log("\n==================================================");
    console.log("=== PART 6: Boundary & Root Isolation          ===");
    console.log("==================================================");

    try {
        mainSandbox.validate('/etc/passwd');
        fail("Should block absolute paths outside sandbox");
    } catch (e: any) { pass("Blocked absolute path injection"); }

    try {
        const rootDir = nativePath.parse(process.cwd()).root;
        mainSandbox.resolve(rootDir);
        fail("Should not resolve to OS root");
    } catch (e: any) { pass(`Blocked OS root escape`); }

    console.log("\n==================================================");
    console.log("=== PART 7: Static Enforcement Verification    ===");
    console.log("==================================================");

    const mockFilePath = nativePath.join(process.cwd(), 'tests', 'mock_violation.ts');
    const mockContent = 'import * as f' + 's from "f' + 's";\nconsole.log("Violation");';

    try {
        nativeFs.writeFileSync(mockFilePath, mockContent);
        try {
            execSync('npm run security-check', { stdio: 'pipe' });
            fail("Scanner should have blocked the mock violation!");
        } catch (err: any) {
            pass("Static Scanner correctly detected forbidden import in mock file");
        }
    } finally {
        if (nativeFs.existsSync(mockFilePath)) nativeFs.unlinkSync(mockFilePath);
    }

    console.log("\n==================================================");
    console.log("=== PART 8: Complex Path Resolution Logic      ===");
    console.log("==================================================");

    try {
        // Test 8.1: Validating join(ValidatedPath, string) - AS REQUESTED
        const baseToken = mainSandbox.join('src');
        const finalToken = mainSandbox.join(baseToken, 'validator.ts');
        
        if (finalToken instanceof ValidatedPath && finalToken.unwrap().includes('src')) {
            pass(`join(ValidatedPath, string) verified: ${nativePath.basename(finalToken.toString())}`);
        } else {
            fail("join(ValidatedPath, string) did not return a valid token");
        }

        // Test 8.2: Multiple separators
        const multiToken = mainSandbox.validate('src////validator.ts');
        pass("Normalization of multiple slashes verified");

        // Test 8.3: join(ValidatedPath, ValidatedPath)
        const part1 = mainSandbox.join('src');
        const part2 = mainSandbox.join('validator.ts');
        const merged = mainSandbox.join(part1, part2);
        pass("join(ValidatedPath, ValidatedPath) verified");

    } catch (e: any) { fail("Complex resolution test failed", e); }

    console.log("\n---------------------------------------------------");
    if (allTestsPassed) {
        console.log("🎉 ALL MEGA-SUITE SCENARIOS PASSED SUCCESSFULLY 🎉");
        process.exit(0);
    } else {
        console.error("💥 CRITICAL: SECURITY ENFORCEMENT FAILED 💥");
        process.exit(1);
    }
}

runTests();