import * as path from 'path';
import { PathValidator } from '../src/validator.js';
import * as securePath from '../src/index.js';

function runTests() {
    let allTestsPassed = true;

    // Helper functions for logging
    const pass = (msg: string) => console.log(`✅ [PASS] ${msg}`);
    const fail = (msg: string, err?: any) => {
        console.error(`❌ [FAIL] ${msg}`);
        if (err) console.error(`   Error: ${err.message}`);
        allTestsPassed = false;
    };

    console.log("==================================================");
    console.log("=== PART 1: Core Logic & Security (Unit Tests) ===");
    console.log("==================================================");
    
    const safeRoot = './';
    const validator = new PathValidator(safeRoot);

    // Test 1: Standard Validation
    try {
        const result = validator.validate('src/validator.ts');
        pass(`Existing file validated: ${result}`);
    } catch (e: any) { fail('Should validate existing file', e); }

    // Test 2: Path Traversal
    try {
        validator.validate('../../etc/passwd');
        fail('Traversal should have been blocked!');
    } catch (e: any) { pass(`Blocked Traversal: ${e.message}`); }

    // Test 3: Null Byte
    try {
        validator.validate('safe.txt\0.malicious');
        fail('Null byte should be blocked');
    } catch (e: any) { pass(`Blocked Null Byte: ${e.message}`); }


    console.log("\n==================================================");
    console.log("=== PART 2: Drop-in Replacement (Namespace)    ===");
    console.log("==================================================");
    
    // Test 4: securePath.join
    try {
        const result = securePath.join('src', 'index.ts');
        pass(`securePath.join worked: ${result}`);
    } catch (e: any) { fail('securePath.join failed', e); }

    // Test 5: securePath.resolve attack
    try {
        securePath.resolve('/bin/bash');
        fail('securePath.resolve should block absolute paths outside root');
    } catch (e: any) { pass(`Blocked absolute path attack: ${e.message}`); }

    // Test 6: Win32 Backdoor (Verifying the fix in index.ts)
    try {
        securePath.win32.join('src', '../../windows/system32');
        fail('win32 namespace should be secured');
    } catch (e: any) { pass(`Blocked win32 backdoor: ${e.message}`); }


    console.log("\n==================================================");
    console.log("=== PART 3: Advanced Options (Local Scope)     ===");
    console.log("==================================================");

    // Test 7: Allow New Files (Local)
    try {
        const newFile = validator.validate('ghost-file.log', { allowNewFiles: true });
        pass(`Allowed new file creation locally: ${newFile}`);
    } catch (e: any) { fail('Local allowNewFiles failed', e); }

    // Test 8: Custom Regex (Local) + New File
    try {
        const hebName = 'שלום.txt';
        const hebRegex = /^[a-zA-Z0-9\u0590-\u05FF._\- ]+$/;
        
        validator.validate(hebName, { 
            filenamePattern: hebRegex,
            allowNewFiles: true 
        });
        pass(`Allowed Hebrew filename locally`);
    } catch (e: any) { fail('Local filenamePattern failed', e); }


    console.log("\n==================================================");
    console.log("=== PART 4: Global Configuration Lifecycle     ===");
    console.log("==================================================");

    // Ensure clean state
    securePath.reset();

    // [Step A] Global Regex + New Files allowed
    console.log("\n[Step A] Configuring Hebrew Support Globally...");
    securePath.configure(null, true, /^[a-zA-Z0-9\u0590-\u05FF._\- ]+$/);

    try {
        securePath.join('תיקיה', 'קובץ.txt');
        pass('Global Hebrew support working');
    } catch (e: any) { fail('Global Hebrew config failed', e); }

    try {
        securePath.join('hack<>.txt');
        fail('Global Regex should still block illegal chars');
    } catch (e: any) { pass('Illegal chars still blocked'); }


    // [Step B] Incremental Update (Extensions)
    console.log("\n[Step B] Adding '.json' restriction (Incremental Update)...");
    securePath.configure(['.json'], null, null);

    try {
        try {
            securePath.join('data.txt'); 
            fail('Should block .txt files now');
        } catch (e) { pass('Blocked .txt correctly'); }

        // Should still allow Hebrew and New Files (from Step A)
        const result = securePath.join('מידע.json'); 
        pass('Hebrew settings persisted after extension update');
    } catch (e: any) { fail('Incremental update broke previous settings', e); }


    // [Step C] Checking Local Override Priority
    console.log("\n[Step C] Checking Local Override Priority...");
    try {
        validator.validate('readme.txt', { 
            allowedExtensions: ['.txt'],
            allowNewFiles: true 
        });
        pass('Local options overrode global restrictions');
    } catch (e: any) { fail('Local override failed', e); }


    // [Step D] Reset
    console.log("\n[Step D] Testing RESET function...");
    securePath.reset();

    try {
        try {
            securePath.join('ghost.json');
            fail('Reset failed: New files still allowed');
        } catch (e) { pass('Reset confirmed: New files blocked'); }

        try {
            securePath.join('שלום.json');
            fail('Reset failed: Hebrew still allowed');
        } catch (e) { pass('Reset confirmed: Hebrew blocked'); }

    } catch (e: any) { fail('Reset verification failed', e); }


    console.log("\n==================================================");
    console.log("=== PART 5: Nasty Edge Cases & Anomalies       ===");
    console.log("==================================================");

    // Test 13: "The Slash Flood"
    try {
        const result = securePath.join('src', '////', 'index.ts');
        if (result.endsWith('src' + path.sep + 'index.ts')) {
            pass(`Handled slash flood correctly`);
        } else {
            fail(`Slash flood resulted in weird path: ${result}`);
        }
    } catch (e: any) { fail('Slash flood caused crash', e); }


    // Test 14: "The Dotty Filename"
    try {
        const oddFile = validator.validate('config...json', { allowNewFiles: true });
        pass(`Handled triple-dot filename correctly: ${oddFile}`);
    } catch (e: any) { fail('Triple-dot filename caused error', e); }


    // Test 15: "The Empty Block"
    try {
        // Empty array means "Allow Nothing"
        validator.validate('safe.txt', { allowedExtensions: [] });
        fail('Empty extension list [] should block everything!');
    } catch (e: any) { 
        pass(`Empty extension list correctly blocked file: ${e.message}`); 
    }


    // Test 16: "The Deep Fake"
    try {
        // Trying to create a file deeply nested in non-existent folders
        const deepPath = validator.validate('a/b/c/new-file.txt', { allowNewFiles: true });
        pass(`Handled deep non-existent path: ${deepPath}`);
    } catch (e: any) { fail('Deep non-existent path failed', e); }


    // Test 17: "Root Escape"
    try {
        const fsRoot = path.parse(process.cwd()).root; // Get C:\ or /
        securePath.resolve(fsRoot);
        fail('Should not be able to resolve filesystem root outside jail');
    } catch (e: any) { pass(`Blocked escape to filesystem root: ${e.message}`); }


    console.log("\n---------------------------------------------------");
    if (allTestsPassed) {
        console.log("🎉 ALL TESTS PASSED SUCCESSFULLY 🎉");
        process.exit(0);
    } else {
        console.error("💥 SOME TESTS FAILED 💥");
        process.exit(1);
    }
}

runTests();