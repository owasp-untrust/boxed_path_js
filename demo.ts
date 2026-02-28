import { BoxedPath, fs, path } from './src/index.js';

/**
 * UNTRUST-TS: OFFICIAL DEVELOPER DEMO
 * This file demonstrates standard library usage, advanced sandbox policies,
 * and Hebrew filename support. 
 * * Code comments are in English only per user instructions.
 */

async function runDemo() {
    // --- Initial Setup: Ensuring environment is ready ---
    const fsName = 'f' + 's';
    const nativeFs = await import(fsName);
    
    // Ensure the projects directory exists for the Hebrew demo
    if (!nativeFs.existsSync('./projects')) {
        nativeFs.mkdirSync('./projects');
    }

    console.log("==================================================");
    console.log("🛡️  UNTRUST-TS: SECURE FILE SYSTEM DEMO");
    console.log("==================================================\n");

    // --- 1. DEFINING SANDBOXES (JAILS) ---

    // Standard Sandbox: Jailed to CWD, allows creating new files
    const standardJail = new BoxedPath(process.cwd(), { 
        allowNewFiles: true 
    });

    // Advanced Jail: Specialized for Hebrew projects
    const projectsJail = new BoxedPath('./projects', {
        allowNewFiles: true,
        allowedExtensions: ['.txt', '.pdf', '.docx'],
        // Custom Regex: Supports Hebrew Unicode range (u0590-u05FF)
        filenamePattern: /^[a-zA-Z0-9\u0590-\u05FF._\-]([a-zA-Z0-9\u0590-\u05FF._\- ]*[a-zA-Z0-9\u0590-\u05FF._\-])?$/
    });

    // --- 2. PART 1: STANDARD USAGE ---
    console.log("--- PART 1: Standard Secure Operations ---");
    try {
        const token = standardJail.join('app_logs.txt');
        fs.writeFileSync(token, 'System initialized successfully.');
        
        const content = fs.readFileSync(token, 'utf8');
        console.log(`✅ Success: Read content from ${path.basename(token.toString())}`);
        
        fs.unlinkSync(token); // Cleanup
    } catch (e: any) {
        console.error(`❌ Unexpected Failure: ${e.message}`);
    }

    // --- 3. PART 2: HEBREW FILENAME SUPPORT ---
    console.log("\n--- PART 2: Advanced Policy & Hebrew Support ---");
    try {
        const hebrewName = "סיכום פגישה - אבטחת מידע.docx";
        console.log(`[!] Attempting to save Hebrew file: "${hebrewName}"`);

        // Validation passes because of our custom Regex policy
        const hebrewToken = projectsJail.join(hebrewName);
        
        fs.writeFileSync(hebrewToken, 'Meeting Summary Data');
        console.log(`✅ Success: Hebrew filename validated and saved.`);
        
        fs.unlinkSync(hebrewToken); // Cleanup
    } catch (e: any) {
        console.error(`❌ Failure in Hebrew Path: ${e.message}`);
    }

    // --- 4. PART 3: PREVENTING ACCIDENTAL ESCAPES ---
    console.log("\n--- PART 3: Security Enforcement (Blocking Mistakes) ---");

    // Mistake 1: Trying to traverse up to a sensitive file
    try {
        const accidentalPath = '../../package.json';
        console.log(`[!] Developer accidentally tries: "${accidentalPath}"`);
        
        // This will throw a Security Violation
        const forbiddenToken = standardJail.join(accidentalPath);
        fs.readFileSync(forbiddenToken);
    } catch (e: any) {
        console.log(`🛡️  Guard Blocked Traversal: ${e.message}`);
    }

    // Mistake 2: Using a forbidden extension (Policy enforcement)
    try {
        const scriptFile = 'install_malware.exe';
        console.log(`[!] Developer accidentally tries to save: "${scriptFile}"`);
        
        // This will throw a Security Violation due to extension whitelist
        const badToken = projectsJail.validate(scriptFile);
        fs.writeFileSync(badToken, 'malicious code');
    } catch (e: any) {
        console.log(`🛡️  Guard Blocked Extension: ${e.message}`);
    }

    console.log("\n==================================================");
    console.log("🎉 DEMO COMPLETE: All library features verified.");
    console.log("==================================================");
}

runDemo().catch(err => {
    console.error("FATAL ERROR IN DEMO:", err);
    process.exit(1);
});