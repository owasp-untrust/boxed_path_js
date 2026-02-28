import * as fs from 'fs';
import * as path from 'path';

/**
 * scanProject: Scans the directory recursively for native 'fs' usage.
 * Returns true if any violations are found.
 */
export function scanProject(dir: string): boolean {
    let violationFound = false;
    
    // Patterns to detect native 'fs' or 'node:fs' imports/requires
    const restrictedPatterns = [
        /import\s+.*\s+from\s+['"](node:)?fs['"]/, 
        /require\(['"](node:)?fs['"]\)/
    ];

    // Explicit directories to ignore to prevent false positives and infinite loops
    const ignoredDirs = ['node_modules', 'dist', '.git'];

    // Use withFileTypes to get Dirent objects (faster, avoids extra statSync calls)
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
            // Check only the directory name, not the full path
            if (ignoredDirs.includes(entry.name)) continue;
            
            // Recursive scan
            if (scanProject(fullPath)) {
                violationFound = true;
            }
        } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
            
            // Whitelist: The library's core files and the scanner script itself MUST use native fs
            const whitelist = ['enforce.ts', 'fs.ts', 'validator.ts', 'index.ts', 'run-security-scan.ts'];
            if (whitelist.includes(entry.name)) continue;

            const content = fs.readFileSync(fullPath, 'utf8');
            
            if (restrictedPatterns.some(regex => regex.test(content))) {
                // ANSI Color coding for better visibility in terminal
                console.error(`\x1b[31m[SECURITY VIOLATION]\x1b[0m Forbidden native access in: ${fullPath}`);
                violationFound = true;
            }
        }
    }
    
    return violationFound;
}