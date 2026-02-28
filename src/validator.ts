import * as path from 'path';
import * as fs from 'fs';

/**
 * ValidatedPath: A security token representing a sanitized, verified path.
 * This ensures that only paths processed by the BoxedPath engine can be used in FS operations,
 * effectively preventing raw string injection at runtime.
 */
export class ValidatedPath {
    private readonly validatedString: string;
    constructor(pathValue: string) { this.validatedString = pathValue; }
    public toString(): string { return this.validatedString; }
    public unwrap(): string { return this.validatedString; }
}

/**
 * Configuration options for the Sandbox engine.
 */
export interface BoxedOptions {
    allowedExtensions?: string[]; // Whitelist of allowed file extensions (e.g., ['.json', '.txt'])
    allowNewFiles?: boolean;      // Whether to allow access to paths that don't exist yet
    filenamePattern?: RegExp;     // Custom regex for filename validation
}

/**
 * BoxedPath: The core Sandbox engine that enforces Zero Trust file access.
 * It prevents Path Traversal, Symlink escapes, and Windows reserved name attacks.
 */
export class BoxedPath {
    private readonly baseDirectory: string;
    // Default: Strict alphanumeric, dots, underscores, and hyphens (No spaces or Unicode by default).
    private readonly defaultFilenamePattern = /^[a-zA-Z0-9._\-]+$/;
    private options: BoxedOptions;

    // Windows Reserved Device Names that can lead to system hangs or denial-of-service.
    private readonly reservedNames = [
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ];

    constructor(rootPath: string = process.cwd(), options: BoxedOptions = {}) {
        const resolvedRoot = path.resolve(rootPath);
        // Canonicalize the root path to ensure we work with physical locations.
        this.baseDirectory = fs.existsSync(resolvedRoot) ? fs.realpathSync(resolvedRoot) : resolvedRoot;
        this.options = { allowNewFiles: false, allowedExtensions: [], ...options };
    }

    /**
     * Checks for known attack patterns before any path resolution occurs.
     */
    private detectSuspiciousPatterns(input: string): void {
        // Prevent Null Byte Injection (\0) often used to truncate filenames in lower-level APIs.
        if (input.includes('\0')) {
            throw new Error(`Security Violation: Null byte injection detected.`);
        }
        
        // Block Tilde (~) expansion which might point to sensitive home directories.
        if (input.startsWith('~')) {
            throw new Error(`Security Violation: Home directory escape attempted.`);
        }

        // Detect redundant dot patterns and common obfuscation techniques.
        if (input.includes('././') || input.includes('....')) {
            throw new Error(`Security Violation: Suspicious path pattern detected.`);
        }

        // Block leading/trailing whitespace which Windows might strip to bypass filters.
        if (input.trim() !== input) {
            throw new Error(`Security Violation: Path contains illegal leading or trailing whitespace.`);
        }
    }

    /**
     * Validates the final component of the path against naming policies and OS constraints.
     */
    private validateFilename(input: string, pattern?: RegExp): void {
        const fileName = path.basename(input);
        
        // Prevent access to Windows reserved names (e.g., CON, NUL) regardless of extension.
        const firstPart = fileName.split('.')[0] ?? '';
        const baseNameOnly = firstPart.toUpperCase();
        if (this.reservedNames.includes(baseNameOnly)) {
            throw new Error(`Security Violation: Reserved device name '${baseNameOnly}' is forbidden.`);
        }

        // Apply the naming policy (Default or Custom).
        const regex = pattern || this.options.filenamePattern || this.defaultFilenamePattern;
        if (!regex.test(fileName)) {
            throw new Error(`Security Violation: Filename '${fileName}' violates naming policy.`);
        }
    }

    /**
     * The main validation logic. Enforces boundary isolation and policy compliance.
     */
    public validate(untrustedInput: string, options?: BoxedOptions): ValidatedPath {
        if (!untrustedInput) throw new Error("Security Violation: Empty path provided.");

        // Stage 1: Pre-resolution analysis.
        this.detectSuspiciousPatterns(untrustedInput);

        const effectiveOptions = { ...this.options, ...options };
        const { allowedExtensions = [], filenamePattern, allowNewFiles = false } = effectiveOptions;

        // Stage 2: Normalization. Resolve the path relative to the sandbox root.
        let resolvedPath = path.resolve(this.baseDirectory, untrustedInput);

        // Stage 3: Boundary Enforcement (Prefix Confusion Fix). 
        // We append a trailing separator to the baseDirectory to prevent "Prefix Confusion" 
        // (e.g., preventing '/app' from matching '/app_secret').
        const normalizedBase = path.normalize(this.baseDirectory);
        const baseWithSlash = normalizedBase.endsWith(path.sep) ? normalizedBase : normalizedBase + path.sep;

        if (!resolvedPath.startsWith(baseWithSlash) && resolvedPath !== normalizedBase) {
            throw new Error(`Security Violation: Path traversal or escape detected!`);
        }

        // Stage 4: Filename and Extension validation.
        this.validateFilename(resolvedPath, filenamePattern);

        if (allowedExtensions.length > 0) {
            const ext = path.extname(resolvedPath).toLowerCase();
            if (!allowedExtensions.includes(ext)) {
                throw new Error(`Security Violation: Forbidden extension '${ext}'.`);
            }
        }

        // Stage 5: Filesystem Integrity. Resolve symlinks and verify the real physical location.
        if (fs.existsSync(resolvedPath)) {
            try {
                const real = fs.realpathSync(resolvedPath);
                // Final boundary check after following symlinks to prevent "Jailbreaking".
                if (!real.startsWith(baseWithSlash) && real !== normalizedBase) {
                    throw new Error(`Security Violation: Symlink escape detected.`);
                }
                resolvedPath = real;
            } catch (e) {
                throw new Error(`Security Violation: Unable to verify physical path.`);
            }
        } else if (!allowNewFiles) {
            // Default Deny: If the file doesn't exist and we don't allow creation, block it.
            throw new Error(`Security Violation: File does not exist.`);
        }

        return new ValidatedPath(resolvedPath);
    }

    /**
     * Secure wrapper for path.join. Validates the result.
     */
    public join(...paths: (string | ValidatedPath)[]): ValidatedPath {
        const stringPaths = paths.map(p => p.toString());
        return this.validate(path.join(...stringPaths));
    }

    /**
     * Secure wrapper for path.resolve. Validates the result relative to the sandbox.
     */
    public resolve(...paths: (string | ValidatedPath)[]): ValidatedPath {
        const stringPaths = paths.map(p => p.toString());
        return this.validate(path.resolve(this.baseDirectory, ...stringPaths));
    }
}