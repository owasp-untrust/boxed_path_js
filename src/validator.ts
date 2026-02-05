import * as path from 'path';
import * as fs from 'fs';

export interface ValidatorOptions {
    allowedExtensions?: string[];
    allowNewFiles?: boolean;
    filenamePattern?: RegExp;
}

export class PathValidator {
    private readonly baseDirectory: string;
    private readonly defaultFilenamePattern = /^[a-zA-Z0-9._\- ]+$/;
    
    // Storage for global configuration
    private globalOptions: ValidatorOptions = {};

    constructor(rootPath: string) {
        try {
             if (fs.existsSync(rootPath)) {
                this.baseDirectory = fs.realpathSync(rootPath);
             } else {
                this.baseDirectory = path.resolve(rootPath);
             }
        } catch (error) {
            this.baseDirectory = path.resolve(rootPath);
        }
    }

    /**
     * Updates the global configuration.
     * Merges new options with existing ones.
     */
    public setGlobalOptions(options: ValidatorOptions): void {
        const cleanOptions: ValidatorOptions = {};
        
        if (options.allowedExtensions) cleanOptions.allowedExtensions = options.allowedExtensions;
        if (options.allowNewFiles !== undefined && options.allowNewFiles !== null) cleanOptions.allowNewFiles = options.allowNewFiles;
        if (options.filenamePattern) cleanOptions.filenamePattern = options.filenamePattern;

        this.globalOptions = { ...this.globalOptions, ...cleanOptions };
    }

    /**
     * Resets the global configuration to default secure values.
     * Clears all custom settings.
     */
    public resetGlobalOptions(): void {
        this.globalOptions = {};
    }

    private validateFilenameCharacters(input: string, pattern?: RegExp): void {
        const fileName = path.basename(input);
        const regex = pattern || this.globalOptions.filenamePattern || this.defaultFilenamePattern;

        if (!regex.test(fileName)) {
            throw new Error(`Security Violation: Filename '${fileName}' contains forbidden characters.`);
        }
    }

    private validateExtension(filePath: string, allowedExtensions?: string[]): void {
        if (!allowedExtensions || allowedExtensions.length === 0) return;

        const ext = path.extname(filePath).toLowerCase();
        if (!allowedExtensions.includes(ext)) {
            throw new Error(`Security Violation: Extension '${ext}' is not in the allow-list.`);
        }
    }

    public validate(untrustedInput: string, options?: ValidatorOptions): string {
        // Merge explicit options with global options
        const effectiveOptions = { ...this.globalOptions, ...options };

        this.validateFilenameCharacters(untrustedInput, effectiveOptions.filenamePattern);

        let resolvedPath = path.resolve(this.baseDirectory, untrustedInput);

        if (effectiveOptions.allowedExtensions) {
            this.validateExtension(resolvedPath, effectiveOptions.allowedExtensions);
        }

        if (fs.existsSync(resolvedPath)) {
            try {
                resolvedPath = fs.realpathSync(resolvedPath);
            } catch (error) {
                throw new Error(`Security Violation: Unable to resolve real path.`);
            }
        } else {
            const allowCreation = effectiveOptions.allowNewFiles === true;

            if (!allowCreation) {
                 throw new Error(`Security Violation: File does not exist and 'allowNewFiles' is disabled.`);
            }

            let parentDir = path.dirname(resolvedPath);
            while (!fs.existsSync(parentDir) && parentDir !== this.baseDirectory && parentDir !== path.parse(parentDir).root) {
                parentDir = path.dirname(parentDir);
            }

            if (fs.existsSync(parentDir)) {
                const realParent = fs.realpathSync(parentDir);
                if (!realParent.startsWith(this.baseDirectory)) {
                     throw new Error(`Security Violation: Parent directory traversal detected!`);
                }
            }
            
            if (!resolvedPath.startsWith(this.baseDirectory)) {
                throw new Error(`Security Violation: Path traversal detected!`);
            }
            return resolvedPath;
        }

        if (!resolvedPath.startsWith(this.baseDirectory)) {
            throw new Error(`Security Violation: Path traversal detected!`);
        }

        return resolvedPath;
    }

    public join(...paths: string[]): string {
        const unsafePath = path.join(...paths);
        return this.validate(unsafePath);
    }

    public resolve(...paths: string[]): string {
        const unsafeResolvedPath = path.resolve(this.baseDirectory, ...paths);
        return this.validate(unsafeResolvedPath);
    }
}