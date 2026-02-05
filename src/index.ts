import * as path from 'path';
import { PathValidator, ValidatorOptions } from './validator.js';

// Create the global singleton validator
const validator = new PathValidator(process.cwd());

export function configure(
    allowedExtensions?: string[] | null,
    allowNewFiles?: boolean | null,
    filenamePattern?: RegExp | null
): void {
    const options: ValidatorOptions = {};

    if (allowedExtensions) {
        options.allowedExtensions = allowedExtensions;
    }
    
    if (allowNewFiles !== null && allowNewFiles !== undefined) {
        options.allowNewFiles = allowNewFiles;
    }

    if (filenamePattern) {
        options.filenamePattern = filenamePattern;
    }

    validator.setGlobalOptions(options);
}

export function reset(): void {
    validator.resetGlobalOptions();
}

// Export the secure drop-in replacements
export const join = (...paths: string[]) => validator.join(...paths);
export const resolve = (...paths: string[]) => validator.resolve(...paths);

// --- THE FIX: Wrap platform specific namespaces ---
// This ensures that users can still access path.win32 and path.posix with our secure overrides.
export const win32 = {
    ...path.win32,
    join: (...paths: string[]) => validator.join(...paths),
    resolve: (...paths: string[]) => validator.resolve(...paths)
};

export const posix = {
    ...path.posix,
    join: (...paths: string[]) => validator.join(...paths),
    resolve: (...paths: string[]) => validator.resolve(...paths)
};

// Re-export standard pass-through functions
export const basename = path.basename;
export const dirname = path.dirname;
export const extname = path.extname;
export const parse = path.parse;
export const format = path.format;
export const isAbsolute = path.isAbsolute;
export const normalize = path.normalize;
export const relative = path.relative;
export const sep = path.sep;
export const delimiter = path.delimiter;

export { PathValidator };