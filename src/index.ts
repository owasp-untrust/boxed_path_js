import * as nativePath from 'path';
import { BoxedPath, ValidatedPath, BoxedOptions } from './validator.js';
import { fs as secureFs } from './fs.js';

/**
 * untrust-ts: Secure-by-design path and filesystem framework.
 */

// 1. Export core security classes
export { BoxedPath, ValidatedPath, BoxedOptions };

/**
 * 2. Secure FS Module:
 * Replacing native 'fs' with a token-enforced wrapper.
 */
export const fs = secureFs;

/**
 * 3. Secure Path Module:
 * Grouping safe string-manipulation utilities into a single 'path' namespace.
 * This provides the familiar Node.js DX while omitting dangerous functions
 * like join() and resolve() which MUST be accessed via BoxedPath.
 */
export const path = {
    basename: nativePath.basename,
    dirname: nativePath.dirname,
    extname: nativePath.extname,
    parse: nativePath.parse,
    format: nativePath.format,
    isAbsolute: nativePath.isAbsolute,
    sep: nativePath.sep,
    delimiter: nativePath.delimiter,
    // Note: join and resolve are excluded to enforce Sandbox-only construction
};