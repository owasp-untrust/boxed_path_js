import * as nativeFs from 'fs';
import { ValidatedPath } from './validator.js';

/**
 * Helper to validate and unwrap the path argument.
 * Throws a Security Violation if a raw string is provided.
 */
const wrapPathArg = (arg: any): string => {
    if (arg instanceof ValidatedPath) {
        return arg.unwrap();
    }
    throw new Error(`Security Violation: Raw strings are forbidden. Use ValidatedPath tokens.`);
};

/**
 * Secure FS Wrapper: Only accepts ValidatedPath tokens.
 * This delegation layer ensures that no filesystem operations can be 
 * performed without a prior validation from a BoxedPath sandbox.
 */
export const fs: any = {
    // --- Synchronous API ---
    readFileSync: (p: ValidatedPath, opt: any) => nativeFs.readFileSync(wrapPathArg(p), opt),
    writeFileSync: (p: ValidatedPath, d: any, opt: any) => nativeFs.writeFileSync(wrapPathArg(p), d, opt),
    appendFileSync: (p: ValidatedPath, d: any, opt: any) => nativeFs.appendFileSync(wrapPathArg(p), d, opt),
    readdirSync: (p: ValidatedPath, opt: any) => nativeFs.readdirSync(wrapPathArg(p), opt),
    unlinkSync: (p: ValidatedPath) => nativeFs.unlinkSync(wrapPathArg(p)),
    statSync: (p: ValidatedPath) => nativeFs.statSync(wrapPathArg(p)),
    existsSync: (p: ValidatedPath) => nativeFs.existsSync(wrapPathArg(p)),

    // --- Promises API ---
    promises: {
        readFile: (p: ValidatedPath, opt: any) => nativeFs.promises.readFile(wrapPathArg(p), opt),
        writeFile: (p: ValidatedPath, d: any, opt: any) => nativeFs.promises.writeFile(wrapPathArg(p), d, opt),
        appendFile: (p: ValidatedPath, d: any, opt: any) => nativeFs.promises.appendFile(wrapPathArg(p), d, opt),
        unlink: (p: ValidatedPath) => nativeFs.promises.unlink(wrapPathArg(p)),
        readdir: (p: ValidatedPath, opt: any) => nativeFs.promises.readdir(wrapPathArg(p), opt),
        stat: (p: ValidatedPath) => nativeFs.promises.stat(wrapPathArg(p)),
    }
};