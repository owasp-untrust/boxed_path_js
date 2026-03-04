# 🛡️ Untrust-TS: Secure FS Enforcement Framework

**Untrust-TS** is a JavaScript/TypeScript security library designed for **server-side environments (Node.js, Deno, Bun).** It prevents **Path Traversal** and **Symlink Escape** attacks by shifting the architectural paradigm: instead of trying to "sanitize" malicious input strings, the library creates a secure "Sandbox" where only strictly validated paths—converted into `ValidatedPath` tokens—are permitted to access the file system.

## 🚀 Why Use Untrust-TS?

* **Secure by Design:** The built-in Node.js File System (`fs`) is replaced with a strict wrapper that refuses to accept raw strings.
* **Build-time Enforcement:** A static scanner ensures that no developer "bypasses" the protections by importing Native libraries directly.
* **Zero Trust:** Explicit definition of internal permissions for each sandbox (write permissions, file extension whitelists, and predefined filename patterns).

---

## 📚 API Reference (Classes and Functions Overview)

### 1. `BoxedPath` Class (The Sandbox Engine)

The core class that manages the boundaries (The Jail) and generates secure tokens.

* **`join(...paths)`**: Concatenates paths (raw strings or existing tokens), verifies they comply with the sandbox policies, and returns a `ValidatedPath`.
* **`resolve(...paths)`**: Resolves an absolute path relative to the sandbox's base path. Executes full validation and returns a `ValidatedPath`.
* **`validate(untrustedInput)`**: Accepts an input string (e.g., from an end-user), passes it through the library's 5 security layers (including blocking Null Bytes, Windows bypasses, and Symlinks), and returns a `ValidatedPath` upon success.

### 2. `fs` Object (Secure File System)

A secure wrapper for the Node.js Native FS. **Critical Protection:** All functions within this object will throw a security error if passed a raw string instead of a `ValidatedPath`.

* **Supported synchronous operations:** `readFileSync`, `writeFileSync`, `appendFileSync`, `readdirSync`, `unlinkSync`, `statSync`, `existsSync`.
* **Asynchronous operations (Promises):** `fs.promises.readFile`, `writeFile`, `appendFile`, `unlink`, `readdir`, `stat`.

### 3. `path` Object (Safe Path Utilities)

To leave no loopholes, the library provides a restricted, risk-free alternative to the Node.js `path` module.

* **Permitted functions (text manipulation only):** `basename`, `dirname`, `extname`, `parse`, `format`, `isAbsolute`, `sep`, `delimiter`.
* **Blocked functions:** Global `join` and `resolve` have been intentionally removed from the object to force developers to use the equivalent validation-enforcing functions within `BoxedPath`.

### 4. `ValidatedPath` Class (The Security Token)

An opaque object representing a secure path. Developers use it as input for `fs` operations, but there is usually no need to instantiate or import it directly, as Sandbox functions return it automatically. This class completely prevents runtime string injection.

---

## 🛠️ Usage and Enforcement Guide

### 1. Build-Time Security Enforcement (Static Analysis)

To ensure the project is fully protected, the library comes with a CLI tool that scans the code to verify there are no direct `node:fs` or `require('fs')` imports. If a bypass is found, the scanner fails the build process.

You can run the scan directly from the terminal:

```bash
npx untrust-ts-scan

```

Or integrate it as a Hook in your `package.json`:

```json
"scripts": {
  "prebuild": "npx untrust-ts-scan"
}

```

### 2. Default Sandbox Settings (Default Deny)

When creating a new instance of `BoxedPath` without passing additional settings, the system operates in the strictest possible mode (**Default Deny**).

Default settings include:

* **Root Directory:** Automatically set to the current working directory (`process.cwd()`).
* **Read-Only:** `allowNewFiles` is set to `false`. Files that do not physically exist on the disk cannot be accessed (blocking attempts to create or write new files).
* **Strict Naming Pattern:** Filenames are restricted to English letters, numbers, dots, underscores, and hyphens only (`/^[a-zA-Z0-9._\-]+$/`). Spaces and special characters are automatically blocked.
* **Reserved Names Blocking:** Access to Windows reserved names (such as `CON`, `PRN`, `NUL`) is completely blocked to prevent system crashes.
* **Hermetic Sealing:** Any attempt to execute Path Traversal (`../`), Symlink Escaping, or Null Byte injection (`\0`) will throw an immediate security error.

### 3. Basic Usage (The Golden Path)

To read an existing file using default settings, we generate a token and pass it to the secure `fs`:

```typescript
import { BoxedPath, fs } from 'untrust-ts';

// 1. Initialize a strict, read-only sandbox scoped to the current directory
const defaultSandbox = new BoxedPath();

try {
    // 2. Safely generate a validated token for an existing file
    const fileToken = defaultSandbox.join('existing_config.json');

    // 3. Perform FS read operation securely using the token
    const data = fs.readFileSync(fileToken, 'utf8');
    
    console.log(`✅ Success: File read securely.`);
} catch (error) {
    console.error(`🛡️ Blocked by Security Guard: ${error.message}`);
}

```

### 4. Advanced Options: File Writing, Unicode, and Custom Policies

To enable more flexible functionality, pass a `BoxedOptions` object to explicitly define the rules.

For example, setting up a "projects" folder that allows the creation of Hebrew documents:

```typescript
import { BoxedPath, fs } from 'untrust-ts';

// Create a specialized sandbox with advanced policies
const projectsJail = new BoxedPath('./projects', {
    allowNewFiles: true, // Enables file creation/writing
    allowedExtensions: ['.pdf', '.docx'], // Explicit extension whitelist
    // Custom Regex: Allows Hebrew Unicode range (\u0590-\u05FF) and internal spaces
    filenamePattern: /^[a-zA-Z0-9\u0590-\u05FF._\-]([a-zA-Z0-9\u0590-\u05FF._\- ]*[a-zA-Z0-9\u0590-\u05FF._\-])?$/
});

try {
    // This will now pass validation and allow creation of a new file
    const hebrewToken = projectsJail.join('פרויקט גמר.pdf');
    
    // Using the secure wrapper to write data
    fs.writeFileSync(hebrewToken, 'PDF File Data...');
    console.log(`✅ Success: Hebrew file validated and created.`);
} catch (error) {
    console.error(`🛡️ Policy Violation: ${error.message}`);
}

```

---

## 📜 License

This system was developed and distributed under the Apache 2.0 License.
**Author:** Or Bibi.
