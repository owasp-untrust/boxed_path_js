# untrust-ts 🛡️

**A Secure, Drop-in Replacement for Node.js `path` Module.**

`untrust-ts` is a hardened TypeScript library designed to prevent **Path Traversal** attacks and enforce strict security boundaries. It acts as a transparent wrapper around the native Node.js `path` module, allowing developers to secure existing applications simply by changing a single import line.

---

## 🚀 The "Drop-in" Magic

The core philosophy of this library is **Zero-Friction Adoption**.
You don't need to rewrite your logic or learn a new API.

### Before (Vulnerable Code)
Standard usage of Node.js `path` allows attackers to access system files via traversal (`../`).
```typescript
import * as path from 'path'; // Standard Import

// ❌ DANGEROUS: Attackers can send '../../etc/passwd'
const filePath = path.join(process.cwd(), userInput); 

```

### After (Secured with untrust-ts)

Change **only the import line**. The rest of your code remains exactly the same.

```typescript
import * as path from 'untrust-ts'; // Secure Import

// ✅ SECURE: Automatically blocks traversal, null bytes, and forbidden characters.
// Throws an Error if the user tries to break out of the root directory.
const filePath = path.join(process.cwd(), userInput); 

```

---

## 🔒 Security Policies & Defaults

Out of the box, `untrust-ts` applies a **"Secure by Default"** policy. It assumes the worst and restricts everything unless configured otherwise.

### Default Security Settings:

1. **Strict Whitelist (Regex):** Only English letters, numbers, spaces, dots, underscores, and hyphens are allowed (`a-zA-Z0-9._- `). **Hebrew, Emoji, and special symbols are blocked.**
2. **Read-Only Mode:** You cannot resolve a path to a file that **does not exist** (prevents arbitrary file creation exploits).
3. **Jail Enforcement:** The resolved path must physically reside within the current working directory (`process.cwd()`).

---

## ⚙️ Global Configuration

While the defaults are strict, real-world apps have different needs (e.g., supporting Hebrew filenames or "Save As" functionality).
We provide two helper functions to adjust security settings globally without changing your code structure.

### 1. `path.configure(extensions, allowNewFiles, pattern)`

Updates the global security settings. Pass `null` to keep the default/current value for a parameter.

**Parameters:**

* `allowedExtensions` (Array): Whitelist specific extensions (e.g., `['.jpg']`). `null` = Allow all.
* `allowNewFiles` (Boolean): Set `true` to allow generating paths for non-existent files. `null` = Keep default (`false`).
* `filenamePattern` (Regex): Custom regex for allowed characters. `null` = Keep default.

#### Example A: Enabling Hebrew Support

```typescript
import * as path from 'untrust-ts';

// Configure once at the start of your app
path.configure(null, null, /^[a-zA-Z0-9\u0590-\u05FF._\- ]+$/);

// Now this works!
const safePath = path.join('מסמכים', 'דוח_שנתי.pdf');

```

#### Example B: Enabling File Creation ("Save As") & Restricting Extensions

```typescript
import * as path from 'untrust-ts';

// Allow creating new files, BUT only if they end in .jpg or .png
path.configure(['.jpg', '.png'], true, null);

// This works even if 'new-image.jpg' doesn't exist yet
const uploadPath = path.join('uploads', 'new-image.jpg');

```

### 2. `path.reset()`

Resets all global configurations back to the strict "Secure by Default" values. Useful for testing cleanup.

```typescript
import * as path from 'untrust-ts';

path.reset(); // Back to strict English-only, Read-only mode.

```

---

## 🛡️ Architecture & Defense Mechanisms

This library implements a **Defense-in-Depth** strategy, aligning with OWASP guidelines.

### 1. Comprehensive Security Checklist

We implement a rigorous validation pipeline to ensure no threat slips through:

| Threat | Protection Mechanism |
| --- | --- |
| **Path Traversal** (`../`) | Validates that the resolved absolute path starts with the trusted root. |
| **Null Byte Injection** | Implicitly blocked by our strict Character Allow-List. |
| **Symlink Attacks** | Uses `fs.realpathSync` to resolve the *physical* path on disk, preventing symlinks from bypassing logical checks (Canonicalization). |
| **Dangerous Filenames** | Blocks reserved OS names (e.g., `CON`, `PRN`) via strict regex filtering. |
| **Input Sanitization** | **Strict Allow-List**: Only allows alphanumeric characters, spaces, dots, underscores, and hyphens (`a-z0-9._- `). All other characters are rejected (unless configured otherwise). |

### 2. Closing "Backdoors"

Many security wrappers fail because they only secure the main functions but leave platform-specific namespaces exposed. `untrust-ts` provides full coverage:

* **Secured Namespaces:** We wrap `path.win32.join` and `path.posix.join` as well. Even if an attacker (or a careless developer) tries to use OS-specific methods to bypass validation, the library intercepts and validates the call.

---

## 🛠️ API Reference

### `path.join(...paths)`

Secure replacement for `path.join`. Joins paths and validates against the Allow-List and Jail.

### `path.resolve(...paths)`

Secure replacement for `path.resolve`. Resolves to an absolute path and validates physical location on disk.

### `path.configure(...)`

Updates global security rules (see above).

### `path.reset()`

Resets global security rules to defaults.

---

## ⚠️ Best Practices

1. **Handle Exceptions:** This library **throws exceptions** when a security violation occurs. You must wrap your path operations in `try/catch` blocks.
2. **Log Attacks:** An exception from this library often means a malicious attempt. **Log this event as a critical security incident.**
3. **Positive Security Model:** By default, if your legitimate filenames contain special characters (like `&`, `$`, `@`), they will be blocked. Configure the regex if you need them.

---

## 🧪 Testing

The library is fully tested with a comprehensive suite covering:

* Traversal attempts (`../../`)
* Null byte injection
* Symlink evasion (Canonicalization)
* File creation scenarios (Save As)
* Backdoor access attempts (`win32` namespace)
* Global Configuration lifecycles

Run tests locally:

```bash
npm install
npm test

```

---

**License:** ISC



