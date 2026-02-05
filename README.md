
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

## 🔒 Security Philosophy & Architecture

This library implements a **Defense-in-Depth** strategy, aligning with OWASP guidelines and the "Secure from Scratch" methodology. It serves as the **Infrastructure** layer  that prevents developers from manually validating paths in every controller.

### 1. The "Boxed Path" Infrastructure (Sandbox)

Based on the "Sandbox" principle, `untrust-ts` enforces a strict jail (Root Directory).

* **Initialization:** When imported, the library locks the context to the current working directory (`process.cwd()`).
* 
**Enforcement:** Every path constructed via `join` or `resolve` is checked to ensure it creates an **Absolute Path** that physically resides inside the jail.



### 2. Comprehensive Security Checklist
We implement a rigorous validation pipeline to ensure no threat slips through:

| Threat | Protection Mechanism |
| :--- | :--- |
| **Path Traversal** (`../`) | Validates that the resolved absolute path starts with the trusted root. |
| **Null Byte Injection** | Implicitly blocked by our strict Character Allow-List. |
| **Symlink Attacks** | Uses `fs.realpathSync` to resolve the *physical* path on disk, preventing symlinks from bypassing logical checks (Canonicalization). |
| **Dangerous Filenames** | Blocks reserved OS names (e.g., `CON`, `PRN`) via strict regex filtering. |
| **Input Sanitization** | **Strict Allow-List**: Only allows alphanumeric characters, spaces, dots, underscores, and hyphens (`a-z0-9._- `). All other characters are rejected. |

### 3. Closing "Backdoors"

Many security wrappers fail because they only secure the main functions but leave platform-specific namespaces exposed. `untrust-ts` provides full coverage:

* **Secured Namespaces:** We wrap `path.win32.join` and `path.posix.join` as well. Even if an attacker (or a careless developer) tries to use OS-specific methods to bypass validation, the library intercepts and validates the call.

---

## 🛠️ API & Usage

### Standard Usage (Global Protection)

```typescript
import * as securePath from 'untrust-ts';

try {
    // 1. Safe Join (Read/Write)
    // Allows joining paths for existing files OR new files (Save As), 
    // as long as the parent directory is safe.
    const safe = securePath.join('uploads', 'image.png');
    
    // 2. Safe Resolve
    const absolute = securePath.resolve('public/css/style.css');

    // 3. Pass-through functions (Work exactly like native 'path')
    const name = securePath.basename('/tmp/file.txt'); 

} catch (error) {
    // ⚠️ IMPORTANT: Always log security violations!
    console.error("Security Alert:", error.message);
}

```

### Advanced Usage (Custom Configuration)

If you need strict file extension validation or a custom root directory, you can instantiate the validator class directly.

```typescript
import { PathValidator } from 'untrust-ts';

// 1. Create a custom jail (e.g., only allow access to 'public/uploads')
const validator = new PathValidator('./public/uploads');

// 2. Validate with options
try {
    const safePath = validator.validate('avatar.jpg', {
        [cite_start]allowedExtensions: ['.jpg', '.png'], // Whitelist extensions [cite: 10]
        allowNewFiles: true                  // Allow paths to non-existent files
    });
} catch (e) {
    console.error("Blocked:", e.message);
}

```

---

## ⚠️ Best Practices

1. **Handle Exceptions:** This library **throws exceptions** when a security violation occurs. You must wrap your path operations in `try/catch` blocks (or use a global exception handler ).


2. **Log Attacks:** As recommended in security training, an exception from this library means someone might be probing your system. **Log this event as a critical security incident.**


3. **Positive Security Model:** We use an **Allow-List** approach. If your legitimate filenames contain special characters (like `&`, `$`, `@`), they will be blocked by default. This is intentional for maximum security.

---

## 🧪 Testing

The library is fully tested with a comprehensive suite covering:

* Traversal attempts (`../../`)
* Null byte injection
* Symlink evasion (Canonicalization)
* File creation scenarios (Save As)
* Backdoor access attempts (`win32` namespace)
* Allow-list enforcement

Run tests locally:

```bash
npm install
npm test

```

---

**License:** ISC



