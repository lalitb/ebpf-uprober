# **Configuration Guide for eBPF-based Function Tracing**

This guide explains how to configure `config.json` for instrumenting multiple applications with **eBPF uprobes**. It covers:
- How function names should be configured based on the programming language (**C, C++, or Rust**).
- How to extract function names correctly from a binary.
- How to properly configure `config.json` for tracing multiple binaries.

---

## **1. Configuration Structure**
The `config.json` file defines:
- **A list of application binaries** where uprobes will be attached.
- **A list of functions to trace for each binary**, identified by a unique `id` and function name.
- **Root functions**, which serve as entry points for tracing spans.

### **Example Configuration (`config.json`) for Multiple Binaries**
```json
{
    "applications": [
        {
            "path": "/tmp/monitor",
            "functions": [
                { "id": 0, "name": "get_cpu_usage" },  // C function (not mangled)
                { "id": 1, "name": "_ZN17monitor_system14get_memory_usageEv" }, // C++ function (mangled)
                { "id": 2, "name": "_ZN17monitor_system12get_disk_usageEv" },  // C++ function (mangled)
                { "id": 3, "name": "get_network_usage" }, // C function (not mangled)
                { "id": 4, "name": "monitor_system" }  // C function (not mangled)
            ],
            "root_functions": ["monitor_system"]
        },
        {
            "path": "/usr/bin/another_app",
            "functions": [
                { "id": 0, "name": "_ZN12another_app13initializeEv" },  // C++ function (mangled)
                { "id": 1, "name": "_ZN12another_app10process_dataEv" }, // C++ function (mangled)
                { "id": 2, "name": "cleanup_resources" }  // C function (not mangled)
            ],
            "root_functions": ["initialize"]
        }
    ]
}
```

### **What This Means**
- The configuration now supports **multiple binaries**.
- Each binary has its own **list of functions to trace**.
- **C++ and Rust functions are mangled**, whereas **C functions (`extern "C"`) are not**.
- **Each application can have its own root functions**.

---

## **2. Explanation of Configuration Fields**

| Field | Type | Description |
|-------|------|-------------|
| `applications` | Array | List of application binaries to instrument. |
| `applications[].path` | String | Path to the **executable binary** where uprobes will be attached. |
| `applications[].functions` | Array | List of functions to trace for each application. |
| `functions[].id` | Integer | A unique **method ID** for identifying the function in eBPF maps. |
| `functions[].name` | String | The function name (**not mangled if `extern "C"`, mangled otherwise**). |
| `applications[].root_functions` | Array | Functions that should **start a new trace span** (entry points of instrumentation). |

---

## **3. Understanding Function Names: Mangled vs. Unmangled**

| Language | Function Type | Name in `config.json` |
|----------|--------------|------------------|
| **C** | Normal function | `"name": "get_cpu_usage"` |
| **C++** | `extern "C"` function | `"name": "get_cpu_usage"` |
| **C++** | Normal function | `"name": "_ZN17monitor_system11get_cpu_usageEv"` (Mangled) |
| **Rust** | `extern "C"` function | `"name": "rust_function"` |
| **Rust** | Normal function | `"name": "_ZN17monitor_system13rust_function17h2c831bb585f38c96E"` (Mangled) |

- If the function is written in **C or declared as `extern "C"` in C++ or Rust**, use its **normal name**.
- If the function is **not `extern "C"`**, use its **mangled name**.

---

## **4. Extracting Function Names from a Binary**
To correctly extract function names, use the following commands.

### **A. Extract Function Names from a Dynamically Linked Binary**
For **C functions (`extern "C"`)** or exported **C++ functions**, use:
```sh
nm -D /tmp/monitor
```

#### **Example output:**
```
0000000000001170 T get_cpu_usage
0000000000001190 T get_memory_usage
00000000000011b0 T get_disk_usage
00000000000011d0 T get_network_usage
00000000000011f0 T monitor_system
```
- If the function name appears **as-is**, you can use it directly in `config.json`.

### **B. Extract Function Names from a C++ Binary (Mangled)**
For **C++ functions (without `extern "C"`)**, use:
```sh
nm -D /tmp/monitor | c++filt
```

#### **Example output:**
```
0000000000001170 T _ZN17monitor_system11get_cpu_usageEv  ->  monitor_system::get_cpu_usage()
```
- The **first column** contains the **mangled name**.
- The **`c++filt`** tool **demangles it**.

### **C. Extract Rust Function Names**
For **Rust functions (without `extern "C"`)**, use:
```sh
nm -D /tmp/monitor | rustfilt
```

#### **Example output:**
```
0000000000001170 T _ZN17monitor_system13rust_function17h2c831bb585f38c96E  ->  monitor_system::rust_function
```
- The **mangled name** is needed for `config.json`.
- You can **demangle it** using `rustfilt` for verification.

---

## **5. Summary**
- **Multiple binaries can be instrumented** using separate entries in `config.json`.
- **C functions (`extern "C"`)** → Use **normal names**.
- **C++ and Rust functions (without `extern "C"`)** → Use **mangled names**.
- **To extract function names**, use:
  - `nm -D <binary>` for **C functions**.
  - `nm -D <binary> | c++filt` for **C++ functions**.
  - `nm -D <binary> | rustfilt` for **Rust functions**.

✅ **By following this guide, you can correctly configure function names in `config.json` for multiple binaries based on their language and linkage.** 🚀
