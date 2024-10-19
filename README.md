# Browser Digital Fingerprinting Hook with Machine Learning

## Contributers:
- Martin Hanna: Data analysis & Statistical calculations, and market research.
- Abdullah AlSharji: Lead developer.
- Nasser AlKhaifi: Website engineering.

## Overview

This project implements a **DLL injector** that attaches to a user's browser, intercepts digital fingerprinting functions, and logs their frequency and combinations. It utilizes a **pre-trained Random Forest model** in C++ to analyze the captured data and detect potential digital fingerprinting attempts based on these API call patterns.

The primary goal of this project is to detect and mitigate fingerprinting techniques used by websites to gather unique system information.

## Features

- **DLL Injection**: Hooks into the browser process to monitor system API calls related to fingerprinting.
- **API Hooking**: Intercepts key Windows API functions (such as `GetSystemInfo`, `GetDeviceCaps`, etc.) and logs function call frequencies and combinations.
- **Random Forest Model**: Uses a pre-trained Random Forest model in C++ to make decisions based on the frequency and combination of function calls.
- **Combination Tracking**: Uses a bitmap to track the combination of API calls and an integer to log frequency.
- **Real-Time Detection**: Processes the data in real-time to detect potential fingerprinting.

## How It Works

1. **DLL Injection**: The DLL is injected into the browser using standard injection techniques, such as `CreateRemoteThread`.
2. **Function Hooking**: The following system APIs are hooked:
   - `GetSystemInfo`
   - `NtQuerySystemInformation`
   - `GlobalMemoryStatus`
   - `GetDeviceCaps`
   - `GetSystemMetrics`
   - `GetUserDefaultLocaleName`
   - `EnumDisplayDevices`
   - ...and others.
3. **Logging and Monitoring**: For each hooked function, the frequency counter in the `DllExtension` struct is incremented, and the function combination is stored in a bitmap.
4. **Random Forest Model**: The captured data (frequency and combination) is passed to a pre-trained Random Forest model, which decides if fingerprinting is likely.
5. **Action**: If fingerprinting is detected, the system logs the event or flags it for further processing.
