# progwrp patcher

progwrp patcher is a tool to patch Windows binaries that normally only work on Windows 7+ to run on Windows XP via the help of progwrp .dll helper files present in [Supermium](https://github.com/win32ss/supermium), but thanks to seperating the progwrp .dll files into multiple shared libraries that follow the Windows structure in terms of kernel functions, we can use the same .dll files for patching other programs that are not just Supermium.

More details about progwrp can be seen [here](https://github.com/Alex313031/thorium-legacy/tree/main/patches/progwrp)

## What does it do?

In short, it implements win32 API functions that are not natively supported on Pre-Windows 7 versions and are instead redirected to the set of progwrp .dll files. The .dll files contain custom implementations of these functions, written in C & C++, "translating" them into something that older Windows can understand.

## How does it work?

It patches the binary to use the progwrp .dll files to call the Windows kernel functions that are normally not available on Windows XP. It does this by replacing known Windows .dll files that are used by the binary to expose Windows API functions (like ntdll.dll, kernel32.dll, etc.) with the progwrp .dll files. It does not affect the binary's functionality in any way and retains the original calls if they are not redirected and if they are redirected, it just makes it run on Windows XP.

## How to use it?

Go 1.15 or higher is required to build the progwrp-patcher executable, which means technically per Go spec Windows 7 or higher (if you are running Windows) is required to run the progwrp-patcher executable, but since you can patch the patcher itself to work on Windows XP, you can use it on Windows XP.

If you are patching a binary to work on Windows XP outside of Windows or a newer Windows machine, keep in mind you need to copy the binary (and the relevant .dll files from progwrp) to the target Windows machine to use it.

From binary releases:
1. Download the progwrp-patcher executables from [here](https://github.com/matu6968/progwrp-patcher/releases)

From source:

1. Clone the repository
2. Run the following command to build the progwrp-patcher executable:
```bash
go build -o progwrp-patcher.exe main.go
```

## Usage

If you are just patching a single binary, you can use the following command:
```bash
progwrp-patcher.exe -i <path to the binary to patch>
```

Or if you want to patch all the binaries in a directory, you can use the following command:
```bash
progwrp-patcher.exe -i <directory to patch all files in> -r
```
Running the above commands will download the progwrp .dll files (by default will point to the [progwrp-patcher](https://github.com/matu6968/progwrp-patcher) repo but you can specify a custom GitHub repository using `-repo owner/repository` that host the progwrp .dll files under the filename `progwrp_blobs-<arch>.zip` in the releases) if not present and patch the binaries which will also copy the required .dll files to the same directory as the binary.

## FAQ

### Why does my binary not work as expected after patching?

progwrp is not a magical tool that can make all binaries compiled to only run on Windows 7+ run on Windows XP, certain Windows API functions are not implemented in progwrp and instead display a dialog message from what functions are not implemented, for example if you try to use the `GetErrorType` function (Usually Go binaries use this Windows API function), it will display a dialog message saying `Implemenation_GetErrorType` and crash the program upon closing the dialog. 

Unfortunantely the creator of progwrp (aka win32ss) assumes all unimplemented functions that don't exist on XP will stop an application from running and do the above, until then you can try to use other tools that can patch the system to get the binary to work on Windows XP such as [OneCoreAPI](https://github.com/shorthorn-project/One-Core-API-Binaries) or if you are a application developer, you can try to implement something like [YY-Thunks](https://github.com/Chuyu-Team/YY-Thunks).

If you are a user of progwrp, try patching a different program and post your results in the [Issue](https://github.com/matu6968/progwrp-patcher/issues/new) section.