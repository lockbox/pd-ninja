# pd-ninja
Author: **lockbox**

_Playdate RE Utilities and Loader_

## Description:
Requires installation of the Playdate SDK which is obtainable [here](https://play.date/dev/). This is not affiliated or endorsed by `Panic Inc.` in any way.

This plugin does a lot of the tedious tasks and exposes a custom binary view when loading memory dumps from the playdate console.

Features:

- can handle user, kernel or full dumps
- imports type library from `<SDK-ROOT>/C_API/pd_api.h`
- discovers (user) `.text` and `.data` boundaries (kernel ones are a mess)
- applies symbols from `<SDK-ROOT>/bin/symbols.db`
- automatically apply typedefs to api structs / functions


## On the Roadmap
- Define the TLS sections in SRAM
- Add user friendly way to add SRAM dump to bndb
- Add lua container types
- Add a check for "functions" in `Symbols.db` being properly
    - if not aligned, then define it as a data symbol
- Provide types for static data symbols (gfx + sound + sprites etc.)
- Find decent heuristics to locate kernel data / code boundaries
- Signature libraries
    - need to fiddle with the FreeRTOS signatures some more to get more reliable
    - need to package the `stm32f7xx` HAL and `lua` (minilua) libraries nicely
    - probably have to add them as a downloadable artifact from a github release
- Adding HAL peripheral memory maps, not really useful but for ocd completeness lol

### Obtaining the SDK

A specific version of the SDK can be obtained from:

`https://download.panic.com/playdate_sdk/Windows/PlaydateSDK-<major.minor.revision>.exe`


### Notes
- why is there a bunch of: `Attempting to add function not backed by file: `?
    - binary ninja assumes a lot of things are code if its coming from something
    it determined was "valid" code, so there's a TON of false positives especially
    when half the instruction set is valid ascii
- The only way to obtain firmware is from reading memory of a device
- Any process can read user space which is from `0x08050000` to `0x080FFFFF`
- The underlying OS is FreeRTOS with MPU enabled. Use [this](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43997) (or similar) to priv esc
- why are _so_ many of the strings not automatically defined?
    - idk man its a data section, ghidra automagically does it but i felt like making a binary ninja plugin

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 3164

## Required Dependencies

The following dependencies are required for this plugin:

 * pip - SQLAlchemy>=2.0.1
 * apt - clang
 * installers - 
 * other - 


## License

This plugin is released under an [MIT license](./license).

## Metadata Version

2
