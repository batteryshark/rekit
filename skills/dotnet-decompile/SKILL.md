---
name: dotnet-decompile
description: "Decompile a .NET / CLR assembly (IL) back to C# with the ilspycmd dotnet tool. Static: reads metadata + IL, never runs the assembly. Prereq-gated on ilspycmd (needs the .NET runtime); honest blind spot with an install hint when absent. Pair with dotnet-analyze for the P/Invoke surface."
---

# .NET Decompiler

Decompile a .NET / CLR assembly (IL) back to C# with
[`ilspycmd`](https://github.com/icsharpcode/ILSpy).

## When to use

A managed .NET assembly you need to read. Run `dotnet-analyze` first for the shape
and P/Invoke surface, then this for full C#.

## What it does

Runs `ilspycmd <assembly> -o <outdir>` (static — reads IL/metadata, never runs the
assembly) and reports the files written.

## Prerequisites

- **python3** (runner) and **`ilspycmd`** on PATH — a dotnet tool that needs the .NET
  runtime, so it is **not bundled**: `dotnet tool install -g ilspycmd`. Until then
  `doctor` marks the skill not-ready and `run` reports the honest blind spot.

## Usage

```bash
rekit run dotnet-decompile ./managed.dll ./out
```
