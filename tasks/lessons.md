# Lessons Learned

## 2026-02-26 10:24:27
- Verify repository identity (path + solution name) before running analysis or commands.
- If multiple similarly named repos exist, confirm the target repo explicitly before proceeding.

## 2026-02-26 10:38:33
- Treat `dotnet pack --no-build` as unsafe unless a clean rebuild was executed immediately before packing.
- For NuGet release workflows, enforce `dotnet clean` + `dotnet build --no-incremental` before pack, and verify packaged DLL assembly version from the generated `.nupkg`.

## 2026-02-26 10:58:34
- A local commit/version change does not publish packages by itself; NuGet release workflows only run on `core-v*.*.*` / `aspnet-v*.*.*` tags or manual dispatch.
- When a package version has already been published or workflow didn't run, bump patch version and retrigger release workflows explicitly.
