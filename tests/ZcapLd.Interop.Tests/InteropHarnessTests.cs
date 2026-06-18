using System.Diagnostics;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace ZcapLd.Interop.Tests;

/// <summary>
/// CI wrapper around <c>interop/run-interop.sh</c>: runs the live cross-stack RDFC delegation
/// interop harness (zcap-dotnet ⇄ the real <c>@digitalbazaar/zcap</c>) and asserts every check
/// passes. The harness itself builds the interop CLI, does <c>npm ci</c>, signs on each stack, and
/// cross-verifies in both directions (single- and multi-level) plus tamper negatives.
///
/// Skips (rather than fails) when bash/node/npm/dotnet are not on PATH, so it is a no-op on
/// machines without Node. The dedicated <c>ci-interop.yml</c> workflow provides those tools.
/// </summary>
[Trait("Category", "Interop")]
public sealed class InteropHarnessTests
{
    private readonly ITestOutputHelper _output;

    public InteropHarnessTests(ITestOutputHelper output) => _output = output;

    [SkippableFact]
    public void RunInteropHarness_RdfcDelegation_RoundTripsWithDigitalBazaar()
    {
        var repoRoot = LocateRepoRoot();
        var script = Path.Combine(repoRoot, "interop", "run-interop.sh");

        var (prereqsOk, prereqDetail) = PrerequisitesAvailable();
        Skip.IfNot(
            prereqsOk,
            $"Skipping cross-stack interop harness — bash/node/npm/dotnet not all available ({prereqDetail}).");

        var (exitCode, output) = RunHarness(script, repoRoot, TimeSpan.FromMinutes(15));
        _output.WriteLine(output);

        Assert.True(
            exitCode == 0,
            $"Interop harness exited with {exitCode}. Output:\n{output}");
        Assert.Contains("ALL 6 CHECKS PASSED", output);
    }

    // Walk up from the test assembly location until we find interop/run-interop.sh.
    private static string LocateRepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "interop", "run-interop.sh")))
                return dir.FullName;
        }

        throw new InvalidOperationException(
            $"Could not locate repo root (interop/run-interop.sh) from {AppContext.BaseDirectory}.");
    }

    // True only if bash can run and node + npm + dotnet are all on PATH.
    private static (bool ok, string detail) PrerequisitesAvailable()
    {
        try
        {
            var psi = new ProcessStartInfo("bash", "-c \"command -v node && command -v npm && command -v dotnet\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi)!;
            var found = p.StandardOutput.ReadToEnd().Trim();
            if (!p.WaitForExit(20_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
                return (false, "prerequisite probe timed out");
            }
            return (p.ExitCode == 0, p.ExitCode == 0 ? found.Replace('\n', ';') : "node/npm/dotnet not found");
        }
        catch (Exception ex)
        {
            // bash itself not available (e.g. Windows without WSL) → skip.
            return (false, ex.Message);
        }
    }

    private static (int exitCode, string output) RunHarness(string script, string repoRoot, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo("bash", $"\"{script}\"")
        {
            WorkingDirectory = repoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var p = new Process { StartInfo = psi };
        var sb = new StringBuilder();
        var sync = new object();
        void Append(string? line) { if (line is not null) lock (sync) sb.AppendLine(line); }

        p.OutputDataReceived += (_, e) => Append(e.Data);
        p.ErrorDataReceived += (_, e) => Append(e.Data);

        p.Start();
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        if (!p.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            lock (sync) return (-1, sb.ToString() + $"\n[harness timed out after {timeout}]");
        }

        // Ensure async output handlers have flushed.
        p.WaitForExit();
        lock (sync) return (p.ExitCode, sb.ToString());
    }
}
