using CodeSignAuto.Coverage;

try
{
    if (args is ["--coverage-process-host", var request, var start, var hostResultPath])
    {
        return await CoverageProcessHost.RunAsync(request, start, hostResultPath);
    }

    if (args is ["--manifest", var manifest])
    {
        var results = CoverageGate.EvaluateManifest(manifest);
        foreach (var (target, result) in results.OrderBy(static item => item.Key, StringComparer.Ordinal))
        {
            Console.WriteLine(
                $"{target}: {result.CoveredLines}/{result.TotalLines} ({result.BasisPoints / 100.0:F2}%, required {result.RequiredBasisPoints / 100.0:F2}%)");
        }

        return 0;
    }

    if (args is ["--run", var repositoryRoot, var outputParent, var dotNetPath])
    {
        var run = await CoverageRunCoordinator.RunAsync(
            repositoryRoot,
            outputParent,
            dotNetPath);
        Console.WriteLine(run.Root);
        foreach (var (target, result) in run.Coverage.OrderBy(static item => item.Key, StringComparer.Ordinal))
        {
            Console.WriteLine(
                $"{target}: {result.CoveredLines}/{result.TotalLines} ({result.BasisPoints / 100.0:F2}%, required {result.RequiredBasisPoints / 100.0:F2}%)");
        }

        return 0;
    }

    throw new CoverageGateException("coverage_arguments_invalid");
}
catch (CoverageGateException error)
{
    Console.Error.WriteLine("coverage_gate_failed:" + error.Code);
    return 2;
}
