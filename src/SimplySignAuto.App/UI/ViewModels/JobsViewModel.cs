using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI.ViewModels;

public sealed class JobListItemViewModel
{
    public JobListItemViewModel(JobPageItem item) =>
        Item = item ?? throw new ArgumentNullException(nameof(item));

    internal JobPageItem Item { get; }

    public Guid JobId => Item.JobId;
    public string SourceText => Item.Source == "local" ? "本机" : "CI/API";
    public string KindText => Item.Kind == "pdf" ? "PDF 文档" : "软件签名";
    public string State => Item.State;
    public string StateText => Item.State switch
    {
        "queued" => "排队中",
        "waiting_for_agent" => "等待签名代理",
        "signing" => "签名中",
        "verifying" => "验证中",
        "succeeded" => "已完成",
        "failed" => "失败",
        "expired" => "结果已清理",
        _ => "未知",
    };
    public string StateIcon => Item.State switch
    {
        "succeeded" => "✓",
        "failed" or "expired" => "×",
        _ => "…",
    };
    public string OriginalName => Item.OriginalName;
    public string DefaultSignedCopyName => LocalJobClient.DefaultSignedCopyName(
        OriginalName,
        Path.GetExtension(OriginalName));
    public bool CanOverwriteResult => Item.Source == "local";
    public DateTimeOffset CreatedAtUtc => Item.CreatedAtUtc;
    public string? ErrorCode => Item.ErrorCode;
    public Guid CorrelationId => Item.CorrelationId;
    public bool HasResult => Item.HasResult;
}

public sealed class JobsViewModel : INotifyPropertyChanged, IDisposable
{
    private const int MaximumRetainedItems = 1_000;
    private readonly IAgentAdministrationClient _administration;
    private readonly ILocalJobClient _localJobs;
    private readonly IUiDispatcher _dispatcher;
    private readonly ITerminalJobFeed? _terminalJobs;
    private readonly object _loadSync = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly ObservableCollection<JobListItemViewModel> _items = [];
    private readonly HashSet<Guid> _seen = [];
    private readonly Dictionary<Guid, TerminalJobEventItem> _terminalItems = [];
    private CancellationTokenSource? _generationCancellation;
    private Task? _loadTask;
    private long _loadGeneration;
    private long _generation;
    private JobPageCursor? _nextCursor;
    private bool _hasLoadedPage;
    private bool _isLoading;
    private string? _errorCode;
    private int _disposed;

    public JobsViewModel(
        IAgentAdministrationClient administration,
        ILocalJobClient localJobs,
        IUiDispatcher? dispatcher = null)
        : this(administration, localJobs, dispatcher, null)
    {
    }

    internal JobsViewModel(
        IAgentAdministrationClient administration,
        ILocalJobClient localJobs,
        IUiDispatcher? dispatcher,
        ITerminalJobFeed? terminalJobs)
    {
        _administration = administration ?? throw new ArgumentNullException(nameof(administration));
        _localJobs = localJobs ?? throw new ArgumentNullException(nameof(localJobs));
        _dispatcher = dispatcher ?? InlineJobsDispatcher.Instance;
        _terminalJobs = terminalJobs;
        if (_terminalJobs is not null)
        {
            _terminalJobs.ItemsChanged += HandleTerminalJobsChanged;
            MergeTerminalItems(_terminalJobs.Items);
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<JobListItemViewModel> Items => _items;

    public bool HasLoadedPage => _hasLoadedPage;

    internal IAgentAdministrationClient AdministrationClient => _administration;

    internal ILocalJobClient LocalJobClient => _localJobs;

    internal IUiDispatcher Dispatcher => _dispatcher;

    internal IReadOnlyList<JobPageItem> NotificationItems => _items.Select(static item => item.Item).ToArray();

    public bool IsLoading
    {
        get => _isLoading;
        private set => SetField(ref _isLoading, value);
    }

    public string? ErrorCode
    {
        get => _errorCode;
        private set => SetField(ref _errorCode, value);
    }

    public bool CanLoadMore => !_hasLoadedPage || _nextCursor is not null;

    public Task RefreshAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var generation = Interlocked.Increment(ref _generation);
        var replacement = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        var previous = Interlocked.Exchange(ref _generationCancellation, replacement);
        previous?.Cancel();
        previous?.Dispose();
        return StartLoadAsync(generation, refresh: true, cancellationToken);
    }

    public Task LoadNextPageAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var generation = Volatile.Read(ref _generation);
        if (generation == 0)
        {
            return RefreshAsync(cancellationToken);
        }

        return StartLoadAsync(generation, refresh: false, cancellationToken);
    }

    public bool CanSaveResult(Guid jobId) =>
        _items.Any(item => item.JobId == jobId && item.HasResult && item.State == "succeeded");

    public async Task SaveResultAsAsync(
        Guid jobId,
        string destinationPath,
        bool overwrite,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        var item = _items.FirstOrDefault(candidate =>
            candidate.JobId == jobId && candidate.HasResult && candidate.State == "succeeded");
        if (item is null)
        {
            return;
        }

        await InvokeUiAsync(() => ErrorCode = null, CancellationToken.None).ConfigureAwait(false);
        try
        {
            await _localJobs.SaveSignedCopyAsync(
                jobId,
                destinationPath,
                overwrite && item.CanOverwriteResult,
                cancellationToken).ConfigureAwait(false);
        }
        catch (LocalJobException error)
        {
            await InvokeUiAsync(() => ErrorCode = error.Code, CancellationToken.None).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();
        if (_terminalJobs is not null)
        {
            _terminalJobs.ItemsChanged -= HandleTerminalJobsChanged;
        }
        var generation = Interlocked.Exchange(ref _generationCancellation, null);
        generation?.Cancel();
        Task? load;
        lock (_loadSync)
        {
            load = _loadTask;
        }

        try
        {
            load?.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
        }

        generation?.Dispose();
        _lifetime.Dispose();
    }

    private Task StartLoadAsync(long generation, bool refresh, CancellationToken callerCancellation)
    {
        Task operation;
        lock (_loadSync)
        {
            if (_loadTask is { IsCompleted: false } && _loadGeneration == generation)
            {
                operation = _loadTask;
            }
            else
            {
                _loadGeneration = generation;
                operation = _loadTask = LoadPageAsync(generation, refresh);
            }
        }

        return operation.WaitAsync(callerCancellation);
    }

    private async Task LoadPageAsync(long generation, bool refresh)
    {
        var generationCancellation = _generationCancellation;
        if (generationCancellation is null)
        {
            return;
        }

        JobPageCursor? cursor = null;
        await InvokeUiAsync(() =>
        {
            if (generation != Volatile.Read(ref _generation))
            {
                return;
            }

            if (refresh)
            {
                _items.Clear();
                _seen.Clear();
                _nextCursor = null;
                _hasLoadedPage = false;
                ErrorCode = null;
                OnPropertyChanged(nameof(Items));
                OnPropertyChanged(nameof(HasLoadedPage));
                OnPropertyChanged(nameof(CanLoadMore));
            }

            cursor = _nextCursor;
            IsLoading = true;
        }, CancellationToken.None).ConfigureAwait(false);

        if (!refresh && _hasLoadedPage && cursor is null)
        {
            await InvokeUiAsync(() => IsLoading = false, CancellationToken.None).ConfigureAwait(false);
            return;
        }

        try
        {
            var page = await _administration.GetJobPageAsync(
                cursor,
                generationCancellation.Token).ConfigureAwait(false);
            await InvokeUiAsync(() =>
            {
                if (generation != Volatile.Read(ref _generation))
                {
                    return;
                }

                foreach (var item in page.Items)
                {
                    if (_items.Count >= MaximumRetainedItems)
                    {
                        break;
                    }

                    if (_seen.Add(item.JobId))
                    {
                        _items.Add(new JobListItemViewModel(ResolveTerminalItem(item)));
                    }
                }

                _nextCursor = page.NextCursor;
                _hasLoadedPage = true;
                ErrorCode = null;
                OnPropertyChanged(nameof(Items));
                OnPropertyChanged(nameof(HasLoadedPage));
                OnPropertyChanged(nameof(CanLoadMore));
            }, CancellationToken.None).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (generationCancellation.IsCancellationRequested)
        {
        }
        catch (ManagementUnavailableException)
        {
            await InvokeUiAsync(() => ErrorCode = "management_unavailable", CancellationToken.None)
                .ConfigureAwait(false);
        }
        finally
        {
            await InvokeUiAsync(() =>
            {
                if (generation == Volatile.Read(ref _generation))
                {
                    IsLoading = false;
                }
            }, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private void HandleTerminalJobsChanged(object? sender, EventArgs eventArgs)
    {
        var terminalItems = _terminalJobs?.Items ?? [];
        _ = InvokeUiAsync(() =>
        {
            MergeTerminalItems(terminalItems);
            var changed = false;
            for (var index = 0; index < _items.Count; index++)
            {
                var current = _items[index].Item;
                var resolved = ResolveTerminalItem(current);
                if (!ReferenceEquals(current, resolved))
                {
                    _items[index] = new JobListItemViewModel(resolved);
                    changed = true;
                }
            }

            if (changed)
            {
                OnPropertyChanged(nameof(Items));
            }
        }, _lifetime.Token);
    }

    private void MergeTerminalItems(IReadOnlyList<TerminalJobEventItem> items)
    {
        _terminalItems.Clear();
        foreach (var item in items.OrderByDescending(static item => item.Sequence))
        {
            _terminalItems.TryAdd(item.Item.JobId, item);
        }
    }

    private JobPageItem ResolveTerminalItem(JobPageItem item)
    {
        if (!_terminalItems.TryGetValue(item.JobId, out var terminal))
        {
            return item;
        }

        var currentCompletedAt = item.CompletedAtUtc;
        var terminalCompletedAt = terminal.Item.CompletedAtUtc;
        return currentCompletedAt is null ||
               terminalCompletedAt is not null && terminalCompletedAt >= currentCompletedAt
            ? terminal.Item
            : item;
    }

    private async Task InvokeUiAsync(Action action, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    action();
                }
            }, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (
            Volatile.Read(ref _disposed) != 0 &&
            error is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private sealed class InlineJobsDispatcher : IUiDispatcher
    {
        public static InlineJobsDispatcher Instance { get; } = new();
        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }
}
