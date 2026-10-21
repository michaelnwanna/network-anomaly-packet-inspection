using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Microsoft.Data.Sqlite;

namespace Traceglass;

public sealed record Flow
{
    public long Id { get; set; }
    public long Timestamp { get; init; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public string Method { get; init; } = "";
    public string Scheme { get; init; } = "";
    public string Host { get; init; } = "";
    public int Port { get; init; }
    public string Mode { get; init; } = "";
    public int Status { get; set; }
    public long RequestBytes { get; set; }
    public long ResponseBytes { get; set; }
    public long DurationMs { get; set; }
    public string[] Flags { get; set; } = [];
    public string ErrorCode { get; set; } = "";
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };
}

/// <summary>Committed retained-flow counters and current-session queue health.</summary>
public sealed record StoreStats(long Records, long Flagged, long RequestBytes, long ResponseBytes, long Dropped = 0, int Queued = 0);

public sealed class MetadataStore : IAsyncDisposable
{
    private readonly Channel<Flow> queue;
    private readonly string connectionString;
    private readonly Task writer;
    private readonly FileStream writerLock;
    private readonly long maxRecords;
    private readonly TimeSpan maxAge;
    private long dropped;
    private StoreStats stats = new(0, 0, 0, 0);
    private readonly TaskCompletionSource<Exception> fatal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly object closeGate = new();
    private Task? close;
    public Task<Exception> Failure => fatal.Task;
    public long Dropped => Interlocked.Read(ref dropped);
    public int Queued => queue.Reader.Count;

    public MetadataStore(string filename, long maxRecords, TimeSpan maxAge, int capacity)
    {
        if (maxRecords < 1 || maxAge <= TimeSpan.Zero || capacity < 1) throw new ArgumentException("Invalid storage bounds");
        this.maxRecords = maxRecords;
        this.maxAge = maxAge;
        filename = Path.GetFullPath(filename);
        var directory = Path.GetDirectoryName(filename)!;
        if (!Directory.Exists(directory))
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
            else Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        writerLock = new FileStream(filename + ".lock", new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None
        });
        try
        {
            using (var file = new FileStream(filename, new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.ReadWrite
            }))
            {
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(filename, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            connectionString = new SqliteConnectionStringBuilder { DataSource = filename, Pooling = false }.ToString();
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA user_version";
            var schema = Convert.ToInt64(command.ExecuteScalar());
            if (schema is not (0 or 101)) throw new IOException($"Unsupported C# database schema: {schema}");
            command.CommandText = """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS flows(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
                  method TEXT NOT NULL, scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
                  mode TEXT NOT NULL, status INTEGER NOT NULL, request_bytes INTEGER NOT NULL,
                  response_bytes INTEGER NOT NULL, duration_ms INTEGER NOT NULL, flags TEXT NOT NULL,
                  flagged INTEGER NOT NULL, error_code TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS flows_timestamp ON flows(timestamp);
                CREATE INDEX IF NOT EXISTS flows_flagged ON flows(flagged,id);
                PRAGMA user_version=101;
                """;
            command.ExecuteNonQuery();
            command.CommandText = "SELECT count(*),coalesce(sum(flagged),0),coalesce(sum(request_bytes),0),coalesce(sum(response_bytes),0) FROM flows";
            using (var reader = command.ExecuteReader())
            {
                reader.Read();
                stats = new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
            }
            Persist(connection, []);
            queue = Channel.CreateBounded<Flow>(new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false
            });
            writer = Task.Run(WriteLoop);
        }
        catch
        {
            writerLock.Dispose();
            throw;
        }
    }

    public bool Enqueue(Flow record)
    {
        if (queue.Writer.TryWrite(record)) return true;
        var total = Interlocked.Increment(ref dropped);
        if (total == 1 || (total & (total - 1)) == 0)
            Console.Error.WriteLine($"metadata queue unavailable; dropped={total}; forwarding continues");
        return false;
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;";
            command.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private async Task WriteLoop()
    {
        try
        {
            using var connection = Open();
            using var tick = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
            var lastPrune = DateTime.UtcNow;
            List<Flow> batch = new(256);
            while (true)
            {
                while (batch.Count < 256 && queue.Reader.TryRead(out var row)) batch.Add(row);
                var finished = queue.Reader.Completion.IsCompleted;
                if (batch.Count != 0 || finished || DateTime.UtcNow - lastPrune >= TimeSpan.FromMinutes(1))
                {
                    Persist(connection, batch);
                    batch.Clear();
                    lastPrune = DateTime.UtcNow;
                }
                if (finished) break;
                if (queue.Reader.Count == 0) await tick.WaitForNextTickAsync();
            }
        }
        catch (Exception ex)
        {
            queue.Writer.TryComplete(ex);
            fatal.TrySetResult(ex);
            Console.Error.WriteLine($"Fatal metadata writer failure: {ex.GetType().Name}");
            throw new IOException("Metadata writer failed", ex);
        }
    }

    private void Persist(SqliteConnection connection, List<Flow> batch)
    {
        var updated = Volatile.Read(ref stats);
        using var transaction = connection.BeginTransaction();
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO flows(timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,flagged,error_code)
            VALUES($ts,$method,$scheme,$host,$port,$mode,$status,$sent,$received,$duration,$flags,$flagged,$error)
            """;
        foreach (var name in new[] { "ts", "method", "scheme", "host", "port", "mode", "status", "sent", "received", "duration", "flags", "flagged", "error" })
            insert.Parameters.Add(new SqliteParameter("$" + name, null));
        insert.Prepare();
        foreach (var row in batch)
        {
            foreach (var (name, value) in new (string, object)[]
            {
                ("ts", row.Timestamp), ("method", row.Method), ("scheme", row.Scheme), ("host", row.Host),
                ("port", row.Port), ("mode", row.Mode), ("status", row.Status), ("sent", row.RequestBytes),
                ("received", row.ResponseBytes), ("duration", row.DurationMs),
                ("flags", JsonSerializer.Serialize(row.Flags)), ("flagged", row.Flags.Length > 0), ("error", row.ErrorCode)
            }) insert.Parameters["$" + name].Value = value;
            insert.ExecuteNonQuery();
            updated = updated with { Records = updated.Records + 1, Flagged = updated.Flagged + (row.Flags.Length > 0 ? 1 : 0),
                RequestBytes = updated.RequestBytes + row.RequestBytes, ResponseBytes = updated.ResponseBytes + row.ResponseBytes };
        }
        updated = Delete(connection, transaction, updated, "timestamp<$value",
            DateTimeOffset.UtcNow.Subtract(maxAge).ToUnixTimeMilliseconds());
        if (updated.Records > maxRecords)
            updated = Delete(connection, transaction, updated, "id IN(SELECT id FROM flows ORDER BY id LIMIT $value)", updated.Records - maxRecords);
        transaction.Commit();
        Volatile.Write(ref stats, updated);
    }

    private static StoreStats Delete(SqliteConnection connection, SqliteTransaction tx, StoreStats current, string where, long value)
    {
        using var command = connection.CreateCommand();
        command.Transaction = tx;
        command.Parameters.AddWithValue("$value", value);
        command.CommandText = $"SELECT count(*),coalesce(sum(flagged),0),coalesce(sum(request_bytes),0),coalesce(sum(response_bytes),0) FROM flows WHERE {where}";
        StoreStats removed;
        using (var reader = command.ExecuteReader())
        {
            reader.Read();
            removed = new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetInt64(3));
        }
        if (removed.Records == 0) return current;
        command.CommandText = "DELETE FROM flows WHERE " + where;
        command.ExecuteNonQuery();
        return current with { Records = current.Records - removed.Records, Flagged = current.Flagged - removed.Flagged,
            RequestBytes = current.RequestBytes - removed.RequestBytes, ResponseBytes = current.ResponseBytes - removed.ResponseBytes };
    }

    public StoreStats Stats() => Volatile.Read(ref stats) with { Dropped = Dropped, Queued = Queued };

    public List<Flow> List(int limit = 100, long before = 0, string host = "", bool flagged = false)
    {
        if (limit is < 1 or > 200 || before < 0 || System.Text.Encoding.UTF8.GetByteCount(host) > 253)
            throw new ArgumentException("Invalid metadata filter");
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandTimeout = 5;
        command.CommandText = "SELECT id,timestamp,method,scheme,host,port,mode,status,request_bytes,response_bytes,duration_ms,flags,error_code FROM flows WHERE 1=1";
        if (before > 0) { command.CommandText += " AND id<$before"; command.Parameters.AddWithValue("$before", before); }
        if (host.Length > 0) { command.CommandText += " AND instr(host,$host)>0"; command.Parameters.AddWithValue("$host", host); }
        if (flagged) command.CommandText += " AND flagged=1";
        command.CommandText += " ORDER BY id DESC LIMIT $limit";
        command.Parameters.AddWithValue("$limit", limit);
        List<Flow> result = new(limit);
        using var reader = command.ExecuteReader();
        while (reader.Read()) result.Add(new Flow
        {
            Id = reader.GetInt64(0), Timestamp = reader.GetInt64(1), Method = reader.GetString(2),
            Scheme = reader.GetString(3), Host = reader.GetString(4), Port = reader.GetInt32(5),
            Mode = reader.GetString(6), Status = reader.GetInt32(7), RequestBytes = reader.GetInt64(8),
            ResponseBytes = reader.GetInt64(9), DurationMs = reader.GetInt64(10),
            Flags = JsonSerializer.Deserialize<string[]>(reader.GetString(11)) ?? throw new InvalidDataException("Null stored flags"),
            ErrorCode = reader.GetString(12)
        });
        return result;
    }

    public ValueTask DisposeAsync()
    {
        lock (closeGate) return new ValueTask(close ??= Close());
    }

    private async Task Close()
    {
        queue.Writer.TryComplete();
        try { await writer; }
        finally { await writerLock.DisposeAsync(); }
    }
}
