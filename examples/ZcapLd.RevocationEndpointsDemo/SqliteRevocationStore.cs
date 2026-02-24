using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.RevocationEndpointsDemo;

internal sealed class SqliteRevocationStore : IRevocationStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _connectionString;

    public SqliteRevocationStore(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("Connection string cannot be null or empty.", nameof(connectionString));
        }

        _connectionString = connectionString;
        InitializeSchema();
    }

    public async Task UpsertAsync(RevocationRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();

        const string sql = """
            INSERT INTO revocation_registry
            (
                capability_id,
                root_capability_id,
                revoked_by,
                revoked_at,
                expires_at,
                reason,
                metadata_json
            )
            VALUES
            (
                $capabilityId,
                $rootCapabilityId,
                $revokedBy,
                $revokedAt,
                $expiresAt,
                $reason,
                $metadataJson
            )
            ON CONFLICT(capability_id) DO UPDATE SET
                root_capability_id = excluded.root_capability_id,
                revoked_by = excluded.revoked_by,
                revoked_at = excluded.revoked_at,
                expires_at = excluded.expires_at,
                reason = excluded.reason,
                metadata_json = excluded.metadata_json;
            """;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$capabilityId", record.CapabilityId);
        command.Parameters.AddWithValue("$rootCapabilityId", (object?)record.RootCapabilityId ?? DBNull.Value);
        command.Parameters.AddWithValue("$revokedBy", record.RevokedBy);
        command.Parameters.AddWithValue("$revokedAt", record.RevokedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue(
            "$expiresAt",
            record.ExpiresAt.HasValue
                ? record.ExpiresAt.Value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)
                : DBNull.Value);
        command.Parameters.AddWithValue("$reason", (object?)record.Reason ?? DBNull.Value);
        command.Parameters.AddWithValue(
            "$metadataJson",
            record.Metadata is { Count: > 0 } ? JsonSerializer.Serialize(record.Metadata, JsonOptions) : DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<RevocationRecord?> GetByCapabilityIdAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return null;
        }

        const string sql = """
            SELECT
                capability_id,
                root_capability_id,
                revoked_by,
                revoked_at,
                expires_at,
                reason,
                metadata_json
            FROM revocation_registry
            WHERE capability_id = $capabilityId
            LIMIT 1;
            """;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$capabilityId", capabilityId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        IReadOnlyDictionary<string, string>? metadata = null;
        if (!reader.IsDBNull(6))
        {
            var metadataJson = reader.GetString(6);
            metadata = JsonSerializer.Deserialize<Dictionary<string, string>>(metadataJson, JsonOptions);
        }

        return new RevocationRecord
        {
            CapabilityId = reader.GetString(0),
            RootCapabilityId = reader.IsDBNull(1) ? null : reader.GetString(1),
            RevokedBy = reader.GetString(2),
            RevokedAt = DateTime.Parse(reader.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            ExpiresAt = reader.IsDBNull(4)
                ? null
                : DateTime.Parse(reader.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            Reason = reader.IsDBNull(5) ? null : reader.GetString(5),
            Metadata = metadata
        };
    }

    public async Task DeleteAsync(string capabilityId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(capabilityId))
        {
            return;
        }

        const string sql = """
            DELETE FROM revocation_registry
            WHERE capability_id = $capabilityId;
            """;

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$capabilityId", capabilityId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private void InitializeSchema()
    {
        const string sql = """
            CREATE TABLE IF NOT EXISTS revocation_registry
            (
                capability_id TEXT PRIMARY KEY,
                root_capability_id TEXT NULL,
                revoked_by TEXT NOT NULL,
                revoked_at TEXT NOT NULL,
                expires_at TEXT NULL,
                reason TEXT NULL,
                metadata_json TEXT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_revocation_registry_expires_at
            ON revocation_registry (expires_at);
            """;

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
