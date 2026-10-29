using FluentAssertions;
using Microsoft.Data.Sqlite;
using Xunit;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.RevocationEndpointsDemo;

namespace ZcapLd.AspNetCore.Tests;

/// <summary>
/// The <see cref="IRevocationStore"/> contract (#158), run against the in-memory store and the demo's
/// SQLite store: records are keyed by <see cref="RevocationRecord.Key"/> only, batch reads return
/// exactly the requested keys, deletes are exact, every field round-trips, and a pre-6.0 SQLite
/// registry migrates into unscoped records.
/// </summary>
public sealed class RevocationStoreContractTests : IDisposable
{
    private static readonly RevocationScope Alice = RevocationScope.Delegated("did:key:z6MkAlice");
    private static readonly RevocationScope Mallory = RevocationScope.Delegated("did:key:z6MkMallory");

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"zcap-revocation-{Guid.NewGuid():N}.db");

    private string ConnectionString => $"Data Source={_dbPath}";

    public static TheoryData<string> Stores => new() { "InMemory", "Sqlite" };

    private IRevocationStore Create(string kind)
        => kind == "Sqlite" ? new SqliteRevocationStore(ConnectionString) : new InMemoryRevocationStore();

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            File.Delete(_dbPath + suffix);
        }
    }

    private static RevocationRecord Record(string id, RevocationScope scope, string revokedBy = "did:key:z6MkRevoker")
        => new()
        {
            CapabilityId = id,
            Scope = scope,
            RootCapabilityId = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fresource",
            RevokedBy = revokedBy,
            RevokedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(3),
            Reason = "rotation",
            Metadata = new Dictionary<string, string> { ["ticket"] = "SEC-158" }
        };

    [Theory]
    [MemberData(nameof(Stores))]
    public async Task Upsert_IsKeyedByScopeNotByCapabilityId(string kind)
    {
        var store = Create(kind);
        const string id = "urn:uuid:shared";
        await store.UpsertAsync(Record(id, Alice, "did:key:z6MkAlice"));
        await store.UpsertAsync(Record(id, Mallory, "did:key:z6MkMallory"));

        (await store.GetAsync([Alice.KeyFor(id)])).Should().ContainSingle().Which.RevokedBy.Should().Be("did:key:z6MkAlice",
            "Mallory's record for the same id must not overwrite Alice's");
        (await store.GetAsync([Mallory.KeyFor(id)])).Should().ContainSingle().Which.RevokedBy.Should().Be("did:key:z6MkMallory");
        (await store.GetAsync([RevocationScope.Unscoped.KeyFor(id)])).Should().BeEmpty();
        (await store.GetAsync([RevocationScope.Root.KeyFor(id)])).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Stores))]
    public async Task Get_ReturnsExactlyTheRequestedKeys(string kind)
    {
        var store = Create(kind);
        var first = Record("urn:uuid:first", Alice);
        var second = Record("urn:uuid:second", RevocationScope.Root);
        var third = Record("urn:uuid:third", RevocationScope.Unscoped);
        foreach (var record in new[] { first, second, third })
        {
            await store.UpsertAsync(record);
        }

        var found = await store.GetAsync([first.Key, third.Key, RevocationScope.Root.KeyFor("urn:uuid:unknown"), first.Key]);

        found.Select(record => record.Key).Should().BeEquivalentTo([first.Key, third.Key]);
        (await store.GetAsync([])).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Stores))]
    public async Task Delete_RemovesOnlyThatKey(string kind)
    {
        var store = Create(kind);
        const string id = "urn:uuid:delete";
        var alice = Record(id, Alice);
        var mallory = Record(id, Mallory);
        await store.UpsertAsync(alice);
        await store.UpsertAsync(mallory);

        await store.DeleteAsync(mallory.Key);

        (await store.GetAsync([mallory.Key])).Should().BeEmpty();
        (await store.GetAsync([alice.Key])).Should().ContainSingle();
    }

    [Theory]
    [MemberData(nameof(Stores))]
    public async Task RoundTrip_PreservesEveryField(string kind)
    {
        var store = Create(kind);
        var record = Record("urn:uuid:round-trip", Alice);

        await store.UpsertAsync(record);
        var stored = (await store.GetAsync([record.Key])).Single();

        stored.Key.Should().Be(record.Key);
        stored.CapabilityId.Should().Be(record.CapabilityId);
        stored.Scope.Should().Be(record.Scope);
        stored.RootCapabilityId.Should().Be(record.RootCapabilityId);
        stored.RevokedBy.Should().Be(record.RevokedBy);
        stored.RevokedAt.ToUniversalTime().Should().Be(record.RevokedAt.ToUniversalTime());
        stored.ExpiresAt!.Value.ToUniversalTime().Should().Be(record.ExpiresAt!.Value.ToUniversalTime());
        stored.Reason.Should().Be(record.Reason);
        stored.Metadata.Should().BeEquivalentTo(record.Metadata);
    }

    [Theory]
    [MemberData(nameof(Stores))]
    public async Task Upsert_SameKeyReplaces(string kind)
    {
        var store = Create(kind);
        var record = Record("urn:uuid:replace", Alice);
        await store.UpsertAsync(record);

        await store.UpsertAsync(record with { Reason = "second" });

        (await store.GetAsync([record.Key])).Should().ContainSingle().Which.Reason.Should().Be("second");
    }

    [Theory]
    [MemberData(nameof(Stores))]
    public async Task ThroughTheService_ScopesIsolateAndUnscopedApplies(string kind)
    {
        var service = new RevocationService(Create(kind));
        await service.RevokeAsync(new RevocationRequest { CapabilityId = "urn:uuid:scoped", Scope = Mallory, RevokedBy = "did:key:z6MkMallory" });
        await service.RevokeAsync(new RevocationRequest { CapabilityId = "urn:uuid:legacy", Scope = RevocationScope.Unscoped, RevokedBy = "did:key:z6MkOperator" });

        (await service.IsRevokedAsync("urn:uuid:scoped", Mallory)).Should().BeTrue();
        (await service.IsRevokedAsync("urn:uuid:scoped", Alice)).Should().BeFalse();
        (await service.IsRevokedAsync("urn:uuid:legacy", Alice)).Should().BeTrue();
        (await service.IsRevokedAsync("urn:uuid:legacy", RevocationScope.Root)).Should().BeTrue();
    }

    [Fact]
    public async Task Sqlite_MigratesALegacyRegistryIntoUnscopedRecords()
    {
        // A 5.x database: one table keyed by bare capability id.
        await using (var connection = new SqliteConnection(ConnectionString))
        {
            await connection.OpenAsync();
            await using var create = connection.CreateCommand();
            create.CommandText = """
                CREATE TABLE revocation_registry
                (
                    capability_id TEXT PRIMARY KEY,
                    root_capability_id TEXT NULL,
                    revoked_by TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    expires_at TEXT NULL,
                    reason TEXT NULL,
                    metadata_json TEXT NULL
                );
                INSERT INTO revocation_registry VALUES
                    ('urn:uuid:legacy-1', 'urn:zcap:root:https%3A%2F%2Fexample.com%2Fr', 'did:key:z6MkOwner', '2026-01-02T03:04:05.0000000Z', NULL, 'lost', '{"ticket":"OLD-1"}'),
                    ('urn:uuid:legacy-2', NULL, 'did:key:z6MkOwner', '2026-01-02T03:04:06.0000000Z', '2099-01-01T00:00:00.0000000Z', NULL, NULL);
                """;
            await create.ExecuteNonQueryAsync();
        }

        var store = new SqliteRevocationStore(ConnectionString);

        var first = (await store.GetAsync([RevocationScope.Unscoped.KeyFor("urn:uuid:legacy-1")])).Should().ContainSingle().Subject;
        first.Scope.Should().Be(RevocationScope.Unscoped);
        first.RootCapabilityId.Should().Be("urn:zcap:root:https%3A%2F%2Fexample.com%2Fr");
        first.RevokedBy.Should().Be("did:key:z6MkOwner");
        first.Reason.Should().Be("lost");
        first.Metadata.Should().ContainKey("ticket").WhoseValue.Should().Be("OLD-1");
        var second = (await store.GetAsync([RevocationScope.Unscoped.KeyFor("urn:uuid:legacy-2")])).Should().ContainSingle().Subject;
        second.ExpiresAt.Should().Be(new DateTime(2099, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        // Migrated records are honoured on every chain, as 5.x records were.
        var service = new RevocationService(store);
        (await service.IsRevokedAsync("urn:uuid:legacy-1", Alice)).Should().BeTrue();
        (await service.IsRevokedAsync("urn:uuid:legacy-1", RevocationScope.Root)).Should().BeTrue();

        // The legacy table is gone, and opening the store again is a no-op.
        await using (var connection = new SqliteConnection(ConnectionString))
        {
            await connection.OpenAsync();
            await using var probe = connection.CreateCommand();
            probe.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'revocation_registry';";
            (await probe.ExecuteScalarAsync()).Should().Be(0L);
        }

        _ = new SqliteRevocationStore(ConnectionString);
        (await store.GetAsync([RevocationScope.Unscoped.KeyFor("urn:uuid:legacy-1")])).Should().ContainSingle();
    }

    [Fact]
    public async Task Sqlite_MigrationSkipsOnlyUnkeyableRows_AndKeepsRevocationsWithBadDates()
    {
        await using (var connection = new SqliteConnection(ConnectionString))
        {
            await connection.OpenAsync();
            await using var create = connection.CreateCommand();
            create.CommandText = """
                CREATE TABLE revocation_registry
                (
                    capability_id TEXT PRIMARY KEY,
                    root_capability_id TEXT NULL,
                    revoked_by TEXT NOT NULL,
                    revoked_at TEXT NOT NULL,
                    expires_at TEXT NULL,
                    reason TEXT NULL,
                    metadata_json TEXT NULL
                );
                INSERT INTO revocation_registry VALUES
                    ('', NULL, 'did:key:z6MkOwner', '2026-01-02T03:04:05.0000000Z', NULL, NULL, NULL),
                    ('urn:uuid:bad-dates', NULL, 'did:key:z6MkOwner', 'not a date', 'also not', NULL, 'not json'),
                    ('urn:uuid:good', NULL, 'did:key:z6MkOwner', '2026-01-02T03:04:06.0000000Z', NULL, NULL, NULL);
                """;
            await create.ExecuteNonQueryAsync();
        }

        // Must not throw: a crash here would repeat on every restart and keep the host down (red team).
        var store = new SqliteRevocationStore(ConnectionString);

        (await store.GetAsync([RevocationScope.Unscoped.KeyFor("urn:uuid:good")])).Should().ContainSingle();
        var kept = (await store.GetAsync([RevocationScope.Unscoped.KeyFor("urn:uuid:bad-dates")])).Should().ContainSingle().Subject;
        kept.ExpiresAt.Should().BeNull("an unparsable expiry must not expire the revocation");
        kept.RevokedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
        kept.Metadata.Should().BeNull();

        await using (var connection = new SqliteConnection(ConnectionString))
        {
            await connection.OpenAsync();
            await using var probe = connection.CreateCommand();
            probe.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'revocation_registry';";
            (await probe.ExecuteScalarAsync()).Should().Be(0L, "the legacy table is dropped once the usable rows are migrated");
        }
    }

    [Fact]
    public async Task Sqlite_PrimaryKeyIsTheRecordKey()
    {
        _ = new SqliteRevocationStore(ConnectionString);

        await using var connection = new SqliteConnection(ConnectionString);
        await connection.OpenAsync();
        await using var pragma = connection.CreateCommand();
        pragma.CommandText = "SELECT name FROM pragma_table_info('revocation_records') WHERE pk = 1;";
        (await pragma.ExecuteScalarAsync()).Should().Be("revocation_key",
            "a primary key on capability_id would let a record in one scope overwrite another's");
    }
}
