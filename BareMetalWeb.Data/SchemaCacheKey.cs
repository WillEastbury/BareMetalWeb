namespace BareMetalWeb.Data;


    public readonly struct SchemaCacheKey : IEquatable<SchemaCacheKey>
    {
        public SchemaCacheKey(Type type, int version, uint hash, SchemaReadMode mode)
        {
            Type = type;
            Version = version;
            Hash = hash;
            Mode = mode;
        }

        public Type Type { get; }
        public int Version { get; }
        public uint Hash { get; }
        public SchemaReadMode Mode { get; }

        public bool Equals(SchemaCacheKey other)
            => ReferenceEquals(Type, other.Type) && Version == other.Version && Hash == other.Hash && Mode == other.Mode;

        public override bool Equals(object? obj)
            => obj is SchemaCacheKey other && Equals(other);

        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Type);
            hash.Add(Version);
            hash.Add(Hash);
            hash.Add((int)Mode);
            return hash.ToHashCode();
        }
    }
