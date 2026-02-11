namespace BareMetalWeb.Data;

    public sealed class TypeShape
    {
        private static readonly Dictionary<string, MemberAccessor> EmptyMemberMap = new Dictionary<string, MemberAccessor>(0, StringComparer.Ordinal);

        public TypeShape(Type type)
        {
            Type = type;
            Kind = TypeKind.Object;
            TypeCode = TypeCode.Object;
            Members = Array.Empty<MemberAccessor>();
            MemberMap = EmptyMemberMap;
            MemberSignatures = Array.Empty<MemberSignature>();
            SignatureHash = 2166136261;
        }

        public Type Type { get; }
        public TypeKind Kind { get; set; }
        public TypeCode TypeCode { get; set; }
        public bool IsNullable { get; set; }
        public Type? NullableUnderlying { get; set; }
        public Type? EnumUnderlying { get; set; }
        public Type? ElementType { get; set; }
        public Type? KeyType { get; set; }
        public Type? ValueType { get; set; }
        public Func<int, Array>? ArrayFactory { get; set; }
        public Func<int, System.Collections.IList>? ListFactory { get; set; }
        public Func<int, System.Collections.IDictionary>? DictionaryFactory { get; set; }
        public MemberAccessor[] Members { get; set; }
        public Dictionary<string, MemberAccessor> MemberMap { get; set; }
        public MemberSignature[] MemberSignatures { get; set; }
        public uint SignatureHash { get; set; }
        public int BlittableSize { get; set; }
        public Action<object?, byte[]>? BlittableWrite { get; set; }
        public Func<byte[], object>? BlittableRead { get; set; }
    }
