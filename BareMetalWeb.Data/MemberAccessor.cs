namespace BareMetalWeb.Data;



    public sealed class MemberAccessor
    {
        public MemberAccessor(string name, Type memberType, Func<object, object?> getter, Action<object, object?> setter)
        {
            Name = name;
            MemberType = memberType;
            Getter = getter;
            Setter = setter;
        }

        public string Name { get; }
        public Type MemberType { get; }
        public Func<object, object?> Getter { get; }
        public Action<object, object?> Setter { get; }
    }
