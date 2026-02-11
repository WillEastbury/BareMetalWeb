using System.Runtime.InteropServices;
namespace BareMetalWeb.Data;

    public static class BinaryArchitectureMapper
    {
        public static BinaryArchitecture Current => FromRuntimeArchitecture(RuntimeInformation.ProcessArchitecture);

        public static BinaryArchitecture FromRuntimeArchitecture(Architecture architecture)
        {
            return architecture switch
            {
                Architecture.X86 => BinaryArchitecture.X86,
                Architecture.X64 => BinaryArchitecture.X64,
                Architecture.Arm => BinaryArchitecture.Arm,
                Architecture.Arm64 => BinaryArchitecture.Arm64,
                Architecture.Wasm => BinaryArchitecture.Wasm,
                Architecture.S390x => BinaryArchitecture.S390x,
                Architecture.LoongArch64 => BinaryArchitecture.LoongArch64,
                _ => BinaryArchitecture.Unknown
            };
        }
    }


