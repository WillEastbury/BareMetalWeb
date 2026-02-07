using System;

namespace BareMetalWeb.Interfaces;

public interface ISynchronousEncryption
{
    byte[] Encrypt(byte[] plaintext, byte[]? associatedData = null);
    byte[] Decrypt(byte[] payload, byte[]? associatedData = null);
    string EncryptToBase64(string plaintext, byte[]? associatedData = null);
    string DecryptFromBase64(string payloadBase64, byte[]? associatedData = null);
}
