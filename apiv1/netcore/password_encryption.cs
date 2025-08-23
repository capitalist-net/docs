using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public static class PasswordEncoder
{
    /// <summary>
    /// Encrypts a password using RSA public key encryption
    /// </summary>
    /// <param name="password">The password to encrypt</param>
    /// <param name="exponent">RSA public key exponent as hex string</param>
    /// <param name="modulus">RSA public key modulus as hex string</param>
    /// <returns>Encrypted password as uppercase hexadecimal string</returns>
    public static string EncryptPassword(string password, string exponent, string modulus)
    {
        try
        {
            // Convert hex strings to BigInteger
            var modulusBigInt = BigInteger.Parse(modulus, System.Globalization.NumberStyles.HexNumber);
            var exponentBigInt = BigInteger.Parse(exponent, System.Globalization.NumberStyles.HexNumber);
            
            // Create RSA parameters
            var rsaParameters = new RSAParameters
            {
                Modulus = GetBytesFromBigInteger(modulusBigInt),
                Exponent = GetBytesFromBigInteger(exponentBigInt)
            };
            
            // Create RSA provider and import public key
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(rsaParameters);
                
                // Convert password to UTF-8 bytes
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                
                // Encrypt with PKCS1 padding
                var encryptedBytes = rsa.Encrypt(passwordBytes, RSAEncryptionPadding.Pkcs1);
                
                // Convert to uppercase hex string
                return ByteArrayToHexString(encryptedBytes);
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to encrypt password", ex);
        }
    }
    
    /// <summary>
    /// Converts BigInteger to byte array with proper formatting for RSA
    /// </summary>
    private static byte[] GetBytesFromBigInteger(BigInteger bigInt)
    {
        var bytes = bigInt.ToByteArray();
        
        // Remove leading zero byte if present (for positive numbers)
        if (bytes.Length > 1 && bytes[bytes.Length - 1] == 0)
        {
            var trimmed = new byte[bytes.Length - 1];
            Array.Copy(bytes, trimmed, trimmed.Length);
            return ReverseBytes(trimmed);
        }
        
        return ReverseBytes(bytes);
    }
    
    /// <summary>
    /// Reverses byte array (BigInteger is little-endian, RSA expects big-endian)
    /// </summary>
    private static byte[] ReverseBytes(byte[] bytes)
    {
        var reversed = new byte[bytes.Length];
        for (int i = 0; i < bytes.Length; i++)
        {
            reversed[i] = bytes[bytes.Length - 1 - i];
        }
        return reversed;
    }
    
    /// <summary>
    /// Converts byte array to uppercase hexadecimal string
    /// </summary>
    private static string ByteArrayToHexString(byte[] bytes)
    {
        var hex = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            hex.AppendFormat("{0:X2}", b);
        }
        return hex.ToString();
    }
}

// Usage example
public class Program
{
    public static void Main()
    {
        // Example parameters (replace with real values from your API)
        string exponent = "10001"; // Usually this is a standard value
        string modulus = "A1B2C3D4E5F6..."; // Your modulus in hex format
        
        string password = "mySecretPassword";
        
        try
        {
            string encryptedPassword = PasswordEncoder.EncryptPassword(password, exponent, modulus);
            Console.WriteLine($"Encrypted password: {encryptedPassword}");
            
            // Now send encryptedPassword to your API
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Encryption failed: {ex.Message}");
        }
    }
}
