using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;


var pemKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCW8dxhuYKAgwfwlNqSit0qxFYNOktxWcRboNopWaia75y8eWEC\nsLqHWpw/gbNbaQzikmI+Hj576RvIvWPDGUHnW8DWnOxliAkd8kYHf1EhVWDzoQCM\nVmRxX8QzmKZtN3DmuctK4qBRCZA9k/1aROJpMBnCkiBBS4Kbyf6/pR1YdQIDAQAB\nAoGAFo9Rc92pDpIG5sMoo8xTX+f2QIXc7rUO7u7sjE+VLorvbw/pGuDVEBPP1IIL\nD3d08IwWWNhmWFivyWHc/jTRL4syyhd0ON2ZjVyaD3gwWOnzlISIcmz5u3iVZbXn\nKHorW4lRWUf6zwyflLDRMi0KDQ9x2ens4iieFIJRcpxsUoUCQQDKhhGY8JcCwdQN\noyS1mixNeGsn56nFWH6+zCGJKDLnCdNCRu9dWb+LRNy2/rUiFYirO9epiiIBeBeH\ncWSgYcU7AkEAvs06GPZjZQrJCif+WsyYSxcsV2i7Hdy1b8jwprEoEA+HYzZnqkgV\nXPsiIIGjRi6l/O/dD/p0jqQqZQ1y6PO+DwJBAMcMFeeXLxSKpHvyyHWkXb6Wh9rk\nmbtYStoDj0JavAzPX09YoJHDT7r1p2hD1or1VynU2xXKqbl/6sA39oqbDVkCQQCO\nfZeIsuCxwec3lXyH9Mk7MtgjgwxSldRN4iOOaTkBHYe/WQ78BQ8nPElVO1ti+01s\n4vkViLZpHEKo6u1I+VaTAkBY1ZkihEiL+4Zv/LIM4wcAewLkADx1Oou6mEDCbF3r\nyZNxhoL3inPPGgGvtVNDgqe8XRiwZc52J8MxWWXDxbii\n-----END RSA PRIVATE KEY-----\n";
var batchBody = "BRBANK;06971135800;PIX;John Smith;j.smith@example.com;1.00;9999;Payout";


try
{
    // get_token is required before import_batch_advanced in case of password encryption
    var resultToken = await get_token(BasicConfig.Login);
    Console.WriteLine("Response:\n" + resultToken);

    // Encrypt password using RSA public key from get_token response
    encryptPassword(BasicConfig.PlainPassword);
    
    // Import batch using encrypted password and RSA private key to sign BATCH_BODY
    var result = await importBatch( batchBody, pemKey);
    Console.WriteLine("Response:\n" + result);
}
catch (Exception ex)
{
    Console.Error.WriteLine("Request failed: " + ex.Message);
}


static async Task<string> importBatch(string batchBody, string pemPrivateKeyPem)
{
    if (batchBody == null) throw new ArgumentNullException(nameof(batchBody));
    if (string.IsNullOrWhiteSpace(pemPrivateKeyPem)) throw new ArgumentException("PEM private key is required", nameof(pemPrivateKeyPem));

    var data = new Dictionary<string, string>
    {
        ["operation"] = "import_batch_advanced",
        ["login"] = BasicConfig.Login,
        ["token"] = AuthState.Token,
        ["batch"] = batchBody,
        ["verification_type"] = "SIGNATURE",
        ["encrypted_password"] = AuthState.Encrypted_Password,
        // Compute RSA signature over the batchBody using SHA-1 + PKCS#1 v1.5 to match PHP example
        ["verification_data"] = SignPlaintext(batchBody, pemPrivateKeyPem), 
    };
    
    // Send the request using form-url-encoded content
    return await ApiClient.PostHashAsync(data, useMultipart: false);
}

static string SignPlaintext(string plaintext, string pemPrivateKeyPem)
{
    if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
    if (string.IsNullOrWhiteSpace(pemPrivateKeyPem)) throw new ArgumentException("PEM private key is required", nameof(pemPrivateKeyPem));

    using RSA rsa = RSA.Create();
    rsa.ImportFromPem(pemPrivateKeyPem.AsSpan());
    byte[] payload = Encoding.UTF8.GetBytes(plaintext);

    // phpseclib RSA::SIGNATURE_PKCS1 without explicit setHash defaults to SHA-1
    // so we mirror that here with SHA1 + PKCS#1 v1.5 and return base64-encoded signature
    byte[] signatureBytes = rsa.SignData(payload, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    return Convert.ToBase64String(signatureBytes);
}

static async Task<string> get_token(string login, CancellationToken cancellationToken = default)
{
    if (string.IsNullOrWhiteSpace(login)) throw new ArgumentException("login is required", nameof(login));

    var data = new Dictionary<string, string>
    {
        ["operation"] = "get_token",
        ["login"] = login,
    };

    var response = await ApiClient.PostHashAsync(data, useMultipart: false, cancellationToken);

    try
    {
        using var doc = JsonDocument.Parse(response);
        var root = doc.RootElement;
        if (root.TryGetProperty("data", out var dataEl))
        {
            if (dataEl.TryGetProperty("token", out var tokenEl))
            {
                AuthState.Token = tokenEl.GetString();
            }
            if (dataEl.TryGetProperty("rsa_public_key_pkcs1_pem", out var pubEl))
            {
                AuthState.PublicKey = pubEl.GetString();
            }
            if (dataEl.TryGetProperty("modulus", out var modEl))
            {
                AuthState.ModulusHex = modEl.GetString();
            }
            if (dataEl.TryGetProperty("exponent", out var expEl))
            {
                AuthState.ExponentHex = expEl.GetString();
            }
        }
    }
    catch
    {
        // Ignore JSON parsing errors; return raw response regardless
    }

    return response;
}

static string encryptPassword(string plainPassword)
{
    if (string.IsNullOrWhiteSpace(plainPassword)) throw new ArgumentException("plainPassword is required", nameof(plainPassword));
    if (string.IsNullOrWhiteSpace(AuthState.ModulusHex) || string.IsNullOrWhiteSpace(AuthState.ExponentHex))
        throw new InvalidOperationException("RSA modulus/exponent are not set. Call get_token first and ensure response contains modulus/exponent.");

    // Build RSA key from modulus and exponent (hex strings from API), then encrypt password using PKCS#1 v1.5
    using RSA rsa = RSA.Create();
    var rsaParams = new RSAParameters
    {
        Modulus = HexToBytes(AuthState.ModulusHex!),
        Exponent = HexToBytes(AuthState.ExponentHex!),
    };
    rsa.ImportParameters(rsaParams);

    byte[] payload = Encoding.UTF8.GetBytes(plainPassword);
    byte[] cipher = rsa.Encrypt(payload, RSAEncryptionPadding.Pkcs1);

    string hex = BytesToUpperHex(cipher);
    AuthState.Encrypted_Password = hex;
    return hex;
}

static byte[] HexToBytes(string hex)
{
    if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex.Substring(2);
    if (hex.Length % 2 == 1) hex = "0" + hex; // pad if needed
    int len = hex.Length / 2;
    byte[] result = new byte[len];
    for (int i = 0; i < len; i++)
    {
        int hi = GetHexVal(hex[2 * i]) << 4;
        int lo = GetHexVal(hex[2 * i + 1]);
        result[i] = (byte)(hi | lo);
    }
    return result;
}

static int GetHexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw new FormatException("Invalid hex character: " + c);
}

static string BytesToUpperHex(ReadOnlySpan<byte> bytes)
{
    char[] c = new char[bytes.Length * 2];
    int b;
    for (int i = 0; i < bytes.Length; i++)
    {
        b = bytes[i] >> 4;
        c[2 * i] = (char)(55 + b + (((b - 10) >> 31) & -7));
        b = bytes[i] & 0xF;
        c[2 * i + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
    }
    return new string(c);
}

static class ApiClient
{
    private static readonly HttpClient http = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    /// <summary>
    /// Sends a hash (dictionary) of data via HTTP POST to https://api.capitalist.net
    /// Adds header: x-response-type: json
    /// Content-Type can be application/x-www-form-urlencoded (default) or multipart/form-data when useMultipart=true
    /// </summary>
    /// <param name="data">Key-value pairs to send</param>
    /// <param name="useMultipart">If true, uses multipart/form-data; otherwise application/x-www-form-urlencoded</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Response body as string</returns>
    public static async Task<string> PostHashAsync(Dictionary<string, string> data, bool useMultipart = false, CancellationToken cancellationToken = default)
    {
        var url = "https://api.capitalist.net";

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        // Required custom header
        request.Headers.TryAddWithoutValidation("x-response-format", "json");
        request.Headers.TryAddWithoutValidation("x-language", "en");

        HttpContent content;
        if (!useMultipart)
        {
            content = new FormUrlEncodedContent(data ?? new Dictionary<string, string>());
        }
        else
        {
            var multipart = new MultipartFormDataContent();
            if (data != null)
            {
                foreach (var kv in data)
                {
                    multipart.Add(new StringContent(kv.Value ?? string.Empty, Encoding.UTF8), kv.Key);
                }
            }
            content = multipart;
        }

        request.Content = content;

        using var response = await http.SendAsync(request, cancellationToken);
        var responseText = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return responseText;
    }
}

static class AuthState
{
    public static string? Token { get; set; }
    public static string? PublicKey { get; set; }
    public static string? Encrypted_Password { get; set; }
    public static string? ModulusHex { get; set; }
    public static string? ExponentHex { get; set; }
}

class BasicConfig
{
    public static string Login { get; set; } = "mylogin";
    public static string PlainPassword { get; set; } = "mypassword";
}
