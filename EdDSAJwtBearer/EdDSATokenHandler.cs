using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace EdDSAJwtBearer
{
    public static class EdDSATokenHandler
    {
        public static string CreateToken(Dictionary<string, object> payload, string edDSAPrivateKey)
        {
            var HeaderValues = new Dictionary<string, object> {
                 { "typ", "JWT" },
                 { "alg", "EdDSA"}
             };

            string Header = JsonSerializer.Serialize(HeaderValues);
            string Payload = JsonSerializer.Serialize(payload);

            Header = Base64UrlEncode(Header);
            Payload = Base64UrlEncode(Payload);

            string Signature = GetJWTSignature(Header, Payload, edDSAPrivateKey);

            return $"{Header}.{Payload}.{Signature}";


        }

        public static string CreateToken(string edDSAPrivateKey,
            string issuer = null,
            string audience = null,
            IEnumerable<Claim> claims = null,
            string[] roles = null,
            DateTime? expires = null)
                {

            Dictionary<string, object> Payload = new Dictionary<string, object>();
            if (claims != null)
            {
                foreach (var Item in claims)
                {
                    Payload.TryAdd(Item.Type, Item.Value);
                }
            }

            if (issuer != null) Payload.Add("iss", issuer);
            if (audience != null) Payload.Add("aud", audience);
            if (expires != null) Payload.Add("exp",
            new DateTimeOffset(expires.Value).ToUnixTimeSeconds());
            if (roles != null && roles.Length > 0) Payload.Add("role", roles);

            return CreateToken(Payload, edDSAPrivateKey);

        }

        public static string Base64UrlEncode(byte[] data)
        {
            string Result = Convert.ToBase64String(data); // Codificar a base64
            Result = Result.Split('=')[0]; // Eliminar caracteres de Padding (=)
            Result = Result.Replace('+', '-'); // Remplazar el caracter (+)
            Result = Result.Replace('/', '_'); // Remplazar el caracter (/)
            return Result;
        }

        public static string Base64UrlEncode(string data)
        {
            byte[] DataBytes = Encoding.UTF8.GetBytes(data);
            return Base64UrlEncode(DataBytes);
        }

        public static byte[] Base64UrlDecode(string data)
        {
            string Result = data;
            Result = Result.Replace('-', '+'); // Remplazar caracter (-)
            Result = Result.Replace('_', '/'); // Remplazar caracter (_)
            switch (Result.Length % 4) // Agregar Padding '='
            {
                case 0: break; // No es necesario el Padding
                case 2: Result += "=="; break; // 2 caracteres de Padding
                case 3: Result += "="; break; // Un caracter de Padding
                default:
                    throw new System.Exception("Illegal base64url string!");
            }
            return Convert.FromBase64String(Result); // decodificar base64
        }

        static string GetJWTSignature(string header, string payload, string edDSAprivateKey)
        {
            string SignatureData = $"{header}.{payload}";
            var SignatureBytes = Encoding.UTF8.GetBytes(SignatureData);

            var Signer = new Ed25519Signer();

            Signer.Init(true, GetDerDecodedAsymmetricPrivateKeyParameter(edDSAprivateKey));
            Signer.BlockUpdate(SignatureBytes, 0, SignatureBytes.Length);
            string Signature = Base64UrlEncode(Signer.GenerateSignature());
            return Signature;
        }

        private static AsymmetricKeyParameter GetDerDecodedAsymmetricPrivateKeyParameter(string privateKey)
        {
            return PrivateKeyFactory.CreateKey(
            Convert.FromBase64String(privateKey));
        }

        private static AsymmetricKeyParameter GetDerDecodedAsymmetricPublicKeyParameter(string publicKey)
        {
            return PublicKeyFactory.CreateKey(
            Convert.FromBase64String(publicKey));
        }

        private static AsymmetricCipherKeyPair GetDerDecodedAsymmetricCipherKeyPair(EdDSAKeys keys)
        {
            var PrivateKey = GetDerDecodedAsymmetricPrivateKeyParameter(keys.Private);
            var PublicKey  = GetDerDecodedAsymmetricPublicKeyParameter(keys.Public);
            return new AsymmetricCipherKeyPair(PublicKey, PrivateKey);
        }

        private static EdDSAKeys GetDerEncodedAsymmetricCipherKeyPair(AsymmetricCipherKeyPair keys)
        {
            EdDSAKeys EdDSAKeys = new EdDSAKeys();
            var PrivateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private);
            byte[] Buffer = PrivateKeyInfo.ToAsn1Object().GetDerEncoded(); // Codifica a formato Der
            EdDSAKeys.Private = Convert.ToBase64String(Buffer);
            var SubjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public);
            Buffer = SubjectPublicKeyInfo.ToAsn1Object().GetDerEncoded();
            EdDSAKeys.Public = Convert.ToBase64String(Buffer);
            return EdDSAKeys;
        }

        private static AsymmetricCipherKeyPair CreateKeys()
        {
            var KeyPairGenerator = new Ed25519KeyPairGenerator();
            KeyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair KeyPair =KeyPairGenerator.GenerateKeyPair();
            return KeyPair;
        }

        public static EdDSAKeys CreateDerEncodedKeys()
        {
            return GetDerEncodedAsymmetricCipherKeyPair(CreateKeys());
        }



        public static bool VerifySignature(string token, string edDSAPublicKey)
        {
            bool Result = false;
            try
            {
                // Dividir el Token en sus 3 partes
                string[] JWTParts = token.Split(".");
                if (JWTParts.Length == 3)
                {
                    string Data = $"{JWTParts[0]}.{JWTParts[1]}";
                    byte[] DataBytes = Encoding.UTF8.GetBytes(Data);
                    // La firma creada por EdDSA fue codificada a Base64Url
                    // por lo que es necesario decodificarla para poder obtener
                    // la firma original (sin codificar) y el validador pueda
                    // hacer la comparación con la firma original y no con
                    // la firma codificada a Base64Url.
                    byte[] Signature = Base64UrlDecode(JWTParts[2]);
                    var Validator = new Ed25519Signer();
                    Validator.Init(false, // Validar, no Crear la firma
                    GetDerDecodedAsymmetricPublicKeyParameter(edDSAPublicKey));
                    Validator.BlockUpdate(DataBytes, 0, DataBytes.Length);
                    Result = Validator.VerifySignature(Signature);
                }
            }
            catch
            {
                // El token no pudo ser verificado
            }
            return Result;
        }


        public static bool TryGetPayloadFromToken(string token, string edDSAPublicKey, 
                                                                out Dictionary<string, object> payload)
        {
            bool Result = false;
            payload = null;
            try
            {
                if (VerifySignature(token, edDSAPublicKey))
                {
                    // Obtener la segunda parte del Token
                    string PayloadData = token.Split(".")[1];
                    // Obtener su representación JSON
                    string JSONPayload =
                     Encoding.UTF8.GetString(Base64UrlDecode(PayloadData));
                    // Deserializar al diccionario de parejas llave-valor
                    payload = JsonSerializer
                    .Deserialize<Dictionary<string, object>>(JSONPayload);
                    Result = true;
                }
            }
            catch
            {
                // No se pudo obtener el contenido
            }
            return Result;
        }






    }
}
