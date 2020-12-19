using System;
using System.Collections.Generic;
using System.Text;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerServerOptions
    {
        // Información útil para el servidor de autorización
        // A quién va dirigido el Token.
        public string Audience { get; set; }
        // URl de quién emite el token.
        public string Issuer { get; set; }
        // Llave para que el servidor de autenticación firme el token
        public string PrivateSigningKey { get; set; }
        // Llave para validar la firma
        public string PublicSigningKey { get; set; }
    }
}
