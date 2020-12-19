using System;
using System.Collections.Generic;
using System.Text;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerErrors
    {
        // Errores al validar las opciones de configuración
        public const string ValidIssuerRequired =
        "ValidIssuer is required when ValidateIssuer is true";
        public const string ValidAudienceRequired =
        "ValidAudience is required when ValidateAudience is true";
        // Errores al validar el Token
        public const string InvalidToken =
        "(001) Invalid Bearer authentication token";
        public const string InvalidIssuer =
        "(002) Invalid Issuer";
        public const string InvalidAudience =
        "(003) Invalid audience";
        public const string ExpiredToken =
        "(004) Token has expired";

    }
}
