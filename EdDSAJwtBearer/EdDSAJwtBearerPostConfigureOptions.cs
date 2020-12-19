using Microsoft.Extensions.Options;
using System;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerPostConfigureOptions : IPostConfigureOptions<EdDSAJwtBearerOptions>
    {
        public void PostConfigure(string name, EdDSAJwtBearerOptions options)
        {
            if (options.ValidateIssuer && string.IsNullOrWhiteSpace(options.ValidIssuer))
            {
                throw new InvalidOperationException(EdDSAJwtBearerErrors.ValidIssuerRequired);
            }
            if (options.ValidateAudience && string.IsNullOrWhiteSpace(options.ValidAudience))
            {
                throw new InvalidOperationException(EdDSAJwtBearerErrors.ValidAudienceRequired);
            }


        }
    }
}
