using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace EdDSAJwtBearer
{
    public class EdDSAJwtBearerAuthenticationHandler : AuthenticationHandler<EdDSAJwtBearerOptions>
    {
        public EdDSAJwtBearerAuthenticationHandler(
             // Utilizado para monitorear cambios de la instancia
             // EdDSAJwtBearerOptions
             IOptionsMonitor<EdDSAJwtBearerOptions> options,
             // Para crear instancias de ILogger y poder escribir mensajes de Log
             ILoggerFactory logger,
             // Para codificar cadenas que sean transportables en un Url
             UrlEncoder encoder,
             // Para tener acceso al reloj del sistema.
             ISystemClock clock) : base(options, logger, encoder, clock) { }


        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            AuthenticateResult Result = AuthenticateResult.NoResult();
            // Lógica de autenticación
            if (Request.Headers.ContainsKey("Authorization"))
            {
                if (AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"],
                    out AuthenticationHeaderValue HeaderValue))
                {
                    if ("Bearer".Equals(HeaderValue.Scheme, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            string Error;
                            string Token = HeaderValue.Parameter;

                            if (TryGetPayloadWithTokenValidation(Token, Options, out Dictionary<string, object> Payload, out Error))
                            {
                                List<Claim> Claims = Payload.Where(c => c.Key != "role")
                                        .Select(c => new Claim(c.Key, $"{c.Value}")).ToList();

                                if (Payload.TryGetValue("role", out object Roles))
                                {
                                    // Deserializar el arreglo JSON
                                    string[] RolesArray = JsonSerializer.Deserialize<string[]>(Roles.ToString());
                                    if (RolesArray != null)
                                    {
                                        // Agregar los roles del usuario a la lista de Claims
                                        foreach (var Role in RolesArray)
                                        {
                                            Claims.Add(new Claim("role", Role.ToString()));
                                        }
                                    }
                                }

                                ClaimsIdentity Identity = new ClaimsIdentity(
                                     // Claims con información del usuario
                                     Claims,
                                     // Nombre del esquema de autenticación
                                     Scheme.Name,
                                     // Nombre del Claim que representa al Claim "name"
                                     "firstName",
                                     // Nombre del Claim que será utilizado para identificar un rol de usuario
                                     "role"
                                     );

                                ClaimsPrincipal Principal = new ClaimsPrincipal(Identity);

                                AuthenticationTicket Ticket;
                                // ¿Las opciones de configuración indican guardar el Token?
                                if (Options.SaveToken)
                                {
                                    // Almacenar el Token en una instancia de
                                    // AuthenticationProperties.
                                    var Properties = new AuthenticationProperties();
                                    Properties.StoreTokens(new AuthenticationToken[]
                                    {
                                        new AuthenticationToken{Name="access_token", Value=Token}
                                    });
                                    // Crear el Ticket
                                    Ticket = new AuthenticationTicket(Principal, Properties, Scheme.Name);
                                }
                                else
                                {
                                    // Crear el Ticket sin AuthenticationProperties.
                                    Ticket = new AuthenticationTicket(Principal, Scheme.Name);
                                }
                                Result = AuthenticateResult.Success(Ticket);

                            }
                            else
                            {
                                // No se pudo validar el Token.
                                // Devolver el error de validación.
                                Result = AuthenticateResult.Fail(Error);
                            }
                        }
                        catch
                        {
                            Result = AuthenticateResult.Fail(EdDSAJwtBearerErrors.InvalidToken);
                        }
                    }
                }


            }




            return Task.FromResult(Result);
        }

        private bool TryGetPayloadWithTokenValidation(string token, EdDSAJwtBearerOptions options, 
                                                                     out Dictionary<string, object> payload, out string error)
        {
            bool IsValid = false;
            payload = default;
            error = string.Empty;
            // Lógica de validación
            try
            {
                if (EdDSATokenHandler.TryGetPayloadFromToken(token, options.PublicSigningKey, out payload))
                {
                    IsValid = true;
                    object Value;
                    if (options.ValidateIssuer)
                    {
                        // Debemos validar el emisor.
                        // El valor se debe encontrar en el Claim "iss"
                        IsValid = payload.TryGetValue("iss", out Value);
                        if (IsValid)
                        {
                            // Se encontró el Claim "iss"
                            // Compararlo con el emisor válido.
                            IsValid = options.ValidIssuer.Equals(Value.ToString(),
                            StringComparison.OrdinalIgnoreCase);
                        }
                        // Si la validación no fue exitosa
                        // devolver el mensaje de emisor no válido.
                        if (!IsValid) error = EdDSAJwtBearerErrors.InvalidIssuer;
                    }

                    if (IsValid && options.ValidateAudience)
                    {
                        // Debemos validar la audiencia.
                        // El valor se encuentra en el Claim "aud"
                        IsValid = payload.TryGetValue("aud", out Value);
                        if (IsValid)
                        {
                            string[] Audiences = Value.ToString().Split(",");
                            IsValid = Audiences.Contains(options.ValidAudience);
                        }
                        if (!IsValid) error = EdDSAJwtBearerErrors.InvalidAudience;
                    }

                    if (IsValid && options.ValidateLifetime)
                    {
                        // Debemos validar la expiración del Token.
                        // El valor se encuentra en el Claim "exp".
                        IsValid = payload.TryGetValue("exp", out Value);
                        if (IsValid)
                        {
                            long ExpirationTime = Convert.ToInt64(Value.ToString());
                            IsValid = ExpirationTime > new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds();
                        }
                        if (!IsValid) error = EdDSAJwtBearerErrors.ExpiredToken;
                    }



                }
                    else
                {
                    IsValid = false;
                    error = EdDSAJwtBearerErrors.InvalidToken;
                }
            }
            catch
            {
                IsValid = false;
                error = EdDSAJwtBearerErrors.InvalidToken;
            }



            return IsValid;
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Indica al cliente que se requiere el método de autenticación Bearer.
            Response.Headers["WWW-Authenticate"] = "Bearer";
            await base.HandleChallengeAsync(properties);
        }



    }
}
