namespace OAuthServer.Implementations
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using Microsoft.IdentityModel.Tokens;
    using System.Text;
    using OAuthServer.Interfaces;

    public class TokenService : ITokenService
    {
        // later will use from Json file
        private readonly string _secretKey = "4dH2H1iJAQvk4epF3S2cTTyEHihKwUtV";

        public bool ValidateToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            // Create a token handler to process the JWT
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_secretKey);

            try
            {
                // Define the validation parameters for the token
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,  // Validate the signing key (signature)
                    IssuerSigningKey = new SymmetricSecurityKey(key),  // Use the same secret key to verify signature
                    ValidateIssuer = false,  // Skip validation of the token issuer
                    ValidateAudience = false,  // Skip validation of the audience
                    ClockSkew = TimeSpan.Zero  // Allow no clock skew (adjust for time differences between servers)
                };

                // Validate the token using the provided validation parameters
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                // You can extract claims here if needed, for example:
                // var username = principal.Identity.Name;

                return true;  // If token is valid, return true
            }
            catch
            {
                return false;  // If token validation fails (signature, expired, etc.), return false
            }
        }
    }

}
