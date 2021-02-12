using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using HashComparer.HashHelpers;
using System;

namespace PasswordVerifier
{
    public class PasswordVerifierFunction
    {
        [FunctionName(nameof(Verify))]
        public IActionResult Verify(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "verify/{hash}/{password}")] HttpRequest req,
            string hash, string password, ILogger log)
        {
            if (string.IsNullOrWhiteSpace(hash))
                return new BadRequestObjectResult("Debe incluir un hash válido.");

            if (string.IsNullOrWhiteSpace(password))
                return new BadRequestObjectResult("Debe incluir una contraseña válida.");

            byte[] hashtBytes = Convert.FromBase64String(hash);

            return new OkObjectResult(Pbkdf2.VerifyHashedPasswordV2(hashtBytes, password));
        }
    }
}
