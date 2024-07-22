using System;
using System.Net.Http;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

namespace ConfidentialClientApp
{
    class Program
    {
        // Configuration values for the Azure AD tenant and app
        private static string tenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"; // MSFT Tenant ID
        private static string clientId = "f62c5ae3-bf3a-4af5-afa8-a68b800396e9"; // RequestMSIDLAB app id
        private static string authority = $"https://login.microsoftonline.com/{tenantId}";

        //Cert location : https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/asset/Microsoft_Azure_KeyVault/Certificate/https://msidlabs.vault.azure.net/certificates/LabAuth
        private static string certificateThumbprint = "f6456f3273677dba268bce224fb6589c5e8fbea2"; // LabAuth cert thumbprint
        
        private static string apiUrl = "https://service.msidlab.com/environmentvariables?resource=WebApp";
        private static string resourceUrl = "https://management.azure.com"; // The resource you want to access with the managed identity

        static async Task Main(string[] args)
        {
            // Get the certificate from the store
            var certificate = GetCertificateFromStore(certificateThumbprint);
            if (certificate == null)
            {
                Console.WriteLine("Certificate not found.");
                return;
            }

            // Create a confidential client application with the certificate
            var confidentialClientApp = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithAuthority(authority)
                .WithCertificate(certificate, true)
                .Build();

            // Define the scopes for the token
            var scopes = new string[] { "https://request.msidlab.com/.default" };

            // Acquire a token for the client
            var authResult = await confidentialClientApp.AcquireTokenForClient(scopes).ExecuteAsync();

            if (authResult == null || string.IsNullOrEmpty(authResult.AccessToken))
            {
                Console.WriteLine("Failed to acquire token.");
                return;
            }

            Console.WriteLine($"MSI Helper Service Access Token acquired: {authResult.AccessToken}");
            Console.WriteLine();

            // Call the environment variables API
            var identityInfo = await CallEnvVarApiAsync(authResult.AccessToken).ConfigureAwait(false);

            // If identity information is retrieved, call the managed identity endpoint
            if (identityInfo != null)
            {
                var managedIdentityToken = await CallManagedIdentityEndpointAsync(identityInfo, authResult.AccessToken);
                if (!string.IsNullOrEmpty(managedIdentityToken))
                {
                    Console.WriteLine($"Managed Identity Token acquired proxying via MSI Helper Service: {managedIdentityToken}");
                }
                else
                {
                    Console.WriteLine("Failed to acquire managed identity token.");
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Retrieves the X509 certificate from the current user's certificate store using the thumbprint.
        /// </summary>
        private static X509Certificate2? GetCertificateFromStore(string thumbprint)
        {
            using (var store = new X509Store(StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certs.Count > 0)
                {
                    return certs[0];
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// Calls the environment variables API with the provided token.
        /// </summary>
        private static async Task<JsonDocument?> CallEnvVarApiAsync(string token)
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                var response = await httpClient.GetAsync(apiUrl);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"API Response: {content}");
                    Console.WriteLine();
                    return JsonDocument.Parse(content);
                }
                else
                {
                    Console.WriteLine($"API call failed with status code: {response.StatusCode}");
                    Console.WriteLine();
                    return null;
                }
            }
        }

        /// <summary>
        /// Calls the managed identity endpoint with the provided identity information and token.
        /// </summary>
        private static async Task<string?> CallManagedIdentityEndpointAsync(JsonDocument identityInfo, string token)
        {
            var root = identityInfo.RootElement;

            if (!root.TryGetProperty("IDENTITY_HEADER", out var identityHeaderElement) ||
                !root.TryGetProperty("IDENTITY_ENDPOINT", out var identityEndpointElement) ||
                !root.TryGetProperty("IDENTITY_API_VERSION", out var identityApiVersionElement))
            {
                Console.WriteLine("One or more required properties are missing from the identity information.");
                Console.WriteLine();
                return null;
            }

            string identityHeader = identityHeaderElement.GetString() ?? string.Empty;
            string identityEndpoint = identityEndpointElement.GetString() ?? string.Empty;
            string identityApiVersion = identityApiVersionElement.GetString() ?? string.Empty;

            if (string.IsNullOrEmpty(identityHeader) || string.IsNullOrEmpty(identityEndpoint) || string.IsNullOrEmpty(identityApiVersion))
            {
                Console.WriteLine("One or more required properties have null or empty values.");
                Console.WriteLine();
                return null;
            }

            // Encode the URL before sending it to the helper service
            string encodedUri = WebUtility.UrlEncode($"{identityEndpoint}?resource={resourceUrl}&api-version={identityApiVersion}".ToLowerInvariant());
            string requestUri = $"https://service.msidlab.com/MSIToken?azureresource=WebApp&uri={encodedUri}";

            using (var httpClient = new HttpClient())
            {
                // Add required headers
                httpClient.DefaultRequestHeaders.Add("X-IDENTITY-HEADER", identityHeader);
                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

                // Send the request to the managed identity endpoint
                var response = await httpClient.GetAsync(requestUri);
                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var tokenResponse = JsonDocument.Parse(content);
                    return tokenResponse.RootElement.GetProperty("access_token").GetString();
                }
                else
                {
                    Console.WriteLine($"Managed Identity call failed with status code: {response.StatusCode}");
                    Console.WriteLine();
                    return null;
                }
            }
        }
    }
}
