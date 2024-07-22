# Exposing the Managed Identity Endpoint on service.msidlab.com

## Introduction
We have implemented a solution that exposes the Managed Identity (MSI) endpoint on the `service.msidlab.com` domain. This allows users to retrieve environment variables and use the service as a proxy to obtain MSI tokens. This document explains the purpose, architecture, and implementation details of this solution.

## Purpose
The primary purpose of this solution is to facilitate the secure and efficient retrieval of MSI tokens. By exposing the MSI endpoint, we enable applications to obtain environment-specific variables and securely proxy MSI token requests through the `service.msidlab.com` service.

## Architecture
The architecture involves three main components:
1. **Client Application**: Makes requests to retrieve environment variables and MSI tokens.
2. **Environment Variables API**: Hosted on `service.msidlab.com`, provides environment-specific configuration data.
3. **Managed Identity Proxy Service**: Also hosted on `service.msidlab.com`, proxies requests to the Azure MSI endpoint to obtain tokens.

## Implementation

### Step 1: Retrieve Environment Variables
The client application first retrieves the necessary environment variables by calling the Environment Variables API.

```csharp
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
```

**Step 2: Proxy MSI Token Requests**
Using the environment variables obtained from the previous step, the client application constructs a request to the Managed Identity Proxy Service to obtain an MSI token.

```csharp
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

```
