using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WebPush.Model;
using WebPush.Util;

namespace WebPush;

public class WebPushClient : IWebPushClient
{
    private readonly HttpClientHandler? _httpClientHandler;

    private HttpClient? _httpClient;
    private VapidDetails? _vapidDetails;

    // Used so we only cleanup internally created http clients
    private bool _isHttpClientInternallyCreated;

    public WebPushClient()
    {

    }

    public WebPushClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public WebPushClient(HttpClientHandler httpClientHandler)
    {
        _httpClientHandler = httpClientHandler;
    }

    protected HttpClient HttpClient
    {
        get
        {
            if (_httpClient is not null)
            {
                return _httpClient;
            }

            _isHttpClientInternallyCreated = true;
            _httpClient = _httpClientHandler == null ? new HttpClient() : new HttpClient(_httpClientHandler);

            return _httpClient;
        }
    }

    /// <summary>
    ///     When marking requests where you want to define VAPID details, call this method
    ///     before sendNotifications() or pass in the details and options to
    ///     sendNotification.
    /// </summary>
    /// <param name="vapidDetails"></param>
    public void SetVapidDetails(VapidDetails vapidDetails)
    {
        VapidHelper.ValidateSubject(vapidDetails.Subject);
        VapidHelper.ValidatePublicKey(vapidDetails.PublicKey);
        VapidHelper.ValidatePrivateKey(vapidDetails.PrivateKey);

        _vapidDetails = vapidDetails;
    }

    /// <summary>
    ///     When marking requests where you want to define VAPID details, call this method
    ///     before sendNotifications() or pass in the details and options to
    ///     sendNotification.
    /// </summary>
    /// <param name="subject">This must be either a URL or a 'mailto:' address</param>
    /// <param name="publicKey">The public VAPID key as a base64 encoded string</param>
    /// <param name="privateKey">The private VAPID key as a base64 encoded string</param>
    public void SetVapidDetails(string subject, string publicKey, string privateKey)
    {
        SetVapidDetails(new VapidDetails(subject, publicKey, privateKey));
    }

    /// <summary>
    ///     To get a request without sending a push notification call this method.
    ///     This method will throw an ArgumentException if there is an issue with the input.
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for the vapid keys can be passed in if they are unique for each
    ///     notification.
    /// </param>
    /// <returns>A HttpRequestMessage object that can be sent.</returns>
    public HttpRequestMessage GenerateRequestDetails(PushSubscription subscription, string? payload, WebPushOptions? options = null)
    {
        if (!Uri.IsWellFormedUriString(subscription.Endpoint, UriKind.Absolute))
        {
            throw new ArgumentException(@"You must pass in a subscription with at least a valid endpoint");
        }

        var request = new HttpRequestMessage(HttpMethod.Post, subscription.Endpoint);

        if (!string.IsNullOrEmpty(payload) && (string.IsNullOrEmpty(subscription.Auth) ||
                                               string.IsNullOrEmpty(subscription.P256DH)))
        {
            throw new ArgumentException(
                @"To send a message with a payload, the subscription must have 'auth' and 'p256dh' keys.");
        }

        if (options is not null)
        {
            if (options.Topic is not null)
            {
                if (string.IsNullOrWhiteSpace(options.Topic) || options.Topic.Length > 32)
                {
                    throw new ArgumentException("options.topic must be of type string and not empty and use a maximum of 32 characters from the URL or filename-safe Base64 characters set");
                }
                if (!Regex.IsMatch(options.Topic, @"^[A-Za-z0-9\-_]+$"))
                {
                    throw new ArgumentException("options.topic uses unsupported characters set, use the URL or filename-safe Base64 characters set");
                }
            }
        }

        string? cryptoKeyHeader = null;
        request.Headers.Add("TTL", (options?.TTL ?? WebPushOptions.DefaultTtl).ToString());
        if (options?.Topic is not null)
        {
            request.Headers.Add("Topic", options.Topic);
        }
        if (options?.Urgency is not null)
        {
            request.Headers.Add("Urgency", options.Urgency.Value.ToKebabCaseLower());
        }

        if (options?.ExtraHeaders is not null)
        {
            foreach (var header in options.ExtraHeaders)
            {
                request.Headers.Add(header.Key, header.Value.ToString());
            }
        }

        var contentEncoding = options?.ContentEncoding ?? WebPushOptions.DefaultContentEncoding;
        if (!string.IsNullOrEmpty(payload))
        {
            if (string.IsNullOrEmpty(subscription.P256DH) || string.IsNullOrEmpty(subscription.Auth))
            {
                throw new ArgumentException(
                    @"Unable to send a message with payload to this subscription since it doesn't have the required encryption key");
            }

            var encryptedPayload = EncryptPayload(subscription, payload);

            request.Content = new ByteArrayContent(encryptedPayload.Payload);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Content.Headers.ContentLength = encryptedPayload.Payload.Length;
            request.Content.Headers.ContentEncoding.Add(contentEncoding.ToKebabCaseLower());
            if (contentEncoding == ContentEncoding.Aesgcm)
            {
                request.Headers.Add("Encryption", "salt=" + encryptedPayload.Base64EncodeSalt());
            }
            cryptoKeyHeader = @"dh=" + encryptedPayload.Base64EncodePublicKey();
        }
        else
        {
            request.Content = new ByteArrayContent([]);
            request.Content.Headers.ContentLength = 0;
        }

        var vapidDetails = options?.VapidDetails ?? _vapidDetails;
        if (vapidDetails is not null)
        {
            var uri = new Uri(subscription.Endpoint);
            var audience = uri.Scheme + @"://" + uri.Host;
            var vapidHeaders = VapidHelper.GetVapidHeaders(audience, vapidDetails.Subject, vapidDetails.PublicKey, vapidDetails.PrivateKey, vapidDetails.Expiration, contentEncoding);
            request.Headers.Add(@"Authorization", vapidHeaders["Authorization"]);
            if (contentEncoding == ContentEncoding.Aesgcm)
            {
                if (string.IsNullOrEmpty(cryptoKeyHeader))
                {
                    cryptoKeyHeader = vapidHeaders["Crypto-Key"];
                }
                else
                {
                    cryptoKeyHeader += @";" + vapidHeaders["Crypto-Key"];
                }
            }
        }
        if (contentEncoding == ContentEncoding.Aesgcm)
        {
            request.Headers.Add("Crypto-Key", cryptoKeyHeader);
        }
        return request;
    }

    private static EncryptionResult EncryptPayload(PushSubscription subscription, string payload)
    {
        try
        {
            return Encryptor.Encrypt(subscription.P256DH, subscription.Auth, payload);
        }
        catch (Exception ex)
        {
            if (ex is FormatException || ex is ArgumentException)
            {
                throw new InvalidEncryptionDetailsException("Unable to encrypt the payload with the encryption key of this subscription.", subscription);
            }

            throw;
        }
    }

    /// <summary>
    ///     To send a push notification call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for the GCM API key and vapid keys can be passed in if they are unique for each
    ///     notification.
    /// </param>
    public void SendNotification(PushSubscription subscription, string? payload = null, WebPushOptions? options = null)
    {
        SendNotificationAsync(subscription, payload, options).ConfigureAwait(false).GetAwaiter().GetResult();
    }

    /// <summary>
    ///     To send a push notification call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="vapidDetails">The vapid details for the notification.</param>
    public void SendNotification(PushSubscription subscription, string payload, VapidDetails vapidDetails)
    {
        var options = new WebPushOptions { VapidDetails = vapidDetails, };
        SendNotification(subscription, payload, options);
    }

    /// <summary>
    ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="options">
    ///     Options for the GCM API key and vapid keys can be passed in if they are unique for each
    ///     notification.
    /// </param>
    /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
    public async Task SendNotificationAsync(PushSubscription subscription, string? payload = null, WebPushOptions? options = null, CancellationToken cancellationToken = default)
    {
        var request = GenerateRequestDetails(subscription, payload, options);
        var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        await HandleResponse(response, subscription).ConfigureAwait(false);
    }

    /// <summary>
    ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
    ///     Will exception if unsuccessful
    /// </summary>
    /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
    /// <param name="payload">The payload you wish to send to the user</param>
    /// <param name="vapidDetails">The vapid details for the notification.</param>
    /// <param name="cancellationToken"></param>
    public async Task SendNotificationAsync(PushSubscription subscription, string payload, VapidDetails vapidDetails, CancellationToken cancellationToken = default)
    {
        var options = new WebPushOptions { VapidDetails = vapidDetails };
        await SendNotificationAsync(subscription, payload, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///     Handle Web Push responses.
    /// </summary>
    /// <param name="response"></param>
    /// <param name="subscription"></param>
    private static async Task HandleResponse(HttpResponseMessage response, PushSubscription subscription)
    {
        // Successful
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        // Error
        var responseCodeMessage = $"Received unexpected response code: {(int)response.StatusCode}";
        switch (response.StatusCode)
        {
            case HttpStatusCode.BadRequest:
                responseCodeMessage = "Bad Request";
                break;

            case HttpStatusCode.RequestEntityTooLarge:
                responseCodeMessage = "Payload too large";
                break;

            case (HttpStatusCode)429:
                responseCodeMessage = "Too many request";
                break;

            case HttpStatusCode.NotFound:
            case HttpStatusCode.Gone:
                responseCodeMessage = "Subscription no longer valid";
                break;
        }

        string? details = null;
        if (response.Content != null)
        {
            details = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }

        var message = string.IsNullOrEmpty(details) ? responseCodeMessage : $"{responseCodeMessage}. Details: {details}";

        throw new WebPushException(message, subscription, response);
    }

    public void Dispose()
    {
        if (_httpClient != null && _isHttpClientInternallyCreated)
        {
            _httpClient.Dispose();
            _httpClient = null;
        }
    }
}
