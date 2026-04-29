# WebPush Csharp library

[![Build](https://github.com/closureOSS/webpush-csharp/actions/workflows/dotnet.yml/badge.svg)](https://github.com/closureOSS/webpush-csharp/actions/workflows/dotnet.yml)
![NuGet Version](https://img.shields.io/nuget/v/ClosureOSS.WebPush)

# Why

To deliver generic events using HTTP Push as outlined in [Generic Event Delivery Using HTTP](https://datatracker.ietf.org/doc/html/rfc8030), backend-triggered push messages must be encrypted. This is accomplished using the [Message Encryption for Web Push](https://datatracker.ietf.org/doc/html/rfc8291) standard, which relies on [Voluntary Application Server Identification (VAPID) for Web Push (RFC8292)](https://datatracker.ietf.org/doc/html/rfc8292) for authentication. Furthermore, any data included with the push message must be separately encrypted following the rules of [Encrypted Content-Encoding for HTTP (RFC8188)](https://datatracker.ietf.org/doc/html/rfc8188).

This package makes it easy to send push notifications from an application server.

## Purpose of fork

Support for message topic and message urgency flag.

Support for the "aes128gcm" HTTP Content Coding.

Rewrite using System.Security.Crytography, Microsoft.IdentityModel and other first party interfaces.

> [!CAUTION]
> This project is a re-implementation of the relevant RFCs. Please note that it is not compatible with the existing public API and does not support older standards.

# Install

Installation is simple, just install via

```shell
dotnet add package ClosureOSS.WebPush
```

# Usage

The common use case for this library is an application server using VAPID keys.

```csharp
using WebPush;

var pushEndpoint = @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6uDLB6....";
var p256dh = @"BKK18ZjtENC4jdhAAg9OfJacySQiDVcXMamy3SKKy7FwJcI5E0DKO9v4V2Pb8NnAPN4EVdmhO............";
var auth = @"fkJatBBEl...............";

var subject = @"mailto:example@example.com";
var publicKey = @"BDjASz8kkVBQJgWcD05uX3VxIs_gSHyuS023jnBoHBgUbg8zIJvTSQytR8MP4Z3-kzcGNVnM...............";
var privateKey = @"mryM-krWj_6IsIMGsd8wNFXGBxnx...............";

var subscription = new PushSubscription(pushEndpoint, p256dh, auth);
var options = new WebPushOptions
{
  VapidDetails = new VapidDetails(subject, publicKey, privateKey),
  ContentEncoding = ContentEncoding.Aes128gcm,
  Urgency = Urgency.High,
};

var webPushClient = new WebPushClient();
try
{
	await webPushClient.SendNotificationAsync(subscription, "payload", options);
}
catch (WebPushException exception)
{
	Console.WriteLine("Http STATUS code" + exception.StatusCode);
}
```

# API Reference

## SendNotificationAsync(pushSubscription, payload, vapidDetails|options, cancellationToken)

```csharp
var subscription = new PushSubscription(pushEndpoint, p256dh, auth);

var options = new WebPushOptions
{
  VapidDetails = new VapidDetails(subject, publicKey, privateKey),
  Topic = "RTQ.....",
};

var webPushClient = new WebPushClient();
try
{
	webPushClient.SendNotificationAsync(subscription, "payload", options);
}
catch (WebPushException exception)
{
	Console.WriteLine("Http STATUS code" + exception.StatusCode);
}
```

> [!NOTE]
> `SendNotificationAsync()` you don't need to define a payload, and this method will work without a VAPID keys if the push service supports it.

### Input

**Push Subscription**

The first argument must be an PushSubscription object containing the details for a push subscription.

**Payload**

The payload is optional, but if set, will be the data sent with a push
message.

This must be a _string_

> **Note:** In order to encrypt the _payload_, the _pushSubscription_ **must**
> have a _keys_ object with _p256dh_ and _auth_ values.

**Options**

Options is an optional argument that if defined should be an Dictionary<string,object> containing any of the following values defined, although none of them are required.

- **VapidDetails** should be a VapidDetails object with _subject_, _publicKey_ and
  _privateKey_ values defined. These values should follow the [Voluntary Application Server Identification (VAPID) for Web Push (RFC8292)](https://datatracker.ietf.org/doc/html/rfc8292).
- **TTL** is a value in seconds that describes how long a push message is
  retained by the push service (by default, four weeks).
- **ContentEncoding** Only Aes128gcm is supported
- **Urgency** [Urgency of notification](https://datatracker.ietf.org/doc/html/rfc8030#section-5.3)
- **Topic** Replacing messages with a [topic header](https://datatracker.ietf.org/doc/html/rfc8030#section-5.4)
- **ExtraHeaders** is an object with all the extra headers you want to add to the request.

<hr />

## GenerateRequestDetails(pushSubscription, payload, options)

Generates a Http message without sending. Parameters have the same meaning as with `SendNotificationAsync`.

See [standalone example](Examples/WebPushMessage.cs).

```csharp
var vapidKeys = VapidHelper.GenerateVapidKeys();
vapidKeys.Subject = @"mailto:user@example.net";
var p256dh = @"BI...MHM";
var auth = @"eSZ...Q";
var webPushClient = new WebPushClient();
var subscription = new PushSubscription("https://server.example.com/notify/Avv3mSO...", p256dh, auth);
var options = new WebPushOptions
{
    VapidDetails = vapidKeys,
    Topic = "Example",
};
```

<hr />

## GenerateVapidKeys()

See [standalone example](Examples/VapidKeys.cs).

```csharp
var vapidKeys = VapidHelper.GenerateVapidKeys();
Console.WriteLine($"Public key:  {vapidKeys.PublicKey}");
Console.WriteLine($"Private key: {vapidKeys.PrivateKey}");
```

outputs for example:

```text
Public key:  BFu5Jx7eA285mMZRx7a-SuFH8Cc2mAMZ5RhbqvGJKAIqRT6VzRc4Y5x7uuBD2AVkeLn13MrQZKHHUV6QDL8arGM
Private key: 5aRRAbKkELlCDlhEO68GItWm9ux2hS7ORP2KmQVHxAI
```

### Input

None.

### Returns

Returns a VapidDetails object with **PublicKey** and **PrivateKey** values populated which are URL Safe Base64 encoded strings.

> [!NOTE]
> You should create these keys once, store them and use them for all future messages you send.

---

## GetVapidHeaders(audience, subject, publicKey, privateKey, expiration)

See [standalone example](Examples/VapidHeaders.cs).

```csharp
Uri uri = new Uri(subscription.Endpoint);
string audience = uri.Scheme + Uri.SchemeDelimiter + uri.Host;

Dictionary<string, string> vapidHeaders = VapidHelper.GetVapidHeaders(
  audience,
  @"mailto: example@example.com",
  publicKey,
  privateKey,
  DateTime.Now.AddDays(2),
  ContentEncoding.Aes128gcm
);
```

The _GetVapidHeaders()_ method will take in the values needed to create an Authorization and Crypto-Key header.

### Input

The `GetVapidHeaders()` method expects the following input:

- _audience_: the origin of the **push service**.
- _subject_: the mailto or URL for your application.
- _publicKey_: the VAPID public key.
- _privateKey_: the VAPID private key.

and optionally

- _expiration_: Expiration date (defaults to 12 hours from now)
- _contentEncoding_: Either Aes128gcm (default) or Aesgcm

### Returns

This method returns a Dictionary<string, string> intented to be headers of a web request. It will contain the `Authorization` header and for Aes128 additionally a `Crypto-Key` header.

---

# Credits

- [C# Sharp original library ](https://github.com/web-push-libs/web-push-csharp)
- Original library ported from https://github.com/web-push-libs/web-push.
