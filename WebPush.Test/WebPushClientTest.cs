using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RichardSzalay.MockHttp;
using WebPush.Model;

namespace WebPush.Test;

[TestClass]
public class WebPushClientTest
{
    private const string TestPublicKey =
        @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

    private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

    private const string TestGcmEndpoint = @"https://android.googleapis.com/gcm/send/";

    private const string TestFcmEndpoint =
        @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6";

    private const string TestFirefoxEndpoint =
        @"https://updates.push.services.mozilla.com/wpush/v2/gBABAABgOe_sGrdrsT35ljtA4O9xCX";

    public const string TestSubject = "mailto:example@example.com";

    private MockHttpMessageHandler httpMessageHandlerMock;
    private WebPushClient client;

    [TestInitialize]
    public void InitializeTest()
    {
        httpMessageHandlerMock = new MockHttpMessageHandler();
        client = new WebPushClient(httpMessageHandlerMock.ToHttpClient());
    }

    [TestMethod]
    public void TestBogusEndpoint()
    {
        var subscription = new PushSubscription("this is not a valid endpoint", TestPublicKey, TestPrivateKey);
        Assert.ThrowsExactly<ArgumentException>(() => client.GenerateRequestDetails(subscription, @"test payload"));
    }


    [TestMethod]
    [DataRow(TestPublicKey, "")]
    [DataRow("", TestPrivateKey)]
    [DataRow("", "")]
    public void TestMissingAuthWithPayload(string publicKey, string privateKey)
    {
        var subscription = new PushSubscription(TestFcmEndpoint, publicKey, privateKey);
        Assert.ThrowsExactly<ArgumentException>(() => client.GenerateRequestDetails(subscription, @"test payload"));
    }

    [TestMethod]
    [DataRow(TestPublicKey, "")]
    [DataRow("", TestPrivateKey)]
    [DataRow("", "")]
    public void TestMissingAuthWithoutPayload(string publicKey, string privateKey)
    {
        var subscription = new PushSubscription(TestFcmEndpoint, publicKey, privateKey);
        var message = client.GenerateRequestDetails(subscription, null);
        Assert.IsNotNull(message);
    }

    [TestMethod]
    public void TestSetTopic()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { Topic = "testtopic" });
        Assert.AreEqual(@"testtopic", message.Headers.GetValues(@"Topic").First());
    }

    [TestMethod]
    [DataRow("failing topic #3")]
    [DataRow("")]
    [DataRow("a123456789012345678901234567890toolong")]
    public void TestSetTopicFailures(string topic)
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        Assert.ThrowsExactly<ArgumentException>(() => client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { Topic = topic, }));
    }

    [TestMethod]
    public void TestExtraHeaders()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        Dictionary<string, object> extraHeaders = [];
        extraHeaders["DEBUG-VERBOSE"] = true;
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { ExtraHeaders = extraHeaders, });
        var checkHeader = message.Headers.GetValues(@"DEBUG-VERBOSE").First();
        Assert.IsNotNull(checkHeader);
        Assert.AreEqual(@"True", checkHeader);
    }



    [TestMethod]
    public void TestSetUrgency()
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { Urgency = Urgency.VeryLow });
        Assert.AreEqual(@"very-low", message.Headers.GetValues(@"Urgency").First());
    }

    [TestMethod]
    [DataRow(ContentEncoding.Aes128gcm, "aes128gcm")]
    [DataRow(ContentEncoding.Aesgcm, "aesgcm")]
    public void TestSetContentEncoding(ContentEncoding encoding, string encodingHeaderValue)
    {
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { ContentEncoding = encoding, });
        Assert.AreEqual(encodingHeaderValue, message.Content.Headers.ContentEncoding.First());
    }

    [TestMethod]
    [DataRow(ContentEncoding.Aes128gcm, "aes128gcm")]
    [DataRow(ContentEncoding.Aesgcm, "aesgcm")]
    public void TestSetContentEncodingWithVapid(ContentEncoding encoding, string encodingHeaderValue)
    {
        client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
        var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload", new WebPushOptions { ContentEncoding = encoding, });
        Assert.AreEqual(encodingHeaderValue, message.Content.Headers.ContentEncoding.First());
        // var authorizationHeader = message.Headers.GetValues(@"Authorization").First();
        // Assert.StartsWith(@"vapid ", authorizationHeader);
    }



    [TestMethod]
    public void TestSetVapidDetails()
    {
        client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);

        var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
        var message = client.GenerateRequestDetails(subscription, @"test payload");
        var authorizationHeader = message.Headers.GetValues(@"Authorization").First();
        // var cryptoHeader = message.Headers.GetValues(@"Crypto-Key").First();

        // Assert.StartsWith(@"WebPush ", authorizationHeader);
        Assert.StartsWith(@"vapid ", authorizationHeader);
        // Assert.Contains(@"p256ecdsa", cryptoHeader);
    }

    [TestMethod]
    [DataRow(HttpStatusCode.Created)]
    [DataRow(HttpStatusCode.Accepted)]
    public void TestHandlingSuccessHttpCodes(HttpStatusCode status)
    {
        TestSendNotification(status);
    }

    [TestMethod]
    [DataRow(HttpStatusCode.BadRequest, "Bad Request")]
    [DataRow(HttpStatusCode.RequestEntityTooLarge, "Payload too large")]
    [DataRow((HttpStatusCode)429, "Too many request")]
    [DataRow(HttpStatusCode.NotFound, "Subscription no longer valid")]
    [DataRow(HttpStatusCode.Gone, "Subscription no longer valid")]
    [DataRow(HttpStatusCode.InternalServerError, "Received unexpected response code: 500")]
    public void TestHandlingFailureHttpCodes(HttpStatusCode status, string expectedMessage)
    {
        var actual = Assert.ThrowsExactly<WebPushException>(() => TestSendNotification(status));
        Assert.AreEqual(expectedMessage, actual.Message);
    }

    [TestMethod]
    [DataRow(HttpStatusCode.BadRequest, "authorization key missing", "Bad Request. Details: authorization key missing")]
    [DataRow(HttpStatusCode.RequestEntityTooLarge, "max size is 512", "Payload too large. Details: max size is 512")]
    [DataRow((HttpStatusCode)429, "the api is limited", "Too many request. Details: the api is limited")]
    [DataRow(HttpStatusCode.NotFound, "", "Subscription no longer valid")]
    [DataRow(HttpStatusCode.Gone, "", "Subscription no longer valid")]
    [DataRow(HttpStatusCode.InternalServerError, "internal error", "Received unexpected response code: 500. Details: internal error")]
    public void TestHandlingFailureMessages(HttpStatusCode status, string response, string expectedMessage)
    {
        var actual = Assert.ThrowsExactly<WebPushException>(() => TestSendNotification(status, response));
        Assert.AreEqual(expectedMessage, actual.Message);
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(5)]
    [DataRow(10)]
    [DataRow(50)]
    public void TestHandleInvalidPublicKeys(int charactersToDrop)
    {
        var invalidKey = TestPublicKey.Substring(0, TestPublicKey.Length - charactersToDrop);

        Assert.ThrowsExactly<InvalidEncryptionDetailsException>(() => TestSendNotification(HttpStatusCode.OK, response: null, invalidKey));
    }

    private void TestSendNotification(HttpStatusCode status, string response = null, string publicKey = TestPublicKey)
    {
        var subscription = new PushSubscription(TestFcmEndpoint, publicKey, TestPrivateKey);
        var httpContent = response == null ? null : new StringContent(response);
        httpMessageHandlerMock.When(TestFcmEndpoint).Respond(req => new HttpResponseMessage { StatusCode = status, Content = httpContent });
        client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
        client.SendNotification(subscription, "123");
    }

}
