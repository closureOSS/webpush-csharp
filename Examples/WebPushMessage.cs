#!/usr/bin/env dotnet
#:package ClosureOSS.WebPush@2.5.1
using WebPush;

var vapidKeys = VapidHelper.GenerateVapidKeys();
vapidKeys.Subject = @"mailto:user@example.net";
// example keys
var p256dh = @"BIwCq8tz028CFq9YFQ56kipZ633EK628l4-u6FcPHTGkS_cqTsV-9MRRAGEu56UmfXQ-8lIg7QXgUTFmzedzMHM";
var auth = @"eSZCfw7d6bXE0erlgnLe_Q";
var webPushClient = new WebPushClient();
var subscription = new PushSubscription("https://server.example.com/notify/Avv3mSO...", p256dh, auth);
var options = new WebPushOptions
{
    VapidDetails = vapidKeys,
    Topic = "Example",
};


var message = webPushClient.GenerateRequestDetails(subscription, "A payload", options);

Console.WriteLine($"{message.Method} {message.RequestUri}");
Console.WriteLine();
foreach (var header in message.Headers){
   foreach (var value in header.Value)
   {
       Console.WriteLine($"{header.Key} : {value}");
   }
}
Console.WriteLine();
Console.WriteLine($"{Convert.ToBase64String(await message.Content!.ReadAsByteArrayAsync())}");
