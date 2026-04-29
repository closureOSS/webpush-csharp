#!/usr/bin/env dotnet
#:package ClosureOSS.WebPush@2.5.2
using WebPush;

var uri = new Uri("https://server.example.com/notify");
var audience = uri.Scheme + Uri.SchemeDelimiter + uri.Host;
var vapidKeys = VapidHelper.GenerateVapidKeys();


var headers = VapidHelper.GetVapidHeaders(
  audience,
  @"mailto: example@example.com",
  vapidKeys.PublicKey,
  vapidKeys.PrivateKey,
  DateTime.Now.AddDays(2),
  ContentEncoding.Aes128gcm
);

foreach (var header in headers)
{
    Console.WriteLine($"{header.Key}: {header.Value}");
}
