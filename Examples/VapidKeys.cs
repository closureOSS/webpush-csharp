#!/usr/bin/env dotnet
#:package ClosureOSS.WebPush@2.5.3
using WebPush;

var vapidKeys = VapidHelper.GenerateVapidKeys();
Console.WriteLine($"Public key:  {vapidKeys.PublicKey}");
Console.WriteLine($"Private key: {vapidKeys.PrivateKey}");

