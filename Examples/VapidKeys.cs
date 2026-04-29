#!/usr/bin/env dotnet
#:package ClosureOSS.WebPush@2.4.1
using WebPush;

var vapidKeys = VapidHelper.GenerateVapidKeys();
Console.WriteLine($"Public key:  {vapidKeys.PublicKey}");
Console.WriteLine($"Private key: {vapidKeys.PrivateKey}");

