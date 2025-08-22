using System.Collections.Generic;

namespace WebPush;

public class WebPushOptions
{
    // 'headers',
    public Dictionary<string, object>? ExtraHeaders { get; set; }
    // 'vapidDetails',
    public VapidDetails? VapidDetails { get; set; }
    // 'gcmAPIKey',
    public string? GcmApiKey { get; set; }
    // 'TTL',
    public const int DefaultTtl = 2419200;// default is 4 weeks
    public int TTL { get; set; } = DefaultTtl;
    // 'contentEncoding', "aes128gcm" or "aesgcm"
    public const ContentEncoding DefaultContentEncoding = WebPush.ContentEncoding.Aes128gcm;
    public ContentEncoding? ContentEncoding { get; set; }
    // 'urgency',
    public Urgency? Urgency { get; set; }
    // 'topic', max 32 characters; URL or filename-safe Base64 characters set
    public string? Topic { get; set; }
    // 'proxy',
    // 'agent',
    // 'timeout'
    public int? Timeout { get; set; }
}