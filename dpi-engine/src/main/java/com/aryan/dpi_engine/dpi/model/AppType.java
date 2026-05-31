package com.aryan.dpi_engine.dpi.model;

public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,

    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE;


    public static String toString(AppType type) {
        switch (type) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }

}
