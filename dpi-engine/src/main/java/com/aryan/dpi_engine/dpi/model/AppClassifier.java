package com.aryan.dpi_engine.dpi.model;

import java.util.Locale;

public final class AppClassifier {

    private AppClassifier(){}

    public static AppType classifyBySni(String sni) {
        if (sni == null || sni.isEmpty()) {
            return AppType.UNKNOWN;
        }

        String lower = sni.toLowerCase(Locale.ROOT);

        if (containsAny(lower, "google", "gstatic", "googleapis", "ggpht", "gvt1"))
            return AppType.GOOGLE;

        if (containsAny(lower, "youtube", "ytimg", "youtu.be", "yt3.ggpht"))
            return AppType.YOUTUBE;

        if (containsAny(lower, "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"))
            return AppType.FACEBOOK;

        if (containsAny(lower, "instagram", "cdninstagram"))
            return AppType.INSTAGRAM;

        if (containsAny(lower, "whatsapp", "wa.me"))
            return AppType.WHATSAPP;

        if (containsAny(lower, "twitter", "twimg", "x.com", "t.co"))
            return AppType.TWITTER;

        if (containsAny(lower, "netflix", "nflxvideo", "nflximg"))
            return AppType.NETFLIX;

        if (containsAny(lower, "amazon", "amazonaws", "cloudfront", "aws"))
            return AppType.AMAZON;

        if (containsAny(lower, "microsoft", "msn.com", "office", "azure",
                "live.com", "outlook", "bing"))
            return AppType.MICROSOFT;

        if (containsAny(lower, "apple", "icloud", "mzstatic", "itunes"))
            return AppType.APPLE;

        if (containsAny(lower, "telegram", "t.me"))
            return AppType.TELEGRAM;

        if (containsAny(lower, "tiktok", "tiktokcdn", "musical.ly", "bytedance"))
            return AppType.TIKTOK;

        if (containsAny(lower, "spotify", "scdn.co"))
            return AppType.SPOTIFY;

        if (lower.contains("zoom"))
            return AppType.ZOOM;

        if (containsAny(lower, "discord", "discordapp"))
            return AppType.DISCORD;

        if (containsAny(lower, "github", "githubusercontent"))
            return AppType.GITHUB;

        if (containsAny(lower, "cloudflare", "cf-"))
            return AppType.CLOUDFLARE;

        return AppType.HTTPS;
    }

    private static boolean containsAny(String s, String... keys) {
        for (String k : keys) {
            if (s.contains(k)) return true;
        }
        return false;
    }
}
