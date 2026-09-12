const EMBED_HOSTS = [
  "youtube.com",
  "www.youtube.com",
  "youtube-nocookie.com",
  "www.youtube-nocookie.com",
  "platform.twitter.com",
  "platform.x.com",
  "syndication.twitter.com",
  "www.facebook.com",
  "facebook.com",
  "www.instagram.com",
  "instagram.com",
  "player.vimeo.com",
  "www.tiktok.com",
  "embed.reddit.com"
];

function isEmbedHost(host) {
  const normalized = String(host || "").replace(/^www\./, "").toLowerCase();
  return EMBED_HOSTS.some((entry) => {
    const item = entry.replace(/^www\./, "");
    return normalized === item || normalized.endsWith("." + item);
  });
}

if (typeof self !== "undefined") {
  self.EMBED_HOSTS = EMBED_HOSTS;
  self.isEmbedHost = isEmbedHost;
}
