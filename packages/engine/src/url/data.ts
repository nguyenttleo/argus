export const BRANDS: Record<string, string> = {
  paypal: 'paypal.com',
  google: 'google.com',
  gmail: 'gmail.com',
  microsoft: 'microsoft.com',
  office: 'office.com',
  outlook: 'outlook.com',
  apple: 'apple.com',
  icloud: 'icloud.com',
  amazon: 'amazon.com',
  facebook: 'facebook.com',
  instagram: 'instagram.com',
  whatsapp: 'whatsapp.com',
  netflix: 'netflix.com',
  linkedin: 'linkedin.com',
  twitter: 'twitter.com',
  ebay: 'ebay.com',
  wellsfargo: 'wellsfargo.com',
  bankofamerica: 'bankofamerica.com',
  chase: 'chase.com',
  citibank: 'citi.com',
  americanexpress: 'americanexpress.com',
  hsbc: 'hsbc.com',
  santander: 'santander.com',
  barclays: 'barclays.co.uk',
  coinbase: 'coinbase.com',
  binance: 'binance.com',
  kraken: 'kraken.com',
  metamask: 'metamask.io',
  dropbox: 'dropbox.com',
  adobe: 'adobe.com',
  docusign: 'docusign.com',
  dhl: 'dhl.com',
  fedex: 'fedex.com',
  ups: 'ups.com',
  usps: 'usps.com',
  steam: 'steampowered.com',
  roblox: 'roblox.com',
  discord: 'discord.com',
  spotify: 'spotify.com',
  github: 'github.com',
  yahoo: 'yahoo.com',
};

export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'zip', 'mov', 'country', 'kim',
  'work', 'click', 'link', 'gdn', 'loan', 'men', 'date', 'racing', 'win',
  'review', 'stream', 'download', 'science', 'party', 'faith', 'cricket',
  'accountant', 'bid', 'trade', 'webcam', 'mom', 'lol', 'rest', 'fit', 'cam',
  'sbs', 'cfd', 'icu', 'autos', 'beauty', 'hair', 'makeup', 'monster', 'quest',
  'skin', 'cyou', 'buzz', 'support', 'live', 'shop',
]);

export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rebrand.ly', 'bl.ink', 'shorturl.at', 'rb.gy', 'tiny.cc', 't.ly',
  'soo.gd', 's.id', 'v.gd', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'bit.do',
  'mcaf.ee', 'shorte.st', 'tr.im', 'cli.gs',
]);

export const PHISHING_KEYWORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'secure',
  'security', 'account', 'update', 'confirm', 'webscr', 'banking', 'wallet',
  'recover', 'unlock', 'suspend', 'suspended', 'alert', 'billing', 'invoice',
  'authenticate', 'authorize', 'unusual', 'limited', 'restricted',
];

export const POPULAR_DOMAINS = new Set([
  ...Object.values(BRANDS),
  'youtube.com', 'wikipedia.org', 'reddit.com', 'bing.com', 'live.com',
  'cloudflare.com', 'mozilla.org', 'stackoverflow.com', 'nytimes.com',
  'cnn.com', 'bbc.co.uk', 'bbc.com', 'wordpress.com', 'wikimedia.org',
  'vimeo.com', 'twitch.tv', 'pinterest.com', 'tumblr.com', 'salesforce.com',
  'slack.com', 'zoom.us', 'gitlab.com', 'bitbucket.org', 'npmjs.com',
  'python.org', 'nodejs.org', 'medium.com', 'quora.com', 'imdb.com',
  'wikihow.com', 'x.com', 'cloudfront.net', 'akamai.com', 'googleusercontent.com',
]);

export const TRUSTED_SSO_RELYING_PARTIES = new Set([
  'instructure.com',
  'canvaslms.com',
]);

export const TRUSTED_SSO_IDPS = new Set([
  'microsoftonline.com',
  'microsoft.com',
  'live.com',
  'office.com',
  'okta.com',
  'okta-emea.com',
  'auth0.com',
  'google.com',
  'accounts.google.com',
]);

export const REDIRECT_PARAMS = new Set([
  'url', 'redirect', 'redirect_uri', 'redirecturl', 'return', 'returnurl',
  'return_to', 'next', 'continue', 'dest', 'destination', 'goto', 'target', 'r', 'u',
]);

export const DANGEROUS_EXTS = new Set([
  'exe', 'scr', 'pif', 'com', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf',
  'wsh', 'hta', 'msi', 'jar', 'ps1', 'apk', 'dmg', 'iso', 'img', 'lnk', 'reg',
]);
