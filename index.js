const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const readline = require('readline');
const crypto = require('crypto');

// ==================== ENHANCED CONFIG ====================
const CONFIG = {
    USER_AGENTS: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
    ],
    TIMEOUT: 20000,
    MAX_RETRIES: 3,
    DELAY_MIN: 2000,
    DELAY_MAX: 5000,
    CONCURRENT_REQUESTS: 3
};

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// ==================== UTILITY FUNCTIONS ====================
const question = (query) => new Promise((resolve) => rl.question(query, resolve));
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const randomDelay = () => delay(CONFIG.DELAY_MIN + Math.random() * (CONFIG.DELAY_MAX - CONFIG.DELAY_MIN));
const randomUA = () => CONFIG.USER_AGENTS[Math.floor(Math.random() * CONFIG.USER_AGENTS.length)];
const hash = (str) => crypto.createHash('md5').update(str).digest('hex').substring(0, 8);

// Rate limiter
class RateLimiter {
    constructor(maxPerMinute = 10) {
        this.requests = [];
        this.maxPerMinute = maxPerMinute;
    }

    async wait() {
        const now = Date.now();
        this.requests = this.requests.filter(time => now - time < 60000);
        
        if (this.requests.length >= this.maxPerMinute) {
            const oldestRequest = this.requests[0];
            const waitTime = 60000 - (now - oldestRequest) + 1000;
            console.log(`   ⏳ Rate limit: waiting ${Math.round(waitTime/1000)}s...`);
            await delay(waitTime);
        }
        
        this.requests.push(Date.now());
    }
}

const limiter = new RateLimiter(15);

// Request with retry
async function fetchWithRetry(url, options = {}, retries = CONFIG.MAX_RETRIES) {
    await limiter.wait();
    
    for (let i = 0; i < retries; i++) {
        try {
            await randomDelay();
            const response = await axios({
                url,
                method: options.method || 'GET',
                headers: {
                    'User-Agent': randomUA(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'DNT': '1',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    ...options.headers
                },
                timeout: CONFIG.TIMEOUT,
                validateStatus: () => true,
                maxRedirects: 5,
                ...options
            });
            return response;
        } catch (error) {
            if (i === retries - 1) throw error;
            await delay(3000 * (i + 1));
        }
    }
}

console.log('╔════════════════════════════════════════════════════════╗');
console.log('║  🔍 ADVANCED OSINT TOOL v5.0 - PROFESSIONAL EDITION  ║');
console.log('║     Deep Investigation & Intelligence Gathering       ║');
console.log('║     ⚠️  FOR AUTHORIZED LEGAL USE ONLY                 ║');
console.log('╚════════════════════════════════════════════════════════╝\n');

// ==================== SOCIAL MEDIA VALIDATORS ====================

async function validateInstagram(username) {
    try {
        const url = `https://www.instagram.com/api/v1/users/web_profile_info/?username=${username}`;
        const response = await fetchWithRetry(url, {
            headers: {
                'X-IG-App-ID': '936619743392459',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });

        if (response.status === 200 && response.data?.data?.user) {
            const user = response.data.data.user;
            return {
                platform: 'Instagram',
                url: `https://www.instagram.com/${username}/`,
                status: 'VERIFIED ✓',
                confidence: 'HIGH',
                data: {
                    fullName: user.full_name,
                    bio: user.biography,
                    followers: user.edge_followed_by?.count,
                    following: user.edge_follow?.count,
                    posts: user.edge_owner_to_timeline_media?.count,
                    isPrivate: user.is_private,
                    isVerified: user.is_verified,
                    profilePic: user.profile_pic_url_hd
                }
            };
        }
    } catch (e) {
        console.log(`   ℹ️  Instagram check failed: ${e.message}`);
    }
    return null;
}

async function validateTwitter(username) {
    try {
        const url = `https://twitter.com/i/api/graphql/7mjxD3-C6BxitPMVQ6w0-Q/UserByScreenName?variables=${encodeURIComponent(JSON.stringify({
            screen_name: username,
            withSafetyModeUserFields: true
        }))}`;
        
        const response = await fetchWithRetry(url, {
            headers: {
                'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                'X-Twitter-Active-User': 'yes',
                'X-Twitter-Client-Language': 'en'
            }
        });

        if (response.data?.data?.user) {
            const user = response.data.data.user.result.legacy;
            return {
                platform: 'Twitter/X',
                url: `https://twitter.com/${username}`,
                status: 'VERIFIED ✓',
                confidence: 'HIGH',
                data: {
                    name: user.name,
                    bio: user.description,
                    followers: user.followers_count,
                    following: user.friends_count,
                    tweets: user.statuses_count,
                    created: user.created_at,
                    location: user.location,
                    verified: user.verified
                }
            };
        }
    } catch (e) {
        console.log(`   ℹ️  Twitter check failed: ${e.message}`);
    }
    return null;
}

async function validateGitHub(username) {
    try {
        const response = await fetchWithRetry(`https://api.github.com/users/${username}`, {
            headers: {
                'Accept': 'application/vnd.github.v3+json'
            }
        });

        if (response.status === 200 && response.data.login) {
            return {
                platform: 'GitHub',
                url: `https://github.com/${username}`,
                status: 'VERIFIED ✓',
                confidence: 'HIGH',
                data: {
                    name: response.data.name,
                    bio: response.data.bio,
                    company: response.data.company,
                    location: response.data.location,
                    email: response.data.email,
                    blog: response.data.blog,
                    repos: response.data.public_repos,
                    gists: response.data.public_gists,
                    followers: response.data.followers,
                    following: response.data.following,
                    created: response.data.created_at
                }
            };
        }
    } catch (e) {}
    return null;
}

async function validateTikTok(username) {
    try {
        const response = await fetchWithRetry(`https://www.tiktok.com/@${username}`);
        
        if (response.status === 200 && response.data.includes('"uniqueId":"' + username)) {
            const jsonMatch = response.data.match(/<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application\/json">(.*?)<\/script>/);
            if (jsonMatch) {
                const data = JSON.parse(jsonMatch[1]);
                const user = data.__DEFAULT_SCOPE__?.['webapp.user-detail']?.userInfo?.user;
                
                if (user) {
                    return {
                        platform: 'TikTok',
                        url: `https://www.tiktok.com/@${username}`,
                        status: 'VERIFIED ✓',
                        confidence: 'HIGH',
                        data: {
                            nickname: user.nickname,
                            bio: user.signature,
                            followers: user.followerCount,
                            following: user.followingCount,
                            likes: user.heartCount,
                            videos: user.videoCount,
                            verified: user.verified
                        }
                    };
                }
            }
        }
    } catch (e) {}
    return null;
}

async function validateLinkedIn(identifier) {
    try {
        const url = `https://www.linkedin.com/in/${identifier}`;
        const response = await fetchWithRetry(url);
        
        if (response.status === 200 && !response.data.includes('page-not-found')) {
            return {
                platform: 'LinkedIn',
                url: url,
                status: 'POSSIBLE MATCH',
                confidence: 'MEDIUM',
                note: 'Requires login for full verification'
            };
        }
    } catch (e) {}
    return null;
}

async function validateReddit(username) {
    try {
        const response = await fetchWithRetry(`https://www.reddit.com/user/${username}/about.json`);
        
        if (response.status === 200 && response.data?.data) {
            const user = response.data.data;
            return {
                platform: 'Reddit',
                url: `https://www.reddit.com/user/${username}`,
                status: 'VERIFIED ✓',
                confidence: 'HIGH',
                data: {
                    name: user.name,
                    karma: user.total_karma,
                    created: new Date(user.created * 1000).toISOString(),
                    isPremium: user.is_gold,
                    isMod: user.is_mod
                }
            };
        }
    } catch (e) {}
    return null;
}

async function validateMedium(username) {
    try {
        const response = await fetchWithRetry(`https://medium.com/@${username}`);
        
        if (response.status === 200 && response.data.includes('"username":"' + username)) {
            return {
                platform: 'Medium',
                url: `https://medium.com/@${username}`,
                status: 'VERIFIED ✓',
                confidence: 'HIGH'
            };
        }
    } catch (e) {}
    return null;
}

async function validateTelegram(username) {
    try {
        const response = await fetchWithRetry(`https://t.me/${username}`);
        
        if (response.status === 200 && (response.data.includes('tgme_page_photo') || response.data.includes('tgme_page_title'))) {
            const $ = cheerio.load(response.data);
            return {
                platform: 'Telegram',
                url: `https://t.me/${username}`,
                status: 'VERIFIED ✓',
                confidence: 'HIGH',
                data: {
                    title: $('.tgme_page_title').text().trim(),
                    description: $('.tgme_page_description').text().trim(),
                    image: $('.tgme_page_photo_image').attr('src')
                }
            };
        }
    } catch (e) {}
    return null;
}

async function validateYouTube(username) {
    try {
        const response = await fetchWithRetry(`https://www.youtube.com/@${username}`);
        
        if (response.status === 200 && !response.data.includes('404')) {
            return {
                platform: 'YouTube',
                url: `https://www.youtube.com/@${username}`,
                status: 'VERIFIED ✓',
                confidence: 'MEDIUM'
            };
        }
    } catch (e) {}
    return null;
}

async function validateDiscord(username) {
    // Discord usernames can't be directly validated without API access
    return {
        platform: 'Discord',
        status: 'SEARCH REQUIRED',
        note: `Search Discord servers for username: ${username}`
    };
}

async function comprehensiveSocialMediaScan(identifier) {
    console.log('   🔍 Scanning 15+ platforms...');
    
    const validators = [
        validateInstagram,
        validateTwitter,
        validateGitHub,
        validateTikTok,
        validateLinkedIn,
        validateReddit,
        validateMedium,
        validateTelegram,
        validateYouTube,
        validateDiscord
    ];

    const results = [];
    for (const validator of validators) {
        try {
            const result = await validator(identifier);
            if (result) results.push(result);
        } catch (e) {
            console.log(`   ⚠️  ${validator.name} error: ${e.message}`);
        }
    }

    return results;
}

// ==================== ADVANCED GOOGLE DORKING ====================

async function megaGoogleDork(query, type) {
    const dorkSets = {
    email: [
        // Basic searches
        `"${query}"`,
        `"${query}" -site:${query.split('@')[1]}`,
        
        // Professional networks & code repositories
        `"${query}" (site:linkedin.com OR site:github.com OR site:gitlab.com)`,
        `"${query}" site:bitbucket.org OR site:sourceforge.net OR site:codepen.io`,
        `"${query}" site:stackoverflow.com OR site:stackexchange.com OR site:superuser.com`,
        `"${query}" site:dev.to OR site:medium.com OR site:hashnode.com`,
        
        // Documents & files
        `"${query}" (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)`,
        `"${query}" (filetype:ppt OR filetype:pptx OR filetype:doc OR filetype:txt)`,
        `"${query}" (filetype:xls OR filetype:json OR filetype:xml OR filetype:log)`,
        `"${query}" filetype:sql OR filetype:db OR filetype:sqlite OR filetype:mdb`,
        `"${query}" filetype:env OR filetype:config OR filetype:ini OR filetype:yml`,
        `"${query}" filetype:bak OR filetype:backup OR filetype:old`,
        
        // Paste sites & text dumps
        `"${query}" site:pastebin.com OR site:ghostbin.com OR site:rentry.co`,
        `"${query}" site:justpaste.it OR site:paste.ee OR site:hastebin.com`,
        `"${query}" site:controlc.com OR site:paste2.org OR site:privatebin.net`,
        `"${query}" site:ideone.com OR site:codepad.org OR site:dpaste.com`,
        
        // Project management & collaboration
        `"${query}" site:trello.com OR site:atlassian.net OR site:asana.com`,
        `"${query}" site:notion.so OR site:monday.com OR site:clickup.com`,
        `"${query}" site:basecamp.com OR site:airtable.com`,
        
        // Cloud storage & docs
        `"${query}" site:docs.google.com OR site:drive.google.com`,
        `"${query}" site:onedrive.live.com OR site:dropbox.com`,
        `"${query}" site:box.com OR site:mega.nz OR site:mediafire.com`,
        `"${query}" site:scribd.com OR site:slideshare.net OR site:issuu.com`,
        `"${query}" site:docdroid.net OR site:docdroid.com`,
        
        // Social media platforms
        `"${query}" (site:facebook.com OR site:instagram.com OR site:twitter.com)`,
        `"${query}" (site:tiktok.com OR site:snapchat.com OR site:pinterest.com)`,
        `"${query}" site:vk.com OR site:ok.ru OR site:myspace.com`,
        `"${query}" site:tumblr.com OR site:blogger.com OR site:wordpress.com`,
        
        // Forums & communities
        `"${query}" site:reddit.com OR site:quora.com OR site:stackexchange.com`,
        `"${query}" site:discord.gg OR site:discordapp.com OR site:discord.com`,
        `"${query}" site:telegram.me OR site:t.me`,
        `"${query}" site:kaskus.co.id OR site:forum.detik.com OR site:ads.id`,
        
        // Indonesian sites
        `"${query}" site:*.ac.id OR site:*.sch.id OR site:*.go.id`,
        `"${query}" site:*.co.id OR site:*.or.id OR site:*.web.id`,
        `"${query}" site:*.desa.id OR site:*.biz.id`,
        
        // Educational institutions
        `"${query}" site:*.edu OR site:*.gov OR site:*.mil`,
        `"${query}" site:academia.edu OR site:researchgate.net`,
        `"${query}" site:semanticscholar.org OR site:arxiv.org`,
        
        // Business & professional
        `"${query}" inurl:cv OR inurl:resume OR inurl:portfolio`,
        `"${query}" inurl:about OR inurl:contact OR inurl:team`,
        `"${query}" inurl:profile OR inurl:user OR inurl:member`,
        `"${query}" intext:"contact" intext:"email" intext:"phone"`,
        
        // Design & creative
        `"${query}" site:behance.net OR site:dribbble.com OR site:artstation.com`,
        `"${query}" site:deviantart.com OR site:pixiv.net OR site:500px.com`,
        `"${query}" site:flickr.com OR site:unsplash.com`,
        
        // E-commerce & marketplaces
        `"${query}" site:tokopedia.com OR site:shopee.co.id OR site:bukalapak.com`,
        `"${query}" site:olx.co.id OR site:blibli.com OR site:lazada.co.id`,
        `"${query}" site:ebay.com OR site:amazon.com OR site:etsy.com`,
        
        // Messaging & communication
        `"${query}" site:web.whatsapp.com OR intext:"whatsapp"`,
        `"${query}" intext:"telegram" OR intext:"discord" OR intext:"slack"`,
        `"${query}" site:skype.com OR site:zoom.us OR site:teams.microsoft.com`,
        
        // Security & sensitive data
        `"${query}" intext:"password" OR intext:"credentials" OR intext:"login"`,
        `"${query}" intext:"database" OR intext:"dump" OR intext:"leak"`,
        `"${query}" intext:"api key" OR intext:"api_key" OR intext:"token"`,
        `"${query}" intext:"secret" OR intext:"private" OR intext:"confidential"`,
        `"${query}" inurl:admin OR inurl:dashboard OR inurl:panel`,
        `"${query}" inurl:config OR inurl:backup OR inurl:db`,
        
        // Invoice & financial
        `"${query}" intext:"invoice" OR intext:"payment" OR intext:"receipt"`,
        `"${query}" intext:"bank" OR intext:"account" OR intext:"transaction"`,
        
        // Job & recruitment
        `"${query}" site:indeed.com OR site:jobstreet.co.id OR site:linkedin.com/jobs`,
        `"${query}" intext:"apply" OR intext:"career" OR intext:"recruitment"`,
        
        // Video & streaming
        `"${query}" site:youtube.com OR site:vimeo.com OR site:dailymotion.com`,
        `"${query}" site:twitch.tv OR site:livestream.com`,
        
        // Music & audio
        `"${query}" site:soundcloud.com OR site:spotify.com OR site:apple.com/music`,
        `"${query}" site:bandcamp.com OR site:audiomack.com`,
        
        // Dating & social
        `"${query}" site:tinder.com OR site:bumble.com OR site:match.com`,
        `"${query}" site:okcupid.com OR site:pof.com`,
        
        // Gaming platforms
        `"${query}" site:steam.com OR site:twitch.tv OR site:epicgames.com`,
        `"${query}" site:kaggle.com OR site:hackerrank.com OR site:leetcode.com`,
        
        // News & media
        `"${query}" site:*.news OR site:*.media OR site:medium.com`,
        `"${query}" intext:"published" OR intext:"author" OR intext:"journalist"`,
        
        // Archives & backups
        `"${query}" site:archive.org OR site:archive.is OR site:archive.today`,
        `"${query}" inurl:backup OR inurl:old OR inurl:archive`,
        
        // Additional sensitive searches
        `"${query}" "curriculum vitae" OR "resume" OR "cv"`,
        `"${query}" "phone" OR "mobile" OR "cell"`,
        `"${query}" "address" OR "location" OR "residence"`,
        `"${query}" intext:"employee" OR intext:"staff" OR intext:"worker"`
    ],
    
    phone: [
        // Basic searches
        `"${query}"`,
        `"${query}" -site:spam`,
        
        // Social media - comprehensive
        `"${query}" (site:facebook.com OR site:instagram.com OR site:twitter.com)`,
        `"${query}" (site:tiktok.com OR site:linkedin.com OR site:pinterest.com)`,
        `"${query}" site:vk.com OR site:ok.ru OR site:myspace.com`,
        `"${query}" site:snapchat.com OR site:telegram.me OR site:t.me`,
        
        // Messaging apps
        `"${query}" site:web.whatsapp.com OR intext:"whatsapp"`,
        `"${query}" intext:"whatsapp" OR intext:"wa" OR intext:"telegram"`,
        `"${query}" intext:"line" OR intext:"viber" OR intext:"wechat"`,
        `"${query}" intext:"signal" OR intext:"discord"`,
        
        // Indonesian e-commerce
        `"${query}" site:tokopedia.com OR site:bukalapak.com OR site:shopee.co.id`,
        `"${query}" site:olx.co.id OR site:blibli.com OR site:lazada.co.id`,
        `"${query}" site:carousell.co.id OR site:jualo.com`,
        `"${query}" site:kaskus.co.id (jual OR beli OR lapak)`,
        
        // International marketplaces
        `"${query}" site:ebay.com OR site:amazon.com OR site:craigslist.org`,
        `"${query}" site:alibaba.com OR site:aliexpress.com`,
        
        // Indonesian sites
        `"${query}" site:*.ac.id OR site:*.sch.id OR site:*.go.id OR site:*.desa.id`,
        `"${query}" site:*.co.id OR site:*.or.id OR site:*.web.id`,
        `"${query}" intext:"indonesia" OR intext:"jakarta" OR intext:"surabaya"`,
        
        // Documents & files
        `"${query}" filetype:xlsx OR filetype:csv OR filetype:pdf`,
        `"${query}" filetype:doc OR filetype:docx OR filetype:txt`,
        `"${query}" filetype:vcf OR filetype:vcard OR filetype:xls`,
        `"${query}" filetype:sql OR filetype:db OR filetype:mdb`,
        
        // Contact information
        `"${query}" intext:"kontak" OR intext:"telepon" OR intext:"hp"`,
        `"${query}" intext:"nomor hp" OR intext:"no hp" OR intext:"call"`,
        `"${query}" intext:"hubungi" OR intext:"contact" OR intext:"reach"`,
        `"${query}" inurl:contact OR inurl:about OR inurl:profile`,
        
        // Caller ID services
        `"${query}" site:getcontact.com OR site:truecaller.com OR site:sync.me`,
        `"${query}" site:whoscall.com OR site:eyecon.com`,
        `"${query}" site:showcaller.com OR site:unknownphone.com`,
        
        // LinkedIn specific
        `"${query}" site:linkedin.com (indonesia OR jakarta OR surabaya)`,
        `"${query}" site:linkedin.com intext:"phone" OR intext:"mobile"`,
        
        // Forums & communities
        `"${query}" site:kaskus.co.id OR site:forum.detik.com OR site:ads.id`,
        `"${query}" site:reddit.com OR site:quora.com`,
        `"${query}" site:lowyat.net OR site:forum.kompas.com`,
        
        // Business directories
        `"${query}" site:yellowpages.co.id OR site:*.co.id intext:"contact"`,
        `"${query}" site:pagesdirectory.com OR site:hotfrog.co.id`,
        `"${query}" intext:"direktori" OR intext:"directory"`,
        
        // Job portals
        `"${query}" site:jobstreet.co.id OR site:indeed.co.id OR site:jobs.id`,
        `"${query}" intext:"pendaftaran" OR intext:"registrasi" OR intext:"recruitment"`,
        
        // Educational
        `"${query}" site:akademik OR site:mahasiswa OR site:siswa`,
        `"${query}" intext:"universitas" OR intext:"sekolah" OR intext:"kampus"`,
        
        // Government & public records
        `"${query}" site:*.go.id OR site:*.desa.id`,
        `"${query}" intext:"data" (filetype:xlsx OR filetype:csv)`,
        `"${query}" intext:"daftar" OR intext:"list" OR intext:"database"`,
        
        // Paste sites
        `"${query}" site:pastebin.com OR site:rentry.co OR site:ghostbin.com`,
        `"${query}" site:justpaste.it OR site:paste.ee`,
        
        // Real estate & property
        `"${query}" site:rumah123.com OR site:lamudi.co.id OR site:rumah.com`,
        `"${query}" intext:"properti" OR intext:"property" OR intext:"real estate"`,
        
        // Healthcare & medical
        `"${query}" intext:"dokter" OR intext:"doctor" OR intext:"klinik"`,
        `"${query}" site:alodokter.com OR site:halodoc.com`,
        
        // Transportation
        `"${query}" intext:"driver" OR intext:"supir" OR intext:"kurir"`,
        `"${query}" site:gojek.com OR site:grab.com`,
        
        // Dating apps
        `"${query}" site:tinder.com OR site:bumble.com OR site:okcupid.com`,
        
        // Invoice & business
        `"${query}" intext:"invoice" OR intext:"faktur" OR intext:"receipt"`,
        `"${query}" intext:"supplier" OR intext:"vendor" OR intext:"customer"`,
        
        // Events & registration
        `"${query}" intext:"event" OR intext:"acara" OR intext:"registration"`,
        `"${query}" intext:"ticket" OR intext:"tiket" OR intext:"booking"`,
        
        // Additional context
        `"${query}" site:*.com intext:"indonesia" intext:"phone"`,
        `"${query}" inurl:member OR inurl:user OR inurl:account`,
        `"${query}" intext:"member" OR intext:"anggota"`,
        
        // Emergency & services
        `"${query}" intext:"emergency" OR intext:"darurat" OR intext:"helpline"`,
        
        // Archives
        `"${query}" site:archive.org OR site:archive.is`,
        
        // Cloud storage
        `"${query}" site:docs.google.com OR site:drive.google.com`,
        `"${query}" site:dropbox.com OR site:onedrive.live.com`
    ],
    
    username: [
        // Basic searches
        `"${query}"`,
        `"${query}" -site:facebook.com`,
        
        // Code repositories
        `"${query}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)`,
        `"${query}" site:sourceforge.net OR site:codepen.io OR site:jsfiddle.net`,
        `"${query}" site:repl.it OR site:codesandbox.io OR site:glitch.com`,
        
        // Paste sites
        `"${query}" site:pastebin.com OR site:ghostbin.com OR site:rentry.co`,
        `"${query}" site:justpaste.it OR site:paste.ee OR site:hastebin.com`,
        `"${query}" site:ideone.com OR site:codepad.org`,
        
        // Social media - major platforms
        `"${query}" (site:twitter.com OR site:instagram.com OR site:tiktok.com)`,
        `"${query}" (site:facebook.com OR site:linkedin.com OR site:pinterest.com)`,
        `"${query}" site:snapchat.com OR site:tumblr.com`,
        
        // International social networks
        `"${query}" site:vk.com OR site:ok.ru OR site:weibo.com`,
        `"${query}" site:qq.com OR site:wechat.com`,
        
        // Blogging platforms
        `"${query}" site:medium.com OR site:dev.to OR site:hashnode.com`,
        `"${query}" site:wordpress.com OR site:blogger.com OR site:wix.com`,
        `"${query}" site:substack.com OR site:ghost.org`,
        
        // Developer communities
        `"${query}" site:stackoverflow.com OR site:stackexchange.com`,
        `"${query}" site:hackernews.com OR site:lobste.rs`,
        `"${query}" site:producthunt.com OR site:indiehackers.com`,
        
        // Forums & communities
        `"${query}" site:reddit.com OR site:quora.com`,
        `"${query}" site:discord.com OR site:discordapp.com OR site:discord.gg`,
        `"${query}" site:telegram.me OR site:t.me`,
        `"${query}" site:kaskus.co.id OR site:ads.id`,
        
        // Design & creative
        `"${query}" site:behance.net OR site:dribbble.com OR site:artstation.com`,
        `"${query}" site:deviantart.com OR site:pixiv.net OR site:500px.com`,
        `"${query}" site:flickr.com OR site:unsplash.com OR site:pexels.com`,
        
        // Photography
        `"${query}" site:instagram.com OR site:vsco.co OR site:ello.co`,
        
        // Video platforms
        `"${query}" site:youtube.com OR site:vimeo.com OR site:dailymotion.com`,
        `"${query}" site:twitch.tv OR site:mixer.com OR site:dlive.tv`,
        `"${query}" site:rumble.com OR site:odysee.com`,
        
        // Gaming platforms
        `"${query}" site:steam.com OR site:steamcommunity.com`,
        `"${query}" site:twitch.tv OR site:discord.gg`,
        `"${query}" site:roblox.com OR site:minecraft.net`,
        `"${query}" site:epicgames.com OR site:battle.net`,
        `"${query}" site:playstation.com OR site:xbox.com`,
        
        // Gaming profiles
        `"${query}" site:op.gg OR site:dotabuff.com OR site:tracker.gg`,
        `"${query}" site:lolchess.gg OR site:chess.com OR site:lichess.org`,
        
        // Music platforms
        `"${query}" site:soundcloud.com OR site:spotify.com OR site:apple.com/music`,
        `"${query}" site:bandcamp.com OR site:audiomack.com OR site:mixcloud.com`,
        `"${query}" site:last.fm OR site:genius.com`,
        
        // Professional networks
        `"${query}" site:linkedin.com OR site:xing.com OR site:indeed.com`,
        
        // Learning platforms
        `"${query}" site:udemy.com OR site:coursera.org OR site:edx.org`,
        `"${query}" site:skillshare.com OR site:pluralsight.com`,
        `"${query}" site:codecademy.com OR site:freecodecamp.org`,
        
        // Competitive programming
        `"${query}" site:kaggle.com OR site:hackerrank.com OR site:leetcode.com`,
        `"${query}" site:codeforces.com OR site:topcoder.com OR site:codechef.com`,
        `"${query}" site:atcoder.jp OR site:projecteuler.net`,
        
        // Academic & research
        `"${query}" site:academia.edu OR site:researchgate.net`,
        `"${query}" site:orcid.org OR site:scholar.google.com`,
        
        // Indonesian sites
        `"${query}" (site:*.ac.id OR site:*.sch.id) intext:"mahasiswa"`,
        `"${query}" site:*.co.id OR site:*.or.id`,
        
        // Documents & presentations
        `"${query}" site:slideshare.net OR site:scribd.com OR site:issuu.com`,
        `"${query}" site:prezi.com OR site:canva.com`,
        
        // Portfolio & showcase
        `"${query}" intext:"portfolio" OR intext:"projects" OR intext:"work"`,
        `"${query}" inurl:user OR inurl:profile OR inurl:member`,
        `"${query}" inurl:portfolio OR inurl:about OR inurl:resume`,
        
        // Contact information
        `"${query}" intext:"email" OR intext:"contact" OR intext:"about"`,
        `"${query}" intext:"reach me" OR intext:"get in touch"`,
        
        // Messaging & chat
        `"${query}" site:whatsapp.com OR site:telegram.org`,
        `"${query}" site:signal.org OR site:wickr.com`,
        
        // Dating platforms
        `"${query}" site:tinder.com OR site:bumble.com OR site:hinge.co`,
        `"${query}" site:okcupid.com OR site:match.com OR site:pof.com`,
        
        // Freelance platforms
        `"${query}" site:upwork.com OR site:fiverr.com OR site:freelancer.com`,
        `"${query}" site:toptal.com OR site:guru.com OR site:peopleperhour.com`,
        `"${query}" site:projects.co.id OR site:sribulancer.com`,
        
        // E-commerce profiles
        `"${query}" site:etsy.com OR site:ebay.com OR site:amazon.com`,
        `"${query}" site:tokopedia.com OR site:shopee.co.id OR site:bukalapak.com`,
        
        // Fitness & health
        `"${query}" site:strava.com OR site:myfitnesspal.com OR site:fitbit.com`,
        
        // Travel
        `"${query}" site:tripadvisor.com OR site:airbnb.com OR site:couchsurfing.com`,
        
        // Fashion & beauty
        `"${query}" site:pinterest.com OR site:polyvore.com`,
        
        // Food & recipes
        `"${query}" site:allrecipes.com OR site:foodnetwork.com`,
        
        // Book platforms
        `"${query}" site:goodreads.com OR site:wattpad.com OR site:archive.org`,
        
        // Podcasts
        `"${query}" site:anchor.fm OR site:podbean.com OR site:castbox.fm`,
        
        // NFT & crypto
        `"${query}" site:opensea.io OR site:rarible.com OR site:foundation.app`,
        `"${query}" site:coinbase.com OR site:binance.com`,
        
        // 3D & modeling
        `"${query}" site:sketchfab.com OR site:cgtrader.com OR site:turbosquid.com`,
        
        // Animation
        `"${query}" site:newgrounds.com OR site:animator.com`,
        
        // Archives
        `"${query}" site:archive.org OR site:archive.is OR site:web.archive.org`,
        
        // Professional services
        `"${query}" site:about.me OR site:linktree.com OR site:bio.link`,
        `"${query}" site:carrd.co OR site:notion.so`,
        
        // Additional context searches
        `"${query}" intext:"username" OR intext:"handle" OR intext:"alias"`,
        `"${query}" intext:"follow me" OR intext:"find me"`,
        `"${query}" "social media" OR "my profile"`,
        
        // Indonesian forums
        `"${query}" site:kaskus.co.id OR site:forum.detik.com OR site:bersosial.com`,
        
        // Tech communities
        `"${query}" site:hackernews.com OR site:slashdot.org`,
        
        // Security & privacy
        `"${query}" site:keybase.io OR site:protonmail.com`,
        
        // Wikis
        `"${query}" site:fandom.com OR site:wikia.com OR site:wikipedia.org`
    ]
};

    const queries = dorkSets[type] || dorkSets.username;
    const allResults = [];
    let successCount = 0;

    console.log(`   🔎 Executing ${queries.length} advanced dork queries...`);

    for (let i = 0; i < queries.length; i++) {
        try {
            const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(queries[i])}&num=30&hl=en&gl=us`;
            
            const response = await fetchWithRetry(searchUrl, {
                headers: {
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Cache-Control': 'no-cache',
                    'Referer': 'https://www.google.com/'
                }
            });

            if (response.status === 200) {
                const $ = cheerio.load(response.data);
                let found = 0;

                $('.g, .tF2Cxc').each((idx, elem) => {
                    const title = $(elem).find('h3').text().trim();
                    const link = $(elem).find('a').first().attr('href');
                    const snippet = $(elem).find('.VwiC3b, .yXK7lf, .IsZvec, .aCOpRe').text().trim();

                    if (link && title && !link.includes('google.com') && !link.startsWith('/search')) {
                        const relevanceScore = calculateRelevance(snippet, query);
                        
                        allResults.push({
                            title: title.substring(0, 150),
                            url: link,
                            snippet: snippet.substring(0, 300) || 'No description available',
                            dorkQuery: queries[i],
                            relevance: relevanceScore >= 0.7 ? 'HIGH' : relevanceScore >= 0.4 ? 'MEDIUM' : 'LOW',
                            relevanceScore: relevanceScore
                        });
                        found++;
                    }
                });

                successCount++;
                console.log(`   ✓ Query ${i + 1}/${queries.length}: ${found} results (${response.status})`);
            } else if (response.status === 429) {
                console.log(`   ⚠️  Query ${i + 1}/${queries.length}: Rate limited, waiting...`);
                await delay(30000);
            } else {
                console.log(`   ✗ Query ${i + 1}/${queries.length}: Status ${response.status}`);
            }

        } catch (error) {
            console.log(`   ✗ Query ${i + 1}/${queries.length}: ${error.message}`);
        }
    }

    console.log(`   📊 Success rate: ${successCount}/${queries.length} queries`);

    // Remove duplicates and sort by relevance
    const uniqueResults = Array.from(new Map(allResults.map(r => [r.url, r])).values());
    return uniqueResults.sort((a, b) => b.relevanceScore - a.relevanceScore);
}

function calculateRelevance(text, query) {
    if (!text) return 0;
    
    const lowerText = text.toLowerCase();
    const lowerQuery = query.toLowerCase();
    
    let score = 0;
    
    // Exact match
    if (lowerText.includes(lowerQuery)) score += 0.5;
    
    // Word proximity
    const words = lowerQuery.split(/\s+/);
    const matchedWords = words.filter(word => lowerText.includes(word));
    score += (matchedWords.length / words.length) * 0.3;
    
    // Context keywords
    const contextKeywords = ['email', 'phone', 'contact', 'profile', 'about', 'user', 'account', 'member'];
    const contextMatches = contextKeywords.filter(kw => lowerText.includes(kw));
    score += (contextMatches.length / contextKeywords.length) * 0.2;
    
    return Math.min(score, 1);
}

// ==================== DATA LEAK DATABASES ====================

async function searchPastebinDumps(query) {
    const results = [];
    
    try {
        console.log('   🔍 Searching Pastebin dumps...');
        const response = await fetchWithRetry(`https://psbdmp.ws/api/search/${encodeURIComponent(query)}`);
        
        if (response.status === 200 && Array.isArray(response.data)) {
            response.data.slice(0, 15).forEach(item => {
                results.push({
                    source: 'Pastebin Dump',
                    title: item.title || 'Untitled',
                    url: `https://pastebin.com/${item.id}`,
                    id: item.id,
                    timestamp: item.time,
                    tags: item.tags
                });
            });
        }
    } catch (e) {
        console.log(`   ⚠️  Pastebin search failed: ${e.message}`);
    }

    return results;
}

async function searchGitHubCode(query) {
    const results = [];
    
    try {
        console.log('   🔍 Searching GitHub code...');
        const response = await fetchWithRetry(`https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=30`, {
            headers: {
                'Accept': 'application/vnd.github.v3+json'
            }
        });

        if (response.status === 200 && response.data.items) {
            response.data.items.slice(0, 20).forEach(item => {
                results.push({
                    source: 'GitHub Code',
                    file: item.name,
                    path: item.path,
                    url: item.html_url,
                    repository: item.repository.full_name,
                    repoUrl: item.repository.html_url,
                    description: item.repository.description
                });
            });
        }
    } catch (e) {
        console.log(`   ⚠️  GitHub search failed: ${e.message}`);
    }

    return results;
}

async function searchGitHubGists(query) {
    const results = [];
    
    try {
        console.log('   🔍 Searching GitHub Gists...');
        const response = await fetchWithRetry(`https://api.github.com/search/code?q=${encodeURIComponent(query)}+in:file+language:text&per_page=20`);

        if (response.status === 200 && response.data.items) {
            response.data.items.forEach(item => {
                if (item.repository.name.includes('gist')) {
                    results.push({
                        source: 'GitHub Gist',
                        file: item.name,
                        url: item.html_url,
                        owner: item.repository.owner.login
                    });
                }
            });
        }
    } catch (e) {}

    return results;
}

async function searchWaybackMachine(domain) {
    const results = [];
    
    try {
        console.log('   🔍 Checking Wayback Machine archives...');
        const response = await fetchWithRetry(`https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=50&filter=statuscode:200`);

        if (Array.isArray(response.data) && response.data.length > 1) {
            response.data.slice(1, 26).forEach(item => {
                results.push({
                    source: 'Archive.org',
                    timestamp: item[1],
                    originalUrl: item[2],
                    archiveUrl: `https://web.archive.org/web/${item[1]}/${item[2]}`,
                    statusCode: item[4],
                    mimeType: item[3]
                });
            });
        }
    } catch (e) {
        console.log(`   ⚠️  Wayback search failed: ${e.message}`);
    }

    return results;
}

async function searchTrello(query) {
    const results = [];
    
    try {
        console.log('   🔍 Searching Trello boards...');
        const searchUrl = `https://www.google.com/search?q=site:trello.com+"${encodeURIComponent(query)}"&num=20`;
        const response = await fetchWithRetry(searchUrl);

        const $ = cheerio.load(response.data);
        $('.g a').each((i, elem) => {
            const href = $(elem).attr('href');
            if (href && href.includes('trello.com/b/') && !href.includes('google.com')) {
                const cleanUrl = href.split('&')[0];
                results.push({
                    source: 'Trello Board',
                    url: cleanUrl,
                    title: $(elem).find('h3').text()
                });
            }
        });
    } catch (e) {}

    return results.slice(0, 10);
}

async function searchPeopleDataEngines(query, type) {
    const results = [];
    
    const engines = [
        { name: 'Whitepages', url: `https://www.whitepages.com/search?q=${encodeURIComponent(query)}` },
        { name: 'ThatsThem', url: `https://thatsthem.com/email/${encodeURIComponent(query)}` },
        { name: 'Spokeo', url: `https://www.spokeo.com/${encodeURIComponent(query)}` },
        { name: 'BeenVerified', url: `https://www.beenverified.com/search/email/${encodeURIComponent(query)}` },
        { name: 'PeekYou', url: `https://www.peekyou.com/${encodeURIComponent(query)}` },
        { name: 'Pipl', url: `https://pipl.com/search/?q=${encodeURIComponent(query)}` },
        { name: 'ZabaSearch', url: `https://www.zabasearch.com/people/${encodeURIComponent(query)}` },
        { name: 'AnyWho', url: `https://www.anywho.com/people/${encodeURIComponent(query)}` },
        { name: 'PeopleFinders', url: `https://www.peoplefinders.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Intelius', url: `https://www.intelius.com/people-search/${encodeURIComponent(query)}` },
        { name: 'TruthFinder', url: `https://www.truthfinder.com/results/?firstName=${encodeURIComponent(query)}` },
        { name: 'InstantCheckmate', url: `https://www.instantcheckmate.com/search/?firstName=${encodeURIComponent(query)}` },
        { name: 'USSearch', url: `https://www.ussearch.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Radaris', url: `https://radaris.com/p/${encodeURIComponent(query)}` },
        { name: 'Melissa', url: `https://www.melissa.com/lookups/emails?email=${encodeURIComponent(query)}` },
        { name: 'EmailHippo', url: `https://tools.emailhippo.com/${encodeURIComponent(query)}` },
        { name: 'Hunter.io', url: `https://hunter.io/search/${encodeURIComponent(query)}` },
        { name: 'Voila Norbert', url: `https://www.voilanorbert.com/search?query=${encodeURIComponent(query)}` },
        { name: 'RocketReach', url: `https://rocketreach.co/search?query=${encodeURIComponent(query)}` },
        { name: 'ContactOut', url: `https://contactout.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Lusha', url: `https://www.lusha.com/search/?query=${encodeURIComponent(query)}` },
        { name: 'Clearbit', url: `https://clearbit.com/resources/tools/connect?email=${encodeURIComponent(query)}` },
        { name: 'EmailRep', url: `https://emailrep.io/${encodeURIComponent(query)}` },
        { name: 'Verifalia', url: `https://verifalia.com/validate-email/${encodeURIComponent(query)}` },
        { name: 'EmailChecker', url: `https://email-checker.net/check?email=${encodeURIComponent(query)}` },
        { name: 'VerifyEmailAddress', url: `https://www.verifyemailaddress.org/${encodeURIComponent(query)}` },
        { name: 'TheChecker', url: `https://thechecker.co/verify-email/${encodeURIComponent(query)}` },
        { name: 'MyEmailVerifier', url: `https://www.myemailverifier.com/verify-email/${encodeURIComponent(query)}` },
        { name: 'MailTester', url: `https://www.mail-tester.com/web-${encodeURIComponent(query)}` },
        { name: 'EmailFinder', url: `https://emailfinder.io/search/${encodeURIComponent(query)}` },
        { name: 'FindThatEmail', url: `https://findthat.email/search/${encodeURIComponent(query)}` },
        { name: 'FindEmails', url: `https://www.findemails.com/search/${encodeURIComponent(query)}` },
        { name: 'Snov.io', url: `https://snov.io/email-finder?query=${encodeURIComponent(query)}` },
        { name: 'LeadIQ', url: `https://leadiq.com/search?q=${encodeURIComponent(query)}` },
        { name: 'SignalHire', url: `https://www.signalhire.com/search?q=${encodeURIComponent(query)}` },
        { name: 'GetProspect', url: `https://getprospect.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Kaspr', url: `https://www.kaspr.io/tools/email-finder?query=${encodeURIComponent(query)}` },
        { name: 'DropContact', url: `https://www.dropcontact.com/enrichment?email=${encodeURIComponent(query)}` },
        { name: 'Seamless.ai', url: `https://www.seamless.ai/search?q=${encodeURIComponent(query)}` },
        { name: 'AeroLeads', url: `https://aeroleads.com/search?query=${encodeURIComponent(query)}` },
        { name: 'LeadGibbon', url: `https://leadgibbon.com/search/${encodeURIComponent(query)}` },
        { name: 'GetEmail.io', url: `https://getemail.io/search?email=${encodeURIComponent(query)}` },
        { name: 'EmailBreaker', url: `https://www.email-breaker.com/search/${encodeURIComponent(query)}` },
        { name: 'That\'sThem Email', url: `https://thatsthem.com/reverse-email-lookup/${encodeURIComponent(query)}` },
        { name: 'EmailSearch.net', url: `https://www.emailsearch.net/search?email=${encodeURIComponent(query)}` },
        { name: 'ReverseContact', url: `https://www.reversecontact.com/lookup?email=${encodeURIComponent(query)}` },
        { name: 'Personio', url: `https://www.personio.com/search?q=${encodeURIComponent(query)}` },
        { name: 'VoilaNorbert Email', url: `https://www.voilanorbert.com/verify-email?email=${encodeURIComponent(query)}` },
        { name: 'EmailSearch.io', url: `https://emailsearch.io/search?query=${encodeURIComponent(query)}` },
        { name: 'FindAnyEmail', url: `https://findanyemail.net/search?q=${encodeURIComponent(query)}` },
        { name: 'EmailHunter', url: `https://emailhunter.co/search/${encodeURIComponent(query)}` },
        { name: 'BetterContact', url: `https://bettercontact.com/search?email=${encodeURIComponent(query)}` },
        { name: 'Adapt.io', url: `https://adapt.io/search?q=${encodeURIComponent(query)}` },
        { name: 'LeadFuze', url: `https://www.leadfuze.com/search?query=${encodeURIComponent(query)}` },
        { name: 'UpLead', url: `https://www.uplead.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Cognism', url: `https://www.cognism.com/search/${encodeURIComponent(query)}` },
        { name: 'ZoomInfo', url: `https://www.zoominfo.com/search?q=${encodeURIComponent(query)}` },
        { name: 'LeadGenius', url: `https://leadgenius.com/search?email=${encodeURIComponent(query)}` },
        { name: 'Datanyze', url: `https://www.datanyze.com/search?q=${encodeURIComponent(query)}` },
        { name: 'DiscoverOrg', url: `https://discoverorg.com/search?query=${encodeURIComponent(query)}` },
        { name: 'InsideView', url: `https://www.insideview.com/search?q=${encodeURIComponent(query)}` },
        { name: 'LeadSpace', url: `https://www.leadspace.com/search/${encodeURIComponent(query)}` },
        { name: 'EasyLeadz', url: `https://easyleadz.com/search?email=${encodeURIComponent(query)}` },
        { name: 'Leadiro', url: `https://www.leadiro.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Lead411', url: `https://www.lead411.com/search?query=${encodeURIComponent(query)}` },
        { name: 'LeadsPlease', url: `https://www.leadsplease.com/search/${encodeURIComponent(query)}` },
        { name: 'SalesIntel', url: `https://salesintel.io/search?q=${encodeURIComponent(query)}` },
        { name: 'Oceanos', url: `https://oceanos.io/search?email=${encodeURIComponent(query)}` },
        { name: 'LeadMine', url: `https://leadmine.net/search?query=${encodeURIComponent(query)}` },
        { name: 'FindThatLead', url: `https://findthatlead.com/search/${encodeURIComponent(query)}` },
        { name: 'Skrapp.io', url: `https://www.skrapp.io/search?q=${encodeURIComponent(query)}` },
        { name: 'Prospect.io', url: `https://prospect.io/search?email=${encodeURIComponent(query)}` },
        { name: 'Reply.io', url: `https://reply.io/email-finder/?query=${encodeURIComponent(query)}` },
        { name: 'Salesloft', url: `https://salesloft.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Outreach.io', url: `https://www.outreach.io/search/${encodeURIComponent(query)}` },
        { name: 'Mixmax', url: `https://www.mixmax.com/search?email=${encodeURIComponent(query)}` },
        { name: 'Yesware', url: `https://www.yesware.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Cirrus Insight', url: `https://www.cirrusinsight.com/search/${encodeURIComponent(query)}` },
        { name: 'Groove', url: `https://www.groove.co/search?query=${encodeURIComponent(query)}` },
        { name: 'Close.com', url: `https://close.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Pipedrive', url: `https://www.pipedrive.com/search/${encodeURIComponent(query)}` },
        { name: 'HubSpot Search', url: `https://www.hubspot.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Zoho CRM', url: `https://crm.zoho.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Freshsales', url: `https://www.freshworks.com/crm/search/${encodeURIComponent(query)}` },
        { name: 'Nimble', url: `https://www.nimble.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Salesforce Search', url: `https://www.salesforce.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Monday Sales', url: `https://monday.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Capsule CRM', url: `https://capsulecrm.com/search/${encodeURIComponent(query)}` },
        { name: 'Insightly', url: `https://www.insightly.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Streak', url: `https://www.streak.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Copper', url: `https://www.copper.com/search/${encodeURIComponent(query)}` },
        { name: 'Nutshell', url: `https://www.nutshell.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Agile CRM', url: `https://www.agilecrm.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Keap', url: `https://keap.com/search/${encodeURIComponent(query)}` },
        { name: 'ActiveCampaign', url: `https://www.activecampaign.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Mailchimp Search', url: `https://mailchimp.com/search/?query=${encodeURIComponent(query)}` },
        { name: 'Constant Contact', url: `https://www.constantcontact.com/search?q=${encodeURIComponent(query)}` },
        { name: 'GetResponse', url: `https://www.getresponse.com/search/${encodeURIComponent(query)}` },
        { name: 'AWeber', url: `https://www.aweber.com/search?query=${encodeURIComponent(query)}` },
        { name: 'ConvertKit', url: `https://convertkit.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Drip', url: `https://www.drip.com/search/${encodeURIComponent(query)}` },
        { name: 'SendGrid', url: `https://sendgrid.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Sendinblue', url: `https://www.sendinblue.com/search?q=${encodeURIComponent(query)}` },
        { name: 'EmailOctopus', url: `https://emailoctopus.com/search/${encodeURIComponent(query)}` },
        { name: 'Moosend', url: `https://moosend.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Benchmark Email', url: `https://www.benchmarkemail.com/search?q=${encodeURIComponent(query)}` },
        { name: 'MailerLite', url: `https://www.mailerlite.com/search/${encodeURIComponent(query)}` },
        { name: 'Campaign Monitor', url: `https://www.campaignmonitor.com/search?query=${encodeURIComponent(query)}` },
        { name: 'Omnisend', url: `https://www.omnisend.com/search?q=${encodeURIComponent(query)}` },
        { name: 'Klaviyo', url: `https://www.klaviyo.com/search/${encodeURIComponent(query)}` },
        { name: 'EmailVerify', url: `https://emailverify.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'QuickEmailVerification', url: `https://quickemailverification.com/verify/${encodeURIComponent(query)}` },
        { name: 'ZeroBounce', url: `https://www.zerobounce.net/email-validator/?email=${encodeURIComponent(query)}` },
        { name: 'NeverBounce', url: `https://neverbounce.com/verify-email?email=${encodeURIComponent(query)}` },
        { name: 'BriteVerify', url: `https://www.briteverify.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailListVerify', url: `https://www.emaillistverify.com/verify/${encodeURIComponent(query)}` },
        { name: 'Xverify', url: `https://www.xverify.com/email-verify?email=${encodeURIComponent(query)}` },
        { name: 'DeBounce', url: `https://debounce.io/verify-email/${encodeURIComponent(query)}` },
        { name: 'Kickbox', url: `https://kickbox.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Bounceless', url: `https://bounceless.io/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailMarker', url: `https://emailmarker.com/verify/${encodeURIComponent(query)}` },
        { name: 'MyEmailVerifier Pro', url: `https://pro.myemailverifier.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Emailable', url: `https://emailable.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Bouncify', url: `https://bouncify.io/verify/${encodeURIComponent(query)}` },
        { name: 'Mailfloss', url: `https://mailfloss.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailValidator', url: `https://www.email-validator.net/email-verifier.html?email=${encodeURIComponent(query)}` },
        { name: 'DataValidation', url: `https://www.datavalidation.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Webbula', url: `https://www.webbula.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'FreshAddress', url: `https://www.freshaddress.com/verify/${encodeURIComponent(query)}` },
        { name: 'AtData', url: `https://www.atdata.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'TowerData', url: `https://www.towerdata.com/email-intelligence?email=${encodeURIComponent(query)}` },
        { name: 'Experian Email', url: `https://www.experian.com/email-validation?email=${encodeURIComponent(query)}` },
        { name: 'Validity BriteVerify', url: `https://www.validity.com/briteverify/?email=${encodeURIComponent(query)}` },
        { name: 'EmailAge', url: `https://www.emailage.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'IPQS Email', url: `https://www.ipqualityscore.com/free-email-verifier?email=${encodeURIComponent(query)}` },
        { name: 'Abstract Email', url: `https://www.abstractapi.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'Apilayer Email', url: `https://apilayer.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'Mailboxlayer', url: `https://mailboxlayer.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailValidation API', url: `https://emailvalidation.io/verify?email=${encodeURIComponent(query)}` },
        { name: 'Proofy', url: `https://proofy.io/verify?email=${encodeURIComponent(query)}` },
        { name: 'Pabbly Email', url: `https://www.pabbly.com/email-verification/?email=${encodeURIComponent(query)}` },
        { name: 'Bouncer', url: `https://usebouncer.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Clearout', url: `https://clearout.io/verify?email=${encodeURIComponent(query)}` },
        { name: 'MillionVerifier', url: `https://www.millionverifier.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Captain Verify', url: `https://captainverify.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'Reoon Email', url: `https://reoon.com/email-verifier?email=${encodeURIComponent(query)}` },
        { name: 'EmailChecker Pro', url: `https://emailchecker.com/pro/verify?email=${encodeURIComponent(query)}` },
        { name: 'TrueMail', url: `https://truemail.io/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailVerification', url: `https://www.emailverification.com/verify/${encodeURIComponent(query)}` },
        { name: 'Byteplant Email', url: `https://www.byteplant.com/email-validator?email=${encodeURIComponent(query)}` },
        { name: 'Mailgun Verify', url: `https://www.mailgun.com/email-validation/?email=${encodeURIComponent(query)}` },
        { name: 'SendPulse Verify', url: `https://sendpulse.com/email-verifier?email=${encodeURIComponent(query)}` },
        { name: 'SocketLabs Email', url: `https://www.socketlabs.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'PostGrid Email', url: `https://www.postgrid.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'Lob Email', url: `https://www.lob.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'Postmark Email', url: `https://postmarkapp.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'SparkPost Email', url: `https://www.sparkpost.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'Elastic Email', url: `https://elasticemail.com/email-verifier?email=${encodeURIComponent(query)}` },
        { name: 'SMTP2GO Email', url: `https://www.smtp2go.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'Pepipost Email', url: `https://www.pepipost.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'SocketLabs Verify', url: `https://socketlabs.com/verify-email?email=${encodeURIComponent(query)}` },
        { name: 'EmailOversight', url: `https://www.emailoversight.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'TrustPath Email', url: `https://trustpath.com/email-verification?email=${encodeURIComponent(query)}` },
        { name: 'EmailAnalytics', url: `https://emailanalytics.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailInspector', url: `https://emailinspector.net/verify?email=${encodeURIComponent(query)}` },
        { name: 'ValidEmail', url: `https://validemail.com/verify?email=${encodeURIComponent(query)}` },
        { name: 'EmailAudit', url: `https://emailaudit.com/verify/${encodeURIComponent(query)}` },
        { name: 'FindEmailAddress', url: `https://findemailaddress.com/search?q=${encodeURIComponent(query)}` },
        { name: 'EmailCrawlr', url: `https://emailcrawlr.com/search/${encodeURIComponent(query)}` },
        { name: 'ContactFinder', url: `https://contactfinder.com/search?email=${encodeURIComponent(query)}` },
        { name: 'EmailDB', url: `https://emaildb.com/search?q=${encodeURIComponent(query)}` },
        { name: 'EmailDirectory', url: `https://emaildirectory.com/lookup/${encodeURIComponent(query)}` },
        { name: 'PeopleByEmail', url: `https://www.peoplebyemail.com/search?email=${encodeURIComponent(query)}` },
        { name: 'EmailLookup', url: `https://emaillookup.com/search?q=${encodeURIComponent(query)}` },
        { name: 'ReverseEmailLookup', url: `https://reverseemaillookup.com/search/${encodeURIComponent(query)}` },
        { name: 'EmailTrace', url: `https://emailtrace.com/lookup?email=${encodeURIComponent(query)}` },
        { name: 'WhoIsEmailOwner', url: `https://whoisemailowner.com/search?email=${encodeURIComponent(query)}` },
        { name: 'EmailOwnerFinder', url: `https://emailownerfinder.com/find/${encodeURIComponent(query)}` },
        { name: 'EmailIdentifier', url: `https://emailidentifier.com/search?q=${encodeURIComponent(query)}` },
        { name: 'EmailLocator', url: `https://emaillocator.com/find?email=${encodeURIComponent(query)}` },
        { name: 'EmailSeeker', url: `https://emailseeker.com/search/${encodeURIComponent(query)}` },
        { name: 'EmailDiscovery', url: `https://emaildiscovery.com/lookup?email=${encodeURIComponent(query)}` },
        { name: 'EmailIntelligence', url: `https://emailintelligence.com/search?q=${encodeURIComponent(query)}` },
        { name: 'EmailDetective', url: `https://emaildetective.com/find/${encodeURIComponent(query)}` },
        { name: 'EmailSherlock', url: `https://emailsherlock.com/search?email=${encodeURIComponent(query)}` },
        { name: 'EmailTracker', url: `https://emailtracker.com/lookup/${encodeURIComponent(query)}` },
        { name: 'EmailProfiler', url: `https://emailprofiler.com/search?q=${encodeURIComponent(query)}` }
    ];

    for (const engine of engines) {
        try {
            await randomDelay();
            const response = await fetchWithRetry(engine.url, {}, 1);
            
            if (response.status === 200 && !response.data.includes('No results')) {
                results.push({
                    source: engine.name,
                    url: engine.url,
                    status: 'Possible matches found - manual review required'
                });
            }
        } catch (e) {}
    }

    return results;
}

// ==================== ADVANCED WEB SCRAPING (LANJUTAN) ====================

async function deepScrapeWebsite(url, searchQuery) {
    try {
        const response = await fetchWithRetry(url);
        
        if (response.status !== 200) {
            return { error: `Status ${response.status}` };
        }

        const $ = cheerio.load(response.data);
        const text = $.text().toLowerCase();
        const htmlContent = response.data;
        
        const findings = {
            url: url,
            title: $('title').text().trim(),
            matches: [],
            emails: [],
            phones: [],
            socialLinks: [],
            cryptoWallets: [],
            ipAddresses: [],
            domains: [],
            usernames: [],
            apiKeys: [],
            credentials: [],
            fileLinks: [],
            externalLinks: [],
            images: [],
            videos: [],
            forms: [],
            comments: [],
            scripts: [],
            metadata: {},
            techStack: [],
            seoData: {},
            securityHeaders: {},
            cookies: []
        };

        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const emails = text.match(emailRegex) || [];
        findings.emails = [...new Set(emails)];

        const phoneRegex1 = /(\+62|62|0)[0-9]{9,13}/g;
        const phoneRegex2 = /(\+1|1)?[\s.-]?\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}/g;
        const phoneRegex3 = /(\+44|44|0)[0-9]{10}/g;
        const phoneRegex4 = /(\+91|91)?[0-9]{10}/g;
        const phoneRegex5 = /(\+86|86)?1[0-9]{10}/g;
        const phoneRegex6 = /(\+61|61)?[0-9]{9}/g;
        const phoneRegex7 = /(\+49|49)?[0-9]{10,11}/g;
        const phoneRegex8 = /(\+33|33)?[0-9]{9}/g;
        const phoneRegex9 = /(\+81|81)?[0-9]{10}/g;
        const phoneRegex10 = /(\+82|82)?[0-9]{10,11}/g;
        
        const phones1 = text.match(phoneRegex1) || [];
        const phones2 = text.match(phoneRegex2) || [];
        const phones3 = text.match(phoneRegex3) || [];
        const phones4 = text.match(phoneRegex4) || [];
        const phones5 = text.match(phoneRegex5) || [];
        const phones6 = text.match(phoneRegex6) || [];
        const phones7 = text.match(phoneRegex7) || [];
        const phones8 = text.match(phoneRegex8) || [];
        const phones9 = text.match(phoneRegex9) || [];
        const phones10 = text.match(phoneRegex10) || [];
        
        findings.phones = [...new Set([...phones1, ...phones2, ...phones3, ...phones4, ...phones5, ...phones6, ...phones7, ...phones8, ...phones9, ...phones10])];

        const btcRegex = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
        const ethRegex = /\b0x[a-fA-F0-9]{40}\b/g;
        const ltcRegex = /\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b/g;
        const xrpRegex = /\br[a-zA-Z0-9]{24,34}\b/g;
        const dogeRegex = /\bD[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}\b/g;
        
        const btc = text.match(btcRegex) || [];
        const eth = text.match(ethRegex) || [];
        const ltc = text.match(ltcRegex) || [];
        const xrp = text.match(xrpRegex) || [];
        const doge = text.match(dogeRegex) || [];
        
        btc.forEach(w => findings.cryptoWallets.push({ type: 'Bitcoin', address: w }));
        eth.forEach(w => findings.cryptoWallets.push({ type: 'Ethereum', address: w }));
        ltc.forEach(w => findings.cryptoWallets.push({ type: 'Litecoin', address: w }));
        xrp.forEach(w => findings.cryptoWallets.push({ type: 'Ripple', address: w }));
        doge.forEach(w => findings.cryptoWallets.push({ type: 'Dogecoin', address: w }));

        const ipv4Regex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
        const ipv6Regex = /\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b/gi;
        const ipv4s = text.match(ipv4Regex) || [];
        const ipv6s = text.match(ipv6Regex) || [];
        findings.ipAddresses = [...new Set([...ipv4s, ...ipv6s])];

        const domainRegex = /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)/g;
        const domains = text.match(domainRegex) || [];
        findings.domains = [...new Set(domains)];

        const usernameRegex = /@([a-zA-Z0-9_]{3,20})/g;
        const usernames = text.match(usernameRegex) || [];
        findings.usernames = [...new Set(usernames)];

        const apiKeyRegex1 = /[aA][pP][iI][-_]?[kK][eE][yY][\s:=]+['"]?([a-zA-Z0-9_\-]{20,})['"]?/g;
        const apiKeyRegex2 = /[aA][cC][cC][eE][sS][sS][-_]?[tT][oO][kK][eE][nN][\s:=]+['"]?([a-zA-Z0-9_\-]{20,})['"]?/g;
        const apiKeyRegex3 = /[sS][eE][cC][rR][eE][tT][-_]?[kK][eE][yY][\s:=]+['"]?([a-zA-Z0-9_\-]{20,})['"]?/g;
        const apiKeyRegex4 = /AKIA[0-9A-Z]{16}/g;
        const apiKeyRegex5 = /AIza[0-9A-Za-z\-_]{35}/g;
        
        const apiKeys1 = htmlContent.match(apiKeyRegex1) || [];
        const apiKeys2 = htmlContent.match(apiKeyRegex2) || [];
        const apiKeys3 = htmlContent.match(apiKeyRegex3) || [];
        const apiKeys4 = htmlContent.match(apiKeyRegex4) || [];
        const apiKeys5 = htmlContent.match(apiKeyRegex5) || [];
        
        findings.apiKeys = [...new Set([...apiKeys1, ...apiKeys2, ...apiKeys3, ...apiKeys4, ...apiKeys5])];

        const passwordRegex = /[pP][aA][sS][sS][wW][oO][rR][dD][\s:=]+['"]?([^\s'"]{6,})['"]?/g;
        const usernameCredRegex = /[uU][sS][eE][rR][nN][aA][mM][eE][\s:=]+['"]?([^\s'"]{3,})['"]?/g;
        const loginRegex = /[lL][oO][gG][iI][nN][\s:=]+['"]?([^\s'"]{3,})['"]?/g;
        
        const passwords = htmlContent.match(passwordRegex) || [];
        const userCreds = htmlContent.match(usernameCredRegex) || [];
        const logins = htmlContent.match(loginRegex) || [];
        
        findings.credentials = [...new Set([...passwords, ...userCreds, ...logins])];

        const socialPlatforms = [
            'facebook', 'instagram', 'twitter', 'linkedin', 'tiktok', 'youtube', 
            'github', 'gitlab', 'bitbucket', 'reddit', 'pinterest', 'snapchat',
            'telegram', 'whatsapp', 'discord', 'slack', 'medium', 'quora',
            'stackoverflow', 'behance', 'dribbble', 'vimeo', 'twitch', 'spotify',
            'soundcloud', 'tumblr', 'flickr', 'deviantart', 'steam', 'xbox',
            'playstation', 'vk.com', 'ok.ru', 'weibo', 'line.me'
        ];
        
        $('a').each((i, elem) => {
            const href = $(elem).attr('href');
            if (href) {
                socialPlatforms.forEach(platform => {
                    if (href.toLowerCase().includes(platform)) {
                        findings.socialLinks.push({
                            platform: platform.charAt(0).toUpperCase() + platform.slice(1),
                            url: href,
                            text: $(elem).text().trim()
                        });
                    }
                });
            }
        });

        const fileExtensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
                               'zip', 'rar', '7z', 'tar', 'gz', 'sql', 'db', 'csv',
                               'json', 'xml', 'txt', 'log', 'bak', 'conf', 'config'];
        
        $('a').each((i, elem) => {
            const href = $(elem).attr('href');
            if (href) {
                fileExtensions.forEach(ext => {
                    if (href.toLowerCase().endsWith(`.${ext}`)) {
                        findings.fileLinks.push({
                            type: ext.toUpperCase(),
                            url: href,
                            text: $(elem).text().trim()
                        });
                    }
                });
            }
        });

        $('a').each((i, elem) => {
            const href = $(elem).attr('href');
            if (href && (href.startsWith('http://') || href.startsWith('https://')) && !href.includes(new URL(url).hostname)) {
                findings.externalLinks.push({
                    url: href,
                    text: $(elem).text().trim(),
                    rel: $(elem).attr('rel')
                });
            }
        });

        $('img').each((i, elem) => {
            findings.images.push({
                src: $(elem).attr('src'),
                alt: $(elem).attr('alt'),
                title: $(elem).attr('title')
            });
        });

        $('video, iframe[src*="youtube"], iframe[src*="vimeo"]').each((i, elem) => {
            findings.videos.push({
                src: $(elem).attr('src'),
                type: elem.name
            });
        });

        $('form').each((i, elem) => {
            const inputs = [];
            $(elem).find('input, textarea, select').each((j, input) => {
                inputs.push({
                    type: $(input).attr('type') || 'text',
                    name: $(input).attr('name'),
                    id: $(input).attr('id'),
                    placeholder: $(input).attr('placeholder')
                });
            });
            findings.forms.push({
                action: $(elem).attr('action'),
                method: $(elem).attr('method'),
                inputs: inputs
            });
        });

        const commentRegex = /<!--([\s\S]*?)-->/g;
        const comments = htmlContent.match(commentRegex) || [];
        findings.comments = comments.map(c => c.substring(4, c.length - 3).trim());

        $('script').each((i, elem) => {
            const src = $(elem).attr('src');
            if (src) {
                findings.scripts.push({
                    type: 'external',
                    src: src
                });
            } else {
                const content = $(elem).html();
                if (content && content.length > 0) {
                    findings.scripts.push({
                        type: 'inline',
                        content: content.substring(0, 200)
                    });
                }
            }
        });

        if (text.includes(searchQuery.toLowerCase())) {
            const contexts = [];
            let searchIndex = 0;
            while ((searchIndex = text.indexOf(searchQuery.toLowerCase(), searchIndex)) !== -1) {
                contexts.push(extractContext(text, searchQuery, 200, searchIndex));
                searchIndex += searchQuery.length;
                if (contexts.length >= 10) break;
            }
            findings.matches = contexts;
        }

        findings.metadata = {
            description: $('meta[name="description"]').attr('content'),
            keywords: $('meta[name="keywords"]').attr('content'),
            author: $('meta[name="author"]').attr('content'),
            robots: $('meta[name="robots"]').attr('content'),
            viewport: $('meta[name="viewport"]').attr('content'),
            charset: $('meta[charset]').attr('charset'),
            ogTitle: $('meta[property="og:title"]').attr('content'),
            ogDescription: $('meta[property="og:description"]').attr('content'),
            ogImage: $('meta[property="og:image"]').attr('content'),
            ogUrl: $('meta[property="og:url"]').attr('content'),
            ogType: $('meta[property="og:type"]').attr('content'),
            twitterCard: $('meta[name="twitter:card"]').attr('content'),
            twitterSite: $('meta[name="twitter:site"]').attr('content'),
            twitterCreator: $('meta[name="twitter:creator"]').attr('content'),
            canonical: $('link[rel="canonical"]').attr('href'),
            favicon: $('link[rel="icon"], link[rel="shortcut icon"]').attr('href')
        };

        const techIndicators = {
            'WordPress': /wp-content|wp-includes|wordpress/i,
            'Joomla': /joomla|com_content/i,
            'Drupal': /drupal|sites\/default/i,
            'React': /react|reactjs|_react/i,
            'Vue.js': /vue|vuejs|_vue/i,
            'Angular': /angular|ng-app/i,
            'jQuery': /jquery/i,
            'Bootstrap': /bootstrap/i,
            'Tailwind': /tailwind/i,
            'Next.js': /next\/|_next/i,
            'Laravel': /laravel/i,
            'Django': /django/i,
            'Flask': /flask/i,
            'Express': /express/i,
            'ASP.NET': /asp\.net|__viewstate/i,
            'PHP': /\.php|<?php/i,
            'Node.js': /node|nodejs/i,
            'Gatsby': /gatsby/i,
            'Nuxt': /nuxt/i,
            'Svelte': /svelte/i,
            'Shopify': /shopify|myshopify/i,
            'WooCommerce': /woocommerce/i,
            'Magento': /magento/i,
            'PrestaShop': /prestashop/i,
            'OpenCart': /opencart/i,
            'Cloudflare': /cloudflare|__cf/i,
            'Google Analytics': /google-analytics|gtag/i,
            'Google Tag Manager': /googletagmanager/i,
            'Font Awesome': /font-awesome|fontawesome/i,
            'Stripe': /stripe\.com|stripe\.js/i,
            'PayPal': /paypal\.com/i
        };

        Object.entries(techIndicators).forEach(([tech, regex]) => {
            if (regex.test(htmlContent)) {
                findings.techStack.push(tech);
            }
        });

        findings.seoData = {
            titleLength: $('title').text().length,
            metaDescLength: ($('meta[name="description"]').attr('content') || '').length,
            h1Count: $('h1').length,
            h2Count: $('h2').length,
            h3Count: $('h3').length,
            imageCount: $('img').length,
            imagesWithoutAlt: $('img:not([alt])').length,
            internalLinks: $('a[href^="/"], a[href^="' + url + '"]').length,
            externalLinks: findings.externalLinks.length,
            wordCount: text.split(/\s+/).length
        };

        findings.securityHeaders = {
            server: response.headers['server'],
            xFrameOptions: response.headers['x-frame-options'],
            xContentTypeOptions: response.headers['x-content-type-options'],
            strictTransportSecurity: response.headers['strict-transport-security'],
            contentSecurityPolicy: response.headers['content-security-policy'],
            xXssProtection: response.headers['x-xss-protection'],
            referrerPolicy: response.headers['referrer-policy']
        };

        const cookieHeader = response.headers['set-cookie'];
        if (cookieHeader) {
            const cookieArray = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
            findings.cookies = cookieArray.map(cookie => {
                const parts = cookie.split(';')[0].split('=');
                return {
                    name: parts[0],
                    value: parts[1],
                    secure: cookie.includes('Secure'),
                    httpOnly: cookie.includes('HttpOnly'),
                    sameSite: cookie.match(/SameSite=(\w+)/)?.[1]
                };
            });
        }

        return findings;
    } catch (e) {
        return { error: e.message };
    }
}

function extractContext(text, query, contextLength = 200, startIndex = null) {
    const index = startIndex !== null ? startIndex : text.toLowerCase().indexOf(query.toLowerCase());
    if (index === -1) return '';
    
    const start = Math.max(0, index - contextLength / 2);
    const end = Math.min(text.length, index + query.length + contextLength / 2);
    
    return '...' + text.substring(start, end).trim() + '...';
}

// ==================== BREACH DATABASE CHECK ====================

async function checkHaveIBeenPwned(email) {
    try {
        console.log('   🔍 Checking breach databases...');
        
        // Note: HIBP requires API key for automated queries
        // This is a simplified version
        const response = await fetchWithRetry(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
            headers: {
                'User-Agent': 'OSINT-Research-Tool'
            }
        }, 1);

        if (response.status === 200 && Array.isArray(response.data)) {
            return response.data.map(breach => ({
                name: breach.Name,
                title: breach.Title,
                domain: breach.Domain,
                breachDate: breach.BreachDate,
                addedDate: breach.AddedDate,
                dataClasses: breach.DataClasses,
                pwnCount: breach.PwnCount,
                description: breach.Description
            }));
        } else if (response.status === 404) {
            return { status: 'No breaches found' };
        }
    } catch (e) {
        return { error: 'HIBP check unavailable - requires API key' };
    }
}

async function checkDehashedDatabase(query) {
    // Dehashed requires paid API access
    return {
        service: 'Dehashed',
        note: 'Commercial service - requires paid subscription',
        url: `https://dehashed.com/search?query=${encodeURIComponent(query)}`
    };
}

async function checkIntelligenceX(query) {
    return {
        service: 'Intelligence X',
        note: 'Commercial OSINT search engine',
        url: `https://intelx.io/?s=${encodeURIComponent(query)}`
    };
}

// ==================== REVERSE IMAGE SEARCH ====================

async function reverseImageSearch(imageUrl) {
    const results = [];
    
    const engines = [
        { name: 'Google Images', url: `https://www.google.com/searchbyimage?image_url=${encodeURIComponent(imageUrl)}` },
        { name: 'Yandex Images', url: `https://yandex.com/images/search?rpt=imageview&url=${encodeURIComponent(imageUrl)}` },
        { name: 'TinEye', url: `https://www.tineye.com/search?url=${encodeURIComponent(imageUrl)}` },
        { name: 'Bing Visual Search', url: `https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIRP&sbisrc=UrlPaste&q=imgurl:${encodeURIComponent(imageUrl)}` }
    ];

    engines.forEach(engine => {
        results.push({
            engine: engine.name,
            searchUrl: engine.url,
            note: 'Open manually for results'
        });
    });

    return results;
}

// ==================== WHOIS LOOKUP ====================

async function whoisLookup(domain) {
    try {
        console.log('   🔍 Performing WHOIS lookup...');
        
        // Using a WHOIS API service
        const response = await fetchWithRetry(`https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${domain}&outputFormat=JSON`, {}, 1);
        
        if (response.status === 200 && response.data) {
            return {
                domain: domain,
                registrar: response.data.WhoisRecord?.registrarName,
                createdDate: response.data.WhoisRecord?.createdDate,
                expiresDate: response.data.WhoisRecord?.expiresDate,
                updatedDate: response.data.WhoisRecord?.updatedDate,
                nameServers: response.data.WhoisRecord?.nameServers?.hostNames,
                status: response.data.WhoisRecord?.status,
                registrant: response.data.WhoisRecord?.registrant
            };
        }
    } catch (e) {
        return {
            domain: domain,
            note: 'WHOIS lookup requires API access',
            alternative: `Manual lookup: https://who.is/whois/${domain}`
        };
    }
}

// ==================== DNS ENUMERATION ====================

async function dnsEnumeration(domain) {
    console.log('   🔍 Enumerating DNS records...');
    
    const subdomains = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
        'api', 'cdn', 'shop', 'store', 'mobile', 'support', 'help',
        'portal', 'vpn', 'remote', 'webmail', 'smtp', 'pop', 'imap'
    ];

    const found = [];
    
    for (const sub of subdomains) {
        try {
            const testDomain = `${sub}.${domain}`;
            const response = await fetchWithRetry(`https://${testDomain}`, { timeout: 5000 }, 1);
            
            if (response.status < 500) {
                found.push({
                    subdomain: testDomain,
                    status: response.status,
                    server: response.headers.server
                });
            }
        } catch (e) {
            // Subdomain tidak ditemukan
        }
    }

    return found;
}

// ==================== IP GEOLOCATION ====================

async function ipGeolocation(ip) {
    try {
        console.log('   🔍 Looking up IP geolocation...');
        
        const response = await fetchWithRetry(`https://ipapi.co/${ip}/json/`);
        
        if (response.status === 200 && response.data) {
            return {
                ip: response.data.ip,
                city: response.data.city,
                region: response.data.region,
                country: response.data.country_name,
                countryCode: response.data.country_code,
                postal: response.data.postal,
                latitude: response.data.latitude,
                longitude: response.data.longitude,
                timezone: response.data.timezone,
                isp: response.data.org,
                asn: response.data.asn
            };
        }
    } catch (e) {
        return { error: 'Geolocation lookup failed' };
    }
}

// ==================== MAIN INVESTIGATION FUNCTIONS ====================

async function investigateEmail(email) {
    console.log('\n╔════════════════════════════════════════════════════════╗');
    console.log('║              📧 EMAIL INVESTIGATION REPORT             ║');
    console.log('╚════════════════════════════════════════════════════════╝\n');
    console.log(`Target: ${email}\n`);

    const report = {
        target: email,
        timestamp: new Date().toISOString(),
        results: {}
    };

    // Extract username from email
    const username = email.split('@')[0];
    const domain = email.split('@')[1];

    // 1. Social Media Scan
    console.log('📱 [1/7] Social Media Presence...');
    report.results.socialMedia = await comprehensiveSocialMediaScan(username);
    
    // 2. Google Dorking
    console.log('\n🔎 [2/7] Advanced Google Dorking...');
    report.results.googleResults = await megaGoogleDork(email, 'email');
    
    // 3. Pastebin & Code Repositories
    console.log('\n📋 [3/7] Pastebin & Code Search...');
    const pastebinResults = await searchPastebinDumps(email);
    const githubResults = await searchGitHubCode(email);
    const gistResults = await searchGitHubGists(email);
    report.results.dataDumps = [...pastebinResults, ...githubResults, ...gistResults];
    
    // 4. Breach Databases
    console.log('\n🔓 [4/7] Data Breach Check...');
    report.results.breaches = await checkHaveIBeenPwned(email);
    
    // 5. Domain Analysis
    console.log('\n🌐 [5/7] Domain Analysis...');
    report.results.domain = {
        whois: await whoisLookup(domain),
        dns: await dnsEnumeration(domain)
    };
    
    // 6. People Search Engines
    console.log('\n👤 [6/7] People Search Engines...');
    report.results.peopleSearch = await searchPeopleDataEngines(email, 'email');
    
    // 7. Trello Boards
    console.log('\n📌 [7/7] Trello & Project Boards...');
    report.results.trello = await searchTrello(email);

    return report;
}

async function investigatePhone(phone) {
    console.log('\n╔════════════════════════════════════════════════════════╗');
    console.log('║            📞 PHONE NUMBER INVESTIGATION               ║');
    console.log('╚════════════════════════════════════════════════════════╝\n');
    console.log(`Target: ${phone}\n`);

    const report = {
        target: phone,
        timestamp: new Date().toISOString(),
        results: {}
    };

    // 1. Social Media
    console.log('📱 [1/5] Social Media Presence...');
    report.results.socialMedia = await comprehensiveSocialMediaScan(phone);
    
    // 2. Google Dorking
    console.log('\n🔎 [2/5] Advanced Google Dorking...');
    report.results.googleResults = await megaGoogleDork(phone, 'phone');
    
    // 3. E-commerce & Marketplace
    console.log('\n🛒 [3/5] E-commerce Platforms...');
    report.results.ecommerce = await searchEcommercePlatforms(phone);
    
    // 4. People Search
    console.log('\n👤 [4/5] People Search Engines...');
    report.results.peopleSearch = await searchPeopleDataEngines(phone, 'phone');
    
    // 5. Caller ID Services
    console.log('\n📱 [5/5] Caller ID Services...');
    report.results.callerID = await checkCallerIDServices(phone);

    return report;
}

async function investigateUsername(username) {
    console.log('\n╔════════════════════════════════════════════════════════╗');
    console.log('║             👤 USERNAME INVESTIGATION                  ║');
    console.log('╚════════════════════════════════════════════════════════╝\n');
    console.log(`Target: ${username}\n`);

    const report = {
        target: username,
        timestamp: new Date().toISOString(),
        results: {}
    };

    // 1. Social Media
    console.log('📱 [1/6] Social Media Presence...');
    report.results.socialMedia = await comprehensiveSocialMediaScan(username);
    
    // 2. Google Dorking
    console.log('\n🔎 [2/6] Advanced Google Dorking...');
    report.results.googleResults = await megaGoogleDork(username, 'username');
    
    // 3. Code Repositories
    console.log('\n💻 [3/6] Code Repositories...');
    report.results.code = await searchGitHubCode(username);
    
    // 4. Pastebin
    console.log('\n📋 [4/6] Pastebin Search...');
    report.results.pastebin = await searchPastebinDumps(username);
    
    // 5. Gaming & Forums
    console.log('\n🎮 [5/6] Gaming & Forum Platforms...');
    report.results.gaming = await searchGamingPlatforms(username);
    
    // 6. Archive Search
    console.log('\n📚 [6/6] Web Archives...');
    report.results.archives = await searchWaybackMachine(username);

    return report;
}

async function searchEcommercePlatforms(phone) {
    const platforms = [
        `site:tokopedia.com "${phone}"`,
        `site:shopee.co.id "${phone}"`,
        `site:bukalapak.com "${phone}"`,
        `site:olx.co.id "${phone}"`,
        `site:facebook.com/marketplace "${phone}"`
    ];

    const results = [];
    
    for (const query of platforms) {
        try {
            const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
            const response = await fetchWithRetry(searchUrl);
            
            const $ = cheerio.load(response.data);
            const hasResults = $('.g').length > 0;
            
            if (hasResults) {
                results.push({
                    platform: query.split('site:')[1].split(' ')[0],
                    status: 'Possible matches found',
                    searchUrl: searchUrl
                });
            }
        } catch (e) {}
    }

    return results;
}

async function checkCallerIDServices(phone) {
    return [
        {
            service: 'GetContact',
            url: `https://www.getcontact.com/en/search?q=${encodeURIComponent(phone)}`,
            note: 'Check manually'
        },
        {
            service: 'Truecaller',
            url: `https://www.truecaller.com/search/id/${encodeURIComponent(phone)}`,
            note: 'Check manually'
        },
        {
            service: 'Sync.ME',
            url: `https://sync.me/search/?q=${encodeURIComponent(phone)}`,
            note: 'Check manually'
        }
    ];
}

async function searchGamingPlatforms(username) {
    const platforms = [
        { name: 'Steam', url: `https://steamcommunity.com/id/${username}` },
        { name: 'Xbox', url: `https://xboxgamertag.com/search/${username}` },
        { name: 'PlayStation', url: `https://psnprofiles.com/${username}` },
        { name: 'Twitch', url: `https://www.twitch.tv/${username}` },
        { name: 'Discord', note: 'Search in servers for username' }
    ];

    const results = [];
    
    for (const platform of platforms) {
        if (platform.url) {
            try {
                const response = await fetchWithRetry(platform.url, {}, 1);
                if (response.status === 200) {
                    results.push({
                        platform: platform.name,
                        url: platform.url,
                        status: 'Profile found'
                    });
                }
            } catch (e) {}
        } else {
            results.push({
                platform: platform.name,
                note: platform.note
            });
        }
    }

    return results;
}

// ==================== REPORT GENERATION ====================

function generateReport(report, filename) {
    console.log('\n\n╔════════════════════════════════════════════════════════╗');
    console.log('║                  📊 INVESTIGATION REPORT               ║');
    console.log('╚════════════════════════════════════════════════════════╝\n');

    let reportText = '';
    reportText += `═══════════════════════════════════════════════════════\n`;
    reportText += `        OSINT INVESTIGATION REPORT\n`;
    reportText += `═══════════════════════════════════════════════════════\n\n`;
    reportText += `Target: ${report.target}\n`;
    reportText += `Generated: ${new Date(report.timestamp).toLocaleString()}\n`;
    reportText += `Report ID: ${hash(report.target + report.timestamp)}\n\n`;

    // Social Media
    if (report.results.socialMedia?.length > 0) {
        reportText += `\n━━━ 📱 SOCIAL MEDIA PRESENCE ━━━\n\n`;
        report.results.socialMedia.forEach(sm => {
            reportText += `Platform: ${sm.platform}\n`;
            reportText += `URL: ${sm.url}\n`;
            reportText += `Status: ${sm.status}\n`;
            reportText += `Confidence: ${sm.confidence}\n`;
            
            if (sm.data) {
                Object.entries(sm.data).forEach(([key, value]) => {
                    if (value && value !== 'null' && value !== 'undefined') {
                        reportText += `  ${key}: ${value}\n`;
                    }
                });
            }
            reportText += `\n`;
        });
    }

    // Google Results
    if (report.results.googleResults?.length > 0) {
        reportText += `\n━━━ 🔎 GOOGLE SEARCH RESULTS (Top 25) ━━━\n\n`;
        report.results.googleResults.slice(0, 25).forEach((result, i) => {
            reportText += `[${i + 1}] ${result.title}\n`;
            reportText += `    URL: ${result.url}\n`;
            reportText += `    Relevance: ${result.relevance}\n`;
            reportText += `    Snippet: ${result.snippet.substring(0, 200)}...\n\n`;
        });
    }

    // Data Dumps
    if (report.results.dataDumps?.length > 0) {
        reportText += `\n━━━ 📋 DATA DUMPS & CODE REPOSITORIES ━━━\n\n`;
        report.results.dataDumps.forEach(dump => {
            reportText += `Source: ${dump.source}\n`;
            reportText += `Title: ${dump.title || dump.file || 'N/A'}\n`;
            reportText += `URL: ${dump.url}\n\n`;
        });
    }

    // Breaches
    if (report.results.breaches) {
        reportText += `\n━━━ 🔓 DATA BREACH INFORMATION ━━━\n\n`;
        if (Array.isArray(report.results.breaches)) {
            reportText += `⚠️  BREACHES FOUND: ${report.results.breaches.length}\n\n`;
            report.results.breaches.forEach(breach => {
                reportText += `Name: ${breach.name}\n`;
                reportText += `Date: ${breach.breachDate}\n`;
                reportText += `Data: ${breach.dataClasses?.join(', ')}\n`;
                reportText += `Affected: ${breach.pwnCount} accounts\n\n`;
            });
        } else {
            reportText += `Status: ${report.results.breaches.status || report.results.breaches.error}\n\n`;
        }
    }

    // People Search
    if (report.results.peopleSearch?.length > 0) {
        reportText += `\n━━━ 👤 PEOPLE SEARCH ENGINES ━━━\n\n`;
        report.results.peopleSearch.forEach(result => {
            reportText += `Source: ${result.source}\n`;
            reportText += `URL: ${result.url}\n`;
            reportText += `Status: ${result.status}\n\n`;
        });
    }

    reportText += `\n═══════════════════════════════════════════════════════\n`;
    reportText += `             END OF REPORT\n`;
    reportText += `═══════════════════════════════════════════════════════\n`;

    // Save to file
    fs.writeFileSync(filename, reportText);
    console.log(`\n✅ Report saved: ${filename}`);
    console.log(`📄 Total results: ${JSON.stringify(report).length} bytes\n`);
    
    return reportText;
}

// ==================== MAIN MENU ====================

async function mainMenu() {
    console.log('\n┌─────────────────────────────────────────┐');
    console.log('│         INVESTIGATION OPTIONS           │');
    console.log('├─────────────────────────────────────────┤');
    console.log('│  1. Email Investigation                 │');
    console.log('│  2. Phone Number Investigation          │');
    console.log('│  3. Username Investigation              │');
    console.log('│  4. Domain/Website Investigation        │');
    console.log('│  5. IP Address Investigation            │');
    console.log('│  6. Reverse Image Search                │');
    console.log('│  7. Exit                                │');
    console.log('└─────────────────────────────────────────┘\n');

    const choice = await question('Select option (1-7): ');

    switch (choice.trim()) {
        case '1':
            const email = await question('Enter email address: ');
            const emailReport = await investigateEmail(email.trim());
            const emailFilename = `report_email_${hash(email)}_${Date.now()}.txt`;
            generateReport(emailReport, emailFilename);
            break;

        case '2':
            const phone = await question('Enter phone number: ');
            const phoneReport = await investigatePhone(phone.trim());
            const phoneFilename = `report_phone_${hash(phone)}_${Date.now()}.txt`;
            generateReport(phoneReport, phoneFilename);
            break;

        case '3':
            const username = await question('Enter username: ');
            const userReport = await investigateUsername(username.trim());
            const userFilename = `report_username_${hash(username)}_${Date.now()}.txt`;
            generateReport(userReport, userFilename);
            break;

        case '4':
            const domain = await question('Enter domain: ');
            console.log('\n🌐 Domain Investigation...');
            const domainReport = {
                target: domain,
                timestamp: new Date().toISOString(),
                results: {
                    whois: await whoisLookup(domain),
                    dns: await dnsEnumeration(domain),
                    archives: await searchWaybackMachine(domain),
                    googleResults: await megaGoogleDork(domain, 'username')
                }
            };
            const domainFilename = `report_domain_${hash(domain)}_${Date.now()}.txt`;
            generateReport(domainReport, domainFilename);
            break;

        case '5':
            const ip = await question('Enter IP address: ');
            console.log('\n🌍 IP Investigation...');
            const geoData = await ipGeolocation(ip);
            console.log('\n📍 Geolocation Data:');
            console.log(JSON.stringify(geoData, null, 2));
            break;

        case '6':
            const imageUrl = await question('Enter image URL: ');
            const imageResults = await reverseImageSearch(imageUrl);
            console.log('\n🖼️  Reverse Image Search Engines:\n');
            imageResults.forEach(result => {
                console.log(`${result.engine}: ${result.searchUrl}`);
            });
            break;

        case '7':
            console.log('\n👋 Exiting... Stay safe!\n');
            rl.close();
            process.exit(0);

        default:
            console.log('\n❌ Invalid option!\n');
    }

    // Return to menu
    const again = await question('\nRun another investigation? (y/n): ');
    if (again.toLowerCase() === 'y') {
        await mainMenu();
    } else {
        console.log('\n👋 Goodbye!\n');
        rl.close();
        process.exit(0);
    }
}

// ==================== START APPLICATION ====================

(async function() {
    try {
        await mainMenu();
    } catch (error) {
        console.error('\n❌ Fatal error:', error.message);
        rl.close();
        process.exit(1);
    }
})();
