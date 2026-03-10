/**
 * routes/reputation.js
 * GET /api/reputation/:domain - Returns domain age and popularity data
 */

// Simple in-memory cache (domain -> { data, timestamp })
const cache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export default function reputationRoute(app) {
    app.get('/api/reputation/:domain', async (req, res) => {
        const domain = req.params.domain.toLowerCase().replace('www.', '');

        if (!domain || domain.length < 3) {
            return res.status(400).json({ error: 'Invalid domain' });
        }

        // Check cache
        const cached = cache.get(domain);
        if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
            return res.json(cached.data);
        }

        console.log(`[Reputation] Looking up: ${domain}`);

        const result = {
            domain,
            domainAgeDays: null,
            trancoRank: null,
            createdDate: null
        };

        // WHOIS lookup via free API
        try {
            const whoisRes = await fetch(`https://api.api-ninjas.com/v1/whois?domain=${encodeURIComponent(domain)}`, {
                headers: { 'X-Api-Key': process.env.NINJAS_API_KEY || '' }
            });
            if (whoisRes.ok) {
                const whois = await whoisRes.json();
                if (whois.creation_date) {
                    const created = new Date(whois.creation_date * 1000);
                    result.domainAgeDays = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
                    result.createdDate = created.toISOString().split('T')[0];
                }
            }
        } catch (e) {
            console.error('[Reputation] WHOIS lookup failed:', e.message);
        }

        // Cache and return
        cache.set(domain, { data: result, timestamp: Date.now() });
        res.json(result);
    });
}
