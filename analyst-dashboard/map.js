/**
 * map.js — Leaflet.js GeoTrace Map Module
 * 
 * Renders the hop-by-hop email relay path on an interactive world map.
 * Features:
 *   - Dark tile layer (CartoDB Dark Matter)
 *   - Animated polyline between hops
 *   - Custom color-coded markers (red=origin, orange=relay, green=destination)
 *   - Popup windows with IP, location, ASN details
 *   - Auto-zoom to fit all hops
 */

// ═══════════════════════════════════════════════
//  Map Instance
// ═══════════════════════════════════════════════

let geoMap = null;
let mapLayers = [];

/**
 * Initialize the Leaflet map.
 */
function initMap() {
    if (geoMap) {
        geoMap.invalidateSize();
        return;
    }

    const mapEl = document.getElementById('geo-map');
    if (!mapEl) return;

    geoMap = L.map('geo-map', {
        center: [20, 0],
        zoom: 2,
        zoomControl: true,
        attributionControl: false,
        minZoom: 2,
        maxZoom: 14,
    });

    // Dark tile layer (Supports CARTO API key via window.CARTO_API_KEY or default tile URL)
    const cartoKey = (typeof window !== 'undefined' && window.CARTO_API_KEY) ? window.CARTO_API_KEY : '';
    const tileUrl = cartoKey ? `https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png?key=${cartoKey}` : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';

    L.tileLayer(tileUrl, {
        subdomains: 'abcd',
        maxZoom: 19,
    }).addTo(geoMap);

    // Attribution
    L.control.attribution({ position: 'bottomright' })
        .addAttribution('© <a href="https://carto.com/">CARTO</a>')
        .addTo(geoMap);
}


/**
 * Clear all existing markers and paths from the map.
 */
function clearMap() {
    mapLayers.forEach(layer => {
        if (geoMap) geoMap.removeLayer(layer);
    });
    mapLayers = [];
}


/**
 * Render hop path on the map.
 * @param {Array} hopPath - Array of hop objects from geo_tracer
 */
function renderHopPath(hopPath) {
    if (!geoMap) initMap();
    clearMap();

    if (!hopPath || hopPath.length === 0) return;

    const coordinates = [];

    // Add markers for each hop
    hopPath.forEach((hop, index) => {
        const lat = hop.latitude;
        const lng = hop.longitude;

        if (lat == null || lng == null) return;

        coordinates.push([lat, lng]);

        // Determine marker color and size
        let color, size, zIndex;
        if (hop.role === 'origin') {
            color = '#ef4444';
            size = 14;
            zIndex = 1000;
        } else if (hop.role === 'destination') {
            color = '#22c55e';
            size = 14;
            zIndex = 999;
        } else {
            color = '#f97316';
            size = 10;
            zIndex = 500;
        }

        // Create custom circular marker
        const marker = L.circleMarker([lat, lng], {
            radius: size,
            fillColor: color,
            fillOpacity: 0.9,
            color: '#fff',
            weight: 2,
            opacity: 0.8,
        });

        // Popup content
        const popupContent = `
            <div style="font-family: 'Inter', sans-serif; min-width: 200px; color: #1a202c;">
                <div style="font-weight: 700; font-size: 14px; margin-bottom: 8px; color: ${color};">
                    Hop ${hop.hop_index} — ${hop.role ? hop.role.charAt(0).toUpperCase() + hop.role.slice(1) : 'Relay'}
                </div>
                <div style="display: grid; gap: 4px; font-size: 12px;">
                    <div><strong>IP:</strong> <code>${hop.ip || 'N/A'}</code></div>
                    <div><strong>Location:</strong> ${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}</div>
                    <div><strong>ISP/Org:</strong> ${hop.org || 'Unknown'}</div>
                    <div><strong>ASN:</strong> ${hop.asn || 'N/A'}</div>
                    ${hop.is_tor ? '<div style="color: #ef4444; font-weight: 600;">⚠️ Tor Exit Node</div>' : ''}
                    ${hop.is_vpn ? '<div style="color: #f97316; font-weight: 600;">🔒 VPN/Proxy</div>' : ''}
                    ${hop.is_datacenter ? '<div style="color: #3b82f6;">☁️ Datacenter</div>' : ''}
                </div>
            </div>
        `;

        marker.bindPopup(popupContent, {
            className: 'custom-popup',
            maxWidth: 280,
        });

        marker.addTo(geoMap);
        mapLayers.push(marker);

        // Add pulse animation for origin
        if (hop.role === 'origin') {
            const pulse = L.circleMarker([lat, lng], {
                radius: 20,
                fillColor: color,
                fillOpacity: 0.2,
                color: color,
                weight: 1,
                opacity: 0.4,
            });
            pulse.addTo(geoMap);
            mapLayers.push(pulse);
        }
    });

    // Draw animated polyline connecting hops
    if (coordinates.length >= 2) {
        // Background line (thicker, semi-transparent)
        const bgLine = L.polyline(coordinates, {
            color: 'rgba(129, 140, 248, 0.2)',
            weight: 6,
            opacity: 1,
            smoothFactor: 1.5,
        });
        bgLine.addTo(geoMap);
        mapLayers.push(bgLine);

        // Foreground animated line
        const fgLine = L.polyline(coordinates, {
            color: '#818cf8',
            weight: 2.5,
            opacity: 0.9,
            dashArray: '8, 12',
            smoothFactor: 1.5,
        });
        fgLine.addTo(geoMap);
        mapLayers.push(fgLine);

        // Animate dash offset
        let offset = 0;
        const lineEl = fgLine.getElement();
        if (lineEl) {
            setInterval(() => {
                offset -= 1;
                lineEl.style.strokeDashoffset = offset;
            }, 50);
        }
    }

    // Auto-fit bounds
    if (coordinates.length > 0) {
        const bounds = L.latLngBounds(coordinates);
        geoMap.fitBounds(bounds, { padding: [60, 60], maxZoom: 6 });
    }
}


/**
 * Render the hop list in the map sidebar.
 * @param {Array} hopPath - Array of hop objects
 */
function renderHopList(hopPath) {
    const container = document.getElementById('hop-list');
    if (!container) return;

    if (!hopPath || hopPath.length === 0) {
        container.innerHTML = '<p class="empty-state">No geographic data available</p>';
        return;
    }

    container.innerHTML = hopPath.map(hop => {
        const markerClass = hop.role === 'origin' ? 'origin' : hop.role === 'destination' ? 'destination' : 'relay';

        let tags = '';
        if (hop.is_tor) tags += '<span class="hop-tag tor">TOR</span>';
        if (hop.is_vpn) tags += '<span class="hop-tag vpn">VPN</span>';
        if (hop.is_datacenter) tags += '<span class="hop-tag dc">DC</span>';

        return `
            <div class="hop-item">
                <div class="hop-marker ${markerClass}"></div>
                <div class="hop-info">
                    <div class="hop-ip">${hop.ip || 'Unknown'}</div>
                    <div class="hop-location">${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}</div>
                    <div class="hop-org">${hop.org || 'Unknown Organization'}</div>
                    ${tags ? `<div class="hop-tags">${tags}</div>` : ''}
                </div>
            </div>
        `;
    }).join('');
}
