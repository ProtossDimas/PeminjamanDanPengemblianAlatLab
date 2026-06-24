// ╔══════════════════════════════════════════════════════════════╗
// ║  LABORATORIUM POLBAN — Cloudflare Pages Functions Backend     ║
// ║  Pengganti Google Apps Script. Database TETAP Google Sheets   ║
// ║  + Google Drive, diakses lewat Service Account (REST API).    ║
// ╚══════════════════════════════════════════════════════════════╝
//
// ENV VARS yang wajib di-set di Cloudflare Pages (Settings → Environment Variables):
//   GOOGLE_SERVICE_ACCOUNT_EMAIL     → email service account (xxx@xxx.iam.gserviceaccount.com)
//   GOOGLE_PRIVATE_KEY      → private key PEM dari JSON key service account
//                             (boleh disalin apa adanya, termasuk \n di dalamnya)
//   GOOGLE_SHEET_ID          → ID spreadsheet (sama seperti GOOGLE_SHEET_ID lama)
//   SUPER_ADMIN_USERNAME    → username super-admin
//   SUPER_ADMIN_PASSWORD    → password super-admin
//
//   --- Khusus upload Drive (akun Gmail pribadi, BUKAN service account) ---
//   GOOGLE_DRIVE_FOLDER_ID       → ID folder Drive (milik akun Gmail pribadi) untuk attachment
//   GOOGLE_OAUTH_CLIENT_ID       → OAuth Client ID dari Google Cloud Console
//   GOOGLE_OAUTH_CLIENT_SECRET   → OAuth Client Secret
//   GOOGLE_OAUTH_REFRESH_TOKEN   → refresh token hasil consent akun Gmail pribadi (sekali saja)
//
// SETUP GOOGLE (sekali saja):
//   1. Buat Service Account di Google Cloud Console (Project apa saja) — untuk Sheets.
//   2. Buat & download JSON key-nya. Share Spreadsheet ke email service account, akses "Editor".
//   3. Salin client_email & private_key dari JSON ke environment variable di atas.
//
//   4. Untuk Drive: Service Account TIDAK punya kuota storage (akun Gmail biasa tidak
//      mendukung Shared Drive), jadi upload file harus pakai OAuth atas nama akun Gmail asli:
//      a. Google Cloud Console → APIs & Services → Credentials → Create Credentials
//         → OAuth client ID → Application type: Web application
//         → Authorized redirect URI: https://developers.google.com/oauthplayground
//      b. Buka https://developers.google.com/oauthplayground → klik ikon gear (kanan atas)
//         → centang "Use your own OAuth credentials" → isi Client ID & Client Secret dari (a)
//      c. Di kiri, pilih/isi scope: https://www.googleapis.com/auth/drive.file
//         → Authorize APIs → login & izinkan dengan akun Gmail pribadi pemilik folder
//      d. Klik "Exchange authorization code for tokens" → copy "Refresh token"
//      e. Simpan Client ID, Client Secret, Refresh token ke 3 env var GOOGLE_OAUTH_* di atas
//      f. GOOGLE_DRIVE_FOLDER_ID = ID folder di My Drive akun Gmail itu (folder TIDAK perlu
//         di-share ke service account lagi, karena yang upload sekarang akun Gmail itu sendiri)

const HEADER_ROW = 3;
const DATA_ROW   = 5;
const SHEET_INVENTORY = 'Inventory';
const SHEET_TRANSAKSI = 'Transaksi';
const SHEET_CONFIG    = 'Config';
const ADMIN_KEY_PREFIX = 'admin_account:';

// ──────────────────────────────────────────────────────────────
// ENTRY POINT
// ──────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  if (url.pathname.startsWith('/api/')) {
    return handleApi(request, env, url.pathname.slice('/api/'.length));
  }

  // Bukan route API → serahkan ke static asset (index.html, css, js, dll)
  return context.env.ASSETS.fetch(request);
}

async function handleApi(request, env, funcName) {
  if (request.method !== 'POST') {
    return jsonResponse({ success: false, message: 'Method not allowed' }, 405);
  }

  let body = {};
  try { body = await request.json(); } catch (e) { /* body kosong, biarkan {} */ }
  const args = Array.isArray(body.args) ? body.args : [];

  const handlers = {
    getInventory,
    pinjamAlat,
    kembalikanAlat,
    getTransaksi,
    addInventoryItem,
    verifyAdmin,
    getAdminAccounts,
    createAdminAccount,
    deleteAdminAccount,
    uploadAttachment,
  };

  const fn = handlers[funcName];
  if (!fn) {
    return jsonResponse({ success: false, message: 'Fungsi tidak dikenal: ' + funcName }, 404);
  }

  try {
    const result = await fn(env, ...args);
    return jsonResponse(result);
  } catch (e) {
    return jsonResponse({ success: false, message: 'Error: ' + e.toString() }, 500);
  }
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

// ══════════════════════════════════════════════════════════════
// GOOGLE AUTH — Service Account JWT (RS256) via Web Crypto
// ══════════════════════════════════════════════════════════════
//
// PENTING: variabel biasa (let _cachedToken) TIDAK bisa diandalkan di
// Cloudflare Pages Functions, karena setiap isolate bisa di-cold-start ulang
// kapan saja (terutama saat traffic jarang/jeda antar klik admin) — begitu
// itu terjadi, variabel di memori hilang dan server harus exchange token
// ke Google lagi dari nol (1 request HTTP tambahan + RSA sign), yang
// membuat proses jadi lambat tanpa terlihat jelas sebabnya.
//
// Solusinya: simpan token di Cloudflare Cache API (`caches.default`).
// Cache ini hidup di level edge/colo, jadi tetap ada walau isolate
// JS-nya direstart, sehingga token benar-benar bisa dipakai ulang.
const GOOGLE_TOKEN_CACHE_KEY = 'https://internal-cache.local/google-sheets-token';
const GOOGLE_DRIVE_TOKEN_CACHE_KEY = 'https://internal-cache.local/google-drive-token';

async function getCachedToken(cacheKey) {
  try {
    const cache = caches.default;
    const hit = await cache.match(cacheKey);
    if (!hit) return null;
    const data = await hit.json();
    if (data.exp > Math.floor(Date.now() / 1000) + 30) return data.token;
    return null;
  } catch (e) {
    return null; // Cache API gagal/unavailable → fallback ke exchange token baru
  }
}

async function setCachedToken(cacheKey, token, expiresInSeconds) {
  try {
    const cache = caches.default;
    const exp = Math.floor(Date.now() / 1000) + expiresInSeconds;
    const body = JSON.stringify({ token, exp });
    const maxAge = Math.max(30, expiresInSeconds - 30);
    await cache.put(cacheKey, new Response(body, {
      headers: { 'Cache-Control': `max-age=${maxAge}`, 'Content-Type': 'application/json' },
    }));
  } catch (e) { /* gagal cache bukan fatal, token tetap dipakai untuk request ini */ }
}

async function getAccessToken(env) {
  const cached = await getCachedToken(GOOGLE_TOKEN_CACHE_KEY);
  if (cached) return cached;

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  };

  const unsigned = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(claim));
  const signature = await signRS256(unsigned, env.GOOGLE_PRIVATE_KEY);
  const jwt = unsigned + '.' + signature;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:
      'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') +
      '&assertion=' + jwt,
  });
  const data = await res.json();
  if (!data.access_token) {
    throw new Error('Gagal otentikasi Google: ' + JSON.stringify(data));
  }

  await setCachedToken(GOOGLE_TOKEN_CACHE_KEY, data.access_token, data.expires_in || 3600);
  return data.access_token;
}

// ══════════════════════════════════════════════════════════════
// GOOGLE DRIVE AUTH — OAuth refresh token (akun Gmail pribadi)
// Dipisah dari getAccessToken() karena Service Account tidak punya
// kuota storage di Drive biasa (bukan Shared Drive).
// ══════════════════════════════════════════════════════════════
async function getDriveAccessToken(env) {
  const cached = await getCachedToken(GOOGLE_DRIVE_TOKEN_CACHE_KEY);
  if (cached) return cached;

  if (!env.GOOGLE_OAUTH_CLIENT_ID || !env.GOOGLE_OAUTH_CLIENT_SECRET || !env.GOOGLE_OAUTH_REFRESH_TOKEN) {
    throw new Error(
      'OAuth Drive belum dikonfigurasi. Set GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, ' +
      'dan GOOGLE_OAUTH_REFRESH_TOKEN di environment variable (lihat komentar setup di atas file ini).'
    );
  }

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:
      'client_id=' + encodeURIComponent(env.GOOGLE_OAUTH_CLIENT_ID) +
      '&client_secret=' + encodeURIComponent(env.GOOGLE_OAUTH_CLIENT_SECRET) +
      '&refresh_token=' + encodeURIComponent(env.GOOGLE_OAUTH_REFRESH_TOKEN) +
      '&grant_type=refresh_token',
  });
  const data = await res.json();
  if (!data.access_token) {
    throw new Error('Gagal refresh OAuth token Drive: ' + JSON.stringify(data));
  }

  await setCachedToken(GOOGLE_DRIVE_TOKEN_CACHE_KEY, data.access_token, data.expires_in || 3600);
  return data.access_token;
}

function base64url(input) {
  let str;
  if (typeof input === 'string') {
    str = btoa(unescape(encodeURIComponent(input)));
  } else {
    const bytes = new Uint8Array(input);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    str = btoa(bin);
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signRS256(data, pem) {
  const key = await importPrivateKey(pem);
  const enc = new TextEncoder().encode(data);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc);
  return base64url(sig);
}

async function importPrivateKey(pem) {
  const clean = String(pem)
    .replace(/\\n/g, '\n')
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return crypto.subtle.importKey(
    'pkcs8',
    bytes.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

// ══════════════════════════════════════════════════════════════
// GOOGLE SHEETS API HELPERS
// ══════════════════════════════════════════════════════════════
async function sheetsGetValues(env, token, range) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(range)}`;
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Sheets API error (get)');
  return data.values || [];
}

async function sheetsUpdateValues(env, token, range, values) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ range, values }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Sheets API error (update)');
  return data;
}

// Update banyak cell sekaligus dalam SATU request HTTP (jauh lebih cepat
// daripada memanggil sheetsUpdateValues() berkali-kali secara berurutan).
async function sheetsBatchUpdateValues(env, token, dataList) {
  // dataList: [{ range, values: [[...]] }, ...]
  if (!dataList.length) return null;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values:batchUpdate`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ valueInputOption: 'USER_ENTERED', data: dataList }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Sheets API error (batchUpdate)');
  return data;
}

async function sheetsAppendRow(env, token, sheetName, row) {
  const range = `${sheetName}!A:A`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: [row] }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Sheets API error (append)');
  return data;
}

async function getSheetId(env, token, sheetName) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}?fields=sheets.properties`;
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Sheets API error (get sheetId)');
  const sheet = (data.sheets || []).find(s => s.properties.title === sheetName);
  return sheet ? sheet.properties.sheetId : null;
}

async function deleteSheetRow(env, token, sheetName, rowIndex1based) {
  const sheetId = await getSheetId(env, token, sheetName);
  if (sheetId == null) throw new Error('Sheet tidak ditemukan: ' + sheetName);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}:batchUpdate`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      requests: [{
        deleteDimension: {
          range: { sheetId, dimension: 'ROWS', startIndex: rowIndex1based - 1, endIndex: rowIndex1based },
        },
      }],
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Sheets API error (delete row)');
  return data;
}

async function ensureConfigSheet(env, token) {
  const sheetId = await getSheetId(env, token, SHEET_CONFIG);
  if (sheetId == null) {
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}:batchUpdate`;
    await fetch(url, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests: [{ addSheet: { properties: { title: SHEET_CONFIG } } }] }),
    });
    await sheetsUpdateValues(env, token, `${SHEET_CONFIG}!A1:C1`, [['KEY', 'VALUE', 'CREATED_AT']]);
  }
}

// Baca sheet bertipe "Inventory/Transaksi": header di HEADER_ROW, data mulai DATA_ROW.
// __row disisipkan di setiap object = nomor baris asli di spreadsheet (untuk update/delete).
async function readSheetRows(env, token, sheetName) {
  const [headerVals, dataVals] = await Promise.all([
    sheetsGetValues(env, token, `${sheetName}!${HEADER_ROW}:${HEADER_ROW}`),
    sheetsGetValues(env, token, `${sheetName}!${DATA_ROW}:200000`),
  ]);
  const headers = headerVals[0] || [];

  const rows = dataVals
    .map((r, idx) => {
      const obj = {};
      headers.forEach((h, i) => { obj[h] = r[i] !== undefined ? r[i] : ''; });
      obj.__row = DATA_ROW + idx;
      return obj;
    })
    .filter(o => headers[0] && o[headers[0]] !== undefined && o[headers[0]] !== '');

  return { headers, rows };
}

// Baca sheet "Config": header di baris 1, data mulai baris 2.
async function readConfigRows(env, token) {
  const values = await sheetsGetValues(env, token, `${SHEET_CONFIG}!A1:C200000`);
  if (!values.length) return { headers: ['KEY', 'VALUE', 'CREATED_AT'], rows: [] };
  const headers = values[0];
  const rows = values.slice(1)
    .map((r, idx) => {
      const obj = {};
      headers.forEach((h, i) => { obj[h] = r[i] !== undefined ? r[i] : ''; });
      obj.__row = idx + 2;
      return obj;
    })
    .filter(o => o.KEY !== undefined && o.KEY !== '');
  return { headers, rows };
}

function colNumToLetter(n) {
  let s = '';
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

// PENTING: server (Cloudflare Workers) selalu berjalan di UTC. Jangan
// menggeser jam secara manual di sini — simpan UTC MURNI dalam format ISO
// (ada "Z" di akhir) supaya browser/HP siapa pun yang membuka aplikasi bisa
// otomatis menampilkannya sesuai timezone lokal masing-masing (WIB/WITA/WIT/
// atau timezone lain di luar negeri), lewat toLocaleString di frontend.
function formatDateTime(d) {
  return d.toISOString(); // contoh: 2026-06-24T03:01:00.000Z
}

function formatCompact(d) {
  const pad = n => String(n).padStart(2, '0');
  // Dipakai untuk ID transaksi (TRX-...) — tetap UTC, hanya untuk keunikan ID,
  // tidak ditampilkan sebagai "jam asli" ke user jadi tidak masalah.
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`;
}

// ══════════════════════════════════════════════════════════════
// INVENTORY — Ambil semua alat untuk dropdown
// ══════════════════════════════════════════════════════════════
async function getInventory(env) {
  try {
    const token = await getAccessToken(env);
    const { rows } = await readSheetRows(env, token, SHEET_INVENTORY);
    const data = rows.map(r => { const c = { ...r }; delete c.__row; return c; });
    return { success: true, data };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

// ══════════════════════════════════════════════════════════════
// PEMINJAMAN — Kurangi stok & catat transaksi
// ══════════════════════════════════════════════════════════════
async function pinjamAlat(env, data) {
  try {
    const token = await getAccessToken(env);
    const { headers, rows } = await readSheetRows(env, token, SHEET_INVENTORY);
    const idxStok = headers.indexOf('Stok Tersedia');
    if (headers.indexOf('ID Alat') < 0 || idxStok < 0) {
      return { success: false, message: 'Kolom "ID Alat" atau "Stok Tersedia" tidak ditemukan di header.' };
    }

    const item = rows.find(r => String(r['ID Alat']).trim() === String(data.id_alat).trim());
    if (!item) {
      return { success: false, message: 'ID Alat "' + data.id_alat + '" tidak ditemukan di Inventory.' };
    }

    const stok = Number(item['Stok Tersedia'] || 0);
    if (Number(data.jumlah) > stok) {
      return { success: false, message: 'Stok tidak cukup. Stok tersedia: ' + stok + ' unit.' };
    }

    const colLetter = colNumToLetter(idxStok + 1);
    await sheetsUpdateValues(env, token, `${SHEET_INVENTORY}!${colLetter}${item.__row}`, [[stok - Number(data.jumlah)]]);

    const now = new Date();
    const idTrans = 'TRX-' + formatCompact(now);

    const row = [
      idTrans,
      data.id_alat,
      data.nama_alat,
      data.nama_peminjam,
      data.nim_nip,
      data.prodi_instansi || '',
      data.no_hp,
      Number(data.jumlah),
      formatDateTime(now),
      data.tanggal_kembali,
      '',
      'Dipinjam',
      data.keperluan || '',
      '',
      '',
      '',
      data.attachment_url || '',
    ];
    await sheetsAppendRow(env, token, SHEET_TRANSAKSI, row);

    return { success: true, message: 'Peminjaman berhasil!', id_transaksi: idTrans };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

// ══════════════════════════════════════════════════════════════
// PENGEMBALIAN — Update transaksi & kembalikan stok
// ══════════════════════════════════════════════════════════════
async function kembalikanAlat(env, data) {
  const t0 = Date.now();
  const timing = {};
  try {
    const token = await getAccessToken(env);
    timing.get_token_ms = Date.now() - t0;

    const t1 = Date.now();
    // Baca Transaksi & Inventory SEKALIGUS (paralel), bukan satu-satu.
    const [{ headers, rows }, { headers: invHeaders, rows: invRows }] = await Promise.all([
      readSheetRows(env, token, SHEET_TRANSAKSI),
      readSheetRows(env, token, SHEET_INVENTORY),
    ]);
    timing.read_sheets_ms = Date.now() - t1;

    const trx = rows.find(r => String(r['ID Transaksi']).trim() === String(data.id_transaksi).trim());
    if (!trx) return { success: false, message: 'ID Transaksi "' + data.id_transaksi + '" tidak ditemukan.', _timing: timing };
    if (trx['Status'] === 'Dikembalikan') {
      return { success: false, message: 'Transaksi ini sudah dikembalikan sebelumnya.', _timing: timing };
    }

    const now = new Date();
    const updates = {
      'Tanggal Dikembalikan': formatDateTime(now),
      'Status': 'Dikembalikan',
      'Ket. Pengembalian': data.keterangan || '',
    };
    if (headers.includes('Nama Penerima')) updates['Nama Penerima'] = data.nama_penerima || '';
    if (headers.includes('Kondisi Pengembalian')) updates['Kondisi Pengembalian'] = data.kondisi_barang || '';
    if (headers.includes('Attachment URL') && data.attachment_url) updates['Attachment URL'] = data.attachment_url;

    // Susun SEMUA perubahan kolom transaksi jadi satu batch request.
    const batchData = [];
    for (const key of Object.keys(updates)) {
      const idx = headers.indexOf(key);
      if (idx < 0) continue;
      const colLetter = colNumToLetter(idx + 1);
      batchData.push({ range: `${SHEET_TRANSAKSI}!${colLetter}${trx.__row}`, values: [[updates[key]]] });
    }

    // Kembalikan stok Inventory — tambahkan ke batch yang sama jika ditemukan.
    const invItem = invRows.find(r => String(r['ID Alat']).trim() === String(trx['ID Alat']).trim());
    if (invItem) {
      const idxStok = invHeaders.indexOf('Stok Tersedia');
      if (idxStok >= 0) {
        const colLetter = colNumToLetter(idxStok + 1);
        const stokLama = Number(invItem['Stok Tersedia'] || 0);
        const jumlah = Number(trx['Jumlah'] || 0);
        batchData.push({ range: `${SHEET_INVENTORY}!${colLetter}${invItem.__row}`, values: [[stokLama + jumlah]] });
      }
    }

    // SATU request HTTP untuk semua update, bukan 5-6 request berurutan.
    const t2 = Date.now();
    await sheetsBatchUpdateValues(env, token, batchData);
    timing.batch_update_ms = Date.now() - t2;
    timing.total_ms = Date.now() - t0;
    console.log('kembalikanAlat timing:', JSON.stringify(timing));

    return { success: true, message: 'Pengembalian berhasil dicatat!', _timing: timing };
  } catch (e) {
    timing.total_ms = Date.now() - t0;
    console.log('kembalikanAlat ERROR timing:', JSON.stringify(timing));
    return { success: false, message: 'Error: ' + e.toString(), _timing: timing };
  }
}

// ══════════════════════════════════════════════════════════════
// HISTORY — Ambil log transaksi
// ══════════════════════════════════════════════════════════════
async function getTransaksi(env, filter) {
  try {
    const token = await getAccessToken(env);
    const { rows } = await readSheetRows(env, token, SHEET_TRANSAKSI);
    let data = rows.map(r => { const c = { ...r }; delete c.__row; return c; });

    const kw = filter && filter.keyword ? String(filter.keyword).trim().toLowerCase() : '';
    if (kw) {
      data = data.filter(r => Object.values(r).some(v => String(v).toLowerCase().includes(kw)));
    }

    data.reverse(); // terbaru di atas
    const total = data.length;
    if (!kw) data = data.slice(0, 300);

    return { success: true, data, total };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

// ══════════════════════════════════════════════════════════════
// INPUT MATERIAL — Tambah alat baru ke Inventory
// ══════════════════════════════════════════════════════════════
async function addInventoryItem(env, item) {
  try {
    const token = await getAccessToken(env);
    const { rows } = await readSheetRows(env, token, SHEET_INVENTORY);
    const newId = String(item.id_alat).trim().toUpperCase();

    if (rows.some(r => String(r['ID Alat']).trim().toUpperCase() === newId)) {
      return { success: false, message: 'ID Alat "' + newId + '" sudah ada. Gunakan ID berbeda.' };
    }

    const now = formatDateTime(new Date());
    const row = [
      newId,
      item.nama_alat,
      item.kategori,
      Number(item.jumlah_total),
      Number(item.jumlah_total),
      item.satuan,
      item.kondisi,
      item.lokasi || '',
      item.keterangan || '',
      now,
    ];
    await sheetsAppendRow(env, token, SHEET_INVENTORY, row);

    return { success: true, message: 'Alat "' + item.nama_alat + '" berhasil ditambahkan!' };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

// ══════════════════════════════════════════════════════════════
// ADMIN — Verifikasi login
// ══════════════════════════════════════════════════════════════
async function verifyAdmin(env, credentials) {
  let username, password;
  if (typeof credentials === 'string') {
    username = env.SUPER_ADMIN_USERNAME;
    password = credentials;
  } else {
    username = String((credentials && credentials.username) || '').trim().toLowerCase();
    password = String((credentials && credentials.password) || '');
  }

  if (username === String(env.SUPER_ADMIN_USERNAME).toLowerCase() && password === env.SUPER_ADMIN_PASSWORD) {
    return { success: true, isSuperAdmin: true, username: env.SUPER_ADMIN_USERNAME };
  }

  try {
    const token = await getAccessToken(env);
    const { rows } = await readConfigRows(env, token);
    const key = ADMIN_KEY_PREFIX + username;
    const acc = rows.find(r => String(r.KEY).trim() === key);
    if (!acc) return { success: false, message: 'Username tidak ditemukan.' };
    if (String(acc.VALUE) === password) return { success: true, isSuperAdmin: false, username };
    return { success: false, message: 'Password salah.' };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

// ══════════════════════════════════════════════════════════════
// ADMIN ACCOUNTS — Daftar / buat / hapus akun admin
// ══════════════════════════════════════════════════════════════
async function getAdminAccounts(env) {
  try {
    const token = await getAccessToken(env);
    const { rows } = await readConfigRows(env, token);
    const accounts = rows
      .filter(r => String(r.KEY).startsWith(ADMIN_KEY_PREFIX))
      .map(r => ({ username: String(r.KEY).slice(ADMIN_KEY_PREFIX.length), createdAt: r.CREATED_AT || '' }));
    return { success: true, data: accounts };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

async function createAdminAccount(env, superPw, newUsername, newPassword) {
  if (superPw !== env.SUPER_ADMIN_PASSWORD) return { success: false, message: 'Akses ditolak.' };

  const uname = String(newUsername || '').trim().toLowerCase();
  const pass = String(newPassword || '').trim();

  if (!uname) return { success: false, message: 'Username tidak boleh kosong.' };
  if (!pass) return { success: false, message: 'Password tidak boleh kosong.' };
  if (pass.length < 6) return { success: false, message: 'Password minimal 6 karakter.' };
  if (uname === String(env.SUPER_ADMIN_USERNAME).toLowerCase()) {
    return { success: false, message: 'Username "' + uname + '" sudah digunakan.' };
  }
  if (!/^[a-z0-9_.]+$/.test(uname)) {
    return { success: false, message: 'Username hanya boleh huruf kecil, angka, titik, dan underscore.' };
  }

  try {
    const token = await getAccessToken(env);
    await ensureConfigSheet(env, token);
    const { rows } = await readConfigRows(env, token);
    const key = ADMIN_KEY_PREFIX + uname;
    if (rows.some(r => String(r.KEY).trim() === key)) {
      return { success: false, message: 'Username "' + uname + '" sudah ada.' };
    }
    const now = formatDateTime(new Date());
    await sheetsAppendRow(env, token, SHEET_CONFIG, [key, pass, now]);
    return { success: true, message: 'Akun admin "' + uname + '" berhasil dibuat!' };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

async function deleteAdminAccount(env, superPw, targetUsername) {
  if (superPw !== env.SUPER_ADMIN_PASSWORD) return { success: false, message: 'Akses ditolak.' };

  const uname = String(targetUsername || '').trim().toLowerCase();
  if (uname === String(env.SUPER_ADMIN_USERNAME).toLowerCase()) {
    return { success: false, message: 'Akun super-admin tidak dapat dihapus.' };
  }

  try {
    const token = await getAccessToken(env);
    const { rows } = await readConfigRows(env, token);
    const key = ADMIN_KEY_PREFIX + uname;
    const acc = rows.find(r => String(r.KEY).trim() === key);
    if (!acc) return { success: false, message: 'Akun "' + uname + '" tidak ditemukan.' };

    await deleteSheetRow(env, token, SHEET_CONFIG, acc.__row);
    return { success: true, message: 'Akun admin "' + uname + '" berhasil dihapus.' };
  } catch (e) {
    return { success: false, message: 'Error: ' + e.toString() };
  }
}

// ══════════════════════════════════════════════════════════════
// UPLOAD ATTACHMENT — Simpan file ke Google Drive (folder pribadi)
// ══════════════════════════════════════════════════════════════
async function uploadAttachment(env, base64, fileName, mimeType, idTrans) {
  try {
    if (!base64 || String(base64).trim() === '') {
      return { success: false, message: 'Data file kosong.' };
    }
    if (!env.GOOGLE_DRIVE_FOLDER_ID) {
      return { success: false, message: 'GOOGLE_DRIVE_FOLDER_ID belum dikonfigurasi.' };
    }

    const token = await getDriveAccessToken(env);
    const safeName = (idTrans + '_' + fileName).replace(/[^a-zA-Z0-9_.\-]/g, '_');

    const metadata = { name: safeName, parents: [env.GOOGLE_DRIVE_FOLDER_ID] };
    const boundary = '-------cfBoundary' + Date.now();
    const bytes = base64ToBytes(base64);

    const head = new TextEncoder().encode(
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n` +
      `--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`
    );
    const tail = new TextEncoder().encode(`\r\n--${boundary}--`);

    const fullBody = new Uint8Array(head.length + bytes.length + tail.length);
    fullBody.set(head, 0);
    fullBody.set(bytes, head.length);
    fullBody.set(tail, head.length + bytes.length);

    const uploadRes = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + token,
        'Content-Type': `multipart/related; boundary=${boundary}`,
      },
      body: fullBody,
    });
    const uploadData = await uploadRes.json();
    if (!uploadRes.ok) {
      return {
        success: false,
        message: 'Gagal membuat file di Drive. Pastikan GOOGLE_OAUTH_CLIENT_ID/SECRET/REFRESH_TOKEN sudah benar dan folder GOOGLE_DRIVE_FOLDER_ID milik akun Gmail yang sama dengan refresh token. Detail: ' +
          (uploadData.error?.message || JSON.stringify(uploadData)),
      };
    }

    const fileId = uploadData.id;

    try {
      await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}/permissions`, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'reader', type: 'anyone' }),
      });
    } catch (e) {
      // File sudah terupload, lanjutkan meski setting sharing gagal
    }

    const fileUrl = `https://drive.google.com/file/d/${fileId}/view`;
    return { success: true, url: fileUrl, fileId, message: 'File berhasil diupload.' };
  } catch (e) {
    return { success: false, message: 'Gagal upload file: ' + e.toString() };
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
