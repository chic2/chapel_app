// server.js - AUI Chapel Auth & API Worker (Production Ready)
// Cloudflare Worker handling authentication via Supabase + D1

import { createClient } from '@supabase/supabase-js';
import manifestJSON from '__STATIC_CONTENT_MANIFEST';
const assetManifest = JSON.parse(manifestJSON);

const getCorsHeaders = (env) => ({
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
});

const corsHeaders = (env) => getCorsHeaders(env);
const getSiteUrl = (env) => env.SITE_URL || 'https://aui-chapel.pages.dev';

// ─── HELPER: Verify staff token ───────────────────────────────────────────────
async function verifyStaff(request, supabaseAdmin) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) return null;
    const token = authHeader.replace('Bearer ', '');
    const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);
    if (error || !user) return null;
    const { data: profile } = await supabaseAdmin.from('staff').select('role').eq('id', user.id).single();
    if (profile?.role !== 'staff') return null;
    return user;
}

// ─── SERVE STATIC ASSETS (Workers Sites) ─────────────────────────────────────
async function serveStaticAsset(request, env, ctx) {
    const url = new URL(request.url);
    let pathname = url.pathname;

    // Normalize path
    if (pathname === '/' || pathname === '') pathname = '/index.html';
    if (!pathname.includes('.')) pathname += '.html';

    // Sanitize: block path traversal attempts
    if (pathname.includes('..') || pathname.includes('//')) {
        return new Response('Forbidden', { status: 403 });
    }

    // Remove leading slash to get KV key
    const key = pathname.replace(/^\//, '');

    // Content type map
    const types = {
        'html': 'text/html; charset=utf-8',
        'css': 'text/css',
        'js': 'application/javascript',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'svg': 'image/svg+xml',
        'ico': 'image/x-icon',
        'mp4': 'video/mp4',
        'webp': 'image/webp',
        'woff': 'font/woff',
        'woff2': 'font/woff2',
    };

    const ext = key.split('.').pop().toLowerCase();
    const contentType = types[ext] || 'application/octet-stream';

    // Look up hashed key in manifest
    const hashedKey = assetManifest[key];
    if (!hashedKey) {
        // Try index.html as fallback
        const indexKey = assetManifest['index.html'];
        if (indexKey) {
            const indexData = await env.__STATIC_CONTENT.get(indexKey, { type: 'arrayBuffer' });
            if (indexData) {
                return new Response(indexData, {
                    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' }
                });
            }
        }
        return new Response('Not found', { status: 404 });
    }

    const data = await env.__STATIC_CONTENT.get(hashedKey, { type: 'arrayBuffer' });
    if (!data) return new Response('Not found', { status: 404 });

    return new Response(data, {
        headers: {
            'Content-Type': contentType,
            'Cache-Control': ext === 'html' ? 'no-store' : ext === 'mp4' ? 'public, max-age=604800' : 'public, max-age=31536000, immutable',
        }
    });
}

export default {
    async fetch(request, env, ctx) {
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders(env) });
        }

        // Basic rate limiting
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const url = new URL(request.url);
        const path = url.pathname;
        const rateKey = `rate:${ip}:${path}`;
        const now = Date.now();
        const rateLimit = 10;
        const windowMs = 60 * 1000;

        if (!globalThis.rateLimits) globalThis.rateLimits = new Map();
        let record = globalThis.rateLimits.get(rateKey) || { count: 0, resetTime: now + windowMs };
        if (now > record.resetTime) record = { count: 0, resetTime: now + windowMs };
        record.count++;
        globalThis.rateLimits.set(rateKey, record);

        if (record.count > rateLimit) {
            return new Response(JSON.stringify({ error: 'Too many requests. Try again later.' }), {
                status: 429,
                headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
            });
        }

        const supabasePublic = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
            auth: { persistSession: false }
        });
        const supabaseAdmin = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
            auth: { persistSession: false }
        });
        const db = env.aui_chapel_db; // D1 database

        try {
            // ─── AUTH ROUTES ───
            if (path === '/api/auth/student-signup' && request.method === 'POST')
                return await handleStudentSignup(request, supabasePublic, supabaseAdmin, env);
            if (path === '/api/auth/student-signin' && request.method === 'POST')
                return await handleStudentSignin(request, supabasePublic, supabaseAdmin, env);
            if (path === '/api/auth/student-forgot' && request.method === 'POST')
                return await handleStudentForgot(request, supabasePublic, env);
            if (path === '/api/auth/student-reset' && request.method === 'POST')
                return await handleStudentReset(request, supabasePublic, env);
            if (path === '/api/auth/staff-signup' && request.method === 'POST')
                return await handleStaffSignup(request, supabaseAdmin, env);
            if (path === '/api/auth/staff-signin' && request.method === 'POST')
                return await handleStaffSignin(request, supabasePublic, supabaseAdmin, env);

            // ─── REFLECTION ROUTES ───
            if (path === '/api/reflections/today' && request.method === 'GET')
                return await getTodayReflection(db, env);
            if (path === '/api/reflections/post' && request.method === 'POST')
                return await postReflection(request, db, supabaseAdmin, env);
            if (path === '/api/reflections/read' && request.method === 'POST')
                return await markReflectionRead(request, db, supabaseAdmin, env);

            // ─── STUDENT ROUTES ───
            if (path === '/api/student/stats' && request.method === 'GET')
                return await getStudentStats(request, supabaseAdmin, env);
            if (path === '/api/leaderboard' && request.method === 'GET')
                return await getLeaderboard(supabaseAdmin, env);
            if (path === '/api/faculty/battle' && request.method === 'GET')
                return await getFacultyBattle(db, supabaseAdmin, env);

            // ─── ADMIN ROUTES ───
            if (path === '/api/admin/stats' && request.method === 'GET')
                return await getAdminStats(request, db, supabaseAdmin, env);
            if (path === '/api/admin/students' && request.method === 'GET')
                return await getAdminStudents(request, supabaseAdmin, env);
            if (path === '/api/admin/ban' && request.method === 'POST')
                return await banStudent(request, supabaseAdmin, env);
            if (path === '/api/admin/challenge' && request.method === 'POST')
                return await createChallenge(request, supabaseAdmin, env);
            if (path === '/api/admin/challenges' && request.method === 'GET')
                return await getChallenges(request, supabaseAdmin, env);
            if (path === '/api/admin/donations' && request.method === 'GET')
                return await getAdminDonations(request, supabaseAdmin, env);

            // ─── PUBLIC CHALLENGE ROUTE (students) ───
            if (path === '/api/challenges/active' && request.method === 'GET')
                return await getActiveChallenges(supabaseAdmin, env);

            // ─── CONFIG ROUTE (public key for Paystack) ───
            if (path === '/api/config/paystack-key' && request.method === 'GET') {
                return new Response(JSON.stringify({ key: env.PAYSTACK_PUBLIC_KEY || '' }), {
                    status: 200,
                    headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
                });
            }

            // ─── DONATION ROUTES ───
            if (path === '/api/donate/verify' && request.method === 'POST')
                return await verifyDonation(request, supabaseAdmin, env);

            // ─── SERVE STATIC FILES (HTML, images, video) ───
            return await serveStaticAsset(request, env, ctx);
        } catch (error) {
            console.error('Worker error:', error);
            return new Response(JSON.stringify({ error: 'Internal server error', details: error.message }), {
                status: 500,
                headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
            });
        }
    },
};

// ─── STUDENT SIGNUP ──────────────────────────────────────────────────────────

async function handleStudentSignup(request, supabase, supabaseAdmin, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request format' }), { status: 400, headers: corsHeaders(env) });
    }

    let { email, password, fullName, matric, faculty } = body || {};
    if (typeof email === 'string') email = email.trim().toLowerCase();
    if (typeof fullName === 'string') fullName = fullName.trim();

    if (!email || !password || !fullName || !matric || !faculty) {
        return new Response(JSON.stringify({ error: 'All fields are required' }), { status: 400, headers: corsHeaders(env) });
    }

    if (!/^AU\d{9}$/.test(matric)) {
        return new Response(JSON.stringify({ error: 'Invalid matric number format (AU followed by 9 digits)' }), { status: 400, headers: corsHeaders(env) });
    }

    const { data: authData, error: authError } = await supabase.auth.signUp({
        email, password,
        options: {
            data: { full_name: fullName, matric_number: matric, faculty, role: 'student' },
            emailRedirectTo: `${getSiteUrl(env)}/studentsignin.html`
        }
    });

    if (authError) {
        console.error('Auth creation error:', authError);
        return new Response(JSON.stringify({ error: `Auth creation failed: ${authError.message}` }), { status: 400, headers: corsHeaders(env) });
    }

    // Trigger handle_new_student() auto-inserts into public.students
    return new Response(JSON.stringify({
        success: true,
        message: 'Account created successfully – you can now sign in',
        userId: authData.user?.id,
    }), { status: 201, headers: corsHeaders(env) });
}

// ─── STUDENT SIGNIN ──────────────────────────────────────────────────────────

async function handleStudentSignin(request, supabase, supabaseAdmin, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { email: rawEmail, password } = body;
    const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : null;

    if (!email || !password) {
        return new Response(JSON.stringify({ error: 'Email and password required' }), { status: 400, headers: corsHeaders(env) });
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
        return new Response(JSON.stringify({ error: 'Invalid credentials or unconfirmed email' }), { status: 401, headers: corsHeaders(env) });
    }

    const { data: profile, error: profileError } = await supabaseAdmin
        .from('students').select('*').eq('id', data.user.id).single();

    if (profileError || !profile) {
        return new Response(JSON.stringify({ error: 'Student profile not found' }), { status: 404, headers: corsHeaders(env) });
    }

    // Check if banned
    if (profile.is_banned) {
        return new Response(JSON.stringify({ error: 'Your account has been suspended. Contact the chaplaincy.' }), { status: 403, headers: corsHeaders(env) });
    }

    return new Response(JSON.stringify({ success: true, session: data.session, user: data.user, profile }), { status: 200, headers: corsHeaders(env) });
}

// ─── STUDENT FORGOT PASSWORD ─────────────────────────────────────────────────

async function handleStudentForgot(request, supabase, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { email: rawEmail } = body;
    const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : null;
    if (!email) return new Response(JSON.stringify({ error: 'Email required' }), { status: 400, headers: corsHeaders(env) });

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${getSiteUrl(env)}/studentreset.html`,
    });

    if (error) return new Response(JSON.stringify({ error: 'Could not send reset link' }), { status: 400, headers: corsHeaders(env) });
    return new Response(JSON.stringify({ success: true, message: 'Password reset link sent' }), { status: 200, headers: corsHeaders(env) });
}

// ─── STUDENT RESET PASSWORD ──────────────────────────────────────────────────

async function handleStudentReset(request, supabase, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { newPassword, access_token, refresh_token } = body;
    if (!access_token || !newPassword || newPassword.length < 8) {
        return new Response(JSON.stringify({ error: 'Valid token and new password (min 8 chars) required' }), { status: 400, headers: corsHeaders(env) });
    }

    const { error: sessionError } = await supabase.auth.setSession({
        access_token,
        refresh_token: refresh_token || access_token,
    });

    if (sessionError) {
        console.error('Session error:', sessionError);
        return new Response(JSON.stringify({ error: 'Reset link is invalid or has expired. Please request a new one.' }), { status: 400, headers: corsHeaders(env) });
    }

    const { error: updateError } = await supabase.auth.updateUser({ password: newPassword });
    if (updateError) {
        console.error('Update error:', updateError);
        if (updateError.code === 'same_password') {
            return new Response(JSON.stringify({ error: 'Your new password must be different from your old password.' }), { status: 400, headers: corsHeaders(env) });
        }
        return new Response(JSON.stringify({ error: 'Password reset failed. Please try again.' }), { status: 400, headers: corsHeaders(env) });
    }

    return new Response(JSON.stringify({ success: true, message: 'Password updated successfully' }), { status: 200, headers: corsHeaders(env) });
}

// ─── STAFF SIGNUP ────────────────────────────────────────────────────────────

async function handleStaffSignup(request, supabase, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    let { email, password } = body || {};
    if (typeof email === 'string') email = email.trim().toLowerCase();
    if (!email || !password) return new Response(JSON.stringify({ error: 'Email and password required' }), { status: 400, headers: corsHeaders(env) });

    try {
        const { data: users } = await supabase.auth.admin.listUsers();
        const existing = users?.users?.find(u => u.email === email);
        if (existing) {
            await supabase.from('staff').delete().eq('id', existing.id).catch(() => {});
            await supabase.auth.admin.deleteUser(existing.id).catch(() => {});
        }
    } catch (e) { console.error('Cleanup error (non-fatal):', e); }

    const { data: authData, error: authError } = await supabase.auth.admin.createUser({
        email, password, email_confirm: true, user_metadata: { role: 'staff' },
    });

    if (authError) {
        console.error('Staff auth creation error:', authError);
        return new Response(JSON.stringify({ error: `Could not create staff account: ${authError.message}` }), { status: 400, headers: corsHeaders(env) });
    }

    const { error: insertError } = await supabase.from('staff').insert({ id: authData.user.id, email, role: 'staff' });
    if (insertError) {
        console.error('Staff insert error:', insertError);
        await supabase.auth.admin.deleteUser(authData.user.id).catch(() => {});
        return new Response(JSON.stringify({ error: `Staff profile setup failed: ${insertError.message}` }), { status: 500, headers: corsHeaders(env) });
    }

    return new Response(JSON.stringify({ success: true, message: 'Staff account created successfully', userId: authData.user.id }), { status: 201, headers: corsHeaders(env) });
}

// ─── STAFF SIGNIN ────────────────────────────────────────────────────────────

async function handleStaffSignin(request, supabase, supabaseAdmin, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { email: rawEmail, password } = body;
    const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : null;
    if (!email || !password) return new Response(JSON.stringify({ error: 'Email and password required' }), { status: 400, headers: corsHeaders(env) });

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: corsHeaders(env) });

    const { data: profile, error: profileError } = await supabaseAdmin
        .from('staff').select('role').eq('id', data.user.id).single();

    if (profileError || profile?.role !== 'staff') {
        return new Response(JSON.stringify({ error: 'Unauthorized - staff access only' }), { status: 403, headers: corsHeaders(env) });
    }

    return new Response(JSON.stringify({ success: true, session: data.session, user: data.user, profile }), { status: 200, headers: corsHeaders(env) });
}

// ─── GET TODAY'S REFLECTION (D1) ─────────────────────────────────────────────

async function getTodayReflection(db, env) {
    try {
        const today = new Date().toISOString().split('T')[0];
        const { results } = await db.prepare(
            `SELECT * FROM reflections WHERE date(created_at) = ? ORDER BY created_at DESC LIMIT 1`
        ).bind(today).all();
        const reflection = results[0] || null;
        return new Response(JSON.stringify({ success: true, reflection }), {
            status: 200,
            headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
        });
    } catch (e) {
        console.error('getTodayReflection error:', e);
        return new Response(JSON.stringify({ success: true, reflection: null }), {
            status: 200,
            headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
        });
    }
}

// ─── POST REFLECTION (D1) ────────────────────────────────────────────────────

async function postReflection(request, db, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders(env) });

    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { title, message, scripture, youtube_url, prayer } = body;
    if (!title || !message) return new Response(JSON.stringify({ error: 'Title and message required' }), { status: 400, headers: corsHeaders(env) });

    // Check if reflection already posted today
    const today = new Date().toISOString().split('T')[0];
    const { results: existing } = await db.prepare(
        `SELECT id FROM reflections WHERE date(created_at) = ?`
    ).bind(today).all();

    if (existing.length > 0) {
        // Update existing reflection
        await db.prepare(
            `UPDATE reflections SET title=?, message=?, scripture=?, youtube_url=?, music_url=?, expires_at=datetime('now', '+24 hours') WHERE id=?`
        ).bind(title, message, scripture || null, youtube_url || null, prayer || null, existing[0].id).run();
    } else {
        // Insert new reflection
        const id = crypto.randomUUID();
        await db.prepare(
            `INSERT INTO reflections (id, title, message, scripture, youtube_url, music_url, posted_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'))`
        ).bind(id, title, message, scripture || null, youtube_url || null, prayer || null, staff.id).run();
    }

    return new Response(JSON.stringify({ success: true, message: 'Reflection posted!' }), { status: 201, headers: corsHeaders(env) });
}

// ─── MARK REFLECTION READ (D1 + Supabase) ────────────────────────────────────

async function markReflectionRead(request, db, supabaseAdmin, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { student_id, reflection_id, listened, prayed } = body;
    if (!student_id || !reflection_id) return new Response(JSON.stringify({ error: 'student_id and reflection_id required' }), { status: 400, headers: corsHeaders(env) });

    // Check if already read
    const { results: existing } = await db.prepare(
        `SELECT id, listened, prayed FROM reflection_reads WHERE student_id=? AND reflection_id=?`
    ).bind(student_id, reflection_id).all();

    let pointsEarned = 0;
    const isFirstRead = existing.length === 0;

    if (isFirstRead) {
        // Insert read record
        const readId = crypto.randomUUID();
        await db.prepare(
            `INSERT INTO reflection_reads (id, student_id, reflection_id, listened, prayed) VALUES (?, ?, ?, ?, ?)`
        ).bind(readId, student_id, reflection_id, listened ? 1 : 0, prayed ? 1 : 0).run();
        pointsEarned += 10; // read points
    } else {
        // Update listened/prayed if new
        const row = existing[0];
        const addedListen = listened && !row.listened;
        const addedPray = prayed && !row.prayed;
        if (addedListen || addedPray) {
            await db.prepare(
                `UPDATE reflection_reads SET listened=?, prayed=? WHERE id=?`
            ).bind(listened ? 1 : 0, prayed ? 1 : 0, row.id).run();
            if (addedListen) pointsEarned += 5;
            if (addedPray) pointsEarned += 5;
        }
    }

    // Update streak and points in Supabase
    if (pointsEarned > 0 || isFirstRead) {
        await updateStudentStreak(student_id, pointsEarned, isFirstRead, supabaseAdmin);
    }

    return new Response(JSON.stringify({ success: true, pointsEarned, isFirstRead }), { status: 200, headers: corsHeaders(env) });
}

// ─── UPDATE STREAK ────────────────────────────────────────────────────────────

async function updateStudentStreak(student_id, pointsEarned, isFirstRead, supabaseAdmin) {
    const today = new Date().toISOString().split('T')[0];

    const { data: stats } = await supabaseAdmin
        .from('student_stats').select('*').eq('student_id', student_id).single();

    if (!stats) {
        // Create stats record for first time
        await supabaseAdmin.from('student_stats').insert({
            student_id,
            current_streak: isFirstRead ? 1 : 0,
            longest_streak: isFirstRead ? 1 : 0,
            total_points: pointsEarned,
            last_read_date: isFirstRead ? today : null,
        });
        return;
    }

    if (!isFirstRead) {
        // Just add points
        await supabaseAdmin.from('student_stats').update({
            total_points: (stats.total_points || 0) + pointsEarned,
            updated_at: new Date().toISOString(),
        }).eq('student_id', student_id);
        return;
    }

    // Calculate streak
    const lastRead = stats.last_read_date;
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    const twoDaysAgo = new Date();
    twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);
    const twoDaysAgoStr = twoDaysAgo.toISOString().split('T')[0];

    let newStreak = stats.current_streak || 0;

    if (lastRead === today) {
        // Already read today, no streak change
    } else if (lastRead === yesterdayStr) {
        // Consecutive day — increment
        newStreak += 1;
    } else if (lastRead === twoDaysAgoStr) {
        // Grace period — keep streak (miss 1 day = freeze)
    } else {
        // Missed 2+ days — reset
        newStreak = 1;
    }

    // Check streak bonuses
    let bonusPoints = 0;
    if (newStreak === 7) bonusPoints = 25;
    if (newStreak === 30) bonusPoints = 100;
    if (newStreak === 60) bonusPoints = 200;
    if (newStreak === 100) bonusPoints = 500;

    const totalPoints = (stats.total_points || 0) + pointsEarned + bonusPoints;
    const longestStreak = Math.max(stats.longest_streak || 0, newStreak);

    await supabaseAdmin.from('student_stats').update({
        current_streak: newStreak,
        longest_streak: longestStreak,
        total_points: totalPoints,
        last_read_date: today,
        updated_at: new Date().toISOString(),
    }).eq('student_id', student_id);

    // Award badges
    await checkAndAwardBadges(student_id, newStreak, totalPoints, supabaseAdmin);
}

// ─── AWARD BADGES ─────────────────────────────────────────────────────────────

async function checkAndAwardBadges(student_id, streak, points, supabaseAdmin) {
    const { data: badges } = await supabaseAdmin.from('badges').select('*');
    const { data: earned } = await supabaseAdmin.from('student_badges').select('badge_id').eq('student_id', student_id);
    const earnedIds = new Set((earned || []).map(b => b.badge_id));

    for (const badge of (badges || [])) {
        if (earnedIds.has(badge.id)) continue;
        const qualifies =
            (badge.streak_required > 0 && streak >= badge.streak_required) ||
            (badge.points_required > 0 && points >= badge.points_required);
        if (qualifies) {
            try {
                await supabaseAdmin.from('student_badges').insert({ student_id, badge_id: badge.id });
            } catch(e) { /* already earned */ }
        }
    }
}

// ─── GET STUDENT STATS ────────────────────────────────────────────────────────

async function getStudentStats(request, supabaseAdmin, env) {
    const url = new URL(request.url);
    const student_id = url.searchParams.get('student_id');
    if (!student_id) return new Response(JSON.stringify({ error: 'student_id required' }), { status: 400, headers: corsHeaders(env) });

    const { data: stats } = await supabaseAdmin
        .from('student_stats').select('*').eq('student_id', student_id).single();

    const { data: badges } = await supabaseAdmin
        .from('student_badges')
        .select('*, badges(*)')
        .eq('student_id', student_id);

    return new Response(JSON.stringify({ success: true, stats: stats || {}, badges: badges || [] }), { status: 200, headers: corsHeaders(env) });
}

// ─── GET LEADERBOARD ──────────────────────────────────────────────────────────

async function getLeaderboard(supabaseAdmin, env) {
    const { data } = await supabaseAdmin
        .from('student_stats')
        .select('student_id, current_streak, longest_streak, total_points, students(fullName, faculty)')
        .order('current_streak', { ascending: false })
        .order('total_points', { ascending: false })
        .limit(10);

    const leaderboard = (data || []).map(row => ({
        student_id: row.student_id,
        name: row.students?.fullName || 'Unknown',
        faculty: row.students?.faculty || '',
        streak: row.current_streak,
        points: row.total_points,
    }));

    return new Response(JSON.stringify({ success: true, leaderboard }), { status: 200, headers: corsHeaders(env) });
}

// ─── GET FACULTY BATTLE ───────────────────────────────────────────────────────

async function getFacultyBattle(db, supabaseAdmin, env) {
    try {
        const { data: allStudents } = await supabaseAdmin
            .from('students').select('id, faculty');

        const facusIds = (allStudents || []).filter(s => s.faculty?.toUpperCase() === 'FACUS').map(s => s.id);
        const fahumsIds = (allStudents || []).filter(s => s.faculty?.toUpperCase() === 'FAHUMS').map(s => s.id);

        const weekStart = new Date();
        weekStart.setDate(weekStart.getDate() - weekStart.getDay());
        const weekStartStr = weekStart.toISOString().split('T')[0];

        let facusReads = 0, fahumsReads = 0;

        if (facusIds.length) {
            const placeholders = facusIds.map(() => '?').join(',');
            const { results } = await db.prepare(
                `SELECT COUNT(*) as count FROM reflection_reads WHERE student_id IN (${placeholders}) AND date(read_at) >= ?`
            ).bind(...facusIds, weekStartStr).all();
            facusReads = results[0]?.count || 0;
        }

        if (fahumsIds.length) {
            const placeholders = fahumsIds.map(() => '?').join(',');
            const { results } = await db.prepare(
                `SELECT COUNT(*) as count FROM reflection_reads WHERE student_id IN (${placeholders}) AND date(read_at) >= ?`
            ).bind(...fahumsIds, weekStartStr).all();
            fahumsReads = results[0]?.count || 0;
        }

        return new Response(JSON.stringify({
            success: true,
            facus: facusReads,
            fahums: fahumsReads,
            facusStudents: facusIds.length,
            fahumsStudents: fahumsIds.length,
        }), {
            status: 200,
            headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
        });
    } catch (e) {
        console.error('getFacultyBattle error:', e);
        return new Response(JSON.stringify({ success: true, facus: 0, fahums: 0, facusStudents: 0, fahumsStudents: 0 }), {
            status: 200,
            headers: { ...corsHeaders(env), 'Content-Type': 'application/json' },
        });
    }
}

// ─── ADMIN: GET STATS ─────────────────────────────────────────────────────────

async function getAdminStats(request, db, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { ...corsHeaders(env), 'Content-Type': 'application/json' } });

    const today = new Date().toISOString().split('T')[0];

    let totalStudents = 0, activeStreaks = 0, readsToday = 0, prayersToday = 0;

    try {
        const { data: studentList } = await supabaseAdmin.from('students').select('id');
        totalStudents = studentList?.length || 0;
    } catch(e) { console.error('getAdminStats students error:', e); }

    try {
        const { count } = await supabaseAdmin
            .from('student_stats').select('*', { count: 'exact', head: true })
            .gt('current_streak', 0);
        activeStreaks = count || 0;
    } catch(e) { console.error('getAdminStats streaks error:', e); }

    try {
        const { results: r1 } = await db.prepare(
            `SELECT COUNT(DISTINCT student_id) as count FROM reflection_reads WHERE date(read_at) = ?`
        ).bind(today).all();
        readsToday = r1[0]?.count || 0;
    } catch(e) { console.error('getAdminStats readsToday error:', e); }

    try {
        const { results: r2 } = await db.prepare(
            `SELECT COUNT(DISTINCT student_id) as count FROM reflection_reads WHERE date(read_at) = ? AND prayed = 1`
        ).bind(today).all();
        prayersToday = r2[0]?.count || 0;
    } catch(e) { console.error('getAdminStats prayersToday error:', e); }

    return new Response(JSON.stringify({
        success: true,
        totalStudents,
        activeStreaks,
        readsToday,
        prayersToday,
    }), { status: 200, headers: { ...corsHeaders(env), 'Content-Type': 'application/json' } });
}

// ─── ADMIN: GET STUDENTS ──────────────────────────────────────────────────────

async function getAdminStudents(request, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders(env) });

    const { data: students } = await supabaseAdmin
        .from('students')
        .select('id, fullName, email, matric, faculty, is_banned, created_at, student_stats(current_streak, total_points)')
        .order('created_at', { ascending: false });

    const mapped = (students || []).map(s => ({
        ...s,
        // student_stats comes back as array from Supabase join
        current_streak: Array.isArray(s.student_stats) ? (s.student_stats[0]?.current_streak || 0) : (s.student_stats?.current_streak || 0),
        total_points: Array.isArray(s.student_stats) ? (s.student_stats[0]?.total_points || 0) : (s.student_stats?.total_points || 0),
    }));

    return new Response(JSON.stringify({ success: true, students: mapped }), { status: 200, headers: corsHeaders(env) });
}

// ─── ADMIN: BAN/UNBAN STUDENT ─────────────────────────────────────────────────

async function banStudent(request, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders(env) });

    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { student_id, ban } = body;
    if (!student_id) return new Response(JSON.stringify({ error: 'student_id required' }), { status: 400, headers: corsHeaders(env) });

    // Check if is_banned column exists, if not add it
    const { error } = await supabaseAdmin
        .from('students').update({ is_banned: ban }).eq('id', student_id);

    if (error) {
        console.error('Ban error:', error);
        return new Response(JSON.stringify({ error: `Could not update student: ${error.message}` }), { status: 500, headers: corsHeaders(env) });
    }

    return new Response(JSON.stringify({ success: true, message: ban ? 'Student banned' : 'Student unbanned' }), { status: 200, headers: corsHeaders(env) });
}

// ─── ADMIN: CREATE CHALLENGE ──────────────────────────────────────────────────

async function createChallenge(request, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders(env) });

    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { title, description, points_reward, duration } = body;
    if (!title || !description) return new Response(JSON.stringify({ error: 'Title and description required' }), { status: 400, headers: corsHeaders(env) });

    const starts_at = new Date().toISOString();
    const ends_at = new Date(Date.now() + (duration || 7) * 24 * 60 * 60 * 1000).toISOString();

    const { error } = await supabaseAdmin.from('challenges').insert({
        title, description,
        points_reward: points_reward || 50,
        starts_at, ends_at,
        created_by: staff.id,
    });

    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders(env) });
    return new Response(JSON.stringify({ success: true, message: 'Challenge created!' }), { status: 201, headers: corsHeaders(env) });
}

// ─── ADMIN: GET CHALLENGES ────────────────────────────────────────────────────

async function getChallenges(request, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders(env) });

    const { data: challenges } = await supabaseAdmin
        .from('challenges')
        .select('*')
        .gte('ends_at', new Date().toISOString())
        .order('created_at', { ascending: false });

    return new Response(JSON.stringify({ success: true, challenges: challenges || [] }), { status: 200, headers: corsHeaders(env) });
}

// ─── ADMIN: GET DONATIONS ─────────────────────────────────────────────────────

async function getAdminDonations(request, supabaseAdmin, env) {
    const staff = await verifyStaff(request, supabaseAdmin);
    if (!staff) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders(env) });

    const { data: donations } = await supabaseAdmin
        .from('donations')
        .select('*, students(email)')
        .order('created_at', { ascending: false });

    const mapped = (donations || []).map(d => ({
        ...d,
        student_email: d.students?.email || 'Anonymous',
    }));

    return new Response(JSON.stringify({ success: true, donations: mapped }), { status: 200, headers: corsHeaders(env) });
}

// ─── VERIFY PAYSTACK DONATION ────────────────────────────────────────────────

async function verifyDonation(request, supabaseAdmin, env) {
    let body;
    try { body = await request.json(); } catch {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: corsHeaders(env) });
    }

    const { reference, student_id, amount } = body;
    if (!reference) return new Response(JSON.stringify({ error: 'reference required' }), { status: 400, headers: corsHeaders(env) });

    // Validate reference to prevent SSRF — only allow alphanumeric, underscores, hyphens
    if (!/^[a-zA-Z0-9_\-]+$/.test(reference)) {
        return new Response(JSON.stringify({ error: 'Invalid reference format' }), { status: 400, headers: corsHeaders(env) });
    }

    // Verify with Paystack API
    try {
        const psRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
            headers: { 'Authorization': `Bearer ${env.PAYSTACK_SECRET_KEY}` }
        });
        const psData = await psRes.json();

        if (!psData.status || psData.data?.status !== 'success') {
            return new Response(JSON.stringify({ error: 'Payment verification failed' }), { status: 400, headers: corsHeaders(env) });
        }

        // Save to Supabase
        try {
            await supabaseAdmin.from('donations').insert({
                student_id: student_id || null,
                amount: psData.data.amount / 100, // Paystack returns kobo, convert to naira
                currency: psData.data.currency,
                flutterwave_ref: reference, // reusing same column for the reference
                status: 'success',
            });
        } catch(insertErr) {
            console.error('Donation insert error (non-fatal):', insertErr);
        }

        return new Response(JSON.stringify({ success: true, message: 'Thank you for your donation! 🙏' }), { status: 200, headers: corsHeaders(env) });
    } catch(e) {
        console.error('Paystack error:', e);
        return new Response(JSON.stringify({ error: 'Could not verify payment' }), { status: 500, headers: corsHeaders(env) });
    }
}

// ─── PUBLIC: GET ACTIVE CHALLENGES (for students) ────────────────────────────

async function getActiveChallenges(supabaseAdmin, env) {
    const { data: challenges } = await supabaseAdmin
        .from('challenges')
        .select('*')
        .gte('ends_at', new Date().toISOString())
        .order('created_at', { ascending: false });

    return new Response(JSON.stringify({ success: true, challenges: challenges || [] }), { status: 200, headers: corsHeaders(env) });
}