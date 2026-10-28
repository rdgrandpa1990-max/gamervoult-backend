import admin from 'firebase-admin';

/**
 * Authentication & Authorization Middleware for Gamervoult & FreeFireOfficial API
 */

/**
 * Verifies Firebase ID Token or Admin API Key.
 * Attaches decoded user to req.user, req.uid, and req.userRole.
 */
export const verifyFirebaseAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  const apiKeyHeader = req.headers['x-api-key'] || '';

  // 1. Check for Service-to-Service Admin Key
  const adminApiKey = process.env.ADMIN_API_KEY || '';
  if (apiKeyHeader && adminApiKey && apiKeyHeader === adminApiKey) {
    req.uid = 'system_admin';
    req.userRole = 'superadmin';
    req.isAdmin = true;
    req.user = { uid: 'system_admin', role: 'superadmin', email: 'admin@system.local' };
    return next();
  }

  // 2. Check for Firebase Bearer Token
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Missing or invalid Authorization header. Expected Bearer token.'
    });
  }

  const idToken = authHeader.split('Bearer ')[1].trim();
  if (!idToken) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Bearer token is empty.'
    });
  }

  try {
    if (!admin.apps.length) {
      return res.status(503).json({
        success: false,
        error: 'Service Unavailable',
        message: 'Firebase Auth service is not initialized on server.'
      });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.uid = decodedToken.uid;
    req.user = decodedToken;

    // Check custom claims role first, then fallback to Firestore user document
    let role = (decodedToken.role || '').toLowerCase().trim();

    const db = admin.firestore();
    const userDocSnap = await db.collection('users').doc(decodedToken.uid).get();

    if (userDocSnap.exists) {
      const userData = userDocSnap.data();
      // Blocked / Suspended account check
      if (userData.isBlocked === true || userData.status === 'Suspended' || userData.status === 'Removed') {
        return res.status(403).json({
          success: false,
          error: 'Forbidden',
          message: 'Account is suspended or blocked. Access denied.'
        });
      }

      if (!role && userData.role) {
        role = String(userData.role).toLowerCase().trim();
      }
      req.userData = userData;
    }

    req.userRole = role || 'user';
    req.isAdmin = req.userRole === 'admin' || req.userRole === 'superadmin';
    req.isStaff = req.isAdmin || req.userRole === 'employee' || req.userRole === 'staff';

    next();
  } catch (err) {
    console.error('[AuthMiddleware] Token verification failed:', err.message);
    if (err.code === 'auth/id-token-expired') {
      return res.status(401).json({
        success: false,
        error: 'Token Expired',
        message: 'Firebase ID token has expired. Please refresh your token.'
      });
    }
    return res.status(401).json({
      success: false,
      error: 'Unauthorized',
      message: 'Invalid authentication token.'
    });
  }
};

/**
 * Enforces minimum role requirements (e.g. ['admin', 'superadmin']).
 */
export const requireRoles = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.userRole || !allowedRoles.includes(req.userRole)) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: `Insufficient permissions. Required role: [${allowedRoles.join(', ')}], current: ${req.userRole || 'none'}`
      });
    }
    next();
  };
};

/**
 * Validates that host input is not pointing to internal network / SSRF targets.
 */
export const validateHostSecurity = (host) => {
  if (!host || typeof host !== 'string') return false;
  const clean = host.trim().toLowerCase();

  // Block localhost and loopback
  if (clean === 'localhost' || clean === '127.0.0.1' || clean === '0.0.0.0' || clean === '::1') {
    return false;
  }

  // Block private IPv4 ranges (10.x.x.x, 192.168.x.x, 172.16.x.x-172.31.x.x, 169.254.x.x)
  if (
    clean.startsWith('10.') ||
    clean.startsWith('192.168.') ||
    clean.startsWith('169.254.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)
  ) {
    return false;
  }

  // Block internal/local domains and cloud metadata hostnames
  if (
    clean.includes('metadata.google.internal') ||
    clean.includes('169.254.169.254') ||
    clean.endsWith('.local') ||
    clean.endsWith('.internal') ||
    clean.endsWith('.lan') ||
    clean.endsWith('.home')
  ) {
    return false;
  }

  // Must contain valid domain syntax or public IP
  return /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(clean) || /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(clean);
};
