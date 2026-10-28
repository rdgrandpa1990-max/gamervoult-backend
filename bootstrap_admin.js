/**
 * bootstrap_admin.js
 * Secure operator script to assign admin/superadmin roles and Custom Claims.
 * Usage: node bootstrap_admin.js <email_or_uid> <admin|superadmin|staff|user>
 */
import admin from 'firebase-admin';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize Firebase Admin SDK safely
const serviceAccountPath = path.join(__dirname, 'serviceAccountKey.json');
if (fs.existsSync(serviceAccountPath)) {
  const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: serviceAccount.project_id || 'ff-store-4a61e'
  });
} else {
  admin.initializeApp({
    projectId: process.env.FIREBASE_PROJECT_ID || 'ff-store-4a61e'
  });
}

const auth = admin.auth();
const db = admin.firestore();

async function bootstrap() {
  const target = process.argv[2];
  const role = (process.argv[3] || 'admin').toLowerCase();

  const allowedRoles = ['superadmin', 'admin', 'staff', 'user', 'client'];
  if (!target || !allowedRoles.includes(role)) {
    console.error('Usage: node bootstrap_admin.js <user_email_or_uid> <superadmin|admin|staff|user>');
    process.exit(1);
  }

  try {
    let userRecord;
    if (target.includes('@')) {
      userRecord = await auth.getUserByEmail(target.trim().toLowerCase());
    } else {
      userRecord = await auth.getUser(target.trim());
    }

    const uid = userRecord.uid;
    console.log(`[BOOTSTRAP] Target user found: ${userRecord.email} (${uid})`);

    // 1. Set Custom Claims for instant token authorization
    const customClaims = {
      role: role,
      admin: ['admin', 'superadmin'].includes(role),
      superadmin: role === 'superadmin',
      staff: role === 'staff'
    };
    await auth.setCustomUserClaims(uid, customClaims);
    console.log(`[BOOTSTRAP] Successfully set Firebase Auth Custom Claims:`, customClaims);

    // 2. Synchronize Firestore profile
    await db.collection('users').doc(uid).set({
      uid: uid,
      email: userRecord.email,
      role: role,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: 'system_bootstrap_cli'
    }, { merge: true });

    // 3. Update system status initialization marker
    await db.collection('system').doc('status').set({
      initialized: true,
      lastAdminBootstrapAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log(`[BOOTSTRAP] SUCCESS: User ${userRecord.email} assigned role '${role}'.`);
    console.log(`[BOOTSTRAP] The user should log out and log back in to refresh their ID token.`);
  } catch (err) {
    console.error('[BOOTSTRAP] Error bootstrapping admin:', err.message);
    process.exit(1);
  }
}

bootstrap();
