// PetShop v473-barcode | TS: 2026-10-21 16:45 MYT
const CONFIG = {
  // Keep this empty in source control. Configure PETSHOP_SPREADSHEET_ID
  // in Script Properties, or set this value locally for a private install.
  SPREADSHEET_ID: '',
  CURRENCY: 'RM',
  SHEETS: {
    CUSTOMERS: 'Customers',
    PETS: 'Pets',
    MEMBERSHIP_PLANS: 'MembershipPlans',
    MEMBERSHIPS: 'Memberships',
    SERVICES: 'Services',
    PRODUCTS: 'Products',
    PROMOTIONS: 'Promotions',
    INVENTORY: 'Inventory',
    BOOKINGS: 'Bookings',
    BOARDING: 'Boarding',
    SALES: 'Sales',
    SALE_ITEMS: 'SaleItems',
    PAYMENTS: 'Payments',
    SETTINGS: 'Settings'
  }
};
const SCHEMA = {
  Customers: ['customer_id','name','phone','email','address','notes','photo_url','created_at','active'],
  Pets: ['pet_id','customer_id','name','species','breed','sex','dob','weight_kg','vaccination_due','allergies','temperament','notes','sticky_note','photo_url','created_at','active'],
  MembershipPlans: ['plan_id','name','price','duration_days','grooming_discount_pct','boarding_discount_pct','retail_discount_pct','points_multiplier','active'],
  Memberships: ['membership_id','customer_id','plan_id','start_date','expiry_date','status','points_balance','notes'],
  Services: ['service_id','name','category','price','duration_min','active'],
  Products: ['product_id','name','description','category','sku','barcode','price','cost','avg_cost','stock','reorder_level','photo_url','active'],
  Promotions: ['promotion_id','name','scope','product_id','product_ids','category','type','value','min_qty','start_date','end_date','allow_membership','active','notes','created_at','updated_at'],
  Bookings: ['booking_id','customer_id','pet_id','type','service_id','start_at','end_at','status','staff','notes','message','photo_url','calendar_color','created_at'],
  Boarding: ['boarding_id','customer_id','pet_id','service_id','check_in','check_out','room_id','room','feeding','care_notes','message','status','photo_url','calendar_color','created_at'],
  BoardingRooms: ['room_id','name','category','notes','photo_url','active','created_at','updated_at'],
  Sales: ['sale_id','customer_id','pet_id','sale_at','subtotal','discount','total','payment_method','membership_id','notes','created_by','receipt_photo_urls','source_type','source_id','source_ids','receipt_token','idempotency_key','sale_status'],
  SaleItems: ['sale_item_id','sale_id','item_type','item_id','description','qty','unit_price','discount','line_total'],
  Payments: ['payment_id','sale_id','paid_at','amount','method','reference','notes'],
  SaleRevisions: ['revision_id','sale_id','revision_no','revised_at','revised_by','change_summary','snapshot_json'],
  SaleAudit: ['log_id','sale_id','revision_id','changed_at','changed_by','action','changes_json'],
  GroomerWork: ['booking_id','pet_id','groomer_email','groomer_name','claimed_at','completed_at','updated_at','updated_by','before_photo_url','after_photo_url'],
  Inventory: ['movement_id','product_id','type','qty','unit_cost','stock_after','reference','created_at','created_by'],
  Settings: ['key','value']
};
// RELEASE MARKER — update these three values for every ZIP/deployment (keep in sync with Index.html).
const APP_RELEASE_VERSION = 'v443-cloudflare-gateway';
const APP_SCRIPT_VERSION = '179';
let RECEIPT_BACKGROUND_CONTEXT_ = false;
const APP_RELEASED_AT = '2026-10-21 16:45 MYT';
// Raw sale-ID public receipt links are disabled immediately; opaque receipt tokens only.
const RECEIPT_PHONE_FAIL_LIMIT_ = 5;
const RECEIPT_PHONE_LOCK_MINUTES_ = 15;
const RECEIPT_PHONE_RATE_WINDOW_SECONDS_ = 900;
const SECURITY_KEYS_ = { OWNER: 'PETSHOP_OWNER_EMAIL', USERS: 'PETSHOP_USERS_JSON' };
const PAYMENT_METHODS_ = ['Cash', 'Card', 'QR', 'Bank Transfer'];
const POINTS_PER_RM_ = 1; // membership points earned per RM of the sale total (x plan multiplier)
const AUTH_SESSION_PREFIX_ = 'PETSHOP_AUTH_SESSION_'; // Legacy property prefix; signed sessions no longer use stored session blobs.
const AUTH_SIGNING_SECRET_KEY_ = 'PETSHOP_AUTH_SIGNING_SECRET_V1';
const AUTH_USER_INDEX_KEY_ = 'PETSHOP_USER_EMAIL_INDEX_V1';
const AUTH_USER_PREFIX_ = 'PETSHOP_USER_RECORD_V1_';
const AUTH_PROFILE_INDEX_KEY_ = 'PETSHOP_PROFILE_EMAIL_INDEX_V1';
const AUTH_PROFILE_PREFIX_ = 'PETSHOP_PROFILE_RECORD_V1_';
const AUTH_GLOBAL_FAILURE_KEY_ = 'petshop_login_global_failures';
const AUTH_GLOBAL_LOCK_KEY_ = 'petshop_login_global_brake';
const AUTH_GLOBAL_FAILURE_LIMIT_ = 25;
const AUTH_GLOBAL_LOCK_SECONDS_ = 60;
const OWNER_RESET_CODE_KEY_ = 'PETSHOP_OWNER_PASSWORD_RESET_CODE';
const OWNER_RESET_CODE_EXPIRY_KEY_ = 'PETSHOP_OWNER_PASSWORD_RESET_EXPIRY';
const AUTH_BOOTSTRAP_KEY_ = 'PETSHOP_OWNER_BOOTSTRAP_CODE';
const AUTH_PASSWORD_ROUNDS_ = 5000;
const SESSION_HOURS = 'never'; // Default policy: keep sessions valid until explicit logout or account/security revocation.
const SESSION_TIMEOUT_KEY_ = 'PETSHOP_SESSION_TIMEOUT_HOURS';
const SESSION_POLICY_MIGRATION_KEY_ = 'PETSHOP_SESSION_POLICY_MIGRATION_V1';
const LOGIN_FAILURE_LIMIT_ = 5;
const LOGIN_LOCK_MINUTES_ = 15;
const STAFF_PRICE_OVERRIDE_ALLOWED_ = false;
// AUTH CONTEXT THREADING (v307): apiCall validates the token once and passes the resulting
// session as the first argument to every guarded API operation. Guarded helpers receive
// that same explicit session; no request identity is stored in shared global state.
// See AUTH_THREADING_v307.md for the call graph and required deployment concurrency tests.
function authDigest_(value) {
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(value), Utilities.Charset.UTF_8);
  return bytes.map(b => ('0' + ((b + 256) % 256).toString(16)).slice(-2)).join('');
}
function passwordHash_(password, salt) {
  let value = String(salt) + ':' + String(password);
  for (let i = 0; i < AUTH_PASSWORD_ROUNDS_; i++) value = authDigest_(value + ':' + i);
  return value;
}
function authUser_(email) {
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const users = getUsers_();
  const user = users[email] || {};
  if (!owner || (email !== owner && !users[email]) || user.active === false) return null;
  if (!user.passwordSalt || !user.passwordHash) return null;
  const profile = getStaffProfiles_()[email] || {};
  return { email: email, name: String(profile.name || user.name || email), role: email === owner ? 'OWNER' : String(user.role || 'STAFF'), active: user.active !== false };
}
function authSigningSecret_() {
  const props = PropertiesService.getScriptProperties();
  let secret = String(props.getProperty(AUTH_SIGNING_SECRET_KEY_) || '');
  if (!secret) {
    const lock = LockService.getScriptLock(); lock.waitLock(5000);
    try {
      secret = String(props.getProperty(AUTH_SIGNING_SECRET_KEY_) || '');
      if (!secret) { secret = Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid(); props.setProperty(AUTH_SIGNING_SECRET_KEY_, secret); }
    } finally { lock.releaseLock(); }
  }
  if (props.getProperty('PETSHOP_SIGNED_SESSION_MIGRATED_V1') !== '1') {
    const all = props.getProperties(); Object.keys(all).filter(k => k.indexOf(AUTH_SESSION_PREFIX_) === 0).forEach(k => props.deleteProperty(k));
    props.setProperty('PETSHOP_SIGNED_SESSION_MIGRATED_V1', '1');
  }
  return secret;
}
function authBase64Url_(text) { return Utilities.base64EncodeWebSafe(String(text), Utilities.Charset.UTF_8).replace(/=+$/g, ''); }
function authDecodeBase64Url_(text) { return Utilities.newBlob(Utilities.base64DecodeWebSafe(String(text))).getDataAsString('UTF-8'); }
function authSignPayload_(payload) {
  const encoded = authBase64Url_(JSON.stringify(payload));
  const sig = Utilities.computeHmacSha256Signature(encoded, authSigningSecret_(), Utilities.Charset.UTF_8);
  return encoded + '.' + Utilities.base64EncodeWebSafe(sig).replace(/=+$/g, '');
}
function authTokenRevoked_(token) { try { return CacheService.getScriptCache().get('petshop_revoked_' + authDigest_(token)) === '1'; } catch (e) { return false; } }
function authSession_(token) {
  token = String(token || '');
  if (!token || token.length > 4096 || token.indexOf('.') < 1 || authTokenRevoked_(token)) return null;
  const parts = token.split('.'); if (parts.length !== 2) return null;
  let payload;
  try {
    const expected = Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(parts[0], authSigningSecret_(), Utilities.Charset.UTF_8)).replace(/=+$/g, '');
    if (expected !== parts[1]) return null;
    payload = JSON.parse(authDecodeBase64Url_(parts[0]));
  } catch (e) { return null; }
  if (!payload || !payload.email || !Number(payload.startedAt) || !Number(payload.exp)) return null;
  const now = Date.now();
  // v332: when the owner setting is 'never', the exp baked into the token (set when it was issued, possibly under an older timeout) must not end the session.
  const neverPref = String(PropertiesService.getScriptProperties().getProperty(SESSION_TIMEOUT_KEY_) || String(SESSION_HOURS)).trim().toLowerCase() === 'never';
  if (!neverPref && now >= Number(payload.exp)) { if (payload.auditId) authAuditLogout_(payload.auditId, {userAgent:'Session expired'}); return null; }
  const email = String(payload.email).trim().toLowerCase();
  const user = authUser_(email);
  if (!user || Number(payload.sv || 0) !== Number((getUsers_()[email] || {}).sessionVersion || 0)) return null;
  const timeoutPref = String(PropertiesService.getScriptProperties().getProperty(SESSION_TIMEOUT_KEY_) || String(SESSION_HOURS)).trim().toLowerCase();
  const timeoutHours = timeoutPref === 'never' ? 0 : Number(timeoutPref);
  if (timeoutPref !== 'never' && (!Number.isFinite(timeoutHours) || timeoutHours <= 0 || now - Number(payload.startedAt) >= timeoutHours * 3600000)) return null;
  return { key: '', email: user.email, role: user.role, name: user.name, startedAt: Number(payload.startedAt), auditId: String(payload.auditId || ''), exp: Number(payload.exp) };
}
function authCreateSessionToken_(email, startedAt, auditId, user) {
  const timeoutPref = String(PropertiesService.getScriptProperties().getProperty(SESSION_TIMEOUT_KEY_) || String(SESSION_HOURS)).trim().toLowerCase();
  const timeoutHours = timeoutPref === 'never' ? 24 * 365 : Number(timeoutPref);
  const hours = Number.isFinite(timeoutHours) && timeoutHours > 0 ? Math.min(timeoutHours, 24 * 365) : (timeoutPref === 'never' ? 24 * 365 : 12);
  const payload = {email:email, startedAt:startedAt, auditId:auditId || '', sv:Number(user.sessionVersion || 0), exp:startedAt + hours * 3600000};
  return authSignPayload_(payload);
}
function authStatus(token) {
  const props = PropertiesService.getScriptProperties();
  // One-time migration: remove the legacy 12-hour default that caused unexpected logouts.
  // This does not disable explicit timeout choices made after this migration.
  if (props.getProperty(SESSION_POLICY_MIGRATION_KEY_) !== '1') {
    props.setProperty(SESSION_TIMEOUT_KEY_, 'never');
    props.setProperty(SESSION_POLICY_MIGRATION_KEY_, '1');
  }
  const owner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const users = getUsers_();
  const ownerUser = users[owner] || {};
  const configured = !!owner && !!(ownerUser.passwordSalt && ownerUser.passwordHash);
  const bootstrapPending = !!owner && !!props.getProperty(AUTH_BOOTSTRAP_KEY_);
  const session = authSession_(token);
  if (session) return { ok: true, user: { email: session.email, name: session.name, role: session.role }, startedAt: session.startedAt };
  // A leftover bootstrap code must never make an already-configured shop look uninitialized.
  if (configured && bootstrapPending) props.deleteProperty(AUTH_BOOTSTRAP_KEY_);
  return { ok: false, needsSetup: !configured, bootstrapPending: !configured && bootstrapPending, setupReady: !configured && bootstrapPending, configured: configured };
}
function authBootstrap(code, password) {
  const props = PropertiesService.getScriptProperties();
  const owner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const expected = String(props.getProperty(AUTH_BOOTSTRAP_KEY_) || '');
  if (!owner || !expected) throw new Error('Owner setup is not available. Run setup() from the Apps Script editor first.');
  if (!code || String(code) !== expected) throw new Error('Invalid or expired owner setup code.');
  password = String(password || '');
  if (password.length < 8) throw new Error('Use a password with at least 8 characters.');
  const users = getUsers_();
  const user = users[owner] || { role: 'OWNER', active: true };
  const salt = Utilities.getUuid() + Utilities.getUuid();
  user.role = 'OWNER'; user.active = true; user.passwordSalt = salt; user.passwordHash = passwordHash_(password, salt);
  users[owner] = user; saveUsers_(users); props.deleteProperty(AUTH_BOOTSTRAP_KEY_);
  return { ok: true, email: owner };
}
const AUTH_AUDIT_SHEET_ = 'AuthLog';
const AUTH_AUDIT_HEADERS_ = ['Session ID','Email','Login At','Logout At','Login IP','Logout IP','Device','Browser','User Agent','Language','Platform','Status'];
function authAuditSheet_() {
  const ss = getSS_();
  let sh = ss.getSheetByName(AUTH_AUDIT_SHEET_);
  if (!sh) sh = ss.insertSheet(AUTH_AUDIT_SHEET_);
  if (sh.getLastRow() === 0) sh.getRange(1, 1, 1, AUTH_AUDIT_HEADERS_.length).setValues([AUTH_AUDIT_HEADERS_]);
  const props=PropertiesService.getScriptProperties();
  if (props.getProperty('AUTH_LOG_TEXT_FORMAT_V1') !== '1') {
    formatPlainTextColumns_(sh, AUTH_AUDIT_HEADERS_);
    props.setProperty('AUTH_LOG_TEXT_FORMAT_V1','1');
  }
  return sh;
}
function authAuditDetails_(clientInfo) {
  const info = clientInfo && typeof clientInfo === 'object' ? clientInfo : {};
  const ua = String(info.userAgent || '').slice(0, 500);
  let browser = 'Unknown';
  if (/Edg\//i.test(ua)) browser = 'Microsoft Edge';
  else if (/OPR\//i.test(ua)) browser = 'Opera';
  else if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) browser = 'Google Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Mozilla Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';
  let device = 'Desktop';
  if (/iPad|Tablet/i.test(ua)) device = 'Tablet';
  else if (/Mobile|Android|iPhone|iPod/i.test(ua)) device = 'Mobile';
  return { userAgent: ua, browser: browser, device: device, ipAddress: String(info.ipAddress || '').slice(0, 64), language: String(info.language || '').slice(0, 40), platform: String(info.platform || '').slice(0, 100) };
}
function authAuditLogin_(email, clientInfo, startedAt) {
  try {
    const detail = authAuditDetails_(clientInfo), auditId = Utilities.getUuid();
    const sh = authAuditSheet_();
    sh.appendRow([auditId, email, new Date(startedAt), '', detail.ipAddress || 'Unavailable', '', detail.device, detail.browser, detail.userAgent, detail.language, detail.platform, 'ACTIVE']);
    return auditId;
  } catch (e) { console.warn('Could not write authentication audit log: ' + e); return ''; }
}
function authAuditLogout_(auditId, clientInfo) {
  if (!auditId) return;
  try {
    const sh = authAuditSheet_(), detail = authAuditDetails_(clientInfo);
    if (sh.getLastRow()<2) return;
    const match=sh.getRange(2,1,sh.getLastRow()-1,1).createTextFinder(String(auditId)).matchEntireCell(true).findNext();
    if(match){
      sh.getRange(match.getRow(),4).setValue(new Date());
      sh.getRange(match.getRow(),6).setValue(detail.ipAddress || 'Unavailable');
      sh.getRange(match.getRow(),12).setValue('LOGGED_OUT');
    }
  } catch (e) { console.warn('Could not update authentication audit log: ' + e); }
}
function loginThrottleKeys_(email) {
  const digest = authDigest_(String(email || '').trim().toLowerCase()).slice(0, 32);
  return { failures: 'petshop_login_fail_' + digest, locked: 'petshop_login_lock_' + digest };
}
function authLoginFailure_(email) {
  const cache = CacheService.getScriptCache(), keys = loginThrottleKeys_(email), lock = LockService.getScriptLock();
  lock.waitLock(5000);
  try {
    const globalCount = Number(cache.get(AUTH_GLOBAL_FAILURE_KEY_) || 0) + 1;
    cache.put(AUTH_GLOBAL_FAILURE_KEY_, String(globalCount), 300);
    if (globalCount >= AUTH_GLOBAL_FAILURE_LIMIT_) { cache.put(AUTH_GLOBAL_LOCK_KEY_, '1', AUTH_GLOBAL_LOCK_SECONDS_); cache.remove(AUTH_GLOBAL_FAILURE_KEY_); }
    if (cache.get(keys.locked)) return;
    const count = Number(cache.get(keys.failures) || 0) + 1;
    if (count >= LOGIN_FAILURE_LIMIT_) { cache.put(keys.locked, '1', LOGIN_LOCK_MINUTES_ * 60); cache.remove(keys.failures); }
    else cache.put(keys.failures, String(count), LOGIN_LOCK_MINUTES_ * 60);
  } finally { lock.releaseLock(); }
}
function authLogin(email, password, clientInfo) {
  email = String(email || '').trim().toLowerCase();
  password = String(password || '');
  const cache = CacheService.getScriptCache(), throttleKeys = loginThrottleKeys_(email);
  if (cache.get(AUTH_GLOBAL_LOCK_KEY_)) throw new Error('Unable to sign in. Check your details or try again later.');
  if (cache.get(throttleKeys.locked)) throw new Error('Unable to sign in. Check your details or try again later.');
  const props = PropertiesService.getScriptProperties();
  const owner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const users = getUsers_();
  const user = users[email] || {};
  // Perform a hash even for unknown accounts to reduce obvious timing differences.
  const salt = String(user.passwordSalt || 'petshop-invalid-account-salt');
  const candidate = passwordHash_(password, salt);
  if (!email || !owner || !user.passwordHash || candidate !== user.passwordHash || user.active === false || (email !== owner && !users[email])) {
    authLoginFailure_(email);
    throw new Error('Unable to sign in. Check your details or try again later.');
  }
  cache.remove(throttleKeys.failures);
  cache.remove(throttleKeys.locked);
  cache.remove(AUTH_GLOBAL_FAILURE_KEY_);
  const startedAt = Date.now();
  const auditId = authAuditLogin_(email, clientInfo, startedAt);
  const token = authCreateSessionToken_(email, startedAt, auditId, user);
  const profile = getStaffProfiles_()[email] || {};
  return { ok: true, token: token, startedAt: startedAt, user: { email: email, name: String(profile.name || user.name || email), role: email === owner ? 'OWNER' : String(user.role || 'STAFF') } };
}
function authLogout(token, clientInfo) {
  token = String(token || '');
  if (token) {
    const session = authSession_(token);
    if (session) {
      // Session versioning revokes every token for this account immediately without a stored session list.
      const lock = LockService.getScriptLock(); lock.waitLock(10000);
      try {
        const users = getUsers_(), user = users[session.email];
        if (user) { user.sessionVersion = Number(user.sessionVersion || 0) + 1; users[session.email] = user; saveUsers_(users); }
      } finally { lock.releaseLock(); }
      if (session.auditId) authAuditLogout_(session.auditId, clientInfo);
    }
    try { CacheService.getScriptCache().put('petshop_revoked_' + authDigest_(token), '1', 21600); } catch (e) {}
  }
  return { ok: true };
}
function authChangePassword(token, currentPassword, newPassword) {
  const session = authSession_(token);
  if (!session) throw new Error('Your session has expired. Please sign in again.');
  currentPassword = String(currentPassword || ''); newPassword = String(newPassword || '');
  if (newPassword.length < 8) throw new Error('Use a password with at least 8 characters.');
  if (currentPassword === newPassword) throw new Error('Choose a password different from your current password.');
  const lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    const users = getUsers_(), user = users[session.email];
    if (!user || passwordHash_(currentPassword, user.passwordSalt || '') !== user.passwordHash) throw new Error('Current password is incorrect.');
    const salt = Utilities.getUuid() + Utilities.getUuid();
    user.passwordSalt = salt; user.passwordHash = passwordHash_(newPassword, salt); user.sessionVersion = Number(user.sessionVersion || 0) + 1;
    users[session.email] = user; saveUsers_(users);
    if (session.auditId) authAuditLogout_(session.auditId, {userAgent:'Password changed; all sessions invalidated'});
  } finally { lock.releaseLock(); }
  return {ok:true, reauthenticate:true};
}
function issueOwnerPasswordResetCode() {
  const props = PropertiesService.getScriptProperties();
  const owner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const active = String(Session.getActiveUser().getEmail() || '').trim().toLowerCase();
  const effective = String(Session.getEffectiveUser().getEmail() || '').trim().toLowerCase();
  if (!owner || !active || active !== owner || effective !== owner) throw new Error('Run this function from the Apps Script editor while signed in as the configured shop owner.');
  const code = Utilities.getUuid() + '-' + Utilities.getUuid() + '-' + Utilities.getUuid();
  props.setProperty(OWNER_RESET_CODE_KEY_, authDigest_(code));
  props.setProperty(OWNER_RESET_CODE_EXPIRY_KEY_, String(Date.now() + 15 * 60 * 1000));
  console.log('Owner password reset code (valid 15 minutes; keep private): ' + code);
  Logger.log('Owner password reset code (valid 15 minutes; keep private): ' + code);
  return 'Reset code issued. Copy it from the execution log; it expires in 15 minutes.';
}
function authResetOwnerPassword(code, newPassword) {
  code = String(code || ''); newPassword = String(newPassword || '');
  if (newPassword.length < 8) throw new Error('Use a password with at least 8 characters.');
  const props = PropertiesService.getScriptProperties(), expected = String(props.getProperty(OWNER_RESET_CODE_KEY_) || ''), expires = Number(props.getProperty(OWNER_RESET_CODE_EXPIRY_KEY_) || 0);
  if (!expected || !expires || Date.now() > expires || authDigest_(code) !== expected) throw new Error('Reset code is invalid or expired. Run issueOwnerPasswordResetCode() again.');
  const owner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (!owner) throw new Error('Owner account is not configured.');
  const lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    const users = getUsers_(), user = users[owner] || {role:'OWNER', active:true};
    const salt = Utilities.getUuid() + Utilities.getUuid();
    user.role = 'OWNER'; user.active = true; user.passwordSalt = salt; user.passwordHash = passwordHash_(newPassword, salt); user.sessionVersion = Number(user.sessionVersion || 0) + 1;
    users[owner] = user; saveUsers_(users);
    props.deleteProperty(OWNER_RESET_CODE_KEY_); props.deleteProperty(OWNER_RESET_CODE_EXPIRY_KEY_);
    CacheService.getScriptCache().removeAll([AUTH_GLOBAL_FAILURE_KEY_, AUTH_GLOBAL_LOCK_KEY_]);
  } finally { lock.releaseLock(); }
  return {ok:true, reauthenticate:true};
}
const AUTH_API_FUNCTIONS_ = {
  applyMutationBatch: applyMutationBatch, outcome_lookup: outcome_lookup, getProcessingSaleResolution: getProcessingSaleResolution, resolveProcessingSale: resolveProcessingSale, discardMutation: discardMutation, registerOfflineDiscard: registerOfflineDiscard, getMutationLedgerHealth: getMutationLedgerHealth,
  getDataVersion: getDataVersion, getPageData: getPageData, getData: getData, search: search,
  getCompanySettings: getCompanySettings, saveCompanySettings: saveCompanySettings,
  getSessionTimeoutSetting: getSessionTimeoutSetting, saveSessionTimeoutSetting: saveSessionTimeoutSetting,
  getRolePagePermissions: getRolePagePermissions, saveRolePagePermissions: saveRolePagePermissions,
  getStaffMembers: getStaffMembers, saveStaffProfile: saveStaffProfile, addStaffMember: addStaffMember,
  getStaffProfilePage: getStaffProfilePage, getStaffProfilePages: getStaffProfilePages,
  saveStaffRole: saveStaffRole, saveStaffStatus: saveStaffStatus, saveStaffPassword: saveStaffPassword, deleteStaffMember: deleteStaffMember,
  setCustomerActive: setCustomerActive, deleteCustomer: deleteCustomer,
  getGroomerCommissionData: getGroomerCommissionData, getStaffCommissionReport: getStaffCommissionReport,
  saveGroomerCommissionRates: saveGroomerCommissionRates, saveStaffCommissionRates: saveStaffCommissionRates,
  getReceiptPrintHtml: getReceiptPrintHtmlApi_, emailSaleReceipt: emailSaleReceipt, getReceiptPdfLink: getReceiptPdfLink, getReceiptWhatsAppLinks: getReceiptWhatsAppLinks,
  preGenerateReceipt: preGenerateReceipt, syncReceiptBatch: syncReceiptBatch, getReceiptStatuses: getReceiptStatuses, startReceiptSync: startReceiptSync, getReceiptSyncProgress: getReceiptSyncProgress, processReceiptSyncQueue_: processReceiptSyncQueue_,
  getReceiptHtml: getReceiptHtml, getReceiptPdf: getReceiptPdf, regenerateReceiptLink: regenerateReceiptLink, getSaleDetails: getSaleDetails, getSaleDetailsBatch: getSaleDetailsBatch, getSaleAudit: getSaleAudit, getSalesPageData: getSalesPageData,
  uploadImage: uploadImage, saveReceiptPhotos: saveReceiptPhotos, deletePhoto: deletePhoto, getPhotoData: getPhotoData,
  saveCustomer: saveCustomer, savePet: savePet, saveMembershipPlan: saveMembershipPlan, saveMembership: saveMembership,
  saveBooking: saveBooking, saveBoarding: saveBoarding, saveBoardingBatch: saveBoardingBatch, saveBoardingRoom: saveBoardingRoom, deleteBoardingRoom: deleteBoardingRoom, getBoardingRoomAvailability: getBoardingRoomAvailability, editSaleReceipt: editSaleReceipt, makeSale: makeSale,
  claimGroomingPet: claimGroomingPet, claimAndCompleteGroomingPet: claimAndCompleteGroomingPet, assignGroomingPet: assignGroomingPet, getGroomerAssignees: getGroomerAssignees, saveGroomingWorkPhotos: saveGroomingWorkPhotos, completeGroomingPet: completeGroomingPet,
  saveProductCategory: saveProductCategory, deleteProductCategory: deleteProductCategory, receiveInventory: receiveInventory,
  saveService: saveService, saveProduct: saveProduct, savePromotion: savePromotion, deletePromotion: deletePromotion,
  deleteMembership: deleteMembership, deleteProduct: deleteProduct,
  deleteService: deleteService, deleteBooking: deleteBooking, deleteBoarding: deleteBoarding, deletePet: deletePet,
  lookupBarcode: lookupBarcode,
  importProductImageFromUrl: importProductImageFromUrl,
  getRuntimeInfo: getRuntimeInfo
};
const ROLE_PAGE_PERMISSIONS_KEY_ = 'PETSHOP_ROLE_PAGE_PERMISSIONS_JSON';
const ROLE_PAGE_DEFAULTS_ = {
  STAFF: { sales: false, reports: false, settings: false, catalog: true, staff: false },
  MANAGER: { sales: true, reports: true, settings: false, catalog: true, staff: true }
};
function getRolePagePermissions_() {
  const raw = PropertiesService.getScriptProperties().getProperty(ROLE_PAGE_PERMISSIONS_KEY_);
  let saved = {};
  if (raw) { try { saved = JSON.parse(raw) || {}; } catch (e) { saved = {}; } }
  const out = {};
  ['STAFF','MANAGER'].forEach(role => {
    out[role] = {};
    Object.keys(ROLE_PAGE_DEFAULTS_[role]).forEach(page => {
      out[role][page] = saved[role] && typeof saved[role][page] === 'boolean' ? saved[role][page] : ROLE_PAGE_DEFAULTS_[role][page];
    });
  });
  return out;
}
function getRolePagePermissions(_authSession) { requireRole_(_authSession, ['OWNER']); return getRolePagePermissions_(); }
function saveRolePagePermissions(_authSession, data) {
  requireRole_(_authSession, ['OWNER']);
  if (!data || typeof data !== 'object') throw new Error('Invalid role permissions.');
  const clean = {};
  ['STAFF','MANAGER'].forEach(role => {
    clean[role] = {};
    Object.keys(ROLE_PAGE_DEFAULTS_[role]).forEach(page => {
      clean[role][page] = page === 'staff' && role === 'STAFF' ? false : !!(data[role] && data[role][page] === true);
    });
  });
  PropertiesService.getScriptProperties().setProperty(ROLE_PAGE_PERMISSIONS_KEY_, JSON.stringify(clean));
  bumpVersion_();
  return clean;
}
function roleCanOpenPage_(role, page) {
  role = String(role || '').toUpperCase(); page = String(page || '').toLowerCase();
  if (role === 'OWNER') return true;
  if (page === 'settings') return false;
  if (page === 'staff') return role === 'MANAGER' && !!getRolePagePermissions_().MANAGER.staff;
  if (['sales','reports','catalog'].includes(page)) return !!getRolePagePermissions_()[role]?.[page];
  return true;
}
function validateIdsDeep_(value, path) {
  if (!value || typeof value !== 'object') return;
  Object.keys(value).forEach(key => {
    const item = value[key], fieldPath = path ? path + '.' + key : key;
    if (/_id$/i.test(key)) {
      if (item == null || String(item).trim() === '') return;
      if (!/^[A-Za-z0-9_-]{1,40}$/.test(String(item))) throw new Error('Invalid identifier in request: ' + fieldPath + '.');
      return;
    }
    if (Array.isArray(item)) item.forEach((entry, index) => validateIdsDeep_(entry, fieldPath + '[' + index + ']'));
    else if (item && typeof item === 'object') validateIdsDeep_(item, fieldPath);
  });
}
function validateIdArguments_(operation, args) {
  const op=String(operation||''), values=Array.isArray(args)?args:[];
  const scalarIdOps=new Set(['getSaleDetails','getSaleAudit','getReceiptPrintHtml','getReceiptPdfLink','getReceiptWhatsAppLinks','getReceiptHtml','getReceiptPdf','regenerateReceiptLink','preGenerateReceipt','emailSaleReceipt','deleteMembership','deleteProduct','deletePromotion','deleteService','deleteBooking','deleteBoarding','deletePet','claimGroomingPet','claimAndCompleteGroomingPet','assignGroomingPet','completeGroomingPet','saveGroomingWorkPhotos','getGroomerAssignees']);
  const listIdOps=new Set(['getSaleDetailsBatch','getReceiptStatuses','syncReceiptBatch']);
  if(scalarIdOps.has(op)&&values[0]!=null&&String(values[0]).trim()!==''&&!/^[A-Za-z0-9_-]{1,40}$/.test(String(values[0]))) throw new Error('Invalid identifier for '+op+'.');
  if(listIdOps.has(op)&&Array.isArray(values[0])) values[0].forEach(id=>{if(String(id||'').trim()&&!/^[A-Za-z0-9_-]{1,40}$/.test(String(id)))throw new Error('Invalid identifier for '+op+'.');});
  if(op==='saveReceiptPhotos'&&values[0]!=null&&String(values[0]).trim()&&!/^[A-Za-z0-9_-]{1,40}$/.test(String(values[0]))) throw new Error('Invalid sale identifier.');
  if(op==='deletePhoto'||op==='getPhotoData') {
    const m=String(values[0]||'').match(/[?&]id=([A-Za-z0-9_-]+)/);
    if(!m) throw new Error('Invalid photo URL.');
    if(!/^(Customers|Pets|Products|Bookings|Boarding|Sales|GroomerWork)$/.test(String(values[1]||'')) ||
       !/^[A-Za-z0-9_-]{1,40}$/.test(String(values[2]||''))) {
      throw new Error('A valid photo record type and record ID are required.');
    }
  }
}
function apiCall(name, args, token) {
  const correlationId = Utilities.getUuid();
  validateIdsDeep_(args, 'args');
  validateIdArguments_(name,args);
  const fn = AUTH_API_FUNCTIONS_[String(name || '')];
  if (!fn) throw new Error('Unsupported PetShop operation.');
  const session = authSession_(token);
  if (!session) throw new Error('PetShop session is invalid. Please sign in again.');
  const op = String(name || '');
  const page = op === 'getPageData' ? String((args || [])[0] || '') : '';
  if (page && !roleCanOpenPage_(session.role, page)) throw new Error('Permission denied. Your role does not have access to this page.');
  if (['getCompanySettings','saveCompanySettings','getSessionTimeoutSetting','saveSessionTimeoutSetting','getMutationLedgerHealth','saveStaffProfile','addStaffMember','saveStaffRole','saveStaffStatus','saveStaffPassword','getGroomerCommissionData','getStaffCommissionReport','saveGroomerCommissionRates'].includes(op) && !roleCanOpenPage_(session.role, 'settings')) throw new Error('Permission denied. Your role does not have access to Settings.');
  if (['getStaffMembers','getStaffProfilePage','getStaffProfilePages','saveStaffCommissionRates'].includes(op) && !roleCanOpenPage_(session.role, 'staff')) throw new Error('Permission denied. Your role does not have access to the Staff page.');
  if (['getSaleDetails','getSaleDetailsBatch','getReceiptPrintHtml','emailSaleReceipt','getReceiptPdfLink','getReceiptHtml','getReceiptPdf','regenerateReceiptLink','editSaleReceipt','preGenerateReceipt','syncReceiptBatch','getReceiptStatuses','startReceiptSync','getReceiptSyncProgress','processReceiptSyncQueue_','getSaleAudit','outcome_lookup','getProcessingSaleResolution','resolveProcessingSale','discardMutation'].includes(op) && !roleCanOpenPage_(session.role, 'sales')) throw new Error('Permission denied. Your role does not have access to Sales.');
  const staffBlocked = ['getStaffMembers','getStaffProfilePage','getStaffProfilePages','saveStaffProfile','addStaffMember','saveStaffRole','saveStaffStatus','saveStaffPassword','saveProductCategory','deleteProductCategory','receiveInventory'];
  const managerOrOwnerOnly = ['saveService','saveProduct','deleteProduct','deleteService','deleteMembership','saveMembershipPlan'];
  if (session.role === 'STAFF' && (staffBlocked.includes(op) || managerOrOwnerOnly.includes(op))) throw new Error('Permission denied. Ask your shop owner or manager.');
  console.log('AUTH_THREADING v307 correlation=' + correlationId + ' operation=' + op + ' email=' + String(session.email || '').toLowerCase());
  return fn.apply(null, [session].concat(Array.isArray(args) ? args : []));
}
function currentUser_() {
  return String(Session.getActiveUser().getEmail() || '').trim().toLowerCase();
}
function getAppAccount() {
  // Legacy compatibility only: never expose the deploying or visitor Google identity.
  return { auth_provider: 'PetShop', signed_in: false };
}
function requireUserEmail_(_authSession) {
  if (_authSession == null) throw new Error('PetShop session required. Please sign in again.');
  if (!_authSession.email) throw new Error('Your PetShop session is no longer valid. Please sign in again.');
  return _authSession.email;
}
const USERS_CACHE_KEY_ = 'petshop_users_json_v2';
function authRecordKey_(prefix, email) { return prefix + authDigest_(String(email || '').trim().toLowerCase()).slice(0, 40); }
function getUsers_() {
  const cache = CacheService.getScriptCache(), cached = cache.get(USERS_CACHE_KEY_);
  if (cached) { try { return JSON.parse(cached) || {}; } catch (e) { cache.remove(USERS_CACHE_KEY_); } }
  const props = PropertiesService.getScriptProperties();
  let index = []; try { index = JSON.parse(props.getProperty(AUTH_USER_INDEX_KEY_) || '[]'); } catch (e) { index = []; }
  const users = {};
  if (Array.isArray(index) && index.length) {
    index.forEach(email => { const e=String(email||'').trim().toLowerCase(); if (!e) return; try { const raw=props.getProperty(authRecordKey_(AUTH_USER_PREFIX_,e)); if(raw) users[e]=JSON.parse(raw); } catch (err) {} });
  } else {
    const legacy = props.getProperty(SECURITY_KEYS_.USERS);
    if (legacy) {
      let old; try { old=JSON.parse(legacy)||{}; } catch (e) { throw new Error('Security configuration is corrupted.'); }
      Object.keys(old).forEach(email => { const e=String(email).trim().toLowerCase(); if(e) { users[e]=old[email]; props.setProperty(authRecordKey_(AUTH_USER_PREFIX_,e),JSON.stringify(old[email])); } });
      props.setProperty(AUTH_USER_INDEX_KEY_,JSON.stringify(Object.keys(users)));
      props.deleteProperty(SECURITY_KEYS_.USERS);
    }
  }
  const owner=String(props.getProperty(SECURITY_KEYS_.OWNER)||'').trim().toLowerCase();
  if (owner && !users[owner]) { const raw=props.getProperty(authRecordKey_(AUTH_USER_PREFIX_,owner)); if(raw) { try { users[owner]=JSON.parse(raw); } catch(e) {} } }
  try { cache.put(USERS_CACHE_KEY_, JSON.stringify(users), 120); } catch (e) {}
  return users;
}
function saveUsers_(users) {
  users = users || {}; const props=PropertiesService.getScriptProperties();
  const oldIndex=[]; try { const x=JSON.parse(props.getProperty(AUTH_USER_INDEX_KEY_)||'[]'); if(Array.isArray(x)) oldIndex.push(...x); } catch(e) {}
  const emails=Object.keys(users).map(e=>String(e).trim().toLowerCase()).filter(Boolean);
  Object.keys(users).forEach(email => { const e=String(email).trim().toLowerCase(); if(e) props.setProperty(authRecordKey_(AUTH_USER_PREFIX_,e),JSON.stringify(users[email])); });
  oldIndex.map(e=>String(e).trim().toLowerCase()).filter(e=>e&&!users[e]).forEach(e=>props.deleteProperty(authRecordKey_(AUTH_USER_PREFIX_,e)));
  props.setProperty(AUTH_USER_INDEX_KEY_,JSON.stringify(emails)); props.deleteProperty(SECURITY_KEYS_.USERS);
  CacheService.getScriptCache().remove(USERS_CACHE_KEY_);
}
const STAFF_PROFILES_KEY_ = 'PETSHOP_STAFF_PROFILES_JSON';
function staffSheetContext_() {
  // Staff profiles and directory metadata must come from the configured Staff sheet.
  // Fail visibly instead of silently falling back to stale Script Properties.
  const ss = getSS_(false);
  const sheet = ss.getSheetByName('Staff');
  if (!sheet || sheet.getLastRow() < 1 || sheet.getLastColumn() < 1) {
    throw new Error('Staff sheet is missing or empty. Restore the migrated Staff sheet before using staff features.');
  }
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getDisplayValues()[0].map(v => String(v || '').trim().toLowerCase());
  const index = {};
  headers.forEach((h, i) => { if (h) index[h] = i; });
  if (index.email === undefined) throw new Error('Staff sheet is missing the email column.');
  return { sheet: sheet, headers: headers, index: index };
}
function getStaffProfiles_() {
  const staffSheet = staffSheetContext_();
  const profiles = {};
  const sheet = staffSheet.sheet, idx = staffSheet.index, lastRow = sheet.getLastRow();
  if (lastRow > 1) {
    const rows = sheet.getRange(2, 1, lastRow - 1, staffSheet.headers.length).getValues();
    rows.forEach(row => {
      const email = String(row[idx.email] || '').trim().toLowerCase();
      if (!email) return;
      profiles[email] = {
        name: idx.name === undefined ? '' : String(row[idx.name] || ''),
        phone: idx.phone === undefined ? '' : String(row[idx.phone] || ''),
        job_title: idx.job_title === undefined ? '' : String(row[idx.job_title] || ''),
        notes: idx.notes === undefined ? '' : String(row[idx.notes] || ''),
        photo_url: idx.photo_url === undefined ? '' : String(row[idx.photo_url] || '')
      };
    });
  }
  return profiles;
}
function saveStaffProfiles_(profiles) {
  profiles = profiles || {};
  const staffSheet = staffSheetContext_();
  const sheet = staffSheet.sheet, headers = staffSheet.headers, idx = staffSheet.index;
  const lastRow = sheet.getLastRow(), rowByEmail = {};
  if (lastRow > 1) sheet.getRange(2, 1, lastRow - 1, headers.length).getValues().forEach((row, i) => {
    const email = String(row[idx.email] || '').trim().toLowerCase(); if (email) rowByEmail[email] = i + 2;
  });
  const users = getUsers_();
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  Object.keys(profiles).forEach(rawEmail => {
    const email = String(rawEmail || '').trim().toLowerCase(); if (!email) return;
    const rowNum = rowByEmail[email];
    const row = rowNum ? sheet.getRange(rowNum, 1, 1, headers.length).getValues()[0] : Array(headers.length).fill('');
    const profile = profiles[rawEmail] || {};
    if (idx.staff_id !== undefined && !row[idx.staff_id]) row[idx.staff_id] = email;
    row[idx.email] = email;
    ['name','phone','job_title','notes','photo_url'].forEach(key => { if (idx[key] !== undefined) row[idx[key]] = String(profile[key] || ''); });
    if (idx.role !== undefined) row[idx.role] = email === owner ? 'OWNER' : String((users[email] || {}).role || row[idx.role] || 'STAFF');
    if (idx.active !== undefined) row[idx.active] = email === owner ? true : ((users[email] || {}).active !== undefined ? (users[email] || {}).active !== false : row[idx.active] !== false);
    if (idx.is_owner !== undefined) row[idx.is_owner] = email === owner;
    if (idx.migrated_at !== undefined && !row[idx.migrated_at]) row[idx.migrated_at] = new Date();
    if (rowNum) sheet.getRange(rowNum, 1, 1, headers.length).setValues([row]);
    else sheet.appendRow(row);
  });
}
function syncStaffSheetAccountMeta_(email, user) {
  email = String(email || '').trim().toLowerCase();
  if (!email) throw new Error('Staff email is required to update the Staff sheet.');
  const staffSheet = staffSheetContext_();
  const sheet = staffSheet.sheet, headers = staffSheet.headers, idx = staffSheet.index;
  const lastRow = sheet.getLastRow();
  let rowNum = 0, row = Array(headers.length).fill('');
  if (lastRow > 1) {
    const values = sheet.getRange(2, 1, lastRow - 1, headers.length).getValues();
    for (let i = 0; i < values.length; i++) {
      if (String(values[i][idx.email] || '').trim().toLowerCase() === email) { rowNum = i + 2; row = values[i]; break; }
    }
  }
  if (!rowNum) {
    if (idx.staff_id !== undefined) row[idx.staff_id] = email;
    row[idx.email] = email;
  }
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (idx.role !== undefined) row[idx.role] = email === owner ? 'OWNER' : String((user || {}).role || 'STAFF');
  if (idx.active !== undefined) row[idx.active] = email === owner ? true : (user || {}).active !== false;
  if (idx.is_owner !== undefined) row[idx.is_owner] = email === owner;
  if (idx.migrated_at !== undefined && !row[idx.migrated_at]) row[idx.migrated_at] = new Date();
  if (rowNum) sheet.getRange(rowNum, 1, 1, headers.length).setValues([row]);
  else sheet.appendRow(row);
}
function staffDirectory_(_authSession) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  const props = PropertiesService.getScriptProperties();
  const owner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const users = getUsers_();
  const profiles = getStaffProfiles_();
  // Include every profile migrated to Staff, even if this script project's
  // authentication properties currently contain only the owner account.
  const emails = [...new Set(Object.keys(users).concat(Object.keys(profiles), owner ? [owner] : []))];
  const staffSheet = staffSheetContext_();
  const sheetMeta = {};
  if (staffSheet) {
    const sheet = staffSheet.sheet, idx = staffSheet.index, lastRow = sheet.getLastRow();
    if (lastRow > 1) sheet.getRange(2, 1, lastRow - 1, staffSheet.headers.length).getValues().forEach(row => {
      const email = String(row[idx.email] || '').trim().toLowerCase();
      if (!email) return;
      sheetMeta[email] = {
        role: idx.role === undefined ? '' : String(row[idx.role] || '').trim().toUpperCase(),
        active: idx.active === undefined ? undefined : !(row[idx.active] === false || String(row[idx.active]).trim().toLowerCase() === 'false' || String(row[idx.active]).trim() === '0'),
        is_owner: idx.is_owner === undefined ? undefined : (row[idx.is_owner] === true || String(row[idx.is_owner]).trim().toLowerCase() === 'true')
      };
    });
  }
  return emails.map(rawEmail => {
    const email = String(rawEmail || '').trim().toLowerCase();
    const user = users[email] || {};
    const profile = profiles[email] || {};
    const meta = sheetMeta[email] || {};
    const isOwner = email === owner || meta.is_owner === true;
    return {
      email: email,
      name: String(profile.name || user.name || ''),
      phone: String(profile.phone || ''),
      job_title: String(profile.job_title || ''),
      notes: String(profile.notes || ''),
      photo_url: String(profile.photo_url || ''),
      role: isOwner ? 'OWNER' : String(meta.role || user.role || 'STAFF'),
      active: isOwner ? true : (meta.active !== undefined ? meta.active : user.active !== false),
      is_owner: isOwner
    };
  }).sort((a,b) => (a.is_owner ? -1 : b.is_owner ? 1 : a.name.localeCompare(b.name)));
}
function getStaffMembers(_authSession) { return staffDirectory_(_authSession); }
function saveStaffProfile(_authSession, data) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  data = data || {};
  const email = String(data.email || '').trim().toLowerCase();
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid staff email.');
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const users = getUsers_();
  if (email !== owner && !users[email]) throw new Error('Staff account not found. Add the account first.');
  const profiles = getStaffProfiles_();
  const previous = profiles[email] || {};
  profiles[email] = { ...previous, name: String(data.name || '').trim(), phone: normalizePhone_(data.phone), job_title: String(data.job_title || '').trim(), notes: data.notes === undefined ? String(previous.notes || '') : String(data.notes || '').trim().slice(0,5000), photo_url: data.photo_url === undefined ? String(previous.photo_url || '') : String(data.photo_url || '').trim() };
  saveStaffProfiles_(profiles);
  return staffDirectory_(_authSession);
}
function addStaffMember(_authSession, data) {
  requireRole_(_authSession, ['OWNER']);
  data = data || {};
  const name = String(data.name || '').trim();
  const email = String(data.email || '').trim().toLowerCase();
  const role = String(data.role || 'STAFF').trim().toUpperCase();
  if (!name) throw new Error('Staff name is required.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid staff email.');
  if (['STAFF','MANAGER'].indexOf(role) < 0) throw new Error('Invalid staff role.');
  const password = String(data.password || '');
  if (password.length < 8) throw new Error('Set a staff password with at least 8 characters.');
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  const users = getUsers_();
  if (email === owner || users[email]) throw new Error('That email already has a PetShop account.');
  const salt = Utilities.getUuid() + Utilities.getUuid();
  users[email] = { role: role, active: true, passwordSalt: salt, passwordHash: passwordHash_(password, salt) };
  saveUsers_(users);
  const profiles = getStaffProfiles_();
  profiles[email] = { name: name, phone: normalizePhone_(data.phone), job_title: String(data.job_title || '').trim(), notes: String(data.notes || '').trim().slice(0,5000), photo_url: String(data.photo_url || '').trim() };
  saveStaffProfiles_(profiles);
  bumpVersion_();
  return staffDirectory_(_authSession);
}
function saveStaffRole(_authSession, data) {
  requireRole_(_authSession, ['OWNER']);
  data = data || {};
  const email = String(data.email || '').trim().toLowerCase();
  const role = String(data.role || '').trim().toUpperCase();
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (!email || email === owner) throw new Error('The owner role cannot be changed.');
  if (['STAFF','MANAGER'].indexOf(role) < 0) throw new Error('Invalid staff role.');
  const users = getUsers_();
  if (!users[email]) throw new Error('Staff account not found.');
  users[email].role = role; users[email].sessionVersion = Number(users[email].sessionVersion || 0) + 1;
  saveUsers_(users);
  syncStaffSheetAccountMeta_(email, users[email]);
  bumpVersion_();
  return staffDirectory_(_authSession);
}
function saveStaffStatus(_authSession, data) {
  requireRole_(_authSession, ['OWNER']);
  data = data || {};
  const email = String(data.email || '').trim().toLowerCase();
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (!email || email === owner) throw new Error('The owner account cannot be deactivated.');
  const users = getUsers_();
  if (!users[email]) throw new Error('Staff account not found.');
  users[email].active = data.active === true; users[email].sessionVersion = Number(users[email].sessionVersion || 0) + 1;
  saveUsers_(users);
  syncStaffSheetAccountMeta_(email, users[email]);
  bumpVersion_();
  return staffDirectory_(_authSession);
}
function saveStaffPassword(_authSession, data) {
  requireRole_(_authSession, ['OWNER']);
  data = data || {};
  const email = String(data.email || '').trim().toLowerCase();
  const password = String(data.password || '');
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (!email || email === owner) throw new Error('Use the owner password setup to change the owner password.');
  if (password.length < 8) throw new Error('Use a password with at least 8 characters.');
  const users = getUsers_();
  if (!users[email]) throw new Error('Staff account not found.');
  const salt = Utilities.getUuid() + Utilities.getUuid();
  users[email].passwordSalt = salt; users[email].passwordHash = passwordHash_(password, salt); users[email].sessionVersion = Number(users[email].sessionVersion || 0) + 1;
  saveUsers_(users); bumpVersion_();
  return { ok: true };
}
function deleteStaffMember(_authSession, email) {
  requireRole_(_authSession, ['OWNER']);
  email = String(email || '').trim().toLowerCase();
  const owner = String(PropertiesService.getScriptProperties().getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (!email || email === owner) throw new Error('The owner account cannot be deleted.');
  const users = getUsers_();
  if (!users[email]) throw new Error('Staff account not found.');
  const mine = v => String(v || '').trim().toLowerCase() === email;
  const used = rows_('GroomerWork').some(r => mine(r.groomer_email)) || rows_('Bookings').some(r => mine(r.staff)) ||
    rows_('Sales').some(r => mine(r.created_by)) || rows_('Inventory').some(r => mine(r.created_by)) ||
    rows_('SaleRevisions').some(r => mine(r.revised_by)) || rows_('SaleAudit').some(r => mine(r.changed_by));
  if (used) throw new Error('This staff member has recorded work (sales, grooming or audit history), so the account cannot be deleted. Retire the account instead.');
  const lock = LockService.getScriptLock(); lock.waitLock(10000);
  try {
    delete users[email]; saveUsers_(users);
    const ctx = staffSheetContext_(), sh = ctx.sheet, idx = ctx.index, last = sh.getLastRow();
    if (last > 1) {
      const vals = sh.getRange(2, 1, last - 1, ctx.headers.length).getValues();
      for (let i = vals.length - 1; i >= 0; i--) if (String(vals[i][idx.email] || '').trim().toLowerCase() === email) sh.deleteRow(i + 2);
    }
    const props = PropertiesService.getScriptProperties();
    try { const rates = getStaffCommissionRates_(); if (rates[email] !== undefined) { delete rates[email]; props.setProperty(STAFF_COMMISSION_KEY_, JSON.stringify(rates)); } } catch (e) {}
  } finally { lock.releaseLock(); }
  bumpVersion_(['Staff']);
  return staffDirectory_(_authSession);
}
function setCustomerActive(_authSession, id, active) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  id = String(id || '').trim();
  if (!rows_('Customers').some(x => String(x.customer_id) === id)) throw new Error('Customer not found.');
  return upsertRow_(_authSession, 'Customers', {customer_id: id, active: active === true || String(active).toLowerCase() === 'true'}, 'customer_id');
}
function deleteCustomer(_authSession, id) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  id = String(id || '').trim();
  if (!rows_('Customers').some(x => String(x.customer_id) === id)) throw new Error('Customer not found.');
  const used = ['Sales','Bookings','Boarding','Memberships'].some(n => rows_(n).some(r => String(r.customer_id || '') === id));
  if (used) throw new Error('This customer has transaction history and cannot be deleted. Retire the customer instead.');
  rows_('Pets').filter(p => String(p.customer_id) === id).forEach(p => deleteRow_(_authSession, 'Pets', 'pet_id', p.pet_id));
  deleteRow_(_authSession, 'Customers', 'customer_id', id);
  return true;
}
function requireAuthorizedUser_(_authSession) {
  if (_authSession == null) throw new Error('PetShop session required. Please sign in again.');
  if (!_authSession.email || !_authSession.role) throw new Error('Your PetShop session is no longer valid. Please sign in again.');
  return { email: _authSession.email, role: _authSession.role };
}
function requireRole_(_authSession, roles) {
  const user = requireAuthorizedUser_(_authSession);
  if (!Array.isArray(roles) || roles.indexOf(user.role) === -1) throw new Error('Permission denied.');
  return user;
}
function doGet(e) {
  const receiptId = String(e && e.parameter && e.parameter.receipt || '').trim();
  if (receiptId) return renderPublicReceipt_(receiptId);
  const t = HtmlService.createTemplateFromFile('Index');
  t.APP_VERSION = APP_RELEASE_VERSION;
  t.APP_SCRIPT_VERSION = APP_SCRIPT_VERSION;
  t.APP_UPDATED = APP_RELEASED_AT;
  t.APP_WEB_URL = ScriptApp.getService().getUrl();
  return t.evaluate().setTitle('PetShop POS');
}
const WEB_GW_VER_ = 'v443';
const OPEN_FNS_ = {
  authStatus: authStatus, authLogin: authLogin, authBootstrap: authBootstrap,
  authLogout: authLogout, authChangePassword: authChangePassword, authResetOwnerPassword: authResetOwnerPassword
};
function jsonOut_(o) {
  return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
}
function doPost(e) {
  try {
    const req = JSON.parse(String((e && e.postData && e.postData.contents) || '{}'));
    const fn = String(req.fn || ''), args = Array.isArray(req.args) ? req.args : [];
    let out;
    if (fn === 'ping') out = {gateway: WEB_GW_VER_, time: new Date().toISOString()};   // deployment check
    else if (fn === 'apiCall') out = apiCall.apply(null, args);                          // args = [name, args, token]
    else if (Object.prototype.hasOwnProperty.call(OPEN_FNS_, fn)) out = OPEN_FNS_[fn].apply(null, args);
    else throw new Error('Unsupported PetShop operation.');
    return jsonOut_({ok: true, result: out === undefined ? null : out});
  } catch (err) {
    return jsonOut_({ok: false, error: String(err && err.message ? err.message : err || 'Request failed.')});
  }
}
function receiptToken_() {
  // Two independent UUIDs provide a high-entropy opaque token without exposing sale IDs.
  return Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
}
function ensureReceiptToken_(saleId, forceNew) {
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Receipt ID is missing.');
  const sh = getSS_().getSheetByName('Sales');
  if (!sh) throw new Error('Sales sheet is unavailable.');
  ensureSchema_(sh, SCHEMA.Sales);
  const lastCol = sh.getLastColumn(), lastRow = sh.getLastRow();
  if (lastRow < 2) throw new Error('Sale not found.');
  const headers = sh.getRange(1, 1, 1, lastCol).getValues()[0].map(String);
  const idCol = headers.indexOf('sale_id'), tokenCol = headers.indexOf('receipt_token');
  if (idCol < 0 || tokenCol < 0) throw new Error('Sale not found.');
  const idCell = sh.getRange(2, idCol + 1, lastRow - 1, 1).createTextFinder(id).matchEntireCell(true).findNext();
  if (!idCell) throw new Error('Sale not found.');
  const rowNumber = idCell.getRow();
  const tokenCell = sh.getRange(rowNumber, tokenCol + 1);
  const current = String(tokenCell.getValue() || '').trim();
  if (current && !forceNew) return current;
  let token = receiptToken_();
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const latest = String(tokenCell.getValue() || '').trim();
    if (!forceNew && latest) return latest;
    if (forceNew && latest) {
      try { CacheService.getScriptCache().remove('receipt_token_sale_' + authDigest_(latest).slice(0, 32)); } catch (e) {}
    }
    // UUID-derived tokens have ample entropy; avoid scanning every Sales row to check uniqueness.
    tokenCell.setValue(token);
    bumpVersion_('Sales');
  } finally {
    lock.releaseLock();
  }
  return token;
}
function resolvePublicReceiptSaleId_(tokenOrLegacyId) {
  const value = String(tokenOrLegacyId || '').trim();
  if (!value || value.length > 200) return '';
  const cache = CacheService.getScriptCache();
  const tokenCacheKey = 'receipt_token_sale_' + authDigest_(value).slice(0, 32);
  try {
    const cachedId = cache.get(tokenCacheKey);
    if (cachedId) return cachedId;
  } catch (e) {}
  const sh = getSS_().getSheetByName('Sales');
  if (!sh || sh.getLastRow() < 2) return '';
  const headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0].map(String);
  const tokenCol = headers.indexOf('receipt_token'), idCol = headers.indexOf('sale_id');
  if (tokenCol >= 0 && idCol >= 0) {
    const tokenCell = sh.getRange(2, tokenCol + 1, sh.getLastRow() - 1, 1).createTextFinder(value).matchEntireCell(true).findNext();
    if (tokenCell) {
      const saleId = String(sh.getRange(tokenCell.getRow(), idCol + 1).getValue() || '').trim();
      if (saleId) { try { cache.put(tokenCacheKey, saleId, 21600); } catch (e) {} return saleId; }
    }
  }
  return ''; // Never resolve a public receipt URL from a raw sale ID.
}
function receiptUrl(saleId) {
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Receipt ID is missing.');
  const token = ensureReceiptToken_(id, false);
  const base = ScriptApp.getService().getUrl();
  if (!base) throw new Error('Web app URL is unavailable.');
  return base + '?receipt=' + encodeURIComponent(token);
}

function htmlEscape_(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;').replace(/'/g, '&#39;');
}
function receiptNeedsPetLabel_(sale, items) {
  const source = String(sale && sale.source_type || '').trim().toUpperCase();
  if (source === 'GROOMING' || source === 'BOARDING') return true;
  const services = rows_('Services');
  const byId = {};
  services.forEach(s => { byId[String(s.service_id || '')] = String(s.category || '').trim().toUpperCase(); });
  return (Array.isArray(items) ? items : []).some(x => {
    if (String(x && x.item_type || 'SERVICE').trim().toUpperCase() !== 'SERVICE') return false;
    return ['GROOMING','BOARDING'].includes(byId[String(x && x.item_id || '')] || '');
  });
}
function receiptPetLabel_(pet, sale, items) {
  const name = String(pet && pet.name != null ? pet.name : '').trim();
  if (name) return name;
  return receiptNeedsPetLabel_(sale, items) ? 'Not specified (grooming/boarding)' : '';
}
function normalizePhone_(phone) {
  return String(phone == null ? '' : phone).replace(/\D/g, '');
}
function receiptPhoneVerificationRequired_() {
  // Default is OFF (no 4-digit prompt) unless the owner explicitly enables it in Settings.
  try {
    const setting = rows_('Settings').find(r => String(r.key || '') === 'REQUIRE_RECEIPT_PHONE_LAST4');
    return !!setting && String(setting.value || '').trim().toLowerCase() === 'true';
  } catch (e) { return false; }
}
function verifyReceiptAccess(tokenOrId, phone) {
  const token = String(tokenOrId || '').trim();
  if (!token || token.length > 200) return {ok:false, message:'Receipt not found.'};
  const requiresPhone = receiptPhoneVerificationRequired_();
  if (!requiresPhone) {
    const saleId = resolvePublicReceiptSaleId_(token);
    return saleId ? {ok:true, sale_id:saleId} : {ok:false, message:'Receipt not found.'};
  }
  const cache = CacheService.getScriptCache();
  const tokenDigest = authDigest_(token).slice(0, 32);
  const key = 'receipt_phone_fail_' + tokenDigest;
  const failures = Number(cache.get(key) || 0);
  if (failures >= RECEIPT_PHONE_FAIL_LIMIT_) {
    return {ok:false, locked:true, message:'Receipt verification is temporarily unavailable. Please try again in 15 minutes.'};
  }
  // Do not resolve the token or read any Sheets until the customer submits the code.
  // The public shell already shows the verification form; this avoids a full sale snapshot on first load.
  if (receiptPhoneVerificationRequired_() && !String(phone || '').trim()) {
    return {ok:false, requiresPhone:true, message:'Phone verification required.'};
  }
  const saleId = resolvePublicReceiptSaleId_(token);
  if (!saleId) return {ok:false, message:'Receipt not found.'};
  if (!receiptPhoneVerificationRequired_()) return {ok:true, sale_id:saleId};
  // Verification needs only the sale's customer phone, not revisions, pets, or sale items.
  const sale = findRowsByValue_('Sales', 'sale_id', saleId)[0];
  if (!sale) return {ok:false, message:'Receipt not found.'};
  const customer = sale.customer_id ? (findRowsByValue_('Customers', 'customer_id', sale.customer_id)[0] || {}) : {};
  const supplied = normalizePhone_(phone).slice(-4);
  const expected = normalizePhone_(customer.phone).slice(-4);
  // Apps Script does not expose the caller's IP address to google.script.run or doGet.
  // Apply a second throttling dimension using the submitted suffix without storing it in clear text.
  const suffixKey = 'receipt_phone_suffix_fail_' + authDigest_(tokenDigest + ':' + supplied).slice(0, 32);
  const suffixFailures = Number(cache.get(suffixKey) || 0);
  if (suffixFailures >= RECEIPT_PHONE_FAIL_LIMIT_) {
    return {ok:false, locked:true, message:'Receipt verification is temporarily unavailable. Please try again in 15 minutes.'};
  }
  if (supplied.length !== 4 || expected.length !== 4 || supplied !== expected) {
    const next = failures + 1;
    try {
      cache.put(key, String(next), RECEIPT_PHONE_LOCK_MINUTES_ * 60);
      cache.put(suffixKey, String(suffixFailures + 1), RECEIPT_PHONE_RATE_WINDOW_SECONDS_);
    } catch (e) {}
    return {ok:false, message:'Unable to verify receipt. Check the last 4 digits and try again.'};
  }
  try { cache.remove(key); cache.remove(suffixKey); } catch (e) {}
  return {ok:true, sale_id:saleId};
}
function renderPublicReceipt_(saleId) {
  const id = String(saleId || '').trim();
  // Render the public receipt shell immediately. Load receipt data asynchronously after the
  // page appears so customers see the page and progress indicator without a blank wait.
  if (!id) return HtmlService.createHtmlOutput('<h2>Receipt link is invalid</h2>').setTitle('PetShop Receipt');
  const safeId = htmlEscape_(id).replace(/'/g, '&#39;');
  const currency = htmlEscape_(CONFIG.CURRENCY);
  const ogImageTag = '';
  const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta property="og:title" content="PetShop Receipt"><meta property="og:description" content="Open this page to view, print, or download your PetShop receipt.">${ogImageTag}<title>PetShop Receipt</title><style>
body{font-family:Arial,sans-serif;background:#f6f7f9;margin:0;padding:20px;color:#222}.box{max-width:520px;margin:auto;background:#fff;padding:22px;border-radius:14px;box-shadow:0 2px 12px #0001}h1{font-size:22px}.err{color:#b00020;margin-top:10px}.receipt table{width:100%;border-collapse:collapse;margin-top:16px}.receipt td,.receipt th{padding:8px;border-bottom:1px solid #eee;text-align:left}.receipt .right{text-align:right}.total{font-size:20px;font-weight:700}.photos{display:flex;flex-wrap:wrap}.photos img{max-width:180px;max-height:180px;object-fit:cover;margin:4px;border-radius:8px}input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #ccc;border-radius:8px;font-size:16px}button{margin-top:12px;padding:11px 16px;border:0;border-radius:8px;background:#222;color:#fff;font-size:16px;cursor:pointer}button:disabled{opacity:.6}.progressWrap{height:8px;background:#f2dce6;border-radius:99px;overflow:hidden;margin:12px 0;display:none}.progressWrap.show{display:block}.progressBar{height:100%;width:35%;background:#df6d9d;border-radius:99px;animation:receiptProgress 1.1s ease-in-out infinite alternate}@keyframes receiptProgress{from{transform:translateX(-20%);width:25%}to{transform:translateX(250%);width:45%}}.progressText{font-size:13px;color:#8a6875;margin-top:6px;display:none}.progressText.show{display:block}
</style></head><body><div class="box"><div id="auth"><h1>🐾 PetShop Receipt</h1><p id="loadMessage">Loading your receipt. You can view it here without downloading a file.</p><div id="phoneGate" hidden><label for="phoneLast4">Last 4 digits of customer phone</label><input id="phoneLast4" type="tel" inputmode="numeric" maxlength="4" autocomplete="off" placeholder="Last 4 digits"><button type="button" onclick="submitPhone()">Verify</button></div><div id="receiptProgressWrap" class="progressWrap show" role="progressbar" aria-label="Loading receipt"><div class="progressBar"></div></div><div id="receiptProgressText" class="progressText show" aria-live="polite">Loading receipt details…</div><div id="err" class="err"></div></div><div id="receipt" class="receipt" hidden></div></div>
<script>
const RECEIPT_ID='${safeId}';
function esc(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function money(v){return '${currency} '+Number(v||0).toFixed(2)}
function loadReceipt(phone){const err=document.getElementById('err'),pw=document.getElementById('receiptProgressWrap'),pt=document.getElementById('receiptProgressText');err.textContent='';pw.classList.add('show');pt.classList.add('show');pt.textContent='Loading receipt details…';google.script.run.withSuccessHandler(r=>{pw.classList.remove('show');pt.classList.remove('show');if(r&&r.requiresPhone){document.getElementById('phoneGate').hidden=false;document.getElementById('loadMessage').textContent='For privacy, enter the last 4 digits of the customer phone number.';return}if(!r||!r.html){err.textContent='Receipt could not be loaded.';document.getElementById('loadMessage').textContent='We could not load this receipt.';return}const doc=new DOMParser().parseFromString(r.html,'text/html'),style=Array.from(doc.head.querySelectorAll('style')).map(x=>'<style>'+x.textContent+'</style>').join('');document.getElementById('auth').hidden=true;document.getElementById('receipt').hidden=false;document.getElementById('receipt').innerHTML=style+(doc.body?doc.body.innerHTML:'')+'<div class=actions><button type=button onclick=printReceiptPage()>Print Receipt</button><button type=button id=downloadPdfBtn onclick=downloadReceiptPdf()>Download PDF</button></div><div class=hint>Downloading is optional.</div>';window.__receiptData={sale_id:RECEIPT_ID};window.__receiptPhone=phone||'';}).withFailureHandler(e=>{pw.classList.remove('show');pt.classList.remove('show');err.textContent=(e&&e.message)||'Receipt could not be loaded.';document.getElementById('loadMessage').textContent='We could not load this receipt.'}).getReceiptPrintHtml(RECEIPT_ID,true,phone||'')}
function submitPhone(){const phone=String(document.getElementById('phoneLast4').value||'').replace(/\D/g,'');if(phone.length!==4){document.getElementById('err').textContent='Enter exactly 4 digits.';return}loadReceipt(phone)}
function render(r){document.getElementById('auth').hidden=true;const items=(r.items||[]).map(x=>'<tr><td>'+esc(x.description)+'</td><td>'+esc(x.qty)+'</td><td class="right">'+money(x.line_total)+'</td></tr>').join('');const photos=(r.photoDataUrls||[]).map(u=>'<img src="'+u+'" alt="Photo">').join('');document.getElementById('receipt').hidden=false;document.getElementById('receipt').innerHTML=(r.logo_url?'<img src="'+esc(r.logo_url)+'" style="max-width:170px;max-height:75px;object-fit:contain;margin-bottom:8px">':'')+'<h1>'+esc(r.store_name||'PetShop')+'</h1>'+(r.address?'<div style="white-space:pre-line">'+esc(r.address)+'</div>':'')+'<div>Receipt: <b>'+esc(r.sale_id)+'</b></div><div>'+esc(r.sale_at)+'</div><hr><b>'+esc(r.customer_name)+'</b>'+(r.show_pet?'<br>Pet: '+esc(r.pet_name||'Not specified (grooming/boarding)'):'')+'<table><tr><th>Description</th><th>Qty</th><th>Amount</th></tr>'+items+'</table><hr><div>Subtotal: '+money(r.subtotal)+'</div><div>Discount: '+money(r.discount)+'</div><div class="total">TOTAL: '+money(r.total)+'</div><div>Payment: '+esc(r.payment_method)+'</div>'+(photos?'<hr><h3>Photos</h3><div class="photos">'+photos+'</div>':'')+'<hr><div>Thank you!</div><div class="actions"><button type="button" onclick="printReceiptPage()">Print Receipt</button><button type="button" id="downloadPdfBtn" onclick="downloadReceiptPdf()">Download PDF</button></div><div class="hint">You can view this receipt safely on this page. Downloading is optional.</div>';window.__receiptData=r;window.__verifiedPhone=''}
function printReceiptPage(){window.print()}
function downloadReceiptPdf(){const r=window.__receiptData,phone=window.__receiptPhone||'',b=document.getElementById('downloadPdfBtn');if(!r)return;if(b){b.disabled=true;b.textContent='Preparing PDF…'}google.script.run.withSuccessHandler(file=>{if(b){b.disabled=false;b.textContent='Download PDF'}if(!file||!file.base64){document.getElementById('err').textContent='Could not prepare PDF. Please retry.';return}const bytes=atob(file.base64),arr=new Uint8Array(bytes.length);for(let i=0;i<bytes.length;i++)arr[i]=bytes.charCodeAt(i);const blob=new Blob([arr],{type:'application/pdf'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=file.name||('PetShop-Receipt-'+r.sale_id+'.pdf');document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000)}).withFailureHandler(e=>{if(b){b.disabled=false;b.textContent='Download PDF'}document.getElementById('err').textContent=(e&&e.message)||'PDF download failed. Please retry.'}).getPublicReceiptPdf(RECEIPT_ID,phone)}
window.addEventListener('load',()=>setTimeout(loadReceipt,0));
</script></body></html>`;
  return HtmlService.createHtmlOutput(html).setTitle('PetShop Receipt');
}
// Only setup() may create a brand-new spreadsheet. Every other call must find the linked one,
// otherwise the app would silently read/write a stray empty "PetShop OS" file.
function getSS_(allowCreate) {
  if (CONFIG.SPREADSHEET_ID) return SpreadsheetApp.openById(CONFIG.SPREADSHEET_ID);
  const props = PropertiesService.getScriptProperties();
  const savedId = props.getProperty('PETSHOP_SPREADSHEET_ID');
  if (savedId) return SpreadsheetApp.openById(savedId);
  let active = null;
  try { active = SpreadsheetApp.getActiveSpreadsheet(); } catch (e) {}
  if (active) {
    props.setProperty('PETSHOP_SPREADSHEET_ID', active.getId());
    return active;
  }
  if (!allowCreate) {
    throw new Error('PetShop spreadsheet is not linked. Run setup() once from the Apps Script editor of the script bound to your Google Sheet (or set CONFIG.SPREADSHEET_ID).');
  }
  const created = SpreadsheetApp.create('PetShop OS');
  props.setProperty('PETSHOP_SPREADSHEET_ID', created.getId());
  return created;
}
let REQUEST_ROWS_CACHE_ = Object.create(null);
function bumpVersion_(collection) {
  const p=PropertiesService.getScriptProperties();
  const n=Number(p.getProperty('DATA_VERSION')||0)+1;
  p.setProperty('DATA_VERSION',String(n));
  const changedCollections=Array.isArray(collection)?collection:(collection?[collection]:[]);
  changedCollections.forEach(name=>{
    const key='DATA_VERSION_COL_'+String(name).replace(/[^A-Za-z0-9_-]/g,'_');
    p.setProperty(key,String(Number(p.getProperty(key)||0)+1));
  });
  REQUEST_ROWS_CACHE_ = Object.create(null);
  return String(n);
}
function getDataVersion(_authSession) {
  requireAuthorizedUser_(_authSession);
  const p=PropertiesService.getScriptProperties(), collections={};
  Object.keys(SCHEMA).forEach(name=>{collections[name]=p.getProperty('DATA_VERSION_COL_'+name)||'0';});
  return {global:p.getProperty('DATA_VERSION')||'1',collections:collections};
}
function formulaSafeSheetValue_(value) {
  // Keep actual numeric/date/boolean values typed; only escape untrusted text.
  if (typeof value !== 'string' || !value) return value;
  // Preserve numeric strings representing legitimate negative numbers.
  if (/^-\d+(?:\.\d+)?$/.test(value)) return value;
  return /^\s*[=+\-@]/.test(value) ? "'" + value : value;
}
function formulaSafeSheetRow_(row) {
  return (row || []).map(formulaSafeSheetValue_);
}
function formatPlainTextColumns_(sh, headers) {
  const textFields = new Set((headers || []).filter(h => /_id$/i.test(String(h)) || ['phone','email','sku','barcode','Session ID','Email','Login IP','Logout IP','User Agent'].includes(String(h))));
  textFields.forEach(field => {
    const col = (headers || []).indexOf(field) + 1;
    if (col > 0) sh.getRange(1, col, Math.max(1, sh.getMaxRows()), 1).setNumberFormat('@');
  });
}
// Offline mutation ledger is deliberately separate from all existing business sheets.
const MUTATION_OUTCOME_SCHEMA_ = ['mutation_id','client_mutation_id','shop_scope','email','function_name','fingerprint','status','result_json','error_text','created_at','updated_at'];
const MUTATION_CHANGED_COLLECTIONS_ = {
  makeSale: ['Sales','SaleItems','Payments','Products','Inventory','Memberships','Bookings','Boarding','GroomerWork'],
  editSaleReceipt: ['Sales','SaleRevisions','SaleAudit'],
  saveCustomer: ['Customers'], savePet: ['Pets'], deletePet: ['Pets'],
  saveBooking: ['Bookings'], deleteBooking: ['Bookings'],
  saveBoarding: ['Boarding'], saveBoardingBatch: ['Boarding'], deleteBoarding: ['Boarding'],
  saveBoardingRoom: ['BoardingRooms'], deleteBoardingRoom: ['BoardingRooms'],
  saveProduct: ['Products'], deleteProduct: ['Products'], saveService: ['Services'], deleteService: ['Services'],
  savePromotion: ['Promotions'], deletePromotion: ['Promotions'],
  saveProductCategory: ['Settings','Products'], deleteProductCategory: ['Settings','Products'], receiveInventory: ['Products','Inventory'],
  saveMembership: ['Memberships'], deleteMembership: ['Memberships'], saveMembershipPlan: ['MembershipPlans'],
  claimGroomingPet: ['Bookings','GroomerWork'], claimAndCompleteGroomingPet: ['Bookings','GroomerWork'],
  assignGroomingPet: ['Bookings','GroomerWork'], completeGroomingPet: ['Bookings','GroomerWork'],
  saveCompanySettings: ['Settings'], saveStaffProfile: ['Staff'],
  saveGroomerCommissionRates: ['Staff','Settings'], saveStaffCommissionRates: ['Staff','Settings'],
  saveReceiptPhotos: ['Sales'], attachReceiptPhotos: ['Sales'], saveGroomingWorkPhotos: ['GroomerWork'], deletePhoto: [],
  uploadImage: []
};
function mutationLedgerSheet_() {
  const ss = getSS_(true); let sh = ss.getSheetByName('MutationOutcomes');
  if (!sh) sh = ss.insertSheet('MutationOutcomes');
  ensureSchema_(sh, MUTATION_OUTCOME_SCHEMA_); sh.setFrozenRows(1); formatPlainTextColumns_(sh, MUTATION_OUTCOME_SCHEMA_); return sh;
}
function mutationShopScope_() { return authDigest_(String(getSS_(true).getId() || 'petshop')).slice(0,32); }
function mutationLedgerRows_() { const sh=mutationLedgerSheet_(), values=sh.getDataRange().getValues(); if(values.length<2)return []; const headers=values[0].map(String); return values.slice(1).map((r,i)=>{const o={__row:i+2};headers.forEach((h,j)=>o[h]=r[j]);return o;}).filter(r=>String(r.mutation_id||'')); }
function mutationLedgerFind_(mutationId, shopScope) { return mutationLedgerRows_().find(r=>String(r.mutation_id)===String(mutationId)&&String(r.shop_scope)===String(shopScope))||null; }
function mutationLedgerWrite_(row, existingRow) {
  const sh=mutationLedgerSheet_(), obj={...row};
  if(existingRow&&existingRow.__row){const headers=MUTATION_OUTCOME_SCHEMA_;sh.getRange(existingRow.__row,1,1,headers.length).setValues([headers.map(h=>Object.prototype.hasOwnProperty.call(obj,h)?obj[h]:existingRow[h]||'')]);}
  else sh.appendRow(formulaSafeSheetRow_(MUTATION_OUTCOME_SCHEMA_.map(h=>obj[h]===undefined?'':obj[h])));
}
function mutationFingerprint_(value) {
  function canon(v) {
    if (v === undefined) throw new Error('Undefined is not permitted in mutation payloads.');
    if (v === null || typeof v === 'boolean') return v;
    if (typeof v === 'number') { if (!Number.isFinite(v)) throw new Error('Non-finite number in mutation payload.'); return v; }
    if (typeof v === 'string') return v.normalize ? v.normalize('NFC') : v;
    if (Array.isArray(v)) return v.map(canon);
    if (typeof v === 'object') { const out={}; Object.keys(v).sort().forEach(k=>{out[k]=canon(v[k]);}); return out; }
    throw new Error('Unsupported mutation payload value.');
  }
  return authDigest_(JSON.stringify(canon(value)));
}
function mutationChangedCollections_(fn,args,result) {
  const list=(MUTATION_CHANGED_COLLECTIONS_[String(fn)]||[]).slice();
  if(String(fn)==='makeSale') {
    const sale=(args||[])[0]||{}, items=Array.isArray((args||[])[1])?(args||[])[1]:[], type=String(sale.source_type||'').toUpperCase();
    const changed=['Sales','SaleItems'];
    if(Number(result&&result.total||sale.total||0)>0)changed.push('Payments');
    if(items.some(x=>String(x&&x.item_type||'').toUpperCase()==='PRODUCT'))changed.push('Products','Inventory');
    if(String(sale.membership_id||'').trim())changed.push('Memberships');
    if(type==='BOARDING')changed.push('Boarding');
    else if(type==='GROOMING')changed.push('Bookings','GroomerWork');
    else changed.push('Bookings','Boarding','GroomerWork'); // unknown source: refresh the union safely
    return Array.from(new Set(changed));
  }
  return Array.from(new Set(list));
}
function applyMutationBatch(_authSession, batch) {
  const session = _authSession;
  const user = requireAuthorizedUser_(_authSession);
  if(!Array.isArray(batch)||batch.length>50) throw new Error('Mutation batch must contain 1 to 50 operations.');
  const scope=mutationShopScope_(), out=[];
  batch.forEach(item=>{
    if(!item||typeof item!=='object') throw new Error('Invalid queued mutation.');
    const clientId=String(item.client_mutation_id||''), fnName=String(item.function_name||''), args=Array.isArray(item.args)?item.args:[];
    if(!/^[0-9a-f-]{36}$/i.test(clientId)) throw new Error('Invalid client mutation ID.');
    if(!Object.prototype.hasOwnProperty.call(MUTATION_CHANGED_COLLECTIONS_,fnName)||fnName==='uploadImage') throw new Error('Operation is not allowed in the offline mutation queue: '+fnName);
    const fingerprintArgs=Array.isArray(item.fingerprint_args)?item.fingerprint_args:args;
    const fingerprint=mutationFingerprint_({function_name:fnName,args:fingerprintArgs});
    if(item.fingerprint && String(item.fingerprint)!==fingerprint) throw new Error('Queued mutation fingerprint does not match its payload.');
    const mutationId=authDigest_(scope+':'+String(session.email||'').toLowerCase()+':'+clientId);
    // UserLock serializes duplicate requests for this authenticated user without
    // deadlocking makeSale, which uses the independent script lock for sheet writes.
    const lock=LockService.getUserLock(); lock.waitLock(20000);
    let started=null;
    try {
      const prior=mutationLedgerFind_(mutationId,scope);
      if(prior) {
        if(String(prior.email||'').toLowerCase()!==String(session.email||'').toLowerCase()) throw new Error('Mutation ledger scope mismatch.');
        if(String(prior.fingerprint||'')!==fingerprint&&String(prior.status)!=='DISCARDED') throw new Error('Client mutation ID was reused with a different payload.');
        if(String(prior.status)==='SUCCEEDED') {
          let saved={}; try{saved=JSON.parse(String(prior.result_json||'{}'))||{};}catch(e){}
          out.push({client_mutation_id:clientId,mutation_id:mutationId,replayed:true,ok:true,result:saved.result,changedCollections:saved.changedCollections||[],orphanedDriveFileIds:saved.orphanedDriveFileIds||[]});
          return;
        }
        if(String(prior.status)==='CONFLICT') {
          let saved={};try{saved=JSON.parse(String(prior.result_json||'{}'))||{};}catch(e){}
          const conflict=saved.conflict||{};
          out.push({status:'CONFLICT',client_mutation_id:clientId,mutation_id:mutationId,replayed:true,ok:false,base_revision_no:conflict.base_revision_no,current_revision_no:conflict.current_revision_no,current_snapshot:conflict.current_snapshot,conflict_at:conflict.conflict_at,error:String(prior.error_text||'Receipt revision conflict.'),changedCollections:[]});
          return;
        }
        if(String(prior.status)==='DISCARDED') {
          out.push({status:'DISCARDED',client_mutation_id:clientId,mutation_id:mutationId,replayed:true,ok:false,error:'This mutation was discarded and will not be replayed.',changedCollections:[]});
          return;
        }
        if(String(prior.status)==='FAILED') {
          const isProcessingSale=fnName==='makeSale'&&/previous attempt for this sale did not finish/i.test(String(prior.error_text||''));
          out.push({status:'FAILED',client_mutation_id:clientId,mutation_id:mutationId,replayed:true,ok:false,retryable:isProcessingSale,error:String(prior.error_text||'Previous mutation failed.'),changedCollections:[]});
          return;
        }
        if(String(prior.status)==='PROCESSING') {
          out.push({client_mutation_id:clientId,mutation_id:mutationId,replayed:true,ok:false,retryable:true,error:'This mutation has an unresolved server outcome. It was not replayed to avoid a duplicate write.',changedCollections:[]});
          return;
        }
      }
      started={mutation_id:mutationId,client_mutation_id:clientId,shop_scope:scope,email:String(session.email||'').toLowerCase(),function_name:fnName,fingerprint,status:'PROCESSING',result_json:'',error_text:'',created_at:new Date().toISOString(),updated_at:new Date().toISOString()};
      mutationLedgerWrite_(started,prior);
      try {
        const fn=AUTH_API_FUNCTIONS_[fnName]; if(typeof fn!=='function') throw new Error('Unsupported queued operation.');
        const result=fn.apply(null,[session].concat(args));
        const changed=mutationChangedCollections_(fnName,args,result);
        const stored={result:result,changedCollections:changed,orphanedDriveFileIds:[]};
        mutationLedgerWrite_({...started,status:'SUCCEEDED',result_json:JSON.stringify(stored),error_text:'',updated_at:new Date().toISOString()},mutationLedgerFind_(mutationId,scope));
        out.push({client_mutation_id:clientId,mutation_id:mutationId,replayed:false,ok:true,result:result,changedCollections:changed,orphanedDriveFileIds:[]});
      } catch(e) {
        const errorText=String(e&&e.message||e);
        const processingSale=fnName==='makeSale'&&/previous attempt for this sale did not finish/i.test(errorText);
        const conflict=e&&e.petshopConflict?e.petshopConflict:null;
        const outcomeStatus=conflict?'CONFLICT':'FAILED';
        mutationLedgerWrite_({...started,status:outcomeStatus,result_json:JSON.stringify({result:null,changedCollections:[],orphanedDriveFileIds:Array.isArray(item.uploadedDriveFileIds)?item.uploadedDriveFileIds:[],conflict:conflict}),error_text:errorText,updated_at:new Date().toISOString()},mutationLedgerFind_(mutationId,scope));
        out.push(conflict?{status:'CONFLICT',client_mutation_id:clientId,mutation_id:mutationId,base_revision_no:conflict.base_revision_no,current_revision_no:conflict.current_revision_no,current_snapshot:conflict.current_snapshot,conflict_at:conflict.conflict_at,ok:false,replayed:false,error:errorText,changedCollections:[]}:{status:outcomeStatus,client_mutation_id:clientId,mutation_id:mutationId,replayed:false,ok:false,retryable:processingSale,error:errorText,changedCollections:[]});
      }
    } finally { lock.releaseLock(); }
  });
  return {results:out,shop_scope:scope};
}
function photoUrlReferencedAnywhere_(url) {
  const needle=String(url||''); if(!needle)return false;
  const specs=[['Customers',['photo_url']],['Pets',['photo_url']],['Products',['photo_url']],['Bookings',['photo_url']],['Boarding',['photo_url']],['Sales',['receipt_photo_urls']],['GroomerWork',['before_photo_url','after_photo_url']]];
  const target=(needle.match(/[?&]id=([A-Za-z0-9_-]+)/)||[])[1]||'';
  return specs.some(([sheet,fields])=>{try{return rows_(sheet).some(row=>fields.some(field=>{const raw=String(row[field]||'');if(raw===needle)return true;const direct=(raw.match(/[?&]id=([A-Za-z0-9_-]+)/)||[])[1]||'';if(target&&direct===target)return true;try{const arr=JSON.parse(raw);return Array.isArray(arr)&&arr.some(u=>String(u)===needle||target&&((String(u).match(/[?&]id=([A-Za-z0-9_-]+)/)||[])[1]||'')===target);}catch(e){return false;}}));}catch(e){return false;}});
}

function mutationIdentity_(clientMutationId, session) {
  const clientId=String(clientMutationId||'');
  if(!/^[0-9a-f-]{36}$/i.test(clientId)) throw new Error('Invalid client mutation ID.');
  const scope=mutationShopScope_();
  return {clientId:clientId,scope:scope,mutationId:authDigest_(scope+':'+String(session.email||'').toLowerCase()+':'+clientId)};
}
function outcome_lookup(_authSession, client_mutation_id, function_name, sale_id) {
  const session = _authSession;
  requireAuthorizedUser_(_authSession);
  const fn=String(function_name||''); if(!fn)throw new Error('Mutation function name is required.');
  const ident=mutationIdentity_(client_mutation_id,session);
  const row=mutationLedgerFind_(ident.mutationId,ident.scope);
  if(row) {
    if(String(row.function_name||'')!==fn)throw new Error('Mutation function mismatch. The local record does not match the server ledger.');
    const status=String(row.status||'');
    if(fn==='makeSale'&&status!=='SUCCEEDED'){
      const saleId=String(sale_id||'').trim(),sale=saleId?rows_('Sales').find(x=>String(x.sale_id||'')===saleId):null;
      if(sale&&String(sale.sale_status||'').toUpperCase()==='PROCESSING')return {status:'PROCESSING',mutation_id:ident.mutationId,sale_id:saleId};
      if(sale&&String(sale.sale_status||'').toUpperCase()==='COMPLETED')return {status:'APPLIED',mutation_id:ident.mutationId,sale_id:saleId};
    }
    if(status==='SUCCEEDED')return {status:'SUCCEEDED',mutation_id:ident.mutationId,function_name:fn};
    if(status==='FAILED'||status==='CONFLICT'||status==='PROCESSING')return {status:status,mutation_id:ident.mutationId,function_name:fn,error:String(row.error_text||'')};
    return {status:'PROCESSING',mutation_id:ident.mutationId,function_name:fn};
  }
  if(fn==='makeSale') {
    const id=String(sale_id||'').trim();
    if(!/^SAL-[A-Z0-9]{8}$/.test(id))return {status:'PROCESSING',mutation_id:ident.mutationId,reason:'Sale identifier is unavailable; cannot safely establish the outcome.'};
    const sale=rows_('Sales').find(x=>String(x.sale_id||'')===id);
    if(!sale)return {status:'NOT_FOUND',mutation_id:ident.mutationId};
    const state=String(sale.sale_status||'').toUpperCase();
    if(state==='COMPLETED')return {status:'APPLIED',mutation_id:ident.mutationId,sale_id:id};
    if(state==='PROCESSING')return {status:'PROCESSING',mutation_id:ident.mutationId,sale_id:id};
    if(state==='VOIDED')return {status:'FAILED',mutation_id:ident.mutationId,sale_id:id};
    return {status:'PROCESSING',mutation_id:ident.mutationId,sale_id:id,reason:'Sale outcome is ambiguous.'};
  }
  // Without a ledger entry, non-sale writes cannot be proven absent from their sheet.
  return {status:'PROCESSING',mutation_id:ident.mutationId,reason:'No ledger outcome exists; the server cannot prove this mutation had no side effects.'};
}

function registerOfflineDiscard(_authSession, client_mutation_id, function_name, sale_id, discarded_at) {
  const session = _authSession;
  requireAuthorizedUser_(_authSession);
  const fn=String(function_name||''),ident=mutationIdentity_(client_mutation_id,session);
  requireRole_(_authSession, fn==='makeSale'||fn==='editSaleReceipt'?['OWNER']:['OWNER','MANAGER']);
  const existing=mutationLedgerFind_(ident.mutationId,ident.scope);
  if(existing&&String(existing.function_name||'')!==fn)throw new Error('Mutation function mismatch. The local discard record does not match the server ledger.');
  if(existing&&String(existing.status)==='SUCCEEDED')return {status:'APPLIED',mutation_id:ident.mutationId};
  if(existing&&String(existing.status)==='PROCESSING')return {status:'PROCESSING',mutation_id:ident.mutationId};
  if(fn==='makeSale'){
    const id=String(sale_id||'').trim(),sale=id?rows_('Sales').find(x=>String(x.sale_id||'')===id):null;
    if(sale&&String(sale.sale_status||'').toUpperCase()==='COMPLETED')return {status:'APPLIED',mutation_id:ident.mutationId};
    if(sale&&String(sale.sale_status||'').toUpperCase()==='PROCESSING')return {status:'PROCESSING',mutation_id:ident.mutationId};
  }
  const now=new Date().toISOString(),row={mutation_id:ident.mutationId,client_mutation_id:ident.clientId,shop_scope:ident.scope,email:String(session.email||'').toLowerCase(),function_name:fn,fingerprint:existing?String(existing.fingerprint||''):'OFFLINE_DISCARD_TOMBSTONE',status:'DISCARDED',result_json:JSON.stringify({offline_discard:true,discarded_at:String(discarded_at||''),registered_at:now}),error_text:'Offline discard registered; mutation must not replay.',created_at:existing?existing.created_at:now,updated_at:now};
  mutationLedgerWrite_(row,existing);
  return {status:'DISCARDED',mutation_id:ident.mutationId};
}
function discardMutation(_authSession, client_mutation_id, function_name, sale_id) {
  const session = _authSession;
  requireAuthorizedUser_(_authSession);
  const fn=String(function_name||''); const ident=mutationIdentity_(client_mutation_id,session);
  const isSale=fn==='makeSale'||fn==='editSaleReceipt';
  const roles=isSale?['OWNER']:['OWNER','MANAGER'];
  const user=requireRole_(_authSession, roles);
  const outcome=outcome_lookup(_authSession, client_mutation_id,fn,sale_id);
  if(!['FAILED','CONFLICT','NOT_FOUND'].includes(String(outcome.status)))throw new Error('Discard refused: server outcome is '+String(outcome.status)+'. Resolve the outcome before discarding.');
  const row=mutationLedgerFind_(ident.mutationId,ident.scope);
  if(row)mutationLedgerWrite_({...row,status:'DISCARDED',error_text:'Discarded by '+user.email+' at '+new Date().toISOString(),updated_at:new Date().toISOString()},row);
  return {ok:true,status:'DISCARDED',mutation_id:ident.mutationId};
}
function getProcessingSaleResolution(_authSession, saleId) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  const id=String(saleId||'').trim(), sale=rows_('Sales').find(x=>String(x.sale_id||'')===id);
  if(!sale||String(sale.sale_status||'').toUpperCase()!=='PROCESSING')throw new Error('Sale is not in PROCESSING state.');
  const items=rows_('SaleItems').filter(x=>String(x.sale_id||'')===id),payments=rows_('Payments').filter(x=>String(x.sale_id||'')===id),inventory=rows_('Inventory').filter(x=>String(x.reference||'')===id);
  const productItems=items.filter(x=>String(x.item_type||'').toUpperCase()==='PRODUCT');
  const productIds=Array.from(new Set(productItems.map(x=>String(x.item_id||''))));
  const inventoryProducts=new Set(inventory.map(x=>String(x.product_id||'')));
  const productSummary=productIds.map(pid=>({product_id:pid,status:inventoryProducts.has(pid)?'written':(!payments.length?'not_written':'unknown')}));
  const membershipStatus=String(sale.membership_id||'').trim()?'unknown':'not_written';
  const sourceType=String(sale.source_type||'').toUpperCase(),sourceIds=[];try{const a=JSON.parse(String(sale.source_ids||'[]'));if(Array.isArray(a))a.forEach(x=>sourceIds.push(String(x)));}catch(e){}if(!sourceIds.length&&sale.source_id)sourceIds.push(String(sale.source_id));
  const sourceSheet=sourceType==='BOARDING'?'Boarding':sourceType==='GROOMING'?'Bookings':'';
  const sourceRows=sourceSheet?rows_(sourceSheet):[];
  const sources=sourceIds.map(sid=>{const r=sourceRows.find(x=>String(x[sourceType==='BOARDING'?'boarding_id':'booking_id'])===sid);return {id:sid,status:!r?'unknown':String(r.status||'').toUpperCase()==='COMPLETED'?'written':!payments.length?'not_written':'unknown'};});
  const summary={
    Sales:'written',SaleItems:items.length?'written':'unknown',Payments:Number(sale.total||0)<=0?'not_written':payments.length?'written':'not_written',
    Products:productSummary.length?(productSummary.every(x=>x.status==='written')?'written':productSummary.every(x=>x.status==='not_written')?'not_written':'unknown'):'not_written',
    Inventory:productSummary.length?(productSummary.every(x=>x.status==='written')?'written':productSummary.every(x=>x.status==='not_written')?'not_written':'unknown'):'not_written',
    Memberships:membershipStatus,
    SourceRecords:sources.length?(sources.every(x=>x.status==='written')?'written':sources.every(x=>x.status==='not_written')?'not_written':'unknown'):'not_written'
  };
  return {sale:sale,summary:summary,products:productSummary,sources:sources,items:items,payments:payments,inventory:inventory,canComplete:items.length>0&&!Object.values(summary).includes('unknown'),canVoid:!Object.values(summary).includes('unknown')&&membershipStatus!=='unknown'&&(!sources.length||sources.every(x=>x.status==='not_written'))};
}
function resolveProcessingSale(_authSession, saleId, action) {
  const user=requireRole_(_authSession, String(action||'').toUpperCase()==='VOID'?['OWNER']:['OWNER','MANAGER']);
  const id=String(saleId||'').trim(), mode=String(action||'').toUpperCase();
  if(!['COMPLETE','VOID'].includes(mode))throw new Error('Unsupported sale resolution action.');
  const lock=LockService.getScriptLock();lock.waitLock(20000);
  try {
    const report=getProcessingSaleResolution(_authSession, id),sale=report.sale;
    if(mode==='COMPLETE') {
      if(!report.canComplete)throw new Error('Sale writes include unknown state. Automatic completion is blocked to protect stock, membership points, and source records.');
      const existingPayments=rows_('Payments').filter(x=>String(x.sale_id||'')===id);
      if(Number(sale.total||0)>0&&!existingPayments.length)append_('Payments',{payment_id:id_('PAY'),sale_id:id,paid_at:sale.sale_at||new Date(),amount:Number(sale.total||0),method:String(sale.payment_method||'Cash'),reference:'',notes:'Recovered by sale resolution'},true);
      const inventory=rows_('Inventory').filter(x=>String(x.reference||'')===id);
      const existingProductIds=new Set(inventory.map(x=>String(x.product_id||'')));
      const need={};report.items.filter(x=>String(x.item_type||'').toUpperCase()==='PRODUCT').forEach(x=>{const pid=String(x.item_id||'');need[pid]=(need[pid]||0)+Number(x.qty||0);});
      Object.keys(need).forEach(pid=>{
        if(existingProductIds.has(pid))return;
        const sh=getSS_().getSheetByName('Products'),data=sh.getDataRange().getValues(),headers=data[0].map(String),ix=Object.fromEntries(headers.map((h,i)=>[h,i]));
        const row=data.findIndex((r,i)=>i>0&&String(r[ix.product_id])===pid);if(row<1)throw new Error('Cannot recover: product row is missing: '+pid);
        const after=Number(data[row][ix.stock]||0)-need[pid];if(after<0)throw new Error('Cannot recover: insufficient stock for '+pid);
        sh.getRange(row+1,ix.stock+1).setValue(after);
        append_('Inventory',{movement_id:id_('INV'),product_id:pid,type:'SALE',qty:-need[pid],unit_cost:Number(data[row][ix.avg_cost]||data[row][ix.cost]||0),stock_after:after,reference:id,created_at:new Date(),created_by:user.email},true);
      });
      if(String(sale.source_type||'').toUpperCase()==='BOARDING'||String(sale.source_type||'').toUpperCase()==='GROOMING'){
        const sheet=String(sale.source_type).toUpperCase()==='BOARDING'?'Boarding':'Bookings',field=sheet==='Boarding'?'boarding_id':'booking_id';let ids=[];try{ids=JSON.parse(String(sale.source_ids||'[]'));}catch(e){}if(!Array.isArray(ids)||!ids.length)ids=sale.source_id?[sale.source_id]:[];
        ids.forEach(sid=>{const row=rows_(sheet).find(x=>String(x[field])===String(sid));if(row){row.status='COMPLETED';upsertRow_(_authSession, sheet,row,field,true);}});
      }
      upsertRow_(_authSession, 'Sales',{sale_id:id,sale_status:'COMPLETED'},'sale_id',true);
      append_('SaleAudit',{log_id:id_('AUD'),sale_id:id,revision_id:'',changed_at:new Date(),changed_by:user.email,action:'RESOLVE_SALE_COMPLETE',changes_json:JSON.stringify({summary:report.summary})},true);
      bumpVersion_(['Sales','Payments','Products','Inventory','Bookings','Boarding','SaleAudit']);
      try{enqueueReceiptGeneration_(id);}catch(e){console.error('Recovered sale receipt queue failed',e);}
      return {ok:true,action:'RESOLVE_SALE_COMPLETE',sale_id:id,sale_status:'COMPLETED'};
    }
    if(!report.canVoid)throw new Error('Sale writes include unknown state. Void is blocked to avoid incorrect stock or membership adjustments.');
    const inventory=rows_('Inventory').filter(x=>String(x.reference||'')===id);
    const productSheet=getSS_().getSheetByName('Products');
    inventory.forEach(m=>{
      const data=productSheet.getDataRange().getValues(),headers=data[0].map(String),ix=Object.fromEntries(headers.map((h,i)=>[h,i]));
      const row=data.findIndex((r,i)=>i>0&&String(r[ix.product_id])===String(m.product_id));if(row<1)throw new Error('Cannot restore stock; product row missing: '+m.product_id);
      productSheet.getRange(row+1,ix.stock+1).setValue(Number(data[row][ix.stock]||0)-Number(m.qty||0));
    });
    const invSheet=getSS_().getSheetByName('Inventory');const invRows=rows_('Inventory');for(let i=invRows.length-1;i>=0;i--){if(String(invRows[i].reference||'')===id)deleteRow_(_authSession, 'Inventory','movement_id',invRows[i].movement_id);}
    upsertRow_(_authSession, 'Sales',{sale_id:id,sale_status:'VOIDED'},'sale_id',true);
    append_('SaleAudit',{log_id:id_('AUD'),sale_id:id,revision_id:'',changed_at:new Date(),changed_by:user.email,action:'RESOLVE_SALE_VOID',changes_json:JSON.stringify({summary:report.summary})},true);
    bumpVersion_(['Sales','Products','Inventory','SaleAudit']);
    return {ok:true,action:'RESOLVE_SALE_VOID',sale_id:id,sale_status:'VOIDED'};
  } finally {lock.releaseLock();}
}
function getMutationLedgerHealth(_authSession) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  const count=Math.max(0,mutationLedgerSheet_().getLastRow()-1),limit=50000;
  return {row_count:count,soft_cap:limit,exceeded:count>limit,message:count>limit?'Mutation ledger has exceeded '+limit+' rows; a prune is recommended.':''};
}
function pruneMutationOutcomesWeekly_() {
  // Keep all outcome rows because an offline client may replay at an unbounded future date.
  // Only sweep uploaded photo files explicitly recorded as orphan candidates by failed mutations.
  let swept=0,skipped=0; mutationLedgerRows_().forEach(row=>{if(String(row.status)!=='FAILED')return;let data={};try{data=JSON.parse(String(row.result_json||'{}'))||{};}catch(e){}(data.orphanedDriveFileIds||[]).forEach(id=>{try{const file=DriveApp.getFileById(String(id));if(!fileInPetShopPhotosFolder_(file)){skipped++;return;}const url='https://drive.google.com/thumbnail?id='+String(id);if(photoUrlReferencedAnywhere_(url)){skipped++;return;}file.setTrashed(true);swept++;}catch(e){/* missing/already trashed is safe */}});});return {ok:true,pruned:0,orphanFilesTrashed:swept,orphanFilesSkipped:skipped,policy:'retain-outcomes-indefinitely-unbounded-offline-replay'};
}
function installMutationOutcomeMaintenanceTrigger_() {
  ScriptApp.getProjectTriggers().filter(t=>t.getHandlerFunction()==='pruneMutationOutcomesWeekly_').forEach(t=>ScriptApp.deleteTrigger(t));
  ScriptApp.newTrigger('pruneMutationOutcomesWeekly_').timeBased().everyWeeks(1).onWeekDay(ScriptApp.WeekDay.SUNDAY).create();
}

function setup() {
  // Installation/bootstrap must be run by the deployment owner from the Apps Script editor,
  // never through the public web app where the effective user is the deployer.
  const email = String(Session.getActiveUser().getEmail() || '').trim().toLowerCase();
  const effective = String(Session.getEffectiveUser().getEmail() || '').trim().toLowerCase();
  if (!email || !effective || email !== effective) throw new Error('Run setup() from the Apps Script editor as the shop owner.');
  const props = PropertiesService.getScriptProperties();
  const existingOwner = String(props.getProperty(SECURITY_KEYS_.OWNER) || '').trim().toLowerCase();
  if (existingOwner && existingOwner !== email) throw new Error('Only the existing PetShop owner can run setup.');
  if (!existingOwner) {
    props.setProperty(SECURITY_KEYS_.OWNER, email);
    saveUsers_({ [email]: { role: 'OWNER', active: true } });
  }
  let users = getUsers_();
  if (!users[email]) { users[email] = { role: 'OWNER', active: true }; saveUsers_(users); }
  // Issue a one-time code only until the first owner password is configured.
  // Re-running setup() must not reopen first-time setup for an existing owner.
  const configuredOwner = (getUsers_()[email] || {});
  if (!(configuredOwner.passwordSalt && configuredOwner.passwordHash)) {
    const bootstrap = Utilities.getUuid() + '-' + Utilities.getUuid();
    props.setProperty(AUTH_BOOTSTRAP_KEY_, bootstrap);
  } else {
    props.deleteProperty(AUTH_BOOTSTRAP_KEY_);
  }
  const ss = getSS_(true);
  Object.keys(SCHEMA).forEach(name => {
    let sh = ss.getSheetByName(name);
    if (!sh) sh = ss.insertSheet(name);
    ensureSchema_(sh, SCHEMA[name]);
    formatPlainTextColumns_(sh, SCHEMA[name]);
    sh.setFrozenRows(1);
  });
  mutationLedgerSheet_();
  installMutationOutcomeMaintenanceTrigger_();
  if (!PropertiesService.getScriptProperties().getProperty('DATA_VERSION')) {
    PropertiesService.getScriptProperties().setProperty('DATA_VERSION','1');
  }
  seedDefaults_();
  const bootstrapCode = props.getProperty(AUTH_BOOTSTRAP_KEY_);
  if (bootstrapCode) {
    const message = 'PetShop one-time owner setup code (share only with the shop owner): ' + bootstrapCode;
    console.log(message);
    Logger.log(message);
    return 'Setup complete. One-time owner setup code: ' + bootstrapCode;
  }
  return 'Setup complete. Owner password is already configured; no setup code is needed.';
}
function ensureSchema_(sh, expected) {
  let headers = sh.getLastColumn() ? sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0].map(String) : [];
  if (!headers.some(Boolean)) {
    sh.getRange(1,1,1,expected.length).setValues([expected]);
    return;
  }
  expected.forEach((h, i) => {
    if (headers[i] === h) return;
    const existing = headers.indexOf(h);
    if (existing >= 0) return;
    sh.insertColumnBefore(Math.min(i + 1, sh.getMaxColumns()));
    sh.getRange(1,i+1).setValue(h);
    headers.splice(i,0,h);
  });
}
function seedDefaults_() {
  const ss = getSS_();
  const defaults = [
    ['Services', [
      ['SVC-GROOM','Full Groom','Grooming',80,120,true],
      ['SVC-BATH','Bath','Grooming',50,60,true],
      ['SVC-NAIL','Nail Trim','Grooming',20,20,true],
      ['SVC-BOARD','Boarding Night','Boarding',45,1440,true]
    ]],
    ['MembershipPlans', [
      ['PLAN-BASIC','Basic',99,365,5,5,0,1,true],
      ['PLAN-GOLD','Gold',199,365,15,10,5,1.2,true]
    ]],
    ['Settings', [
      ['shop_name','PetShop'],
      ['receipt_footer','Thank you!']
    ]]
  ];
  defaults.forEach(([sheet, rows]) => {
    const sh = ss.getSheetByName(sheet);
    if (sh.getLastRow() <= 1) sh.getRange(2,1,rows.length,rows[0].length).setValues(rows);
  });
}
function rows_(sheetName) {
  if (Object.prototype.hasOwnProperty.call(REQUEST_ROWS_CACHE_, sheetName)) return REQUEST_ROWS_CACHE_[sheetName].map(row => ({...row}));
  const cache = CacheService.getScriptCache();
  const version = PropertiesService.getScriptProperties().getProperty('DATA_VERSION_COL_' + String(sheetName).replace(/[^A-Za-z0-9_-]/g, '_')) || '0';
  const sharedCacheKey = 'petshop_rows_v2_' + String(sheetName).replace(/[^A-Za-z0-9_-]/g, '_') + '_' + version;
  try {
    const cached = cache.get(sharedCacheKey);
    if (cached) {
      const parsed = JSON.parse(cached);
      if (Array.isArray(parsed)) {
        REQUEST_ROWS_CACHE_[sheetName] = parsed.map(row => ({...row}));
        return REQUEST_ROWS_CACHE_[sheetName].map(row => ({...row}));
      }
    }
  } catch (cacheReadError) { console.warn('Collection cache read skipped for ' + sheetName, cacheReadError); }
  const sh = getSS_().getSheetByName(sheetName);
  if (!sh) return [];
  // Schema migration is done by setup(), not repeatedly on every hot-path read.
  if (sh.getLastRow() < 2) { REQUEST_ROWS_CACHE_[sheetName]=[]; return []; }
  const values = sh.getRange(2,1,sh.getLastRow()-1,sh.getLastColumn()).getValues();
  // Always map values using the sheet's actual header positions. SCHEMA is the
  // desired schema, not a safe substitute for physical column order in older sheets.
  const headers = sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0].map(h => String(h || '').trim());
  const result = values.filter(r => r.some(v => v !== '')).map(r => {
    const o = {};
    headers.forEach((h,i) => { if (h) o[h] = normalize_(r[i]); });
    return o;
  });
  REQUEST_ROWS_CACHE_[sheetName] = result.map(row => ({...row}));
  // Script Cache has a per-value size limit; cache only compact collections and let oversized ones remain request-local.
  try {
    const serialized = JSON.stringify(REQUEST_ROWS_CACHE_[sheetName]);
    if (serialized.length <= 85000) cache.put(sharedCacheKey, serialized, 60);
  } catch (cacheWriteError) { console.warn('Collection cache write skipped for ' + sheetName, cacheWriteError); }
  return result;
}
function normalize_(v) {
  if (v instanceof Date) return Utilities.formatDate(v, Session.getScriptTimeZone(), "yyyy-MM-dd'T'HH:mm:ss");
  return v;
}
// google.script.run turns objects containing Date values into null; return a serialisable copy instead.
function plain_(obj) {
  const o = {};
  Object.keys(obj || {}).forEach(k => o[k] = normalize_(obj[k]));
  return o;
}
function round2_(n) { return Math.round((Number(n) + Number.EPSILON) * 100) / 100; }
function receiptPhotoDataUrls_(saleId, sale, pet) {
  const photoUrls = [];
  const addPhotos = raw => {
    if (!raw) return;
    try { const parsed = JSON.parse(String(raw)); if (Array.isArray(parsed)) parsed.forEach(u => { if (u && !photoUrls.includes(String(u))) photoUrls.push(String(u)); }); }
    catch (e) { if (String(raw).trim() && !photoUrls.includes(String(raw).trim())) photoUrls.push(String(raw).trim()); }
  };
  addPhotos(sale && sale.receipt_photo_urls);
  addPhotos(pet && pet.photo_url);
  const out = [];
  photoUrls.slice(0, 12).forEach(u => {
    try {
      const raw = String(u).trim();
      const m = raw.match(/^https:\/\/drive\.google\.com\/thumbnail\?id=([A-Za-z0-9_-]+)(?:&sz=w[1-9]\d{0,3})?$/) || raw.match(/^https:\/\/drive\.google\.com\/file\/d\/([A-Za-z0-9_-]+)(?:\/.*)?$/) || raw.match(/^https:\/\/drive\.google\.com\/open\?id=([A-Za-z0-9_-]+)$/);
      if (!m) return;
      const file = DriveApp.getFileById(m[1]);
      if (!fileInPetShopPhotosFolder_(file)) return;
      let blob = null; try { blob = file.getThumbnail(); } catch (e) {}
      if (!blob) blob = file.getBlob();
      const mime = String(blob.getContentType() || 'image/jpeg');
      if (/^image\/(jpeg|png|webp|gif)$/i.test(mime)) out.push('data:'+mime+';base64,'+Utilities.base64Encode(blob.getBytes()));
    } catch (e) {}
  });
  return out;
}
function receiptCacheKey_(kind, saleId) {
  // Keep receipt caches stable across deployments and unrelated data changes.
  // Only collections that can affect the rendered receipt participate in invalidation.
  const props = PropertiesService.getScriptProperties();
  const collections = ['Sales','SaleItems','SaleRevisions','Customers','Pets','Settings','GroomerWork'];
  const versions = collections.map(name =>
    name + '=' + (props.getProperty('DATA_VERSION_COL_' + name) || '0')
  ).join('|');
  return 'receipt:' + kind + ':' + authDigest_(versions).slice(0, 24) + ':' + String(saleId || '').trim();
}
function getReceiptPrintHtmlApi_(_authSession, saleId, publicAccess, phone) {
  // Public access must resolve an opaque token (or a time-limited legacy sale ID) and never use staff bypasses.
  if (publicAccess === true) {
    const verified = verifyReceiptAccess(saleId, phone);
    if (!verified.ok) {
      if (receiptPhoneVerificationRequired_() && !String(phone || '').trim() && !verified.locked) return {requiresPhone:true};
      throw new Error(verified.message || 'Receipt not found.');
    }
    return {html:getReceiptHtml(_authSession, verified.sale_id, false, true)};
  }
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  return {html:getReceiptHtml(_authSession, saleId, true, false)};
}

function companyLogoDataUrl_(logoUrl) {
  const raw = String(logoUrl || '').trim();
  if (!raw) return '';
  try {
    const m = raw.match(/^https:\/\/drive\.google\.com\/thumbnail\?id=([A-Za-z0-9_-]+)(?:&sz=w[1-9]\d{0,3})?$/) || raw.match(/^https:\/\/drive\.google\.com\/file\/d\/([A-Za-z0-9_-]+)(?:\/.*)?$/) || raw.match(/^https:\/\/drive\.google\.com\/open\?id=([A-Za-z0-9_-]+)$/);
    if (!m) return '';
    const file = DriveApp.getFileById(m[1]);
    if (!fileInPetShopPhotosFolder_(file)) return '';
    const blob = file.getBlob();
    const mime = String(blob.getContentType() || 'image/png');
    if (!/^image\/(jpeg|png|webp|gif)$/i.test(mime)) return '';
    return 'data:' + mime + ';base64,' + Utilities.base64Encode(blob.getBytes());
  } catch (e) {
    return '';
  }
}

function groomingBeforeAfterReceiptHtml_(sale, company, publicAccess) {
  if (publicAccess || !company || company.show_grooming_before_after_photos !== true || String(sale && sale.source_type || '').toUpperCase() !== 'GROOMING') return '';
  const bookingId = String(sale && sale.source_id || '').trim();
  if (!bookingId) return '';
  const work = groomerWorkRows_().find(row => String(row.booking_id) === bookingId) || {};
  const beforeUrl = String(work.before_photo_url || '').trim();
  const afterUrl = String(work.after_photo_url || '').trim();
  // Only show the pair when both images are available.
  if (!beforeUrl || !afterUrl) return '';
  const toDataUrl = url => {
    try {
      const raw = String(url).trim();
      const m = raw.match(/^https:\/\/drive\.google\.com\/thumbnail\?id=([A-Za-z0-9_-]+)(?:&sz=w[1-9]\d{0,3})?$/) || raw.match(/^https:\/\/drive\.google\.com\/file\/d\/([A-Za-z0-9_-]+)(?:\/.*)?$/) || raw.match(/^https:\/\/drive\.google\.com\/open\?id=([A-Za-z0-9_-]+)$/);
      if (!m) return '';
      const file = DriveApp.getFileById(m[1]);
      if (!fileInPetShopPhotosFolder_(file)) return '';
      let blob = null; try { blob = file.getThumbnail(); } catch (e) {}
      if (!blob) blob = file.getBlob();
      const mime = String(blob.getContentType() || 'image/jpeg');
      if (!/^image\/(jpeg|png|webp|gif)$/i.test(mime)) return '';
      return 'data:' + mime + ';base64,' + Utilities.base64Encode(blob.getBytes());
    } catch (e) { return ''; }
  };
  const before = toDataUrl(beforeUrl), after = toDataUrl(afterUrl);
  if (!before || !after) return '';
  return '<div class="photos grooming-before-after"><h3>Grooming Before &amp; After</h3><div class="before-after-pair"><div><b>Before</b><br><img src="' + before + '"></div><div><b>After</b><br><img src="' + after + '"></div></div></div>';
}

// Public receipt page entry point; the public token/phone check is intentionally separate
// from the authenticated apiCall operation mapped to getReceiptPrintHtml.
function getReceiptPrintHtml(saleId, publicAccess, phone) {
  if (publicAccess !== true) throw new Error('PetShop session required. Please sign in again.');
  const verified = verifyReceiptAccess(saleId, phone);
  if (!verified.ok) {
    if (receiptPhoneVerificationRequired_() && !String(phone || '').trim() && !verified.locked) return {requiresPhone:true};
    throw new Error(verified.message || 'Receipt not found.');
  }
  return {html:getReceiptHtml(null, verified.sale_id, false, true)};
}
function getReceiptHtml(_authSession, saleId, includePhotos, publicAccess) {
  publicAccess = publicAccess === true;
  if (!publicAccess && !RECEIPT_BACKGROUND_CONTEXT_) requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  includePhotos = includePhotos !== false;
  const cache = CacheService.getScriptCache(), cacheKey = receiptCacheKey_((publicAccess ? 'publichtml' : (includePhotos ? 'html' : 'emailhtml')), saleId);
  try { const cached = cache.get(cacheKey); if (cached) return cached; } catch (e) {}
  const snap = saleSnapshot_(saleId);
  if (!snap) throw new Error('Sale not found.');
  const co = getCompanySettings_();
  const s = snap.sale || {}, sourceCustomer = snap.customer || {}, sourcePhone = normalizePhone_(sourceCustomer.phone || ''), c = publicAccess ? {...sourceCustomer, phone: sourcePhone.length >= 4 ? '•••• ' + sourcePhone.slice(-4) : ''} : sourceCustomer, pet = snap.pet || {}, items = snap.items || [];
  const photos = includePhotos && !publicAccess ? receiptPhotoDataUrls_(saleId, s, pet) : [];
  const design = ['classic','minimal','cute','professional'].indexOf(String(co.receipt_design || 'professional')) >= 0 ? String(co.receipt_design || 'professional') : 'professional';
  const styles = {
    classic: {accent:'#7b4f2c',bg:'#fffaf5',border:'#d8c5b5',font:'Georgia,serif'},
    minimal: {accent:'#333',bg:'#fff',border:'#ddd',font:'Arial,sans-serif'},
    cute: {accent:'#d85c91',bg:'#fff7fb',border:'#f2c5d8',font:'Arial,sans-serif'},
    professional: {accent:'#263238',bg:'#fff',border:'#d8dde1',font:'Arial,sans-serif'}
  }[design];
  const generalPhotoHtml = photos.length ? '<div class="photos"><h3>Photos</h3>'+photos.map(u=>'<img src="'+u+'">').join('')+'</div>' : '';
  const groomingBeforeAfterHtml = includePhotos ? groomingBeforeAfterReceiptHtml_(s, co, publicAccess) : '';
  const photoHtml = generalPhotoHtml + groomingBeforeAfterHtml;
  const petLabel = receiptPetLabel_(pet, s, items);
  const petHtml = petLabel ? '<br>Pet: '+htmlEscape_(petLabel) : '';
  const logoSrc = companyLogoDataUrl_(co.logo_url);
  const logo = logoSrc ? '<img class="logo" src="'+htmlEscape_(logoSrc)+'">' : '';
  // Public receipts never display payment/social QR codes; avoid unnecessary Drive reads.
  const tngQrSrc = !publicAccess && co.tng_qr_active !== false ? companyLogoDataUrl_(co.tng_qr_url) : '';
  const duitnowQrSrc = !publicAccess && co.duitnow_qr_active !== false ? companyLogoDataUrl_(co.duitnow_qr_url) : '';
  const socmedQrSrc = !publicAccess && co.socmed_qr_active === true ? companyLogoDataUrl_(co.socmed_qr_url) : '';
  const paymentQrHtml = (!publicAccess && (tngQrSrc || duitnowQrSrc || socmedQrSrc)) ? '<div class="payment-qr"><h3>Scan to pay / connect</h3><p>For payment QR codes, enter the total amount shown above.</p><div class="qr-list">'+(tngQrSrc ? '<div><b>Touch &#39;n Go</b><br><img src="'+htmlEscape_(tngQrSrc)+'"></div>' : '')+(duitnowQrSrc ? '<div><b>DuitNow</b><br><img src="'+htmlEscape_(duitnowQrSrc)+'"></div>' : '')+(socmedQrSrc ? '<div><b>Social media</b><br><img src="'+htmlEscape_(socmedQrSrc)+'"></div>' : '')+'</div></div>' : '';
  const html = '<!doctype html><html><head><meta charset="utf-8"><style>@page{size:A4;margin:16mm}body{font-family:'+styles.font+';color:#222;background:'+styles.bg+';margin:0;padding:8px}.sheet{border:1px solid '+styles.border+';padding:24px;border-radius:12px}.head{border-bottom:3px solid '+styles.accent+';padding-bottom:14px;margin-bottom:18px}.logo{max-width:170px;max-height:75px;object-fit:contain;margin-bottom:8px}h1{color:'+styles.accent+';margin:0 0 5px;font-size:25px}h2{font-size:16px;color:'+styles.accent+'}table{width:100%;border-collapse:collapse;margin-top:16px}th{background:'+styles.accent+';color:#fff}td,th{padding:8px;border-bottom:1px solid '+styles.border+';text-align:left;font-size:11px}th:nth-child(n+2),td:nth-child(n+2){text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.right{text-align:right}.summary{width:100%;margin-top:14px}.summary-row{display:flex;justify-content:space-between;align-items:baseline;padding:3px 0}.summary-row .label{text-align:left}.summary-row .value{text-align:right;min-width:120px;font-variant-numeric:tabular-nums;white-space:nowrap}.summary{width:100%;margin-top:14px}.summary-row{display:flex;justify-content:space-between;align-items:baseline;padding:3px 0}.summary-row .label{text-align:left}.summary-row .value{text-align:right;min-width:120px;font-variant-numeric:tabular-nums;white-space:nowrap}.total{font-size:20px;font-weight:700;color:'+styles.accent+'}.photos{margin-top:22px;border-top:1px solid '+styles.border+';padding-top:12px}.photos img{width:145px;height:145px;object-fit:cover;margin:4px;border-radius:8px;border:1px solid '+styles.border+'}.before-after-pair{display:flex;gap:16px;flex-wrap:wrap}.before-after-pair>div{text-align:center}.before-after-pair img{width:180px;height:180px;object-fit:cover}.message{margin-top:22px;border-top:1px solid '+styles.border+';padding-top:12px;white-space:pre-wrap}.payment-qr{margin-top:22px;border-top:1px solid '+styles.border+';padding-top:12px;text-align:center}.qr-list{display:flex;justify-content:center;gap:18px;flex-wrap:wrap}.qr-list img{width:160px;height:160px;object-fit:contain}</style></head><body><div class="sheet"><div class="head">'+logo+'<h1>'+htmlEscape_(co.store_name || 'PetShop')+'</h1>'+(!publicAccess && co.address?'<div>'+htmlEscape_(co.address)+'</div>':'')+(co.email?'<div>'+htmlEscape_(co.email)+'</div>':'')+(co.contact?'<div>'+htmlEscape_(co.contact)+'</div>':'')+'</div><div><b>Receipt</b> '+htmlEscape_(s.sale_id||'')+'<br>'+htmlEscape_(s.sale_at||'')+'</div><p><b>'+htmlEscape_(c.name||'Walk-in')+'</b>'+(c.phone?'<br>'+htmlEscape_(c.phone):'')+petHtml+'</p><table><tr><th>Description</th><th>Qty</th><th>Unit</th><th>Discount</th><th class="right">Total</th></tr>'+items.map(x=>'<tr><td>'+htmlEscape_(x.description)+'</td><td>'+htmlEscape_(x.qty)+'</td><td>'+CONFIG.CURRENCY+' '+Number(x.unit_price||0).toFixed(2)+'</td><td>'+CONFIG.CURRENCY+' '+Number(x.discount||0).toFixed(2)+'</td><td class="right">'+CONFIG.CURRENCY+' '+Number(x.line_total||0).toFixed(2)+'</td></tr>').join('')+'</table><div class="summary"><div class="summary-row"><span class="label">Subtotal</span><span class="value">'+CONFIG.CURRENCY+' '+Number(s.subtotal||0).toFixed(2)+'</span></div><div class="summary-row"><span class="label">Discount</span><span class="value">'+CONFIG.CURRENCY+' '+Number(s.discount||0).toFixed(2)+'</span></div><div class="summary-row total"><span class="label">TOTAL</span><span class="value">'+CONFIG.CURRENCY+' '+Number(s.total||0).toFixed(2)+'</span></div><div class="summary-row"><span class="label">Payment</span><span class="value">'+htmlEscape_(s.payment_method||'')+'</span></div></div>'+paymentQrHtml+photoHtml+'<p style="margin-top:24px;color:#666">Thank you for visiting us.</p></div></body></html>';
  try { if (html.length < 95000) cache.put(cacheKey, html, 21600); } catch (e) {}
  return html;
}
function getReceiptPdf(_authSession, saleId) {
  if (!RECEIPT_BACKGROUND_CONTEXT_) requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  // PDF, print, email and in-app receipts all use the same canonical HTML including photos.
  const html = getReceiptHtml(_authSession, saleId, true);
  const blob = HtmlService.createHtmlOutput(html).getBlob().getAs(MimeType.PDF).setName('PetShop-Receipt-'+String(saleId)+'.pdf');
  return {name:blob.getName(),mimeType:'application/pdf',base64:Utilities.base64Encode(blob.getBytes())};
}
// Public PDF is rendered from the same redacted HTML as the public receipt page.
function getPublicReceiptPdf(tokenOrId, phone) {
  const verified = verifyReceiptAccess(tokenOrId, phone);
  if (!verified || !verified.ok) throw new Error((verified && verified.message) || 'Receipt not found.');
  const html = getReceiptHtml(null, verified.sale_id, false, true);
  const blob = HtmlService.createHtmlOutput(html).getBlob().getAs(MimeType.PDF)
    .setName('PetShop-Receipt-' + String(verified.sale_id) + '.pdf');
  return {name:blob.getName(),mimeType:'application/pdf',base64:Utilities.base64Encode(blob.getBytes())};
}
function regenerateReceiptLink(_authSession, saleId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const id = String(saleId || '').trim();
  if (!id || !rows_('Sales').some(row => String(row.sale_id) === id)) throw new Error('Sale not found.');
  ensureReceiptToken_(id, true);
  return {sale_id:id, preview_url:receiptUrl(id)};
}
function receiptMetadataKey_(saleId) {
  return 'PETSHOP_RECEIPT_META_' + authDigest_(String(saleId || '').trim()).slice(0, 40);
}
function receiptRevisionSignature_(saleId) {
  const snap = saleSnapshot_(saleId);
  if (!snap) throw new Error('Sale not found.');
  const co = getCompanySettings_();
  const payload = {
    sale: {sale_id:snap.sale.sale_id||'',sale_at:snap.sale.sale_at||'',subtotal:Number(snap.sale.subtotal||0),discount:Number(snap.sale.discount||0),total:Number(snap.sale.total||0),payment_method:snap.sale.payment_method||''},
    customer: {customer_id:snap.customer.customer_id||'',name:snap.customer.name||'',phone:snap.customer.phone||''},
    pet: {pet_id:snap.pet.pet_id||'',name:snap.pet.name||''}, items: snap.items || [],
    revision_no: Number(snap.revision_no || 0), revision_id: String(snap.revision_id || ''),
    settings: {
      store_name: co.store_name || '', address: co.address || '', email: co.email || '', contact: co.contact || '',
      logo_url: co.logo_url || '', receipt_design: co.receipt_design || 'professional',
      tng_qr_url: co.tng_qr_url || '', tng_qr_active: co.tng_qr_active !== false,
      duitnow_qr_url: co.duitnow_qr_url || '', duitnow_qr_active: co.duitnow_qr_active !== false,
      socmed_qr_url: co.socmed_qr_url || '', socmed_qr_active: co.socmed_qr_active === true
    }
  };
  return authDigest_(JSON.stringify(payload));
}
function getOrCreateReceiptPdfFile_(_authSession, saleId, internalBackground) {
  if (!internalBackground) requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Sale ID is required.');
  const signature = receiptRevisionSignature_(id);
  const props = PropertiesService.getScriptProperties();
  const metaKey = receiptMetadataKey_(id);

  // Keep the global script lock only around the tiny metadata read. PDF rendering and
  // Drive operations can take seconds; holding ScriptLock here blocked unrelated writes
  // and other receipt-sync requests, producing repeated Lock timeout errors.
  let meta = null;
  const readLock = LockService.getScriptLock();
  readLock.waitLock(3000);
  try { try { meta = JSON.parse(props.getProperty(metaKey) || 'null'); } catch (e) {} }
  finally { readLock.releaseLock(); }
  if (meta && meta.signature === signature && meta.fileId) {
    try { const cachedFile = DriveApp.getFileById(meta.fileId); if (!cachedFile.isTrashed()) return cachedFile; } catch (e) {}
  }

  // Do the expensive work without the global lock so the app remains responsive.
  const pdf = getReceiptPdf(_authSession, id);
  if (!pdf || !pdf.base64) throw new Error('Unable to create PDF receipt.');
  const blob = Utilities.newBlob(Utilities.base64Decode(pdf.base64), MimeType.PDF, pdf.name || ('PetShop-Receipt-'+id+'.pdf'));
  const folderName = 'PetShop Receipts';
  const folders = DriveApp.getFoldersByName(folderName);
  const folder = folders.hasNext() ? folders.next() : DriveApp.createFolder(folderName);
  const file = folder.createFile(blob);
  try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (e) {}
  const nextMeta = {saleId:id, fileId:file.getId(), signature:signature, status:'READY', generatedAt:new Date().toISOString()};
  const writeLock = LockService.getScriptLock();
  writeLock.waitLock(3000);
  try {
    // If another request finished the same receipt while this one rendered, prefer its
    // valid file and trash this duplicate rather than replacing the current metadata.
    let latest = null;
    try { latest = JSON.parse(props.getProperty(metaKey) || 'null'); } catch (e) {}
    if (latest && latest.signature === signature && latest.fileId && latest.fileId !== file.getId()) {
      try { const existing = DriveApp.getFileById(latest.fileId); if (!existing.isTrashed()) { try { file.setTrashed(true); } catch (ignored) {} return existing; } } catch (e) {}
    }
    props.setProperty(metaKey, JSON.stringify(nextMeta));
    try { CacheService.getScriptCache().put(receiptCacheKey_('pdfFile', id), file.getId(), 21600); } catch (e) {}
  } finally { writeLock.releaseLock(); }
  return file;
}
function preGenerateReceipt(_authSession, saleId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const file = getOrCreateReceiptPdfFile_(_authSession, saleId);
  return {ok:true, sale_id:String(saleId), file_id:file.getId(), status:'READY'};
}
const RECEIPT_QUEUE_KEY_ = 'PETSHOP_RECEIPT_GENERATION_QUEUE_V1';
function enqueueReceiptGeneration_(saleId) {
  const id = String(saleId || '').trim();
  if (!id) return false;
  const props = PropertiesService.getScriptProperties();
  const lock = LockService.getScriptLock();
  lock.waitLock(5000);
  try {
    let queue = [];
    try { queue = JSON.parse(props.getProperty(RECEIPT_QUEUE_KEY_) || '[]'); } catch (e) {}
    if (!Array.isArray(queue)) queue = [];
    if (!queue.includes(id)) queue.push(id);
    props.setProperty(RECEIPT_QUEUE_KEY_, JSON.stringify(queue.slice(-500)));
  } finally { lock.releaseLock(); }
  scheduleReceiptGeneration_();
  return true;
}
function scheduleReceiptGeneration_() {
  const exists = ScriptApp.getProjectTriggers().some(t => t.getHandlerFunction() === 'processReceiptGenerationQueue_');
  if (!exists) ScriptApp.newTrigger('processReceiptGenerationQueue_').timeBased().after(1000).create();
}
function processReceiptGenerationQueue_() {
  const props = PropertiesService.getScriptProperties();
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  let batch = [];
  try {
    let queue = [];
    try { queue = JSON.parse(props.getProperty(RECEIPT_QUEUE_KEY_) || '[]'); } catch (e) {}
    if (!Array.isArray(queue)) queue = [];
    batch = queue.splice(0, 3);
    props.setProperty(RECEIPT_QUEUE_KEY_, JSON.stringify(queue));
  } finally { lock.releaseLock(); }
  // Remove this one-shot trigger before processing; another batch can schedule a new one.
  ScriptApp.getProjectTriggers().filter(t => t.getHandlerFunction() === 'processReceiptGenerationQueue_').forEach(t => ScriptApp.deleteTrigger(t));
  batch.forEach(id => {
    RECEIPT_BACKGROUND_CONTEXT_ = true;
    try {
      getOrCreateReceiptPdfFile_(null, id, true);
    } catch (e) {
      try {
        const metaKey = receiptMetadataKey_(id), current = JSON.parse(props.getProperty(metaKey) || '{}');
        current.saleId = id; current.status = 'FAILED'; current.error = String(e && e.message || e).slice(0, 180); current.failedAt = new Date().toISOString();
        props.setProperty(metaKey, JSON.stringify(current));
      } catch (ignored) {}
      console.error('Receipt background generation failed for ' + id + ': ' + String(e && e.message || e));
    } finally {
      RECEIPT_BACKGROUND_CONTEXT_ = false;
    }
  });
  let remaining = [];
  try { remaining = JSON.parse(props.getProperty(RECEIPT_QUEUE_KEY_) || '[]'); } catch (e) {}
  if (Array.isArray(remaining) && remaining.length) scheduleReceiptGeneration_();
  return {processed:batch.length, remaining:Array.isArray(remaining)?remaining.length:0};
}
function getReceiptStatuses(_authSession, saleIds) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const ids = Array.isArray(saleIds) ? saleIds.slice(0, 100) : [];
  const props = PropertiesService.getScriptProperties();
  const out = {};
  ids.forEach(value => {
    const id = String(value || '').trim();
    if (!id) return;
    let meta = null;
    try { meta = JSON.parse(props.getProperty(receiptMetadataKey_(id)) || 'null'); } catch (e) {}
    let ready = !!(meta && meta.status === 'READY' && meta.fileId && meta.signature === receiptRevisionSignature_(id));
    if (ready) { try { ready = !DriveApp.getFileById(meta.fileId).isTrashed(); } catch (e) { ready = false; } }
    out[id] = ready ? 'READY' : (meta && meta.status === 'FAILED' ? 'FAILED' : 'MISSING');
  });
  return out;
}
const RECEIPT_SYNC_QUEUE_KEY_ = 'PETSHOP_RECEIPT_SYNC_QUEUE_V1';
const RECEIPT_SYNC_STATE_KEY_ = 'PETSHOP_RECEIPT_SYNC_STATE_V1';
function receiptSyncState_() { const p=PropertiesService.getScriptProperties(); try { return JSON.parse(p.getProperty(RECEIPT_SYNC_STATE_KEY_)||'null') || null; } catch(e) { return null; } }
const RECEIPT_SYNC_LAST_COMPLETED_KEY_ = 'PETSHOP_RECEIPT_SYNC_LAST_COMPLETED_AT_V1';
function startReceiptSync(_authSession, limit) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const requestedLimit = Number(limit) > 0 ? Math.max(1, Math.min(50, Math.floor(Number(limit)))) : 0;
  const props=PropertiesService.getScriptProperties(), lock=LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const existing=receiptSyncState_();
    if(existing && existing.active) return {active:true,jobId:existing.jobId,total:existing.total,processed:existing.processed||0,generated:existing.generated||0,skipped:existing.skipped||0,failed:existing.failed||0,newCount:existing.total||0,message:'Receipt sync is already running.'};
    let lastSyncAt=String(props.getProperty(RECEIPT_SYNC_LAST_COMPLETED_KEY_)||'').trim();
    // Migrate the previous completed sync once, so upgrading does not restart the old queue.
    if(!lastSyncAt && existing && !existing.active && Number(existing.total||0)>0 && Number(existing.processed||0)>=Number(existing.total||0) && Number(existing.failed||0)===0) {
      lastSyncAt=String(existing.syncCutoffAt||existing.updatedAt||existing.startedAt||'').trim();
      if(lastSyncAt) props.setProperty(RECEIPT_SYNC_LAST_COMPLETED_KEY_,lastSyncAt);
    }
    const cutoffAt=new Date().toISOString();
    const allSales=rows_('Sales').filter(s=>String(s.sale_id||'').trim()).sort((a,b)=>String(a.sale_at||'').localeCompare(String(b.sale_at||'')));
    let sales;
    if(lastSyncAt) {
      const cutoffMs=Date.parse(lastSyncAt);
      sales=allSales.filter(s=>{const t=Date.parse(String(s.sale_at||''));return Number.isFinite(t)&&Number.isFinite(cutoffMs)&&t>cutoffMs&&t<=Date.parse(cutoffAt);});
    } else {
      // First run after installation: preserve the existing newest-50 login pass.
      sales=allSales.slice().reverse().slice(0,requestedLimit||50);
    }
    if(requestedLimit && !lastSyncAt) sales=sales.slice(0,requestedLimit);
    const queue=sales.map(s=>String(s.sale_id||'').trim()).filter(Boolean);
    if(!queue.length) {
      const state={active:false,jobId:'RS-'+Utilities.getUuid().replace(/-/g,'').slice(0,12),total:0,processed:0,generated:0,skipped:0,failed:0,failureDetails:[],startedAt:cutoffAt,syncCutoffAt:cutoffAt,updatedAt:cutoffAt,newCount:0,message:'No new receipts since last sync · 0 new'};
      props.setProperty(RECEIPT_SYNC_STATE_KEY_,JSON.stringify(state));
      return {active:false,jobId:state.jobId,total:0,processed:0,generated:0,skipped:0,failed:0,newCount:0,message:state.message};
    }
    const state={active:true,jobId:'RS-'+Utilities.getUuid().replace(/-/g,'').slice(0,12),total:queue.length,processed:0,generated:0,skipped:0,failed:0,failureDetails:[],startedAt:cutoffAt,syncCutoffAt:cutoffAt,newCount:queue.length,message:'Checking '+queue.length+' new receipts in background…'};
    props.setProperty(RECEIPT_SYNC_QUEUE_KEY_,JSON.stringify(queue));
    props.setProperty(RECEIPT_SYNC_STATE_KEY_,JSON.stringify(state));
    return {active:true,jobId:state.jobId,total:state.total,processed:0,generated:0,skipped:0,failed:0,newCount:queue.length,message:state.message};
  } finally { lock.releaseLock(); }
}
function scheduleReceiptSync_() {
  // Receipt sync is advanced by the authenticated browser poller; do not inspect/create project triggers.
  return true;
}
function processReceiptSyncQueue_(_authSession) {  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);

  const props=PropertiesService.getScriptProperties(),lock=LockService.getScriptLock(); let batch=[];
  lock.waitLock(10000);
  try { let q=[];try{q=JSON.parse(props.getProperty(RECEIPT_SYNC_QUEUE_KEY_)||'[]');}catch(e){};if(!Array.isArray(q))q=[];batch=q.splice(0,2);props.setProperty(RECEIPT_SYNC_QUEUE_KEY_,JSON.stringify(q)); }
  finally { lock.releaseLock(); }
  // No trigger cleanup needed: receipt sync batches are driven by the authenticated browser poller.
  let generated=0,skipped=0,failed=0;const failureDetails=[];
  batch.forEach(id=>{RECEIPT_BACKGROUND_CONTEXT_=true;try{const before=receiptMetadataForSync_(id);getOrCreateReceiptPdfFile_(_authSession, id, true);const after=receiptMetadataForSync_(id);if(before&&after&&before.signature===after.signature&&before.fileId===after.fileId)skipped++;else generated++;}catch(e){failed++;const message=String(e&&e.message||e).slice(0,180);failureDetails.push({sale_id:String(id),error:message});try{const key=receiptMetadataKey_(id),old=JSON.parse(props.getProperty(key)||'{}');old.saleId=id;old.status='FAILED';old.error=message;old.failedAt=new Date().toISOString();props.setProperty(key,JSON.stringify(old));}catch(ignore){}}finally{RECEIPT_BACKGROUND_CONTEXT_=false;}});
  const lock2=LockService.getScriptLock();lock2.waitLock(10000);let remain=0;try{let q=[];try{q=JSON.parse(props.getProperty(RECEIPT_SYNC_QUEUE_KEY_)||'[]');}catch(e){};remain=Array.isArray(q)?q.length:0;const state=receiptSyncState_()||{total:batch.length,processed:0,generated:0,skipped:0,failed:0};state.processed=Math.min(Number(state.total||0),Number(state.processed||0)+batch.length);state.generated=Number(state.generated||0)+generated;state.skipped=Number(state.skipped||0)+skipped;state.failed=Number(state.failed||0)+failed;state.failureDetails=(Array.isArray(state.failureDetails)?state.failureDetails:[]).concat(failureDetails).slice(-50);state.active=remain>0;state.updatedAt=new Date().toISOString();state.message=`${state.processed} / ${state.total} finished · ${state.generated} generated · ${state.skipped} already ready · ${state.failed} failed`;if(!state.active&&Number(state.failed||0)===0){state.lastCompletedAt=state.updatedAt;props.setProperty(RECEIPT_SYNC_LAST_COMPLETED_KEY_,String(state.syncCutoffAt||state.updatedAt));}props.setProperty(RECEIPT_SYNC_STATE_KEY_,JSON.stringify(state));}finally{lock2.releaseLock();}
  if(remain) scheduleReceiptSync_();
  return {processed:batch.length,remaining:remain};
}
function receiptMetadataForSync_(id){try{return JSON.parse(PropertiesService.getScriptProperties().getProperty(receiptMetadataKey_(id))||'null');}catch(e){return null;}}
function getReceiptSyncProgress(_authSession){requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);const s=receiptSyncState_();if(!s)return {active:false,total:0,processed:0,generated:0,skipped:0,failed:0,failureDetails:[],message:'No receipt sync has run.'};let failureDetails=Array.isArray(s.failureDetails)?s.failureDetails:[];if(!s.active&&Number(s.failed||0)>0&&!failureDetails.length){failureDetails=[];rows_('Sales').forEach(row=>{if(failureDetails.length>=50)return;const id=String(row.sale_id||'').trim();if(!id)return;const meta=receiptMetadataForSync_(id);if(meta&&meta.status==='FAILED')failureDetails.push({sale_id:id,error:String(meta.error||'No error detail recorded')});});}return {active:!!s.active,jobId:s.jobId,total:Number(s.total||0),processed:Number(s.processed||0),generated:Number(s.generated||0),skipped:Number(s.skipped||0),failed:Number(s.failed||0),failureDetails:failureDetails,message:String(s.message||'')};}

function syncReceiptBatch(_authSession, offset, limit) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const start = Math.max(0, Number(offset) || 0);
  const size = Math.max(1, Math.min(8, Number(limit) || 5));
  const sales = rows_('Sales').filter(s => String(s.sale_id || '').trim()).sort((a,b) => String(a.sale_at||'').localeCompare(String(b.sale_at||'')));
  const batch = sales.slice(start, start + size);
  let generated = 0, skipped = 0, failed = 0;
  const errors = [];
  batch.forEach(s => {
    try {
      const signature = receiptRevisionSignature_(s.sale_id);
      const props = PropertiesService.getScriptProperties();
      let meta = null;
      try { meta = JSON.parse(props.getProperty(receiptMetadataKey_(s.sale_id)) || 'null'); } catch (e) {}
      if (meta && meta.signature === signature && meta.fileId) {
        try { const existingFile = DriveApp.getFileById(meta.fileId); if (!existingFile.isTrashed()) { skipped++; return; } } catch (e) {}
      }
      getOrCreateReceiptPdfFile_(_authSession, s.sale_id, false);
      generated++;
    } catch (e) { failed++; errors.push({sale_id:String(s.sale_id), message:String(e && e.message || e).slice(0,180)}); }
  });
  return {offset:start, nextOffset:start+batch.length, total:sales.length, done:start+batch.length>=sales.length, generated:generated, skipped:skipped, failed:failed, errors:errors};
}
function emailSaleReceipt(_authSession, saleId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const snap = saleSnapshot_(saleId);
  if (!snap) throw new Error('Sale not found.');
  const c = snap.customer || {};
  const to = String(c.email || '').trim();
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) throw new Error('Customer email is missing or invalid.');
  const file = getOrCreateReceiptPdfFile_(_authSession, saleId);
  const s = snap.sale || {};
  const co = getCompanySettings_();
  const shop = String(co.store_name || 'PetShop').trim() || 'PetShop';
  MailApp.sendEmail({to:to,subject:shop+' Receipt '+String(saleId),body:'Receipt '+String(saleId)+'.',attachments:[file.getBlob().setName('PetShop-Receipt-'+String(saleId)+'.pdf')]});
  return {sent:true,to:to,sale_id:String(saleId)};
}
function getReceiptPdfLink(_authSession, saleId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const file = getOrCreateReceiptPdfFile_(_authSession, saleId);
  return 'https://drive.google.com/uc?export=download&id=' + encodeURIComponent(file.getId());
}
// Create a JPG preview from Drive's rendered PDF thumbnail and keep it alongside the cached PDF.
// The full PDF remains available for download; the JPG is intended for quick WhatsApp preview.
function getOrCreateReceiptJpgFile_(_authSession, saleId, internalBackground) {
  if (!internalBackground) requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Sale ID is required.');
  const signature = receiptRevisionSignature_(id);
  const props = PropertiesService.getScriptProperties();
  const metaKey = receiptMetadataKey_(id);
  let meta = null;
  try { meta = JSON.parse(props.getProperty(metaKey) || 'null'); } catch (e) {}
  if (meta && meta.signature === signature && meta.jpgFileId) {
    try { const cached = DriveApp.getFileById(meta.jpgFileId); if (!cached.isTrashed()) return cached; } catch (e) {}
  }
  const pdfFile = getOrCreateReceiptPdfFile_(_authSession, id, !!internalBackground);
  let thumbnail = null;
  for (let attempt = 0; attempt < 3 && !thumbnail; attempt++) {
    try { thumbnail = pdfFile.getThumbnail(); } catch (e) {}
    if (!thumbnail && attempt < 2) Utilities.sleep(800);
  }
  if (!thumbnail) throw new Error('Google Drive has not produced a receipt preview image yet. Please retry in a few seconds.');
  let jpg;
  try { jpg = thumbnail.getAs(MimeType.JPEG); } catch (e) { throw new Error('Could not convert the receipt preview to JPG: ' + String(e && e.message || e)); }
  jpg.setName('PetShop-Receipt-' + id + '.jpg');
  const folders = DriveApp.getFoldersByName('PetShop Receipts');
  const folder = folders.hasNext() ? folders.next() : DriveApp.createFolder('PetShop Receipts');
  const jpgFile = folder.createFile(jpg);
  try { jpgFile.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (e) {}
  // Merge rather than overwrite the PDF metadata.
  try { meta = JSON.parse(props.getProperty(metaKey) || '{}'); } catch (e) { meta = {}; }
  meta.saleId = id; meta.signature = signature; meta.jpgFileId = jpgFile.getId(); meta.jpgGeneratedAt = new Date().toISOString();
  props.setProperty(metaKey, JSON.stringify(meta));
  return jpgFile;
}
function getReceiptWhatsAppLinks(_authSession, saleId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Sale ID is required.');
  if (!rows_('Sales').some(x => String(x.sale_id) === id)) throw new Error('Sale not found.');
  return { sale_id: id, preview_url: receiptUrl(id) };
}
function getSessionTimeoutSetting(_authSession) {
  requireRole_(_authSession, ['OWNER']);
  const value = String(PropertiesService.getScriptProperties().getProperty(SESSION_TIMEOUT_KEY_) || String(SESSION_HOURS)).trim().toLowerCase();
  return ['1','4','8','12','24','168','never'].includes(value) ? value : String(SESSION_HOURS);
}
function saveSessionTimeoutSetting(_authSession, value) {
  requireRole_(_authSession, ['OWNER']);
  value = String(value == null ? '' : value).trim().toLowerCase();
  if (!['1','4','8','12','24','168','never'].includes(value)) throw new Error('Choose a valid session timeout.');
  PropertiesService.getScriptProperties().setProperty(SESSION_TIMEOUT_KEY_, value);
  return { value: value, label: value === 'never' ? 'Never' : (value === '168' ? '7 days' : value + ' hours') };
}
function getCompanySettings(_authSession) { requireRole_(_authSession, ['OWNER','MANAGER']); return getCompanySettings_(); }
function getCompanySettings_() {
  const cache = CacheService.getScriptCache();
  const cacheKey = 'petshop_company_settings_v1_' + (PropertiesService.getScriptProperties().getProperty('DATA_VERSION_COL_Settings') || '0');
  try { const cached = cache.get(cacheKey); if (cached) return JSON.parse(cached); } catch (e) {}
  const rows = rows_('Settings');
  const get = key => { const r = rows.find(x => String(x.key) === key); return r ? String(r.value || '') : ''; };
  const result = {
    store_name: get('COMPANY_STORE_NAME'),
    address: get('COMPANY_ADDRESS'),
    email: get('COMPANY_EMAIL'),
    contact: get('COMPANY_CONTACT'),
    logo_url: get('COMPANY_LOGO_URL'),
    tng_qr_url: get('COMPANY_TNG_QR_URL'),
    tng_qr_active: get('COMPANY_TNG_QR_ACTIVE') !== 'false',
    duitnow_qr_url: get('COMPANY_DUITNOW_QR_URL'),
    duitnow_qr_active: get('COMPANY_DUITNOW_QR_ACTIVE') !== 'false',
    socmed_qr_url: get('COMPANY_SOCMED_QR_URL'),
    socmed_qr_active: get('COMPANY_SOCMED_QR_ACTIVE') === 'true',
    receipt_design: get('RECEIPT_DESIGN') || 'professional',
    receipt_delivery: ['email','whatsapp'].indexOf(get('RECEIPT_DELIVERY')) >= 0 ? get('RECEIPT_DELIVERY') : 'email',
    show_grooming_before_after_photos: get('SHOW_GROOMING_BEFORE_AFTER_PHOTOS') === 'true',
    require_receipt_phone_last4: get('REQUIRE_RECEIPT_PHONE_LAST4').trim().toLowerCase() === 'true'
  };
  try { cache.put(cacheKey, JSON.stringify(result), 300); } catch (e) {}
  return result;
}
function saveCompanySettings(_authSession, data) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  data = data || {};
  const currentUser = requireAuthorizedUser_(_authSession);
  const values = {
    COMPANY_STORE_NAME: String(data.store_name || '').trim(),
    COMPANY_ADDRESS: String(data.address || '').trim(),
    COMPANY_EMAIL: String(data.email || '').trim(),
    COMPANY_CONTACT: String(data.contact || '').trim(),
    COMPANY_LOGO_URL: String(data.logo_url || '').trim(),
    COMPANY_TNG_QR_URL: String(data.tng_qr_url || '').trim(),
    COMPANY_TNG_QR_ACTIVE: data.tng_qr_active === false ? 'false' : 'true',
    COMPANY_DUITNOW_QR_URL: String(data.duitnow_qr_url || '').trim(),
    COMPANY_DUITNOW_QR_ACTIVE: data.duitnow_qr_active === false ? 'false' : 'true',
    COMPANY_SOCMED_QR_URL: String(data.socmed_qr_url || '').trim(),
    COMPANY_SOCMED_QR_ACTIVE: data.socmed_qr_active === true ? 'true' : 'false',
    RECEIPT_DESIGN: ['classic','minimal','cute','professional'].indexOf(String(data.receipt_design || 'professional')) >= 0 ? String(data.receipt_design || 'professional') : 'professional',
    RECEIPT_DELIVERY: ['email','whatsapp'].indexOf(String(data.receipt_delivery || 'email').toLowerCase()) >= 0 ? String(data.receipt_delivery || 'email').toLowerCase() : 'email'
  };
  if (Object.prototype.hasOwnProperty.call(data, 'show_grooming_before_after_photos')) {
    if (currentUser.role !== 'OWNER') throw new Error('Only the owner can change grooming receipt photo settings.');
    values.SHOW_GROOMING_BEFORE_AFTER_PHOTOS = data.show_grooming_before_after_photos === true ? 'true' : 'false';
  }
  if (Object.prototype.hasOwnProperty.call(data, 'require_receipt_phone_last4')) {
    values.REQUIRE_RECEIPT_PHONE_LAST4 = data.require_receipt_phone_last4 === true ? 'true' : 'false';
  }
  Object.keys(values).forEach(key => upsertRow_(_authSession, 'Settings', {key: key, value: values[key]}, 'key', true));
  bumpVersion_('Settings');
  try { CacheService.getScriptCache().removeAll(['petshop_company_settings_v1_' + (PropertiesService.getScriptProperties().getProperty('DATA_VERSION_COL_Settings') || '0')]); } catch (e) {}
  return getCompanySettings_();
}
function expireMemberships_() {
  const today = Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM-dd');
  const sh = getSS_().getSheetByName('Memberships');
  if (!sh || sh.getLastRow() < 2) return;
  const values = sh.getDataRange().getValues();
  const headers = values[0].map(String);
  const statusCol = headers.indexOf('status'), expiryCol = headers.indexOf('expiry_date');
  if (statusCol < 0 || expiryCol < 0) return;
  let changed = false;
  for (let r = 1; r < values.length; r++) {
    const status = String(values[r][statusCol] || '').trim().toUpperCase();
    let expiry = values[r][expiryCol];
    if (expiry instanceof Date) expiry = Utilities.formatDate(expiry, Session.getScriptTimeZone(), 'yyyy-MM-dd');
    else {
      expiry = String(expiry || '').trim();
      const iso = expiry.match(/^(\d{4}-\d{2}-\d{2})/);
      const dmy = expiry.match(/^(\d{1,2})[\/.-](\d{1,2})[\/.-](\d{4})$/);
      if (iso) expiry = iso[1];
      else if (dmy) expiry = dmy[3] + '-' + String(dmy[2]).padStart(2, '0') + '-' + String(dmy[1]).padStart(2, '0');
      else expiry = '';
    }
    if (status === 'ACTIVE' && expiry && expiry < today) {
      sh.getRange(r + 1, statusCol + 1).setValue('EXPIRED');
      changed = true;
    }
  }
  if (changed) bumpVersion_('Memberships');
}
function getData(_authSession) {
  const user = requireAuthorizedUser_(_authSession);
  expireMemberships_();
  const canViewSales = roleCanOpenPage_(user.role, 'sales');
  return {
    customers: rows_('Customers'),
    pets: rows_('Pets'),
    plans: rows_('MembershipPlans'),
    memberships: rows_('Memberships'),
    services: rows_('Services'),
    products: rows_('Products').map(p => { const x = {...p}; if (user.role === 'STAFF') { delete x.cost; delete x.avg_cost; } return x; }),
    categories: getProductCategories_(),
    promotions: rows_('Promotions'),
    bookings: rows_('Bookings'),
    boarding: rows_('Boarding'),
    boardingRooms: boardingRoomRows_(),
    groomerWork: groomerWorkRows_(),
    sales: canViewSales ? rows_('Sales').slice(-200) : [],
    company: getCompanySettings_()
  };
}
function getSalesPageData(_authSession, fromDate, toDate, saleIdQuery) {
  const user = requireAuthorizedUser_(_authSession);
  if (!roleCanOpenPage_(user.role, 'sales')) throw new Error('Permission denied. Your role does not have access to this page.');
  expireMemberships_();
  const from = String(fromDate || '').slice(0, 10), to = String(toDate || '').slice(0, 10);
  const query = String(saleIdQuery || '').trim().toLowerCase();
  const allSales = rows_('Sales');
  // When searching by Sale ID, search the complete sales history instead of restricting results to the selected date range.
  const sales = allSales.filter(s => {
    if (query) return String(s.sale_id || '').toLowerCase().includes(query);
    const k = String(s.sale_at || '').slice(0, 10);
    return (!from || k >= from) && (!to || k <= to);
  });
  const ids = new Set(sales.map(s => String(s.sale_id)));
  const saleRevisions = rows_('SaleRevisions').filter(r => ids.has(String(r.sale_id)));
  const customerIds = new Set(sales.map(s => String(s.customer_id || '')).filter(Boolean));
  const petIds = new Set(sales.map(s => String(s.pet_id || '')).filter(Boolean));
  return {sales:sales, saleRevisions:saleRevisions, customers:rows_('Customers').filter(c => customerIds.has(String(c.customer_id))), pets:rows_('Pets').filter(p => petIds.has(String(p.pet_id)))};
}
function getPageData(_authSession, page) {
  const user = requireAuthorizedUser_(_authSession);
  if (!roleCanOpenPage_(user.role, page)) throw new Error('Permission denied. Your role does not have access to this page.');
  expireMemberships_();
  const read = n => rows_(n);
  if (page === 'customers') return {customers:read('Customers'),pets:read('Pets'),memberships:read('Memberships'),plans:read('MembershipPlans')};
  if (page === 'bookings') return {bookings:read('Bookings'),pets:read('Pets'),services:read('Services'),customers:read('Customers')};
  if (page === 'groomer') return {bookings:read('Bookings'),pets:read('Pets'),services:read('Services'),customers:read('Customers'),groomerWork:groomerWorkRows_()};
  if (page === 'boarding') return {boarding:read('Boarding'),boardingRooms:boardingRoomRows_(),pets:read('Pets'),customers:read('Customers'),services:read('Services')};
  if (page === 'pos') return {customers:read('Customers'),services:read('Services'),products:read('Products'),memberships:read('Memberships'),plans:read('MembershipPlans'),categories:getProductCategories_(),promotions:read('Promotions')};
  if (page === 'membership') return {memberships:read('Memberships'),customers:read('Customers'),plans:read('MembershipPlans')};
  if (page === 'catalog') { const products=read('Products').map(p=>{const x={...p};if(requireAuthorizedUser_(_authSession).role==='STAFF'){delete x.cost;delete x.avg_cost;}return x;});return {services:read('Services'),products:products,categories:getProductCategories_(),promotions:read('Promotions')}; }
  if (page === 'sales') return {sales:read('Sales'),saleRevisions:read('SaleRevisions'),customers:read('Customers'),pets:read('Pets')};
  if (page === 'reports') return {sales:read('Sales').slice(-200),memberships:read('Memberships')};
  if (page === 'all') return getData(_authSession);
  throw new Error('Unknown data page.');
}
function id_(prefix) {
  return prefix + '-' + Utilities.getUuid().slice(0,8).toUpperCase();
}
function append_(sheetName, obj, noBump) {
  const sh = getSS_().getSheetByName(sheetName);
  const headers = SCHEMA[sheetName];
  sh.appendRow(formulaSafeSheetRow_(headers.map(h => obj[h] === undefined ? '' : obj[h])));
  if (!noBump) bumpVersion_(sheetName);
  return plain_(obj);
}
function appendMany_(sheetName, objects, noBump) {
  const list = Array.isArray(objects) ? objects : [];
  if (!list.length) return [];
  const sh = getSS_().getSheetByName(sheetName);
  const headers = SCHEMA[sheetName];
  if (!sh || !headers) throw new Error('Missing sheet schema: ' + sheetName);
  const values = list.map(obj => formulaSafeSheetRow_(headers.map(h => obj[h] === undefined ? '' : obj[h])));
  sh.getRange(sh.getLastRow() + 1, 1, values.length, headers.length).setValues(values);
  if (!noBump) bumpVersion_(sheetName);
  return list.map(plain_);
}
function petShopPhotosFolder_() {
  const root = DriveApp.getRootFolder();
  const folders = root.getFoldersByName('PetShop Photos');
  return folders.hasNext() ? folders.next() : root.createFolder('PetShop Photos');
}
function fileInPetShopPhotosFolder_(file) {
  const folder = petShopPhotosFolder_(), parents = file.getParents();
  while (parents.hasNext()) if (parents.next().getId() === folder.getId()) return true;
  return false;
}
function uploadImage(_authSession, dataUrl, fileName) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const m = String(dataUrl || '').match(/^data:([^;]+);base64,(.+)$/);
  if (!m) throw new Error('Invalid image data.');
  const mime = m[1].toLowerCase();
  if (!/^image\/(jpeg|png|webp|gif)$/.test(mime)) throw new Error('Only JPG, PNG, WEBP or GIF images are supported.');
  const bytes = Utilities.base64Decode(m[2]);
  if (bytes.length > 5 * 1024 * 1024) throw new Error('Image is too large. Maximum 5 MB.');
  const folder = petShopPhotosFolder_();
  const safe = String(fileName || 'photo').replace(/[^A-Za-z0-9._-]/g,'_').slice(-100);
  const file = folder.createFile(Utilities.newBlob(bytes, mime, safe));
  try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (e) {}
  return 'https://drive.google.com/thumbnail?id=' + file.getId() + '&sz=w600';
}
function isApprovedDriveThumbnailUrl_(value) {
  const raw = String(value == null ? '' : value).trim();
  return /^https:\/\/drive\.google\.com\/thumbnail\?id=[A-Za-z0-9_-]+(?:&sz=w[1-9]\d{0,3})?$/.test(raw);
}
function validatePhotoUrlField_(value, fieldName) {
  const label = fieldName || 'Photo';
  if (value === null || value === undefined || value === '') return '';
  let list = null, wasArray = false;
  if (Array.isArray(value)) { list = value; wasArray = true; }
  else if (typeof value === 'string') {
    const raw = value.trim();
    if (!raw) return '';
    if (raw[0] === '[') {
      try { list = JSON.parse(raw); } catch (e) { throw new Error(label + ' URLs are invalid.'); }
      if (!Array.isArray(list)) throw new Error(label + ' URLs must be an array.');
      wasArray = true;
    } else {
      if (!isApprovedDriveThumbnailUrl_(raw)) throw new Error(label + ' must use an approved PetShop Drive thumbnail URL.');
      return raw;
    }
  } else {
    throw new Error(label + ' URLs must be a URL string or an array.');
  }
  if (!list.every(url => typeof url === 'string' && isApprovedDriveThumbnailUrl_(url.trim()))) {
    throw new Error(label + ' contains an invalid or unapproved URL.');
  }
  const clean = [...new Set(list.map(url => url.trim()))];
  return wasArray ? JSON.stringify(clean) : clean[0] || '';
}
function saveReceiptPhotos(_authSession, saleId, photoUrls) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Sale ID is required.');
  const sale = rows_('Sales').find(x => String(x.sale_id) === id);
  if (!sale) throw new Error('Sale not found.');
  let existing = [];
  try { const parsed = JSON.parse(String(sale.receipt_photo_urls || '[]')); if (Array.isArray(parsed)) existing = parsed.map(String); } catch (e) {}
  if (!Array.isArray(photoUrls)) throw new Error('Receipt photos must be provided as an array.');
  const incoming = photoUrls.map(url => {
    if (typeof url !== 'string' || !isApprovedDriveThumbnailUrl_(url.trim())) throw new Error('Receipt photos must use approved PetShop Drive thumbnail URLs.');
    return url.trim();
  }).filter(Boolean);
  const merged = existing.filter(isApprovedDriveThumbnailUrl_).concat(incoming.filter(u => !existing.includes(u) && !existing.filter(isApprovedDriveThumbnailUrl_).includes(u)));
  sale.receipt_photo_urls = JSON.stringify(merged);
  const saved = upsertRow_(_authSession, 'Sales', sale, 'sale_id');
  return saved;
}
function photoRecordReferencesUrl_(recordType, recordId, photoUrl) {
  const type = String(recordType || '').trim();
  const id = String(recordId || '').trim();
  const url = String(photoUrl || '').trim();
  const allowed = {
    Customers: {key:'customer_id', fields:['photo_url']},
    Pets: {key:'pet_id', fields:['photo_url']},
    Products: {key:'product_id', fields:['photo_url']},
    Bookings: {key:'booking_id', fields:['photo_url']},
    Boarding: {key:'boarding_id', fields:['photo_url']},
    Sales: {key:'sale_id', fields:['receipt_photo_urls']},
    GroomerWork: {key:'booking_id', fields:['before_photo_url','after_photo_url']}
  };
  const spec = allowed[type];
  if (!spec || !id || !url) return false;
  const record = rows_(type).find(row => String(row[spec.key] || '') === id);
  if (!record) return false;
  return spec.fields.some(field => {
    const raw = String(record[field] || '').trim();
    if (raw === url) return true;
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) && parsed.map(String).includes(url);
    } catch (e) { return false; }
  });
}
function deletePhoto(_authSession, photoUrl, recordType, recordId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const rawUrl = String(photoUrl || '').trim();
  const m = rawUrl.match(/[?&]id=([A-Za-z0-9_-]+)/);
  if (!m) return true; // already absent / non-Drive placeholder is an idempotent no-op
  if (!photoRecordReferencesUrl_(recordType, recordId, rawUrl)) return true; // do not fail a batch if another live record owns it
  try {
    const file=DriveApp.getFileById(m[1]);
    if(!fileInPetShopPhotosFolder_(file)) return true;
    file.setTrashed(true);
    return true;
  } catch (e) {
    const message=String(e&&e.message||e);
    if (/file not found|not found|no such file|does not exist|already trashed/i.test(message)) return true;
    throw e; // permission, quota, and transient Drive errors must be retried
  }
}
// Return a small inline image so mobile Safari does not have to hot-link a Drive URL.
function getPhotoData(_authSession, photoUrl, recordType, recordId) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const rawUrl = String(photoUrl || '').trim();
  const m = rawUrl.match(/[?&]id=([A-Za-z0-9_-]+)/);
  if (!m) throw new Error('Invalid photo URL.');
  if (!photoRecordReferencesUrl_(recordType, recordId, rawUrl)) throw new Error('Photo is not linked to the specified record.');
  const file = DriveApp.getFileById(m[1]);
  if (!fileInPetShopPhotosFolder_(file)) throw new Error('Photo is outside the PetShop Photos folder.');
  const cache=CacheService.getScriptCache(), cacheKey='petshop_photo_'+file.getId()+'_'+file.getLastUpdated().getTime();
  try { const cached=cache.get(cacheKey); if(cached)return cached; } catch(e) {}
  let blob = null;
  try { blob = file.getThumbnail(); } catch (e) {}
  if (!blob) blob = file.getBlob();
  const mime = String(blob.getContentType() || 'image/jpeg');
  if (!/^image\/(jpeg|png|webp|gif)$/i.test(mime)) throw new Error('Unsupported photo type.');
  const dataUrl='data:' + mime + ';base64,' + Utilities.base64Encode(blob.getBytes());
  try { if(dataUrl.length<95000)cache.put(cacheKey,dataUrl,21600); } catch(e) {}
  return dataUrl;
}
function saveCustomer(_authSession, c) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  c = c || {};
  c.photo_url = validatePhotoUrlField_(c.photo_url, 'Customer photo');
  c.phone = normalizePhone_(c.phone);
  c.customer_id = c.customer_id || id_('CUS');
  c.created_at = c.created_at || new Date();
  c.active = c.active !== false;
  return upsertRow_(_authSession, 'Customers', c, 'customer_id');
}
function savePet(_authSession, p) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  p = p || {};
  p.photo_url = validatePhotoUrlField_(p.photo_url, 'Pet photo');
  // Sticky note is a separate Pets field; never derive it from the general notes field.
  p.sticky_note = String(p.sticky_note || '').trim();
  p.pet_id = p.pet_id || id_('PET');
  p.created_at = p.created_at || new Date();
  p.active = p.active !== false;
  return upsertRow_(_authSession, 'Pets', p, 'pet_id');
}
function saveMembershipPlan(_authSession, p) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  p = p || {};
  if (!String(p.name || '').trim()) throw new Error('Membership plan name required.');
  p.plan_id = p.plan_id || id_('PLN');
  p.name = String(p.name).trim();
  p.price = Number(p.price || 0);
  p.duration_days = Number(p.duration_days || 0);
  p.grooming_discount_pct = Number(p.grooming_discount_pct || 0);
  p.boarding_discount_pct = Number(p.boarding_discount_pct || 0);
  p.retail_discount_pct = Number(p.retail_discount_pct || 0);
  p.points_multiplier = Number(p.points_multiplier || 1);
  p.active = p.active !== false;
  if (p.price < 0 || p.duration_days < 0 || p.grooming_discount_pct < 0 || p.boarding_discount_pct < 0 || p.retail_discount_pct < 0 || p.points_multiplier < 0) {
    throw new Error('Invalid membership plan values.');
  }
  return upsertRow_(_authSession, 'MembershipPlans', p, 'plan_id');
}
function saveMembership(_authSession, m) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  m = m || {};
  if (!m.customer_id || !m.plan_id) throw new Error('Customer and plan are required.');
  if (!rows_('MembershipPlans').some(p => String(p.plan_id) === String(m.plan_id))) throw new Error('Membership plan not found.');
  m.membership_id = m.membership_id || id_('MEM');
  m.status = m.status || 'ACTIVE';
  m.points_balance = Number(m.points_balance || 0);
  return append_('Memberships', m);
}
function saveBooking(_authSession, b) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  b = b || {};
  b.booking_id = b.booking_id || id_('BKG');
  b.status = b.status || 'BOOKED';
  b.photo_url = validatePhotoUrlField_(b.photo_url, 'Grooming photo');
  b.calendar_color = String(b.calendar_color || '');
  b.created_at = b.created_at || new Date();
  // Resolve the sheet here before writing so a missing spreadsheet connection
  // produces a clear error instead of a null.getSheetByName() failure.
  const ss = getSS_(false);
  if (!ss) throw new Error('PetShop spreadsheet is not linked.');
  const sh = ss.getSheetByName('Bookings');
  if (!sh) throw new Error('Missing sheet: Bookings. Run setup() once.');
  return upsertRow_(_authSession, 'Bookings', b, 'booking_id');
}
function ensureBoardingRoomsSheet_(){const ss=getSS_(true);let sh=ss.getSheetByName('BoardingRooms');if(!sh)sh=ss.insertSheet('BoardingRooms');ensureSchema_(sh,SCHEMA.BoardingRooms);return sh;}
function boardingRoomRows_(){ensureBoardingRoomsSheet_();return rows_('BoardingRooms');}
function saveBoardingRoom(_authSession, room){requireRole_(_authSession, ['OWNER','MANAGER']);room=room||{};room.room_id=String(room.room_id||id_('ROOM'));room.name=String(room.name||'').trim();room.category=String(room.category||'').trim();room.notes=String(room.notes||'').trim();room.photo_url=validatePhotoUrlField_(room.photo_url,'Boarding room photo');room.active=room.active!==false&&room.active!=='false';const old=boardingRoomRows_().find(x=>String(x.room_id)===room.room_id);if(!room.name)throw new Error('Room name is required.');if(boardingRoomRows_().some(x=>String(x.room_id)!==room.room_id&&String(x.name||'').toLowerCase()===room.name.toLowerCase()))throw new Error('A boarding room with this name already exists.');if(old){room.created_at=old.created_at||'';room.updated_at=new Date().toISOString();}else{room.created_at=new Date().toISOString();room.updated_at=room.created_at;}const saved=upsertRow_(_authSession, 'BoardingRooms',room,'room_id');bumpVersion_();return saved;}
function deleteBoardingRoom(_authSession, roomId){requireRole_(_authSession, ['OWNER','MANAGER']);const id=String(roomId||'');if(!id)throw new Error('Room ID is required.');const used=rows_('Boarding').some(b=>String(b.room_id||'')===id&&!['COMPLETED','CANCELLED','CANCELED','CHECKED_OUT','CHECKEDOUT'].includes(String(b.status||'').toUpperCase().replace(/[ _-]+/g,'_')));if(used)throw new Error('Cannot delete a room with an active booking.');return deleteRow_(_authSession, 'BoardingRooms','room_id',id);}
function boardingRoomConflict_(roomId,checkIn,checkOut,excludeId){const start=Date.parse(checkIn||''),end=Date.parse(checkOut||'');if(!Number.isFinite(start)||!Number.isFinite(end)||end<=start)throw new Error('Enter valid boarding check-in and check-out times.');const room=boardingRoomRows_().find(r=>String(r.room_id)===String(roomId));return rows_('Boarding').some(b=>String(b.boarding_id)!==String(excludeId||'')&&(String(b.room_id||'')===String(roomId)||(!String(b.room_id||'')&&room&&String(b.room||'').trim().toLowerCase()===String(room.name||'').trim().toLowerCase()))&&!['COMPLETED','CANCELLED','CANCELED','CHECKED_OUT','CHECKEDOUT'].includes(String(b.status||'').toUpperCase().replace(/[ _-]+/g,'_'))&&Number.isFinite(Date.parse(b.check_in||''))&&Number.isFinite(Date.parse(b.check_out||''))&&start<Date.parse(b.check_out)&&end>Date.parse(b.check_in));}
function getBoardingRoomAvailability(_authSession, checkIn, checkOut, excludeId){requireAuthorizedUser_(_authSession);const rooms=boardingRoomRows_().filter(r=>r.active!==false&&r.active!=='false');return rooms.map(r=>Object.assign({},r,{vacant:!boardingRoomConflict_(r.room_id,checkIn,checkOut,excludeId)}));}
function saveBoardingBatch(_authSession, bookings) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  if (!Array.isArray(bookings) || !bookings.length) throw new Error('Select at least one pet for boarding.');
  if (bookings.length > 30) throw new Error('Create up to 30 boarding bookings at a time.');
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    // Read the required collections once for the entire multi-pet booking.
    const services = rows_('Services');
    const rooms = boardingRoomRows_();
    const existing = rows_('Boarding');
    const prepared = bookings.map(function(input) {
      const b = Object.assign({}, input || {});
      b.boarding_id = String(b.boarding_id || id_('BRD'));
      b.status = String(b.status || 'BOOKED');
      b.photo_url = validatePhotoUrlField_(b.photo_url, 'Boarding photo');
      b.calendar_color = String(b.calendar_color || '');
      b.service_id = String(b.service_id || '').trim();
      b.room_id = String(b.room_id || '').trim();
      b.room = String(b.room || '').trim();
      b.check_in = String(b.check_in || '');
      b.check_out = String(b.check_out || '');
      if (!b.customer_id || !b.pet_id) throw new Error('Select a customer and pet for boarding.');
      if (!b.service_id) throw new Error('Select a boarding package.');
      if (!services.some(function(s){return String(s.service_id)===b.service_id && String(s.category||'').toLowerCase().includes('boarding') && s.active!==false && s.active!=='false';})) throw new Error('Selected boarding package is unavailable.');
      if (!b.room_id) throw new Error('Select a vacant boarding room for each pet.');
      const room = rooms.find(function(r){return String(r.room_id)===b.room_id && r.active!==false && r.active!=='false';});
      if (!room) throw new Error('Selected boarding room is unavailable.');
      const start = Date.parse(b.check_in), end = Date.parse(b.check_out);
      if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) throw new Error('Enter valid boarding check-in and check-out times.');
      b.room = room.name;
      b.created_at = b.created_at || new Date();
      return b;
    });
    for (let i=0;i<prepared.length;i++) {
      const b=prepared[i], start=Date.parse(b.check_in), end=Date.parse(b.check_out);
      const conflict = existing.some(function(x){return String(x.boarding_id)!==b.boarding_id && (String(x.room_id||'')===b.room_id || (!String(x.room_id||'') && String(x.room||'').trim().toLowerCase()===String(b.room||'').trim().toLowerCase())) && !['COMPLETED','CANCELLED','CANCELED','CHECKED_OUT','CHECKEDOUT'].includes(String(x.status||'').toUpperCase().replace(/[ _-]+/g,'_')) && Number.isFinite(Date.parse(x.check_in||'')) && Number.isFinite(Date.parse(x.check_out||'')) && start<Date.parse(x.check_out) && end>Date.parse(x.check_in);});
      if (conflict) throw new Error('Room '+b.room+' is already occupied during the selected dates. Choose another vacant room.');
      for (let j=0;j<i;j++) {
        const other=prepared[j];
        if (other.room_id===b.room_id && start<Date.parse(other.check_out) && end>Date.parse(other.check_in)) throw new Error('Room '+b.room+' was assigned to more than one pet for overlapping dates.');
      }
    }
    const saved=prepared.map(function(b){return upsertRow_(_authSession, 'Boarding',b,'boarding_id',true);});
    bumpVersion_('Boarding');
    return saved;
  } finally { lock.releaseLock(); }
}
function saveBoarding(_authSession, b) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);b=b||{};b.boarding_id=b.boarding_id||id_('BRD');b.status=b.status||'BOOKED';b.photo_url=validatePhotoUrlField_(b.photo_url,'Boarding photo');b.calendar_color=String(b.calendar_color||'');b.service_id=String(b.service_id||'').trim();b.room_id=String(b.room_id||'').trim();b.room=String(b.room||'').trim();b.check_in=String(b.check_in||'');b.check_out=String(b.check_out||'');
  if(!b.customer_id||!b.pet_id)throw new Error('Select a customer and pet for boarding.');if(!b.service_id)throw new Error('Select a boarding package.');const services=rows_('Services');const pack=services.find(s=>String(s.service_id)===b.service_id&&String(s.category||'').toLowerCase().includes('boarding')&&s.active!==false&&s.active!=='false');if(!pack)throw new Error('Selected boarding package is unavailable.');if(!b.room_id)throw new Error('Select a vacant boarding room.');const rooms=boardingRoomRows_();const room=rooms.find(r=>String(r.room_id)===b.room_id&&r.active!==false&&r.active!=='false');if(!room)throw new Error('Selected boarding room is unavailable.');const lock=LockService.getScriptLock();lock.waitLock(10000);try{if(boardingRoomConflict_(b.room_id,b.check_in,b.check_out,b.boarding_id))throw new Error('This room is already occupied during the selected dates. Choose another vacant room.');b.room=room.name;b.created_at=b.created_at||new Date();const saved=upsertRow_(_authSession, 'Boarding',b,'boarding_id');bumpVersion_();return saved;}finally{lock.releaseLock();}
}
// The server is the source of truth for prices, discounts, totals and stock.
// The browser only sends WHAT is being sold (item_type, item_id, qty), never the amounts.
function findRowsByValue_(sheetName, fieldName, value) {
  // Walk-in sales legitimately have no customer_id or pet_id. TextFinder rejects an empty search value.
  if (value === null || value === undefined || String(value).trim() === '') return [];
  const sh = getSS_().getSheetByName(sheetName);
  if (!sh || sh.getLastRow() < 2) return [];
  const headers = SCHEMA[sheetName] || sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0].map(String);
  const col = headers.indexOf(fieldName) + 1;
  if (col < 1) return [];
  const target = String(value == null ? '' : value);
  const matches = sh.getRange(2, col, sh.getLastRow() - 1, 1).createTextFinder(target).matchEntireCell(true).findAll() || [];
  return matches.map(cell => {
    const vals = sh.getRange(cell.getRow(), 1, 1, sh.getLastColumn()).getValues()[0], obj = {};
    headers.forEach((h, i) => obj[h] = normalize_(vals[i]));
    return obj;
  }).filter(o => Object.keys(o).some(k => o[k] !== ''));
}
function saleSnapshot_(saleId) {
  const id = String(saleId || '').trim();
  if (!id) return null;
  const sale = findRowsByValue_('Sales', 'sale_id', id)[0];
  if (!sale) return null;
  const revs = findRowsByValue_('SaleRevisions', 'sale_id', id).sort((a,b) => Number(a.revision_no||0) - Number(b.revision_no||0));
  if (revs.length) {
    try {
      const snap = JSON.parse(String(revs[revs.length - 1].snapshot_json || '{}'));
      snap.sale = snap.sale || {};
      snap.customer = snap.customer || {};
      snap.pet = snap.pet && typeof snap.pet === 'object' ? snap.pet : {};
      snap.pet.name = String(snap.pet.name == null ? '' : snap.pet.name).trim();
      snap.customer = snap.customer && typeof snap.customer === 'object' ? snap.customer : {};
      snap.items = Array.isArray(snap.items) ? snap.items.filter(function(item){ return item && typeof item === 'object'; }) : [];
      if (snap.sale.receipt_photo_urls === undefined || snap.sale.receipt_photo_urls === null || snap.sale.receipt_photo_urls === '') snap.sale.receipt_photo_urls = sale.receipt_photo_urls || '[]';
      if (!snap.sale.source_type) snap.sale.source_type = sale.source_type || '';
      if (!snap.sale.source_id) snap.sale.source_id = sale.source_id || '';
      snap.revised = true; snap.revision_id = revs[revs.length - 1].revision_id; snap.revision_no = Number(revs[revs.length - 1].revision_no || 0);
      return snap;
    } catch (e) {}
  }
  const customer = findRowsByValue_('Customers', 'customer_id', sale.customer_id)[0] || {};
  const petId = String(sale.pet_id || '').trim();
  const pet = petId ? (findRowsByValue_('Pets', 'pet_id', petId)[0] || {}) : {};
  const items = findRowsByValue_('SaleItems', 'sale_id', id).map(x => ({sale_item_id:x.sale_item_id,description:x.description,qty:Number(x.qty||0),unit_price:Number(x.unit_price||0),discount:Number(x.discount||0),line_total:Number(x.line_total||0),item_type:x.item_type,item_id:x.item_id}));
  return {sale:{sale_id:sale.sale_id,customer_id:sale.customer_id,pet_id:sale.pet_id,sale_at:sale.sale_at,subtotal:Number(sale.subtotal||0),discount:Number(sale.discount||0),total:Number(sale.total||0),payment_method:sale.payment_method,notes:sale.notes,membership_id:sale.membership_id,source_type:sale.source_type||'',source_id:sale.source_id||'',receipt_photo_urls:sale.receipt_photo_urls||'[]'},customer:{customer_id:customer.customer_id,name:customer.name,phone:customer.phone,email:customer.email},pet:{pet_id:pet.pet_id,name:pet.name},items:items,revised:false,revision_no:0};
}
function getSaleDetails(_authSession, saleId) {
  requireAuthorizedUser_(_authSession);
  const cache = CacheService.getScriptCache(), cacheKey = receiptCacheKey_('detail', saleId);
  try { const cached = cache.get(cacheKey); if (cached) return JSON.parse(cached); } catch (e) {}
  const snap = saleSnapshot_(saleId);
  if (!snap) return { sale:null };
  snap.sale = snap.sale || {}; snap.customer = snap.customer || {}; snap.pet = snap.pet || {}; snap.items = Array.isArray(snap.items) ? snap.items : [];
  let groomingWork = null;
  if(String(snap.sale.source_type||'').toUpperCase()==='GROOMING'&&snap.sale.source_id){const bookingId=String(snap.sale.source_id),booking=findRowsByValue_('Bookings','booking_id',bookingId)[0]||{};ensureGroomerWorkSheet_();groomingWork=findRowsByValue_('GroomerWork','booking_id',bookingId)[0]||{booking_id:bookingId,pet_id:booking.pet_id||snap.sale.pet_id||'',groomer_email:'',groomer_name:'',claimed_at:'',completed_at:''};}
  const result = Object.assign({}, snap, { groomingWork:groomingWork, audit:[], pet_label:receiptPetLabel_(snap.pet, snap.sale, snap.items) });
  try { const json = JSON.stringify(result); if (json.length < 95000) cache.put(cacheKey, json, 21600); } catch (e) {}
  return result;
}
function getSaleDetailsBatch(_authSession, saleIds) {
  requireAuthorizedUser_(_authSession);
  const ids = Array.isArray(saleIds) ? saleIds.map(x => String(x || '').trim()).filter(Boolean).slice(0, 50) : [];
  const details = [];
  ids.forEach(id => {
    try {
      const detail = getSaleDetails(_authSession, id);
      if (detail && detail.sale) details.push({sale_id:id, detail:detail});
      else details.push({sale_id:id, error:'Sale details are unavailable.'});
    } catch (e) {
      details.push({sale_id:id, error:String(e && e.message || e || 'Could not cache sale details.')});
    }
  });
  return {details:details};
}
function getSaleAudit(_authSession, saleId) {
  requireAuthorizedUser_(_authSession);
  const id=String(saleId||'').trim();
  if(!id) return {audit:[]};
  const cache=CacheService.getScriptCache(),key=receiptCacheKey_('audit',id);
  try { const cached=cache.get(key); if(cached) return JSON.parse(cached); } catch(e) {}
  const logs=findRowsByValue_('SaleAudit','sale_id',id).sort((a,b)=>String(a.changed_at).localeCompare(String(b.changed_at))).map(x=>({log_id:x.log_id,revision_id:x.revision_id,changed_at:x.changed_at,changed_by:x.changed_by,action:x.action,changes_json:x.changes_json}));
  const result={audit:logs};
  try { const json=JSON.stringify(result); if(json.length<95000) cache.put(key,json,21600); } catch(e) {}
  return result;
}
function editSaleReceipt(_authSession, saleId, edit) {
  const revisionLock=LockService.getScriptLock();revisionLock.waitLock(20000);try {
  const user = requireRole_(_authSession, ['OWNER','MANAGER']);
  const id = String(saleId || '').trim();
  if (!id) throw new Error('Sale ID is required.');
  edit = edit || {};
  const base = saleSnapshot_(id);
  if (!base) throw new Error('Sale not found.');
  const suppliedBaseRevision = Number(edit.base_revision_no);
  const currentRevision = Number(base.revision_no || 0);
  if (!Number.isInteger(suppliedBaseRevision) || suppliedBaseRevision < 0 || suppliedBaseRevision !== currentRevision) {
    const conflict = {status:'CONFLICT',sale_id:id,base_revision_no:Number.isInteger(suppliedBaseRevision)&&suppliedBaseRevision>=0?suppliedBaseRevision:-1,current_revision_no:currentRevision,current_snapshot:base,conflict_at:new Date().toISOString()};
    const err = new Error('Receipt changed on another device. Review the latest version before saving.');
    err.petshopConflict = conflict;
    throw err;
  }
  const current = JSON.parse(JSON.stringify(base));
  // Receipt photos belong to the sale and must survive every append-only revision.
  current.sale = current.sale || {};
  if (current.sale.receipt_photo_urls === undefined || current.sale.receipt_photo_urls === null || current.sale.receipt_photo_urls === '') {
    const originalSale = rows_('Sales').find(x => String(x.sale_id) === id) || {};
    current.sale.receipt_photo_urls = originalSale.receipt_photo_urls || '[]';
  }
  const allowedPayment = PAYMENT_METHODS_.indexOf(String(edit.payment_method || current.sale.payment_method)) >= 0 ? String(edit.payment_method || current.sale.payment_method) : current.sale.payment_method;
  if (edit.customer_id !== undefined) {
    const c = rows_('Customers').find(x=>String(x.customer_id)===String(edit.customer_id));
    if (!c) throw new Error('Customer not found.');
    current.sale.customer_id=c.customer_id; current.customer={customer_id:c.customer_id,name:c.name,phone:c.phone,email:c.email};
  }
  if (edit.pet_id !== undefined) {
    const pet = rows_('Pets').find(x=>String(x.pet_id)===String(edit.pet_id));
    if (!pet) throw new Error('Pet not found.');
    current.sale.pet_id=pet.pet_id; current.pet={pet_id:pet.pet_id,name:pet.name};
  }
  current.sale.payment_method=allowedPayment;
  current.sale.notes=String(edit.notes === undefined ? current.sale.notes || '' : edit.notes);
  let groomingWork=null;
  if(String(current.sale.source_type||'').toUpperCase()==='GROOMING'&&current.sale.source_id&&(edit.groomer_email!==undefined||edit.groomer_name!==undefined||edit.groomer_in!==undefined||edit.groomer_out!==undefined)){
    const manager=requireRole_(_authSession, ['OWNER','MANAGER']),bookingId=String(current.sale.source_id),booking=rows_('Bookings').find(b=>String(b.booking_id)===bookingId);if(!booking)throw new Error('Linked grooming booking not found.');
    const existing=groomerWorkRows_().find(w=>String(w.booking_id)===bookingId)||{};const email=String(edit.groomer_email===undefined?existing.groomer_email||'':edit.groomer_email).trim().toLowerCase();
    groomingWork={booking_id:bookingId,pet_id:booking.pet_id||'',groomer_email:email,groomer_name:String(edit.groomer_name===undefined?existing.groomer_name||email:edit.groomer_name).trim(),claimed_at:toIsoFromLocalInput_(edit.groomer_in===undefined?existing.claimed_at:edit.groomer_in),completed_at:toIsoFromLocalInput_(edit.groomer_out===undefined?existing.completed_at:edit.groomer_out),updated_at:new Date().toISOString(),updated_by:manager.email};
    if(groomingWork.completed_at&&groomingWork.claimed_at&&Date.parse(groomingWork.completed_at)<Date.parse(groomingWork.claimed_at))throw new Error('Out time cannot be earlier than in time.');
    upsertRow_(_authSession, 'GroomerWork',groomingWork,'booking_id');current.groomingWork=groomingWork;
  } else if(String(current.sale.source_type||'').toUpperCase()==='GROOMING'&&current.sale.source_id) {
    const bookingId=String(current.sale.source_id),booking=rows_('Bookings').find(b=>String(b.booking_id)===bookingId)||{};current.groomingWork=groomerWorkRows_().find(w=>String(w.booking_id)===bookingId)||{booking_id:bookingId,pet_id:booking.pet_id||current.sale.pet_id||'',groomer_email:'',groomer_name:'',claimed_at:'',completed_at:''};
  }
  const inItems=Array.isArray(edit.items)?edit.items:current.items;
  if (!inItems.length) throw new Error('At least one receipt item is required.');
  current.items=inItems.map((x,i)=>{
    const qty=Number(x.qty), unit=Number(x.unit_price), disc=Number(x.discount||0);
    if (!(qty>0) || !Number.isFinite(qty) || !Number.isFinite(unit) || unit<0 || !Number.isFinite(disc) || disc<0) throw new Error('Invalid receipt line '+(i+1)+'.');
    const gross=round2_(qty*unit), d=round2_(Math.min(gross,disc));
    return {sale_item_id:x.sale_item_id||'',item_type:String(x.item_type||''),item_id:String(x.item_id||''),description:String(x.description||''),qty:qty,unit_price:round2_(unit),discount:d,line_total:round2_(gross-d)};
  });
  current.sale.subtotal=round2_(current.items.reduce((a,x)=>a+x.qty*x.unit_price,0));
  current.sale.discount=round2_(current.items.reduce((a,x)=>a+x.discount,0));
  current.sale.total=round2_(current.sale.subtotal-current.sale.discount);
  const revs=rows_('SaleRevisions').filter(x=>String(x.sale_id)===id);
  const no=revs.reduce((m,x)=>Math.max(m,Number(x.revision_no||0)),0)+1;
  const revisionId=id_('REV');
  const now=new Date();
  const before={sale:base.sale,items:base.items};
  const changes=[];
  [['customer_id',before.sale.customer_id,current.sale.customer_id],['pet_id',before.sale.pet_id,current.sale.pet_id],['payment_method',before.sale.payment_method,current.sale.payment_method],['notes',before.sale.notes||'',current.sale.notes||''],['subtotal',before.sale.subtotal,current.sale.subtotal],['discount',before.sale.discount,current.sale.discount],['total',before.sale.total,current.sale.total]].forEach(x=>{if(String(x[1])!==String(x[2]))changes.push({field:x[0],from:x[1],to:x[2]});});
  if (JSON.stringify(before.items)!==JSON.stringify(current.items)) changes.push({field:'items',from:before.items,to:current.items});
  if(groomingWork)changes.push({field:'grooming_assignment',from:null,to:groomingWork});
  const snapshot=JSON.stringify(current);
  append_('SaleRevisions',{revision_id:revisionId,sale_id:id,revision_no:no,revised_at:now,revised_by:user.email,change_summary:changes.map(x=>x.field).join(', '),snapshot_json:snapshot},true);
  append_('SaleAudit',{log_id:id_('AUD'),sale_id:id,revision_id:revisionId,changed_at:now,changed_by:user.email,action:'EDIT_RECEIPT',changes_json:JSON.stringify(changes)},true);
  bumpVersion_(['Sales','SaleRevisions','SaleAudit']);
  try { enqueueReceiptGeneration_(id); } catch (receiptQueueError) { console.error('Could not queue updated receipt generation for ' + id, receiptQueueError); }
  return Object.assign({},current,{revised:true,revision_id:revisionId,revision_no:no,audit:rows_('SaleAudit').filter(x=>String(x.sale_id)===id)});
  } finally { revisionLock.releaseLock(); }
}
function ensureGroomerWorkSheet_() {
  const ss=getSS_(true);let sh=ss.getSheetByName('GroomerWork');if(!sh)sh=ss.insertSheet('GroomerWork');ensureSchema_(sh,SCHEMA.GroomerWork);return sh;
}
function groomerWorkRows_(){ensureGroomerWorkSheet_();return rows_('GroomerWork');}
function claimGroomingPet(_authSession, bookingId){
  const user=requireRole_(_authSession, ['OWNER','MANAGER','STAFF']),id=String(bookingId||'').trim();if(!id)throw new Error('Booking ID is required.');
  const booking=rows_('Bookings').find(b=>String(b.booking_id)===id);if(!booking)throw new Error('Grooming booking not found.');if(String(booking.status||'').toUpperCase()==='CANCELLED')throw new Error('Cancelled bookings cannot be claimed.');
  const lock=LockService.getScriptLock();lock.waitLock(10000);try{const rows=groomerWorkRows_(),old=rows.find(w=>String(w.booking_id)===id)||{};if(old.completed_at)throw new Error('This grooming job is already completed.');if(old.groomer_email&&String(old.groomer_email).toLowerCase()!==user.email.toLowerCase())throw new Error('This pet has already been claimed by '+String(old.groomer_name||old.groomer_email)+'.');const now=new Date().toISOString();const rec={booking_id:id,pet_id:booking.pet_id||'',groomer_email:user.email,groomer_name:user.name||user.email,claimed_at:old.claimed_at||now,completed_at:'',updated_at:now,updated_by:user.email,before_photo_url:String(old.before_photo_url||''),after_photo_url:String(old.after_photo_url||'')};upsertRow_(_authSession, 'GroomerWork',rec,'booking_id');return rec;}finally{lock.releaseLock();}
}

function claimAndCompleteGroomingPet(_authSession, bookingId){
  const user=requireRole_(_authSession, ['OWNER','MANAGER','STAFF']),id=String(bookingId||'').trim();
  if(!id)throw new Error('Booking ID is required.');
  const booking=rows_('Bookings').find(b=>String(b.booking_id)===id);
  if(!booking)throw new Error('Grooming booking not found.');
  if(String(booking.status||'').toUpperCase()==='CANCELLED')throw new Error('Cancelled bookings cannot be completed.');
  const lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    const old=groomerWorkRows_().find(w=>String(w.booking_id)===id)||{};
    if(old.completed_at)throw new Error('This grooming job is already completed.');
    if(old.groomer_email&&String(old.groomer_email).toLowerCase()!==user.email.toLowerCase()&&!['OWNER','MANAGER'].includes(user.role))throw new Error('This pet has already been claimed by '+String(old.groomer_name||old.groomer_email)+'.');
    const now=new Date().toISOString();
    const rec={booking_id:id,pet_id:booking.pet_id||old.pet_id||'',groomer_email:old.groomer_email||user.email,groomer_name:old.groomer_name||user.name||user.email,claimed_at:old.claimed_at||now,completed_at:now,updated_at:now,updated_by:user.email,before_photo_url:String(old.before_photo_url||''),after_photo_url:String(old.after_photo_url||'')};
    upsertRow_(_authSession, 'GroomerWork',rec,'booking_id');bumpVersion_();return rec;
  }finally{lock.releaseLock();}
}

function getGroomerAssignees(_authSession){
  requireRole_(_authSession, ['OWNER','MANAGER']);
  return staffDirectory_(_authSession).filter(s=>s.active!==false).map(s=>({email:s.email,name:s.name||s.email,role:s.role,active:s.active!==false}));
}
function assignGroomingPet(_authSession, bookingId, groomerEmail){
  const user=requireRole_(_authSession, ['OWNER','MANAGER']);
  const id=String(bookingId||'').trim(),email=String(groomerEmail||'').trim().toLowerCase();
  if(!id)throw new Error('Booking ID is required.');
  const booking=rows_('Bookings').find(b=>String(b.booking_id)===id);
  if(!booking)throw new Error('Grooming booking not found.');
  if(String(booking.status||'').toUpperCase()==='CANCELLED')throw new Error('Cancelled bookings cannot be assigned.');
  const lock=LockService.getScriptLock();lock.waitLock(10000);
  try{
    const rows=groomerWorkRows_(),old=rows.find(w=>String(w.booking_id)===id)||{};
    // Completed jobs can be reopened by assigning them to an active groomer from the searchable history.
    if(old.completed_at&&!email)throw new Error('Choose a groomer to reopen and reassign this completed job.');
    let staff=null;
    if(email){staff=staffDirectory_(_authSession).find(s=>String(s.email||'').toLowerCase()===email&&s.active!==false);if(!staff)throw new Error('Select an active staff member.');}
    if(!email&&old.claimed_at)throw new Error('A grooming job that has started cannot be unassigned.');
    const now=new Date().toISOString();
    const wasCompleted=!!old.completed_at;
    const rec={booking_id:id,pet_id:booking.pet_id||old.pet_id||'',groomer_email:email,groomer_name:staff?String(staff.name||staff.email):'',claimed_at:wasCompleted?'':(old.claimed_at||''),completed_at:'',updated_at:now,updated_by:user.email,before_photo_url:String(old.before_photo_url||''),after_photo_url:String(old.after_photo_url||'')};
    upsertRow_(_authSession, 'GroomerWork',rec,'booking_id');bumpVersion_();return rec;
  }finally{lock.releaseLock();}
}

function saveGroomingWorkPhotos(_authSession, bookingId, beforePhotoUrl, afterPhotoUrl){
  const user=requireRole_(_authSession, ['OWNER','MANAGER','STAFF']),id=String(bookingId||'').trim();
  if(!id)throw new Error('Booking ID is required.');
  const booking=rows_('Bookings').find(b=>String(b.booking_id)===id);if(!booking)throw new Error('Grooming booking not found.');
  const lock=LockService.getScriptLock();lock.waitLock(10000);try{
    const old=groomerWorkRows_().find(w=>String(w.booking_id)===id)||{};
    if(old.groomer_email&&String(old.groomer_email).toLowerCase()!==user.email.toLowerCase()&&!['OWNER','MANAGER'].includes(user.role))throw new Error('Only the assigned groomer or a manager/owner can update these photos.');
    const rec={...old,booking_id:id,pet_id:booking.pet_id||old.pet_id||'',before_photo_url:String(beforePhotoUrl||old.before_photo_url||''),after_photo_url:String(afterPhotoUrl||old.after_photo_url||''),updated_at:new Date().toISOString(),updated_by:user.email};
    upsertRow_(_authSession, 'GroomerWork',rec,'booking_id');bumpVersion_();return rec;
  }finally{lock.releaseLock();}
}

function completeGroomingPet(_authSession, bookingId){
  const user=requireRole_(_authSession, ['OWNER','MANAGER','STAFF']),id=String(bookingId||'').trim();if(!id)throw new Error('Booking ID is required.');const lock=LockService.getScriptLock();lock.waitLock(10000);try{const rec=groomerWorkRows_().find(w=>String(w.booking_id)===id);if(!rec||!rec.groomer_email)throw new Error('Claim this pet before marking it done.');if(rec.completed_at)throw new Error('This grooming job is already completed.');if(!['OWNER','MANAGER'].includes(user.role)&&String(rec.groomer_email).toLowerCase()!==user.email.toLowerCase())throw new Error('Only the assigned groomer or a manager/owner can complete this job.');rec.completed_at=new Date().toISOString();rec.updated_at=rec.completed_at;rec.updated_by=user.email;rec.before_photo_url=String(rec.before_photo_url||'');rec.after_photo_url=String(rec.after_photo_url||'');upsertRow_(_authSession, 'GroomerWork',rec,'booking_id');bumpVersion_();return rec;}finally{lock.releaseLock();}
}
function toIsoFromLocalInput_(value){const s=String(value||'').trim();if(!s)return '';const d=new Date(s);if(!Number.isFinite(d.getTime()))throw new Error('Invalid grooming in/out time.');return d.toISOString();}

function makeSale(_authSession, sale, items, payment) {
  const user = requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  sale = sale || {};
  items = Array.isArray(items) ? items : [];
  payment = payment || {};
  if (!items.length) throw new Error('Cart is empty.');
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  let receiptToQueue = '';
  let saleResult = null;
  try {
    const ss = getSS_();
    const salesSheet = ss.getSheetByName('Sales');
    if (!salesSheet) throw new Error('Missing sheet: Sales');
    ensureSchema_(salesSheet, SCHEMA.Sales);
    REQUEST_ROWS_CACHE_ = Object.create(null);
    const requestedSaleId = String(sale.sale_id || '').trim() || id_('SAL');
    const idempotencyKey = String(sale.idempotency_key || requestedSaleId).trim();
    if (!/^SAL-[A-Z0-9]{8}$/.test(requestedSaleId)) throw new Error('Invalid sale ID.');
    if (!idempotencyKey || idempotencyKey.length > 128) throw new Error('Invalid sale idempotency key.');
    const existingSale = rows_('Sales').find(x => String(x.sale_id || '') === requestedSaleId || String(x.idempotency_key || '') === idempotencyKey);
    if (existingSale) {
      if (String(existingSale.sale_id || '') !== requestedSaleId || String(existingSale.idempotency_key || '') !== idempotencyKey || String(existingSale.created_by || '').toLowerCase() !== String(user.email || '').toLowerCase()) {
        throw new Error('Sale ID or idempotency key already exists. Please start a new checkout.');
      }
      if (String(existingSale.sale_status || '').toUpperCase() !== 'COMPLETED') {
        throw new Error('A previous attempt for this sale did not finish. Do not retry as a new sale; inspect this sale in testing before continuing.');
      }
      let priorPhotos = [];
      try { const parsed = JSON.parse(String(existingSale.receipt_photo_urls || '[]')); if (Array.isArray(parsed)) priorPhotos = parsed; } catch (e) {}
      const priorLines = rows_('SaleItems').filter(x => String(x.sale_id || '') === requestedSaleId).map(x => ({ item_type:x.item_type, item_id:x.item_id, description:x.description, qty:Number(x.qty||0), unit_price:Number(x.unit_price||0), discount:Number(x.discount||0), line_total:Number(x.line_total||0) }));
      return { sale_id:requestedSaleId, sale_at:existingSale.sale_at, subtotal:Number(existingSale.subtotal||0), discount:Number(existingSale.discount||0), total:Number(existingSale.total||0), payment_method:String(existingSale.payment_method||''), points_earned:0, lines:priorLines, receipt_photo_urls:priorPhotos, idempotent_replay:true, skip_receipt_enqueue:true };
    }
    const now = new Date();
    const today = Utilities.formatDate(now, Session.getScriptTimeZone(), 'yyyy-MM-dd');
    const customerId = String(sale.customer_id || '');
    // Optional booking/boarding source: validate before allowing the sale to complete.
    const sourceType = String(sale.source_type || '').toUpperCase();
    const sourceId = String(sale.source_id || '');
    let sourceIds = [];
    try { sourceIds = Array.isArray(sale.source_ids) ? sale.source_ids.map(x=>String(x||'').trim()).filter(Boolean) : JSON.parse(String(sale.source_ids||'[]')); } catch(e) { sourceIds=[]; }
    if (!Array.isArray(sourceIds)) sourceIds=[];
    sourceIds = Array.from(new Set([...(sourceId?[sourceId]:[]),...sourceIds]));
    if (sourceType && sourceIds.length) {
      if (!['BOARDING','GROOMING'].includes(sourceType)) throw new Error('Invalid checkout source.');
      const sourceSheet = sourceType === 'BOARDING' ? 'Boarding' : 'Bookings';
      const sourceField = sourceType === 'BOARDING' ? 'boarding_id' : 'booking_id';
      const allSources = rows_(sourceSheet);
      const existingSales = rows_('Sales');
      sourceIds.forEach(sid => {
        const src=allSources.find(x=>String(x[sourceField])===sid);
        if(!src)throw new Error((sourceType==='BOARDING'?'Boarding':'Grooming booking')+' record not found: '+sid);
        const normalizedStatus=String(src.status||'').toUpperCase().replace(/[ _-]+/g,'_');if(['COMPLETED','CHECKED_OUT','CHECKEDOUT'].includes(normalizedStatus))throw new Error('This booking has already been checked out: '+sid);if(String(src.customer_id||'')!==customerId)throw new Error('All bookings in a grouped checkout must belong to the same customer.');
        const alreadySold=existingSales.some(x=>String(x.source_id||'')===sid || (()=>{try{return JSON.parse(String(x.source_ids||'[]')).map(String).includes(sid)}catch(e){return false}})());
        if(alreadySold)throw new Error('This booking has already been checked out: '+sid);
      });
    }
    const requestedGroomerEmail = String(sale.groomer_email || '').trim().toLowerCase();
    let requestedGroomer = null;
    if (requestedGroomerEmail) {
      if (sourceType !== 'GROOMING') throw new Error('Groomer assignment is only available for grooming checkout.');
      if (!['OWNER','MANAGER'].includes(user.role)) throw new Error('Only an owner or manager can assign a groomer at checkout.');
      requestedGroomer = staffDirectory_(_authSession).find(s => String(s.email || '').toLowerCase() === requestedGroomerEmail && s.active !== false) || null;
      if (!requestedGroomer) throw new Error('Select an active groomer.');
    }
    const svcById = {}, prodById = {};
    rows_('Services').forEach(s => { svcById[String(s.service_id)] = s; });
    rows_('Products').forEach(p => { prodById[String(p.product_id)] = p; });
    // Use the membership selected at checkout. If none is selected, do not apply membership discounts.
    let membership = null, plan = null;
    const requestedMembershipId = String(sale.membership_id || '').trim();
    if (requestedMembershipId) {
      membership = rows_('Memberships').find(m =>
        String(m.membership_id) === requestedMembershipId &&
        String(m.customer_id) === customerId &&
        String(m.status) === 'ACTIVE' &&
        (!m.start_date || String(m.start_date).slice(0, 10) <= today) &&
        (!m.expiry_date || String(m.expiry_date).slice(0, 10) >= today)) || null;
      if (!membership) throw new Error('Selected membership is not active or does not belong to this customer.');
      plan = rows_('MembershipPlans').find(p => String(p.plan_id) === String(membership.plan_id) && p.active !== false) || null;
      if (!plan) throw new Error('Membership plan not found or inactive.');
    }
    // Price every line and validate stock BEFORE writing anything.
    const lines = [], need = {};
    let subtotal = 0, discount = 0;
    items.forEach(it => {
      const qty = Number(it.qty);
      if (!(qty > 0) || Math.floor(qty) !== qty) throw new Error('Invalid quantity.');
      let rec, pct = 0;
      if (it.item_type === 'PRODUCT') {
        rec = prodById[String(it.item_id)];
        if (!rec || rec.active === false) throw new Error('Product not available: ' + (it.description || it.item_id));
        need[String(rec.product_id)] = (need[String(rec.product_id)] || 0) + qty;
        if (plan) pct = Number(plan.retail_discount_pct || 0);
      } else if (it.item_type === 'SERVICE') {
        rec = svcById[String(it.item_id)];
        if (!rec && !String(it.item_id || '')) rec = { name: String(it.description || 'Service'), price: Number(it.unit_price || 0), category: 'Other' };
        if (!rec || rec.active === false) throw new Error('Service not available: ' + (it.description || it.item_id));
        if (plan && String(it.item_id || '')) pct = String(rec.category) === 'Boarding' ? Number(plan.boarding_discount_pct || 0) : Number(plan.grooming_discount_pct || 0);
      } else {
        throw new Error('Invalid item type.');
      }
      const requestedUnit = Number(it.unit_price);
      const catalogUnit = round2_(Number(rec.price || 0));
      if (user.role === 'STAFF' && !STAFF_PRICE_OVERRIDE_ALLOWED_ && (!String(it.item_id || '') || (Number.isFinite(requestedUnit) && round2_(requestedUnit) !== catalogUnit))) {
        throw new Error('Staff cannot override catalog prices.');
      }
      const unit = user.role === 'STAFF' && !STAFF_PRICE_OVERRIDE_ALLOWED_ ? catalogUnit : (Number.isFinite(requestedUnit) && requestedUnit >= 0 ? round2_(requestedUnit) : catalogUnit);
      const gross = round2_(unit * qty);
      const requestedDiscount = Number(it.discount);
      const disc = user.role === 'STAFF' ? round2_(gross * pct / 100) : (Number.isFinite(requestedDiscount) && requestedDiscount >= 0 ? round2_(Math.min(gross, requestedDiscount)) : round2_(gross * pct / 100));
      lines.push({ item_type: it.item_type, item_id: String(it.item_id), description: String(it.description || rec.name), qty: qty, unit_price: unit, discount: disc, line_total: round2_(gross - disc) });
      subtotal += gross;
      discount += disc;
    });
    Object.keys(need).forEach(pid => {
      const have = Number(prodById[pid].stock || 0);
      if (have < need[pid]) throw new Error('Insufficient stock for ' + prodById[pid].name + ' (available ' + have + ', requested ' + need[pid] + ').');
    });
    subtotal = round2_(subtotal);
    // Preserve line-item discounts, then apply any additional sale-level discount
    // supplied by checkout without assigning it to individual SaleItems rows.
    const lineDiscountTotal = round2_(discount);
    const requestedSaleDiscount = Number(sale.discount);
    const totalDiscount = Number.isFinite(requestedSaleDiscount) && requestedSaleDiscount >= 0
      ? round2_(Math.min(subtotal, requestedSaleDiscount))
      : lineDiscountTotal;
    const extraDiscount = round2_(Math.max(0, totalDiscount - lineDiscountTotal));
    discount = round2_(Math.min(subtotal, lineDiscountTotal + extraDiscount));
    const total = round2_(subtotal - discount);
    const method = PAYMENT_METHODS_.indexOf(payment.method || sale.payment_method) >= 0 ? (payment.method || sale.payment_method) : 'Cash';
    const saleId = requestedSaleId;
    let receiptPhotoUrls = [];
    try {
      const rawPhotos = sale.receipt_photo_urls;
      if (Array.isArray(rawPhotos)) receiptPhotoUrls = rawPhotos.map(String).filter(Boolean);
      else if (String(rawPhotos || '').trim()) {
        const parsed = JSON.parse(String(rawPhotos));
        if (Array.isArray(parsed)) receiptPhotoUrls = parsed.map(String).filter(Boolean);
      }
    } catch (e) {}
    // Carry photos from every booking in a grouped customer checkout.
    if (sourceType && sourceIds.length) {
      const sourceSheet = sourceType === 'BOARDING' ? 'Boarding' : sourceType === 'GROOMING' ? 'Bookings' : '';
      const sourceField = sourceType === 'BOARDING' ? 'boarding_id' : 'booking_id';
      if (sourceSheet) {
        const sourceRows = rows_(sourceSheet);
        sourceIds.forEach(sid=>{
          const source = sourceRows.find(x => String(x[sourceField]) === sid) || {};
          try { const parsed=JSON.parse(String(source.photo_url||'[]')); if(Array.isArray(parsed))parsed.map(String).filter(Boolean).forEach(u=>{if(!receiptPhotoUrls.includes(u))receiptPhotoUrls.push(u);}); }
          catch(e){if(String(source.photo_url||'').trim()&&!receiptPhotoUrls.includes(String(source.photo_url).trim()))receiptPhotoUrls.push(String(source.photo_url).trim());}
        });
      }
    }
    append_('Sales', {
      sale_id: saleId, customer_id: customerId, pet_id: String(sale.pet_id || ''), sale_at: now,
      subtotal: subtotal, discount: discount, total: total, payment_method: method,
      membership_id: membership ? membership.membership_id : '', notes: String(sale.notes || ''), created_by: user.email,
      receipt_photo_urls: JSON.stringify(receiptPhotoUrls), source_type: sourceType, source_id: sourceId, source_ids: JSON.stringify(sourceIds),
      idempotency_key: idempotencyKey, sale_status: 'PROCESSING'
    }, true);
    // Make the PROCESSING row visible to a retry even if execution stops before final version bump.
    REQUEST_ROWS_CACHE_ = Object.create(null);
    try {
      const salesVersion = PropertiesService.getScriptProperties().getProperty('DATA_VERSION_COL_Sales') || '0';
      CacheService.getScriptCache().remove('petshop_rows_v1_Sales_' + salesVersion);
    } catch (cacheError) {}
    appendMany_('SaleItems', lines.map(l => Object.assign({ sale_item_id: id_('ITM'), sale_id: saleId }, l)), true);
    if (total > 0) {
      append_('Payments', {
        payment_id: id_('PAY'), sale_id: saleId, paid_at: now, amount: total, method: method,
        reference: String(payment.reference || ''), notes: String(payment.notes || '')
      }, true);
    }
    // Reduce stock (only the stock cells) and log an Inventory movement per product.
    if (Object.keys(need).length) {
      const psh = ss.getSheetByName('Products');
      const data = psh.getDataRange().getValues();
      const idx = Object.fromEntries(data[0].map((h, i) => [h, i]));
      for (let r = 1; r < data.length; r++) {
        const pid = String(data[r][idx.product_id]);
        if (!need[pid]) continue;
        const after = Number(data[r][idx.stock] || 0) - need[pid];
        psh.getRange(r + 1, idx.stock + 1).setValue(after);
        append_('Inventory', {
          movement_id: id_('INV'), product_id: pid, type: 'SALE', qty: -need[pid],
          unit_cost: Number(data[r][idx.avg_cost] || data[r][idx.cost] || 0), stock_after: after,
          reference: saleId, created_at: now, created_by: user.email
        }, true);
      }
    }
    // Membership points
    let pointsEarned = 0;
    if (membership && plan) {
      pointsEarned = Math.floor(total * POINTS_PER_RM_ * Number(plan.points_multiplier || 1));
      if (pointsEarned > 0) {
        const msh = ss.getSheetByName('Memberships');
        const mv = msh.getDataRange().getValues();
        const mi = Object.fromEntries(mv[0].map((h, i) => [h, i]));
        for (let r = 1; r < mv.length; r++) {
          if (String(mv[r][mi.membership_id]) === String(membership.membership_id)) {
            msh.getRange(r + 1, mi.points_balance + 1).setValue(Number(mv[r][mi.points_balance] || 0) + pointsEarned);
            break;
          }
        }
      }
    }
    if (sourceType && sourceIds.length) {
      const sourceSheet = sourceType === 'BOARDING' ? 'Boarding' : 'Bookings';
      const sourceField = sourceType === 'BOARDING' ? 'boarding_id' : 'booking_id';
      const sourceRows = rows_(sourceSheet);
      sourceIds.forEach(sid=>{const src=sourceRows.find(x=>String(x[sourceField])===sid);if(src){src.status='COMPLETED';upsertRow_(_authSession, sourceSheet,src,sourceField,true);}});
    }
    let groomerWorkUpdated = false;
    if (sourceType === 'GROOMING' && sourceIds.length) {
      const allWork=groomerWorkRows_();
      sourceIds.forEach(sid=>{const oldWork=allWork.find(w=>String(w.booking_id)===sid)||{};const chosenEmail=requestedGroomerEmail||String(oldWork.groomer_email||'').trim().toLowerCase();const chosenStaff=requestedGroomer||(chosenEmail?staffDirectory_(_authSession).find(s=>String(s.email||'').toLowerCase()===chosenEmail):null);if(chosenEmail){const completedAt=now.toISOString();const booking=rows_('Bookings').find(b=>String(b.booking_id)===sid)||{};const work={...oldWork,booking_id:sid,pet_id:String(booking.pet_id||oldWork.pet_id||''),groomer_email:chosenEmail,groomer_name:String(chosenStaff&&chosenStaff.name||oldWork.groomer_name||chosenEmail),claimed_at:oldWork.claimed_at||completedAt,completed_at:completedAt,updated_at:completedAt,updated_by:user.email,before_photo_url:String(oldWork.before_photo_url||''),after_photo_url:String(oldWork.after_photo_url||'')};upsertRow_(_authSession, 'GroomerWork',work,'booking_id',true);groomerWorkUpdated=true;}});
    }
    const changedCollections=['Sales','SaleItems'];
    if(total>0) changedCollections.push('Payments');
    if(Object.keys(need).length){changedCollections.push('Products','Inventory');}
    if(membership&&pointsEarned>0) changedCollections.push('Memberships');
    if(sourceType==='BOARDING') changedCollections.push('Boarding');
    else if(sourceType==='GROOMING') changedCollections.push('Bookings');
    if(groomerWorkUpdated) changedCollections.push('GroomerWork');
    // The durable completion marker makes repeated requests safe. If execution fails
    // before this point, the sale remains PROCESSING and is blocked from double-writing.
    upsertRow_(_authSession, 'Sales', {sale_id:saleId, sale_status:'COMPLETED', idempotency_key:idempotencyKey}, 'sale_id', true);
    bumpVersion_(changedCollections);
    receiptToQueue = saleId;
    saleResult = { sale_id: saleId, sale_at: now, subtotal: subtotal, discount: discount, total: total, payment_method: method, points_earned: pointsEarned, lines: lines, receipt_photo_urls: receiptPhotoUrls };
  } finally {
    lock.releaseLock();
  }
  if (receiptToQueue && !(saleResult && saleResult.idempotent_replay)) {
    try { enqueueReceiptGeneration_(receiptToQueue); } catch (receiptQueueError) { console.error('Could not queue receipt generation for ' + receiptToQueue, receiptQueueError); }
  }
  return saleResult;
}
function search(_authSession, q) {
  q = String(q || '').trim().toLowerCase();
  if (!q) return getData(_authSession);
  const d = getData(_authSession);
  return {
    customers: d.customers.filter(x => `${x.name} ${x.phone} ${x.email}`.toLowerCase().includes(q)),
    pets: d.pets.filter(x => `${x.name} ${x.breed} ${x.pet_id}`.toLowerCase().includes(q)),
    services: d.services.filter(x => String(x.name).toLowerCase().includes(q)),
    products: d.products.filter(x => `${x.name} ${x.sku}`.toLowerCase().includes(q))
  };
}
function upsertRow_(_authSession, sheetName, obj, idField, noBump) {
  requireAuthorizedUser_(_authSession);
  const sh = getSS_().getSheetByName(sheetName);
  const headers = SCHEMA[sheetName];
  if (!sh) throw new Error('Missing sheet: ' + sheetName);
  if (headers) ensureSchema_(sh, headers);
  const id = String(obj[idField] || '');
  if (id) {
    const actualHeaders = sh.getRange(1,1,1,sh.getLastColumn()).getValues()[0].map(String);
    const idCol = actualHeaders.indexOf(idField);
    if (idCol >= 0 && sh.getLastRow() >= 2) {
      const match = sh.getRange(2,idCol+1,sh.getLastRow()-1,1).createTextFinder(id).matchEntireCell(true).findNext();
      if (match) {
        const r=match.getRow(), oldValues=sh.getRange(r,1,1,sh.getLastColumn()).getValues()[0];
        const row = headers.map(h => {
          const col = actualHeaders.indexOf(h);
          return obj[h] === undefined ? (col >= 0 ? oldValues[col] : '') : obj[h];
        });
        sh.getRange(r, 1, 1, headers.length).setValues([formulaSafeSheetRow_(row)]);
        if (!noBump) bumpVersion_(sheetName);
        return plain_(Object.fromEntries(headers.map((h,i) => [h,row[i]])));
      }
    }
  }
  const row = headers.map(h => obj[h] === undefined ? '' : obj[h]);
  sh.getRange(sh.getLastRow() + 1, 1, 1, headers.length).setValues([formulaSafeSheetRow_(row)]);
  if (!noBump) bumpVersion_(sheetName);
  return plain_(Object.fromEntries(headers.map((h,i) => [h,row[i]])));
}
function getProductCategories_(){
  const row=rows_('Settings').find(x=>x.key==='PRODUCT_CATEGORIES');
  if(!row||!row.value)return ['Food','Treats','Toys','Grooming','Healthcare','Accessories','Other'];
  try{const a=JSON.parse(String(row.value));return Array.isArray(a)?a.filter(Boolean):[];}catch(e){return ['Food','Treats','Toys','Grooming','Healthcare','Accessories','Other'];}
}
function saveProductCategory(_authSession, name){requireRole_(_authSession, ['OWNER','MANAGER']);name=String(name||'').trim();if(!name)throw new Error('Category name required.');const a=getProductCategories_();if(!a.some(x=>x.toLowerCase()===name.toLowerCase()))a.push(name);upsertRow_(_authSession, 'Settings',{key:'PRODUCT_CATEGORIES',value:JSON.stringify(a)},'key');bumpVersion_();return a;}
function deleteProductCategory(_authSession, name){requireRole_(_authSession, ['OWNER','MANAGER']);name=String(name||'').trim();const used=rows_('Products').some(p=>String(p.category||'').toLowerCase()===name.toLowerCase());if(used)throw new Error('Category is used by a product.');const a=getProductCategories_().filter(x=>x.toLowerCase()!==name.toLowerCase());upsertRow_(_authSession, 'Settings',{key:'PRODUCT_CATEGORIES',value:JSON.stringify(a)},'key');bumpVersion_();return a;}
function receiveInventory(_authSession, productId, qty, unitCost, reference){requireRole_(_authSession, ['OWNER','MANAGER']);qty=Number(qty||0);unitCost=Number(unitCost||0);if(qty<=0||unitCost<0)throw new Error('Enter a valid quantity and cost.');const sh=getSS_().getSheetByName('Products');const data=sh.getDataRange().getValues(),h=data[0],idx=Object.fromEntries(h.map((x,i)=>[x,i]));let row=-1;for(let r=1;r<data.length;r++)if(String(data[r][idx.product_id])===String(productId)){row=r;break;}if(row<0)throw new Error('Product not found.');const oldStock=Number(data[row][idx.stock]||0),oldAvg=Number(data[row][idx.avg_cost]||data[row][idx.cost]||0),newStock=oldStock+qty,newAvg=newStock?((oldStock*oldAvg)+(qty*unitCost))/newStock:unitCost;data[row][idx.stock]=newStock;data[row][idx.cost]=unitCost;data[row][idx.avg_cost]=newAvg;sh.getRange(row+1,1,1,h.length).setValues([data[row]]);append_('Inventory',{movement_id:id_('INV'),product_id:productId,type:'RECEIVE',qty:qty,unit_cost:unitCost,stock_after:newStock,reference:reference||'',created_at:new Date(),created_by:requireUserEmail_(_authSession)});bumpVersion_();return {stock:newStock,avg_cost:newAvg};}
const GROOMER_COMMISSION_KEY_ = 'GROOMER_COMMISSION_RATES_JSON';
const STAFF_COMMISSION_KEY_ = 'GROOMER_STAFF_COMMISSION_RATES_JSON';
function getStaffCommissionRates_() {
  const raw = PropertiesService.getScriptProperties().getProperty(STAFF_COMMISSION_KEY_);
  if (!raw) return {};
  try { return JSON.parse(raw) || {}; } catch (e) { throw new Error('Staff commission settings are corrupted.'); }
}
function saveStaffCommissionRates(_authSession, email, data) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  email = String(email || '').trim().toLowerCase();
  if (!email || !staffDirectory_(_authSession).some(x => String(x.email).toLowerCase() === email)) throw new Error('Staff member not found.');
  data = data || {};
  const allowed = rows_('Services').filter(s => String(s.category || '').toLowerCase() === 'grooming');
  const all = getStaffCommissionRates_();
  const rates = {};
  allowed.forEach(s => {
    const key = String(s.service_id), raw = data[key];
    if (raw === '' || raw === null || raw === undefined) return;
    if (raw && typeof raw === 'object') {
      const type = String(raw.type || 'percent').toLowerCase();
      const n = Number(raw.value);
      if (!['percent','fixed'].includes(type) || !Number.isFinite(n) || n < 0 || (type === 'percent' && n > 100)) throw new Error(type === 'fixed' ? 'Fixed commission must be zero or more.' : 'Commission rate must be between 0 and 100%.');
      rates[key] = {type:type, value:Math.round(n * 100) / 100};
    } else {
      const n = Number(raw);
      if (!Number.isFinite(n) || n < 0 || n > 100) throw new Error('Commission rate must be between 0 and 100%.');
      rates[key] = Math.round(n * 100) / 100;
    }
  });
  all[email] = rates;
  PropertiesService.getScriptProperties().setProperty(STAFF_COMMISSION_KEY_, JSON.stringify(all));
  bumpVersion_();
  return rates;
}
function getGroomerCommissionRates_() {
  const raw = PropertiesService.getScriptProperties().getProperty(GROOMER_COMMISSION_KEY_);
  if (!raw) return {};
  try { return JSON.parse(raw) || {}; } catch (e) { throw new Error('Groomer commission settings are corrupted.'); }
}
function getGroomerCommissionData(_authSession, month) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  month = String(month || Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyy-MM')).slice(0, 7);
  if (!/^\d{4}-\d{2}$/.test(month)) throw new Error('Select a valid month.');
  const rates = getGroomerCommissionRates_();
  const staffRates = getStaffCommissionRates_();
  const services = rows_('Services').filter(s => String(s.category || '').toLowerCase() === 'grooming');
  const bookings = rows_('Bookings');
  const sales = rows_('Sales').filter(s => String(s.source_type || '').toUpperCase() === 'GROOMING' && String(s.sale_at || '').slice(0, 7) === month);
  const items = rows_('SaleItems');
  const saleById = Object.fromEntries(sales.map(s => [String(s.sale_id), s]));
  const bookingById = Object.fromEntries(bookings.map(b => [String(b.booking_id), b]));
  const staff = staffDirectory_(_authSession);
  const staffNameByEmail = Object.fromEntries(staff.map(x => [String(x.email || '').toLowerCase(), String(x.name || x.email || '')]));
  const details = [];
  items.forEach(it => {
    const sale = saleById[String(it.sale_id)];
    if (!sale || String(it.item_type).toUpperCase() !== 'SERVICE') return;
    const booking = bookingById[String(sale.source_id || '')];
    if (!booking || String(booking.status || '').toUpperCase() !== 'COMPLETED') return;
    const service = services.find(x => String(x.service_id) === String(it.item_id));
    if (!service) return;
    const groomerKey = String(booking.staff || '').trim();
    const staffRate = staffRates[groomerKey.toLowerCase()] || {};
    const personal = staffRate[String(service.service_id)];
    const defaultRate = rates[String(service.service_id)];
    const selectedRate = personal !== undefined ? personal : defaultRate;
    const rateType = selectedRate && typeof selectedRate === 'object' ? String(selectedRate.type || 'percent') : 'percent';
    const rate = selectedRate !== undefined ? Number(selectedRate && typeof selectedRate === 'object' ? selectedRate.value : selectedRate) : 0;
    const safeRate = Math.max(0, rateType === 'percent' ? Math.min(100, rate) : rate);
    const charged = Math.max(0, Number(it.line_total || 0)), qty = Math.max(0, Number(it.qty || 1));
    const commission = rateType === 'fixed' ? safeRate * qty : charged * safeRate / 100;
    const groomer = staffNameByEmail[groomerKey.toLowerCase()] || groomerKey || 'Unassigned';
    details.push({sale_id:sale.sale_id, sale_at:sale.sale_at, booking_id:booking.booking_id, groomer:groomer, service_id:service.service_id, service_name:service.name, price:Number(it.unit_price || service.price || 0), qty:qty, charged:charged, rate:safeRate, rateType:rateType, commission:Math.round(commission * 100) / 100});
  });
  const totals = {};
  details.forEach(d => {
    if (!totals[d.groomer]) totals[d.groomer] = {groomer:d.groomer, services:0, sales:0, commission:0};
    totals[d.groomer].services += d.qty;
    totals[d.groomer].sales += d.charged;
    totals[d.groomer].commission += d.commission;
  });
  Object.keys(totals).forEach(k => { totals[k].sales = Math.round(totals[k].sales*100)/100; totals[k].commission = Math.round(totals[k].commission*100)/100; });
  return {month:month, services:services.map(s => {const raw=rates[String(s.service_id)],obj=raw&&typeof raw==='object'?raw:{type:'percent',value:Number(raw||0)};return {service_id:s.service_id,name:s.name,price:Number(s.price||0),rate:Math.max(0,Math.min(100,Number(obj.value||0))),defaultRate:{type:String(obj.type||'percent'),value:Number(obj.value||0)}};}), staffRates:staffRates, totals:Object.values(totals).sort((a,b)=>a.groomer.localeCompare(b.groomer)), details:details, staff:staff};
}
function getStaffProfilePage(_authSession, email) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  return buildStaffProfilePage_(_authSession, email, null);
}
function getStaffProfilePages(_authSession, emails) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  const staff = staffDirectory_(_authSession);
  const requested = Array.isArray(emails) && emails.length ? emails : staff.map(x => x.email);
  const allowed = new Set(staff.map(x => String(x.email || '').trim().toLowerCase()).filter(Boolean));
  const list = [...new Set(requested.map(x => String(x || '').trim().toLowerCase()).filter(x => x && allowed.has(x)))];
  const context = {
    staff: staff,
    allRates: getStaffCommissionRates_(),
    defaults: getGroomerCommissionRates_(),
    services: rows_('Services').filter(s => String(s.category || '').toLowerCase() === 'grooming'),
    bookings: rows_('Bookings'), pets: rows_('Pets'), customers: rows_('Customers'),
    works: rows_('GroomerWork'), sales: rows_('Sales'), saleItems: rows_('SaleItems')
  };
  const profiles = {};
  list.forEach(email => { profiles[email] = buildStaffProfilePage_(_authSession, email, context); });
  return {profiles: profiles, count: Object.keys(profiles).length};
}
function buildStaffProfilePage_(_authSession, email, context) {
  email = String(email || '').trim().toLowerCase();
  if (!email) throw new Error('Select a staff member.');
  const profile = (context?.staff || staffDirectory_(_authSession)).find(x => String(x.email || '').toLowerCase() === email);
  if (!profile) throw new Error('Staff member not found.');
  const allRates = context?.allRates || getStaffCommissionRates_(), personalRates = allRates[email] || {}, defaults = context?.defaults || getGroomerCommissionRates_();
  const services = context?.services || rows_('Services').filter(s => String(s.category || '').toLowerCase() === 'grooming');
  const bookings = context?.bookings || rows_('Bookings'), pets = context?.pets || rows_('Pets'), customers = context?.customers || rows_('Customers'), works = context?.works || rows_('GroomerWork');
  const bookingsById = Object.fromEntries(bookings.map(b => [String(b.booking_id), b]));
  const petsById = Object.fromEntries(pets.map(p => [String(p.pet_id), p]));
  const customersById = Object.fromEntries(customers.map(c => [String(c.customer_id), c]));
  const servicesById = Object.fromEntries(services.map(s => [String(s.service_id), s]));
  const assigned = works.filter(w => String(w.groomer_email || '').trim().toLowerCase() === email);
  const assignedByBooking = Object.fromEntries(assigned.map(w => [String(w.booking_id), w]));
  const sales = (context?.sales || rows_('Sales')).filter(s => String(s.source_type || '').toUpperCase() === 'GROOMING' && assignedByBooking[String(s.source_id || '')]);
  const salesByBooking = {};
  sales.forEach(s => { const k = String(s.source_id || ''); (salesByBooking[k] || (salesByBooking[k] = [])).push(s); });
  const itemsBySale = {};
  (context?.saleItems || rows_('SaleItems')).forEach(it => { (itemsBySale[String(it.sale_id)] || (itemsBySale[String(it.sale_id)] = [])).push(it); });
  const orders = assigned.map(w => {
    const b = bookingsById[String(w.booking_id)] || {}, pet = petsById[String(b.pet_id || w.pet_id)] || {}, customer = customersById[String(b.customer_id || pet.customer_id)] || {};
    const service = servicesById[String(b.service_id)] || {};
    const matchedSales = salesByBooking[String(w.booking_id)] || [];
    let charged = 0, commission = 0, saleId = '', saleDate = '';
    matchedSales.forEach(s => {
      if (!saleId || String(s.sale_at || '') > saleDate) { saleId = String(s.sale_id || ''); saleDate = String(s.sale_at || ''); }
      (itemsBySale[String(s.sale_id)] || []).forEach(it => {
        if (String(it.item_type || '').toUpperCase() !== 'SERVICE') return;
        const itemService = servicesById[String(it.item_id)]; if (!itemService) return;
        const line = Math.max(0, Number(it.line_total || 0)), qty = Math.max(0, Number(it.qty || 1));
        charged += line;
        const own = personalRates[String(itemService.service_id)], def = defaults[String(itemService.service_id)];
        const selected = own !== undefined ? own : def;
        const type = selected && typeof selected === 'object' ? String(selected.type || 'percent') : 'percent';
        const rate = selected !== undefined ? Number(selected && typeof selected === 'object' ? selected.value : selected) : 0;
        commission += type === 'fixed' ? Math.max(0, rate) * qty : line * Math.max(0, Math.min(100, rate)) / 100;
      });
    });
    const completed = !!w.completed_at;
    return {booking_id:String(w.booking_id || ''), pet:String(pet.name || ''), customer:String(customer.name || ''), service:String(service.name || b.service_id || 'Grooming'), date:String(b.start_at || saleDate || w.claimed_at || ''), sale_id:saleId, status:completed?'Completed':(w.claimed_at?'In progress':'Assigned'), claimed_at:String(w.claimed_at || ''), completed_at:String(w.completed_at || ''), charged:Math.round(charged*100)/100, commission:Math.round(commission*100)/100};
  }).sort((a,b)=>String(b.date||'').localeCompare(String(a.date||'')));
  const totals = orders.reduce((out,o)=>{out.sales+=Number(o.charged||0);out.commission+=Number(o.commission||0);if(o.status==='Completed')out.completed++;else out.active++;return out;},{sales:0,commission:0,completed:0,active:0});
  totals.sales=Math.round(totals.sales*100)/100; totals.commission=Math.round(totals.commission*100)/100;
  const rateList = services.map(s => { const raw=defaults[String(s.service_id)], obj=raw&&typeof raw==='object'?raw:{type:'percent',value:Number(raw||0)}; return {service_id:String(s.service_id),name:String(s.name||''),defaultType:String(obj.type||'percent'),defaultRate:Number(obj.value||0)}; });
  return {profile:profile,orders:orders,totals:totals,services:rateList,commissionRates:personalRates};
}
function getStaffCommissionReport(_authSession, email, startDate, endDate) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  email = String(email || '').trim().toLowerCase();
  if (!email) throw new Error('Select a staff member.');
  startDate = String(startDate || '').slice(0, 10);
  endDate = String(endDate || '').slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(startDate) || !/^\d{4}-\d{2}-\d{2}$/.test(endDate) || startDate > endDate) {
    throw new Error('Choose a valid date range.');
  }
  const rates = getGroomerCommissionRates_();
  const staffRates = getStaffCommissionRates_();
  const personalRates = staffRates[email] || {};
  const services = rows_('Services').filter(s => String(s.category || '').toLowerCase() === 'grooming');
  const bookings = rows_('Bookings');
  const bookingById = Object.fromEntries(bookings.map(b => [String(b.booking_id), b]));
  const sales = rows_('Sales').filter(s => {
    const date = String(s.sale_at || '').slice(0, 10);
    return String(s.source_type || '').toUpperCase() === 'GROOMING' && date >= startDate && date <= endDate;
  });
  const saleById = Object.fromEntries(sales.map(s => [String(s.sale_id), s]));
  const details = [];
  rows_('SaleItems').forEach(it => {
    const sale = saleById[String(it.sale_id)];
    if (!sale || String(it.item_type || '').toUpperCase() !== 'SERVICE') return;
    const booking = bookingById[String(sale.source_id || '')];
    if (!booking || String(booking.status || '').toUpperCase() !== 'COMPLETED') return;
    if (String(booking.staff || '').trim().toLowerCase() !== email) return;
    const service = services.find(x => String(x.service_id) === String(it.item_id));
    if (!service) return;
    const serviceKey = String(service.service_id), personal = personalRates[serviceKey], defaultRate = rates[serviceKey];
    const selectedRate = personal !== undefined ? personal : defaultRate;
    const rateType = selectedRate && typeof selectedRate === 'object' ? String(selectedRate.type || 'percent') : 'percent';
    const rate = selectedRate !== undefined ? Number(selectedRate && typeof selectedRate === 'object' ? selectedRate.value : selectedRate) : 0;
    const safeRate = Math.max(0, rateType === 'percent' ? Math.min(100, rate) : rate);
    const charged = Math.max(0, Number(it.line_total || 0)), qty = Math.max(0, Number(it.qty || 1));
    const commission = rateType === 'fixed' ? safeRate * qty : charged * safeRate / 100;
    details.push({sale_at:sale.sale_at, booking_id:booking.booking_id, service_name:service.name,
      price:Number(it.unit_price || service.price || 0), qty:qty, charged:charged,
      rate:safeRate, rateType:rateType, commission:Math.round(commission * 100) / 100});
  });
  const totalSales = details.reduce((n, x) => n + x.charged, 0);
  const totalCommission = details.reduce((n, x) => n + x.commission, 0);
  return {email:email, startDate:startDate, endDate:endDate, services:details.length,
    sales:Math.round(totalSales * 100) / 100,
    commission:Math.round(totalCommission * 100) / 100, details:details};
}
function saveGroomerCommissionRates(_authSession, data) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  data = data || {};
  const allowed = rows_('Services').filter(s => String(s.category || '').toLowerCase() === 'grooming');
  const rates = {};
  allowed.forEach(s => {
    const raw = data[String(s.service_id)];
    const type = raw && typeof raw === 'object' ? String(raw.type || 'percent').toLowerCase() : 'percent';
    const n = Number(raw && typeof raw === 'object' ? raw.value : (raw || 0));
    if (!['percent','fixed'].includes(type) || !Number.isFinite(n) || n < 0 || (type === 'percent' && n > 100)) throw new Error(type === 'fixed' ? 'Fixed commission must be zero or more.' : 'Commission rate must be between 0 and 100%.');
    rates[String(s.service_id)] = {type:type,value:Math.round(n * 100) / 100};
  });
  PropertiesService.getScriptProperties().setProperty(GROOMER_COMMISSION_KEY_, JSON.stringify(rates));
  bumpVersion_();
  return rates;
}
function saveService(_authSession, x) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  x = x || {};
  if (!String(x.name||'').trim()) throw new Error('Service name required.');
  x.service_id = x.service_id || id_('SVC');
  x.name = String(x.name).trim(); x.category = String(x.category||'').trim();
  x.price = Number(x.price || 0); x.duration_min = Number(x.duration_min || 0);
  x.active = x.active !== false && x.active !== 'false';
  if (x.price < 0 || x.duration_min < 0) throw new Error('Invalid service price/duration.');
  return upsertRow_(_authSession, 'Services', x, 'service_id');
}
function saveProduct(_authSession, x) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  x = x || {};
  if (!String(x.name||'').trim()) throw new Error('Product name required.');
  // Stock and average cost on an EXISTING product are ledger-managed (sales / receiveInventory);
  // editing the product form must not overwrite them with a stale value from the browser.
  const existing = x.product_id ? rows_('Products').find(p => String(p.product_id) === String(x.product_id)) : null;
  x.product_id=x.product_id||id_('PRD');
  x.name=String(x.name).trim(); x.description=String(x.description||'').trim(); x.category=String(x.category||'').trim(); x.sku=String(x.sku||'').trim(); x.barcode=String(x.barcode||'').trim();
  x.price=Number(x.price||0); x.cost=Number(x.cost||0); x.reorder_level=Number(x.reorder_level||0); x.active=x.active!==false && x.active!=='false'; x.photo_url=String(x.photo_url||'');
  if (existing) {
    x.stock=Number(existing.stock||0);
    x.avg_cost=Number(existing.avg_cost||existing.cost||x.cost||0);
  } else {
    x.stock=Number(x.stock||0);
    x.avg_cost=Number(x.avg_cost||x.cost||0);
  }
  if(x.price<0||x.cost<0||x.avg_cost<0||x.stock<0||x.reorder_level<0)throw new Error('Invalid product values.');
  return upsertRow_(_authSession, 'Products',x,'product_id');
}
function deleteRow_(_authSession, sheetName, idField, id) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  const sh=getSS_().getSheetByName(sheetName), headers=SCHEMA[sheetName];
  if (!sh || sh.getLastRow()<2) throw new Error('Record not found.');
  const idx=headers.indexOf(idField);
  if (idx<0) throw new Error('Record not found.');
  const match=sh.getRange(2,idx+1,sh.getLastRow()-1,1).createTextFinder(String(id)).matchEntireCell(true).findNext();
  if(match){sh.deleteRow(match.getRow());bumpVersion_(sheetName);return true;}
  throw new Error('Record not found.');
}
function deleteMembership(_authSession, id){return deleteRow_(_authSession, 'Memberships','membership_id',id);}
function deleteProduct(_authSession, id){return deleteRow_(_authSession, 'Products','product_id',id);}
function deleteService(_authSession, id){return deleteRow_(_authSession, 'Services','service_id',id);}

/* ───────── Promotions (single/multiple products, category, all products) ─────────
   scope: 'product'   → single product_id
          'products'  → JSON product_ids array
          'category'  → exact product category
          'all'       → every product line
   type:  'percent'   → value is % off gross line
          'fixed'     → RM off per min_qty units on each qualifying product line
*/
function ensurePromotionsSheet_() {
  const ss = getSS_(true);
  let sh = ss.getSheetByName('Promotions');
  if (!sh) sh = ss.insertSheet('Promotions');
  ensureSchema_(sh, SCHEMA.Promotions);
  formatPlainTextColumns_(sh, SCHEMA.Promotions);
  sh.setFrozenRows(1);
  return sh;
}

function savePromotion(_authSession, data) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  ensurePromotionsSheet_();
  data = data || {};
  const id = String(data.promotion_id || '').trim();
  const name = String(data.name || '').trim();
  if (!name) throw new Error('Promotion name is required.');

  const rawScope = String(data.scope || 'product').trim().toLowerCase();
  const scope = ['product','products','category','all'].includes(rawScope) ? rawScope : 'product';
  const productId = scope === 'product' ? String(data.product_id || '').trim() : '';
  let productIds = [];
  if (scope === 'products') {
    const rawIds = data.product_ids;
    try {
      productIds = Array.isArray(rawIds) ? rawIds : JSON.parse(String(rawIds || '[]'));
    } catch (e) {
      throw new Error('Invalid selected product list.');
    }
    if (!Array.isArray(productIds)) throw new Error('Invalid selected product list.');
    productIds = [...new Set(productIds.map(x => String(x || '').trim()).filter(Boolean))];
    if (!productIds.length) throw new Error('Select at least one product.');
    const products = rows_('Products');
    for (const pid of productIds) {
      if (!products.some(p => String(p.product_id) === pid)) throw new Error('Selected product not found: ' + pid);
    }
  }
  const category = scope === 'category' ? String(data.category || '').trim() : '';
  if (scope === 'product' && !productId) throw new Error('Pick a product.');
  if (scope === 'product' && !rows_('Products').some(p => String(p.product_id) === productId)) {
    throw new Error('Product not found.');
  }
  if (scope === 'category' && !category) throw new Error('Pick a category.');
  if (scope === 'category' && !rows_('Products').some(p => String(p.category || '').trim() === category)) {
    throw new Error('Product category not found.');
  }

  const rawType = String(data.type || 'percent').trim().toLowerCase();
  const type = ['percent','fixed','bundle_price'].includes(rawType) ? rawType : 'percent';
  const value = Number(data.value || 0);
  if (!Number.isFinite(value) || value <= 0) throw new Error('Discount value must be greater than 0.');
  if (type === 'percent' && value > 100) throw new Error('Percent discount cannot exceed 100%.');
  if (type === 'bundle_price' && value <= 0) throw new Error('Bundle price must be greater than 0.');

  const minQty = Math.max(1, Math.floor(Number(data.min_qty || 1)));
  const startDate = String(data.start_date || '').slice(0, 10);
  const endDate   = String(data.end_date   || '').slice(0, 10);
  if (startDate && !/^\d{4}-\d{2}-\d{2}$/.test(startDate)) throw new Error('Invalid start date.');
  if (endDate   && !/^\d{4}-\d{2}-\d{2}$/.test(endDate))   throw new Error('Invalid end date.');
  if (startDate && endDate && startDate > endDate) throw new Error('Start date must be on/before end date.');

  const now = new Date().toISOString();
  const existing = id ? rows_('Promotions').find(x => String(x.promotion_id) === id) : null;
  const row = {
    promotion_id: id || id_('PRM'),
    name: name,
    scope: scope,
    product_id: productId,
    product_ids: scope === 'products' ? JSON.stringify(productIds) : '',
    category: category,
    type: type,
    value: round2_(value),
    min_qty: minQty,
    start_date: startDate,
    end_date: endDate,
    allow_membership: data.allow_membership === true || String(data.allow_membership) === 'true',
    active: data.active !== false && String(data.active) !== 'false',
    notes: String(data.notes || '').trim(),
    created_at: existing ? (existing.created_at || now) : now,
    updated_at: now
  };
  return upsertRow_(_authSession, 'Promotions', row, 'promotion_id');
}

function deletePromotion(_authSession, id) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  ensurePromotionsSheet_();
  const cleanId = String(id || '').trim();
  if (!cleanId) throw new Error('Promotion ID is required.');
  return deleteRow_(_authSession, 'Promotions', 'promotion_id', cleanId);
}
function deleteBooking(_authSession, id){return deleteRow_(_authSession, 'Bookings','booking_id',id);}
function deleteBoarding(_authSession, id){return deleteRow_(_authSession, 'Boarding','boarding_id',id);}
function softDeleteRow_(_authSession, sheetName, idField, id, flagField) {
  requireRole_(_authSession, ['OWNER','MANAGER']);
  const sh = getSS_().getSheetByName(sheetName), headers = SCHEMA[sheetName];
  const idx = headers.indexOf(idField), flagIdx = headers.indexOf(flagField);
  if (!sh || sh.getLastRow()<2 || idx<0 || flagIdx<0) throw new Error('Record not found.');
  const match=sh.getRange(2,idx+1,sh.getLastRow()-1,1).createTextFinder(String(id)).matchEntireCell(true).findNext();
  if(match){sh.getRange(match.getRow(),flagIdx+1).setValue(false);bumpVersion_(sheetName);return true;}
  throw new Error('Record not found.');
}
function deletePet(_authSession, id){ return softDeleteRow_(_authSession, 'Pets','pet_id',id,'active'); }
function getRuntimeInfo(_authSession) {
  requireAuthorizedUser_(_authSession);
  // Note: Google Apps Script does not expose deployment timestamps or version numbers
  // via server-side API. We return the hardcoded release constants from Code.gs.
  return {
    scriptVersion: APP_SCRIPT_VERSION,
    scriptTimestamp: APP_RELEASED_AT
  };
}
// ========== BARCODE LOOKUP (add-product helper) ==========

function lookupBarcodeExternal_(code) {
  // Log the GS1 prefix so you can see which Asian country registered this barcode.
  // 885 = Thailand, 880 = South Korea, 45–49 = Japan, 690–699 = China,
  // 955 = Malaysia, 958 = Macau, 00–13 = US/Canada, 30–37 = France, etc.
  const prefix = String(code).slice(0, 3);
  console.log('Barcode lookup prefix=' + prefix + ' code=' + code);

  /**
   * Query one Open*Facts instance (Open Food Facts, Open Pet Food Facts,
   * Open Products Facts, Open Beauty Facts). All four share the same v2 JSON API.
   */
  function fetchOpenFacts_(host, label) {
    try {
      const resp = UrlFetchApp.fetch(
        'https://' + host + '/api/v2/product/' + encodeURIComponent(code) + '.json',
        { muteHttpExceptions: true, headers: { 'User-Agent': 'PetShopPOS/1.0' } }
      );
      if (resp.getResponseCode() !== 200) return null;
      const data = JSON.parse(resp.getContentText());
      if (data.status !== 1 || !data.product) return null;
      const p = data.product;
      const name = String(p.product_name || p.product_name_en || '').trim();
      if (!name) return null;
      return {
        found: true,
        source: label || host,
        barcode: code,
        name: name,
        brand: String(p.brands || '').split(',')[0].trim(),
        category: String(p.categories || '').split(',')[0].trim(),
        description: [p.quantity, p.categories].filter(Boolean).join(' · ').slice(0, 300),
        image_url: String(p.image_front_url || p.image_url || '')
      };
    } catch (e) {
      console.warn((label || host) + ' lookup failed: ' + e);
      return null;
    }
  }

  // 1) Open Pet Food Facts — the most relevant database for dog treats and pet food.
  let hit = fetchOpenFacts_('world.openpetfoodfacts.org', 'Open Pet Food Facts');
  if (hit) return hit;

  // 2) Open Products Facts — general consumer products, often covers pet accessories.
  hit = fetchOpenFacts_('world.openproductsfacts.org', 'Open Products Facts');
  if (hit) return hit;

  // 3) Open Beauty Facts — catches some packaged items that are mis-categorised or cross-listed.
  hit = fetchOpenFacts_('world.openbeautyfacts.org', 'Open Beauty Facts');
  if (hit) return hit;

  // 4) Universal Open*Facts endpoint (product_type=all).
  //    This asks Open Food Facts to search across ALL four Open*Facts databases
  //    and redirect to the correct instance if the product exists elsewhere.
  //    It is the single best fallback for mixed Asian catalogues.
  try {
    const resp = UrlFetchApp.fetch(
      'https://world.openfoodfacts.org/api/v2/product/' +
        encodeURIComponent(code) + '?product_type=all',
      { muteHttpExceptions: true, headers: { 'User-Agent': 'PetShopPOS/1.0' } }
    );
    if (resp.getResponseCode() === 200) {
      const data = JSON.parse(resp.getContentText());
      if (data.status === 1 && data.product) {
        const p = data.product;
        const name = String(p.product_name || p.product_name_en || '').trim();
        if (name) {
          return {
            found: true,
            source: 'Open*Facts (universal)',
            barcode: code,
            name: name,
            brand: String(p.brands || '').split(',')[0].trim(),
            category: String(p.categories || '').split(',')[0].trim(),
            description: [p.quantity, p.categories].filter(Boolean).join(' · ').slice(0, 300),
            image_url: String(p.image_front_url || p.image_url || '')
          };
        }
      }
    }
  } catch (e) { console.warn('Open*Facts universal lookup failed: ' + e); }

  // 5) Open Food Facts — original fallback (kept for backward compatibility).
  hit = fetchOpenFacts_('world.openfoodfacts.org', 'Open Food Facts');
  if (hit) return hit;

  // 6) UPCitemdb trial — lookup endpoint (exact barcode match).
  try {
    const resp = UrlFetchApp.fetch(
      'https://api.upcitemdb.com/prod/trial/lookup?upc=' + encodeURIComponent(code),
      { muteHttpExceptions: true, headers: { 'Accept': 'application/json', 'User-Agent': 'PetShopPOS/1.0' } }
    );
    if (resp.getResponseCode() === 200) {
      const data = JSON.parse(resp.getContentText());
      if (data.code === 'OK' && data.items && data.items.length) {
        const item = data.items[0];
        return {
          found: true,
          source: 'UPCitemdb (lookup)',
          barcode: code,
          name: String(item.title || '').trim(),
          brand: String(item.brand || '').trim(),
          category: String(item.category || '').trim(),
          description: String(item.description || '').slice(0, 300),
          image_url: String((item.images && item.images[0]) || '')
        };
      }
    }
  } catch (e) { console.warn('UPCitemdb lookup failed: ' + e); }

  // 7) UPCitemdb trial — search endpoint (keyword fallback when exact lookup misses).
  //    The trial search endpoint is free and does not require a key.
  try {
    const resp = UrlFetchApp.fetch(
      'https://api.upcitemdb.com/prod/trial/search?s=' + encodeURIComponent(code),
      { muteHttpExceptions: true, headers: { 'Accept': 'application/json', 'User-Agent': 'PetShopPOS/1.0' } }
    );
    if (resp.getResponseCode() === 200) {
      const data = JSON.parse(resp.getContentText());
      if (data.code === 'OK' && data.items && data.items.length) {
        const item = data.items[0];
        return {
          found: true,
          source: 'UPCitemdb (search)',
          barcode: code,
          name: String(item.title || '').trim(),
          brand: String(item.brand || '').trim(),
          category: String(item.category || '').trim(),
          description: String(item.description || '').slice(0, 300),
          image_url: String((item.images && item.images[0]) || '')
        };
      }
    }
  } catch (e) { console.warn('UPCitemdb search failed: ' + e); }

  // 8) Optional ReefAPI lane. Configure PETSHOP_REEFAPI_KEY in Script
  //    Properties for a private installation; never put the key in source.
  const reefKey = String(PropertiesService.getScriptProperties().getProperty('PETSHOP_REEFAPI_KEY') || '').trim();
  if (reefKey) {
    try {
      const resp = UrlFetchApp.fetch(
        'https://api.reefapi.com/barcode/v1/search?key=' + encodeURIComponent(reefKey) + '&query=' +
          encodeURIComponent(code),
        { muteHttpExceptions: true }
      );
      if (resp.getResponseCode() === 200) {
        const data = JSON.parse(resp.getContentText());
        const row = data && data.data && data.data[0];
        if (row && row.title) {
          return {
            found: true,
            source: 'ReefAPI',
            barcode: code,
            name: String(row.title || '').trim(),
            brand: String(row.brand || '').trim(),
            category: String(row.category || '').trim(),
            description: String(row.description || '').slice(0, 300),
            image_url: String(row.image || '')
          };
        }
      }
    } catch (e) { console.warn('ReefAPI lookup failed: ' + e); }
  }

  return { found: false, reason: 'not_found', barcode: code };
}
function lookupBarcode(_authSession, barcode) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const code = String(barcode || '').trim();
  if (!code) throw new Error('Barcode is required.');
  if (!/^[0-9]{8,14}$/.test(code)) return { found: false, reason: 'invalid_format', barcode: code };
  const cache = CacheService.getScriptCache();
  const cacheKey = 'barcode_lookup_v1_' + code;
  try { const cached = cache.get(cacheKey); if (cached) return JSON.parse(cached); } catch (e) {}
  const result = lookupBarcodeExternal_(code);
  try { cache.put(cacheKey, JSON.stringify(result), 3600); } catch (e) {}
  return result;
}

// Import an external product image into the PetShop Photos Drive folder.
// Returns an approved Drive thumbnail URL (the only form saveProduct accepts).
function importProductImageFromUrl(_authSession, imageUrl) {
  requireRole_(_authSession, ['OWNER','MANAGER','STAFF']);
  const url = String(imageUrl || '').trim();
  if (!/^https?:\/\//i.test(url)) throw new Error('Invalid image URL.');
  const resp = UrlFetchApp.fetch(url, {
    muteHttpExceptions: true,
    followRedirects: true,
    headers: { 'User-Agent': 'Mozilla/5.0 PetShopPOS/1.0' }
  });
  if (resp.getResponseCode() !== 200) throw new Error('Image fetch failed (HTTP ' + resp.getResponseCode() + ').');
  const blob = resp.getBlob();
  const mime = String(blob.getContentType() || '').toLowerCase().split(';')[0];
  if (!/^image\/(jpeg|png|webp|gif)$/.test(mime)) throw new Error('Not a supported image type (' + mime + ').');
  if (blob.getBytes().length > 5 * 1024 * 1024) throw new Error('Image is too large (max 5 MB).');
  const folder = petShopPhotosFolder_();
  const safeName = 'imported-' + Date.now() + '.' + (mime.split('/')[1] || 'jpg');
  const file = folder.createFile(blob.setName(safeName));
  try { file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW); } catch (e) {}
  return 'https://drive.google.com/thumbnail?id=' + file.getId() + '&sz=w600';
}

