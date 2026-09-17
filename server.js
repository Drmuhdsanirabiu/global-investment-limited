require('dotenv').config();
const express=require('express');
const session=require('express-session');
const path=require('path');
const crypto=require('crypto');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const helmet=require('helmet');
const rateLimit=require('express-rate-limit');
const speakeasy=require('speakeasy');
const nodemailer=require('nodemailer');

const app=express();
const PORT=Number(process.env.PORT||3000);
const BASE_URL=process.env.BASE_URL||`http://localhost:${PORT}`;
const db=new Database(path.join(__dirname,'data.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, referral_code TEXT NOT NULL UNIQUE, balance REAL NOT NULL DEFAULT 0,
 role TEXT NOT NULL DEFAULT 'user',
 twofa_enabled INTEGER NOT NULL DEFAULT 0, twofa_secret TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', provider TEXT, reference TEXT UNIQUE, note TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS referrals(
 id INTEGER PRIMARY KEY AUTOINCREMENT, referrer_id INTEGER NOT NULL, referred_id INTEGER NOT NULL UNIQUE,
 commission REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(referrer_id) REFERENCES users(id), FOREIGN KEY(referred_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, ip TEXT, metadata TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS webhook_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

function seedAdmin(){
 const email='admin@globalinvestment.test';
 if(!db.prepare('SELECT id FROM users WHERE email=?').get(email)){
  db.prepare('INSERT INTO users(full_name,email,password_hash,referral_code,role) VALUES(?,?,?,?,?)')
   .run('System Administrator',email,bcrypt.hashSync('Admin@12345',12),'ADMIN001','admin');
 }
}
seedAdmin();

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'100kb',verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf)}}));
app.use(express.urlencoded({extended:true,limit:'100kb'}));
app.use(session({
 secret:process.env.SESSION_SECRET||'CHANGE_ME',resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}
}));
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));
app.use(express.static(path.join(__dirname,'public')));

const authLimiter=rateLimit({windowMs:15*60*1000,max:10,skipSuccessfulRequests:true});
const paymentLimiter=rateLimit({windowMs:15*60*1000,max:30});

function cleanEmail(x){return String(x||'').trim().toLowerCase()}
function auth(req,res,next){if(!req.session.userId)return res.status(401).json({error:'Please log in.'});next()}
function admin(req,res,next){if(!req.session.userId)return res.status(401).json({error:'Please log in.'});const u=db.prepare('SELECT role FROM users WHERE id=?').get(req.session.userId);if(!u||u.role!=='admin')return res.status(403).json({error:'Admin access required.'});next()}
function userById(id){return db.prepare('SELECT id,full_name,email,referral_code,balance,role,twofa_enabled,created_at FROM users WHERE id=?').get(id)}
function audit(req,action,metadata={}){db.prepare('INSERT INTO audit_logs(user_id,action,ip,metadata) VALUES(?,?,?,?)').run(req.session.userId||null,action,req.ip,JSON.stringify(metadata))}
function csrf(req,res,next){if(['GET','HEAD','OPTIONS'].includes(req.method))return next();const origin=req.get('origin');if(origin&&origin!==BASE_URL)return res.status(403).json({error:'Origin check failed.'});next()}
app.use('/api',csrf);

function mailer(){if(!process.env.SMTP_HOST)return null;return nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:Number(process.env.SMTP_PORT||587)===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}})}
async function sendMail(to,subject,text){const t=mailer();if(!t)return;await t.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,to,subject,text})}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'global-investment-limited',time:new Date().toISOString()}));
app.get('/api/me',(req,res)=>{if(!req.session.userId)return res.json({authenticated:false});res.json({authenticated:true,user:userById(req.session.userId)})});

app.post('/api/register',authLimiter,(req,res)=>{
 const {fullName,password,referralCode}=req.body;const email=cleanEmail(req.body.email);
 if(!fullName||!email||!password)return res.status(400).json({error:'Full name, email and password are required.'});
 if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return res.status(400).json({error:'Enter a valid email.'});
 if(String(password).length<8)return res.status(400).json({error:'Password must be at least 8 characters.'});
 if(db.prepare('SELECT id FROM users WHERE email=?').get(email))return res.status(409).json({error:'Email already registered.'});
 let ref=null;if(referralCode)ref=db.prepare('SELECT id FROM users WHERE referral_code=?').get(String(referralCode).trim());
 const code='GI'+crypto.randomBytes(4).toString('hex').toUpperCase();
 const tx=db.transaction(()=>{const r=db.prepare('INSERT INTO users(full_name,email,password_hash,referral_code) VALUES(?,?,?,?)').run(String(fullName).trim(),email,bcrypt.hashSync(String(password),12),code);if(ref)db.prepare('INSERT INTO referrals(referrer_id,referred_id) VALUES(?,?)').run(ref.id,r.lastInsertRowid);return r.lastInsertRowid});
 const id=tx();req.session.userId=id;audit(req,'register');res.json({message:'Registration successful.',user:userById(id)});
});

app.post('/api/login',authLimiter,async(req,res)=>{
 const email=cleanEmail(req.body.email),password=String(req.body.password||''),u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'Invalid email or password.'});
 if(u.twofa_enabled){const code=String(req.body.otp||'');if(!speakeasy.totp.verify({secret:u.twofa_secret,encoding:'base32',token:code,window:1}))return res.status(401).json({error:'2FA code required or invalid.'})}
 req.session.userId=u.id;audit(req,'login');res.json({message:'Login successful.',user:userById(u.id)});
});
app.post('/api/logout',auth,(req,res)=>{audit(req,'logout');req.session.destroy(()=>res.json({message:'Logged out.'}))});

app.post('/api/2fa/setup',auth,(req,res)=>{const secret=speakeasy.generateSecret({name:`Global Investment Limited (${userById(req.session.userId).email})`});db.prepare('UPDATE users SET twofa_secret=?,twofa_enabled=0 WHERE id=?').run(secret.base32,req.session.userId);res.json({secret:secret.base32,otpauth_url:secret.otpauth_url});});
app.post('/api/2fa/enable',auth,(req,res)=>{const u=db.prepare('SELECT twofa_secret FROM users WHERE id=?').get(req.session.userId);if(!u?.twofa_secret)return res.status(400).json({error:'Run 2FA setup first.'});if(!speakeasy.totp.verify({secret:u.twofa_secret,encoding:'base32',token:String(req.body.otp||''),window:1}))return res.status(400).json({error:'Invalid code.'});db.prepare('UPDATE users SET twofa_enabled=1 WHERE id=?').run(req.session.userId);audit(req,'2fa_enabled');res.json({message:'2FA enabled.'})});
app.post('/api/2fa/disable',auth,(req,res)=>{const u=db.prepare('SELECT twofa_secret FROM users WHERE id=?').get(req.session.userId);if(!u?.twofa_secret||!speakeasy.totp.verify({secret:u.twofa_secret,encoding:'base32',token:String(req.body.otp||''),window:1}))return res.status(400).json({error:'Invalid code.'});db.prepare('UPDATE users SET twofa_enabled=0,twofa_secret=NULL WHERE id=?').run(req.session.userId);res.json({message:'2FA disabled.'})});

app.get('/api/dashboard',auth,(req,res)=>{const u=userById(req.session.userId);const tx=db.prepare('SELECT id,type,amount,status,provider,reference,note,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 50').all(u.id);const referrals=db.prepare('SELECT COUNT(*) count,COALESCE(SUM(commission),0) commission FROM referrals WHERE referrer_id=?').get(u.id);res.json({user:u,transactions:tx,referrals})});
app.get('/api/referrals',auth,(req,res)=>{const u=userById(req.session.userId);const rows=db.prepare('SELECT u.full_name,u.email,r.commission,r.created_at FROM referrals r JOIN users u ON u.id=r.referred_id WHERE r.referrer_id=? ORDER BY r.id DESC').all(u.id);res.json({code:u.referral_code,link:`${BASE_URL}/?ref=${u.referral_code}`,referrals:rows})});

async function flutterwaveInitialize(req,email,name,amount,reference){const r=await fetch('https://api.flutterwave.com/v3/payments',{method:'POST',headers:{Authorization:`Bearer ${process.env.FLW_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({tx_ref:reference,amount,currency:'NGN',redirect_url:`${BASE_URL}/?payment=flutterwave`,customer:{email,name}})});const d=await r.json();if(!r.ok||d.status!=='success')throw new Error(d.message||'Flutterwave initialization failed');return d.data.link}

app.post('/api/deposit',auth,paymentLimiter,async(req,res)=>{
 const amount=Number(req.body.amount);if(!Number.isFinite(amount)||amount<100)return res.status(400).json({error:'Minimum deposit is ₦100.'});
 const u=userById(req.session.userId);const provider=String(process.env.PAYMENT_PROVIDER||'none').toLowerCase();const reference='GI-'+Date.now()+'-'+crypto.randomBytes(3).toString('hex');
 try{
  let url=null;
  if(provider==='flutterwave'){url=await flutterwaveInitialize(req,u.email,u.full_name,amount,reference)}
  else {db.prepare('INSERT INTO transactions(user_id,type,amount,status,provider,reference,note) VALUES(?,?,?,?,?,?,?)').run(u.id,'deposit',amount,'pending','manual',reference,'Demo/manual deposit pending admin review.')}
  if(provider!=='none')db.prepare('INSERT INTO transactions(user_id,type,amount,status,provider,reference,note) VALUES(?,?,?,?,?,?,?)').run(u.id,'deposit',amount,'pending',provider,reference,'Awaiting verified payment webhook/callback.');
  audit(req,'deposit_created',{amount,provider,reference});res.json({message:provider==='none'?'Deposit request submitted for admin approval.':'Continue to secure payment checkout.',checkoutUrl:url,reference});
 }catch(e){res.status(400).json({error:e.message})}
});

app.post('/api/withdraw',auth,paymentLimiter,(req,res)=>{
 const amount=Number(req.body.amount);const u=userById(req.session.userId);if(!Number.isFinite(amount)||amount<=0)return res.status(400).json({error:'Enter a valid amount.'});if(amount>u.balance)return res.status(400).json({error:'Insufficient available balance.'});
 const ref='WD-'+Date.now()+'-'+crypto.randomBytes(3).toString('hex');db.prepare('INSERT INTO transactions(user_id,type,amount,status,provider,reference,note) VALUES(?,?,?,?,?,?,?)').run(u.id,'withdrawal',amount,'pending','manual',ref,'Withdrawal queued for admin approval.');audit(req,'withdrawal_created',{amount,reference:ref});res.json({message:'Withdrawal request submitted for review.',reference:ref});
});


app.post('/api/webhooks/flutterwave',express.json({type:'application/json'}),(req,res)=>{if(!process.env.FLW_SECRET_HASH||req.get('verif-hash')!==process.env.FLW_SECRET_HASH)return res.status(401).end();const p=req.body;const eventId=`flutterwave:${p.data?.id||p.data?.tx_ref}`;try{db.prepare('INSERT INTO webhook_events(provider,event_id,payload) VALUES(?,?,?)').run('flutterwave',eventId,JSON.stringify(p))}catch(e){return res.status(200).end()};res.status(200).end();});

app.get('/api/admin/summary',admin,(req,res)=>{const users=db.prepare("SELECT COUNT(*) count FROM users WHERE role='user'").get().count;const deposits=db.prepare("SELECT COALESCE(SUM(amount),0) total FROM transactions WHERE type='deposit' AND status='approved'").get().total;const withdrawals=db.prepare("SELECT COALESCE(SUM(amount),0) total FROM transactions WHERE type='withdrawal' AND status='approved'").get().total;const pending=db.prepare("SELECT COUNT(*) count FROM transactions WHERE status='pending'").get().count;res.json({users,deposits,withdrawals,pending})});
app.get('/api/admin/transactions',admin,(req,res)=>res.json(db.prepare('SELECT t.*,u.full_name,u.email FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC').all()));
app.get('/api/admin/users',admin,(req,res)=>res.json(db.prepare('SELECT id,full_name,email,referral_code,balance,role,twofa_enabled,created_at FROM users ORDER BY id DESC').all()));
app.post('/api/admin/transactions/:id/:action',admin,(req,res)=>{const tx=db.prepare('SELECT * FROM transactions WHERE id=?').get(req.params.id);if(!tx||tx.status!=='pending')return res.status(400).json({error:'Transaction is not pending.'});if(req.params.action==='reject'){db.prepare("UPDATE transactions SET status='rejected',note=? WHERE id=?").run(req.body.note||'Rejected by admin.',tx.id);audit(req,'transaction_rejected',{id:tx.id});return res.json({message:'Transaction rejected.'})}if(req.params.action!=='approve')return res.status(400).json({error:'Invalid action.'});try{db.transaction(()=>{if(tx.type==='deposit')db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(tx.amount,tx.user_id);if(tx.type==='withdrawal'){const u=userById(tx.user_id);if(tx.amount>u.balance)throw new Error('Insufficient balance at approval time.');db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(tx.amount,tx.user_id)}db.prepare("UPDATE transactions SET status='approved',note=? WHERE id=?").run('Approved by admin.',tx.id)})();audit(req,'transaction_approved',{id:tx.id});res.json({message:'Transaction approved.'})}catch(e){res.status(400).json({error:e.message})}});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`Global Investment Limited running at ${BASE_URL}`));
