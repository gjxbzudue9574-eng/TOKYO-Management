
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "tokyo.db");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'employee',
  permissions TEXT NOT NULL DEFAULT '{}',
  photo TEXT DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS customers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  name TEXT NOT NULL,
  phone TEXT DEFAULT '',
  address TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS measurements(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER,
  shape TEXT,
  length REAL DEFAULT 0,
  width REAL DEFAULT 0,
  kitchen_height REAL DEFAULT 0,
  walls TEXT DEFAULT '[]',
  elements TEXT DEFAULT '[]',
  details TEXT DEFAULT '',
  photos TEXT DEFAULT '[]',
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contracts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER,
  contract_no TEXT UNIQUE,
  total REAL DEFAULT 0,
  paid REAL DEFAULT 0,
  date_from TEXT DEFAULT '',
  date_to TEXT DEFAULT '',
  receipt_date TEXT DEFAULT '',
  notes TEXT DEFAULT '[]',
  design3d TEXT DEFAULT '',
  drawing TEXT DEFAULT '',
  additions TEXT DEFAULT '',
  attachments TEXT DEFAULT '[]',
  status TEXT DEFAULT 'new',
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contract_id INTEGER,
  amount REAL NOT NULL,
  note TEXT DEFAULT '',
  created_by INTEGER,
  paid_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS attendance(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  server_time TEXT NOT NULL,
  latitude REAL,
  longitude REAL,
  selfie TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS expenses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  area TEXT NOT NULL,
  name TEXT NOT NULL,
  amount REAL NOT NULL,
  note TEXT DEFAULT '',
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  area TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  urgent INTEGER NOT NULL DEFAULT 0,
  pinned INTEGER NOT NULL DEFAULT 0,
  audience TEXT DEFAULT 'all',
  created_by INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS factory_jobs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER,
  contract_id INTEGER,
  priority TEXT DEFAULT 'normal',
  status TEXT DEFAULT 'new',
  start_date TEXT DEFAULT '',
  due_date TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS materials(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER,
  name TEXT NOT NULL,
  qty REAL DEFAULT 0,
  unit TEXT DEFAULT '',
  status TEXT DEFAULT 'available'
);
CREATE TABLE IF NOT EXISTS shortages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  qty REAL DEFAULT 0,
  unit TEXT DEFAULT '',
  job_id INTEGER,
  note TEXT DEFAULT '',
  resolved INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

function parseJSON(v, fallback={}){ try{return JSON.parse(v||"")}catch{return fallback} }
function setting(key, fallback=""){
  const r=db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return r ? r.value : fallback;
}
function setSetting(key,value){
  db.prepare(`INSERT INTO settings(key,value) VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value`).run(key,String(value));
}
const admin = db.prepare("SELECT * FROM users WHERE username=?").get("admin");
if(!admin){
  const perms = {
    search:true, customers:true, measurements:true, contracts:true, attendance:true,
    exhibition:true, factory:true, notes:true, users:true, reports:true, settings:true
  };
  db.prepare("INSERT INTO users(name,username,password_hash,role,permissions) VALUES(?,?,?,?,?)")
    .run("مدير طوكيو","admin",bcrypt.hashSync("1234",12),"admin",JSON.stringify(perms));
}
if(!setting("company_name")) setSetting("company_name","طوكيو");
if(!setting("company_subtitle")) setSetting("company_subtitle","إدارة طوكيو");
if(!setting("work_hours")) setSetting("work_hours","8");

app.use(express.json({limit:"12mb"}));
app.use(express.urlencoded({extended:true,limit:"12mb"}));
app.use(session({
  secret: process.env.SESSION_SECRET || "TOKYO_CHANGE_THIS_SECRET",
  resave:false,
  saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:false,maxAge:1000*60*60*12}
}));
app.use(express.static(path.join(__dirname,"public")));

function userSafe(u){
  return {
    id:u.id,name:u.name,username:u.username,role:u.role,photo:u.photo||"",
    permissions:parseJSON(u.permissions,{})
  };
}
function auth(req,res,next){
  if(!req.session.user) return res.status(401).json({error:"يجب تسجيل الدخول"});
  next();
}
function adminOnly(req,res,next){
  if(req.session.user?.role!=="admin") return res.status(403).json({error:"هذه الصلاحية للمدير فقط"});
  next();
}
function allow(p){
  return (req,res,next)=>{
    const u=req.session.user;
    if(u?.role==="admin" || u?.permissions?.[p]) return next();
    return res.status(403).json({error:"ليس لديك صلاحية لهذا القسم"});
  }
}

app.post("/api/login",(req,res)=>{
  const {username,password}=req.body||{};
  const u=db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(username||"");
  if(!u || !bcrypt.compareSync(password||"",u.password_hash))
    return res.status(401).json({error:"اسم المستخدم أو كلمة المرور غير صحيحة"});
  req.session.user=userSafe(u);
  res.json(req.session.user);
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json(req.session.user||null));

app.get("/api/dashboard",auth,(req,res)=>{
  const today=new Date().toISOString().slice(0,10);
  const contracts=db.prepare("SELECT COUNT(*) n FROM contracts WHERE substr(created_at,1,10)=?").get(today).n;
  const measures=db.prepare("SELECT COUNT(*) n FROM measurements WHERE substr(created_at,1,10)=?").get(today).n;
  const urgent=db.prepare("SELECT COUNT(*) n FROM notes WHERE urgent=1").get().n;
  const expenses=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE substr(created_at,1,10)=?").get(today).s;
  const present=db.prepare("SELECT COUNT(DISTINCT user_id) n FROM attendance WHERE type='in' AND substr(server_time,1,10)=?").get(today).n;
  res.json({contracts,measures,urgent,expenses,present});
});

app.get("/api/users",auth,adminOnly,(req,res)=>{
  res.json(db.prepare("SELECT id,name,username,role,permissions,photo,active,created_at FROM users ORDER BY id DESC").all()
    .map(u=>({...u,permissions:parseJSON(u.permissions,{})})));
});
app.post("/api/users",auth,adminOnly,(req,res)=>{
  const b=req.body||{};
  if(!b.name||!b.username||!b.password) return res.status(400).json({error:"الاسم واسم المستخدم وكلمة المرور مطلوبة"});
  try{
    const info=db.prepare("INSERT INTO users(name,username,password_hash,role,permissions,photo) VALUES(?,?,?,?,?,?)")
      .run(b.name,b.username,bcrypt.hashSync(b.password,12),b.role||"employee",JSON.stringify(b.permissions||{}),b.photo||"");
    res.json({id:info.lastInsertRowid});
  }catch(e){ res.status(400).json({error:"اسم المستخدم مستخدم مسبقًا"}); }
});
app.patch("/api/users/:id",auth,adminOnly,(req,res)=>{
  const old=db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if(!old) return res.status(404).json({error:"الموظف غير موجود"});
  const b=req.body||{};
  db.prepare("UPDATE users SET name=?,active=?,permissions=?,password_hash=? WHERE id=?")
    .run(b.name??old.name,b.active??old.active,JSON.stringify(b.permissions??parseJSON(old.permissions,{})),
      b.password?bcrypt.hashSync(b.password,12):old.password_hash,old.id);
  res.json({ok:true});
});

app.get("/api/customers",auth,allow("customers"),(req,res)=>{
  const q=String(req.query.q||"").trim();
  if(!q) return res.json(db.prepare("SELECT * FROM customers ORDER BY id DESC LIMIT 200").all());
  const like="%"+q+"%";
  res.json(db.prepare("SELECT * FROM customers WHERE name LIKE ? OR phone LIKE ? OR code LIKE ? OR address LIKE ? ORDER BY id DESC").all(like,like,like,like));
});
app.post("/api/customers",auth,allow("customers"),(req,res)=>{
  const b=req.body||{};
  if(!b.name) return res.status(400).json({error:"اسم الزبون مطلوب"});
  const code=b.code||("T"+Date.now().toString().slice(-7));
  try{
    const info=db.prepare("INSERT INTO customers(code,name,phone,address) VALUES(?,?,?,?)").run(code,b.name,b.phone||"",b.address||"");
    res.json({id:info.lastInsertRowid,code});
  }catch(e){res.status(400).json({error:"رقم الزبون/الملف مستخدم مسبقًا"});}
});
app.get("/api/customers/:id/full",auth,(req,res)=>{
  const c=db.prepare("SELECT * FROM customers WHERE id=?").get(req.params.id);
  if(!c) return res.status(404).json({error:"الزبون غير موجود"});
  const measures=db.prepare("SELECT * FROM measurements WHERE customer_id=? ORDER BY id DESC").all(c.id)
    .map(x=>({...x,walls:parseJSON(x.walls,[]),elements:parseJSON(x.elements,[]),photos:parseJSON(x.photos,[])}));
  const contracts=db.prepare("SELECT * FROM contracts WHERE customer_id=? ORDER BY id DESC").all(c.id)
    .map(x=>({...x,notes:parseJSON(x.notes,[]),attachments:parseJSON(x.attachments,[]),
      payments:db.prepare("SELECT * FROM payments WHERE contract_id=? ORDER BY id DESC").all(x.id)}));
  const jobs=db.prepare("SELECT * FROM factory_jobs WHERE customer_id=? ORDER BY id DESC").all(c.id);
  res.json({customer:c,measurements:measures,contracts,jobs});
});

app.post("/api/measurements",auth,allow("measurements"),(req,res)=>{
  const b=req.body||{};
  const info=db.prepare(`INSERT INTO measurements(customer_id,shape,length,width,kitchen_height,walls,elements,details,photos,created_by)
    VALUES(?,?,?,?,?,?,?,?,?,?)`)
    .run(b.customer_id||null,b.shape||"rectangle",+b.length||0,+b.width||0,+b.kitchen_height||0,
      JSON.stringify(b.walls||[]),JSON.stringify(b.elements||[]),b.details||"",JSON.stringify(b.photos||[]),req.session.user.id);
  res.json({id:info.lastInsertRowid});
});
app.get("/api/measurements",auth,allow("measurements"),(req,res)=>{
  res.json(db.prepare(`SELECT m.*,c.name customer_name,c.code customer_code
    FROM measurements m LEFT JOIN customers c ON c.id=m.customer_id ORDER BY m.id DESC LIMIT 200`).all());
});

app.post("/api/contracts",auth,allow("contracts"),(req,res)=>{
  const b=req.body||{};
  const no=b.contract_no||("C-"+Date.now().toString().slice(-8));
  try{
    const info=db.prepare(`INSERT INTO contracts(customer_id,contract_no,total,paid,date_from,date_to,receipt_date,notes,design3d,drawing,additions,attachments,status,created_by)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      b.customer_id||null,no,+b.total||0,+b.paid||0,b.date_from||"",b.date_to||"",b.receipt_date||"",
      JSON.stringify((b.notes||[]).slice(0,7)),b.design3d||"",b.drawing||"",b.additions||"",JSON.stringify(b.attachments||[]),
      b.status||"new",req.session.user.id);
    if(+b.paid>0) db.prepare("INSERT INTO payments(contract_id,amount,note,created_by) VALUES(?,?,?,?)")
      .run(info.lastInsertRowid,+b.paid,"دفعة أولى",req.session.user.id);
    res.json({id:info.lastInsertRowid,contract_no:no});
  }catch(e){res.status(400).json({error:"رقم العقد مستخدم مسبقًا"});}
});
app.get("/api/contracts",auth,allow("contracts"),(req,res)=>{
  res.json(db.prepare(`SELECT ct.*,c.name customer_name,c.phone customer_phone,c.address customer_address
    FROM contracts ct LEFT JOIN customers c ON c.id=ct.customer_id ORDER BY ct.id DESC LIMIT 200`).all());
});
app.get("/api/contracts/:id",auth,allow("contracts"),(req,res)=>{
  const ct=db.prepare(`SELECT ct.*,c.name customer_name,c.phone customer_phone,c.address customer_address,c.code customer_code
    FROM contracts ct LEFT JOIN customers c ON c.id=ct.customer_id WHERE ct.id=?`).get(req.params.id);
  if(!ct) return res.status(404).json({error:"العقد غير موجود"});
  ct.notes=parseJSON(ct.notes,[]);
  ct.attachments=parseJSON(ct.attachments,[]);
  ct.payments=db.prepare("SELECT * FROM payments WHERE contract_id=? ORDER BY id DESC").all(ct.id);
  ct.company={name:setting("company_name","طوكيو"),subtitle:setting("company_subtitle","إدارة طوكيو")};
  res.json(ct);
});
app.post("/api/contracts/:id/payments",auth,allow("contracts"),(req,res)=>{
  const amount=+req.body.amount||0;
  if(amount<=0) return res.status(400).json({error:"أدخل مبلغ صحيح"});
  db.prepare("INSERT INTO payments(contract_id,amount,note,created_by) VALUES(?,?,?,?)")
    .run(req.params.id,amount,req.body.note||"",req.session.user.id);
  db.prepare("UPDATE contracts SET paid=paid+? WHERE id=?").run(amount,req.params.id);
  res.json({ok:true});
});

app.post("/api/attendance",auth,(req,res)=>{
  const b=req.body||{};
  if(!["in","out"].includes(b.type)) return res.status(400).json({error:"نوع التسجيل غير صحيح"});
  if(!b.selfie) return res.status(400).json({error:"السيلفي إجباري"});
  if(!Number.isFinite(Number(b.latitude))||!Number.isFinite(Number(b.longitude)))
    return res.status(400).json({error:"الموقع الجغرافي إجباري"});
  const now=new Date().toISOString();
  db.prepare("INSERT INTO attendance(user_id,type,server_time,latitude,longitude,selfie) VALUES(?,?,?,?,?,?)")
    .run(req.session.user.id,b.type,now,+b.latitude,+b.longitude,b.selfie);
  res.json({ok:true,server_time:now});
});
app.get("/api/attendance/me",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM attendance WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.session.user.id));
});
app.get("/api/attendance/all",auth,adminOnly,(req,res)=>{
  res.json(db.prepare(`SELECT a.*,u.name FROM attendance a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500`).all());
});

app.get("/api/expenses",auth,(req,res)=>{
  const area=req.query.area||"exhibition";
  const rows=db.prepare(`SELECT e.*,u.name employee_name FROM expenses e LEFT JOIN users u ON u.id=e.created_by
    WHERE e.area=? ORDER BY e.id DESC LIMIT 500`).all(area);
  res.json({rows,total:rows.reduce((s,x)=>s+Number(x.amount||0),0)});
});
app.post("/api/expenses",auth,(req,res)=>{
  const b=req.body||{};
  if(!["exhibition","factory"].includes(b.area)) return res.status(400).json({error:"القسم غير صحيح"});
  if(!b.name||!(+b.amount>0)) return res.status(400).json({error:"اسم المصروف والمبلغ مطلوبان"});
  const info=db.prepare("INSERT INTO expenses(area,name,amount,note,created_by) VALUES(?,?,?,?,?)")
    .run(b.area,b.name,+b.amount,b.note||"",req.session.user.id);
  res.json({id:info.lastInsertRowid});
});

app.get("/api/notes",auth,(req,res)=>{
  const area=req.query.area||"company";
  res.json(db.prepare(`SELECT n.*,u.name creator FROM notes n LEFT JOIN users u ON u.id=n.created_by
    WHERE n.area=? ORDER BY n.pinned DESC,n.urgent DESC,n.id DESC LIMIT 300`).all(area));
});
app.post("/api/notes",auth,(req,res)=>{
  const b=req.body||{};
  if(!b.title||!b.body) return res.status(400).json({error:"العنوان والملاحظة مطلوبان"});
  const info=db.prepare("INSERT INTO notes(area,title,body,urgent,pinned,audience,created_by) VALUES(?,?,?,?,?,?,?)")
    .run(b.area||"company",b.title,b.body,b.urgent?1:0,b.pinned?1:0,b.audience||"all",req.session.user.id);
  res.json({id:info.lastInsertRowid});
});

app.get("/api/factory/jobs",auth,allow("factory"),(req,res)=>{
  const rows=db.prepare(`SELECT j.*,c.name customer_name,ct.contract_no
    FROM factory_jobs j LEFT JOIN customers c ON c.id=j.customer_id LEFT JOIN contracts ct ON ct.id=j.contract_id
    ORDER BY CASE j.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,j.id DESC`).all();
  res.json(rows);
});
app.post("/api/factory/jobs",auth,allow("factory"),(req,res)=>{
  const b=req.body||{};
  const info=db.prepare(`INSERT INTO factory_jobs(customer_id,contract_id,priority,status,start_date,due_date,notes)
    VALUES(?,?,?,?,?,?,?)`).run(b.customer_id||null,b.contract_id||null,b.priority||"normal",b.status||"new",b.start_date||"",b.due_date||"",b.notes||"");
  res.json({id:info.lastInsertRowid});
});
app.get("/api/factory/shortages",auth,allow("factory"),(req,res)=>{
  res.json(db.prepare("SELECT * FROM shortages WHERE resolved=0 ORDER BY id DESC").all());
});
app.post("/api/factory/shortages",auth,allow("factory"),(req,res)=>{
  const b=req.body||{};
  if(!b.name) return res.status(400).json({error:"اسم المادة مطلوب"});
  const info=db.prepare("INSERT INTO shortages(name,qty,unit,job_id,note) VALUES(?,?,?,?,?)")
    .run(b.name,+b.qty||0,b.unit||"",b.job_id||null,b.note||"");
  res.json({id:info.lastInsertRowid});
});
app.get("/api/factory/materials",auth,allow("factory"),(req,res)=>{
  res.json(db.prepare("SELECT * FROM materials ORDER BY id DESC LIMIT 500").all());
});
app.post("/api/factory/materials",auth,allow("factory"),(req,res)=>{
  const b=req.body||{};
  if(!b.name) return res.status(400).json({error:"اسم المادة مطلوب"});
  const info=db.prepare("INSERT INTO materials(job_id,name,qty,unit,status) VALUES(?,?,?,?,?)")
    .run(b.job_id||null,b.name,+b.qty||0,b.unit||"",b.status||"available");
  res.json({id:info.lastInsertRowid});
});

app.get("/api/search",auth,(req,res)=>{
  const q=String(req.query.q||"").trim();
  if(!q) return res.json([]);
  const like="%"+q+"%";
  const customers=db.prepare("SELECT * FROM customers WHERE name LIKE ? OR phone LIKE ? OR code LIKE ? OR address LIKE ? LIMIT 50")
    .all(like,like,like,like);
  const results=[];
  for(const c of customers){
    const full={
      customer:c,
      measurements:db.prepare("SELECT COUNT(*) n FROM measurements WHERE customer_id=?").get(c.id).n,
      contracts:db.prepare("SELECT COUNT(*) n FROM contracts WHERE customer_id=?").get(c.id).n,
      latest_contract:db.prepare("SELECT id,contract_no,total,paid,status,date_to FROM contracts WHERE customer_id=? ORDER BY id DESC LIMIT 1").get(c.id)||null,
      factory:db.prepare("SELECT status,due_date FROM factory_jobs WHERE customer_id=? ORDER BY id DESC LIMIT 1").get(c.id)||null
    };
    results.push(full);
  }
  res.json(results);
});

app.get("/api/reports/summary",auth,allow("reports"),(req,res)=>{
  const today=new Date().toISOString().slice(0,10);
  res.json({
    customers:db.prepare("SELECT COUNT(*) n FROM customers").get().n,
    contracts:db.prepare("SELECT COUNT(*) n FROM contracts").get().n,
    contract_total:db.prepare("SELECT COALESCE(SUM(total),0) s FROM contracts").get().s,
    paid_total:db.prepare("SELECT COALESCE(SUM(paid),0) s FROM contracts").get().s,
    expenses_exhibition:db.prepare("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE area='exhibition'").get().s,
    expenses_factory:db.prepare("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE area='factory'").get().s,
    measurements:db.prepare("SELECT COUNT(*) n FROM measurements").get().n,
    jobs:db.prepare("SELECT COUNT(*) n FROM factory_jobs").get().n,
    today_attendance:db.prepare("SELECT COUNT(*) n FROM attendance WHERE type='in' AND substr(server_time,1,10)=?").get(today).n
  });
});

app.get("/api/settings",auth,adminOnly,(req,res)=>{
  const rows=db.prepare("SELECT key,value FROM settings").all();
  res.json(Object.fromEntries(rows.map(x=>[x.key,x.value])));
});
app.post("/api/settings",auth,adminOnly,(req,res)=>{
  for(const [k,v] of Object.entries(req.body||{})) setSetting(k,v);
  res.json({ok:true});
});

app.get("*",(req,res)=>{
  if(req.path.startsWith("/api/")) return res.status(404).json({error:"API غير موجود"});
  res.sendFile(path.join(__dirname,"public","index.html"));
});

app.listen(PORT,()=>console.log(`TOKYO Management running on http://localhost:${PORT}`));
