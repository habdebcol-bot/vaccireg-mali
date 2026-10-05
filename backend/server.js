require("dotenv").config();
const express=require("express"), cors=require("cors"), helmet=require("helmet"), morgan=require("morgan");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), Database=require("better-sqlite3");
const path=require("path");

const app=express();
app.use(helmet({crossOriginResourcePolicy:false}));
app.use(cors({origin:process.env.CORS_ORIGIN?.split(",").map(x=>x.trim())||true}));
app.use(express.json({limit:"1mb"}));
app.use(morgan("combined"));

const db=new Database(process.env.DB_FILE||"./vaccireg.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS centers(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,location TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'agent',center_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(center_id) REFERENCES centers(id));
CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY AUTOINCREMENT,full_name TEXT NOT NULL,dob TEXT,sex TEXT,village TEXT,phone TEXT,center_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(center_id) REFERENCES centers(id));
CREATE TABLE IF NOT EXISTS vaccinations(id INTEGER PRIMARY KEY AUTOINCREMENT,person_id INTEGER NOT NULL,vaccine TEXT NOT NULL,dose TEXT,vaccination_date TEXT NOT NULL,lot TEXT,next_reminder TEXT,center_id INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(person_id) REFERENCES people(id) ON DELETE CASCADE,FOREIGN KEY(center_id) REFERENCES centers(id));
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,action TEXT,entity TEXT,entity_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id));
`);
const seed=db.transaction(()=>{
  let c=db.prepare("SELECT id FROM centers LIMIT 1").get();
  if(!c) { const r=db.prepare("INSERT INTO centers(name,location) VALUES(?,?)").run("Centre de démonstration","Bamako, Mali"); c={id:r.lastInsertRowid}; }
  const email=process.env.ADMIN_EMAIL||"admin@vaccireg.local";
  if(!db.prepare("SELECT id FROM users WHERE email=?").get(email)){
    const hash=bcrypt.hashSync(process.env.ADMIN_PASSWORD||"ChangeMeNow!",12);
    db.prepare("INSERT INTO users(name,email,password_hash,role,center_id) VALUES(?,?,?,?,?)").run("Administrateur",email,hash,"admin",c.id);
  }
}); seed();

function auth(req,res,next){
  try{ const h=req.headers.authorization||""; if(!h.startsWith("Bearer ")) throw 0;
    req.user=jwt.verify(h.slice(7),process.env.JWT_SECRET||"dev-secret-change-me"); next();
  }catch(e){res.status(401).json({error:"Authentification requise"});}
}
function admin(req,res,next){ if(req.user.role!=="admin") return res.status(403).json({error:"Droits administrateur requis"}); next(); }
function log(user,action,entity,id){db.prepare("INSERT INTO audit_logs(user_id,action,entity,entity_id) VALUES(?,?,?,?)").run(user?.id||null,action,entity,id||null);}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"VacciReg Mali API"}));

app.post("/api/auth/login",(req,res)=>{
  const {email,password}=req.body||{}, u=db.prepare("SELECT * FROM users WHERE email=?").get(email||"");
  if(!u || !bcrypt.compareSync(password||"",u.password_hash)) return res.status(401).json({error:"Email ou mot de passe incorrect"});
  const token=jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role,center_id:u.center_id},process.env.JWT_SECRET||"dev-secret-change-me",{expiresIn:"8h"});
  res.json({token,user:{id:u.id,name:u.name,email:u.email,role:u.role,center_id:u.center_id}});
});

app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));

app.get("/api/centers",auth,(req,res)=>res.json(db.prepare("SELECT * FROM centers ORDER BY name").all()));
app.post("/api/centers",auth,admin,(req,res)=>{
  const {name,location}=req.body||{}; if(!name) return res.status(400).json({error:"Nom requis"});
  const r=db.prepare("INSERT INTO centers(name,location) VALUES(?,?)").run(name,location||"");
  log(req.user,"create","center",r.lastInsertRowid); res.status(201).json(db.prepare("SELECT * FROM centers WHERE id=?").get(r.lastInsertRowid));
});

app.get("/api/users",auth,admin,(req,res)=>res.json(db.prepare("SELECT id,name,email,role,center_id,created_at FROM users ORDER BY name").all()));
app.post("/api/users",auth,admin,(req,res)=>{
  const {name,email,password,role="agent",center_id}=req.body||{};
  if(!name||!email||!password) return res.status(400).json({error:"Nom, email et mot de passe requis"});
  try{
    const hash=bcrypt.hashSync(password,12);
    const r=db.prepare("INSERT INTO users(name,email,password_hash,role,center_id) VALUES(?,?,?,?,?)").run(name,email,hash,role,center_id||null);
    log(req.user,"create","user",r.lastInsertRowid); res.status(201).json({id:r.lastInsertRowid,name,email,role,center_id});
  }catch(e){res.status(409).json({error:"Cet email existe déjà"});}
});

app.get("/api/people",auth,(req,res)=>{
  const q=(req.query.q||"").trim(), cid=req.user.role==="admin" && req.query.center_id ? Number(req.query.center_id) : req.user.center_id;
  let sql="SELECT * FROM people WHERE center_id=?"; let args=[cid];
  if(q){sql+=" AND (full_name LIKE ? OR village LIKE ? OR phone LIKE ?)"; const s="%"+q+"%"; args.push(s,s,s);}
  sql+=" ORDER BY full_name"; res.json(db.prepare(sql).all(...args));
});
app.post("/api/people",auth,(req,res)=>{
  const {full_name,dob,sex,village,phone,center_id}=req.body||{}, cid=req.user.role==="admin"&&center_id?center_id:req.user.center_id;
  if(!full_name||!cid) return res.status(400).json({error:"Nom et centre requis"});
  const r=db.prepare("INSERT INTO people(full_name,dob,sex,village,phone,center_id) VALUES(?,?,?,?,?,?)").run(full_name,dob||null,sex||null,village||null,phone||null,cid);
  log(req.user,"create","person",r.lastInsertRowid); res.status(201).json(db.prepare("SELECT * FROM people WHERE id=?").get(r.lastInsertRowid));
});
app.delete("/api/people/:id",auth,(req,res)=>{
  const p=db.prepare("SELECT * FROM people WHERE id=?").get(req.params.id);
  if(!p || (req.user.role!=="admin" && p.center_id!==req.user.center_id)) return res.status(404).json({error:"Personne introuvable"});
  db.prepare("DELETE FROM people WHERE id=?").run(req.params.id); log(req.user,"delete","person",req.params.id); res.json({ok:true});
});

app.get("/api/vaccinations",auth,(req,res)=>{
  const cid=req.user.role==="admin"&&req.query.center_id?Number(req.query.center_id):req.user.center_id;
  const rows=db.prepare(`SELECT v.*,p.full_name FROM vaccinations v JOIN people p ON p.id=v.person_id WHERE v.center_id=? ORDER BY v.vaccination_date DESC`).all(cid);
  res.json(rows);
});
app.post("/api/vaccinations",auth,(req,res)=>{
  const {person_id,vaccine,dose,vaccination_date,lot,next_reminder,center_id}=req.body||{}, cid=req.user.role==="admin"&&center_id?center_id:req.user.center_id;
  if(!person_id||!vaccine||!vaccination_date||!cid) return res.status(400).json({error:"Personne, vaccin, date et centre requis"});
  const p=db.prepare("SELECT id,center_id FROM people WHERE id=?").get(person_id);
  if(!p || p.center_id!==cid) return res.status(400).json({error:"Personne invalide pour ce centre"});
  const r=db.prepare("INSERT INTO vaccinations(person_id,vaccine,dose,vaccination_date,lot,next_reminder,center_id) VALUES(?,?,?,?,?,?,?)").run(person_id,vaccine,dose||null,vaccination_date,lot||null,next_reminder||null,cid);
  log(req.user,"create","vaccination",r.lastInsertRowid); res.status(201).json(db.prepare("SELECT * FROM vaccinations WHERE id=?").get(r.lastInsertRowid));
});

app.get("/api/dashboard",auth,(req,res)=>{
  const cid=req.user.role==="admin"?(req.query.center_id?Number(req.query.center_id):null):req.user.center_id;
  const people=cid?db.prepare("SELECT COUNT(*) n FROM people WHERE center_id=?").get(cid).n:db.prepare("SELECT COUNT(*) n FROM people").get().n;
  const vacc=cid?db.prepare("SELECT COUNT(*) n FROM vaccinations WHERE center_id=?").get(cid).n:db.prepare("SELECT COUNT(*) n FROM vaccinations").get().n;
  const overdue=cid?db.prepare("SELECT COUNT(*) n FROM vaccinations WHERE center_id=? AND next_reminder IS NOT NULL AND date(next_reminder)<date('now')").get(cid).n:db.prepare("SELECT COUNT(*) n FROM vaccinations WHERE next_reminder IS NOT NULL AND date(next_reminder)<date('now')").get().n;
  const centers=db.prepare("SELECT COUNT(*) n FROM centers").get().n;
  res.json({people,vaccinations:vacc,overdue,centers});
});

app.get("/api/audit",auth,admin,(req,res)=>res.json(db.prepare(`SELECT a.*,u.name user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 200`).all()));

app.use(express.static(path.join(__dirname,"../frontend")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"../frontend/index.html")));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`VacciReg Mali Web: http://localhost:${port}`));
