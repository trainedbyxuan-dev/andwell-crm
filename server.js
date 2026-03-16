const express=require('express');
const {Pool}=require('pg');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const cors=require('cors');
const path=require('path');
const cron=require('node-cron');

const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}});
const JWT_SECRET=process.env.JWT_SECRET||'andwell-crm-secret-change-me';
const PORT=process.env.PORT||3000;
const SLACK=process.env.SLACK_WEBHOOK_URL||'';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname,'public')));

function auth(req,res,next){
  const token=req.headers.authorization?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'No token'});
  try{req.user=jwt.verify(token,JWT_SECRET);next();}
  catch{res.status(401).json({error:'Invalid token'});}
}

app.post('/api/login',async(req,res)=>{
  const{email,password}=req.body;
  try{
    const{rows}=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    if(!rows.length) return res.status(401).json({error:'Invalid credentials'});
    const ok=await bcrypt.compare(password,rows[0].password);
    if(!ok) return res.status(401).json({error:'Invalid credentials'});
    const token=jwt.sign({id:rows[0].id,name:rows[0].name,email:rows[0].email},JWT_SECRET,{expiresIn:'30d'});
    res.json({token,user:{id:rows[0].id,name:rows[0].name,email:rows[0].email}});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/change-password',auth,async(req,res)=>{
  const{currentPassword,newPassword}=req.body;
  try{
    const{rows}=await pool.query('SELECT * FROM users WHERE id=$1',[req.user.id]);
    const ok=await bcrypt.compare(currentPassword,rows[0].password);
    if(!ok) return res.status(400).json({error:'Current password incorrect'});
    const hash=await bcrypt.hash(newPassword,10);
    await pool.query('UPDATE users SET password=$1 WHERE id=$2',[hash,req.user.id]);
    res.json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/members',auth,async(req,res)=>{
  try{const{rows}=await pool.query('SELECT * FROM members ORDER BY name ASC');res.json(rows);}
  catch(e){res.status(500).json({error:e.message});}
});

app.patch('/api/members/:id',auth,async(req,res)=>{
  const allowed=['status','membership','needs','coach','goals','habits','notes','flagged','contacted','timeline'];
  const updates=[],values=[];let i=1;
  for(const key of allowed){
    if(req.body[key]!==undefined){
      updates.push(key+'=$'+i++);
      values.push(typeof req.body[key]==='object'?JSON.stringify(req.body[key]):req.body[key]);
    }
  }
  if(!updates.length) return res.status(400).json({error:'No valid fields'});
  updates.push('updated_at=NOW()');values.push(req.params.id);
  try{
    const{rows}=await pool.query('UPDATE members SET '+updates.join(',')+ ' WHERE id=$'+i+' RETURNING *',values);
    if(!rows.length) return res.status(404).json({error:'Not found'});
    await logActivity(req.user.name,'Updated '+Object.keys(req.body).filter(k=>allowed.includes(k)).join(', '),'member',rows[0].id,rows[0].name,null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/leads',auth,async(req,res)=>{
  try{const{rows}=await pool.query('SELECT * FROM leads ORDER BY added DESC');res.json(rows);}
  catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/leads',auth,async(req,res)=>{
  const{name,email,phone,status,source,coach,consult_date,notes}=req.body;
  const id='lead_'+Date.now();
  try{
    const{rows}=await pool.query('INSERT INTO leads (id,name,email,phone,status,source,coach,consult_date,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [id,name,email||'',phone||'',status||'New Lead',source||'',coach||'',consult_date||null,notes||'']);
    await logActivity(req.user.name,'Added lead','lead',rows[0].id,rows[0].name,null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.patch('/api/leads/:id',auth,async(req,res)=>{
  const allowed=['name','email','phone','status','source','coach','consult_date','notes','timeline'];
  const updates=[],values=[];let i=1;
  for(const key of allowed){
    if(req.body[key]!==undefined){
      updates.push(key+'=$'+i++);
      values.push(typeof req.body[key]==='object'?JSON.stringify(req.body[key]):req.body[key]);
    }
  }
  if(!updates.length) return res.status(400).json({error:'No valid fields'});
  updates.push('updated_at=NOW()');values.push(req.params.id);
  try{
    const{rows}=await pool.query('UPDATE leads SET '+updates.join(',')+'  WHERE id=$'+i+' RETURNING *',values);
    if(!rows.length) return res.status(404).json({error:'Not found'});
    await logActivity(req.user.name,'Updated lead','lead',rows[0].id,rows[0].name,null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.delete('/api/leads/:id',auth,async(req,res)=>{
  try{await pool.query('DELETE FROM leads WHERE id=$1',[req.params.id]);res.json({ok:true});}
  catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/sync/members',async(req,res)=>{
  if(req.headers['x-sync-secret']!==(process.env.SYNC_SECRET||'andwell-sync-2026'))
    return res.status(401).json({error:'Unauthorized'});
  const{members}=req.body;
  if(!Array.isArray(members)) return res.status(400).json({error:'members array required'});
  try{
    const client=await pool.connect();let upserted=0;
    try{
      await client.query('BEGIN');
      for(const m of members){
        await client.query(`INSERT INTO members (id,name,email,phone,status,membership,last_visit,visits_7d,total_visits,needs,flagged,join_date,momence_id,updated_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
          ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name,email=EXCLUDED.email,phone=EXCLUDED.phone,
          status=EXCLUDED.status,membership=EXCLUDED.membership,last_visit=EXCLUDED.last_visit,
          visits_7d=EXCLUDED.visits_7d,total_visits=EXCLUDED.total_visits,needs=EXCLUDED.needs,
          flagged=EXCLUDED.flagged,join_date=EXCLUDED.join_date,momence_id=EXCLUDED.momence_id,updated_at=NOW()`,
          [m.id,m.name,m.email||'',m.phone||'',m.status||'Active',m.membership||'',
           m.lastVisit||null,m.visits7d||0,m.totalVisits||0,m.needs||'Low',m.flagged||false,
           m.joinDate||null,m._momenceId||null]);
        upserted++;
      }
      await client.query('COMMIT');
    }catch(e){await client.query('ROLLBACK');throw e;}
    finally{client.release();}
    res.json({ok:true,upserted});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/stats',auth,async(req,res)=>{
  try{
    const[members,leads,activity]=await Promise.all([
      pool.query("SELECT COUNT(*) total,COUNT(*) FILTER(WHERE status='Active') active,COUNT(*) FILTER(WHERE status='At-Risk') at_risk,COUNT(*) FILTER(WHERE flagged=true) flagged,COUNT(*) FILTER(WHERE join_date>=NOW()-INTERVAL '30 days') new_this_month FROM members"),
      pool.query("SELECT COUNT(*) total,COUNT(*) FILTER(WHERE added>=NOW()-INTERVAL '7 days') new_this_week FROM leads"),
      pool.query('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 10'),
    ]);
    res.json({members:members.rows[0],leads:leads.rows[0],recent:activity.rows});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/activity',auth,async(req,res)=>{
  try{const{rows}=await pool.query('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 100');res.json(rows);}
  catch(e){res.status(500).json({error:e.message});}
});

async function logActivity(userName,action,entityType,entityId,entityName,detail){
  try{await pool.query('INSERT INTO activity_log (user_name,action,entity_type,entity_id,entity_name,detail) VALUES ($1,$2,$3,$4,$5,$6)',[userName,action,entityType,entityId,entityName,detail]);}catch{}
}

async function sendDailyReachout(){
  if(!SLACK){console.log('No Slack webhook');return;}
  try{
    const{rows}=await pool.query("SELECT name,coach,last_visit,needs,EXTRACT(DAY FROM NOW()-last_visit::timestamptz)::int AS days_since FROM members WHERE flagged=true AND coach IS NOT NULL AND coach!='' ORDER BY coach,days_since DESC NULLS LAST");
    if(!rows.length) return;
    const byCoach={};
    rows.forEach(m=>{if(!byCoach[m.coach])byCoach[m.coach]=[];byCoach[m.coach].push(m);});
    const today=new Date().toLocaleDateString('en-CA',{weekday:'long',month:'long',day:'numeric'});
    let text='📋 *Andwell Daily Check-ins — '+today+'*\n\n';
    for(const[coach,members] of Object.entries(byCoach)){
      text+='*'+coach+'* ('+members.length+')\n';
      members.slice(0,8).forEach(m=>{text+='  • '+m.name+' — '+(m.days_since?m.days_since+'d since last visit':'no visit on record')+'\n';});
      text+='\n';
    }
    text+='_'+rows.length+' total members to contact today_';
    await fetch(SLACK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
    console.log('Slack sent');
  }catch(e){console.error('Slack error:',e.message);}
}

cron.schedule('0 12 * * *',async()=>{
  console.log('Running daily tasks...');
  await sendDailyReachout();
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT,()=>{
  console.log('Andwell CRM running on port',PORT);
  console.log('DB:',process.env.DATABASE_URL?'connected':'NOT SET');
  console.log('Slack:',SLACK?'configured':'not configured');
});
