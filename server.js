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
  const allowed=['name','email','phone','status','membership','needs','coach','goals','notes','follow_up_date'];
  const dateFields=['follow_up_date'];
  const jsonFields=['goals','notes'];
  const updates=[],values=[];let i=1;
  for(const key of allowed){
    if(req.body[key]!==undefined){
      updates.push(key+'=$'+i++);
      let val=req.body[key];
      if(dateFields.includes(key)&&(val===''||val===null)) val=null;
      else if(jsonFields.includes(key)&&val==='') val=null;
      values.push(val);
    }
  }
  if(!updates.length) return res.status(400).json({error:'No valid fields'});
  updates.push('updated_at=NOW()');values.push(req.params.id);
  try{
    const{rows}=await pool.query('UPDATE members SET '+updates.join(',')+ ' WHERE id=$'+i+' RETURNING *',values);
    if(!rows.length) return res.status(404).json({error:'Not found'});
    await logActivity(req.user.name,'Updated '+Object.keys(req.body).filter(k=>allowed.includes(k)).join(', '),'member',rows[0].id,rows[0].name,null);
    res.json(rows[0]);
  }catch(e){
    console.error('PATCH members ERROR:',e.message,JSON.stringify(values));
    res.status(500).json({error:e.message});
  }
});

app.get('/api/leads',auth,async(req,res)=>{
  try{const{rows}=await pool.query('SELECT * FROM leads ORDER BY added DESC');res.json(rows);}
  catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/leads',auth,async(req,res)=>{
  if(req.user.role==='readonly') return res.status(403).json({error:'Read only'});
  const{name,email,phone,status,source,coach,consult_date,notes,ad_campaign_name}=req.body;
  const id='lead_'+Date.now();
  const captureDate=new Date().toISOString().split('T')[0];
  const{next_action,next_action_due}=calcNextAction(captureDate,1);
  try{
    const{rows}=await pool.query(
      `INSERT INTO leads (id,name,email,phone,status,source,coach,consult_date,notes,lead_capture_date,cadence_status,contact_status,current_touch_number,next_action,next_action_due,ad_campaign_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
      [id,name,email||'',phone||'',status||'New Inquiry',source||'',coach||'',consult_date||null,notes||'',captureDate,'active','never_contacted',0,next_action,next_action_due,ad_campaign_name||'']);
    await logActivity(req.user.name,'Added lead','lead',rows[0].id,rows[0].name,null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.patch('/api/leads/:id',auth,async(req,res)=>{
  const allowed=['name','email','phone','status','source','coach','consult_date','notes','timeline','cadence_status','contact_status','next_action','next_action_due','current_touch_number','ad_campaign_name','lead_capture_date'];
  const dateFields=['consult_date','next_action_due','lead_capture_date'];
  const jsonFields=['timeline'];
  const updates=[],values=[];let i=1;
  for(const key of allowed){
    if(req.body[key]!==undefined){
      updates.push(key+'=$'+i++);
      let val=req.body[key];
      if(dateFields.includes(key)&&(val===''||val===null)) val=null;
      else if(jsonFields.includes(key)){
        if(val===''||val===null||val===undefined) val=null;
        else if(typeof val==='string'){
          try{ JSON.parse(val); }catch(e){ val=JSON.stringify(val); }
        } else { val=JSON.stringify(val); }
      } else if(typeof val==='object'&&val!==null) val=JSON.stringify(val);
      values.push(val);
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


// ══════════════════════════════════════════════
// LEADS CADENCE — schema + endpoints
// ══════════════════════════════════════════════
async function ensureLeadsCadence(){
  try{
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS lead_capture_date DATE`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS cadence_status TEXT DEFAULT 'active'`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS contact_status TEXT DEFAULT 'never_contacted'`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS current_touch_number INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS next_action TEXT DEFAULT ''`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS next_action_due DATE`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS ad_campaign_name TEXT DEFAULT ''`);
    await pool.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS touch_at_conversion INTEGER`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_leads_next_due ON leads(next_action_due) WHERE cadence_status='active'`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_leads_cadence ON leads(cadence_status)`);
    console.log('Leads cadence columns ready');
  }catch(e){console.error('ensureLeadsCadence error:',e.message);}
}
ensureLeadsCadence();

const TOUCH_OFFSETS=[0,0,1,2,2,3,4,5,5,6,7,8,9,9,10,11,12,14];
const TOUCH_LABELS=[
  'Send T1 — Opening question (Text)',
  'Send T2 — IG mirror (DM)',
  'Send T3 — Welcome email (Email)',
  'Send T4 — Remove friction (Text)',
  'Send T5 — First call attempt (Call)',
  'Send T6 — Social proof (Email)',
  'Send T7 — Curiosity hook (Text)',
  'Send T8 — Share content (DM)',
  'Send T9 — Free tip (Email)',
  'Send T10 — Check-in question (Text)',
  'Send T11 — Call attempt 2 (Call)',
  'Send T12 — Consult offer (Email)',
  'Send T13 — LBO offer (Text)',
  'Send T14 — DM mirror of LBO (DM)',
  'Send T15 — Objection handling (Email)',
  'Send T16 — Last objection check (Text)',
  'Send T17 — Final call (Call)',
  'Send T18 — Close the loop (Text)'
];

function calcNextAction(captureDate,touchNumber){
  if(touchNumber>18) return{next_action:'Cadence complete — move to nurture',next_action_due:null};
  const idx=touchNumber-1;
  const offset=TOUCH_OFFSETS[idx];
  const due=new Date(captureDate);
  due.setDate(due.getDate()+offset);
  return{next_action:TOUCH_LABELS[idx],next_action_due:due.toISOString().split('T')[0]};
}

app.post('/api/leads/:id/touch',auth,async(req,res)=>{
  if(req.user.role==='readonly') return res.status(403).json({error:'Read only'});
  try{
    const{rows}=await pool.query('SELECT * FROM leads WHERE id=$1',[req.params.id]);
    if(!rows.length) return res.status(404).json({error:'Not found'});
    const lead=rows[0];
    const completedTouch=(lead.current_touch_number||0)+1;
    const nextTouch=completedTouch+1;
    const captureDate=lead.lead_capture_date||new Date().toISOString().split('T')[0];
    const{next_action,next_action_due}=calcNextAction(captureDate,nextTouch);
    const cadenceStatus=completedTouch>=18?'completed':(lead.cadence_status||'active');
    const{rows:updated}=await pool.query(
      `UPDATE leads SET current_touch_number=$1,next_action=$2,next_action_due=$3,cadence_status=$4,contact_status=CASE WHEN contact_status='never_contacted' THEN 'no_reply' ELSE contact_status END,updated_at=NOW() WHERE id=$5 RETURNING *`,
      [completedTouch,next_action,next_action_due,cadenceStatus,req.params.id]
    );
    const touchNote={touch:completedTouch,action:TOUCH_LABELS[completedTouch-1],sent_at:new Date().toISOString(),by:req.user.name};
    const existingTimeline=Array.isArray(lead.timeline)?lead.timeline:[];
    await pool.query(`UPDATE leads SET timeline=$1 WHERE id=$2`,[JSON.stringify([...existingTimeline,touchNote]),req.params.id]);
    await logActivity(req.user.name,'Completed touch '+completedTouch,'lead',lead.id,lead.name,null);
    res.json(updated[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/leads/:id/convert',auth,async(req,res)=>{
  if(req.user.role==='readonly') return res.status(403).json({error:'Read only'});
  const{conversion_type}=req.body;
  const allowed=['trial_signup','consult_booked','membership','package'];
  if(!allowed.includes(conversion_type)) return res.status(400).json({error:'Invalid conversion_type'});
  try{
    const{rows:lead}=await pool.query('SELECT * FROM leads WHERE id=$1',[req.params.id]);
    if(!lead.length) return res.status(404).json({error:'Not found'});
    const newStatus=conversion_type==='trial_signup'?'Trial Signup':conversion_type==='consult_booked'?'Consult Booked':'Joined';
    const{rows}=await pool.query(
      `UPDATE leads SET cadence_status='converted_exit',contact_status='converted',touch_at_conversion=$1,status=$2,next_action='Converted — cadence complete',next_action_due=NULL,updated_at=NOW() WHERE id=$3 RETURNING *`,
      [lead[0].current_touch_number,newStatus,req.params.id]
    );
    await logActivity(req.user.name,'Converted lead: '+conversion_type,'lead',req.params.id,lead[0].name,null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/queue',auth,async(req,res)=>{
  try{
    const{rows}=await pool.query(`
      SELECT *,
        CASE WHEN next_action_due < CURRENT_DATE THEN 'overdue'
             WHEN next_action_due = CURRENT_DATE THEN 'due_today'
             ELSE 'upcoming' END AS due_status
      FROM leads
      WHERE cadence_status='active' AND next_action_due<=CURRENT_DATE
      ORDER BY
        CASE WHEN next_action_due < CURRENT_DATE THEN 0 ELSE 1 END ASC,
        next_action_due ASC, added ASC
    `);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});


// ══════════════════════════════════════════════
// CADENCE STATS
// ══════════════════════════════════════════════
app.get('/api/cadence-stats', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE cadence_status = 'active')::int AS active_in_cadence,
        COUNT(*) FILTER (WHERE cadence_status = 'active' AND next_action_due <= CURRENT_DATE)::int AS due_today,
        COUNT(*) FILTER (WHERE cadence_status = 'active' AND next_action_due < CURRENT_DATE)::int AS overdue,
        COUNT(*) FILTER (WHERE cadence_status = 'converted_exit' AND updated_at >= NOW() - INTERVAL '30 days')::int AS converted_30d,
        COUNT(*) FILTER (WHERE added >= NOW() - INTERVAL '30 days')::int AS new_30d,
        COUNT(*) FILTER (WHERE contact_status IN ('in_conversation','converted'))::int AS contacted,
        COUNT(*) FILTER (WHERE cadence_status != 'unsubscribed')::int AS total_active_leads
      FROM leads
    `);
    const r = rows[0];
    const contactRate = r.total_active_leads > 0
      ? Math.round((r.contacted / r.total_active_leads) * 100)
      : 0;
    res.json({ ...r, contact_rate: contactRate });
  } catch(e) { res.status(500).json({ error: e.message }); }
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
    const{rows}=await pool.query(`
    SELECT m.name, m.coach, m.last_visit, m.needs,
      EXTRACT(DAY FROM NOW()-m.last_visit::timestamptz)::int AS days_since
    FROM members m
    WHERE m.coach IS NOT NULL AND m.coach!=''
      AND (m.last_visit IS NULL OR m.last_visit < NOW() - INTERVAL '14 days')
      AND LOWER(COALESCE(m.status,'')) NOT IN ('paused','frozen','pause','freeze')
      AND NOT EXISTS (
        SELECT 1 FROM contact_log cl
        WHERE cl.member_id = m.id
          AND cl.contacted_at >= NOW() - INTERVAL '7 days'
      )
    ORDER BY m.coach, days_since DESC NULLS LAST
  `);
    if(!rows.length) return;
    // Get yesterday's contact counts
    const{rows:contactRows}=await pool.query("SELECT logged_by, COUNT(*)::int AS count FROM contact_log WHERE contacted_at >= NOW()::date - INTERVAL '1 day' AND contacted_at < NOW()::date GROUP BY logged_by");
    const contactMap={};
    contactRows.forEach(r=>{contactMap[r.logged_by]=r.count;});
    const byCoach={};
    rows.forEach(m=>{if(!byCoach[m.coach])byCoach[m.coach]=[];byCoach[m.coach].push(m);});
    const today=new Date().toLocaleDateString('en-CA',{weekday:'long',month:'long',day:'numeric'});
    let text='📋 *Andwell Daily Check-ins — '+today+'*\n\n';
    const coachOrder=['Xuan','Linda','Alvin','Andrew'];
    const sortedCoaches=[...coachOrder.filter(c=>byCoach[c]),...Object.keys(byCoach).filter(c=>!coachOrder.includes(c)).sort()];
    for(const coach of sortedCoaches){
      const members=byCoach[coach];
      const contacted=contactMap[coach]||0;
      text+='*'+coach+'* — '+members.length+' to contact'+(contacted>0?' · ✓ '+contacted+' contacted yesterday':'')+'\n';
      members.forEach(m=>{text+='  • '+m.name+' — '+(m.days_since?m.days_since+'d since last visit':'no visit on record')+'\n';});
      text+='\n';
    }
    text+='_'+rows.length+' total members need contact today_';
    await fetch(SLACK,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
    console.log('Slack sent');
  }catch(e){console.error('Slack error:',e.message);}
}

cron.schedule('0 12 * * *',async()=>{
  console.log('Running daily tasks...');
  await sendDailyReachout();
});


app.post('/api/slack/test',auth,async(req,res)=>{
  try{
    await sendDailyReachout();
    res.json({ok:true,message:'Slack reach-out triggered'});
  }catch(e){res.status(500).json({error:e.message});}
});


// ══════════════════════════════════════════════
// MOMENCE AUTO-SYNC
// ══════════════════════════════════════════════
async function syncFromMomence() {
  const CLIENT_ID     = process.env.MOMENCE_CLIENT_ID;
  const CLIENT_SECRET = process.env.MOMENCE_CLIENT_SECRET;
  const USERNAME      = process.env.MOMENCE_USERNAME;
  const PASSWORD      = process.env.MOMENCE_PASSWORD;
  const MAPI          = 'https://api.momence.com/api/v2';
  if (!CLIENT_ID || !USERNAME) { console.log('Momence env vars not set, skipping sync'); return; }

  // Auth
  console.log('Momence sync: authenticating...');
  const authBody = new URLSearchParams({ grant_type:'password', username:USERNAME, password:PASSWORD, client_id:CLIENT_ID, client_secret:CLIENT_SECRET });
  const authRes = await fetch(`${MAPI}/auth/token`, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:authBody.toString(), signal:AbortSignal.timeout(15000) });
  const authData = await authRes.json();
  const token = authData.access_token;
  if (!token) throw new Error('Momence auth failed: ' + JSON.stringify(authData));
  console.log('Momence sync: authenticated');

  // Fetch all members
  const allMembers = [];
  let page = 0;
  const pageSize = 100;
  while (true) {
    const res = await fetch(`${MAPI}/host/members?page=${page}&pageSize=${pageSize}`, { headers:{ Authorization:`Bearer ${token}`, 'Content-Type':'application/json' }, signal:AbortSignal.timeout(20000) });
    const body = await res.json();
    const items = Array.isArray(body) ? body : (body.payload || body.data || body.items || body.members || []);
    if (!items.length) break;
    allMembers.push(...items);
    console.log(`Momence sync: fetched ${allMembers.length} members...`);
    if (items.length < pageSize) break;
    page++;
    await new Promise(r => setTimeout(r, 200));
  }
  console.log(`Momence sync: ${allMembers.length} total members fetched`);

  // Map and upsert — preserve coach/goals/notes/needs already set in DB
  const client = await pool.connect();
  let upserted = 0;
  try {
    await client.query('BEGIN');
    for (const m of allMembers) {
      const firstName = m.firstName || m.first_name || '';
      const lastName  = m.lastName  || m.last_name  || '';
      const name = `${firstName} ${lastName}`.trim() || m.email || 'Unknown';
      const lastSeen = m.lastSeen ? m.lastSeen.slice(0,10) : null;
      const firstSeen = m.firstSeen ? m.firstSeen.slice(0,10) : null;
      const visitsObj = m.visits || {};
      const totalVisits = visitsObj.totalVisits ?? visitsObj.total ?? 0;
      const daysSince = lastSeen ? Math.floor((Date.now() - new Date(lastSeen)) / 86400000) : 999;
      const status = daysSince >= 21 ? 'At-Risk' : 'Active';
      const flagged = daysSince >= 21;
      const momenceId = `momence_${m.id}`;

      // Membership from tags as fallback
      let membership = 'Unknown';
      if (m.customerTags?.length > 0) membership = m.customerTags.map(t => t.label||t.name||t).join(', ');

      // Upsert — ON CONFLICT preserves coach, goals, notes, needs (manually set fields)
      await client.query(`
        INSERT INTO members (id, name, email, phone, status, membership, last_visit, total_visits, flagged, join_date)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          email = EXCLUDED.email,
          phone = EXCLUDED.phone,
          status = EXCLUDED.status,
          membership = EXCLUDED.membership,
          last_visit = EXCLUDED.last_visit,
          total_visits = EXCLUDED.total_visits,
          flagged = EXCLUDED.flagged,
          updated_at = NOW()
      `, [momenceId, name, m.email||'', m.phoneNumber||m.phone||'', status, membership, lastSeen, totalVisits, flagged, firstSeen]);
      upserted++;
    }
    await client.query('COMMIT');
    console.log(`Momence sync: upserted ${upserted} members`);

    // Auto-populate trials from members with trial membership
    let trialCount = 0;
    for (const m of allMembers) {
      const tags = (m.customerTags||[]).map(t => (t.name||t.label||'').toLowerCase()).join(' ');
      const isTrial = tags.includes('trial') || tags.includes('7 day') || tags.includes('7day');
      if (!isTrial) continue;
      const firstName = m.firstName || m.first_name || '';
      const lastName = m.lastName || m.last_name || '';
      const name = `${firstName} ${lastName}`.trim() || m.email || 'Unknown';
      const momenceId = String(m.id);
      // Only insert if not already in trials
      const exists = await client.query('SELECT id FROM trials WHERE momence_id=$1', [momenceId]);
      if (!exists.rows.length) {
        const id = 'trial_' + momenceId;
        await client.query(
          `INSERT INTO trials (id,name,email,phone,stage,membership,momence_id,source)
           VALUES ($1,$2,$3,$4,'Trial Purchased','7 Day Trial',$5,'momence')
           ON CONFLICT (id) DO NOTHING`,
          [id, name, m.email||'', m.phoneNumber||'', momenceId]
        );
        trialCount++;
      }
    }
    if (trialCount > 0) console.log(`Momence sync: added ${trialCount} new trial members`);
  } catch(e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
  return upserted;
}

// Schedule: daily at 6am EST (11:00 UTC)
cron.schedule('0 11 * * *', async () => {
  console.log('Running scheduled Momence sync...');
  try { await syncFromMomence(); console.log('Scheduled sync complete'); }
  catch(e) { console.error('Scheduled sync failed:', e.message); }
});

// Manual trigger endpoint
app.post('/api/sync/momence', auth, async (req, res) => {
  try {
    const count = await syncFromMomence();
    res.json({ ok: true, synced: count });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════
// OUTREACH / CONTACT LOG
// ══════════════════════════════════════════════

// Ensure contact_log table exists on startup
async function ensureContactLog(){
  try{
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contact_log (
        id SERIAL PRIMARY KEY,
        member_id VARCHAR(50) REFERENCES members(id) ON DELETE CASCADE,
        logged_by VARCHAR(100) NOT NULL,
        contacted_at TIMESTAMPTZ DEFAULT NOW()
      )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_contact_log_member ON contact_log(member_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_contact_log_user_date ON contact_log(logged_by, contacted_at)`);
    // Add follow_up_date column if it doesn't exist
    await pool.query(`ALTER TABLE members ADD COLUMN IF NOT EXISTS follow_up_date DATE`);
    console.log('contact_log table and follow_up_date column ready');
  }catch(e){console.error('contact_log init error:',e.message);}
}
ensureContactLog();

// GET /api/outreach — all members 14+ days absent, with last_contacted_at
app.get('/api/outreach', auth, async(req,res)=>{
  try{
    const{rows}=await pool.query(`
      SELECT m.id, m.name, m.coach, m.last_visit, m.needs, m.membership, m.status,
        m.follow_up_date,
        EXTRACT(DAY FROM NOW()-m.last_visit::timestamptz)::int AS days_since,
        cl.contacted_at AS last_contacted_at,
        cl.logged_by AS last_contacted_by
      FROM members m
      LEFT JOIN LATERAL (
        SELECT contacted_at, logged_by FROM contact_log
        WHERE member_id = m.id
        ORDER BY contacted_at DESC LIMIT 1
      ) cl ON true
      WHERE (m.last_visit IS NULL OR m.last_visit < NOW() - INTERVAL '14 days')
        AND LOWER(COALESCE(m.status,'')) NOT IN ('paused','frozen','pause','freeze')
        AND m.coach IS NOT NULL AND m.coach != ''
        AND (m.follow_up_date IS NULL OR m.follow_up_date <= CURRENT_DATE)
      ORDER BY m.coach ASC, days_since DESC NULLS LAST
    `);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});

// POST /api/outreach/:memberId/contact — log a contact for the current user
app.post('/api/outreach/:memberId/contact', auth, async(req,res)=>{
  try{
    const{rows}=await pool.query(
      `INSERT INTO contact_log (member_id, logged_by) VALUES ($1,$2) RETURNING *`,
      [req.params.memberId, req.user.name]
    );
    await logActivity(req.user.name,'Logged outreach contact','member',req.params.memberId,'',null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

// DELETE /api/outreach/:memberId/contact — undo today's most recent contact log
app.delete('/api/outreach/:memberId/contact', auth, async(req,res)=>{
  try{
    const{rows}=await pool.query(
      `DELETE FROM contact_log WHERE id = (
        SELECT id FROM contact_log
        WHERE member_id=$1 AND contacted_at >= NOW()::date
        ORDER BY contacted_at DESC LIMIT 1
      ) RETURNING *`,
      [req.params.memberId]
    );
    if(rows.length) await logActivity(req.user.name,'Undid outreach contact','member',req.params.memberId,'',null);
    res.json({ok:true,deleted:rows.length});
  }catch(e){res.status(500).json({error:e.message});}
});

// POST /api/outreach/:memberId/contact/manual — log contact with a specific date
app.post('/api/outreach/:memberId/contact/manual', auth, async(req,res)=>{
  const{date}=req.body;
  if(!date) return res.status(400).json({error:'date required'});
  try{
    // Delete any existing log for this member on this date first (avoid duplicates)
    await pool.query(
      `DELETE FROM contact_log WHERE member_id=$1 AND contacted_at::date=$2`,
      [req.params.memberId, date]
    );
    const{rows}=await pool.query(
      `INSERT INTO contact_log (member_id, logged_by, contacted_at) VALUES ($1,$2,$3) RETURNING *`,
      [req.params.memberId, req.user.name, date]
    );
    await logActivity(req.user.name,'Manually logged contact on '+date,'member',req.params.memberId,'',null);
    res.json(rows[0]);
  }catch(e){res.status(500).json({error:e.message});}
});

// GET /api/outreach/today — all member IDs contacted today (for UI state)
app.get('/api/outreach/today', auth, async(req,res)=>{
  try{
    const{rows}=await pool.query(
      `SELECT DISTINCT member_id FROM contact_log WHERE contacted_at >= NOW()::date`
    );
    res.json(rows.map(r=>r.member_id));
  }catch(e){res.status(500).json({error:e.message});}
});
app.get('/api/outreach/stats', auth, async(req,res)=>{
  try{
    const{rows}=await pool.query(`
      SELECT logged_by, COUNT(*)::int AS count
      FROM contact_log
      WHERE contacted_at >= NOW()::date
      GROUP BY logged_by
      ORDER BY count DESC
    `);
    res.json(rows);
  }catch(e){res.status(500).json({error:e.message});}
});


// ══════════════════════════════════════════════
// TRIALS PIPELINE
// ══════════════════════════════════════════════
async function ensureTrialsTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS trials (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      stage TEXT DEFAULT 'Trial Purchased',
      coach TEXT,
      membership TEXT,
      first_visit DATE,
      trial_start DATE,
      trial_end DATE,
      notes TEXT,
      momence_id TEXT,
      source TEXT DEFAULT 'manual',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_trials_stage ON trials(stage)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_trials_momence ON trials(momence_id)`);
}
ensureTrialsTable().catch(e => console.error('Trials table error:', e.message));

app.get('/api/trials', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM trials ORDER BY created_at DESC');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/trials', auth, async (req, res) => {
  if(req.user.role==='readonly') return res.status(403).json({error:'Read only'});
  const { name, email, phone, stage, coach, membership, notes, trial_start, trial_end } = req.body;
  const id = 'trial_' + Date.now();
  try {
    const { rows } = await pool.query(
      `INSERT INTO trials (id,name,email,phone,stage,coach,membership,notes,trial_start,trial_end)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [id, name, email||'', phone||'', stage||'Trial Purchased', coach||'', membership||'7 Day Trial', notes||'', trial_start||null, trial_end||null]
    );
    await logActivity(req.user.name, 'Added trial', 'trial', rows[0].id, rows[0].name, null);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/trials/:id', auth, async (req, res) => {
  if(req.user.role==='readonly') return res.status(403).json({error:'Read only'});
  const allowed = ['name','email','phone','stage','coach','membership','notes','trial_start','trial_end','first_visit'];
  const updates = [], values = []; let i = 1;
  for(const key of allowed) {
    if(req.body[key] !== undefined) { updates.push(key+'=$'+i++); values.push(req.body[key]); }
  }
  if(!updates.length) return res.status(400).json({error:'No valid fields'});
  updates.push('updated_at=NOW()'); values.push(req.params.id);
  try {
    const { rows } = await pool.query(
      'UPDATE trials SET '+updates.join(',')+'  WHERE id=$'+i+' RETURNING *', values
    );
    if(!rows.length) return res.status(404).json({error:'Not found'});
    await logActivity(req.user.name, 'Updated trial', 'trial', rows[0].id, rows[0].name, null);
    res.json(rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/trials/:id', auth, async (req, res) => {
  if(req.user.role==='readonly') return res.status(403).json({error:'Read only'});
  try {
    await pool.query('DELETE FROM trials WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT,()=>{
  console.log('Andwell CRM running on port',PORT);
  console.log('DB:',process.env.DATABASE_URL?'connected':'NOT SET');
  console.log('Slack:',SLACK?'configured':'not configured');
});
