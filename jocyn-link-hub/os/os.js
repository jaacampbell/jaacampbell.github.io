(function(){
"use strict";
const $=(q,r=document)=>r.querySelector(q), $$=(q,r=document)=>Array.from(r.querySelectorAll(q));
const root=$("#viewRoot"), viewTitle=$("#viewTitle"), toast=$("#toast");
let currentView="home", toastTimer;
const createOptions=[
["Post","Draft platform-specific social content."],["Campaign","Turn a goal into content, tasks and a timeline."],
["Idea","Capture a raw creative thought."],["Release Plan","Build a full single or project rollout."],
["Content Series","Create a repeatable format."],["Link","Add something to the public Link Hub."],
["Upload Media","Add reusable images, video or audio."],["Task","Create a lightweight execution reminder."]
];
const aiPrompts=["What should I post today?","Build a campaign around TALK BOUT","Repurpose my latest video","Update my Link Hub for this release"];
const state={
content:[
{title:"TALK BOUT — announcement reel",meta:"Release campaign • vertical video",status:"Ready",platforms:["IG","TT","YT"]},
{title:"WANDERLVST world teaser",meta:"Album campaign • cinematic",status:"Draft",platforms:["IG","TT"]},
{title:"Boarding Lounge RSVP push",meta:"Event • static + story",status:"Scheduled",platforms:["IG","FB"]},
{title:"Chasing Fog film still",meta:"Catalog extension • image",status:"Idea",platforms:["IG"]}
],
tasks:[
["1","Finalize TALK BOUT release post","Campaign","Today"],
["2","Add final streaming links to Link Hub","Link Hub","Next"],
["3","Approve WANDERLVST teaser cut","Content","Review"]
],
campaigns:[
{title:"TALK BOUT",status:"Active",goal:"Launch lead single with a focused 14-day content cycle.",progress:62},
{title:"WANDERLVST",status:"Planning",goal:"Build the album world into one connected release system.",progress:28}
]
};
const store=window.JOCYN_STORE||null;
if(store){
  const persisted=store.getState();
  state.content=persisted.content;
  state.tasks=persisted.tasks;
  state.campaigns=persisted.campaigns;
  state.media=persisted.media;
}else if(!state.media){state.media=[]}
let hubDraft=store?store.getPublished():{
  heroTitle:"WANDERLVST",heroSubtitle:"Music • film • story",heroStatus:"ALBUM • MAR 5",heroAction:"ENTER",
  featuredTitle:"TALK BOUT",featuredSubtitle:"Single • Current direction",featuredCta:"Listen now",
  featuredVisible:true,chasingVisible:true,wanderVisible:true,boardingVisible:true,emailVisible:true
};
function persistState(){if(store)store.saveState(state)}
function attr(v){return escapeHtml(String(v==null?"":v)).replace(/"/g,"&quot;")}
function note(msg){clearTimeout(toastTimer);toast.textContent=msg;toast.classList.add("show");toastTimer=setTimeout(()=>toast.classList.remove("show"),2200)}
function openOverlay(id){const el=$("#"+id);el.classList.add("open");el.setAttribute("aria-hidden","false")}
function closeOverlay(id){const el=$("#"+id);el.classList.remove("open");el.setAttribute("aria-hidden","true")}
$$("[data-close]").forEach(b=>b.addEventListener("click",()=>closeOverlay(b.dataset.close)));
$$(".overlay").forEach(o=>o.addEventListener("click",e=>{if(e.target===o)closeOverlay(o.id)}));
function setView(view){
  currentView=view; const titles={home:"Command Center",content:"Content Studio",ideas:"Ideas",calendar:"Calendar",campaigns:"Campaigns",projects:"Projects",linkhub:"Link Hub",analytics:"Analytics",media:"Media Library",settings:"Settings"};
  viewTitle.textContent=titles[view]||"Command Center";
  $("#aiContextLabel").textContent=viewTitle.textContent;
  $$(".nav-item[data-view]").forEach(b=>b.classList.toggle("active",b.dataset.view===view));
  $$(".mobile-dock [data-view]").forEach(b=>b.classList.toggle("active",b.dataset.view===view));
  render(view); root.focus({preventScroll:true}); window.scrollTo({top:0,behavior:"smooth"}); $("#sidebar").classList.remove("open");
}
function pageHead(title,subtitle,actions=""){
  return '<div class="page-head"><div><span class="overline">JO₵YN / ARTIST WORKSPACE</span><h1>'+title+'</h1><p>'+subtitle+'</p></div><div class="head-actions">'+actions+'</div></div>';
}
function home(){
const live=store?store.getAnalytics():{pageViews:0,ctr:0,topDestination:"—"};
const displayViews=live.pageViews||1284;
const displayCtr=live.pageViews?live.ctr:18.6;
const displayTop=live.topDestination&&live.topDestination!=="—"?live.topDestination:"Spotify";
return pageHead("Command Center","The day-to-day operating view for your music, content, campaigns and public profile.",'<button class="btn ghost" data-action="preview">Public hub</button><button class="btn primary" data-action="create">Create</button>')+
'<div class="grid home-grid">'+
'<section class="card hero-command"><div class="hero-content"><span class="overline">TODAY • CREATIVE PRIORITY</span><h1>Move TALK BOUT from “ready” to “in motion.”</h1><p>The single direction is clear. Your strongest next move is to finish the launch post, connect the public hub to the campaign, then build the next three pieces around the same visual world.</p><div class="hero-actions"><button class="btn primary" data-view-jump="campaigns">Open campaign</button><button class="btn" data-action="ask-ai">Build today’s plan ✦</button></div></div><div class="hero-meta"><span class="meta-pill">1 ACTIVE CAMPAIGN</span><span class="meta-pill">4 CONTENT ITEMS</span><span class="meta-pill">2 NEED ATTENTION</span></div></section>'+
'<section class="card"><div class="card-head"><div><h2>Today’s priorities</h2><p>Only what needs attention now.</p></div><button class="muted-link" data-action="all-tasks">All tasks</button></div><div class="priority-list">'+state.tasks.map(t=>'<div class="priority"><div class="priority-index">'+t[0]+'</div><div><strong>'+t[1]+'</strong><span>'+t[2]+'</span></div><div class="tag">'+t[3]+'</div></div>').join("")+'</div></section>'+
'<section class="card span-2"><div class="card-head"><div><h2>Content pipeline</h2><p>From raw idea to published content.</p></div><button class="muted-link" data-view-jump="content">Open studio →</button></div>'+pipeline()+'</section>'+
'<section class="card"><div class="card-head"><div><h2>Active campaign</h2><p>Release system, not disconnected posts.</p></div><button class="muted-link" data-view-jump="campaigns">Open →</button></div><div class="campaign-card"><div class="campaign-art">TALK<br>BOUT</div><div class="campaign-info"><span class="status ready">Active</span><h3>TALK BOUT</h3><p>Lead-single campaign • content, assets, Link Hub and rollout tasks connected.</p><div class="progress"><i></i></div><div class="progress-label"><span>Campaign readiness</span><b>62%</b></div></div></div></section>'+
'<section class="card"><div class="card-head"><div><h2>Public Link Hub</h2><p>Your owned destination is part of the campaign.</p></div><button class="muted-link" data-view-jump="linkhub">Edit →</button></div><div class="link-preview-wrap"><div class="phone"><div class="phone-notch"></div><div class="phone-avatar">J</div><div class="phone-name">@jocyn</div><div class="phone-bio">Artist • creator • world builder</div><div class="phone-hero">WANDERLVST</div><div class="phone-link">TALK BOUT</div><div class="phone-link">Chasing Fog</div><div class="phone-link">Boarding Lounge</div></div><div class="link-stats"><div class="link-stat"><strong>'+displayViews.toLocaleString()+'</strong><span>profile visits • 7 days</span></div><div class="link-stat"><strong>'+displayCtr+'%</strong><span>click-through rate</span></div><div class="link-stat"><strong>'+displayTop+'</strong><span>top destination</span></div></div></div></section>'+
'<section class="card"><div class="card-head"><div><h2>AI recommendations</h2><p>What happened → why → what to do.</p></div><button class="muted-link" data-action="ask-ai">Ask AI</button></div><div class="insight"><div class="insight-icon">✦</div><div><strong>Put TALK BOUT above the album hub during launch week.</strong><p>Your public profile should mirror the priority of the active campaign.</p></div></div><div class="insight"><div class="insight-icon">↻</div><div><strong>Repurpose the latest vertical video into three platform-native cuts.</strong><p>Change the hook and CTA instead of reposting identical copy.</p></div></div><div class="insight"><div class="insight-icon">□</div><div><strong>Thursday is still open.</strong><p>Use it for a low-lift story sequence that reinforces the single.</p></div></div></section>'+
'<section class="card"><div class="card-head"><div><h2>This week</h2><p>Release rhythm at a glance.</p></div><button class="muted-link" data-view-jump="calendar">Calendar →</button></div><div class="calendar-strip">'+["MON","TUE","WED","THU","FRI","SAT","SUN"].map((d,i)=>'<div class="day"><div class="date">'+d+' '+(6+i)+'</div>'+(i===1?'<div class="dot"></div><small>Reel draft</small>':i===3?'<div class="dot" style="background:var(--amber)"></div><small>Open slot</small>':i===4?'<div class="dot" style="background:var(--green)"></div><small>TALK BOUT</small>':'')+'</div>').join("")+'</div></section>'+
'</div>';
}
function pipeline(){
const cols={Idea:[],Draft:[],Ready:[],Scheduled:[]};state.content.forEach(c=>(cols[c.status]||cols.Idea).push(c));
return '<div class="pipeline">'+Object.keys(cols).map(k=>'<div class="pipeline-col"><div class="pipeline-head"><span>'+k+'</span><b>'+cols[k].length+'</b></div>'+cols[k].map(c=>'<div class="content-card"><div class="thumb"></div><strong>'+c.title+'</strong><span>'+c.meta+'</span><div class="platform-row">'+c.platforms.map(p=>'<i class="platform-chip">'+p+'</i>').join("")+'</div></div>').join("")+(cols[k].length?'':'<div class="empty" style="padding:18px 8px"><p style="margin:0">Nothing here yet.</p></div>')+'</div>').join("")+'</div>';
}
function content(){
return pageHead("Content Studio","Create, review, schedule and repurpose content without losing the campaign context.",'<button class="btn" data-action="upload">Upload media</button><button class="btn primary" data-action="create">New content</button>')+
'<div class="list-toolbar"><div class="segmented"><button class="active">List</button><button>Pipeline</button><button>Calendar</button></div><button class="btn">Filter</button></div>'+
'<div class="table-list">'+state.content.map((c,i)=>'<div class="table-row"><div class="row-art"></div><div class="row-main"><strong>'+c.title+'</strong><span>'+c.meta+'</span></div><span class="status '+c.status.toLowerCase()+'">'+c.status+'</span><div class="platform-row">'+c.platforms.map(p=>'<i class="platform-chip">'+p+'</i>').join("")+'</div><button class="btn">Open</button></div>').join("")+'</div>'+
'<section class="card" style="margin-top:14px"><div class="card-head"><div><h2>Repurpose lane</h2><p>One source becomes platform-native variations.</p></div><button class="btn primary" data-action="repurpose">Repurpose content ✦</button></div><div class="flow"><div class="flow-step"><b>01</b><div><strong>Original: TALK BOUT vertical master</strong><span>Source video + core message</span></div></div><div class="flow-step"><b>02</b><div><strong>Instagram Reel</strong><span>Visual-first hook • save/share CTA</span></div></div><div class="flow-step"><b>03</b><div><strong>TikTok cut</strong><span>Faster opening • conversational caption</span></div></div><div class="flow-step"><b>04</b><div><strong>YouTube Short</strong><span>Searchable title • clean end card</span></div></div></div></section>';
}
function ideas(){
const presets=[["Promote my latest release","Build ideas around TALK BOUT."],["Create a content series","Turn one theme into a repeatable format."],["Repurpose something","Expand one asset into platform-specific pieces."],["Find a growth opportunity","Use performance patterns to suggest a move."],["Plan next week","Fill gaps without overposting."],["Start from nothing","Open creative canvas with no preset."]];
return pageHead("Idea Engine","Start from a goal, a half-formed thought or nothing at all. AI turns it into an executable system.",'<button class="btn" data-action="saved-ideas">Saved ideas</button>')+
'<div class="idea-shell"><section class="card idea-box"><span class="overline">OPEN CANVAS</span><h2>What do you want to create, promote, launch or grow?</h2><p>You are not choosing a template. Start with the outcome or idea in your own words and the system will build the strategy around it.</p><div class="idea-input"><textarea id="ideaInput" placeholder="Example: I want TALK BOUT to feel unavoidable for two weeks without repeating the same post…"></textarea><button class="btn primary" id="ideaGo">Build with AI ✦</button></div><div class="preset-grid">'+presets.map(p=>'<button class="preset" data-idea="'+p[0]+'"><strong>'+p[0]+'</strong><span>'+p[1]+'</span></button>').join("")+'</div></section><section class="card"><div class="card-head"><div><h2>How ideas become output</h2><p>One connected creation flow.</p></div></div><div class="flow">'+["Idea","Strategy","Concepts","Drafts","Media needs","Platform adaptations","Schedule","Publish","Measure","Next action"].map((x,i)=>'<div class="flow-step"><b>'+String(i+1).padStart(2,"0")+'</b><div><strong>'+x+'</strong><span>'+(["Your intent","Define the objective","Choose creative angles","Write and shape","Know what to make","Adapt by platform","Place into rhythm","Execute","Read the signal","Keep momentum"][i])+'</span></div></div>').join("")+'</div></section></div>';
}
function calendar(){
return pageHead("Calendar","See the content rhythm, campaign windows, releases and gaps — not just individual posts.",'<button class="btn">Month</button><button class="btn primary" data-action="create">Schedule content</button>')+
'<section class="card"><div class="card-head"><div><h2>October 2026</h2><p>Campaign-aware editorial calendar.</p></div><div class="segmented"><button>Day</button><button class="active">Week</button><button>Month</button><button>Campaign</button></div></div><div class="calendar-strip" style="grid-template-columns:repeat(7,minmax(120px,1fr))">'+["Mon 5","Tue 6","Wed 7","Thu 8","Fri 9","Sat 10","Sun 11"].map((d,i)=>'<div class="day" style="min-height:260px"><div class="date">'+d+'</div>'+(i===1?'<div class="content-card"><strong>TALK BOUT teaser</strong><span>Draft • IG / TT</span></div>':i===2?'<div class="content-card"><strong>Studio clip</strong><span>Ready • Stories</span></div>':i===3?'<div class="empty" style="padding:20px 5px;margin-top:15px"><p>Content gap</p><button class="muted-link" data-action="ask-ai">Fill with AI</button></div>':i===4?'<div class="content-card"><strong>TALK BOUT push</strong><span>Campaign • all platforms</span></div>':'')+'</div>').join("")+'</div></section>';
}
function campaigns(){
return pageHead("Campaigns","Organize a release or objective into one connected system of content, assets, links, tasks and performance.",'<button class="btn primary" data-action="new-campaign">New campaign</button>')+
'<div class="campaign-grid">'+state.campaigns.map(c=>'<section class="card campaign-panel"><div class="campaign-top"><div><span class="status '+(c.status==="Active"?"ready":"draft")+'">'+c.status+'</span><h3>'+c.title+'</h3></div><small>'+c.progress+'% ready</small></div><p style="font-size:11px;color:var(--muted);line-height:1.5">'+c.goal+'</p><div class="progress"><i style="width:'+c.progress+'%"></i></div><div class="task-list"><label class="task"><input type="checkbox" '+(c.progress>50?"checked":"")+'><b>Campaign strategy</b><span>Strategy</span></label><label class="task"><input type="checkbox"><b>Content package</b><span>Content</span></label><label class="task"><input type="checkbox"><b>Public Link Hub update</b><span>Link Hub</span></label><label class="task"><input type="checkbox"><b>Launch analytics view</b><span>Measure</span></label></div><button class="btn" style="margin-top:13px">Open workspace →</button></section>').join("")+'</div>';
}
function projects(){
return pageHead("Projects","Keep singles, albums, events and creative projects connected to campaigns, assets and content.",'<button class="btn primary" data-action="new-project">New project</button>')+
'<div class="campaign-grid"><section class="card campaign-panel"><span class="overline">ALBUM</span><div class="campaign-top"><h3>WANDERLVST</h3><small>Mar 5</small></div><p style="font-size:11px;color:var(--muted)">Album world • music, visuals, content, listening experience and release timeline.</p><button class="btn" style="margin-top:14px">Open project →</button></section><section class="card campaign-panel"><span class="overline">SINGLE</span><div class="campaign-top"><h3>TALK BOUT</h3><small>Active</small></div><p style="font-size:11px;color:var(--muted)">Lead single direction • release campaign connected.</p><button class="btn" style="margin-top:14px">Open project →</button></section></div>';
}
function toggle(label,key,on){
return '<div class="toggle-row"><span>'+label+'</span><button type="button" class="switch '+(on?'on':'')+'" data-hub-toggle="'+key+'" aria-pressed="'+(on?'true':'false')+'"><i></i></button></div>';
}
function linkhub(){
return pageHead("Link Hub","Control the public JO₵YN mini-site like a website — not a generic list of links.",'<a class="btn" href="../index.html" target="_blank">Open public site ↗</a><button class="btn primary" data-action="publish-hub">Publish changes</button>')+
'<div class="linkhub-editor">'+
'<aside class="editor-panel"><h3>Blocks</h3><div class="block-list">'+
'<button class="block-item"><strong>Hero / profile</strong><span>Identity + social shortcuts</span></button>'+
'<button class="block-item"><strong>Featured release</strong><span>Campaign-level spotlight</span></button>'+
'<button class="block-item"><strong>Smart music link</strong><span>Streaming destinations</span></button>'+
'<button class="block-item"><strong>Video / visual</strong><span>Embed or open destination</span></button>'+
'<button class="block-item"><strong>Event</strong><span>RSVP, tickets, details</span></button>'+
'<button class="block-item"><strong>Email signup</strong><span>Own the audience relationship</span></button>'+
'</div><button class="btn" style="width:100%;margin-top:10px" data-action="add-block">＋ Add block</button></aside>'+
'<section class="preview-stage"><div><span class="overline" style="text-align:center">LIVE MOBILE PREVIEW</span><div class="editor-phone">'+
'<div class="phone-avatar">J</div><div class="phone-name">@jocyn</div><div class="phone-bio">Artist • creator • world builder</div>'+
'<div class="phone-hero" id="hubPreviewHero">'+escapeHtml(hubDraft.heroTitle)+'</div>'+
(hubDraft.featuredVisible?'<div class="phone-link" id="hubPreviewFeatured">'+escapeHtml(hubDraft.featuredTitle)+' — FEATURED</div>':'')+
(hubDraft.chasingVisible?'<div class="phone-link">Chasing Fog</div>':'')+
(hubDraft.wanderVisible?'<div class="phone-link">WANDERLVST</div>':'')+
(hubDraft.boardingVisible?'<div class="phone-link">Boarding Lounge</div>':'')+
'</div></div></section>'+
'<aside class="editor-panel"><h3>Publish controls</h3>'+
'<div class="settings-group"><span class="overline">CURRENT ERA</span>'+
'<div class="field"><label>Hero title</label><input id="hubHeroTitle" value="'+attr(hubDraft.heroTitle)+'"></div>'+
'<div class="field"><label>Hero subtitle</label><input id="hubHeroSubtitle" value="'+attr(hubDraft.heroSubtitle)+'"></div>'+
'<div class="field"><label>Status</label><input id="hubHeroStatus" value="'+attr(hubDraft.heroStatus)+'"></div></div>'+
'<div class="settings-group"><span class="overline">FEATURED RELEASE</span>'+
'<div class="field"><label>Title</label><input id="hubFeaturedTitle" value="'+attr(hubDraft.featuredTitle)+'"></div>'+
'<div class="field"><label>Subtitle</label><input id="hubFeaturedSubtitle" value="'+attr(hubDraft.featuredSubtitle)+'"></div>'+
'<div class="field"><label>Primary CTA</label><input id="hubFeaturedCta" value="'+attr(hubDraft.featuredCta)+'"></div></div>'+
'<div class="settings-group">'+
toggle("Featured release","featuredVisible",hubDraft.featuredVisible)+
toggle("Chasing Fog","chasingVisible",hubDraft.chasingVisible)+
toggle("WANDERLVST card","wanderVisible",hubDraft.wanderVisible)+
toggle("Boarding Lounge","boardingVisible",hubDraft.boardingVisible)+
toggle("Email signup","emailVisible",hubDraft.emailVisible)+
'</div><div class="settings-group"><small style="font-size:9px;color:var(--muted)">Publish writes this configuration to the shared prototype layer. The public hub reads it on refresh.</small></div></aside>'+
'</div>';
}
function analytics(){
const a=store?store.getAnalytics():{pageViews:0,clicks:0,contentOpens:0,ctr:0,topDestination:"—"};
const hasLive=!!(a.pageViews||a.clicks||a.contentOpens);
const visits=hasLive?a.pageViews:4800;
const clicks=hasLive?a.clicks:892;
const opens=hasLive?a.contentOpens:311;
const ctr=hasLive?a.ctr:18.6;
const top=hasLive&&a.topDestination!=="—"?a.topDestination:"Spotify";
return pageHead("Analytics","Turn performance into decisions. Every number should answer what happened, why and what to do next.",'<button class="btn">'+(hasLive?'Live local data':'Prototype data')+'</button>')+
'<div class="analytics-grid"><div class="metric"><span class="label">Profile visits</span><strong>'+visits.toLocaleString()+'</strong><small class="positive">'+(hasLive?'Tracked from the public hub':'↑ 18% vs prior period')+'</small></div>'+
'<div class="metric"><span class="label">Link + content clicks</span><strong>'+clicks.toLocaleString()+'</strong><small class="positive">'+(hasLive?'Local event stream':'↑ 24% vs prior period')+'</small></div>'+
'<div class="metric"><span class="label">Content opens</span><strong>'+opens.toLocaleString()+'</strong><small>'+top+' is the top destination</small></div>'+
'<div class="metric"><span class="label">Hub CTR</span><strong>'+ctr+'%</strong><small>Tracked actions divided by visits</small></div></div>'+
'<div class="grid" style="grid-template-columns:minmax(0,1.3fr) minmax(280px,.7fr);margin-top:14px"><section class="card"><div class="card-head"><div><h2>Attention trend</h2><p>Profile visits and link activity.</p></div></div><div class="chart"><div style="font-size:10px;color:var(--muted)">7-DAY SIGNAL</div><div style="font-size:24px;font-weight:730;margin-top:7px">'+visits.toLocaleString()+' visits</div><div style="font-size:9px;color:var(--green);margin-top:3px">'+(hasLive?'Reading this browser’s real prototype events':'Demo until audience traffic arrives')+'</div><svg viewBox="0 0 600 120" preserveAspectRatio="none"><path d="M0,100 C70,88 90,105 145,74 S235,80 290,55 S390,68 445,38 S530,48 600,16" fill="none" stroke="rgba(239,233,224,.8)" stroke-width="3"/><path d="M0,100 C70,88 90,105 145,74 S235,80 290,55 S390,68 445,38 S530,48 600,16 L600,120 L0,120 Z" fill="rgba(239,233,224,.06)"/></svg></div></section>'+
'<section class="card"><div class="card-head"><div><h2>AI readout</h2><p>The useful part of analytics.</p></div></div><div class="insight"><div class="insight-icon">↗</div><div><strong>'+top+' is currently the strongest destination signal.</strong><p>Keep high-intent music actions above secondary links while the release campaign is active.</p></div></div><div class="insight"><div class="insight-icon">◎</div><div><strong>'+ctr+'% of visits are turning into tracked actions.</strong><p>Use the Link Hub editor to test hierarchy before adding more destinations.</p></div></div></section></div>';
}
function media(){
const assets=(state.media&&state.media.length)?state.media:[
{name:"TALK BOUT key art",kind:"Campaign asset"},{name:"WANDERLVST still 01",kind:"Photo"},{name:"Chasing Fog night exterior",kind:"Photo"}
];
return pageHead("Media Library","One reusable asset system for campaign imagery, video, audio, artwork and brand files.",'<button class="btn">Filter</button><button class="btn primary" data-action="upload">Upload media</button>')+
'<div class="media-grid">'+assets.map(x=>'<article class="media-card"><div class="media-label"><strong>'+escapeHtml(x.name)+'</strong><span>'+escapeHtml(x.kind||"Asset")+'</span></div></article>').join("")+'</div>';
}
function settings(){
return pageHead("Settings","Keep the workspace identity, voice, integrations and public profile context in one place.")+
'<div class="campaign-grid"><section class="card"><div class="card-head"><div><h2>Brand profile</h2><p>AI and content context for JO₵YN.</p></div></div><div class="field"><label>Workspace name</label><input value="JO₵YN"></div><div class="field"><label>Primary identity</label><input value="Artist"></div><div class="field"><label>Brand voice</label><input value="Confident, cinematic, direct, Southern energy"></div></section><section class="card"><div class="card-head"><div><h2>Connections</h2><p>Designed for platform-specific capability states.</p></div></div><div class="task"><b>Instagram</b><span>Prototype • connect later</span></div><div class="task"><b>TikTok</b><span>Prototype • connect later</span></div><div class="task"><b>YouTube</b><span>Prototype • connect later</span></div><div class="task"><b>Spotify</b><span>Prototype • connect later</span></div></section></div>';
}
function render(view){
const views={home,content,ideas,calendar,campaigns,projects,linkhub,analytics,media,settings};root.innerHTML=(views[view]||home)();
wireView();
}
function wireView(){
$$("[data-view-jump]",root).forEach(b=>b.addEventListener("click",()=>setView(b.dataset.viewJump)));
$$("[data-action]",root).forEach(b=>b.addEventListener("click",()=>action(b.dataset.action)));
$("#ideaGo",root)?.addEventListener("click",()=>{
  const v=$("#ideaInput").value.trim();
  if(!v){note("Add an idea or choose a preset.");return}
  openAi("Turn this into a full content strategy: "+v);
});
$$("[data-idea]",root).forEach(b=>b.addEventListener("click",()=>openAi(b.dataset.idea)));
$$(".switch",root).forEach(sw=>sw.addEventListener("click",()=>{
  sw.classList.toggle("on");
  const key=sw.dataset.hubToggle;
  if(key){
    hubDraft[key]=sw.classList.contains("on");
    sw.setAttribute("aria-pressed",hubDraft[key]?"true":"false");
    render("linkhub");
  }
}));
const bindHub=(id,key,previewId)=>{
  const el=$("#"+id,root);
  if(!el)return;
  el.addEventListener("input",()=>{
    hubDraft[key]=el.value;
    const preview=previewId?$("#"+previewId,root):null;
    if(preview)preview.textContent=el.value;
  });
};
bindHub("hubHeroTitle","heroTitle","hubPreviewHero");
bindHub("hubHeroSubtitle","heroSubtitle");
bindHub("hubHeroStatus","heroStatus");
bindHub("hubFeaturedTitle","featuredTitle","hubPreviewFeatured");
bindHub("hubFeaturedSubtitle","featuredSubtitle");
bindHub("hubFeaturedCta","featuredCta");
}
function action(a){
if(a==="create")openOverlay("createOverlay");
else if(a==="ask-ai"||a==="repurpose")openAi(a==="repurpose"?"Repurpose my current TALK BOUT master into platform-native content.":"What should I do next in this workspace?");
else if(a==="preview")window.open("../index.html","_blank");
else if(a==="publish-hub"){
  if(store){hubDraft=store.publishHub(hubDraft);note("Published. Refresh the public hub to see the update.");}
  else note("Persistence layer is unavailable.");
}
else if(a==="add-block")note("Custom block creation is staged for the database-backed editor.");
else if(a==="upload"){
  const input=document.createElement("input");
  input.type="file";input.multiple=true;input.accept="image/*,video/*,audio/*";
  input.addEventListener("change",()=>{
    const files=Array.from(input.files||[]);
    if(!files.length)return;
    if(!state.media)state.media=[];
    files.forEach(file=>state.media.unshift({
      id:"local-"+Date.now()+"-"+Math.random().toString(16).slice(2),
      name:file.name,
      kind:file.type.startsWith("video/")?"Video":file.type.startsWith("audio/")?"Audio":"Image",
      size:file.size
    }));
    persistState();
    note(files.length+" asset"+(files.length===1?"":"s")+" added to the prototype library.");
    if(currentView==="media")render("media");
  });
  input.click();
}
else if(a==="new-campaign")openAi("Create a new campaign from my objective.");
else if(a==="new-project")note("Project creation is staged for the database-backed build.");
else note("This action is represented in the prototype and ready for implementation.");
}
function openAi(seed=""){openOverlay("aiOverlay");if(seed){$("#aiInput").value=seed;setTimeout(()=>$("#aiInput").focus(),50)}}
function init(){
$("#createGrid").innerHTML=createOptions.map(x=>'<button class="create-option" data-create="'+x[0]+'"><b>'+x[0]+'</b><span>'+x[1]+'</span></button>').join("");
$("#aiChips").innerHTML=aiPrompts.map(x=>'<button type="button" data-prompt="'+x+'">'+x+'</button>').join("");
$("[data-create]").forEach(b=>b.addEventListener("click",()=>{
  closeOverlay("createOverlay");
  if(b.dataset.create==="Idea")setView("ideas");
  else if(b.dataset.create==="Campaign")setView("campaigns");
  else if(b.dataset.create==="Link")setView("linkhub");
  else if(b.dataset.create==="Upload Media")action("upload");
  else if(b.dataset.create==="Post"){
    state.content.unshift({id:"draft-"+Date.now(),title:"New content draft",meta:"Created from global launcher",status:"Draft",platforms:["IG"]});
    persistState();
    setView("content");
    note("New draft created.");
  }else note(b.dataset.create+" creation flow is staged for the next implementation pass.");
}));
$$("[data-prompt]").forEach(b=>b.addEventListener("click",()=>{$("#aiInput").value=b.dataset.prompt;$("#aiInput").focus()}));
$("#createBtn").addEventListener("click",()=>openOverlay("createOverlay"));
$("#mobileCreate").addEventListener("click",()=>openOverlay("createOverlay"));
$("#startWithAi").addEventListener("click",()=>{closeOverlay("createOverlay");openAi()});
$("#aiBtn").addEventListener("click",()=>openAi());
$("#mobileAi").addEventListener("click",()=>openAi());
$("#searchBtn").addEventListener("click",openCommand);
$("#mobileMenu").addEventListener("click",()=>$("#sidebar").classList.toggle("open"));
$("#mobileMore").addEventListener("click",()=>$("#sidebar").classList.toggle("open"));
$$("[data-view]").forEach(b=>b.addEventListener("click",()=>setView(b.dataset.view)));
$("#aiForm").addEventListener("submit",e=>{e.preventDefault();const q=$("#aiInput").value.trim();if(!q)return;const feed=$("#assistantFeed");feed.insertAdjacentHTML("beforeend",'<div class="assistant-msg" style="margin-top:12px"><span class="assistant-star" style="background:#29292d;color:#fff">J</span><p>'+escapeHtml(q)+'</p></div><div class="assistant-msg" style="margin-top:12px"><span class="assistant-star">✦</span><p>I’ve got the context. In the connected build, I’ll turn this into structured strategy, drafts, media needs, scheduling and Link Hub actions instead of returning disconnected copy.</p></div>');$("#aiInput").value="";feed.scrollTop=feed.scrollHeight});
document.addEventListener("keydown",e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k"){e.preventDefault();openCommand()}if(e.key==="Escape"){$$(".overlay.open").forEach(o=>closeOverlay(o.id));$("#sidebar").classList.remove("open")}});
render("home");
}
function escapeHtml(s){return s.replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
const commands=[
{label:"Create post",desc:"Start new content",icon:"＋",run:()=>{closeOverlay("commandOverlay");openOverlay("createOverlay")}},
{label:"Ask JO₵YN Assistant",desc:"Open contextual AI",icon:"✦",run:()=>{closeOverlay("commandOverlay");openAi()}},
{label:"Open Content Studio",desc:"Content pipeline and repurposing",icon:"▦",run:()=>setView("content")},
{label:"Open Calendar",desc:"Campaign-aware schedule",icon:"□",run:()=>setView("calendar")},
{label:"Open TALK BOUT campaign",desc:"Active single campaign",icon:"◎",run:()=>setView("campaigns")},
{label:"Edit Link Hub",desc:"Public owned mini-site",icon:"↗",run:()=>setView("linkhub")},
{label:"Open Analytics",desc:"Performance and AI insights",icon:"⌁",run:()=>setView("analytics")},
{label:"Search Media",desc:"Reusable asset library",icon:"◩",run:()=>setView("media")}
];
function openCommand(){openOverlay("commandOverlay");$("#commandInput").value="";renderCommands(commands);setTimeout(()=>$("#commandInput").focus(),30)}
function renderCommands(items){$("#commandResults").innerHTML=items.map((c,i)=>'<button class="command-item" data-command="'+i+'"><span class="command-icon">'+c.icon+'</span><div><strong>'+c.label+'</strong><span>'+c.desc+'</span></div><kbd>↵</kbd></button>').join("");$$("[data-command]").forEach((b,i)=>b.addEventListener("click",()=>items[i].run()))}
$("#commandInput").addEventListener("input",e=>{const q=e.target.value.toLowerCase();renderCommands(commands.filter(c=>(c.label+" "+c.desc).toLowerCase().includes(q)))});
$("#notifBtn").addEventListener("click",()=>note("2 items need attention: Link Hub destination + campaign asset review."));
$("#workspaceBtn").addEventListener("click",()=>note("V1: JO₵YN only. The selector is ready for multi-brand workspaces later."));
init();
})();