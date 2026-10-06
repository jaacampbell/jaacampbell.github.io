(function(){
"use strict";

const KEYS={
  state:"jocyn_os_state_v1",
  published:"jocyn_public_hub_v1",
  analytics:"jocyn_analytics_v1"
};

const defaults={
  workspace:{id:"jocyn",name:"JO₵YN",type:"Artist"},
  content:[
    {id:"talk-bout-reel",title:"TALK BOUT — announcement reel",meta:"Release campaign • vertical video",status:"Ready",platforms:["IG","TT","YT"]},
    {id:"wanderlvst-teaser",title:"WANDERLVST world teaser",meta:"Album campaign • cinematic",status:"Draft",platforms:["IG","TT"]},
    {id:"boarding-rsvp",title:"Boarding Lounge RSVP push",meta:"Event • static + story",status:"Scheduled",platforms:["IG","FB"]},
    {id:"chasing-still",title:"Chasing Fog film still",meta:"Catalog extension • image",status:"Idea",platforms:["IG"]}
  ],
  tasks:[
    ["1","Finalize TALK BOUT release post","Campaign","Today"],
    ["2","Add final streaming links to Link Hub","Link Hub","Next"],
    ["3","Approve WANDERLVST teaser cut","Content","Review"]
  ],
  campaigns:[
    {id:"talk-bout",title:"TALK BOUT",status:"Active",goal:"Launch lead single with a focused 14-day content cycle.",progress:62},
    {id:"wanderlvst",title:"WANDERLVST",status:"Planning",goal:"Build the album world into one connected release system.",progress:28}
  ],
  media:[
    {id:"m1",name:"TALK BOUT key art",kind:"Campaign asset"},
    {id:"m2",name:"WANDERLVST still 01",kind:"Photo"},
    {id:"m3",name:"Chasing Fog night exterior",kind:"Photo"},
    {id:"m4",name:"Boarding Lounge mark",kind:"Campaign asset"},
    {id:"m5",name:"Studio portrait 03",kind:"Photo"},
    {id:"m6",name:"Performance still",kind:"Photo"},
    {id:"m7",name:"WANDERLVST texture",kind:"Campaign asset"},
    {id:"m8",name:"TALK BOUT vertical master",kind:"Video"}
  ]
};

const defaultPublished={
  heroTitle:"WANDERLVST",
  heroSubtitle:"Music • film • story",
  heroStatus:"ALBUM • MAR 5",
  heroAction:"ENTER",
  featuredTitle:"TALK BOUT",
  featuredSubtitle:"Single • Current direction",
  featuredCta:"Listen now",
  featuredVisible:true,
  chasingVisible:true,
  wanderVisible:true,
  boardingVisible:true,
  emailVisible:true,
  updatedAt:null
};

function clone(v){return JSON.parse(JSON.stringify(v))}
function parse(raw,fallback){
  if(!raw)return clone(fallback);
  try{return Object.assign(clone(fallback),JSON.parse(raw)||{})}
  catch(e){return clone(fallback)}
}
function read(key,fallback){
  try{return parse(localStorage.getItem(key),fallback)}
  catch(e){return clone(fallback)}
}
function write(key,value){
  try{localStorage.setItem(key,JSON.stringify(value));return true}
  catch(e){return false}
}
function getState(){
  const saved=read(KEYS.state,{});
  return {
    workspace:Object.assign({},defaults.workspace,saved.workspace||{}),
    content:Array.isArray(saved.content)?saved.content:clone(defaults.content),
    tasks:Array.isArray(saved.tasks)?saved.tasks:clone(defaults.tasks),
    campaigns:Array.isArray(saved.campaigns)?saved.campaigns:clone(defaults.campaigns),
    media:Array.isArray(saved.media)?saved.media:clone(defaults.media)
  };
}
function saveState(next){return write(KEYS.state,next)}
function getPublished(){return read(KEYS.published,defaultPublished)}
function publishHub(patch){
  const next=Object.assign({},getPublished(),patch||{},{updatedAt:new Date().toISOString()});
  write(KEYS.published,next);
  return next;
}
function track(type,payload){
  const events=read(KEYS.analytics,[]);
  const item={
    id:(crypto&&crypto.randomUUID)?crypto.randomUUID():String(Date.now())+"-"+Math.random().toString(16).slice(2),
    type:String(type||"event"),
    ts:new Date().toISOString(),
    payload:payload||{}
  };
  events.push(item);
  if(events.length>1000)events.splice(0,events.length-1000);
  write(KEYS.analytics,events);
  return item;
}
function getAnalytics(){
  const events=read(KEYS.analytics,[]);
  const since=Date.now()-7*24*60*60*1000;
  const recent=events.filter(e=>Date.parse(e.ts)>=since);
  const byType=t=>recent.filter(e=>e.type===t).length;
  const destinations={};
  recent.filter(e=>e.type==="destination_click").forEach(e=>{
    const key=(e.payload&&e.payload.destination)||"Unknown";
    destinations[key]=(destinations[key]||0)+1;
  });
  const topDestination=Object.entries(destinations).sort((a,b)=>b[1]-a[1])[0];
  const views=byType("page_view");
  const clicks=byType("destination_click")+byType("content_open");
  return {
    events,
    recent,
    pageViews:views,
    clicks,
    contentOpens:byType("content_open"),
    signupIntents:byType("signup_intent"),
    messageIntents:byType("message_intent"),
    topDestination:topDestination?topDestination[0]:"—",
    ctr:views?Math.round((clicks/views)*1000)/10:0
  };
}

window.JOCYN_STORE={
  defaults:clone(defaults),
  defaultPublished:clone(defaultPublished),
  getState,
  saveState,
  getPublished,
  publishHub,
  track,
  getAnalytics
};
})();