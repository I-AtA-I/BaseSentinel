"use strict";
const token=sessionStorage.getItem("basesentinel_token"),eventId=document.body.dataset.eventId,$=id=>document.getElementById(id);
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function date(v){if(!v)return "—";const d=new Date(v);return Number.isNaN(d.getTime())?"—":d.toLocaleString();}
function levelClass(v){const n=Number(v);if(n===0)return "level-informational";if(n>=9)return "level-critical";if(n>=7)return "level-high";if(n>=4)return "level-medium";return "level-low";}
function levelName(v){const n=Number(v);if(n===0)return "Informational · audit telemetry";if(n<=3)return "Low";if(n<=6)return "Medium";if(n<=8)return "High";return "Critical";}
function title(e){const known={"login.success":"Successful login","login.failed":"Failed login attempt","privilege.special_assignment":"Special privileges assigned","account.created":"User account created"};return known[e.event_type]||String(e.event_type||"Security event").replace(/[._-]+/g," ").replace(/\b\w/g,c=>c.toUpperCase());}
function assessment(e){
 const notes={
 "login.success":{summary:"Windows recorded a successful sign-in. This is routine audit telemetry and is not treated as a security finding by itself.",guidance:"Check the account, source address, workstation and logon type if the sign-in was unexpected. This record remains available under the Level 0 filter."},
 "login.failed":{summary:"Windows recorded an unsuccessful sign-in attempt. A single failure can be caused by a mistyped password or a stale saved credential.",guidance:"Look for repeated failures, unusual source addresses or activity across multiple accounts. BaseSentinel currently correlates repeated failed logins into a separate alert."},
 "privilege.special_assignment":{summary:"Windows recorded a sign-in session that received special privileges. This can be expected for an administrator or a system service.",guidance:"Verify that the account and time of access match an expected administrative task. The event alone does not prove misuse."},
 "account.created":{summary:"Windows recorded the creation of a local or domain account.",guidance:"Confirm that the account was created by an authorized administrator and that its purpose is known."}
 };
 if(notes[e.event_type])return notes[e.event_type];
 if(Number(e.severity)===0)return {summary:"This is informational telemetry retained for audit and investigation.",guidance:"Level 0 records are hidden from the default security feed. They can be reviewed by selecting the Level 0 filter."};
 return {summary:"This event was classified as security-relevant by its source severity or an ingestion-side rule.",guidance:"Review the captured fields and compare the event with other activity from this device and time window. A severity level is a prioritization signal, not proof of compromise."};
}
function rows(el,items){el.innerHTML=items.map(([k,v])=>`<div class="detail-row"><dt>${esc(k)}</dt><dd>${esc(v||"—")}</dd></div>`).join("");}
function error(v){$("detail-error").textContent=v;$("detail-error").hidden=!v;}
async function api(path){const r=await fetch("/api/v1"+path,{headers:{"Accept":"application/json",...(token?{"Authorization":"Bearer "+token}:{})},cache:"no-store"});const d=await r.json().catch(()=>({}));if(r.status===401){sessionStorage.removeItem("basesentinel_token");window.location.replace("/login");}if(!r.ok)throw new Error(d?.error?.message||"Request failed ("+r.status+").");return d;}
function theme(v){const t=v==="light"?"light":"dark";document.documentElement.dataset.theme=t;try{localStorage.setItem("basesentinel_theme",t);}catch(_){}$("theme-toggle").querySelector(".theme-label").textContent=t==="dark"?"LIGHT MODE":"DARK MODE";}
function render(e){
 const n=Number(e.severity),d=e.device||{},a=assessment(e);
 $("event-level").className="event-level-pill "+levelClass(n);$("event-level").textContent="LEVEL "+n;$("event-classification").textContent=levelName(n);
 $("event-title").textContent=title(e);$("event-message").textContent=e.message||"No source message was provided.";
 $("event-category").textContent=e.category||"Unknown category";$("event-source").textContent=e.source||"Unknown source";$("event-code").textContent=e.event_code?"Event ID "+e.event_code:"No event code";
 $("event-assessment").textContent=a.summary;$("event-guidance").textContent=a.guidance;
 rows($("event-timeline"),[["Occurred",date(e.occurred_at)],["Received by BaseSentinel",date(e.received_at)]]);
 $("device-name").textContent=d.name||"Unknown device";$("device-hostname").textContent=d.hostname||"Hostname not reported";
 rows($("device-details"),[["Platform",d.platform],["OS version",d.platform_version],["Architecture",d.architecture],["Agent version",d.agent_version],["Agent ID",e.agent_id]]);
 rows($("event-metadata"),[["Category",e.category],["Event type",e.event_type],["Windows event ID",e.event_code],["Source",e.source],["Schema version",e.schema_version],["Event UID",e.event_uid],["Record ID",e.event_data?.record_id]]);
 const fields=e.event_data&&typeof e.event_data==="object"?Object.entries(e.event_data):[];
 $("event-fields").innerHTML=fields.length?fields.map(([k,v])=>`<div class="event-field"><span>${esc(k.replace(/([A-Z])/g," $1"))}</span><strong>${esc(typeof v==="object"?JSON.stringify(v):v)}</strong></div>`).join(""):'<p class="muted">The source did not provide additional structured fields.</p>';
 $("raw-event-data").textContent=JSON.stringify(e.event_data??{},null,2);$("detail-updated").textContent="Event record "+String(e.id).slice(0,8)+"…";$("event-detail-content").hidden=false;
}
async function load(){error("");$("event-detail-content").hidden=true;try{render(await api("/events/"+encodeURIComponent(eventId)));}catch(e){error(e.message);}}
async function logout(){try{await fetch("/api/v1/auth/logout",{method:"POST",headers:{"Authorization":"Bearer "+token},cache:"no-store"});}catch(_){}sessionStorage.removeItem("basesentinel_token");sessionStorage.removeItem("basesentinel_user");window.location.replace("/login");}
async function init(){
 if(!token){window.location.replace("/login");return;}theme(document.documentElement.dataset.theme||"dark");
 $("theme-toggle").addEventListener("click",()=>theme(document.documentElement.dataset.theme==="dark"?"light":"dark"));
 $("logout-button").addEventListener("click",logout);$("detail-refresh").addEventListener("click",load);
 try{const u=await api("/auth/me");$("current-username").textContent=u.username;$("current-role").textContent=u.role;await load();}catch(e){error(e.message);}
}
document.addEventListener("DOMContentLoaded",init);
