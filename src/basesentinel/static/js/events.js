"use strict";
const state={token:sessionStorage.getItem("basesentinel_token"),offset:0,limit:50,total:0,items:[],busy:false};
const $=id=>document.getElementById(id);
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function date(v){if(!v)return "—";const d=new Date(v);return Number.isNaN(d.getTime())?"—":d.toLocaleString();}
function levelClass(v){const n=Number(v);if(n===0)return "level-informational";if(n>=9)return "level-critical";if(n>=7)return "level-high";if(n>=4)return "level-medium";return "level-low";}
function title(e){const known={"login.success":"Successful login","login.failed":"Failed login attempt","privilege.special_assignment":"Special privileges assigned","account.created":"User account created"};return known[e.event_type]||String(e.event_type||"Security event").replace(/[._-]+/g," ").replace(/\b\w/g,c=>c.toUpperCase());}
function showError(v){$("events-error").textContent=v;$("events-error").hidden=!v;}
async function api(path,options={}){const r=await fetch("/api/v1"+path,{...options,headers:{"Accept":"application/json",...(state.token?{"Authorization":"Bearer "+state.token}:{}),...(options.headers||{})},cache:"no-store"});const d=await r.json().catch(()=>({}));if(r.status===401){sessionStorage.removeItem("basesentinel_token");window.location.replace("/login");}if(!r.ok)throw new Error(d?.error?.message||"Request failed ("+r.status+").");return d;}
function theme(v){const t=v==="light"?"light":"dark";document.documentElement.dataset.theme=t;try{localStorage.setItem("basesentinel_theme",t);}catch(_){}$("theme-toggle").querySelector(".theme-label").textContent=t==="dark"?"LIGHT MODE":"DARK MODE";}
function render(){
 const a=state.items;
 $("count-total").textContent=state.total.toLocaleString();
 $("count-severe").textContent=a.filter(x=>x.severity>=7).length;
 $("count-auth").textContent=a.filter(x=>x.category==="authentication").length;
 $("latest-received").textContent=a.length?new Date(a[0].received_at).toLocaleTimeString():"—";
 $("result-summary").textContent=state.total.toLocaleString()+" matching events · "+a.length+" on this page";
 $("events-list").innerHTML=a.length?a.map(e=>{
  const device=e.device||{},deviceName=device.hostname||device.name||("Device "+String(e.agent_id||"").slice(0,8)),n=Number(e.severity);
  return `<a class="event-card" href="/events/${encodeURIComponent(e.id)}">
   <div class="event-card-level ${levelClass(n)}">L${n}</div>
   <div class="event-card-content"><div class="event-card-heading"><h3>${esc(title(e))}</h3><span class="event-level-label ${levelClass(n)}">Level ${n}</span></div>
   <p>${esc(e.message)}</p><div class="event-card-meta"><span>${esc(e.category)}</span><span>${esc(deviceName)}</span><time datetime="${esc(e.occurred_at)}">${esc(date(e.occurred_at))}</time></div></div>
   <span class="event-card-arrow" aria-hidden="true">→</span></a>`;
 }).join(""):'<div class="event-empty">No events match this view.</div>';
 const first=state.total?state.offset+1:0,last=Math.min(state.offset+state.limit,state.total);
 $("pagination-label").textContent=first+"–"+last+" of "+state.total;
 $("page-first").disabled=$("page-prev").disabled=state.offset===0;
 $("page-next").disabled=$("page-last").disabled=state.offset+state.limit>=state.total;
}
async function load(){
 if(state.busy)return;state.busy=true;showError("");$("events-list").setAttribute("aria-busy","true");
 try{
  const p=new URLSearchParams({limit:String(state.limit),offset:String(state.offset)});
  if($("filter-category").value)p.set("category",$("filter-category").value);
  if($("filter-level").value==="0"){p.set("severity_min","0");p.set("severity_max","0");}else p.set("severity_min","1");
  const d=await api("/events?"+p);state.items=d.items||[];state.total=d.pagination?.total??0;
  if(state.offset>=state.total&&state.offset>0){state.offset=Math.max(0,Math.floor((state.total-1)/state.limit)*state.limit);state.busy=false;return load();}
  render();$("last-updated").textContent="Updated "+new Date().toLocaleTimeString();
 }catch(e){showError(e.message);$("events-list").innerHTML='<div class="event-empty">Event feed unavailable.</div>';}
 finally{state.busy=false;$("events-list").removeAttribute("aria-busy");}
}
async function logout(){try{await api("/auth/logout",{method:"POST"});}catch(_){}sessionStorage.removeItem("basesentinel_token");sessionStorage.removeItem("basesentinel_user");window.location.replace("/login");}
async function init(){
 if(!state.token){window.location.replace("/login");return;}
 theme(document.documentElement.dataset.theme||"dark");
 $("theme-toggle").addEventListener("click",()=>theme(document.documentElement.dataset.theme==="dark"?"light":"dark"));
 $("logout-button").addEventListener("click",logout);$("refresh-button").addEventListener("click",load);
 $("apply-filters").addEventListener("click",()=>{state.offset=0;state.limit=Number($("filter-limit").value);load();});
 $("clear-filters").addEventListener("click",()=>{$("filter-category").value="";$("filter-level").value="security";$("filter-limit").value="50";state.offset=0;state.limit=50;load();});
 $("page-first").addEventListener("click",()=>{state.offset=0;load();});
 $("page-prev").addEventListener("click",()=>{state.offset=Math.max(0,state.offset-state.limit);load();});
 $("page-next").addEventListener("click",()=>{state.offset+=state.limit;load();});
 $("page-last").addEventListener("click",()=>{state.offset=Math.max(0,Math.floor((state.total-1)/state.limit)*state.limit);load();});
 try{const u=await api("/auth/me");$("current-username").textContent=u.username;$("current-role").textContent=u.role;await load();}catch(e){showError(e.message);}
}
document.addEventListener("DOMContentLoaded",init);
