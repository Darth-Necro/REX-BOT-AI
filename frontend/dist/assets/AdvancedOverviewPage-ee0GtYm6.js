import{j as e,r as y,d as O}from"./index-BMXdczKu.js";import{b as h}from"./vendor-Bafxjlbx.js";import"./state-BPa8-Yex.js";function b({label:t,value:s,delta:a=null,icon:l=null}){let r="text-slate-400",i="";if(a!=null){const n=Number(a);n>0?(r="text-emerald-400",i="+"):n<0&&(r="text-red-400")}return e.jsxs("div",{className:`
        relative overflow-hidden
        ${y.card} border border-white/[0.06]
        bg-gradient-to-br from-[#0B1020] to-[#11192C]
        p-5 flex flex-col gap-1
        transition-shadow duration-300
        hover:shadow-[0_0_24px_rgba(34,211,238,0.06)]
      `,children:[e.jsx("div",{className:"absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent"}),e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("span",{className:"text-xs font-medium tracking-wide uppercase text-slate-500",children:t}),l&&e.jsx("span",{className:"text-slate-600 text-lg shrink-0",children:l})]}),e.jsx("span",{className:"text-2xl font-bold text-slate-100 tabular-nums leading-tight",children:s??"--"}),a!=null&&e.jsxs("span",{className:`text-xs font-medium ${r}`,children:[i,a]})]})}const _={nominal:{label:"ALL CLEAR",bark:"*woof* All clear!",glowColor:"rgba(34,211,238,0.12)",borderColor:"border-cyan-500/20",accentColor:"text-cyan-400",eyeColor:"#22D3EE",breathe:!0,alert:!1},elevated:{label:"ELEVATED",bark:"*GRRRRR* Something suspicious...",glowColor:"rgba(251,191,36,0.14)",borderColor:"border-amber-400/30",accentColor:"text-amber-300",eyeColor:"#FBBF24",breathe:!1,alert:!0},critical:{label:"CRITICAL",bark:"*WOOF WOOF WOOF!* THREAT DETECTED!",glowColor:"rgba(239,68,68,0.18)",borderColor:"border-red-500/40",accentColor:"text-red-400",eyeColor:"#EF4444",breathe:!1,alert:!0},junkyard:{label:"JUNKYARD DOG",bark:"*GRRRRR WOOF WOOF WOOF!* NO MERCY!",glowColor:"rgba(239,68,68,0.25)",borderColor:"border-orange-500/50",accentColor:"text-orange-400",eyeColor:"#F97316",breathe:!1,alert:!0},unknown:{label:"UNKNOWN",bark:"*ruff?* Sniffing around...",glowColor:"rgba(100,116,139,0.10)",borderColor:"border-slate-700",accentColor:"text-slate-400",eyeColor:"#64748B",breathe:!1,alert:!1}},j={awake:"AWAKE",alert_sleep:"LIGHT SLEEP",deep_sleep:"DEEP SLEEP",off:"OFFLINE",unknown:"UNKNOWN"},w={ready:"LLM READY",loading:"LLM LOADING",error:"LLM ERROR",disabled:"LLM OFF",unknown:"LLM --"},f={normal:`    ^
   / \\__
  (    @\\___
  /         O
 /   (_____/
/_____/   U`,alert:`    ^
   / \\__
  (!O @\\___
  /         O
 /   (\\____/
/_____/ | U
         |~~`,sleep:`    ^
   / \\__
  (  - @\\___  zzz
  /         O
 /   (_____/
/_____/   U`,happy:`    ^
   / \\__
  (  O @\\___
  /         O
 /   (_____/
/_____/   U~`},k={nominal:f.normal,elevated:f.happy,critical:f.alert,junkyard:`    ^
   / \\__
  (!O @\\___    *GRRRRR!*
  /         O  JUNKYARD DOG!
 /   (_____/
/_____/   U
  |||||||||
  CHAIN~~~~`,unknown:f.sleep},g={idle:[`  /^-----^\\
 V  o o  V
  |  Y  |
   \\ Q /
   / - \\
   |    \\
   |     \\_
   || (___\\`,`   /^-----^\\
  V  o o  V
   |  Y  |
    \\ Q /
    / - \\
    |    \\
    |     \\_
    || (___\\`,`  /^-----^\\
 V  o o  V
  |  Y  |
   \\ Q /
   / p \\
   |    \\
   |     \\_
   || (___\\`],alert:[`  /^-----^\\
 V  O O  V
  |  Y  |
   \\ W /  GRRR!
   / - \\
   |    \\
   |     \\_
   || (___\\`,`  /^-----^\\
 V !O O! V
  |  Y  |
   \\ W /  WOOF!
   / = \\~
   |    \\
   |     \\_
   || (___\\`]};function L({posture:t,eyeColor:s}){const[a,l]=h.useState(0),[r,i]=h.useState(!1),n=t==="critical"||t==="elevated"||t==="junkyard";h.useEffect(()=>{const o=setInterval(()=>{i(x=>!x)},6e3);return()=>clearInterval(o)},[]),h.useEffect(()=>{const o=n?g.alert:g.idle,x=setInterval(()=>{l(m=>(m+1)%o.length)},n?500:2e3);return()=>clearInterval(x)},[n]);let c;if(r){const o=n?g.alert:g.idle;c=o[a%o.length]}else c=k[t]||k.nominal;return e.jsx("pre",{className:"font-mono text-xs sm:text-sm md:text-base leading-snug select-none whitespace-pre",style:{color:s},"aria-hidden":"true",children:c})}function R({threatPosture:t="unknown",powerState:s="unknown",llmStatus:a="unknown",connected:l=!1}){const r=_[t]||_.unknown,i=j[s]||j.unknown,n=w[a]||w.unknown,c=["*woof*","*ruff*","*ruff ruff*","*WOOF!*","*pant pant*"],[o,x]=h.useState(0);h.useEffect(()=>{if(r.alert)return;const d=setInterval(()=>{x(u=>(u+1)%c.length)},5e3);return()=>clearInterval(d)},[r.alert]);const m=r.alert?r.bark:`${c[o]} ${r.bark}`;return e.jsxs("div",{className:`
        relative overflow-hidden
        ${y.panel} border ${r.borderColor}
        bg-gradient-to-b from-[#0B1020] to-[#050816]
        p-6 flex flex-col items-center gap-4
        transition-all duration-500
      `,style:{boxShadow:`0 0 40px ${r.glowColor}, inset 0 1px 0 rgba(255,255,255,0.04)`},role:"status","aria-label":`REX threat posture: ${r.label}`,children:[e.jsx("div",{className:"absolute inset-x-0 top-0 h-px",style:{background:`linear-gradient(90deg, transparent, ${r.glowColor}, transparent)`}}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx("span",{className:`
            inline-block w-2 h-2 rounded-full
            ${r.alert?"animate-ping":""}
          `,style:{backgroundColor:r.eyeColor}}),e.jsx("span",{className:`text-xs font-bold tracking-widest uppercase ${r.accentColor}`,children:r.label})]}),e.jsx("div",{className:r.breathe?"animate-breathe":r.alert?"animate-pulse":"",children:e.jsx(L,{posture:t,eyeColor:r.eyeColor})}),e.jsx("p",{className:`text-xs italic ${r.accentColor} text-center`,children:m}),e.jsxs("div",{className:"flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[11px] font-medium tracking-wide uppercase",children:[e.jsx("span",{className:s==="awake"?"text-emerald-400":"text-slate-500",children:i}),e.jsx("span",{className:"text-slate-700",children:"|"}),e.jsx("span",{className:a==="ready"?"text-cyan-400":a==="error"?"text-red-400":"text-slate-500",children:n}),e.jsx("span",{className:"text-slate-700",children:"|"}),e.jsx("span",{className:l?"text-emerald-400":"text-red-400",children:l?"LINK UP":"LINK DOWN"})]})]})}function E(t){if(!t||t<=0)return"--";const s=Math.floor(t/3600),a=Math.floor(t%3600/60);return s>0?`${s}h ${a}m`:`${a}m`}function M(t){if(!t)return"";const s=Date.now()-new Date(t).getTime(),a=Math.floor(s/6e4);if(a<1)return"just now";if(a<60)return`${a}m ago`;const l=Math.floor(a/60);return l<24?`${l}h ago`:`${Math.floor(l/24)}d ago`}const v={critical:"border-l-red-500 bg-red-500/5",high:"border-l-orange-500 bg-orange-500/5",medium:"border-l-amber-400 bg-amber-400/5",low:"border-l-cyan-400 bg-cyan-400/5",info:"border-l-slate-500 bg-slate-500/5"},N={operational:{label:"Operational",color:"text-emerald-400"},degraded:{label:"Degraded",color:"text-amber-300"},critical:{label:"Critical",color:"text-red-400"},maintenance:{label:"Maintenance",color:"text-sky-400"},unknown:{label:"Unknown",color:"text-slate-400"}};function S({title:t,subtitle:s}){return e.jsxs("div",{className:"mb-3",children:[e.jsx("h2",{className:"text-sm font-bold tracking-widest uppercase text-slate-400",children:t}),s&&e.jsx("p",{className:"text-xs text-slate-600 mt-0.5",children:s})]})}function A({alert:t,index:s}){const a=t.severity||"info";return e.jsx("div",{className:`border-l-4 rounded-r-lg p-3 ${v[a]||v.info}`,children:e.jsxs("div",{className:"flex justify-between items-start gap-2",children:[e.jsxs("div",{className:"flex-1 min-w-0",children:[e.jsx("p",{className:"text-sm text-slate-200 truncate",children:t.description||t.message||"Security event detected"}),e.jsx("span",{className:"text-[10px] font-medium uppercase tracking-wide text-slate-500",children:a})]}),e.jsx("span",{className:"text-xs text-slate-500 whitespace-nowrap shrink-0",children:M(t.timestamp)})]})})}function C({message:t}){return e.jsx("div",{className:"flex items-center justify-center py-10 text-sm text-slate-600",children:t})}function W({status:t}){const s=N[t]||N.unknown;return e.jsxs("div",{className:`
      inline-flex items-center gap-2 px-4 py-2
      rounded-full border border-white/[0.06]
      bg-slate-900/60
    `,children:[e.jsx("span",{className:`w-2 h-2 rounded-full ${t==="operational"?"bg-emerald-400":t==="degraded"?"bg-amber-400":t==="critical"?"bg-red-500":"bg-slate-500"}`}),e.jsx("span",{className:`text-xs font-bold tracking-widest uppercase ${s.color}`,children:s.label})]})}function I(){const{bootstrapState:t,status:s,powerState:a,llmStatus:l,threatPosture:r,connected:i,deviceCount:n,activeThreats:c,threatsBlocked24h:o,uptimeSeconds:x,recentAlerts:m}=O(),d=t==="idle"||t==="loading";return e.jsxs("div",{className:"p-6 lg:p-8 space-y-8 max-w-7xl mx-auto",children:[e.jsxs("div",{className:"flex flex-col lg:flex-row gap-6",children:[e.jsxs("div",{className:"flex-1 space-y-6",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("h1",{className:"text-xl font-bold text-slate-100 tracking-tight",children:"System Overview"}),e.jsx(W,{status:s})]}),e.jsxs("div",{className:"grid grid-cols-2 lg:grid-cols-4 gap-4",children:[e.jsx(b,{label:"Devices",value:d?"--":n,icon:e.jsxs("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:[e.jsx("rect",{x:"4",y:"4",width:"10",height:"10",rx:"1.5",stroke:"currentColor",strokeWidth:"1.5"}),e.jsx("path",{d:"M7 1V4M11 1V4M7 14V17M11 14V17M1 7H4M1 11H4M14 7H17M14 11H17",stroke:"currentColor",strokeWidth:"1.2",strokeLinecap:"round"})]})}),e.jsx(b,{label:"Active Threats",value:d?"--":c,icon:e.jsxs("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:[e.jsx("path",{d:"M9 1L1.5 16H16.5L9 1Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinejoin:"round"}),e.jsx("path",{d:"M9 7V10.5M9 13V13.01",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"})]})}),e.jsx(b,{label:"Blocked (24h)",value:d?"--":o,icon:e.jsx("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:e.jsx("path",{d:"M9 1L2 4.5V9C2 13.1 5 16.4 9 17.5C13 16.4 16 13.1 16 9V4.5L9 1Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinejoin:"round"})})}),e.jsx(b,{label:"Uptime",value:d?"--":E(x),icon:e.jsxs("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:[e.jsx("circle",{cx:"9",cy:"9",r:"7.5",stroke:"currentColor",strokeWidth:"1.5"}),e.jsx("path",{d:"M9 5V9.5L12 11",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})]})})]})]}),e.jsx("div",{className:"w-full lg:w-80 shrink-0",children:e.jsx(R,{threatPosture:r,powerState:a,llmStatus:l,connected:i})})]}),e.jsxs("section",{children:[e.jsx(S,{title:"Recent Alerts",subtitle:d?"Waiting for data...":`${m.length} events cached`}),d?e.jsx(C,{message:"Loading alert data..."}):m.length===0?e.jsx(C,{message:i?"No recent alerts -- all clear.":"Waiting for backend connection..."}):e.jsx("div",{className:"space-y-2",children:m.slice(0,8).map((u,p)=>e.jsx(A,{alert:u,index:p},u.id||p))})]}),t==="error"&&e.jsx("div",{className:"rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300",children:"Failed to reach REX backend. Stats above may be stale or unavailable. The system will retry when the WebSocket reconnects."})]})}export{I as default};
