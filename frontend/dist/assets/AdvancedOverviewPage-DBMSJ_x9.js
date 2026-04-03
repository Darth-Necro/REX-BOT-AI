import{j as e,r as R,d as S,u as A}from"./index-C2xi5fcN.js";import{b as u}from"./vendor-Bafxjlbx.js";import{u as M,D as W,S as F,A as $,R as D}from"./RecentActions-BZMk3Bh3.js";import"./state-BPa8-Yex.js";function b({label:t,value:s,delta:a=null,icon:l=null}){let r="text-slate-400",i="";if(a!=null){const n=Number(a);n>0?(r="text-emerald-400",i="+"):n<0&&(r="text-red-400")}return e.jsxs("div",{className:`
        relative overflow-hidden
        ${R.card} border border-white/[0.06]
        bg-gradient-to-br from-[#0B1020] to-[#11192C]
        p-5 flex flex-col gap-1
        transition-shadow duration-300
        hover:shadow-[0_0_24px_rgba(34,211,238,0.06)]
      `,children:[e.jsx("div",{className:"absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent"}),e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("span",{className:"text-xs font-medium tracking-wide uppercase text-slate-500",children:t}),l&&e.jsx("span",{className:"text-slate-600 text-lg shrink-0",children:l})]}),e.jsx("span",{className:"text-2xl font-bold text-slate-100 tabular-nums leading-tight",children:s??"--"}),a!=null&&e.jsxs("span",{className:`text-xs font-medium ${r}`,children:[i,a]})]})}const k={nominal:{label:"ALL CLEAR",bark:"*woof* All clear!",glowColor:"rgba(34,211,238,0.12)",borderColor:"border-cyan-500/20",accentColor:"text-cyan-400",eyeColor:"#22D3EE",breathe:!0,alert:!1},elevated:{label:"ELEVATED",bark:"*GRRRRR* Something suspicious...",glowColor:"rgba(251,191,36,0.14)",borderColor:"border-amber-400/30",accentColor:"text-amber-300",eyeColor:"#FBBF24",breathe:!1,alert:!0},critical:{label:"CRITICAL",bark:"*WOOF WOOF WOOF!* THREAT DETECTED!",glowColor:"rgba(239,68,68,0.18)",borderColor:"border-red-500/40",accentColor:"text-red-400",eyeColor:"#EF4444",breathe:!1,alert:!0},junkyard:{label:"JUNKYARD DOG",bark:"*GRRRRR WOOF WOOF WOOF!* NO MERCY!",glowColor:"rgba(239,68,68,0.25)",borderColor:"border-orange-500/50",accentColor:"text-orange-400",eyeColor:"#F97316",breathe:!1,alert:!0},unknown:{label:"UNKNOWN",bark:"*ruff?* Sniffing around...",glowColor:"rgba(100,116,139,0.10)",borderColor:"border-slate-700",accentColor:"text-slate-400",eyeColor:"#64748B",breathe:!1,alert:!1}},v={awake:"AWAKE",alert_sleep:"LIGHT SLEEP",deep_sleep:"DEEP SLEEP",off:"OFFLINE",unknown:"UNKNOWN"},N={ready:"LLM READY",loading:"LLM LOADING",error:"LLM ERROR",disabled:"LLM OFF",unknown:"LLM --"},g={normal:`    ^
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
/_____/   U~`},y={nominal:g.normal,elevated:g.happy,critical:g.alert,junkyard:`    ^
   / \\__
  (!O @\\___    *GRRRRR!*
  /         O  JUNKYARD DOG!
 /   (_____/
/_____/   U
  |||||||||
  CHAIN~~~~`,unknown:g.sleep},p={idle:[`  /^-----^\\
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
   || (___\\`]};function V({posture:t,eyeColor:s}){const[a,l]=u.useState(0),[r,i]=u.useState(!1),n=t==="critical"||t==="elevated"||t==="junkyard";u.useEffect(()=>{const o=setInterval(()=>{i(d=>!d)},6e3);return()=>clearInterval(o)},[]),u.useEffect(()=>{const o=n?p.alert:p.idle,d=setInterval(()=>{l(x=>(x+1)%o.length)},n?500:2e3);return()=>clearInterval(d)},[n]);let c;if(r){const o=n?p.alert:p.idle;c=o[a%o.length]}else c=y[t]||y.nominal;return e.jsx("pre",{className:"font-mono text-xs sm:text-sm md:text-base leading-snug select-none whitespace-pre",style:{color:s},"aria-hidden":"true",children:c})}function I({threatPosture:t="unknown",powerState:s="unknown",llmStatus:a="unknown",connected:l=!1}){const r=k[t]||k.unknown,i=v[s]||v.unknown,n=N[a]||N.unknown,c=["*woof*","*ruff*","*ruff ruff*","*WOOF!*","*pant pant*"],[o,d]=u.useState(0);u.useEffect(()=>{if(r.alert)return;const m=setInterval(()=>{d(_=>(_+1)%c.length)},5e3);return()=>clearInterval(m)},[r.alert]);const x=r.alert?r.bark:`${c[o]} ${r.bark}`;return e.jsxs("div",{className:`
        relative overflow-hidden
        ${R.panel} border ${r.borderColor}
        bg-gradient-to-b from-[#0B1020] to-[#050816]
        p-6 flex flex-col items-center gap-4
        transition-all duration-500
      `,style:{boxShadow:`0 0 40px ${r.glowColor}, inset 0 1px 0 rgba(255,255,255,0.04)`},role:"status","aria-label":`REX threat posture: ${r.label}`,children:[e.jsx("div",{className:"absolute inset-x-0 top-0 h-px",style:{background:`linear-gradient(90deg, transparent, ${r.glowColor}, transparent)`}}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsx("span",{className:`
            inline-block w-2 h-2 rounded-full
            ${r.alert?"animate-ping":""}
          `,style:{backgroundColor:r.eyeColor}}),e.jsx("span",{className:`text-xs font-bold tracking-widest uppercase ${r.accentColor}`,children:r.label})]}),e.jsx("div",{className:r.breathe?"animate-breathe":r.alert?"animate-pulse":"",children:e.jsx(V,{posture:t,eyeColor:r.eyeColor})}),e.jsx("p",{className:`text-xs italic ${r.accentColor} text-center`,children:x}),e.jsxs("div",{className:"flex flex-wrap items-center justify-center gap-x-4 gap-y-1 text-[11px] font-medium tracking-wide uppercase",children:[e.jsx("span",{className:s==="awake"?"text-emerald-400":"text-slate-500",children:i}),e.jsx("span",{className:"text-slate-700",children:"|"}),e.jsx("span",{className:a==="ready"?"text-cyan-400":a==="error"?"text-red-400":"text-slate-500",children:n}),e.jsx("span",{className:"text-slate-700",children:"|"}),e.jsx("span",{className:l?"text-emerald-400":"text-red-400",children:l?"LINK UP":"LINK DOWN"})]})]})}function B(t){if(!t||t<=0)return"--";const s=Math.floor(t/3600),a=Math.floor(t%3600/60);return s>0?`${s}h ${a}m`:`${a}m`}function T(t){if(!t)return"";const s=Date.now()-new Date(t).getTime(),a=Math.floor(s/6e4);if(a<1)return"just now";if(a<60)return`${a}m ago`;const l=Math.floor(a/60);return l<24?`${l}h ago`:`${Math.floor(l/24)}d ago`}const C={critical:"border-l-red-500 bg-red-500/5",high:"border-l-orange-500 bg-orange-500/5",medium:"border-l-amber-400 bg-amber-400/5",low:"border-l-cyan-400 bg-cyan-400/5",info:"border-l-slate-500 bg-slate-500/5"},O={operational:{label:"Operational",color:"text-emerald-400"},degraded:{label:"Degraded",color:"text-amber-300"},critical:{label:"Critical",color:"text-red-400"},maintenance:{label:"Maintenance",color:"text-sky-400"},unknown:{label:"Unknown",color:"text-slate-400"}};function U({title:t,subtitle:s}){return e.jsxs("div",{className:"mb-3",children:[e.jsx("h2",{className:"text-sm font-bold tracking-widest uppercase text-slate-400",children:t}),s&&e.jsx("p",{className:"text-xs text-slate-600 mt-0.5",children:s})]})}function H({alert:t,index:s}){const a=t.severity||"info";return e.jsx("div",{className:`border-l-4 rounded-r-lg p-3 ${C[a]||C.info}`,children:e.jsxs("div",{className:"flex justify-between items-start gap-2",children:[e.jsxs("div",{className:"flex-1 min-w-0",children:[e.jsx("p",{className:"text-sm text-slate-200 truncate",children:t.description||t.message||"Security event detected"}),e.jsx("span",{className:"text-[10px] font-medium uppercase tracking-wide text-slate-500",children:a})]}),e.jsx("span",{className:"text-xs text-slate-500 whitespace-nowrap shrink-0",children:T(t.timestamp)})]})})}function L({message:t}){return e.jsx("div",{className:"flex items-center justify-center py-10 text-sm text-slate-600",children:t})}function Y({status:t}){const s=O[t]||O.unknown;return e.jsxs("div",{className:`
      inline-flex items-center gap-2 px-4 py-2
      rounded-full border border-white/[0.06]
      bg-slate-900/60
    `,children:[e.jsx("span",{className:`w-2 h-2 rounded-full ${t==="operational"?"bg-emerald-400":t==="degraded"?"bg-amber-400":t==="critical"?"bg-red-500":"bg-slate-500"}`}),e.jsx("span",{className:`text-xs font-bold tracking-widest uppercase ${s.color}`,children:s.label})]})}function Q(){const{bootstrapState:t,status:s,powerState:a,llmStatus:l,threatPosture:r,connected:i,deviceCount:n,activeThreats:c,threatsBlocked24h:o,uptimeSeconds:d,recentAlerts:x,health:m}=S(),_=A(f=>f.token),{actions:E}=M(),h=t==="idle"||t==="loading",j=m?{redis:m.redis!=="unhealthy",ollama:m.ollama!=="unhealthy"}:null;return e.jsxs("div",{className:"p-6 lg:p-8 space-y-8 max-w-7xl mx-auto",children:[j&&e.jsx(W,{services:j}),e.jsxs("div",{className:"flex flex-col lg:flex-row gap-6",children:[e.jsxs("div",{className:"flex-1 space-y-6",children:[e.jsxs("div",{className:"flex items-center justify-between",children:[e.jsx("h1",{className:"text-xl font-bold text-slate-100 tracking-tight",children:"System Overview"}),e.jsx(Y,{status:s})]}),e.jsxs("div",{className:"grid grid-cols-2 lg:grid-cols-4 gap-4",children:[e.jsx(b,{label:"Devices",value:h?"--":n,icon:e.jsxs("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:[e.jsx("rect",{x:"4",y:"4",width:"10",height:"10",rx:"1.5",stroke:"currentColor",strokeWidth:"1.5"}),e.jsx("path",{d:"M7 1V4M11 1V4M7 14V17M11 14V17M1 7H4M1 11H4M14 7H17M14 11H17",stroke:"currentColor",strokeWidth:"1.2",strokeLinecap:"round"})]})}),e.jsx(b,{label:"Active Threats",value:h?"--":c,icon:e.jsxs("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:[e.jsx("path",{d:"M9 1L1.5 16H16.5L9 1Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinejoin:"round"}),e.jsx("path",{d:"M9 7V10.5M9 13V13.01",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round"})]})}),e.jsx(b,{label:"Blocked (24h)",value:h?"--":o,icon:e.jsx("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:e.jsx("path",{d:"M9 1L2 4.5V9C2 13.1 5 16.4 9 17.5C13 16.4 16 13.1 16 9V4.5L9 1Z",stroke:"currentColor",strokeWidth:"1.5",strokeLinejoin:"round"})})}),e.jsx(b,{label:"Uptime",value:h?"--":B(d),icon:e.jsxs("svg",{width:"18",height:"18",viewBox:"0 0 18 18",fill:"none",children:[e.jsx("circle",{cx:"9",cy:"9",r:"7.5",stroke:"currentColor",strokeWidth:"1.5"}),e.jsx("path",{d:"M9 5V9.5L12 11",stroke:"currentColor",strokeWidth:"1.5",strokeLinecap:"round",strokeLinejoin:"round"})]})})]})]}),e.jsx("div",{className:"w-full lg:w-80 shrink-0",children:e.jsx(I,{threatPosture:r,powerState:a,llmStatus:l,connected:i})})]}),e.jsxs("section",{children:[e.jsx(U,{title:"Recent Alerts",subtitle:h?"Waiting for data...":`${x.length} events cached`}),h?e.jsx(L,{message:"Loading alert data..."}):x.length===0?e.jsx(L,{message:i?"No recent alerts -- all clear.":"Waiting for backend connection..."}):e.jsx("div",{className:"space-y-2",children:x.slice(0,8).map((f,w)=>e.jsx(H,{alert:f,index:w},f.id||w))})]}),e.jsx(F,{}),e.jsx($,{token:_}),e.jsx(D,{actions:E}),t==="error"&&e.jsx("div",{className:"rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300",children:"Failed to reach REX backend. Stats above may be stale or unavailable. The system will retry when the WebSocket reconnects."})]})}export{Q as default};
