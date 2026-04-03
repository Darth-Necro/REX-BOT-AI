import{d as f,j as t,c as O}from"./index-C2xi5fcN.js";import{b as x}from"./vendor-Bafxjlbx.js";import"./state-BPa8-Yex.js";const k={awake:"text-rex-safe",patrol:"text-cyan-400",alert_sleep:"text-rex-warn",deep_sleep:"text-rex-muted",off:"text-rex-muted",unknown:"text-rex-warn"},N={awake:"*WOOF WOOF!* REX is awake and protecting your network",patrol:"*ruff ruff* REX is on patrol! *sniff sniff* Inspecting the network...",alert_sleep:"*woof* ... zzz ... REX is sleeping with one ear open",deep_sleep:"*zzz* ... REX is in deep sleep",off:"*whimper* REX is off",unknown:"*ruff?* Connecting to REX backend..."},R={awake:"animate-breathe",patrol:"animate-pulse",alert_sleep:"animate-pulse-slow",deep_sleep:"",off:"opacity-50",unknown:"animate-pulse"},n={normal:`    ^
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
/_____/   U~`},h={awake:n.normal,patrol:n.happy,alert_sleep:n.sleep,deep_sleep:n.sleep,off:n.sleep,unknown:n.normal},c={idle:[`  /^-----^\\
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
   || (___\\`,`  /^-----^\\
 V  - o  V
  |  Y  |
   \\ Q /
   / - \\
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
   || (___\\`],sleep:[`  /^-----^\\
 V  - -  V
  |  Y  |  zzz
   \\ q /
   / - \\
   |    \\
   |     \\_
   || (___\\
  U     U`,`  /^-----^\\
 V  - -  V
  |  Y  | zzZZ
   \\ q /
   / - \\
   |    \\
   |     \\_
   || (___\\`]},g=[n.alert,n.happy];function V(){const{powerState:s,activeThreats:r}=f(),e=r>0,a=e?"text-rex-threat":k[s]||"text-rex-safe",_=e?"animate-pulse":R[s]||"",m=e?`*GRRRRR WOOF WOOF!* ${r} active threat${r>1?"s":""} detected!`:N[s]||"*ruff* REX is ready",[d,v]=x.useState(0),[u,j]=x.useState(!1);x.useEffect(()=>{const l=setInterval(()=>{j(o=>!o)},8e3);return()=>clearInterval(l)},[]),x.useEffect(()=>{const l=e?c.alert:s==="deep_sleep"||s==="alert_sleep"?c.sleep:c.idle,o=setInterval(()=>{v(b=>(b+1)%l.length)},e?500:2500);return()=>clearInterval(o)},[e,s]);let i;if(e)if(u){const l=c.alert;i=l[d%l.length]}else i=g[d%g.length];else if(u){const o=s==="deep_sleep"||s==="alert_sleep"?c.sleep:c.idle;i=o[d%o.length]}else i=h[s]||h.awake;return t.jsxs("div",{className:`flex flex-col items-center ${_}`,role:"status","aria-live":"polite",children:[t.jsx("pre",{className:`text-2xl sm:text-3xl md:text-4xl font-mono leading-tight select-none ${a}`,children:i}),t.jsx("p",{className:`mt-4 text-lg font-medium ${a}`,"aria-label":m,children:m})]})}function p({label:s,value:r,color:e="text-rex-text"}){return t.jsxs("div",{className:"bg-rex-card rounded-xl p-4 flex flex-col items-center",children:[t.jsx("span",{className:`text-3xl font-bold ${e}`,children:r}),t.jsx("span",{className:"text-sm text-rex-muted mt-1",children:s})]})}function y(){const{deviceCount:s,threatsBlocked24h:r,activeThreats:e}=f(),a=e===0?"Good":e<5?"Fair":"Needs Attention",_=e===0?"text-rex-safe":e<5?"text-rex-warn":"text-rex-threat";return t.jsxs("div",{className:"grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-xl",children:[t.jsx(p,{label:"Devices Protected",value:s,color:"text-rex-accent"}),t.jsx(p,{label:"Threats Blocked (24h)",value:r,color:"text-rex-safe"}),t.jsx(p,{label:"Network Health",value:a,color:_})]})}const w={critical:"border-rex-threat bg-rex-threat/10",high:"border-orange-500 bg-orange-500/10",medium:"border-rex-warn bg-rex-warn/10",low:"border-rex-accent bg-rex-accent/10",info:"border-rex-muted bg-rex-muted/10"};function z(s){if(!s)return"";const r=Date.now()-new Date(s).getTime(),e=Math.floor(r/6e4);if(e<1)return"just now";if(e<60)return`${e} min ago`;const a=Math.floor(e/60);return a<24?`${a}h ago`:`${Math.floor(a/24)}d ago`}function S(){const{threats:s}=O(),r=s.slice(0,5);if(r.length===0){const e=f.getState().connected;return t.jsx("div",{className:"w-full max-w-xl text-center text-rex-muted py-8",children:e?"No recent alerts.":"Waiting for backend connection..."})}return t.jsxs("div",{className:"w-full max-w-xl space-y-2",children:[t.jsx("h3",{className:"text-sm font-semibold text-rex-muted uppercase tracking-wide",children:"Recent Alerts"}),r.map((e,a)=>t.jsx("div",{className:`border-l-4 rounded-r-lg p-3 ${w[e.severity]||w.info}`,children:t.jsxs("div",{className:"flex justify-between items-start",children:[t.jsx("p",{className:"text-sm",children:e.description||"Security event detected"}),t.jsx("span",{className:"text-xs text-rex-muted ml-2 whitespace-nowrap",children:z(e.timestamp)})]})},e.id||a))]})}function W(){return t.jsxs("div",{className:"flex flex-col items-center justify-center min-h-[calc(100vh-4rem)] px-4 py-8 gap-8",children:[t.jsx(V,{}),t.jsx(y,{}),t.jsx(S,{})]})}export{W as default};
