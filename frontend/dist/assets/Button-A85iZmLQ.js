import{j as e}from"./index-BWbfWyd8.js";import"./vendor-CcksFWhd.js";const t={primary:"bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500/30 shadow-sm",secondary:"bg-rex-surface hover:bg-slate-700/50 text-slate-200 border-slate-600/50",ghost:"bg-transparent hover:bg-slate-700/30 text-slate-300 border-transparent",danger:"bg-red-600/20 hover:bg-red-600/30 text-red-300 border-red-500/30"},o={sm:"text-xs px-3 py-1.5 rounded-lg",md:"text-sm px-4 py-2 rounded-xl",lg:"text-sm px-5 py-2.5 rounded-xl"};function h({children:i,variant:n="secondary",size:a="md",loading:s=!1,disabled:d=!1,className:l="",onClick:c,type:b="button",ariaLabel:u,...x}){const r=d||s,f=t[n]||t.secondary,m=o[a]||o.md;return e.jsxs("button",{type:b,disabled:r,"aria-disabled":r||void 0,"aria-busy":s||void 0,"aria-label":u,onClick:r?void 0:c,className:`
        inline-flex items-center justify-center gap-2 border font-medium
        transition-colors duration-200
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400
        focus-visible:ring-offset-2 focus-visible:ring-offset-rex-bg
        disabled:opacity-40 disabled:cursor-not-allowed
        ${f} ${m} ${l}
      `,...x,children:[s&&e.jsx(p,{}),i]})}function p(){return e.jsxs("svg",{className:"w-4 h-4 animate-spin shrink-0",fill:"none",viewBox:"0 0 24 24","aria-hidden":"true",children:[e.jsx("circle",{className:"opacity-25",cx:"12",cy:"12",r:"10",stroke:"currentColor",strokeWidth:"4"}),e.jsx("path",{className:"opacity-75",fill:"currentColor",d:"M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"})]})}export{h as B};
