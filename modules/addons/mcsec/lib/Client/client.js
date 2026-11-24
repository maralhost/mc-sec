(function(){
'use strict';
// MC-Sec client pages. Everything works without this script (plain links and POST forms); with it, moving between
// the section's pages and sending its forms load the next view by AJAX (pjax=1) and swap it in place. A running
// scan's page asks for its progress every few seconds; a report being built reloads itself when ready; the scan
// launcher shows the total cost on its button before the click; copy buttons copy values (DNS records, snippets).
// The view is the server's own HTML, in which every dynamic value is already escaped; messages the script writes
// itself use textContent only.
var root=document.querySelector('.mcs');if(!root||root.getAttribute('data-mcs-on'))return;root.setAttribute('data-mcs-on','1');
var view=root.querySelector('[data-mcs-view]')||root;
function qa(sel,el){return Array.prototype.slice.call((el||root).querySelectorAll(sel));}
// Two languages: the page says which (data-mcs-lang); the few messages this script writes itself have their English here.
var en=root.getAttribute('data-mcs-lang')==='en';
var EN={'ارسال انجام نشد؛ دوباره امتحان کنید.':'Could not send. Please try again.','ذخیره انجام نشد؛ دوباره امتحان کنید.':'Could not save. Please try again.','خروج از تمام‌صفحه':'Exit full screen','تمام‌صفحه':'Full screen','کپی شد':'Copied','کپی':'Copy',
 'متن انتخاب شد؛ با Ctrl+C کپی کنید.':'Text selected. Press Ctrl+C to copy.','دارایی را انتخاب کنید':'Choose an asset','شروع اسکن · {n} اعتبار':'Start scan · {n} credits','شروع اسکن رایگان':'Start free scan','نوع اسکن را انتخاب کنید':'Choose a scan','شروع {s} اسکن · {n} اعتبار':'Start {s} scans · {n} credits','شروع {s} اسکن رایگان':'Start {s} free scans',
 'اعتبار کافی نیست: {need} لازم است و {have} دارید.':'Not enough credits: {need} needed, you have {have}.','مانده پس از این اسکن: {n} اعتبار':'Balance after this scan: {n} credits','{n}٪':'{n}%','اسکن {label}.':'Scan {label}.'};
function T(s,v){var o=en&&EN[s]?EN[s]:s;if(v)for(var k in v)o=o.split('{'+k+'}').join(v[k]);return o;}
function fa(n){return en?String(n):String(n).replace(/\d/g,function(d){return '۰۱۲۳۴۵۶۷۸۹'.charAt(+d);});}
var toastT;function toast(m,bad){var t=root.querySelector('[data-mcs-toast]');if(!t||!m)return;t.textContent=m;t.classList.toggle('is-bad',!!bad);t.hidden=false;clearTimeout(toastT);toastT=setTimeout(function(){t.hidden=true;},3600);}

var cur=location.href,navCtl=null;
var titleTail=document.title.indexOf(' - ')>0?document.title.slice(document.title.indexOf(' - ')):'';
function inSection(href){var u;try{u=new URL(href||'',location.href);}catch(e){return null;}
 if(u.origin!==location.origin||!/\/index\.php$/.test(u.pathname)||u.searchParams.get('m')!=='mcsec'||u.searchParams.get('progress'))return null;return u;}
function swap(j,u,push,keep){var doc=new DOMParser().parseFromString('<!doctype html><body>'+j.html,'text/html');view.textContent='';
 while(doc.body.firstChild)view.appendChild(document.adoptNode(doc.body.firstChild));cur=u.href;
 if(j.title)document.title=j.title+titleTail;if(push)history.pushState({mcs:u.href},'',u.href);
 if(keep)return;var at=u.hash?document.getElementById(decodeURIComponent(u.hash.slice(1))):null;
 if(at&&view.contains(at)){if(at.tagName==='DETAILS')at.open=true;at.scrollIntoView({block:'start'});}else if(root.classList.contains('mcs-full')){root.scrollTop=0;}else{var r=root.getBoundingClientRect();if(r.top<0)root.scrollIntoView({block:'start'});}
 var msg=view.querySelector('[role=alert],[role=status]');var f=msg||view;f.setAttribute('tabindex','-1');f.focus({preventScroll:true});}
function go(href,push,data,keep){var u=inSection(href);if(!u){location.href=href;return Promise.resolve();}
 if(navCtl&&navCtl.abort)navCtl.abort();navCtl=window.AbortController?new AbortController():null;
 var x=new URL(u.href);x.searchParams.set('pjax','1');x.hash='';if(!keep)root.classList.add('mcs-busy');
 var opt={credentials:'same-origin'};if(navCtl)opt.signal=navCtl.signal;if(data){opt.method='POST';opt.body=data;}
 return fetch(x.href,opt).then(function(r){return r.json();}).then(function(j){root.classList.remove('mcs-busy');
  if(j&&j.redirect){var ru=inSection(j.redirect);if(ru)return go(ru.href,true);location.href=j.redirect;return;}
  if(!j||typeof j.html!=='string')throw new Error('no view');swap(j,u,push,keep);
 }).catch(function(e){if(e&&e.name==='AbortError')return;root.classList.remove('mcs-busy');if(data)toast(T('ارسال انجام نشد؛ دوباره امتحان کنید.'),true);else if(!keep)location.href=u.href;});}

root.addEventListener('click',function(e){if(e.defaultPrevented||e.button!==0||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey)return;
 var a=e.target.closest&&e.target.closest('a[href]');if(!a||!root.contains(a)||a.target||a.hasAttribute('download'))return;
 if((a.getAttribute('href')||'').charAt(0)==='#'||!inSection(a.href))return;e.preventDefault();go(a.href,true);});

function quiet(f,u,d,bs){var x=new URL(u.href);x.searchParams.set('pjax','1');d.append('quiet','1');
 return fetch(x.href,{method:'POST',body:d,credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){
  if(!j||typeof j.ok!=='boolean')throw new Error('no answer');toast(j.flash,!j.ok);
  if(j.ok&&f.hasAttribute('data-mcs-remove')){var row=f.closest('[data-mcs-row]');if(row){row.classList.remove('is-unread');f.remove();}}
  if(typeof j.unread==='number')qa('[data-mcs-count="unread"]').forEach(function(c){if(j.unread>0)c.textContent=fa(j.unread);else c.remove();});
 }).catch(function(){toast(T('ذخیره انجام نشد؛ دوباره امتحان کنید.'),true);}).then(function(){bs.forEach(function(b){b.disabled=false;});});}

root.addEventListener('submit',function(e){var f=e.target;if(e.defaultPrevented||!f||f.tagName!=='FORM'||(f.getAttribute('method')||'').toLowerCase()!=='post')return;
 var s=e.submitter;var ask=(s&&s.getAttribute('data-mcs-confirm'))||f.getAttribute('data-mcs-confirm');
 if(ask&&!window.confirm(ask)){e.preventDefault();return;}
 if(f.classList.contains('mcs-native'))return; // the answer is a file to download, not a view
 var u=inSection(f.getAttribute('action')||location.href);if(!u)return;e.preventDefault();
 var d=new FormData(f);if(s&&s.name)d.append(s.name,s.value);var bs=qa('button',f);bs.forEach(function(b){b.disabled=true;});
 if(f.hasAttribute('data-mcs-quiet')){quiet(f,u,d,bs);return;}
 go(u.href,true,d).then(function(){bs.forEach(function(b){b.disabled=false;});});});

// the assistant: "thinking" while the answer is on its way; Enter sends, Shift+Enter makes a new line
root.addEventListener('submit',function(e){var f=e.target;if(!f||!f.hasAttribute||!f.hasAttribute('data-mcs-chat'))return;var c=view.querySelector('.mcs-chat');if(!c)return;
 c.classList.add('is-sending');var w=c.querySelector('.mcs-chat-wait');if(w)w.scrollIntoView({block:'nearest'});setTimeout(function(){c.classList.remove('is-sending');},120000);},true);
root.addEventListener('keydown',function(e){var t=e.target;if(e.key!=='Enter'||e.shiftKey||e.isComposing||!t||t.id!=='mcs-chat-text'||!t.form)return;
 e.preventDefault();if(t.value.trim()==='')return;if(t.form.requestSubmit)t.form.requestSubmit();else t.form.submit();});

document.addEventListener('click',function(e){qa('details.mcs-menu[open]').forEach(function(d){if(!d.contains(e.target))d.removeAttribute('open');});});
document.addEventListener('keydown',function(e){if(e.key!=='Escape')return;qa('details.mcs-menu[open]').forEach(function(d){d.removeAttribute('open');});
});

// full screen and the phone menu
function setFull(on){root.classList.toggle('mcs-full',on);document.documentElement.classList.toggle('mcs-lock',on);
 document.cookie='mcs_full='+(on?'1;max-age=31536000':';max-age=0')+';path=/;SameSite=Lax';
 qa('[data-mcs-full]').forEach(function(b){b.setAttribute('aria-pressed',on?'true':'false');b.title=T(on?'خروج از تمام‌صفحه':'تمام‌صفحه');});}
function strip(){var s=view.querySelector('.mcs-side'),a=s&&s.querySelector('.mcs-side-link.active');if(a&&s.scrollWidth>s.clientWidth+4)s.scrollLeft+=a.getBoundingClientRect().left-s.getBoundingClientRect().left-(s.clientWidth-a.offsetWidth)/2;}
root.addEventListener('click',function(e){var t=e.target;if(!t.closest)return;
 if(t.closest('[data-mcs-full]')){setFull(!root.classList.contains('mcs-full'));return;}
 var cp=t.closest('[data-mcs-copy]');if(cp){var src=document.getElementById(cp.getAttribute('data-mcs-copy'));if(!src)return;var text=src.textContent||'';
  var done=function(){cp.classList.add('is-done');var sp=cp.querySelector('span');if(sp){sp.textContent=T('کپی شد');}setTimeout(function(){cp.classList.remove('is-done');if(sp)sp.textContent=T('کپی');},1800);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,function(){sel(src);});}else{sel(src);}return;}
 if(t.closest('[data-mcs-print]')){window.print();}});
function sel(el){var r=document.createRange();r.selectNodeContents(el);var s=window.getSelection();s.removeAllRanges();s.addRange(r);try{document.execCommand('copy');}catch(e){}toast(T('متن انتخاب شد؛ با Ctrl+C کپی کنید.'));}

// the scan launcher: total cost on the button, assets that do not fit the chosen scan are greyed out
function launcher(){var f=view.querySelector('form.mcs-launcher');if(!f)return;
 var btn=f.querySelector('[data-mcs-launch-text]'),bal=f.querySelector('[data-mcs-balance]');
 function upd(){var want={},total=0,scans=0;
  qa('input[name="profiles[]"]:checked',f).forEach(function(i){want[i.value]=1;});
  qa('input[name="bundles[]"]:checked',f).forEach(function(i){(i.getAttribute('data-mcs-bundle')||'').split(',').forEach(function(k){if(k)want[k]=1;});});
  var assets=qa('input[name="assets[]"]:checked',f).map(function(a){return a.getAttribute('data-mcs-kind');});
  qa('input[name="profiles[]"]',f).forEach(function(i){if(!want[i.value]||i.disabled)return;var kinds=(i.getAttribute('data-mcs-kinds')||'').split(','),cost=+i.getAttribute('data-mcs-cost')||0;
   assets.forEach(function(k){if(kinds.indexOf(k)>=0){total+=cost;scans++;}});});
  var none=assets.length===0?T('دارایی را انتخاب کنید'):(scans===0?T('نوع اسکن را انتخاب کنید'):'');
  if(btn)btn.textContent=none||(scans>1?(total>0?T('شروع {s} اسکن · {n} اعتبار',{s:fa(scans),n:fa(total)}):T('شروع {s} اسکن رایگان',{s:fa(scans)})):(total>0?T('شروع اسکن · {n} اعتبار',{n:fa(total)}):T('شروع اسکن رایگان')));
  var b=f.querySelector('[data-mcs-launch]');if(b)b.disabled=!!none;
  if(bal){var have=+bal.getAttribute('data-mcs-balance');bal.textContent=total>have?T('اعتبار کافی نیست: {need} لازم است و {have} دارید.',{need:fa(total),have:fa(have)}):T('مانده پس از این اسکن: {n} اعتبار',{n:fa(have-total)});bal.style.color=total>have?'var(--t-err)':'';}}
 f.addEventListener('change',upd);upd();}
// live progress of a running scan
var progT=null,progN=0;
function progress(){clearTimeout(progT);var el=view.querySelector('[data-mcs-progress]');if(!el){progN=0;return;}
 progT=setTimeout(function(){if(document.visibilityState!=='visible'){progress();return;}progN++;var u;try{u=new URL(el.getAttribute('data-mcs-progress')||'',location.href);}catch(e){return;}if(u.origin!==location.origin||u.searchParams.get('m')!=='mcsec')return;
  fetch(u.href,{credentials:'same-origin'}).then(function(r){return r.json();}).then(function(j){if(!j||!j.ok)return;
   var bar=el.querySelector('.mcs-progress-bar');if(bar){bar.setAttribute('aria-valuenow',j.progress);var s=bar.querySelector('span');if(s)s.style.inlineSize=j.progress+'%';}
   var st=el.querySelector('[data-mcs-stage]');if(st&&j.stage)st.textContent=j.stage;var pc=el.querySelector('[data-mcs-pct]');if(pc)pc.textContent=T('{n}٪',{n:fa(j.progress)});
   if(typeof j.step==='number')qa('[data-mcs-steps] li',el).forEach(function(li,i){li.className=i<j.step?'is-done':(i===j.step?'is-active':'is-todo');});
   if(j.done){toast(T('اسکن {label}.',{label:j.label||''}));go(cur,false,null,true);return;}if(progN<720)progress();}).catch(function(){if(progN<720)progress();});},progN<12?5000:15000);}

// a report being built reloads itself
var relT=null,relN=0;
function reload(){clearTimeout(relT);var el=view.querySelector('[data-mcs-reload]');if(!el){relN=0;return;}
 relT=setTimeout(function(){relN++;if(document.visibilityState==='visible'&&!root.classList.contains('mcs-busy'))go(cur,false,null,true);else if(relN<60)reload();},Math.max(5,+el.getAttribute('data-mcs-reload'))*1000);}

function boot(){strip();qa('[data-mcs-full],[data-mcs-copy],[data-mcs-print]').forEach(function(b){b.hidden=false;});
 qa('[data-mcs-full]').forEach(function(b){var on=root.classList.contains('mcs-full');b.setAttribute('aria-pressed',on?'true':'false');});
 launcher();progress();reload();}
var mo=new MutationObserver(function(){boot();});mo.observe(view,{childList:true});boot();
if(root.classList.contains('mcs-full'))document.documentElement.classList.add('mcs-lock');
try{var at0=location.hash?document.getElementById(decodeURIComponent(location.hash.slice(1))):null;if(at0&&at0.tagName==='DETAILS'&&view.contains(at0))at0.open=true;}catch(e){}
history.replaceState({mcs:location.href},'',location.href);
window.addEventListener('popstate',function(e){if(e.state&&e.state.mcs)go(e.state.mcs,false);});
})();
